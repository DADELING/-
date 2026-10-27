#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U盘文件加密工具 (USB File Guard) v1.1

对U盘（或任意目录）中的指定文件进行 AES-256-GCM 认证加密与解密。

特性:
  * AES-256-GCM 认证加密（防窃取、防篡改、防截断、防乱序）
  * PBKDF2-HMAC-SHA256 密码派生，每文件独立随机盐（默认 600000 次迭代）
  * 分块流式处理，内存占用恒定，支持大文件
  * 临时文件 + 原子替换，中途断电/拔盘不会损坏数据
  * 支持按扩展名批量加密、递归子目录、自动检测U盘
  * 三级加密范围: ① 整个U盘 ② 指定文件夹 ③ 指定文件（encrypt-drive 整盘一键；encrypt 按路径自动识别层级）
  * 提供命令行、交互菜单、图形界面三种使用方式

依赖:
  Python 3.8+；第三方库 cryptography（pip install cryptography，建议 >= 3.4）

用法示例:
  python usb_file_guard.py                          # 交互模式
  python usb_file_guard.py drives                   # 检测U盘
  python usb_file_guard.py scan E:/资料             # 扫描目录
  python usb_file_guard.py encrypt E:/资料 -e .docx,.xlsx
  python usb_file_guard.py decrypt E:/资料
  python usb_file_guard.py encrypt-drive            # 整盘加密自动检测的U盘
  python usb_file_guard.py encrypt-drive E:/        # 整盘加密指定U盘
  python usb_file_guard.py decrypt-drive E:/        # 整盘解密
"""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import shutil
import string
import struct
import sys
import time
import zipfile
from pathlib import Path

__version__ = "1.3"
APP_NAME = "U盘文件加密工具 (USB File Guard)"

# ---------------- 常量 ----------------
MAGIC = b"UFG1"                 # 单文件加密魔数
MAGIC_VAULT = b"UFGV"           # 文件夹打包加密魔数（外壳同为 .ufg，内部负载为ZIP）
ENC_SUFFIX = ".ufg"             # 加密文件扩展名
SALT_LEN = 16                   # PBKDF2 盐长度（字节）
NONCE_LEN = 12                  # GCM nonce 长度（字节）
TAG_LEN = 16                    # GCM 认证标签长度（字节）
HEADER_LEN = 48                 # 加密文件头长度（字节）
DEFAULT_ITERATIONS = 600_000    # PBKDF2 默认迭代次数
DEFAULT_CHUNK_MB = 4.0          # 默认分块大小（MiB）
MIN_CHUNK = 64 * 1024
MAX_CHUNK = 256 * 1024 * 1024
LARGE_FILE_PROGRESS = 8 * 1024 * 1024   # 超过该大小显示进度百分比

EXCLUDE_DIRS = {
    "System Volume Information", "$RECYCLE.BIN", "RECYCLER", "Recycled",
    ".Trashes", ".Trash-1000", ".Spotlight-V100", ".fseventsd",
}
JUNK_FILES = {"desktop.ini", "thumbs.db", "autorun.inf"}

CRYPTO_HINT = "缺少加密库 cryptography，请先执行: python -m pip install cryptography"

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


class GuardError(Exception):
    """带友好提示的操作错误。"""


def require_crypto() -> None:
    if not _HAS_CRYPTO:
        raise GuardError(CRYPTO_HINT)


def try_install_crypto() -> bool:
    """缺少 cryptography 时询问并尝试自动安装（官方源 + 清华镜像）。"""
    import subprocess

    print("缺少加密库 cryptography（AES 加密所需，仅需安装一次）。")
    try:
        ans = input("是否现在自动安装? [Y/n] ").strip().lower()
    except Exception:  # 无控制台（如 pythonw）等场景一律视为拒绝
        ans = "n"
    if ans not in ("", "y", "yes", "是"):
        print("请手动执行后重新运行: python -m pip install cryptography")
        return False
    attempts = [[], ["-i", "https://pypi.tuna.tsinghua.edu.cn/simple"]]
    for extra in attempts:
        cmd = [sys.executable, "-m", "pip", "install", "cryptography"] + extra
        if extra:
            print("改用清华镜像重试...")
        print("执行:", " ".join(cmd))
        try:
            if subprocess.call(cmd) == 0:
                try:
                    from cryptography.exceptions import InvalidTag  # noqa: F401
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
                    return True
                except ImportError:
                    continue
        except Exception:
            continue
    print("自动安装失败。请手动执行: python -m pip install cryptography")
    print("网络不通时可换镜像: python -m pip install cryptography -i https://pypi.tuna.tsinghua.edu.cn/simple")
    return False


# ---------------- 核心加密 ----------------
def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    """PBKDF2-HMAC-SHA256 派生 256 位密钥。"""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def chunk_nonce(nonce_base: bytes, index: int) -> bytes:
    """由随机基值 XOR 计数器生成每个数据块的 nonce（同一文件内互不相同）。"""
    n = bytearray(nonce_base)
    counter = struct.pack(">Q", index)
    for i in range(8):
        n[4 + i] ^= counter[i]
    return bytes(n)


def encrypt_file(src: Path, dst: Path, password: str, *,
                 chunk_size: int, iterations: int, progress=None,
                 magic: bytes = MAGIC) -> None:
    """将 src 加密写入 dst。头 48 字节 = 魔数+盐+迭代次数+nonce基值+分块大小+明文长度。"""
    salt = secrets.token_bytes(SALT_LEN)
    nonce_base = secrets.token_bytes(NONCE_LEN)
    key = derive_key(password, salt, iterations)
    aes = AESGCM(key)
    total = src.stat().st_size
    header = (magic + salt + struct.pack(">I", iterations) + nonce_base
              + struct.pack(">IQ", chunk_size, total))
    tmp = dst.with_name(dst.name + ".part")
    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            fout.write(header)
            index = 0
            done = 0
            while True:
                block = fin.read(chunk_size)
                if not block:
                    break
                aad = header + struct.pack(">Q", index)   # 绑定头部与块序号
                fout.write(aes.encrypt(chunk_nonce(nonce_base, index), block, aad))
                index += 1
                done += len(block)
                if progress:
                    progress(done, total)
        os.replace(tmp, dst)   # 原子替换
    except BaseException:
        _unlink_quiet(tmp)
        raise


def decrypt_file(src: Path, dst: Path, password: str, *, progress=None) -> None:
    """解密 src 到 dst。密码错误或数据损坏时抛出 GuardError，且不写出目标文件。"""
    if src.stat().st_size < HEADER_LEN:
        raise GuardError("不是有效的加密文件（文件太小）")
    tmp = dst.with_name(dst.name + ".part")
    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            header = fin.read(HEADER_LEN)
            if header[:4] not in (MAGIC, MAGIC_VAULT):
                raise GuardError("不是有效的加密文件（魔数不匹配）")
            salt = header[4:20]
            (iterations,) = struct.unpack(">I", header[20:24])
            nonce_base = header[24:36]
            chunk_size, total = struct.unpack(">IQ", header[36:48])
            if not (MIN_CHUNK <= chunk_size <= MAX_CHUNK):
                raise GuardError("加密文件头参数异常，文件可能已损坏")
            if not (1000 <= iterations <= 100_000_000):
                raise GuardError("加密文件头参数异常，文件可能已损坏")
            key = derive_key(password, salt, iterations)
            aes = AESGCM(key)
            index = 0
            remaining = total
            while remaining > 0:
                expect = min(chunk_size, remaining) + TAG_LEN
                blob = fin.read(expect)
                if len(blob) != expect:
                    raise GuardError("加密文件被截断，数据不完整")
                aad = header + struct.pack(">Q", index)
                try:
                    block = aes.decrypt(chunk_nonce(nonce_base, index), blob, aad)
                except InvalidTag:
                    raise GuardError("解密失败：密码错误，或文件已损坏/被篡改")
                fout.write(block)
                remaining -= len(block)
                index += 1
                if progress:
                    progress(total - remaining, total)
            if fin.read(1):
                raise GuardError("加密文件尾部有多余数据，文件可能被篡改")
        os.replace(tmp, dst)
    except BaseException:
        _unlink_quiet(tmp)
        raise


def _unlink_quiet(p: Path) -> None:
    try:
        p.unlink()
    except FileNotFoundError:
        pass


# ---------------- 文件收集 ----------------
def _is_junk(name: str) -> bool:
    return (name.startswith(".") or name.startswith("~$")
            or name.lower() in JUNK_FILES)


def normalize_exts(ext_str):
    """"docx,.JPG，png" -> {'.docx', '.jpg', '.png'}；空返回 None（全部）。"""
    if not ext_str:
        return None
    exts = set()
    for part in ext_str.replace("，", ",").split(","):
        part = part.strip().lower()
        if not part:
            continue
        if not part.startswith("."):
            part = "." + part
        exts.add(part)
    return exts or None


def collect_encrypt_targets(target: Path, exts):
    if target.is_file():
        if target.suffix.lower() == ENC_SUFFIX:
            raise GuardError(f"文件已是加密格式（{ENC_SUFFIX}），无需重复加密: {target}")
        return [target]
    files = []
    for root, dirs, names in os.walk(target):
        dirs[:] = sorted(d for d in dirs
                         if d not in EXCLUDE_DIRS and not d.startswith("."))
        for name in sorted(names):
            if _is_junk(name):
                continue
            p = Path(root) / name
            if not p.is_file():
                continue
            if p.suffix.lower() == ENC_SUFFIX:
                continue
            if exts and p.suffix.lower() not in exts:
                continue
            files.append(p)
    return files


def collect_decrypt_targets(target: Path):
    if target.is_file():
        if target.suffix.lower() != ENC_SUFFIX:
            raise GuardError(f"该文件不是加密文件（缺少 {ENC_SUFFIX} 扩展名）: {target}")
        return [target]
    files = []
    for root, dirs, names in os.walk(target):
        dirs[:] = sorted(d for d in dirs
                         if d not in EXCLUDE_DIRS and not d.startswith("."))
        for name in sorted(names):
            if name.lower().endswith(ENC_SUFFIX):
                p = Path(root) / name
                if p.is_file():
                    files.append(p)
    return files


# ---------------- 文件夹打包加密（vault） ----------------
def peek_magic(p: Path) -> bytes:
    """读取文件前4字节魔数；读不到返回 b""。"""
    try:
        with open(p, "rb") as f:
            return f.read(4)
    except OSError:
        return b""


def pack_folder_zip(folder: Path, dest_zip: Path, log=print) -> int:
    """把 folder 递归打包为 ZIP（仅存储不压缩，保证速度）。返回打包文件数。

    排除系统目录/隐藏目录/垃圾文件；保留空子文件夹（写入目录条目）。
    """
    count = 0
    with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_STORED, allowZip64=True) as zf:
        for root, dirs, names in os.walk(folder):
            dirs[:] = sorted(d for d in dirs
                             if d not in EXCLUDE_DIRS and not d.startswith("."))
            rel = Path(root).relative_to(folder)
            arc_base = "" if str(rel) == "." else str(rel).replace("\\", "/") + "/"
            if not dirs and not names:
                if str(rel) != ".":
                    zf.writestr(zipfile.ZipInfo(arc_base), b"")  # 保留空文件夹
                continue
            for name in sorted(names):
                if _is_junk(name):
                    continue
                p = Path(root) / name
                if not p.is_file():
                    continue
                zf.write(p, arcname=arc_base + name)
                count += 1
    return count


def _safe_extract_zip(zip_path: Path, dest: Path, overwrite: bool, log=print):
    """防路径攻击的安全解压（Zip Slip 防护）。返回 (还原文件数, 跳过数)。"""
    ok = skip = 0
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/").lstrip("/")
            parts = [seg for seg in name.split("/") if seg and seg != "."]
            if not parts or any(seg == ".." for seg in parts) or ":" in name:
                log(f"跳过异常条目: {info.filename}")
                skip += 1
                continue
            target = dest.joinpath(*parts)
            if info.is_dir() or name.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            if target.exists() and not overwrite:
                log(f"跳过 {info.filename} ：目标已存在")
                skip += 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as fsrc, open(target, "wb") as fdst:
                shutil.copyfileobj(fsrc, fdst)
            dt = info.date_time
            if dt and dt[0] >= 1980:
                try:
                    ts = time.mktime(dt + (0, 0, -1))
                    os.utime(target, (ts, ts))
                except (OSError, OverflowError, ValueError):
                    pass
            ok += 1
    return ok, skip


def encrypt_folder_vault(folder_str, password: str, *, remove_original: bool = True,
                         overwrite: bool = False, chunk_size: int | None = None,
                         iterations: int | None = None, yes: bool = False,
                         log=print, progress_factory=None) -> int:
    """把整个文件夹打包加密为单个 .ufg 文件（文件夹名与内容全部隐藏）。

    成功后可选删除原文件夹。返回 0 成功 / 1 取消；出错抛 GuardError。
    """
    require_crypto()
    folder = Path(folder_str)
    if not folder.is_dir():
        raise GuardError(f"路径不是文件夹: {folder}")
    if folder.parent == folder:
        raise GuardError("不能对盘符根目录整体打包。如需加密整个U盘，请用「整个U盘」逐文件加密。")
    out = folder.with_name(folder.name + ENC_SUFFIX)
    if out.exists() and not overwrite:
        raise GuardError(f"同名加密文件已存在: {out}\n请先改名/移走它，或使用覆盖模式。")

    # 预览要打包的内容
    n = total = 0
    for root, dirs, names in os.walk(folder):
        dirs[:] = sorted(d for d in dirs
                         if d not in EXCLUDE_DIRS and not d.startswith("."))
        for name in names:
            if _is_junk(name):
                continue
            p = Path(root) / name
            if p.is_file():
                n += 1
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
    if n == 0:
        raise GuardError("文件夹内没有可打包的文件（可能为空或只含系统/垃圾文件）。")

    if not yes:
        print(f"即将把文件夹打包加密为: {out.name}")
        print(f"  来源: {folder}  （{n} 个文件，共 {human_size(total)}）")
        print("  文件夹名与内部结构将全部隐藏在加密文件中。")
        print("  " + ("加密成功后将删除原文件夹，请确认已牢记密码！"
                      if remove_original else "加密成功后保留原文件夹。"))
        if not ask_yesno("确认?"):
            log("已取消。")
            return 1

    chunk_size = chunk_size or parse_chunk(DEFAULT_CHUNK_MB)
    iterations = iterations or DEFAULT_ITERATIONS
    tmp_zip = folder.with_name("." + folder.name + ".pack.part")
    pair = (None, None)
    try:
        log(f"正在打包 {folder.name} 下的 {n} 个文件 ...")
        pack_folder_zip(folder, tmp_zip, log=log)
        zsize = tmp_zip.stat().st_size
        if progress_factory:
            pair = progress_factory(out.name, zsize)
        log(f"打包完成（{human_size(zsize)}），正在加密 ...")
        encrypt_file(tmp_zip, out, password, chunk_size=chunk_size,
                     iterations=iterations, progress=pair[0],
                     magic=MAGIC_VAULT)
        if not out.is_file() or out.stat().st_size == 0:
            raise GuardError("加密输出异常，已中止。")
    except BaseException:
        _unlink_quiet(out)  # 清理可能产生的半成品
        raise
    finally:
        _unlink_quiet(tmp_zip)
        if pair[1]:
            pair[1]()

    if remove_original:
        shutil.rmtree(folder)
        log(f"加密完成: {out}（原文件夹已删除）")
    else:
        log(f"加密完成: {out}（原文件夹保留）")
    return 0


def decrypt_vault(src_str, password: str, *, remove_original: bool = False,
                  overwrite: bool = False, log=print,
                  progress_factory=None) -> int:
    """解密文件夹打包加密文件(.ufg)，还原出完整文件夹。返回 0 成功。"""
    require_crypto()
    src = Path(src_str)
    if not src.is_file():
        raise GuardError(f"路径不是加密文件: {src}")
    if peek_magic(src) != MAGIC_VAULT:
        raise GuardError("这不是文件夹打包加密文件（魔数不匹配），请用普通文件方式解密。")
    base_name = src.name[: -len(ENC_SUFFIX)]
    if not base_name:
        raise GuardError("文件名异常，无法确定还原的文件夹名。")
    dest = src.parent / base_name
    created = not dest.exists()
    if dest.exists() and not overwrite:
        raise GuardError(f"目标文件夹已存在: {dest}\n请先改名/移走它，或使用覆盖模式。")

    pair = (None, None)
    if progress_factory:
        try:
            pair = progress_factory(src.name, src.stat().st_size)
        except Exception:
            pair = (None, None)
    tmp_zip = src.with_name("." + base_name + ".extract.part")
    try:
        decrypt_file(src, tmp_zip, password, progress=pair[0])
        dest.mkdir(parents=True, exist_ok=True)
        ok, skipped = _safe_extract_zip(tmp_zip, dest, overwrite, log=log)
        tip = f"（{ok} 个文件" + (f"，跳过 {skipped}" if skipped else "") + "）"
        log(f"文件夹已还原: {dest}{tip}")
    except GuardError:
        if created:
            shutil.rmtree(dest, ignore_errors=True)  # 失败不留半成品文件夹
        raise
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        if created:
            shutil.rmtree(dest, ignore_errors=True)
        raise GuardError(f"还原文件夹失败: {exc}")
    finally:
        _unlink_quiet(tmp_zip)
        if pair[1]:
            pair[1]()
    if remove_original:
        try:
            src.unlink()
        except OSError as exc:
            log(f"警告：删除加密包失败: {exc}")
    return 0


# ---------------- 批量处理 ----------------
def run_batch(action: str, files, password: str, *,
              chunk_size: int, iterations: int, overwrite: bool,
              remove_original: bool, log=print, progress_factory=None):
    """逐文件执行加密/解密。返回 (成功数, 失败数, 跳过数)。"""
    ok = fail = skip = 0
    total_n = len(files)
    verb = "加密" if action == "encrypt" else "解密"
    for i, path in enumerate(files, 1):
        label = f"[{i}/{total_n}]"
        # 文件夹打包加密文件：按魔数自动识别，走解包还原流程
        if action == "decrypt" and peek_magic(path) == MAGIC_VAULT:
            try:
                decrypt_vault(path, password, remove_original=remove_original,
                              overwrite=overwrite,
                              log=lambda m, l=label: log(f"{l} {m}"),
                              progress_factory=progress_factory)
            except GuardError as exc:
                fail += 1
                log(f"{label} 失败 {path.name} ：{exc}")
                continue
            except OSError as exc:
                fail += 1
                log(f"{label} 失败 {path.name} ：系统错误 {exc}")
                continue
            ok += 1
            log(f"{label} 完成 解密文件夹包 {path.name}")
            continue
        if action == "encrypt":
            dst = path.with_name(path.name + ENC_SUFFIX)
        else:
            base = path.name[: -len(ENC_SUFFIX)]
            if not base:
                fail += 1
                log(f"{label} 失败 {path.name} ：文件名异常")
                continue
            dst = path.with_name(base)
        if dst.exists() and not overwrite:
            skip += 1
            log(f"{label} 跳过 {path.name} ：目标文件已存在（如需覆盖请加 --overwrite）")
            continue
        pair = (None, None)
        try:
            size = path.stat().st_size
            if progress_factory:
                pair = progress_factory(path.name, size)
            progress = pair[0]
            if action == "encrypt":
                encrypt_file(path, dst, password, chunk_size=chunk_size,
                             iterations=iterations, progress=progress)
            else:
                decrypt_file(path, dst, password, progress=progress)
        except GuardError as exc:
            fail += 1
            log(f"{label} 失败 {path.name} ：{exc}")
            continue
        except OSError as exc:
            fail += 1
            log(f"{label} 失败 {path.name} ：系统错误 {exc}")
            continue
        finally:
            if pair[1]:
                pair[1]()
        if remove_original:
            try:
                path.unlink()
            except OSError as exc:
                log(f"{label} 警告 {path.name} ：已生成输出文件，但删除原文件失败: {exc}")
        ok += 1
        log(f"{label} 完成 {verb} {path.name}")
    return ok, fail, skip


def summary(ok: int, fail: int, skip: int) -> None:
    parts = [f"成功 {ok}"]
    if skip:
        parts.append(f"跳过 {skip}")
    if fail:
        parts.append(f"失败 {fail}")
    print("-" * 46)
    print("处理结束: " + "，".join(parts))


def cli_progress_pair(name: str, total: int):
    """终端进度显示：返回 (回调, 清行回调)。小文件或非终端返回 (None, None)。"""
    if total < LARGE_FILE_PROGRESS or not sys.stdout.isatty():
        return None, None
    used = [False]

    def cb(done, tot):
        used[0] = True
        pct = done * 100 // tot if tot else 100
        sys.stdout.write(f"\r    {name}: {pct:3d}%")
        sys.stdout.flush()

    def clear():
        if used[0]:
            sys.stdout.write("\r" + " " * min(len(name) + 12, 60) + "\r")
            sys.stdout.flush()

    return cb, clear


# ---------------- 高层操作（CLI 与交互模式共用） ----------------
def encrypt_path(path_str: str, password: str, *, ext=None,
                 remove_original: bool = False, yes: bool = False,
                 overwrite: bool = False, chunk_mb: float = DEFAULT_CHUNK_MB,
                 iterations: int = DEFAULT_ITERATIONS) -> int:
    require_crypto()
    target = Path(path_str)
    if not target.exists():
        raise GuardError(f"路径不存在: {target}")
    chunk = parse_chunk(chunk_mb)
    if iterations < 10_000:
        raise GuardError("PBKDF2 迭代次数过低（至少 10000）")
    files = collect_encrypt_targets(target, normalize_exts(ext))
    if not files:
        print("没有找到需要加密的文件。")
        return 0
    if not confirm_action("encrypt", files, remove_original, yes):
        print("已取消。")
        return 1
    ok, fail, skip = run_batch("encrypt", files, password, chunk_size=chunk,
                               iterations=iterations, overwrite=overwrite,
                               remove_original=remove_original,
                               progress_factory=cli_progress_pair)
    summary(ok, fail, skip)
    if ok:
        print("提醒: 请牢记密码（忘记密码将无法解密）；加密文件扩展名为 .ufg，请勿改动。")
    return 0 if fail == 0 else 1


def decrypt_path(path_str: str, password: str, *, remove_original: bool = False,
                 yes: bool = False, overwrite: bool = False) -> int:
    require_crypto()
    target = Path(path_str)
    if not target.exists():
        raise GuardError(f"路径不存在: {target}")
    files = collect_decrypt_targets(target)
    if not files:
        print("没有找到需要解密的文件（未发现 .ufg 加密文件）。")
        return 0
    if not confirm_action("decrypt", files, remove_original, yes):
        print("已取消。")
        return 1
    ok, fail, skip = run_batch("decrypt", files, password, chunk_size=0,
                               iterations=0, overwrite=overwrite,
                               remove_original=remove_original,
                               progress_factory=cli_progress_pair)
    summary(ok, fail, skip)
    if ok:
        print("解密后的文件已还原到加密文件所在目录。")
    return 0 if fail == 0 else 1


def parse_chunk(mb: float) -> int:
    b = int(mb * 1024 * 1024)
    return max(MIN_CHUNK, min(MAX_CHUNK, b))


# ---------------- U盘整盘操作 ----------------
def pick_drive(drive_str):
    """用户指定了U盘则直接使用；否则自动检测（多个U盘时让用户选择）。"""
    if drive_str:
        d = Path(drive_str)
        if not d.exists():
            raise GuardError(f"盘符路径不存在: {drive_str}")
        return str(d)
    drives = list_removable_drives()
    if not drives:
        raise GuardError("未检测到可移动磁盘（U盘）；也可以直接把U盘路径作为参数传入，"
                         "如: encrypt-drive E:/")
    if len(drives) == 1:
        return drives[0][0]
    if not sys.stdin.isatty():
        raise GuardError("检测到多个可移动磁盘（" + " ".join(mp for mp, _, _ in drives)
                         + "），请在命令中指定U盘路径，如: encrypt-drive " + drives[0][0])
    print("检测到多个可移动磁盘:")
    for i, (mp, total, _free) in enumerate(drives, 1):
        cap = f"（总容量 {human_size(total)}）" if total else ""
        print(f"  {i}) {mp} {cap}")
    raw = input(f"请选择要操作的U盘 [1-{len(drives)}，回车=1]: ").strip()
    idx = int(raw) if raw.isdigit() and 1 <= int(raw) <= len(drives) else 1
    return drives[idx - 1][0]


def estimate_time(total_size: int) -> str:
    """按常见U盘吞吐粗略估算整盘处理耗时区间。"""
    if total_size <= 0:
        return "-"
    def fmt(sec: float) -> str:
        if sec < 90:
            return f"{sec:.0f}秒"
        if sec < 5400:
            return f"{sec / 60:.0f}分钟"
        return f"{sec / 3600:.1f}小时"
    best = total_size / (80 * 1024 * 1024)    # 约 USB 3.0（含加密开销）
    worst = total_size / (15 * 1024 * 1024)   # 约 USB 2.0
    return f"{fmt(best)} ~ {fmt(worst)}"


def confirm_drive_action(action: str, count: int, total_size: int,
                         remove_original: bool, yes: bool) -> bool:
    verb = "加密" if action == "encrypt" else "解密"
    extra = ("，成功后删除源文件（请确认重要数据已另行备份）！"
             if remove_original else "。")
    print(f"即将{verb}整个U盘: 共 {count} 个文件，约 {human_size(total_size)}" + extra)
    if yes:
        return True
    if not sys.stdin.isatty():
        print("当前为非交互环境，请加 -y 参数确认后重试。")
        return False
    return ask_yesno(f"确认{verb}整个U盘?")


def drive_action(action: str, drive_str, password: str, *, ext=None,
                 remove_original: bool = False, yes: bool = False,
                 overwrite: bool = False, chunk_mb: float = DEFAULT_CHUNK_MB,
                 iterations: int = DEFAULT_ITERATIONS) -> int:
    """一键加密/解密整个U盘（含全部子目录）。"""
    require_crypto()
    drive = Path(pick_drive(drive_str))
    print(f"U盘目标: {drive}")
    print("正在扫描全盘，请稍候...")
    if action == "encrypt":
        files = collect_encrypt_targets(drive, normalize_exts(ext))
        if not files:
            print("U盘中没有需要加密的文件（可能已全部加密）。")
            return 0
    else:
        files = collect_decrypt_targets(drive)
        if not files:
            print("U盘中没有找到加密文件（.ufg）。")
            return 0
    total_size = 0
    for p in files:
        try:
            total_size += p.stat().st_size
        except OSError:
            pass
    print(f"共找到 {len(files)} 个文件，约 {human_size(total_size)}，"
          f"预计耗时 {estimate_time(total_size)}:")
    for p in files[:8]:
        print(f"    {p}")
    if len(files) > 8:
        print(f"    ...等共 {len(files)} 个文件")
    if not confirm_drive_action(action, len(files), total_size, remove_original, yes):
        print("已取消。")
        return 1
    ok, fail, skip = run_batch(
        action, files, password,
        chunk_size=parse_chunk(chunk_mb) if action == "encrypt" else 0,
        iterations=iterations if action == "encrypt" else 0,
        overwrite=overwrite, remove_original=remove_original,
        progress_factory=cli_progress_pair)
    summary(ok, fail, skip)
    if ok:
        if action == "encrypt":
            print("提醒: 请牢记密码（忘记密码将无法解密）；加密文件扩展名为 .ufg，请勿改动。")
        else:
            print("全部文件已还原到原位置。")
    return 0 if fail == 0 else 1


# ---------------- 交互辅助 ----------------
def ask_yesno(prompt: str, default: bool = False) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    try:
        ans = input(f"{prompt} {hint} ").strip().lower()
    except EOFError:
        return False
    if not ans:
        return default
    return ans in ("y", "yes", "是")


def get_password(args, confirm: bool) -> str:
    pw = getattr(args, "password", None)
    if pw is not None:
        if not pw:
            print("密码不能为空。")
            raise SystemExit(2)
        print("[提示] 密码经由命令行参数传入，可能残留在 shell 历史记录中。")
        return pw
    if not sys.stdin.isatty():
        raise SystemExit("当前为非交互环境，请使用 -p/--password 传入密码。")
    while True:
        pw = getpass.getpass("请输入并确认密码: " if confirm else "请输入密码: ")
        if not pw:
            print("密码不能为空，请重新输入。")
            continue
        if confirm:
            again = getpass.getpass("请再次输入密码: ")
            if pw != again:
                print("两次输入不一致，请重试。")
                continue
        if len(pw) < 8 and not ask_yesno("密码少于 8 位，强度偏低，仍要使用该密码?"):
            continue
        return pw


def confirm_action(action: str, files, remove_original: bool, yes: bool) -> bool:
    verb = "加密" if action == "encrypt" else "解密"
    print(f"即将{verb} {len(files)} 个文件"
          + ("，成功后删除原文件。" if remove_original else "。"))
    for p in files[:10]:
        print(f"    {p}")
    if len(files) > 10:
        print(f"    ...等共 {len(files)} 个文件")
    if yes:
        return True
    if not sys.stdin.isatty():
        print("当前为非交互环境，请加 -y 参数确认后重试。")
        return False
    return ask_yesno(f"确认{verb}?")


def prompt_path(prompt: str):
    try:
        raw = input(prompt)
    except EOFError:
        return None
    return raw.strip().strip('"').strip("'") or None


# ---------------- U盘检测与扫描 ----------------
def list_removable_drives():
    """返回 [(挂载点, 总容量, 可用容量), ...]，容量获取失败时为 None。"""
    candidates = []
    if sys.platform.startswith("win"):
        import ctypes
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i, letter in enumerate(string.ascii_uppercase):
            if (bitmask >> i) & 1:
                drive = f"{letter}:\\"
                # GetDriveTypeW == 2 (DRIVE_REMOVABLE)
                if ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive)) == 2:
                    candidates.append(drive)
    elif sys.platform == "darwin":
        base = Path("/Volumes")
        if base.exists():
            candidates = [str(p) for p in sorted(base.iterdir()) if p.is_dir()]
    else:
        try:
            text = Path("/proc/mounts").read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                mp = parts[1].replace("\\040", " ")
                if "/media/" in mp or "/run/media/" in mp:
                    candidates.append(mp)
    result = []
    for mp in candidates:
        try:
            usage = shutil.disk_usage(mp)
            result.append((mp, usage.total, usage.free))
        except OSError:
            result.append((mp, None, None))
    return result


def first_drive():
    try:
        drives = list_removable_drives()
    except Exception:
        return None
    return drives[0][0] if drives else None


def human_size(n) -> str:
    if n is None:
        return "?"
    x = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if x < 1024 or unit == "TB":
            return f"{int(x)}B" if unit == "B" else f"{x:.1f}{unit}"
        x /= 1024
    return f"{x:.1f}TB"


def scan_path(path_str: str) -> int:
    target = Path(path_str)
    if not target.exists():
        print(f"路径不存在: {target}")
        return 2
    plain_cnt = enc_cnt = 0
    plain_sz = enc_sz = 0
    plain_samples, enc_samples = [], []
    for root, dirs, names in os.walk(target):
        dirs[:] = sorted(d for d in dirs
                         if d not in EXCLUDE_DIRS and not d.startswith("."))
        for name in sorted(names):
            if _is_junk(name):
                continue
            p = Path(root) / name
            try:
                sz = p.stat().st_size
            except OSError:
                continue
            if name.lower().endswith(ENC_SUFFIX):
                enc_cnt += 1
                enc_sz += sz
                if len(enc_samples) < 15:
                    enc_samples.append((p, sz))
            else:
                plain_cnt += 1
                plain_sz += sz
                if len(plain_samples) < 15:
                    plain_samples.append((p, sz))
    print(f"扫描: {target}")
    print(f"  普通文件    : {plain_cnt} 个, 共 {human_size(plain_sz)}")
    print(f"  已加密(.ufg): {enc_cnt} 个, 共 {human_size(enc_sz)}")
    if plain_samples:
        print("  普通文件示例:")
        for p, sz in plain_samples:
            print(f"    {human_size(sz):>9}  {p}")
    if enc_samples:
        print("  加密文件示例:")
        for p, sz in enc_samples:
            print(f"    {human_size(sz):>9}  {p}")
    print("提示: encrypt 加密 / decrypt 解密，加 -h 查看参数。")
    return 0


# ---------------- 自检 ----------------
def cmd_selftest(_args=None) -> int:
    require_crypto()
    import tempfile
    print("运行自检（验证加密/解密/防篡改逻辑）...")
    cases = []
    pw = "SelfTest#2026"
    chunk = 64 * 1024
    iters = 50_000

    with tempfile.TemporaryDirectory(prefix="ufg_selftest_") as td_name:
        td = Path(td_name)
        # 1) 不同大小的往返测试（含 0 字节、非整块）
        for size in (0, 1, 1024, 700_000, 1_600_000):
            data = secrets.token_bytes(size)
            src = td / f"case_{size}.bin"
            src.write_bytes(data)
            enc = Path(str(src) + ENC_SUFFIX)
            encrypt_file(src, enc, pw, chunk_size=chunk, iterations=iters)
            dec = td / f"case_{size}.dec"
            decrypt_file(enc, dec, pw)
            cases.append((f"往返测试 size={size}", dec.read_bytes() == data))
            cases.append((f"文件头魔数 size={size}", enc.read_bytes()[:4] == MAGIC))
        # 2) 错误密码拒绝
        src = td / "wrong.bin"
        src.write_bytes("hello 世界，机密数据".encode("utf-8"))
        enc = Path(str(src) + ENC_SUFFIX)
        encrypt_file(src, enc, pw, chunk_size=chunk, iterations=iters)
        try:
            decrypt_file(enc, td / "wrong.dec", "错误密码!")
            cases.append(("错误密码拒绝", False))
        except GuardError:
            cases.append(("错误密码拒绝", True))
        # 3) 篡改检测（选取大文件，篡改其数据区字节）
        big_enc = Path(str(td / "case_700000.bin") + ENC_SUFFIX)
        blob = bytearray(big_enc.read_bytes())
        blob[HEADER_LEN + 10] ^= 0xFF
        bad = td / "tampered.ufg"
        bad.write_bytes(bytes(blob))
        try:
            decrypt_file(bad, td / "tampered.dec", pw)
            cases.append(("篡改检测", False))
        except GuardError:
            cases.append(("篡改检测", True))
        # 4) 截断检测
        raw = big_enc.read_bytes()
        cut = td / "truncated.ufg"
        cut.write_bytes(raw[: len(raw) // 2])
        try:
            decrypt_file(cut, td / "truncated.dec", pw)
            cases.append(("截断检测", False))
        except GuardError:
            cases.append(("截断检测", True))

        # 5) 文件夹打包加密往返：建树 → 打包 → 还原 → 逐文件比对
        vf = td / "资料夹"
        (vf / "子目录/深层").mkdir(parents=True)
        (vf / "空目录").mkdir()
        (vf / "报告.txt").write_text("机密报告内容", encoding="utf-8")
        (vf / "子目录/图.jpg").write_bytes(b"\xff\xd8jpgdata" * 100)
        (vf / "子目录/深层/数据.bin").write_bytes(secrets.token_bytes(12345))
        vault_enc = encrypt_folder_vault(vf, pw, remove_original=False,
                                         chunk_size=chunk, iterations=iters, yes=True,
                                         log=lambda *a, **k: None)
        ok_enc = vault_enc == 0 and (td / "资料夹.ufg").is_file() \
            and peek_magic(td / "资料夹.ufg") == MAGIC_VAULT
        cases.append(("文件夹打包加密", ok_enc))
        cases.append(("文件夹名隐藏(原文件夹保留时仍可见)", vf.is_dir()))
        # 模拟真实流程：打包加密后删除原文件夹，仅留一个加密文件
        shutil.rmtree(vf)
        # 错误密码应被拒绝且不产生还原目录
        try:
            decrypt_vault(td / "资料夹.ufg", "错误密码!")
            cases.append(("文件夹包错误密码拒绝", False))
        except GuardError:
            cases.append(("文件夹包错误密码拒绝", not (td / "资料夹").exists()))
        # 正确密码还原，比对内容
        decrypt_vault(td / "资料夹.ufg", pw)
        back = td / "资料夹"
        same = ((back / "报告.txt").read_text(encoding="utf-8") == "机密报告内容"
                and (back / "子目录/图.jpg").read_bytes() == (vf / "子目录/图.jpg").read_bytes()
                and (back / "子目录/深层/数据.bin").read_bytes()
                == (vf / "子目录/深层/数据.bin").read_bytes()
                and (back / "空目录").is_dir())
        cases.append(("文件夹解包还原(含中文/深层/空目录)", same))
        # 防路径攻击条目应被跳过
        evil = td / "evil.ufg"
        zf_payload = td / "evil.zip"
        with zipfile.ZipFile(zf_payload, "w") as zfw:
            zfw.writestr("../evil.txt", "bad")
        encrypt_file(zf_payload, evil, pw, chunk_size=chunk, iterations=iters,
                     magic=MAGIC_VAULT)
        try:
            decrypt_vault(evil, pw)
            evil_ok = not (td / "evil.txt").exists() and not (td / "资料夹/evil.txt").exists()
        except GuardError:
            evil_ok = True
        cases.append(("解包路径安全(Zip Slip防护)", evil_ok))
        # 再解密一次：覆盖模式 + 成功后删除加密包
        decrypt_vault(td / "资料夹.ufg", pw, remove_original=True, overwrite=True)
        cases.append(("文件夹覆盖模式还原", back.is_dir() and not (td / "资料夹.ufg").exists()))

    all_ok = True
    for name, passed in cases:
        print(f"  [{'通过' if passed else '失败'}] {name}")
        all_ok = all_ok and passed
    print("自检结果: " + ("全部通过" if all_ok else "存在失败项！"))
    return 0 if all_ok else 1


# ---------------- 图形界面 ----------------
def run_gui() -> int:
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
        from tkinter.scrolledtext import ScrolledText
    except ImportError:
        print("未找到 tkinter，无法启动图形界面。请安装带 Tk 支持的 Python，或使用命令行模式。")
        return 1
    if not _HAS_CRYPTO:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(APP_NAME, "缺少加密库 cryptography：\n\n"
                             "pip install cryptography\n\n安装后重新启动程序。")
        root.destroy()
        return 1

    import queue as _queue
    import threading

    root = tk.Tk()
    root.title(f"{APP_NAME} v{__version__}")
    frm = ttk.Frame(root, padding=12)
    frm.grid(row=0, column=0, sticky="nsew")
    root.columnconfigure(0, weight=1)
    frm.columnconfigure(1, weight=1)

    mode = tk.StringVar(value="encrypt")
    path_var = tk.StringVar()
    pw_var = tk.StringVar()
    pw2_var = tk.StringVar()
    ext_var = tk.StringVar()
    remove_var = tk.BooleanVar(value=False)
    over_var = tk.BooleanVar(value=False)
    vault_var = tk.BooleanVar(value=True)  # 文件夹打包模式（文件夹→单个加密文件）
    q = _queue.Queue()
    busy = {"flag": False}

    def log_write(msg):
        output.configure(state="normal")
        output.insert("end", msg + "\n")
        output.see("end")
        output.configure(state="disabled")

    def on_mode_change():
        enc = mode.get() == "encrypt"
        pw2_entry.configure(state="normal" if enc else "disabled")
        ext_entry.configure(state="normal" if enc else "disabled")
        if not enc:
            pw2_var.set("")
        try:
            vault_cb.configure(state="normal" if enc else "disabled")
        except NameError:
            pass  # 布局尚未创建完成（初始化阶段）

    def browse_dir():
        d = filedialog.askdirectory(title="选择U盘或目录")
        if d:
            path_var.set(d)

    def browse_file():
        f = filedialog.askopenfilename(title="选择文件")
        if f:
            path_var.set(f)

    def browse_drive():
        drives = list_removable_drives()
        if not drives:
            messagebox.showinfo(APP_NAME, "未检测到可移动磁盘（U盘）。")
            return
        if len(drives) == 1:
            path_var.set(drives[0][0])
            return
        top = tk.Toplevel(root)
        top.title("选择U盘")
        top.transient(root)
        ttk.Label(top, text="请选择要操作的U盘:").pack(padx=14, pady=(10, 4), anchor="w")
        var = tk.StringVar(value=drives[0][0])
        for mp, total, _free in drives:
            cap = f"（总容量 {human_size(total)}）" if total else ""
            ttk.Radiobutton(top, text=f"{mp} {cap}", value=mp,
                            variable=var).pack(anchor="w", padx=18)

        def _ok():
            path_var.set(var.get())
            top.destroy()

        ttk.Button(top, text="确定", command=_ok).pack(pady=10)

    def start():
        if busy["flag"]:
            return
        p = path_var.get().strip().strip('"').strip("'")
        if not p:
            messagebox.showwarning(APP_NAME, "请先选择目标文件或目录。")
            return
        target = Path(p)
        if not target.exists():
            messagebox.showerror(APP_NAME, f"路径不存在:\n{p}")
            return
        pw = pw_var.get()
        if not pw:
            messagebox.showwarning(APP_NAME, "请输入密码。")
            return
        act = mode.get()
        verb = "加密" if act == "encrypt" else "解密"
        if act == "encrypt" and pw != pw2_var.get():
            messagebox.showerror(APP_NAME, "两次输入的密码不一致。")
            return
        # 文件夹打包模式：整个文件夹 → 单个加密文件
        if act == "encrypt" and vault_var.get():
            if not target.is_dir():
                messagebox.showwarning(
                    APP_NAME,
                    "打包模式需要选择文件夹。\n加密单个文件请取消勾选「文件夹打包为一个加密文件」。")
                return
            remove = remove_var.get()
            msg = (f"将把整个文件夹打包加密为一个加密文件：\n"
                   f"{target.name}{ENC_SUFFIX}\n\n"
                   "文件夹名与内部结构将全部隐藏。\n"
                   + ("确认后，原文件夹将在加密成功后被删除！"
                      if remove else "加密成功后保留原文件夹。"))
            if not messagebox.askyesno(APP_NAME, msg):
                return
            busy["flag"] = True
            start_btn.configure(state="disabled")
            bar["value"] = 0
            log_write(f"== 开始打包加密 {target.name} ==")
            threading.Thread(target=worker_vault, daemon=True,
                             args=(p, pw, remove, over_var.get())).start()
            return
        try:
            if act == "encrypt":
                files = collect_encrypt_targets(target, normalize_exts(ext_var.get()))
            else:
                files = collect_decrypt_targets(target)
        except GuardError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        if not files:
            messagebox.showinfo(APP_NAME, "没有找到需要处理的文件。")
            return
        if len(files) > 5 and not messagebox.askyesno(APP_NAME, f"共找到 {len(files)} 个文件，确认开始{verb}?"):
            return
        busy["flag"] = True
        start_btn.configure(state="disabled")
        bar["value"] = 0
        log_write(f"== 开始{verb}，共 {len(files)} 个文件 ==")
        threading.Thread(target=worker, daemon=True,
                         args=(act, files, pw, remove_var.get(), over_var.get())).start()

    def worker(act, files, pw, remove, overwrite):
        def glog(msg):
            q.put(("log", msg))

        def gfactory(name, total):
            if total < LARGE_FILE_PROGRESS:
                return None, None

            def cb(done, tot):
                q.put(("progress", name, int(done * 100 / tot) if tot else 100))
            return cb, None

        try:
            ok, fail, skip = run_batch(act, files, pw,
                                       chunk_size=parse_chunk(DEFAULT_CHUNK_MB),
                                       iterations=DEFAULT_ITERATIONS,
                                       overwrite=overwrite, remove_original=remove,
                                       log=glog, progress_factory=gfactory)
            q.put(("done", ok, fail, skip))
        except Exception as exc:  # 兜底，避免线程静默失败
            q.put(("log", f"发生异常: {exc}"))
            q.put(("done", 0, 1, 0))

    def worker_vault(p, pw, remove, overwrite):
        def glog(msg):
            q.put(("log", msg))

        def gfactory(name, total):
            if not total or total < LARGE_FILE_PROGRESS:
                return None, None

            def cb(done, tot):
                q.put(("progress", name, int(done * 100 / tot) if tot else 100))
            return cb, None

        try:
            rc = encrypt_folder_vault(p, pw, remove_original=remove,
                                      overwrite=overwrite,
                                      chunk_size=parse_chunk(DEFAULT_CHUNK_MB),
                                      iterations=DEFAULT_ITERATIONS,
                                      yes=True, log=glog,
                                      progress_factory=gfactory)
            q.put(("done", 1 if rc == 0 else 0, 0 if rc == 0 else 1, 0))
        except Exception as exc:  # 兜底，避免线程静默失败
            q.put(("log", f"发生异常: {exc}"))
            q.put(("done", 0, 1, 0))

    def poll():
        try:
            while True:
                msg = q.get_nowait()
                kind = msg[0]
                if kind == "log":
                    log_write(str(msg[1]))
                elif kind == "progress":
                    bar["value"] = msg[2]
                elif kind == "done":
                    _, ok, fail, skip = msg
                    bar["value"] = 0
                    log_write(f"== 处理结束: 成功 {ok}，跳过 {skip}，失败 {fail} ==")
                    if fail:
                        messagebox.showwarning(APP_NAME, f"处理完成，但有 {fail} 个文件失败，详情见日志。")
                    busy["flag"] = False
                    start_btn.configure(state="normal")
        except _queue.Empty:
            pass
        root.after(120, poll)

    def clear_log():
        output.configure(state="normal")
        output.delete("1.0", "end")
        output.configure(state="disabled")

    # ------- 布局 -------
    ttk.Label(frm, text="操作:").grid(row=0, column=0, sticky="e", pady=3)
    mode_frame = ttk.Frame(frm)
    mode_frame.grid(row=0, column=1, sticky="w", pady=3)
    ttk.Radiobutton(mode_frame, text="加密", variable=mode, value="encrypt",
                    command=on_mode_change).pack(side="left")
    ttk.Radiobutton(mode_frame, text="解密", variable=mode, value="decrypt",
                    command=on_mode_change).pack(side="left", padx=10)

    ttk.Label(frm, text="目标:").grid(row=1, column=0, sticky="e", pady=3)
    ttk.Entry(frm, textvariable=path_var, width=44).grid(row=1, column=1, sticky="we", pady=3)
    side = ttk.Frame(frm)
    side.grid(row=1, column=2, sticky="w", padx=4)
    btns = ttk.Frame(side)
    btns.pack()
    ttk.Button(btns, text="U盘…", command=browse_drive).pack(side="left")
    ttk.Button(btns, text="目录…", command=browse_dir).pack(side="left", padx=4)
    ttk.Button(btns, text="文件…", command=browse_file).pack(side="left", padx=4)
    scope_var = tk.StringVar()
    ttk.Label(side, textvariable=scope_var, foreground="#555").pack(anchor="w", pady=(2, 0))

    def describe_scope(path_str: str) -> str:
        """根据目标路径自动识别加密层级: 整个U盘 / 文件夹 / 单个文件。"""
        if not path_str.strip():
            return ""
        p = Path(path_str)
        try:
            if p.exists():
                root = str(p).rstrip("\\/").lower()
                drives = {str(mp).rstrip("\\/").lower()
                          for mp, _t, _f in list_removable_drives()}
                if root in drives:
                    return "层级①: 整个U盘（含全部子目录）"
                if p.is_dir():
                    return "层级②: 指定文件夹（打包为单文件 或 逐文件，见下方选项）"
                if p.is_file():
                    return "层级③: 指定文件"
        except OSError:
            pass
        return "范围: 路径无效"

    def _update_scope(*_a):
        scope_var.set(describe_scope(path_var.get()))

    path_var.trace("w", _update_scope)
    _update_scope()

    ttk.Label(frm, text="密码:").grid(row=2, column=0, sticky="e", pady=3)
    ttk.Entry(frm, textvariable=pw_var, show="*", width=24).grid(
        row=2, column=1, sticky="w", pady=3)

    ttk.Label(frm, text="确认密码:").grid(row=3, column=0, sticky="e", pady=3)
    pw2_entry = ttk.Entry(frm, textvariable=pw2_var, show="*", width=24)
    pw2_entry.grid(row=3, column=1, sticky="w", pady=3)

    ttk.Label(frm, text="扩展名过滤:").grid(row=4, column=0, sticky="e", pady=3)
    ext_entry = ttk.Entry(frm, textvariable=ext_var, width=24)
    ext_entry.grid(row=4, column=1, sticky="w", pady=3)
    ttk.Label(frm, text="（仅加密时有效，如 .docx,.jpg；空=全部）").grid(
        row=4, column=2, sticky="w")

    vault_cb = ttk.Checkbutton(
        frm, text="文件夹打包为一个加密文件（文件夹名也隐藏，仅加密时有效）",
        variable=vault_var)
    vault_cb.grid(row=5, column=1, sticky="w", pady=3)
    opt = ttk.Frame(frm)
    opt.grid(row=6, column=1, sticky="w", pady=3)
    ttk.Checkbutton(opt, text="成功后删除原文件/原文件夹", variable=remove_var).pack(side="left")
    ttk.Checkbutton(opt, text="覆盖已存在的输出文件", variable=over_var).pack(side="left", padx=10)

    start_btn = ttk.Button(frm, text="开始", command=start)
    start_btn.grid(row=7, column=1, sticky="w", pady=6)
    ttk.Button(frm, text="清空日志", command=clear_log).grid(row=7, column=2, sticky="w", pady=6)
    bar = ttk.Progressbar(frm, length=200, mode="determinate", maximum=100)
    bar.grid(row=7, column=1, sticky="e", pady=6)

    output = ScrolledText(frm, width=72, height=15, state="disabled", font=("TkFixedFont",))
    output.grid(row=8, column=0, columnspan=3, sticky="nsew", pady=(8, 0))

    log_write("提示: 文件/文件夹加密后变为 *.ufg，解密时自动还原（文件夹包会还原出完整文件夹）。")
    log_write("请牢记密码——忘记密码将无法恢复。建议先在少量文件上试用，确认无误后再批量处理。")
    on_mode_change()
    poll()
    root.mainloop()
    return 0


# ---------------- 交互模式 ----------------
def interactive_pick_drive():
    """交互模式选择U盘：返回路径或 None。"""
    drives = list_removable_drives()
    if not drives:
        return None
    print("检测到可移动磁盘:")
    for i, (mp, total, free) in enumerate(drives, 1):
        cap = f"（总容量 {human_size(total)}，可用 {human_size(free)}）" if total else ""
        print(f"  {i}) {mp} {cap}")
    raw = prompt_path(f"请选择要操作的U盘 [1-{len(drives)}，回车=1]（或直接输入路径）: ")
    if raw is None:
        return None
    if raw == "":
        return drives[0][0]
    if raw.isdigit() and 1 <= int(raw) <= len(drives):
        return drives[int(raw) - 1][0]
    return raw


def interactive_encrypt_drive():
    drive = interactive_pick_drive()
    if not drive:
        print("未检测到U盘；如需加密文件夹请用菜单 2 或 3，加密文件用菜单 4。")
        return
    ext = input("仅加密指定扩展名(逗号分隔，如 .docx,.jpg；回车=全部): ").strip() or None
    remove = ask_yesno("加密成功后删除原文件?（U盘内容将不可恢复，请先备份）")
    password = get_password(argparse.Namespace(password=None), confirm=True)
    drive_action("encrypt", drive, password, ext=ext, remove_original=remove, yes=True)


def interactive_encrypt_folder_vault():
    """整个文件夹打包加密 → 单个 .ufg 文件（文件夹名也隐藏）。"""
    p = prompt_path("请输入要加密的文件夹路径(如 E:/资料，回车取消): ")
    if not p:
        return
    if not Path(p).is_dir():
        print(f"错误: 该路径不是文件夹: {p}")
        return
    remove = ask_yesno("加密成功后删除原文件夹?（原文件夹将被一个加密文件取代）", default=True)
    password = get_password(argparse.Namespace(password=None), confirm=True)
    encrypt_folder_vault(p, password, remove_original=remove, yes=True)


def interactive_encrypt_folder():
    """逐文件加密指定文件夹（保留文件夹名，含子目录）。"""
    p = prompt_path("请输入要加密的文件夹路径(如 E:/资料，回车取消): ")
    if not p:
        return
    if not Path(p).is_dir():
        print(f"错误: 该路径不是文件夹: {p}")
        return
    ext = input("仅加密指定扩展名(逗号分隔，如 .docx,.jpg；回车=全部): ").strip() or None
    remove = ask_yesno("加密成功后删除原文件?")
    password = get_password(argparse.Namespace(password=None), confirm=True)
    encrypt_path(p, password, ext=ext, remove_original=remove, yes=True)


def interactive_encrypt_file():
    """层级③: 加密一个或多个指定文件。"""
    files = []
    while True:
        p = prompt_path("请输入要加密的文件路径（回车结束选择）: ")
        if not p:
            break
        if not Path(p).is_file():
            print(f"错误: 该路径不是文件: {p}")
            continue
        files.append(p)
        if not ask_yesno("再添加一个文件?"):
            break
    if not files:
        print("未选择任何文件。")
        return
    remove = ask_yesno("加密成功后删除原文件?")
    password = get_password(argparse.Namespace(password=None), confirm=True)
    for f in files:
        try:
            encrypt_path(f, password, ext=None, remove_original=remove, yes=True)
        except GuardError as exc:
            print(f"错误: {exc}")


def interactive_decrypt():
    p = prompt_path("请输入要解密的U盘/文件夹/.ufg文件(直接回车=自动检测U盘): ")
    if not p:
        drive = interactive_pick_drive()
        if not drive:
            print("未检测到U盘；请输入要解密的文件夹或 .ufg 文件路径。")
            return
        password = get_password(argparse.Namespace(password=None), confirm=False)
        remove = ask_yesno("解密成功后删除加密文件(.ufg)?")
        drive_action("decrypt", drive, password, remove_original=remove, yes=True)
        return
    password = get_password(argparse.Namespace(password=None), confirm=False)
    remove = ask_yesno("解密成功后删除加密文件(.ufg)?")
    decrypt_path(p, password, remove_original=remove, yes=True)


def interactive() -> int:
    print("=" * 52)
    print(f"  {APP_NAME}  v{__version__}")
    print("=" * 52)
    print("范围: ① 整个U盘  ② 整个文件夹打包(推荐)  ③ 文件夹内逐文件  ④ 指定文件\n")
    while True:
        print("== 加密 ==")
        print("  1) 整个U盘        逐文件加密全部文件（文件夹名保留）")
        print("  2) 整个文件夹打包  文件夹 → 一个加密文件（文件夹名也隐藏）★")
        print("  3) 文件夹内文件    逐文件加密（文件夹名保留，含子目录）")
        print("  4) 指定文件        加密一个或多个文件")
        print("== 解密 ==")
        print("  5) 解密            自动识别U盘/文件夹包/加密文件")
        print("== 工具 ==")
        print("  6) 检测U盘   7) 扫描目录   8) 自检   0) 退出")
        try:
            choice = input("请选择: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n再见。")
            return 0
        try:
            if choice == "1":
                interactive_encrypt_drive()
            elif choice == "2":
                interactive_encrypt_folder_vault()
            elif choice == "3":
                interactive_encrypt_folder()
            elif choice == "4":
                interactive_encrypt_file()
            elif choice == "5":
                interactive_decrypt()
            elif choice == "6":
                cmd_drives()
            elif choice == "7":
                p = prompt_path("请输入要扫描的目录(如 E:/资料 或 /media/usb): ")
                if p:
                    scan_path(p)
            elif choice == "8":
                cmd_selftest()
            elif choice in ("0", "q", "Q", "exit", "退出"):
                print("再见。")
                return 0
            else:
                print("无效选择，请重新输入。")
        except GuardError as exc:
            print(f"错误: {exc}")
        print()


# ---------------- 命令行入口 ----------------
def cmd_drives(_args=None) -> int:
    drives = list_removable_drives()
    if not drives:
        print("未检测到可移动磁盘（U盘）。")
        print("提示: 也可直接对任意目录使用 scan / encrypt / decrypt 命令。")
        return 0
    print(f"检测到 {len(drives)} 个可移动磁盘:")
    for mp, total, free in drives:
        if total is not None:
            print(f"  {mp:<14} 总容量 {human_size(total):>9}   可用 {human_size(free):>9}")
        else:
            print(f"  {mp}")
    return 0


def cmd_scan(args) -> int:
    return scan_path(args.path)


def cmd_encrypt(args) -> int:
    return encrypt_path(args.path, get_password(args, confirm=True),
                        ext=args.ext, remove_original=args.remove_original,
                        yes=args.yes, overwrite=args.overwrite,
                        chunk_mb=args.chunk_mb, iterations=args.iterations)


def cmd_decrypt(args) -> int:
    return decrypt_path(args.path, get_password(args, confirm=False),
                        remove_original=args.remove_original, yes=args.yes,
                        overwrite=args.overwrite)


def cmd_vault(args) -> int:
    return encrypt_folder_vault(args.path, get_password(args, confirm=True),
                                remove_original=args.remove_original,
                                yes=args.yes, overwrite=args.overwrite,
                                chunk_size=parse_chunk(args.chunk_mb),
                                iterations=args.iterations)


def cmd_encrypt_drive(args) -> int:
    return drive_action("encrypt", args.drive, get_password(args, confirm=True),
                        ext=args.ext, remove_original=args.remove_original,
                        yes=args.yes, overwrite=args.overwrite,
                        chunk_mb=args.chunk_mb, iterations=args.iterations)


def cmd_decrypt_drive(args) -> int:
    return drive_action("decrypt", args.drive, get_password(args, confirm=False),
                        remove_original=args.remove_original, yes=args.yes,
                        overwrite=args.overwrite)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="usb_file_guard",
        description=f"{APP_NAME} v{__version__} —— 对U盘指定文件进行 AES-256-GCM 加密/解密",
        epilog="示例:\n"
               "  python usb_file_guard.py                                交互模式\n"
               "  python usb_file_guard.py drives                         检测U盘\n"
               "  python usb_file_guard.py scan E:/资料                   扫描目录\n"
               "  python usb_file_guard.py vault E:/资料                  文件夹打包加密为一个文件\n"
               "  python usb_file_guard.py encrypt E:/资料 -e .docx,.xlsx  逐文件加密\n"
               "  python usb_file_guard.py decrypt E:/资料                解密（自动识别文件夹包）\n"
               "  python usb_file_guard.py encrypt-drive                  一键整盘加密U盘\n"
               "  python usb_file_guard.py decrypt-drive E:/              一键整盘解密\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("drives", help="检测并列出可移动磁盘(U盘)")
    p.set_defaults(func=cmd_drives)

    p = sub.add_parser("scan", help="扫描目录，统计普通/已加密文件")
    p.add_argument("path", help="要扫描的U盘或目录路径")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("encrypt", help="加密指定文件或目录")
    p.add_argument("path", help="文件或目录路径")
    p.add_argument("-p", "--password", help="密码（不传则交互输入；命令行传入可能残留历史记录）")
    p.add_argument("-e", "--ext", help="仅加密指定扩展名，如 .docx,.jpg（默认全部）")
    p.add_argument("--remove-original", action="store_true", help="加密成功后删除原文件")
    p.add_argument("--overwrite", action="store_true", help="同名加密文件已存在时覆盖")
    p.add_argument("-y", "--yes", action="store_true", help="跳过执行前确认")
    p.add_argument("--chunk-mb", type=float, default=DEFAULT_CHUNK_MB,
                   help=f"分块大小 MiB（默认 {DEFAULT_CHUNK_MB:g}）")
    p.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS,
                   help=f"PBKDF2 迭代次数（默认 {DEFAULT_ITERATIONS}）")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt", help="解密指定文件或目录")
    p.add_argument("path", help="加密文件或目录路径")
    p.add_argument("-p", "--password", help="密码（不传则交互输入）")
    p.add_argument("--remove-original", action="store_true", help="解密成功后删除加密文件")
    p.add_argument("--overwrite", action="store_true", help="同名输出文件已存在时覆盖")
    p.add_argument("-y", "--yes", action="store_true", help="跳过执行前确认")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("vault",
                       help="把整个文件夹打包加密为一个 .ufg 文件（文件夹名也隐藏）")
    p.add_argument("path", help="要打包加密的文件夹路径")
    p.add_argument("-p", "--password", help="密码（不传则交互输入；命令行传入可能残留历史记录）")
    p.add_argument("--remove-original", action="store_true",
                   help="加密成功后删除原文件夹（交互确认时可再选择）")
    p.add_argument("--overwrite", action="store_true", help="同名加密文件已存在时覆盖")
    p.add_argument("-y", "--yes", action="store_true", help="跳过执行前确认")
    p.add_argument("--chunk-mb", type=float, default=DEFAULT_CHUNK_MB,
                   help=f"分块大小 MiB（默认 {DEFAULT_CHUNK_MB:g}）")
    p.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS,
                   help=f"PBKDF2 迭代次数（默认 {DEFAULT_ITERATIONS}）")
    p.set_defaults(func=cmd_vault)

    p = sub.add_parser("selftest", help="运行加密/解密自检")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("encrypt-drive",
                       help="一键加密整个U盘（含全部子目录；省略U盘路径则自动检测）")
    p.add_argument("drive", nargs="?", default=None,
                   help="U盘路径（如 E:/；省略时自动检测，多个U盘会提示选择）")
    p.add_argument("-p", "--password", help="密码（不传则交互输入；命令行传入可能残留历史记录）")
    p.add_argument("-e", "--ext", help="仅加密指定扩展名，如 .docx,.jpg（默认全部）")
    p.add_argument("--remove-original", action="store_true", help="加密成功后删除原文件")
    p.add_argument("--overwrite", action="store_true", help="同名加密文件已存在时覆盖")
    p.add_argument("-y", "--yes", action="store_true", help="跳过执行前确认")
    p.add_argument("--chunk-mb", type=float, default=DEFAULT_CHUNK_MB,
                   help=f"分块大小 MiB（默认 {DEFAULT_CHUNK_MB:g}）")
    p.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS,
                   help=f"PBKDF2 迭代次数（默认 {DEFAULT_ITERATIONS}）")
    p.set_defaults(func=cmd_encrypt_drive)

    p = sub.add_parser("decrypt-drive",
                       help="一键解密整个U盘（还原全部 .ufg 文件；省略U盘路径则自动检测）")
    p.add_argument("drive", nargs="?", default=None,
                   help="U盘路径（如 E:/；省略时自动检测，多个U盘会提示选择）")
    p.add_argument("-p", "--password", help="密码（不传则交互输入）")
    p.add_argument("--remove-original", action="store_true", help="解密成功后删除加密文件")
    p.add_argument("--overwrite", action="store_true", help="同名输出文件已存在时覆盖")
    p.add_argument("-y", "--yes", action="store_true", help="跳过执行前确认")
    p.set_defaults(func=cmd_decrypt_drive)

    p = sub.add_parser("gui", help="启动图形界面（需要桌面环境）")
    p.set_defaults(func=lambda a: run_gui())
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not _HAS_CRYPTO and try_install_crypto():
        # 安装成功后重启进程，重新加载加密库
        os.execv(sys.executable, [sys.executable] + list(sys.argv))
    try:
        if args.cmd is None:
            if not _HAS_CRYPTO:
                print(f"错误: {CRYPTO_HINT}")
                return 1
            return interactive()
        return args.func(args)
    except GuardError as exc:
        print(f"错误: {exc}")
        return 1
    except KeyboardInterrupt:
        print("\n已取消。")
        return 130


if __name__ == "__main__":
    sys.exit(main())
