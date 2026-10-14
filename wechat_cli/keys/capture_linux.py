"""Linux 显式 GDB 捕获；只适配 MIT 上游已证实的 x86_64 特征。

定位及参数布局参考 TANGandXUE/wcdb-key-tool 的 wcdb_key_tool.py。
未采用上游的权限修改、全局 killall、明文日志和 passphrase 落盘。

MIT License
Copyright (c) 2025 CloudDreamAI / TANGandXUE
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import hashlib
import math
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess

from .common import verify_enc_key
from .cipher_config import CONFIG_CIPHER_NAME


class CaptureError(RuntimeError):
    """不包含候选数据的捕获错误。"""


def _load_elf(binary_path):
    data = Path(binary_path).read_bytes()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise CaptureError("仅支持 ELF64 小端序")
    header = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    etype, machine, _, _, phoff, shoff, _, _, phsize, phnum, shsize, shnum, names_idx = header
    if machine != 62:
        raise CaptureError("GDB 捕获仅支持 x86_64；未实现 ARM64 参数布局")
    if etype not in (2, 3) or shsize != 64 or phsize != 56:
        raise CaptureError("不支持的 ELF 布局")

    def bounded(offset, size):
        if offset < 0 or size < 0 or offset + size > len(data):
            raise CaptureError("ELF 数据越界或截断")
        return data[offset:offset + size]

    bounded(shoff, shsize * shnum)
    bounded(phoff, phsize * phnum)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shsize)
                for i in range(shnum)]
    if not 0 <= names_idx < shnum:
        raise CaptureError("ELF 节名表无效")
    names = bounded(sections[names_idx][4], sections[names_idx][5])
    result = {}
    for section in sections:
        name_offset, kind, _, va, offset, size = section[:6]
        if name_offset >= len(names):
            raise CaptureError("ELF 节名越界")
        end = names.find(b"\0", name_offset)
        if end < 0:
            raise CaptureError("ELF 节名缺少终止符")
        name = names[name_offset:end].decode("utf-8", errors="replace")
        if name in (".text", ".rodata"):
            if kind != 1:
                raise CaptureError("ELF 必要节类型不支持")
            result[name] = (va, bounded(offset, size))
    loads = []
    for i in range(phnum):
        kind, flags, offset, va, _, filesz, memsz, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + i * phsize)
        if kind == 1:
            bounded(offset, filesz)
            if filesz > memsz:
                raise CaptureError("ELF 加载段无效")
            loads.append((offset, va, memsz, flags))
    return result, loads


def _refs(text, va, opcode, target):
    return [offset for offset in range(max(0, len(text) - 6))
            if text[offset:offset + 3] == opcode
            and va + offset + 7 + struct.unpack_from("<i", text, offset + 3)[0] == target]


def find_hook_offset(binary_path):
    """返回静态虚拟地址；歧义时拒绝任意挑选，避免错误断点。"""
    sections, _ = _load_elf(binary_path)
    if ".text" not in sections or ".rodata" not in sections:
        raise CaptureError("ELF 缺少 .text 或 .rodata")
    text_va, text = sections[".text"]
    ro_va, rodata = sections[".rodata"]
    candidates = set()
    start = 0
    while True:
        anchor = rodata.find(CONFIG_CIPHER_NAME, start)
        if anchor < 0:
            break
        start = anchor + 1
        for first in _refs(text, text_va, b"\x48\x8d\x35", ro_va + anchor):
            if first < 7 or text[first - 7:first - 4] != b"\x48\x8d\x3d":
                continue
            target = text_va + first + struct.unpack_from("<i", text, first - 4)[0]
            for second in _refs(text, text_va, b"\x48\x8d\x35", target):
                for pos in range(second, max(0, second - 0x500) - 1, -1):
                    if text[pos:pos + 3] == b"\x55\x41\x57":
                        candidates.add(text_va + pos)
                        break
    if len(candidates) != 1:
        raise CaptureError("ELF 捕获特征缺失或存在歧义，不支持此布局")
    return candidates.pop()


def find_runtime_base(pid, binary_path, maps_text=None):
    """按 PT_LOAD 文件偏移/虚拟地址计算加载偏移，兼容 PIE 与 ET_EXEC。"""
    _, loads = _load_elf(binary_path)
    path = os.path.realpath(binary_path)
    if maps_text is None:
        maps_text = Path(f"/proc/{pid}/maps").read_text()
    # 当前仅支持 Linux x86_64，其基础映射页为 4 KiB，不能使用 macOS 宿主页大小。
    page = 4096
    biases = set()
    for line in maps_text.splitlines():
        parts = line.split(maxsplit=5)
        if len(parts) != 6 or os.path.realpath(parts[5]) != path or "x" not in parts[1]:
            continue
        start = int(parts[0].split("-")[0], 16)
        file_offset = int(parts[2], 16)
        for offset, va, size, flags in loads:
            aligned_offset = offset // page * page
            aligned_va = va // page * page
            if flags & 1 and aligned_offset <= file_offset < offset + size:
                biases.add(start - aligned_va - (file_offset - aligned_offset))
    if len(biases) != 1:
        raise CaptureError("无法唯一确定 ELF 运行时加载偏移")
    return biases.pop()


def _gdb_script(pid, address, candidate_fd):
    # 两种参数布局都来自上游，仅在 32 字节长度成立时读取。
    return f'''set pagination off
set confirm off
set print thread-events off
attach {pid}
python
import gdb, os, struct
class CaptureBreakpoint(gdb.Breakpoint):
    def stop(self):
        try:
            pointer = int(gdb.parse_and_eval("$rsi"))
            length = int(gdb.parse_and_eval("$rdx"))
            inferior = gdb.selected_inferior()
            if not pointer:
                return False
            if length != 32:
                obj = inferior.read_memory(pointer + 8, 16).tobytes()
                pointer, length = struct.unpack("<QQ", obj)
            if pointer and length == 32:
                raw = inferior.read_memory(pointer, 32).tobytes()
                os.write({candidate_fd}, raw)
                return True
        except Exception:
            pass
        return False
bp = CaptureBreakpoint("*{address:#x}")
try:
    gdb.execute("continue")
finally:
    bp.delete()
    gdb.execute("detach")
end
quit
'''


def capture_passphrase(pid, timeout=120):
    """显式附加已运行进程；候选仅通过匿名管道传输，不打印或落盘。"""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise ValueError("pid 必须为正整数")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout 必须为有限正数")
    gdb = shutil.which("gdb")
    if not gdb:
        raise CaptureError("未安装 GDB，显式捕获不可用")
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        if any(line.startswith("TracerPid:") and int(line.split(":")[1])
               for line in status.splitlines()):
            raise CaptureError("目标进程已有调试器，拒绝附加")
        binary = os.readlink(f"/proc/{pid}/exe")
        address = find_runtime_base(pid, binary) + find_hook_offset(binary)
    except OSError:
        raise CaptureError("无法读取目标进程信息；请检查当前读取权限及进程状态") from None
    read_fd, write_fd = os.pipe()
    proc = None
    try:
        script = _gdb_script(pid, address, write_fd)
        proc = subprocess.Popen(
            [gdb, "--nx", "--nh", "-q", "-batch", "-x", "/dev/stdin"],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            pass_fds=(write_fd,),
        )
        os.close(write_fd)
        write_fd = -1
        try:
            proc.communicate(script.encode("utf-8"), timeout=timeout)
        except subprocess.TimeoutExpired:
            # 只中断本次 GDB，给 finally 删除断点及 detach 的机会。
            proc.send_signal(signal.SIGINT)
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
            raise CaptureError("GDB 捕获超时；断点未触发或布局不支持") from None
        raw = os.read(read_fd, 33)
        if proc.returncode != 0 or len(raw) != 32:
            raise CaptureError("GDB 未捕获有效候选；请检查实际附加权限、断点及触发状态")
        return raw
    except OSError:
        raise CaptureError("GDB 启动或候选管道失败") from None
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.communicate()
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def derive_keys_from_passphrase(passphrase, db_files, salt_to_dbs):
    """按每库 salt 派生 32 字节密钥，只返回 HMAC 验证通过的结果。"""
    if not isinstance(passphrase, bytes) or len(passphrase) != 32:
        raise ValueError("passphrase 必须为 32 字节")
    key_map = {}
    for salt in salt_to_dbs:
        candidate = hashlib.pbkdf2_hmac("sha512", passphrase, bytes.fromhex(salt),
                                       256000, dklen=32)
        for _, _, _, db_salt, page in db_files:
            if db_salt == salt and len(page) == 4096 and verify_enc_key(candidate, page):
                key_map[salt] = candidate.hex()
                break
    return key_map
