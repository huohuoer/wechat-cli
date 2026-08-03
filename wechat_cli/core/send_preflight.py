"""发送 bridge 注入前的只读、fail-closed 环境校验。"""

from __future__ import annotations

import hashlib
import os
import platform
import plistlib
import stat
import struct
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from .sending import SendUnavailableError


EXPECTED_BUNDLE_PATH = Path("/Applications/WeChat.app")
EXPECTED_BUNDLE_ID = "com.tencent.xinWeChat"
EXPECTED_EXECUTABLE = "WeChat"
EXPECTED_SHORT_VERSION = "4.1.8"
EXPECTED_BUILD_VERSION = "36571"
EXPECTED_WECHAT_BUNDLE_VERSION = "4.1.8.28"
EXPECTED_DYLIB_RELATIVE_PATH = Path("Contents/Frameworks/wechat.dylib")
EXPECTED_DYLIB_SHA256 = (
    "b4a740135f3f1e937bca10caf0a95cff986ddf27fa6bb15ccaf64001fc651c93"
)
EXPECTED_DYLIB_UUID = "ABD88EC8-4590-3FDB-AAB5-4E5865B86B2A"

CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_MASK = 0x00FFFFFF
CPU_SUBTYPE_ARM64_ALL = 0
MH_EXECUTE = 0x2
MH_DYLIB = 0x6
LC_UUID = 0x1B
MAX_FAT_SLICES = 32
MAX_LOAD_COMMANDS = 65536
COMMAND_TIMEOUT_SECONDS = 3.0


class MachOError(ValueError):
    """Mach-O 结构无法被严格解析。"""


@dataclass(frozen=True)
class MachOSlice:
    cpu_type: int
    cpu_subtype: int
    file_type: int
    is_64: bool
    command_count: int
    uuid: str | None


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    uid: int
    started_at: str
    executable_path: Path


@dataclass(frozen=True)
class WeChatProfile:
    """已经完成全部注入前校验的目标信息。"""

    pid: int
    process_uid: int
    process_started_at: str
    bundle_id: str
    bundle_path: Path
    executable_path: Path
    arch: str
    short_version: str
    build_version: str
    wechat_bundle_version: str
    dylib_path: Path
    dylib_sha256: str
    dylib_uuid: str
    open_db_paths: tuple[Path, ...]


def _unpack(data: bytes, offset: int, fmt: str):
    size = struct.calcsize(fmt)
    end = offset + size
    if offset < 0 or end > len(data):
        raise MachOError("Mach-O 数据被截断")
    return struct.unpack_from(fmt, data, offset)


def _parse_thin(data: bytes) -> MachOSlice:
    if len(data) < 4:
        raise MachOError("Mach-O 头被截断")
    magic = data[:4]
    formats = {
        b"\xcf\xfa\xed\xfe": ("<", 32, True),
        b"\xfe\xed\xfa\xcf": (">", 32, True),
        b"\xce\xfa\xed\xfe": ("<", 28, False),
        b"\xfe\xed\xfa\xce": (">", 28, False),
    }
    try:
        endian, command_offset, is_64 = formats[magic]
    except KeyError as error:
        raise MachOError("不是受支持的 Mach-O slice") from error

    cpu_type = _unpack(data, 4, f"{endian}I")[0]
    cpu_subtype = _unpack(data, 8, f"{endian}I")[0]
    file_type = _unpack(data, 12, f"{endian}I")[0]
    command_count = _unpack(data, 16, f"{endian}I")[0]
    command_bytes = _unpack(data, 20, f"{endian}I")[0]
    if command_count > MAX_LOAD_COMMANDS:
        raise MachOError("Mach-O load command 数量异常")
    command_end = command_offset + command_bytes
    if command_end > len(data):
        raise MachOError("Mach-O load command 区域被截断")

    found_uuid = None
    offset = command_offset
    command_alignment = 8 if is_64 else 4
    for _ in range(command_count):
        command, size = _unpack(data, offset, f"{endian}II")
        if (
            size < 8
            or size % command_alignment != 0
            or offset + size > command_end
        ):
            raise MachOError("Mach-O load command 长度无效")
        if command == LC_UUID:
            if size != 24 or found_uuid is not None:
                raise MachOError("Mach-O LC_UUID 无效")
            raw_uuid = data[offset + 8 : offset + 24]
            if len(raw_uuid) != 16:
                raise MachOError("Mach-O LC_UUID 被截断")
            found_uuid = str(uuid.UUID(bytes=raw_uuid)).upper()
        offset += size
    if offset != command_end:
        raise MachOError("Mach-O load command 大小不一致")
    return MachOSlice(
        cpu_type=cpu_type,
        cpu_subtype=cpu_subtype,
        file_type=file_type,
        is_64=is_64,
        command_count=command_count,
        uuid=found_uuid,
    )


def parse_macho(data: bytes) -> tuple[MachOSlice, ...]:
    """解析 thin/FAT Mach-O，并返回每个 slice 的架构与 UUID。"""

    if len(data) < 4:
        raise MachOError("Mach-O 数据被截断")
    magic = data[:4]
    fat_formats = {
        b"\xca\xfe\xba\xbe": (">", False),
        b"\xbe\xba\xfe\xca": ("<", False),
        b"\xca\xfe\xba\xbf": (">", True),
        b"\xbf\xba\xfe\xca": ("<", True),
    }
    if magic not in fat_formats:
        return (_parse_thin(data),)

    endian, is_64 = fat_formats[magic]
    slice_count = _unpack(data, 4, f"{endian}I")[0]
    if not 1 <= slice_count <= MAX_FAT_SLICES:
        raise MachOError("Mach-O FAT slice 数量无效")
    entry_format = f"{endian}IIQQII" if is_64 else f"{endian}IIIII"
    entry_size = struct.calcsize(entry_format)
    table_end = 8 + slice_count * entry_size
    if table_end > len(data):
        raise MachOError("Mach-O FAT header 被截断")

    slices = []
    occupied = []
    for index in range(slice_count):
        values = _unpack(data, 8 + index * entry_size, entry_format)
        outer_cpu_type = values[0]
        outer_cpu_subtype = values[1]
        slice_offset = values[2]
        slice_size = values[3]
        slice_alignment = values[4]
        reserved = values[5] if is_64 else 0
        slice_end = slice_offset + slice_size
        if (
            slice_size == 0
            or slice_offset < table_end
            or slice_end > len(data)
            or slice_end < slice_offset
            or slice_alignment > 63
            or slice_offset % (1 << slice_alignment) != 0
        ):
            raise MachOError("Mach-O FAT slice 边界无效")
        if reserved != 0:
            raise MachOError("Mach-O FAT64 reserved 字段无效")
        if any(slice_offset < end and start < slice_end for start, end in occupied):
            raise MachOError("Mach-O FAT slice 重叠")
        occupied.append((slice_offset, slice_end))
        parsed = _parse_thin(data[slice_offset:slice_end])
        if (
            parsed.cpu_type != outer_cpu_type
            or parsed.cpu_subtype != outer_cpu_subtype
        ):
            raise MachOError("Mach-O FAT 架构声明不一致")
        slices.append(parsed)
    return tuple(slices)


def arm64_uuid(data: bytes) -> str:
    """取得唯一 arm64 slice 的 LC_UUID，缺失或重复时拒绝。"""

    arm64_slices = [item for item in parse_macho(data) if item.cpu_type == CPU_TYPE_ARM64]
    if len(arm64_slices) != 1:
        raise MachOError("Mach-O 必须恰好包含一个 arm64 slice")
    value = arm64_slices[0].uuid
    if value is None:
        raise MachOError("arm64 slice 缺少 LC_UUID")
    return value


def _default_command_runner(args: Sequence[str], *, timeout: float):
    return subprocess.run(
        list(args),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        shell=False,
    )


class PreflightInspector:
    """可注入依赖的 macOS 只读检查器。"""

    def __init__(
        self,
        *,
        system: Callable[[], str] = platform.system,
        machine: Callable[[], str] = platform.machine,
        euid: Callable[[], int] = os.geteuid,
        command_runner: Callable = _default_command_runner,
        expected_bundle_path: Path = EXPECTED_BUNDLE_PATH,
    ):
        self.system = system
        self.machine = machine
        self.euid = euid
        self.command_runner = command_runner
        self.expected_bundle_path = Path(expected_bundle_path)

    def run(self, args: Sequence[str]):
        try:
            return self.command_runner(
                list(args),
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise SendUnavailableError(
                "无法完成 WeChat 运行状态校验，未发送任何消息"
            ) from error


def _file_identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    )


def _open_regular_path_without_symlinks(path: Path):
    """逐组件绑定绝对路径，拒绝任意父级或末级符号链接。"""

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory_flag:
        raise OSError("secure component open unavailable")

    normalized = Path(os.path.normpath(os.fspath(path)))
    if not normalized.is_absolute() or len(normalized.parts) < 2:
        raise OSError("path must identify an absolute file")
    components = normalized.parts[1:]
    if any(component in ("", ".", "..") for component in components):
        raise OSError("unsafe path component")

    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | directory_flag | nofollow | close_on_exec
    file_flags = os.O_RDONLY | nofollow | close_on_exec
    current_fd = os.open(os.path.sep, directory_flags)
    ancestor_identities = []
    try:
        metadata = os.fstat(current_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError("root is not a directory")
        ancestor_identities.append(_directory_identity(metadata))

        for component in components[:-1]:
            next_fd = os.open(
                component,
                directory_flags,
                dir_fd=current_fd,
            )
            try:
                metadata = os.fstat(next_fd)
                if not stat.S_ISDIR(metadata.st_mode):
                    raise OSError("path component is not a directory")
                ancestor_identities.append(_directory_identity(metadata))
            except Exception:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd

        descriptor = os.open(
            components[-1],
            file_flags,
            dir_fd=current_fd,
        )
        return descriptor, tuple(ancestor_identities)
    finally:
        os.close(current_fd)


def _read_regular_file(path: Path, *, max_size: int) -> bytes:
    descriptor = None
    verification_descriptor = None
    try:
        descriptor, ancestor_identities = _open_regular_path_without_symlinks(
            path
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size < 1
            or metadata.st_size > max_size
        ):
            raise OSError("invalid regular file")
        chunks = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise OSError("file truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OSError("file grew while reading")

        after_read = os.fstat(descriptor)
        (
            verification_descriptor,
            verification_ancestors,
        ) = _open_regular_path_without_symlinks(path)
        path_after_read = os.fstat(verification_descriptor)
        if (
            _file_identity(after_read) != _file_identity(metadata)
            or _file_identity(path_after_read) != _file_identity(metadata)
            or verification_ancestors != ancestor_identities
        ):
            raise OSError("file changed while reading")
        return b"".join(chunks)
    except OSError as error:
        raise SendUnavailableError(
            f"所需 WeChat 文件不可安全读取: {path.name}；未发送任何消息"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if verification_descriptor is not None:
            os.close(verification_descriptor)


def _single_wechat_pid(inspector: PreflightInspector) -> int:
    result = inspector.run(["/usr/bin/pgrep", "-x", "WeChat"])
    if result.returncode == 1:
        pids = []
    elif result.returncode == 0:
        try:
            pids = [
                int(line)
                for line in result.stdout.decode("ascii", "strict").splitlines()
                if line
            ]
        except (UnicodeError, ValueError) as error:
            raise SendUnavailableError(
                "无法确认 WeChat 主进程，未发送任何消息"
            ) from error
    else:
        raise SendUnavailableError("无法确认 WeChat 主进程，未发送任何消息")
    if len(pids) != 1 or pids[0] <= 0:
        raise SendUnavailableError(
            "必须恰好一个 WeChat 主进程，未发送任何消息"
        )
    return pids[0]


def _process_identity(
    inspector: PreflightInspector,
    pid: int,
) -> ProcessIdentity:
    result = inspector.run(
        [
            "/bin/ps",
            "-p",
            str(pid),
            "-o",
            "pid=",
            "-o",
            "uid=",
            "-o",
            "lstart=",
            "-o",
            "comm=",
        ]
    )
    if result.returncode != 0:
        raise SendUnavailableError("WeChat 进程已变化，未发送任何消息")
    try:
        lines = result.stdout.decode("utf-8", "strict").splitlines()
    except UnicodeError as error:
        raise SendUnavailableError(
            "无法确认 WeChat 可执行文件路径，未发送任何消息"
        ) from error
    if len(lines) != 1:
        raise SendUnavailableError(
            "无法确认 WeChat 进程身份，未发送任何消息"
        )
    fields = lines[0].split(maxsplit=7)
    if len(fields) != 8:
        raise SendUnavailableError(
            "无法确认 WeChat 进程身份，未发送任何消息"
        )
    try:
        reported_pid = int(fields[0])
        process_uid = int(fields[1])
    except ValueError as error:
        raise SendUnavailableError(
            "无法确认 WeChat 进程身份，未发送任何消息"
        ) from error
    started_at = " ".join(fields[2:7])
    executable_value = fields[7]
    if (
        reported_pid != pid
        or pid <= 0
        or process_uid < 0
        or process_uid != inspector.euid()
        or not started_at
    ):
        raise SendUnavailableError(
            "WeChat 进程身份与当前用户不一致，未发送任何消息"
        )
    if not executable_value.startswith("/"):
        raise SendUnavailableError(
            "无法确认 WeChat 可执行文件路径，未发送任何消息"
        )
    return ProcessIdentity(
        pid=pid,
        uid=process_uid,
        started_at=started_at,
        executable_path=Path(os.path.normpath(executable_value)),
    )


def _read_info_plist(bundle_path: Path) -> dict:
    raw = _read_regular_file(bundle_path / "Contents/Info.plist", max_size=1024 * 1024)
    try:
        value = plistlib.loads(raw)
    except (plistlib.InvalidFileException, ValueError, TypeError) as error:
        raise SendUnavailableError(
            "WeChat Info.plist 无法解析，未发送任何消息"
        ) from error
    if not isinstance(value, dict):
        raise SendUnavailableError(
            "WeChat Info.plist 格式无效，未发送任何消息"
        )
    return value


def _validate_info_plist(info: dict):
    expected = {
        "CFBundleIdentifier": EXPECTED_BUNDLE_ID,
        "CFBundleExecutable": EXPECTED_EXECUTABLE,
        "CFBundleShortVersionString": EXPECTED_SHORT_VERSION,
        "CFBundleVersion": EXPECTED_BUILD_VERSION,
        "WeChatBundleVersion": EXPECTED_WECHAT_BUNDLE_VERSION,
    }
    if any(
        type(info.get(key)) is not str or info.get(key) != value
        for key, value in expected.items()
    ):
        raise SendUnavailableError(
            "WeChat Info.plist 与唯一批准版本不一致，未发送任何消息"
        )


def _open_database_paths(
    inspector: PreflightInspector,
    pid: int,
    db_dir,
) -> tuple[Path, ...]:
    try:
        db_root = Path(db_dir).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, TypeError) as error:
        raise SendUnavailableError(
            "数据库目录不可用，未发送任何消息"
        ) from error
    if not db_root.is_dir():
        raise SendUnavailableError("数据库目录不可用，未发送任何消息")

    result = inspector.run(
        ["/usr/sbin/lsof", "-n", "-P", "-a", "-p", str(pid), "-Fn"]
    )
    if result.returncode != 0:
        raise SendUnavailableError(
            "无法确认 WeChat 已打开数据库，未发送任何消息"
        )
    try:
        output = result.stdout.decode("utf-8", "strict")
    except UnicodeError as error:
        raise SendUnavailableError(
            "无法确认 WeChat 已打开数据库，未发送任何消息"
        ) from error

    found = set()
    for line in output.splitlines():
        if not line.startswith("n/"):
            continue
        raw_path = line[1:]
        if "\x00" in raw_path:
            continue
        try:
            normalized = Path(os.path.realpath(raw_path))
            normalized.relative_to(db_root)
        except (OSError, RuntimeError, ValueError):
            continue
        name = normalized.name.lower()
        if (
            name.endswith((".db", ".db-wal", ".db-shm"))
            and normalized.is_file()
        ):
            found.add(normalized)
    if not found:
        raise SendUnavailableError(
            "WeChat 未打开配置目录下的数据库文件，未发送任何消息"
        )
    return tuple(sorted(found))


def verify_pre_injection(
    app_context,
    *,
    inspector: PreflightInspector | None = None,
) -> WeChatProfile:
    """在任何注入或发送动作前验证唯一批准的 WeChat profile。"""

    inspector = inspector or PreflightInspector()
    if inspector.system() != "Darwin" or inspector.machine() != "arm64":
        raise SendUnavailableError(
            "发送 bridge 仅支持 macOS arm64，未发送任何消息"
        )

    pid = _single_wechat_pid(inspector)
    bundle_path = inspector.expected_bundle_path
    expected_executable_path = bundle_path / "Contents/MacOS/WeChat"
    process_identity = _process_identity(inspector, pid)
    if process_identity.executable_path != expected_executable_path:
        raise SendUnavailableError(
            "WeChat 可执行文件路径不是唯一批准路径，未发送任何消息"
        )

    info = _read_info_plist(bundle_path)
    _validate_info_plist(info)
    executable_data = _read_regular_file(
        expected_executable_path,
        max_size=1024 * 1024 * 1024,
    )
    try:
        executable_slices = parse_macho(executable_data)
    except MachOError as error:
        raise SendUnavailableError(
            "WeChat 可执行文件 Mach-O 无效，未发送任何消息"
        ) from error
    executable_arm64 = [
        item for item in executable_slices
        if item.cpu_type == CPU_TYPE_ARM64
    ]
    if (
        len(executable_arm64) != 1
        or not executable_arm64[0].is_64
        or executable_arm64[0].file_type != MH_EXECUTE
        or (
            executable_arm64[0].cpu_subtype & CPU_SUBTYPE_MASK
        ) != CPU_SUBTYPE_ARM64_ALL
        or executable_arm64[0].command_count < 1
    ):
        raise SendUnavailableError(
            "WeChat 可执行文件不是批准的 arm64 架构，未发送任何消息"
        )

    dylib_path = bundle_path / EXPECTED_DYLIB_RELATIVE_PATH
    dylib_data = _read_regular_file(dylib_path, max_size=512 * 1024 * 1024)
    dylib_sha256 = hashlib.sha256(dylib_data).hexdigest()
    if dylib_sha256 != EXPECTED_DYLIB_SHA256:
        raise SendUnavailableError(
            "wechat.dylib SHA-256 与批准版本不一致，未发送任何消息"
        )
    try:
        dylib_slices = parse_macho(dylib_data)
    except MachOError as error:
        raise SendUnavailableError(
            "wechat.dylib 不含唯一有效 arm64 slice，未发送任何消息"
        ) from error
    dylib_arm64 = [
        item for item in dylib_slices
        if item.cpu_type == CPU_TYPE_ARM64
    ]
    if (
        len(dylib_arm64) != 1
        or not dylib_arm64[0].is_64
        or dylib_arm64[0].file_type != MH_DYLIB
        or (
            dylib_arm64[0].cpu_subtype & CPU_SUBTYPE_MASK
        ) != CPU_SUBTYPE_ARM64_ALL
        or dylib_arm64[0].command_count < 1
        or dylib_arm64[0].uuid is None
    ):
        raise SendUnavailableError(
            "wechat.dylib 不含唯一有效 arm64 slice，未发送任何消息"
        )
    dylib_uuid = dylib_arm64[0].uuid
    if dylib_uuid != EXPECTED_DYLIB_UUID:
        raise SendUnavailableError(
            "wechat.dylib arm64 UUID 与批准版本不一致，未发送任何消息"
        )

    open_db_paths = _open_database_paths(
        inspector,
        pid,
        getattr(app_context, "db_dir", None),
    )
    final_process_identity = _process_identity(inspector, pid)
    if final_process_identity != process_identity:
        raise SendUnavailableError(
            "WeChat 进程已变化，未发送任何消息"
        )
    return WeChatProfile(
        pid=pid,
        process_uid=process_identity.uid,
        process_started_at=process_identity.started_at,
        bundle_id=EXPECTED_BUNDLE_ID,
        bundle_path=bundle_path,
        executable_path=expected_executable_path,
        arch="arm64",
        short_version=EXPECTED_SHORT_VERSION,
        build_version=EXPECTED_BUILD_VERSION,
        wechat_bundle_version=EXPECTED_WECHAT_BUNDLE_VERSION,
        dylib_path=dylib_path,
        dylib_sha256=dylib_sha256,
        dylib_uuid=dylib_uuid,
        open_db_paths=open_db_paths,
    )
