"""按需加载并复用当前 WeChat PID 的原生发送 bridge。"""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import time

from .send_bridge import AuthenticatedUnixBridgeClient, read_bridge_metadata
from .sending import SendUnavailableError


INJECT_TIMEOUT_SECONDS = 3.0
READY_TIMEOUT_SECONDS = 3.0
_STARTUP_REASON = re.compile(r"[a-z0-9_]{1,128}")
BRIDGE_INSTANCE_TAG = "official-task-v1"
BRIDGE_DYLIB_NAME = "libwechat_official_task_bridge_v2.dylib"


def _package_binary(name: str) -> Path:
    return Path(__file__).resolve().parents[1] / "bin" / name


def _safe_bridge_directory() -> Path:
    try:
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    except (KeyError, OSError) as error:
        raise SendUnavailableError(
            "无法确定当前用户目录，未发送任何消息"
        ) from error
    directory = (
        home
        / "Library"
        / "Containers"
        / "com.tencent.xinWeChat"
        / "Data"
        / "wcb"
    )
    try:
        directory.mkdir(mode=0o700, exist_ok=True)
        metadata = directory.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or directory.resolve(strict=True) != directory
        ):
            raise OSError("unsafe bridge directory")
        os.chmod(directory, 0o700)
    except (OSError, RuntimeError) as error:
        raise SendUnavailableError(
            "bridge 安全目录不可用，未发送任何消息"
        ) from error
    return directory


def _usable_metadata(path: Path, pid: int) -> bool:
    try:
        read_bridge_metadata(path, pid)
        return True
    except SendUnavailableError:
        return False


def _read_bridge_startup_error(path: Path, pid: int) -> str | None:
    path = Path(path)
    if path.name != f"bridge-{BRIDGE_INSTANCE_TAG}-{pid}.error":
        return None
    descriptor = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= 256
        ):
            return None
        raw = os.read(descriptor, 257)
        if len(raw) != metadata.st_size:
            return None
        reason = raw.decode("ascii", "strict").strip()
        return reason if _STARTUP_REASON.fullmatch(reason) else None
    except (OSError, UnicodeError, ValueError):
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _bridge_paths(directory: Path, pid: int) -> tuple[Path, Path]:
    stem = f"bridge-{BRIDGE_INSTANCE_TAG}-{pid}"
    return directory / f"{stem}.json", directory / f"{stem}.error"


def prepare_native_bridge(profile, request_id: str):
    """首次发送时注入一次；同一 PID 后续直接复用现有 socket。"""

    pid = getattr(profile, "pid", None)
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        raise SendUnavailableError(
            "WeChat PID 无效，未发送任何消息"
        )
    directory = _safe_bridge_directory()
    metadata_path, startup_error_path = _bridge_paths(directory, pid)

    if not _usable_metadata(metadata_path, pid):
        if metadata_path.exists():
            raise SendUnavailableError(
                "当前 PID 的 bridge 凭据异常，未发送任何消息"
            )
        injector = _package_binary("wechat_send_injector")
        bridge_dylib = _package_binary(BRIDGE_DYLIB_NAME)
        try:
            for binary in (injector, bridge_dylib):
                info = binary.lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid not in (0, os.geteuid())
                    or info.st_mode & 0o022
                ):
                    raise OSError("unsafe packaged native binary")
            result = subprocess.run(
                [str(injector), str(pid), str(bridge_dylib)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=INJECT_TIMEOUT_SECONDS,
                check=False,
                shell=False,
                text=True,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise SendUnavailableError(
                "无法加载发送 bridge，未发送任何消息"
            ) from error
        if result.returncode != 0:
            detail = (result.stderr or "").strip().splitlines()
            reason = detail[-1] if detail else "native_injector_failed"
            raise SendUnavailableError(
                f"无法加载发送 bridge（{reason}），未发送任何消息"
            )

        deadline = time.monotonic() + READY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if _usable_metadata(metadata_path, pid):
                break
            time.sleep(0.05)
        else:
            reason = _read_bridge_startup_error(startup_error_path, pid)
            detail = f"（{reason}）" if reason else ""
            raise SendUnavailableError(
                f"发送 bridge 启动失败{detail}，未发送任何消息"
            )

    return AuthenticatedUnixBridgeClient(
        pid=pid,
        metadata_path=metadata_path,
        request_id_factory=lambda: request_id,
    )
