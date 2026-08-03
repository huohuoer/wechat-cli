"""经过本地凭据认证的单次 AF_UNIX bridge 传输。"""

from __future__ import annotations

import ctypes
import json
import math
import os
import re
import socket
import stat
import struct
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable

from .sending import SendRequest, SendUnavailableError, SendUnknownError


PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 1024 * 1024
MAX_METADATA_BYTES = 16 * 1024
MAX_TOKEN_BYTES = 512
MIN_TOKEN_BYTES = 32
MAX_UNIX_PATH_BYTES = 103


class BridgeAckState(str, Enum):
    """bridge 自身观察到的原始 ACK 状态，不代表服务器最终接受。"""

    ACKNOWLEDGED = "acknowledged"
    SUBMITTED = "submitted"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class BridgeMetadata:
    version: int
    pid: int
    socket_path: Path
    token: str
    socket_device: int | None = None
    socket_inode: int | None = None
    socket_uid: int | None = None
    socket_mode: int | None = None


@dataclass(frozen=True)
class BridgeReceipt:
    """未经数据库二次确认的 bridge 原始回执。"""

    request_id: str
    ack_state: BridgeAckState
    group: str
    username: str
    local_id: int | None
    server_id: int | None


def _mentions_pid(path: Path, pid: int) -> bool:
    return re.search(rf"(?<![0-9]){pid}(?![0-9])", path.name) is not None


def _socket_mentions_pid(path: Path, pid: int) -> bool:
    if _mentions_pid(path, pid):
        return True
    return re.fullmatch(rf"w-[0-9a-f]{{16}}{pid}", path.name) is not None


def _decode_unique_json(raw: bytes):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    return json.loads(
        raw.decode("utf-8", "strict"),
        object_pairs_hook=unique_object,
    )


def _read_credential_file(path: Path, expected_uid: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != expected_uid
            or metadata.st_nlink != 1
            or metadata.st_size < 1
            or metadata.st_size > MAX_METADATA_BYTES
        ):
            raise OSError("unsafe credential metadata")
        chunks = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                raise OSError("credential file truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OSError("credential file changed")
        return b"".join(chunks)
    except OSError as error:
        raise SendUnavailableError(
            "bridge 凭据文件不可安全读取，未发送任何消息"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_bridge_metadata(
    metadata_path,
    pid: int,
    *,
    expected_uid: int | None = None,
) -> BridgeMetadata:
    """安全读取 PID 专属、当前用户所有且权限恰为 0600 的凭据文件。"""

    path = Path(metadata_path)
    uid = os.geteuid() if expected_uid is None else expected_uid
    if (
        isinstance(pid, bool)
        or not isinstance(pid, int)
        or pid <= 0
        or not path.is_absolute()
        or not _mentions_pid(path, pid)
    ):
        raise SendUnavailableError(
            "bridge 凭据路径不是 PID 专属路径，未发送任何消息"
        )
    raw = _read_credential_file(path, uid)
    try:
        payload = _decode_unique_json(raw)
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as error:
        raise SendUnavailableError(
            "bridge 凭据格式无效，未发送任何消息"
        ) from error
    if not isinstance(payload, dict) or set(payload) != {
        "version",
        "pid",
        "socket_path",
        "token",
    }:
        raise SendUnavailableError(
            "bridge 凭据格式无效，未发送任何消息"
        )

    version = payload.get("version")
    metadata_pid = payload.get("pid")
    socket_value = payload.get("socket_path")
    token = payload.get("token")
    if version != PROTOCOL_VERSION or type(version) is not int:
        raise SendUnavailableError(
            "bridge 协议版本不受支持，未发送任何消息"
        )
    if type(metadata_pid) is not int or metadata_pid != pid:
        raise SendUnavailableError(
            "bridge 凭据 PID 不匹配，未发送任何消息"
        )
    if type(socket_value) is not str or "\x00" in socket_value:
        raise SendUnavailableError(
            "bridge socket 路径无效，未发送任何消息"
        )
    socket_path = Path(socket_value)
    encoded_path = os.fsencode(socket_path)
    if (
        not socket_path.is_absolute()
        or socket_path != Path(os.path.normpath(socket_value))
        or not _socket_mentions_pid(socket_path, pid)
        or len(encoded_path) > MAX_UNIX_PATH_BYTES
    ):
        raise SendUnavailableError(
            "bridge socket 路径不是 PID 专属路径，未发送任何消息"
        )
    if type(token) is not str:
        raise SendUnavailableError(
            "bridge 凭据格式无效，未发送任何消息"
        )
    try:
        token_bytes = token.encode("ascii", "strict")
    except UnicodeError as error:
        raise SendUnavailableError(
            "bridge 凭据格式无效，未发送任何消息"
        ) from error
    if (
        not MIN_TOKEN_BYTES <= len(token_bytes) <= MAX_TOKEN_BYTES
        or any(byte <= 0x20 or byte >= 0x7F for byte in token_bytes)
    ):
        raise SendUnavailableError(
            "bridge 凭据格式无效，未发送任何消息"
        )

    try:
        socket_metadata = socket_path.lstat()
    except OSError as error:
        raise SendUnavailableError(
            "bridge socket 不可用，未发送任何消息"
        ) from error
    socket_mode = stat.S_IMODE(socket_metadata.st_mode)
    if (
        not stat.S_ISSOCK(socket_metadata.st_mode)
        or socket_metadata.st_uid != uid
        or socket_mode != 0o600
    ):
        raise SendUnavailableError(
            "bridge socket 不可信，未发送任何消息"
        )
    return BridgeMetadata(
        version=version,
        pid=metadata_pid,
        socket_path=socket_path,
        token=token,
        socket_device=socket_metadata.st_dev,
        socket_inode=socket_metadata.st_ino,
        socket_uid=socket_metadata.st_uid,
        socket_mode=socket_mode,
    )


def _default_socket_factory():
    return socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)


def _peer_uid(sock) -> int:
    """通过 Darwin getpeereid(3) 取得已连接 AF_UNIX 对端的有效 UID。"""

    try:
        descriptor = sock.fileno()
        if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 0:
            raise OSError("invalid socket descriptor")
        libc = ctypes.CDLL(None, use_errno=True)
        getpeereid = libc.getpeereid
        getpeereid.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(ctypes.c_uint),
        ]
        getpeereid.restype = ctypes.c_int
        peer_uid = ctypes.c_uint()
        peer_gid = ctypes.c_uint()
        if getpeereid(
            descriptor,
            ctypes.byref(peer_uid),
            ctypes.byref(peer_gid),
        ) != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))
        return int(peer_uid.value)
    except (AttributeError, TypeError, ValueError) as error:
        raise OSError("getpeereid unavailable") from error


def verify_connected_bridge_peer(
    sock,
    metadata: BridgeMetadata,
    *,
    expected_uid: int | None = None,
    peer_uid_reader: Callable = _peer_uid,
):
    """在提交任何字节前，把已连接对端绑定回预先检查的 socket。"""

    uid = os.geteuid() if expected_uid is None else expected_uid
    try:
        peer_uid = peer_uid_reader(sock)
        peer_name = sock.getpeername()
        if isinstance(peer_name, bytes):
            peer_name = os.fsdecode(peer_name)
        current = metadata.socket_path.lstat()
    except (OSError, TypeError, ValueError) as error:
        raise SendUnavailableError(
            "bridge socket 对端身份不可确认，未发送任何消息"
        ) from error

    if (
        not isinstance(metadata, BridgeMetadata)
        or peer_uid != uid
        or type(peer_name) is not str
        or peer_name != str(metadata.socket_path)
        or not stat.S_ISSOCK(current.st_mode)
        or stat.S_IMODE(current.st_mode) != 0o600
        or current.st_uid != uid
        or metadata.socket_device != current.st_dev
        or metadata.socket_inode != current.st_ino
        or metadata.socket_uid != current.st_uid
        or metadata.socket_mode != stat.S_IMODE(current.st_mode)
    ):
        raise SendUnavailableError(
            "bridge socket 对端身份不可信，未发送任何消息"
        )


def _default_request_id():
    return str(uuid.uuid4())


def _encode_frame(payload: dict) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise SendUnavailableError(
            "发送请求无法安全编码，未发送任何消息"
        ) from error
    if not 1 <= len(encoded) <= MAX_FRAME_BYTES:
        raise SendUnavailableError(
            "发送请求过大，未发送任何消息"
        )
    return struct.pack(">I", len(encoded)) + encoded


def _recv_exact(sock, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("unexpected EOF")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _receive_payload(sock):
    prefix = _recv_exact(sock, 4)
    size = struct.unpack(">I", prefix)[0]
    if not 1 <= size <= MAX_FRAME_BYTES:
        raise ValueError("invalid response frame size")
    raw = _recv_exact(sock, size)
    payload = _decode_unique_json(raw)
    if not isinstance(payload, dict):
        raise ValueError("response is not an object")
    return payload


def _positive_id(value, *, optional: bool):
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("invalid message id")
    return value


def _validate_receipt(payload, request: SendRequest, request_id: str) -> BridgeReceipt:
    expected_keys = {
        "version",
        "type",
        "ack_state",
        "request_id",
        "group",
        "username",
        "local_id",
        "server_id",
    }
    if set(payload) != expected_keys:
        raise ValueError("unexpected receipt fields")
    if payload["version"] != PROTOCOL_VERSION or type(payload["version"]) is not int:
        raise ValueError("invalid protocol version")
    if payload["type"] != "send_receipt":
        raise ValueError("invalid receipt type")
    if (
        payload["request_id"] != request_id
        or payload["group"] != request.group
        or payload["username"] != request.username
    ):
        raise ValueError("receipt does not match request")
    try:
        ack_state = BridgeAckState(payload["ack_state"])
    except (ValueError, TypeError) as error:
        raise ValueError("invalid ACK state") from error
    if ack_state is BridgeAckState.SUBMITTED:
        if payload["local_id"] is not None or payload["server_id"] is not None:
            raise ValueError("submitted receipt must not contain message ids")
        local_id = None
        server_id = None
    else:
        optional_ids = ack_state is BridgeAckState.UNKNOWN
        local_id = _positive_id(payload["local_id"], optional=optional_ids)
        server_id = _positive_id(payload["server_id"], optional=optional_ids)
    return BridgeReceipt(
        request_id=request_id,
        ack_state=ack_state,
        group=request.group,
        username=request.username,
        local_id=local_id,
        server_id=server_id,
    )


class AuthenticatedUnixBridgeClient:
    """不重试的单次 bridge 调用；返回原始 ACK，不产生最终发送结果。"""

    def __init__(
        self,
        *,
        pid: int,
        metadata_path,
        metadata_reader: Callable = read_bridge_metadata,
        socket_factory: Callable = _default_socket_factory,
        peer_verifier: Callable = verify_connected_bridge_peer,
        request_id_factory: Callable[[], str] = _default_request_id,
    ):
        self.pid = pid
        self.metadata_path = Path(metadata_path)
        self.metadata_reader = metadata_reader
        self.socket_factory = socket_factory
        self.peer_verifier = peer_verifier
        self.request_id_factory = request_id_factory

    def send_text(self, request: SendRequest) -> BridgeReceipt:
        if not isinstance(request, SendRequest):
            raise SendUnavailableError(
                "发送请求类型无效，未发送任何消息"
            )
        if (
            isinstance(request.timeout, bool)
            or not isinstance(request.timeout, (int, float))
            or not math.isfinite(request.timeout)
            or request.timeout <= 0
        ):
            raise SendUnavailableError(
                "bridge timeout 无效，未发送任何消息"
            )
        try:
            request_id = self.request_id_factory()
        except Exception as error:
            raise SendUnavailableError(
                "bridge request_id 无法生成，未发送任何消息"
            ) from error
        if (
            type(request_id) is not str
            or not request_id
            or len(request_id.encode("utf-8")) > 256
        ):
            raise SendUnavailableError(
                "bridge request_id 无效，未发送任何消息"
            )
        try:
            metadata = self.metadata_reader(self.metadata_path, self.pid)
        except SendUnavailableError:
            raise
        except Exception as error:
            raise SendUnavailableError(
                "bridge 凭据不可用，未发送任何消息"
            ) from error
        if not isinstance(metadata, BridgeMetadata) or metadata.pid != self.pid:
            raise SendUnavailableError(
                "bridge 凭据与目标进程不匹配，未发送任何消息"
            )
        frame = _encode_frame(
            {
                "version": PROTOCOL_VERSION,
                "type": "send_text",
                "auth_token": metadata.token,
                "request_id": request_id,
                "group": request.group,
                "username": request.username,
                "text": request.text,
            }
        )

        sock = None
        submitted = 0
        try:
            try:
                sock = self.socket_factory()
                sock.settimeout(float(request.timeout))
            except Exception as error:
                raise SendUnavailableError(
                    "bridge socket 无法初始化，未发送任何消息"
                ) from error
            try:
                sock.connect(str(metadata.socket_path))
            except (OSError, TimeoutError) as error:
                raise SendUnavailableError(
                    "bridge 连接不可用，未发送任何消息"
                ) from error
            try:
                self.peer_verifier(sock, metadata)
            except SendUnavailableError:
                raise
            except Exception as error:
                raise SendUnavailableError(
                    "bridge socket 对端身份不可确认，未发送任何消息"
                ) from error

            while submitted < len(frame):
                try:
                    count = sock.send(memoryview(frame)[submitted:])
                except (OSError, TimeoutError) as error:
                    if submitted == 0:
                        raise SendUnavailableError(
                            "bridge 在提交前不可用，未发送任何消息"
                        ) from error
                    raise SendUnknownError(
                        "bridge 提交状态未知，禁止自动重试"
                    ) from error
                if not isinstance(count, int) or count <= 0:
                    if submitted == 0:
                        raise SendUnavailableError(
                            "bridge 在提交前不可用，未发送任何消息"
                        )
                    raise SendUnknownError(
                        "bridge 提交状态未知，禁止自动重试"
                    )
                submitted += count

            try:
                payload = _receive_payload(sock)
                return _validate_receipt(payload, request, request_id)
            except SendUnknownError:
                raise
            except (OSError, TimeoutError, UnicodeError, ValueError, TypeError) as error:
                raise SendUnknownError(
                    "bridge 回执无法确认，禁止自动重试"
                ) from error
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
