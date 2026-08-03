import json
import os
import socket
import struct
import tempfile
from pathlib import Path

import pytest

from wechat_cli.core.sending import (
    SendRequest,
    SendUnavailableError,
    SendUnknownError,
)


PID = 4242
TOKEN = "secret-token-value-that-is-never-logged"


class FakeSocket:
    def __init__(
        self,
        response=b"",
        *,
        connect_error=None,
        send_plan=None,
        recv_error=None,
    ):
        self.response = bytearray(response)
        self.connect_error = connect_error
        self.send_plan = list(send_plan or [])
        self.recv_error = recv_error
        self.connected_to = None
        self.sent = bytearray()
        self.timeouts = []
        self.closed = False
        self.connect_calls = 0

    def settimeout(self, value):
        self.timeouts.append(value)

    def connect(self, path):
        self.connect_calls += 1
        if self.connect_error:
            raise self.connect_error
        self.connected_to = path

    def send(self, data):
        if self.send_plan:
            action = self.send_plan.pop(0)
            if isinstance(action, BaseException):
                raise action
            count = min(action, len(data))
        else:
            count = len(data)
        self.sent.extend(bytes(data[:count]))
        return count

    def recv(self, size):
        if self.recv_error:
            raise self.recv_error
        if not self.response:
            return b""
        result = bytes(self.response[:size])
        del self.response[:size]
        return result

    def close(self):
        self.closed = True


def _metadata(tmp_path):
    from wechat_cli.core.send_bridge import BridgeMetadata

    return BridgeMetadata(
        version=1,
        pid=PID,
        socket_path=tmp_path / f"wechat-bridge-{PID}.sock",
        token=TOKEN,
    )


def _response(payload):
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return struct.pack(">I", len(encoded)) + encoded


def _success_payload(**overrides):
    payload = {
        "version": 1,
        "type": "send_receipt",
        "ack_state": "acknowledged",
        "request_id": "req-fixed",
        "group": "精确群名",
        "username": "room@chatroom",
        "local_id": 11,
        "server_id": 22,
    }
    payload.update(overrides)
    return payload


def _client(tmp_path, fake_socket, **overrides):
    from wechat_cli.core.send_bridge import AuthenticatedUnixBridgeClient

    options = {
        "pid": PID,
        "metadata_path": tmp_path / f"bridge-{PID}.json",
        "metadata_reader": lambda path, pid: _metadata(tmp_path),
        "socket_factory": lambda: fake_socket,
        "peer_verifier": lambda sock, metadata: None,
        "request_id_factory": lambda: "req-fixed",
    }
    options.update(overrides)
    return AuthenticatedUnixBridgeClient(**options)


def _request(text="原样消息"):
    return SendRequest(
        group="精确群名",
        username="room@chatroom",
        text=text,
        timeout=2.5,
    )


def test_metadata_reader_requires_pid_specific_0600_owned_regular_file_and_socket(
    tmp_path,
):
    from wechat_cli.core.send_bridge import read_bridge_metadata

    with tempfile.TemporaryDirectory(prefix="wechat-bridge-test-", dir="/tmp") as raw:
        short_dir = Path(raw)
        socket_path = short_dir / f"wechat-bridge-{PID}.sock"
        unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        unix_socket.bind(str(socket_path))
        socket_path.chmod(0o600)
        metadata_path = short_dir / f"bridge-{PID}.json"
        metadata_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "pid": PID,
                    "socket_path": str(socket_path),
                    "token": TOKEN,
                }
            ),
            encoding="utf-8",
        )
        metadata_path.chmod(0o600)
        try:
            metadata = read_bridge_metadata(metadata_path, PID)
        finally:
            unix_socket.close()

        assert metadata.pid == PID
        assert metadata.socket_path == socket_path
        assert metadata.token == TOKEN


def test_metadata_reader_accepts_exact_legacy_compact_socket_name():
    from wechat_cli.core.send_bridge import read_bridge_metadata

    with tempfile.TemporaryDirectory(prefix="wechat-bridge-test-", dir="/tmp") as raw:
        short_dir = Path(raw)
        socket_path = short_dir / f"w-0123456789abcde4{PID}"
        unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        unix_socket.bind(str(socket_path))
        socket_path.chmod(0o600)
        metadata_path = short_dir / f"bridge-{PID}.json"
        metadata_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "pid": PID,
                    "socket_path": str(socket_path),
                    "token": TOKEN,
                }
            ),
            encoding="utf-8",
        )
        metadata_path.chmod(0o600)
        try:
            metadata = read_bridge_metadata(metadata_path, PID)
        finally:
            unix_socket.close()

        assert metadata.socket_path == socket_path


def test_metadata_reader_rejects_socket_mode_other_than_0600(tmp_path):
    from wechat_cli.core.send_bridge import read_bridge_metadata

    with tempfile.TemporaryDirectory(prefix="wechat-bridge-test-", dir="/tmp") as raw:
        short_dir = Path(raw)
        socket_path = short_dir / f"wechat-bridge-{PID}.sock"
        unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        unix_socket.bind(str(socket_path))
        socket_path.chmod(0o777)
        metadata_path = short_dir / f"bridge-{PID}.json"
        metadata_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "pid": PID,
                    "socket_path": str(socket_path),
                    "token": TOKEN,
                }
            ),
            encoding="utf-8",
        )
        metadata_path.chmod(0o600)
        try:
            with pytest.raises(SendUnavailableError, match="socket"):
                read_bridge_metadata(metadata_path, PID)
        finally:
            unix_socket.close()


def test_connected_peer_matches_uid_path_and_inspected_socket_inode():
    from wechat_cli.core.send_bridge import (
        read_bridge_metadata,
        verify_connected_bridge_peer,
    )

    with tempfile.TemporaryDirectory(prefix="wechat-bridge-test-", dir="/tmp") as raw:
        short_dir = Path(raw)
        socket_path = short_dir / f"wechat-bridge-{PID}.sock"
        metadata_path = short_dir / f"bridge-{PID}.json"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        accepted = None
        server.bind(str(socket_path))
        socket_path.chmod(0o600)
        server.listen(1)
        metadata_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "pid": PID,
                    "socket_path": str(socket_path),
                    "token": TOKEN,
                }
            ),
            encoding="utf-8",
        )
        metadata_path.chmod(0o600)
        metadata = read_bridge_metadata(metadata_path, PID)
        try:
            client.connect(str(socket_path))
            accepted, _ = server.accept()

            verify_connected_bridge_peer(client, metadata)
        finally:
            client.close()
            if accepted is not None:
                accepted.close()
            server.close()


def test_connected_peer_rejects_endpoint_replaced_after_metadata_read():
    from wechat_cli.core.send_bridge import (
        read_bridge_metadata,
        verify_connected_bridge_peer,
    )

    with tempfile.TemporaryDirectory(prefix="wechat-bridge-test-", dir="/tmp") as raw:
        short_dir = Path(raw)
        socket_path = short_dir / f"wechat-bridge-{PID}.sock"
        metadata_path = short_dir / f"bridge-{PID}.json"
        original = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        original.bind(str(socket_path))
        socket_path.chmod(0o600)
        metadata_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "pid": PID,
                    "socket_path": str(socket_path),
                    "token": TOKEN,
                }
            ),
            encoding="utf-8",
        )
        metadata_path.chmod(0o600)
        metadata = read_bridge_metadata(metadata_path, PID)
        original.close()
        socket_path.unlink()

        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        accepted = None
        replacement.bind(str(socket_path))
        socket_path.chmod(0o600)
        replacement.listen(1)
        try:
            client.connect(str(socket_path))
            accepted, _ = replacement.accept()

            with pytest.raises(SendUnavailableError, match="socket"):
                verify_connected_bridge_peer(client, metadata)
        finally:
            client.close()
            if accepted is not None:
                accepted.close()
            replacement.close()


@pytest.mark.parametrize("mode", [0o644, 0o400, 0o666])
def test_metadata_reader_rejects_any_mode_other_than_0600(tmp_path, mode):
    from wechat_cli.core.send_bridge import read_bridge_metadata

    metadata_path = tmp_path / f"bridge-{PID}.json"
    metadata_path.write_text("{}", encoding="utf-8")
    metadata_path.chmod(mode)

    with pytest.raises(SendUnavailableError, match="凭据"):
        read_bridge_metadata(metadata_path, PID)


def test_metadata_reader_rejects_symlink_without_disclosing_contents(tmp_path):
    from wechat_cli.core.send_bridge import read_bridge_metadata

    target = tmp_path / "target.json"
    target.write_text(TOKEN, encoding="utf-8")
    target.chmod(0o600)
    metadata_path = tmp_path / f"bridge-{PID}.json"
    metadata_path.symlink_to(target)

    with pytest.raises(SendUnavailableError) as raised:
        read_bridge_metadata(metadata_path, PID)

    assert TOKEN not in str(raised.value)


@pytest.mark.parametrize(
    "mutation",
    [
        {"pid": PID + 1},
        {"version": 2},
        {"token": "short"},
        {"socket_path": "/tmp/not-pid-specific.sock"},
    ],
)
def test_metadata_reader_rejects_mismatched_or_weak_metadata(tmp_path, mutation):
    from wechat_cli.core.send_bridge import read_bridge_metadata

    metadata_path = tmp_path / f"bridge-{PID}.json"
    payload = {
        "version": 1,
        "pid": PID,
        "socket_path": str(tmp_path / f"bridge-{PID}.sock"),
        "token": TOKEN,
    }
    payload.update(mutation)
    metadata_path.write_text(json.dumps(payload), encoding="utf-8")
    metadata_path.chmod(0o600)

    with pytest.raises(SendUnavailableError) as raised:
        read_bridge_metadata(metadata_path, PID)

    assert TOKEN not in str(raised.value)


def test_client_sends_one_authenticated_length_prefixed_json_frame(tmp_path):
    fake_socket = FakeSocket(_response(_success_payload()))
    client = _client(tmp_path, fake_socket)

    result = client.send_text(_request("你好 👋\n$HOME `nope`"))

    size = struct.unpack(">I", fake_socket.sent[:4])[0]
    payload = json.loads(fake_socket.sent[4 : 4 + size])
    assert len(fake_socket.sent) == size + 4
    assert payload == {
        "version": 1,
        "type": "send_text",
        "auth_token": TOKEN,
        "request_id": "req-fixed",
        "group": "精确群名",
        "username": "room@chatroom",
        "text": "你好 👋\n$HOME `nope`",
    }
    assert result.ack_state.value == "acknowledged"
    assert result.local_id == 11
    assert result.server_id == 22
    assert fake_socket.connect_calls == 1
    assert fake_socket.connected_to.endswith(f"wechat-bridge-{PID}.sock")
    assert fake_socket.closed is True
    assert fake_socket.timeouts


def test_client_checks_connected_peer_before_submitting_any_bytes(tmp_path):
    fake_socket = FakeSocket(_response(_success_payload()))

    def reject_peer(sock, metadata):
        raise SendUnavailableError(
            "bridge socket 对端身份不可信，未发送任何消息"
        )

    client = _client(
        tmp_path,
        fake_socket,
        peer_verifier=reject_peer,
    )

    with pytest.raises(SendUnavailableError, match="对端身份"):
        client.send_text(_request())

    assert fake_socket.connect_calls == 1
    assert fake_socket.sent == b""
    assert fake_socket.closed is True


@pytest.mark.parametrize(
    ("failure", "expected_error"),
    [
        ("connect", SendUnavailableError),
        ("first-send", SendUnavailableError),
        ("partial-send", SendUnknownError),
        ("response-timeout", SendUnknownError),
        ("response-eof", SendUnknownError),
    ],
)
def test_client_classifies_transport_failure_from_bytes_submitted(
    tmp_path,
    failure,
    expected_error,
):
    kwargs = {}
    if failure == "connect":
        kwargs["connect_error"] = ConnectionRefusedError()
    elif failure == "first-send":
        kwargs["send_plan"] = [BrokenPipeError()]
    elif failure == "partial-send":
        kwargs["send_plan"] = [2, BrokenPipeError()]
    elif failure == "response-timeout":
        kwargs["recv_error"] = TimeoutError()
    fake_socket = FakeSocket(**kwargs)
    client = _client(tmp_path, fake_socket)

    with pytest.raises(expected_error) as raised:
        client.send_text(_request())

    assert fake_socket.connect_calls == 1
    assert fake_socket.closed is True
    assert TOKEN not in str(raised.value)
    assert "原样消息" not in str(raised.value)


@pytest.mark.parametrize(
    "response",
    [
        struct.pack(">I", 0),
        struct.pack(">I", 1024 * 1024 + 1),
        _response({"not": "a receipt"}),
        _response(_success_payload(request_id="another-request")),
        _response(_success_payload(username="other@chatroom")),
        _response(_success_payload(local_id=0)),
        _response(_success_payload(local_id=None)),
        _response(_success_payload(server_id=None)),
        _response(
            _success_payload(
                ack_state="submitted",
                local_id=11,
                server_id=None,
            )
        ),
        _response(
            _success_payload(
                ack_state="submitted",
                local_id=None,
                server_id=22,
            )
        ),
    ],
)
def test_client_rejects_oversized_malformed_or_mismatched_response_as_unknown(
    tmp_path,
    response,
):
    fake_socket = FakeSocket(response)
    client = _client(tmp_path, fake_socket)

    with pytest.raises(SendUnknownError):
        client.send_text(_request())


def test_client_maps_valid_explicit_unknown_receipt_without_retry(tmp_path):
    fake_socket = FakeSocket(
        _response(
            _success_payload(
                ack_state="unknown",
                local_id=None,
                server_id=None,
            )
        )
    )
    client = _client(tmp_path, fake_socket)

    result = client.send_text(_request())

    assert result.ack_state.value == "unknown"
    assert result.request_id == "req-fixed"


def test_client_accepts_submitted_receipt_without_ids(tmp_path):
    fake_socket = FakeSocket(
        _response(
            _success_payload(
                ack_state="submitted",
                local_id=None,
                server_id=None,
            )
        )
    )
    client = _client(tmp_path, fake_socket)

    result = client.send_text(_request())

    assert result.ack_state.value == "submitted"
    assert result.local_id is None
    assert result.server_id is None
    assert fake_socket.connect_calls == 1


def test_client_rejects_oversized_outbound_frame_before_opening_socket(tmp_path):
    from wechat_cli.core.send_bridge import MAX_FRAME_BYTES

    socket_creations = []
    client = _client(
        tmp_path,
        FakeSocket(),
        socket_factory=lambda: socket_creations.append(True),
    )

    with pytest.raises(SendUnavailableError, match="过大"):
        client.send_text(_request("x" * (MAX_FRAME_BYTES + 1)))

    assert socket_creations == []


def test_client_does_not_retry_after_connect_or_transaction_failure(tmp_path):
    sockets = []

    def make_socket():
        value = FakeSocket(connect_error=ConnectionRefusedError())
        sockets.append(value)
        return value

    client = _client(tmp_path, FakeSocket(), socket_factory=make_socket)

    with pytest.raises(SendUnavailableError):
        client.send_text(_request())

    assert len(sockets) == 1
    assert sockets[0].connect_calls == 1


@pytest.mark.parametrize("failure_point", ["socket-factory", "set-timeout"])
def test_client_classifies_socket_setup_failure_as_pre_send_unavailable(
    tmp_path,
    failure_point,
):
    if failure_point == "socket-factory":
        def make_socket():
            raise OSError("socket unavailable")
    else:
        fake_socket = FakeSocket()

        def fail_timeout(value):
            raise OSError("timeout setup unavailable")

        fake_socket.settimeout = fail_timeout
        make_socket = lambda: fake_socket
    client = _client(tmp_path, FakeSocket(), socket_factory=make_socket)

    with pytest.raises(SendUnavailableError, match="未发送") as raised:
        client.send_text(_request())

    assert TOKEN not in str(raised.value)


@pytest.mark.parametrize("dependency", ["request-id", "metadata"])
def test_client_classifies_pre_transport_dependency_failure_as_unavailable(
    tmp_path,
    dependency,
):
    def fail():
        raise RuntimeError("dependency failed")

    overrides = {}
    if dependency == "request-id":
        overrides["request_id_factory"] = fail
    else:
        def fail_metadata(path, pid):
            raise RuntimeError("dependency failed")

        overrides["metadata_reader"] = fail_metadata
    client = _client(tmp_path, FakeSocket(), **overrides)

    with pytest.raises(SendUnavailableError, match="未发送"):
        client.send_text(_request())
