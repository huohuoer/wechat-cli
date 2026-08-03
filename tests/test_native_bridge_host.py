import json
import os
import platform
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from wechat_cli.core.send_bridge import AuthenticatedUnixBridgeClient
from wechat_cli.core.sending import SendRequest


pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin" or platform.machine() != "arm64",
    reason="native bridge is a macOS ARM64 component",
)

ROOT = Path(__file__).resolve().parents[1]
MAX_FRAME_BYTES = 1024 * 1024


@pytest.fixture(scope="session")
def native_build(tmp_path_factory):
    output = tmp_path_factory.mktemp("native-bridge-build")
    subprocess.run(
        [str(ROOT / "native" / "build.sh"), str(output)],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    dylib = output / "libwechat_bridge_core.dylib"
    host = output / "native_fake_host"
    assert dylib.is_file()
    assert host.is_file()
    file_output = subprocess.run(
        ["file", str(dylib), str(host)],
        check=True,
        text=True,
        capture_output=True,
    ).stdout
    assert file_output.count("arm64") == 2
    return host, dylib


class RunningHost:
    def __init__(self, process, safe_directory, instance_tag=""):
        self.process = process
        self.safe_directory = safe_directory
        self.pid = process.pid
        suffix = f"-{instance_tag}" if instance_tag else ""
        self.metadata_path = (
            safe_directory / f"bridge{suffix}-{self.pid}.json"
        )
        self.socket_path = (
            safe_directory / f"wechat-bridge{suffix}-{self.pid}.sock"
        )
        self.stats = None
        self.stdout = None
        self.stderr = None

    def stop(self):
        if self.stats is not None:
            return
        if self.process.poll() is None:
            self.process.terminate()
        stdout, stderr = self.process.communicate(timeout=5)
        self.stdout = stdout
        self.stderr = stderr
        assert self.process.returncode == 0, stderr
        lines = [line for line in stdout.splitlines() if line]
        assert len(lines) == 1
        label, calls, max_active = lines[0].split()
        assert label == "STATS"
        self.stats = (int(calls), int(max_active))


@contextmanager
def _running_host(
    native_build,
    tmp_path,
    *,
    ack_state="acknowledged",
    delay_ms=0,
    adapter_timeout_ms=3000,
    instance_tag="",
    directory_prefix="wb-",
):
    host, _ = native_build
    safe_directory = Path(
        tempfile.mkdtemp(prefix=directory_prefix, dir="/tmp")
    ).resolve()
    safe_directory.chmod(0o700)
    arguments = [
            str(host),
            "--safe-directory",
            str(safe_directory),
            "--ack-state",
            ack_state,
            "--delay-ms",
            str(delay_ms),
            "--adapter-timeout-ms",
            str(adapter_timeout_ms),
        ]
    if instance_tag:
        arguments.extend(["--instance-tag", instance_tag])
    process = subprocess.Popen(
        arguments,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    running = RunningHost(process, safe_directory, instance_tag)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if running.metadata_path.exists():
            try:
                running.socket_path = Path(
                    json.loads(
                        running.metadata_path.read_text(encoding="utf-8")
                    )["socket_path"]
                )
            except (OSError, KeyError, TypeError, ValueError):
                pass
            if running.socket_path.exists():
                break
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(f"native host exited before ready: {stdout!r} {stderr!r}")
        time.sleep(0.01)
    else:
        process.kill()
        stdout, stderr = process.communicate()
        pytest.fail(f"native host did not become ready: {stdout!r} {stderr!r}")
    try:
        yield running
    finally:
        running.stop()
        safe_directory.rmdir()


def _metadata(host):
    return json.loads(host.metadata_path.read_text(encoding="utf-8"))


def _request_payload(host, **overrides):
    metadata = _metadata(host)
    payload = {
        "version": 1,
        "type": "send_text",
        "auth_token": metadata["token"],
        "request_id": "req-native-fixed",
        "group": "精确群名",
        "username": "room@chatroom",
        "text": "你好 👋\n第二行",
    }
    payload.update(overrides)
    return payload


def _encode_frame(payload):
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return struct.pack(">I", len(encoded)) + encoded


def _receive_exact(sock, size):
    chunks = []
    while sum(map(len, chunks)) < size:
        chunk = sock.recv(size - sum(map(len, chunks)))
        if not chunk:
            raise EOFError
        chunks.append(chunk)
    return b"".join(chunks)


def _transact(host, frame, *, chunks=None):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3)
    try:
        client.connect(str(host.socket_path))
        if chunks is None:
            client.sendall(frame)
        else:
            offset = 0
            for size in chunks:
                client.sendall(frame[offset : offset + size])
                offset += size
            client.sendall(frame[offset:])
        prefix = _receive_exact(client, 4)
        size = struct.unpack(">I", prefix)[0]
        return json.loads(_receive_exact(client, size))
    finally:
        client.close()


def _assert_rejected(host, frame):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3)
    try:
        client.connect(str(host.socket_path))
        client.sendall(frame)
        assert client.recv(1) == b""
    finally:
        client.close()


def test_builds_arm64_dylib_and_pid_scoped_private_metadata(native_build, tmp_path):
    with _running_host(native_build, tmp_path) as host:
        metadata = _metadata(host)
        mode = stat.S_IMODE(host.metadata_path.stat().st_mode)

        assert set(metadata) == {"version", "pid", "socket_path", "token"}
        assert metadata["version"] == 1
        assert metadata["pid"] == host.pid
        assert metadata["socket_path"] == str(host.socket_path)
        assert len(metadata["token"]) == 64
        assert metadata["token"].isascii()
        assert mode == 0o600
        assert host.metadata_path.stat().st_uid == os.geteuid()
        assert stat.S_ISSOCK(host.socket_path.stat().st_mode)


def test_supports_distinct_instance_tag_paths(native_build, tmp_path):
    with _running_host(
        native_build, tmp_path, instance_tag="lv6"
    ) as host:
        metadata = _metadata(host)

        assert host.metadata_path.name.startswith(
            "bridge-lv6-"
        )
        assert host.socket_path.name.startswith(
            "wechat-bridge-lv6-"
        )
        assert metadata["socket_path"] == str(host.socket_path)


def test_long_safe_directory_uses_compact_socket_name(native_build, tmp_path):
    from wechat_cli.core.send_bridge import read_bridge_metadata

    with _running_host(
        native_build,
        tmp_path,
        instance_tag="official-task-v1",
        directory_prefix="wb-" + "x" * 55,
    ) as host:
        metadata = _metadata(host)

        assert host.socket_path.name.startswith("w")
        assert len(os.fsencode(metadata["socket_path"])) < 104
        assert read_bridge_metadata(host.metadata_path, host.pid).socket_path == (
            host.socket_path
        )


def test_python_client_round_trips_unicode_newline_and_raw_ack(native_build, tmp_path):
    with _running_host(native_build, tmp_path) as host:
        token = _metadata(host)["token"]
        client = AuthenticatedUnixBridgeClient(
            pid=host.pid,
            metadata_path=host.metadata_path,
            request_id_factory=lambda: "req-native-fixed",
        )
        receipt = client.send_text(
            SendRequest(
                group="精确群名",
                username="room@chatroom",
                text="你好 👋\n第二行",
                timeout=3,
            )
        )

        assert receipt.ack_state.value == "acknowledged"
        assert receipt.local_id == 41
        assert receipt.server_id == 99
        assert receipt.request_id == "req-native-fixed"

    assert host.stats == (1, 1)
    assert token not in host.stdout
    assert token not in host.stderr
    assert "你好" not in host.stdout
    assert "第二行" not in host.stdout
    assert host.stderr == ""


def test_fragmented_big_endian_frame_is_accepted(native_build, tmp_path):
    with _running_host(native_build, tmp_path) as host:
        frame = _encode_frame(_request_payload(host))
        receipt = _transact(host, frame, chunks=[1, 2, 1, 7, 13])

        assert receipt == {
            "version": 1,
            "type": "send_receipt",
            "ack_state": "acknowledged",
            "request_id": "req-native-fixed",
            "group": "精确群名",
            "username": "room@chatroom",
            "local_id": 41,
            "server_id": 99,
        }


def test_invalid_and_duplicate_auth_never_invoke_adapter(native_build, tmp_path):
    with _running_host(native_build, tmp_path) as host:
        invalid = _encode_frame(_request_payload(host, auth_token="x" * 64))
        _assert_rejected(host, invalid)

        payload = _request_payload(host)
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        duplicated = raw[:-1] + ',"auth_token":"x"}'
        duplicate_frame = struct.pack(">I", len(duplicated.encode())) + duplicated.encode()
        _assert_rejected(host, duplicate_frame)

        escaped_duplicate = raw[:-1] + ',"auth\\u005ftoken":"x"}'
        escaped_duplicate_frame = (
            struct.pack(">I", len(escaped_duplicate.encode()))
            + escaped_duplicate.encode()
        )
        _assert_rejected(host, escaped_duplicate_frame)

    assert host.stats == (0, 0)


def test_malformed_and_oversize_frames_never_invoke_adapter(native_build, tmp_path):
    with _running_host(native_build, tmp_path) as host:
        malformed = b'{"version":1,"type":'
        _assert_rejected(host, struct.pack(">I", len(malformed)) + malformed)
        _assert_rejected(host, struct.pack(">I", 0))
        _assert_rejected(host, struct.pack(">I", MAX_FRAME_BYTES + 1))

    assert host.stats == (0, 0)


@pytest.mark.parametrize("wrong_version", [2, 1.0, True])
def test_wrong_version_and_unexpected_fields_never_invoke_adapter(
    native_build, tmp_path, wrong_version
):
    with _running_host(native_build, tmp_path) as host:
        _assert_rejected(
            host,
            _encode_frame(_request_payload(host, version=wrong_version)),
        )
        unexpected = _request_payload(host)
        unexpected["extra"] = "not allowed"
        _assert_rejected(host, _encode_frame(unexpected))

    assert host.stats == (0, 0)


@pytest.mark.parametrize(
    "overrides",
    [
        {"group": ""},
        {"group": "含\u0000群名"},
        {"username": "wxid_not_a_group"},
        {"username": "room@chatroom\u0000"},
        {"text": ""},
        {"text": " \n\t"},
        {"text": "含\u0000文本"},
    ],
)
def test_invalid_target_or_text_never_invokes_adapter(
    native_build,
    tmp_path,
    overrides,
):
    with _running_host(native_build, tmp_path) as host:
        _assert_rejected(
            host,
            _encode_frame(_request_payload(host, **overrides)),
        )

    assert host.stats == (0, 0)


def test_deeply_nested_json_is_rejected_without_crashing_host(
    native_build,
    tmp_path,
):
    with _running_host(native_build, tmp_path) as host:
        metadata = _metadata(host)
        prefix = (
            '{"version":1,"type":"send_text","auth_token":"'
            + metadata["token"]
            + '","request_id":"req-deep","group":"精确群名",'
              '"username":"room@chatroom","text":'
        ).encode("utf-8")
        nested = b"[" * 20000 + b"null" + b"]" * 20000
        raw = prefix + nested + b"}"
        _assert_rejected(host, struct.pack(">I", len(raw)) + raw)

        receipt = _transact(host, _encode_frame(_request_payload(host)))
        assert receipt["ack_state"] == "acknowledged"

    assert host.stats == (1, 1)


def test_host_rejects_non_private_runtime_directory(native_build, tmp_path):
    host, _ = native_build
    unsafe_directory = tmp_path / "unsafe-runtime"
    unsafe_directory.mkdir(mode=0o755)
    unsafe_directory.chmod(0o755)
    result = subprocess.run(
        [
            str(host),
            "--safe-directory",
            str(unsafe_directory),
            "--ack-state",
            "acknowledged",
            "--delay-ms",
            "0",
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 4
    assert list(unsafe_directory.iterdir()) == []


def test_host_rejects_symlinked_runtime_directory(native_build, tmp_path):
    host, _ = native_build
    short_root = Path(tempfile.mkdtemp(prefix="wb-link-", dir="/tmp"))
    real_directory = short_root / "real"
    linked_directory = short_root / "link"
    real_directory.mkdir(mode=0o700)
    linked_directory.symlink_to(real_directory, target_is_directory=True)

    result = subprocess.run(
        [
            str(host),
            "--safe-directory",
            str(linked_directory),
            "--ack-state",
            "acknowledged",
            "--delay-ms",
            "0",
            "--adapter-timeout-ms",
            "3000",
            "--start-once",
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        timeout=10,
    )
    try:
        assert result.returncode == 4
        assert list(real_directory.iterdir()) == []
    finally:
        linked_directory.unlink(missing_ok=True)
        real_directory.rmdir()
        short_root.rmdir()


def test_concurrent_clients_are_processed_single_flight(native_build, tmp_path):
    with _running_host(native_build, tmp_path, delay_ms=120) as host:
        barrier = threading.Barrier(4)
        receipts = []
        errors = []

        def worker(index):
            try:
                barrier.wait()
                receipts.append(
                    _transact(
                        host,
                        _encode_frame(
                            _request_payload(host, request_id=f"req-{index}")
                        ),
                    )
                )
            except Exception as error:
                errors.append(error)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(3)]
        for thread in threads:
            thread.start()
        started = time.monotonic()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=3)
        elapsed = time.monotonic() - started

        assert errors == []
        assert len(receipts) == 3
        assert all(receipt["ack_state"] == "acknowledged" for receipt in receipts)
        assert elapsed >= 0.30

    assert host.stats == (3, 1)


def test_unknown_adapter_result_preserves_raw_unknown(native_build, tmp_path):
    with _running_host(native_build, tmp_path, ack_state="unknown") as host:
        receipt = _transact(host, _encode_frame(_request_payload(host)))

        assert receipt["ack_state"] == "unknown"
        assert receipt["local_id"] is None
        assert receipt["server_id"] is None

    assert host.stats == (1, 1)


def test_submitted_adapter_result_preserves_raw_submitted(
    native_build,
    tmp_path,
):
    with _running_host(
        native_build,
        tmp_path,
        ack_state="submitted",
    ) as host:
        receipt = _transact(host, _encode_frame(_request_payload(host)))

        assert receipt["ack_state"] == "submitted"
        assert receipt["local_id"] is None
        assert receipt["server_id"] is None

    assert host.stats == (1, 1)


def test_adapter_timeout_retires_socket_and_metadata(native_build, tmp_path):
    with _running_host(
        native_build,
        tmp_path,
        delay_ms=200,
        adapter_timeout_ms=20,
    ) as host:
        receipt = _transact(host, _encode_frame(_request_payload(host)))
        assert receipt["ack_state"] == "unknown"

        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            if not host.socket_path.exists() and not host.metadata_path.exists():
                break
            time.sleep(0.01)
        assert not host.socket_path.exists()
        assert not host.metadata_path.exists()


def test_stop_interrupts_adapter_wait_promptly(native_build, tmp_path):
    with _running_host(
        native_build,
        tmp_path,
        delay_ms=3000,
        adapter_timeout_ms=3000,
    ) as host:
        errors = []

        def transact():
            try:
                _transact(host, _encode_frame(_request_payload(host)))
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=transact, daemon=True)
        worker.start()
        time.sleep(0.1)
        started = time.monotonic()
        host.stop()
        elapsed = time.monotonic() - started

        assert elapsed < 1.0


def test_teardown_removes_only_owned_exact_paths(native_build, tmp_path):
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")

    with _running_host(native_build, tmp_path) as host:
        metadata_path = host.metadata_path
        socket_path = host.socket_path
        assert metadata_path.exists()
        assert socket_path.exists()

    assert not metadata_path.exists()
    assert not socket_path.exists()
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_production_factory_rejects_process_without_pinned_wechat_image(
    native_build,
):
    host, _ = native_build
    completed = subprocess.run(
        [str(host), "--verify-production-image-rejected"],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_official_task_adapter_contract(native_build):
    host, _ = native_build
    completed = subprocess.run(
        [str(host), "--verify-official-task-adapter"],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "dispatch_calls": 1,
        "builder_calls": 1,
        "submit_calls": 1,
        "builder_before_submit": True,
        "builder_service_is_null": True,
        "builder_mode": 1,
        "model_fields_valid": True,
        "vector_aliases_model": True,
        "vector_shares_ownership": True,
        "callbacks_empty": True,
        "source_location_valid": True,
        "receipt": {
            "ack_state": "submitted",
            "local_id": None,
            "server_id": None,
        },
    }


def test_official_task_adapter_uses_exact_sret_storage_sizes():
    source = (ROOT / "native" / "src" / "official_task_adapter.mm").read_text(
        encoding="utf-8"
    )

    assert "static_assert(sizeof(OpaqueTask) == 0x38);" in source
    assert "static_assert(sizeof(OpaqueHandle) == 0x28);" in source


def test_injector_keeps_loader_code_off_pthread_storage_page(native_build):
    host, _ = native_build
    injector = host.parent / "wechat_send_injector"

    result = subprocess.run(
        [str(injector), "--verify-memory-layout"],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_injector_loader_stub_exits_the_created_pthread(native_build):
    host, _ = native_build
    injector = host.parent / "wechat_send_injector"

    result = subprocess.run(
        [str(injector), "--verify-loader-stub"],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_fixed_hook_island_signature_is_fail_closed(native_build):
    host, _ = native_build

    result = subprocess.run(
        [str(host), "--verify-hook-island-signature"],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_hook_writes_never_request_write_and_execute_together(native_build):
    host, _ = native_build

    result = subprocess.run(
        [str(host), "--verify-hook-write-protection"],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_empty_text_response_reports_decode_success(native_build):
    host, _ = native_build

    result = subprocess.run(
        [str(host), "--verify-empty-response-status"],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_production_build_excludes_crashing_high_level_send(native_build):
    host, _ = native_build
    dylib = host.parent / "libwechat_official_task_bridge_v2.dylib"
    assert dylib.is_file()
    symbols = subprocess.run(
        ["nm", "-nm", str(dylib)],
        check=True,
        text=True,
        capture_output=True,
    ).stdout
    build_script = (ROOT / "native" / "build.sh").read_text(encoding="utf-8")
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "native" / "src").glob("*.mm")
    )

    assert "OwlHighLevelSendAdapter" not in symbols
    assert "OwlHighLevelSendAdapter" not in source
    assert "VerifyOwlMainScopeRunner" not in symbols
    assert "CreateLocalVisibleAdapter" not in symbols
    assert "CreateLegacyMarsWeChatAdapter" not in symbols
    assert "WechatBridgeReq2Buf" not in symbols
    assert "WechatBridgeHandleReq2Buf" not in symbols
    assert "wechat_local_visible.mm" not in build_script
    assert "libwechat_official_task_bridge_v2.dylib" in build_script
    assert "official_task_adapter.mm" in build_script
    assert "0x25cd228" not in source.lower()
    assert "0x3399194" not in source.lower()
    unsafe_artifacts = (
        "libwechat_local_visible_bridge.dylib",
        "libwechat_local_visible_bridge_v3.dylib",
        "libwechat_local_visible_bridge_v4.dylib",
        "libwechat_local_visible_bridge_v5.dylib",
        "libwechat_local_visible_bridge_v6.dylib",
    )
    assert all(not (ROOT / "wechat_cli" / "bin" / name).exists()
               for name in unsafe_artifacts)


def test_release_package_excludes_legacy_mars_bridge():
    assert not (
        ROOT / "wechat_cli" / "bin" / "libwechat_send_bridge.dylib"
    ).exists()


def _run_transaction_scenario(native_build, scenario):
    host, _ = native_build
    result = subprocess.run(
        [str(host), "--verify-local-visible-transaction", scenario],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize(
    (
        "scenario",
        "expected_local_calls",
        "expected_network_calls",
        "expected_update_calls",
    ),
    [
        ("insert-failed", 1, 0, 0),
        ("network-unknown", 1, 1, 0),
        ("accepted", 1, 1, 1),
    ],
)
def test_local_visible_transaction_order(
    native_build,
    scenario,
    expected_local_calls,
    expected_network_calls,
    expected_update_calls,
):
    result = _run_transaction_scenario(native_build, scenario)

    assert result["insert_calls"] == expected_local_calls
    assert result["network_calls"] == expected_network_calls
    assert result["update_calls"] == expected_update_calls


def test_local_visible_transaction_reuses_identifiers(native_build):
    result = _run_transaction_scenario(native_build, "accepted")

    assert result["insert_client_id"] == result["network_client_id"]
    assert result["insert_local_id"] == result["update_local_id"] == 41
    assert result["receipt"] == {
        "ack_state": "acknowledged",
        "local_id": 41,
        "server_id": 99,
    }
