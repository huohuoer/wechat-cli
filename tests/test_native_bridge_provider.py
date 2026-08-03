from types import SimpleNamespace

from wechat_cli.core import native_bridge_provider


def _reader(path, pid):
    reader = getattr(
        native_bridge_provider,
        "_read_bridge_startup_error",
        lambda _path, _pid: None,
    )
    return reader(path, pid)


def test_reads_safe_pid_scoped_bridge_startup_reason(tmp_path):
    path = tmp_path / "bridge-official-task-v1-123.error"
    path.write_text("wechat_hook_install_failed\n", encoding="ascii")
    path.chmod(0o600)

    assert _reader(path, 123) == (
        "wechat_hook_install_failed"
    )


def test_ignores_unsafe_bridge_startup_reason(tmp_path):
    path = tmp_path / "bridge-official-task-v1-123.error"
    path.write_text("unsafe detail with spaces", encoding="ascii")
    path.chmod(0o644)

    assert _reader(path, 123) is None


def test_uses_official_task_bridge_artifacts(tmp_path):
    metadata, startup_error = native_bridge_provider._bridge_paths(
        tmp_path, 123
    )

    assert metadata.name == "bridge-official-task-v1-123.json"
    assert startup_error.name == "bridge-official-task-v1-123.error"
    assert native_bridge_provider.BRIDGE_INSTANCE_TAG == "official-task-v1"
    assert native_bridge_provider.BRIDGE_DYLIB_NAME == (
        "libwechat_official_task_bridge_v2.dylib"
    )


def test_prepare_native_bridge_does_not_require_profile_manifest(
    monkeypatch,
    tmp_path,
):
    injector = tmp_path / "wechat_send_injector"
    bridge_dylib = tmp_path / "libwechat_official_task_bridge_v2.dylib"
    injector.write_bytes(b"injector")
    bridge_dylib.write_bytes(b"bridge")
    usable_calls = []
    run_calls = []

    def usable_metadata(path, pid):
        usable_calls.append((path, pid))
        return len(usable_calls) > 1

    def fake_run(args, **kwargs):
        run_calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(
        native_bridge_provider,
        "_safe_bridge_directory",
        lambda: tmp_path,
    )
    monkeypatch.setattr(
        native_bridge_provider,
        "_usable_metadata",
        usable_metadata,
    )
    monkeypatch.setattr(
        native_bridge_provider,
        "_package_binary",
        lambda name: tmp_path / name,
    )
    monkeypatch.setattr(
        native_bridge_provider.subprocess,
        "run",
        fake_run,
    )

    client = native_bridge_provider.prepare_native_bridge(
        SimpleNamespace(pid=123),
        "12345678-1234-1234-1234-123456789abc",
    )

    assert client.pid == 123
    assert client.metadata_path == tmp_path / "bridge-official-task-v1-123.json"
    assert len(run_calls) == 1
    assert run_calls[0][0] == [str(injector), "123", str(bridge_dylib)]
