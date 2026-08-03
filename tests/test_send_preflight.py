import hashlib
import plistlib
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from wechat_cli.core.sending import SendUnavailableError


ARM64 = 0x0100000C
EXPECTED_UUID = "ABD88EC8-4590-3FDB-AAB5-4E5865B86B2A"
MH_EXECUTE = 2
MH_DYLIB = 6


def _thin_macho(
    cpu_type=ARM64,
    uuid=EXPECTED_UUID,
    *,
    cpu_subtype=0,
    file_type=MH_EXECUTE,
    is_64=True,
):
    uuid_bytes = bytes.fromhex(uuid.replace("-", ""))
    command = struct.pack("<II16s", 0x1B, 24, uuid_bytes)
    if is_64:
        header = struct.pack(
            "<IIIIIIII",
            0xFEEDFACF,
            cpu_type,
            cpu_subtype,
            file_type,
            1,
            len(command),
            0,
            0,
        )
    else:
        header = struct.pack(
            "<IIIIIII",
            0xFEEDFACE,
            cpu_type,
            cpu_subtype,
            file_type,
            1,
            len(command),
            0,
        )
    return header + command


@pytest.fixture(autouse=True)
def _approve_test_dylib_hash(monkeypatch):
    from wechat_cli.core import send_preflight

    monkeypatch.setattr(
        send_preflight,
        "EXPECTED_DYLIB_SHA256",
        hashlib.sha256(_thin_macho(file_type=MH_DYLIB)).hexdigest(),
    )


def _fat_macho(*slices):
    header_size = 8 + 20 * len(slices)
    offset = header_size
    entries = []
    payload = []
    for cpu_type, data in slices:
        entries.append(struct.pack(">IIIII", cpu_type, 0, offset, len(data), 0))
        payload.append(data)
        offset += len(data)
    return (
        struct.pack(">II", 0xCAFEBABE, len(slices))
        + b"".join(entries)
        + b"".join(payload)
    )


def _fat64_macho(data, *, reserved=0):
    header_size = 8 + 32
    entry = struct.pack(
        ">IIQQII",
        ARM64,
        0,
        header_size,
        len(data),
        3,
        reserved,
    )
    return struct.pack(">II", 0xCAFEBABF, 1) + entry + data


def test_macho_parser_reads_arm64_uuid_from_fat_binary():
    from wechat_cli.core.send_preflight import arm64_uuid

    data = _fat_macho(
        (0x01000007, _thin_macho(0x01000007, "00112233-4455-6677-8899-AABBCCDDEEFF")),
        (ARM64, _thin_macho()),
    )

    assert arm64_uuid(data) == EXPECTED_UUID


@pytest.mark.parametrize(
    "data",
    [
        b"",
        struct.pack(">II", 0xCAFEBABE, 1),
        _thin_macho()[:-1],
        _fat_macho((ARM64, b"not-a-mach-o")),
    ],
)
def test_macho_parser_fails_closed_on_truncated_or_invalid_data(data):
    from wechat_cli.core.send_preflight import MachOError, arm64_uuid

    with pytest.raises(MachOError):
        arm64_uuid(data)


def test_macho_parser_rejects_nonzero_fat64_reserved_field():
    from wechat_cli.core.send_preflight import MachOError, parse_macho

    with pytest.raises(MachOError, match="reserved"):
        parse_macho(_fat64_macho(_thin_macho(), reserved=1))


class FakeRunner:
    def __init__(
        self,
        bundle_path,
        db_path,
        pids=(4242,),
        executable_path=None,
        process_uid=501,
        change_identity=False,
    ):
        self.bundle_path = Path(bundle_path)
        self.db_path = Path(db_path)
        self.pids = pids
        self.executable_path = executable_path
        self.process_uid = process_uid
        self.change_identity = change_identity
        self.identity_calls = 0
        self.calls = []

    def __call__(self, args, *, timeout):
        self.calls.append((tuple(args), timeout))
        if args == ["/usr/bin/pgrep", "-x", "WeChat"]:
            if not self.pids:
                return SimpleNamespace(returncode=1, stdout=b"", stderr=b"")
            output = "".join(f"{pid}\n" for pid in self.pids).encode()
            return SimpleNamespace(returncode=0, stdout=output, stderr=b"")
        if args[:3] == ["/bin/ps", "-p", str(self.pids[0])]:
            self.identity_calls += 1
            executable = self.executable_path or (
                self.bundle_path / "Contents/MacOS/WeChat"
            )
            started_at = (
                "Thu Jul 30 16:52:06 2026"
                if self.change_identity and self.identity_calls > 1
                else "Thu Jul 30 16:52:05 2026"
            )
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    f"{self.pids[0]} {self.process_uid} "
                    f"{started_at} {executable}\n"
                ).encode(),
                stderr=b"",
            )
        if args[:5] == [
            "/usr/sbin/lsof",
            "-n",
            "-P",
            "-a",
            "-p",
        ]:
            return SimpleNamespace(
                returncode=0,
                stdout=f"p{self.pids[0]}\nfcwd\nn/\nf10\nn{self.db_path}\n".encode(),
                stderr=b"",
            )
        raise AssertionError(f"unexpected command: {args!r}")


def _make_bundle(tmp_path):
    bundle = tmp_path / "Applications/WeChat.app"
    executable = bundle / "Contents/MacOS/WeChat"
    dylib = bundle / "Contents/Frameworks/wechat.dylib"
    executable.parent.mkdir(parents=True)
    dylib.parent.mkdir(parents=True)
    executable.write_bytes(_thin_macho(file_type=MH_EXECUTE))
    dylib.write_bytes(_thin_macho(file_type=MH_DYLIB))
    with (bundle / "Contents/Info.plist").open("wb") as file:
        plistlib.dump(
            {
                "CFBundleIdentifier": "com.tencent.xinWeChat",
                "CFBundleExecutable": "WeChat",
                "CFBundleShortVersionString": "4.1.8",
                "CFBundleVersion": "36571",
                "WeChatBundleVersion": "4.1.8.28",
            },
            file,
        )
    db_dir = tmp_path / "db"
    db_dir.mkdir()
    db_path = db_dir / "message_0.db"
    db_path.write_bytes(b"db")
    return bundle, db_dir, db_path


def _inspector(bundle, runner, **overrides):
    from wechat_cli.core.send_preflight import PreflightInspector

    options = {
        "system": lambda: "Darwin",
        "machine": lambda: "arm64",
        "euid": lambda: 501,
        "command_runner": runner,
        "expected_bundle_path": bundle,
    }
    options.update(overrides)
    return PreflightInspector(**options)


def test_preflight_accepts_only_exact_supported_profile_and_open_database(
    tmp_path,
    monkeypatch,
):
    from wechat_cli.core import send_preflight
    from wechat_cli.core.send_preflight import verify_pre_injection

    bundle, db_dir, db_path = _make_bundle(tmp_path)
    dylib = bundle / "Contents/Frameworks/wechat.dylib"
    monkeypatch.setattr(
        send_preflight,
        "EXPECTED_DYLIB_SHA256",
        hashlib.sha256(dylib.read_bytes()).hexdigest(),
    )
    runner = FakeRunner(bundle, db_path)

    profile = verify_pre_injection(
        SimpleNamespace(db_dir=str(db_dir)),
        inspector=_inspector(bundle, runner),
    )

    assert profile.pid == 4242
    assert profile.bundle_path == bundle
    assert profile.executable_path == bundle / "Contents/MacOS/WeChat"
    assert profile.dylib_path == bundle / "Contents/Frameworks/wechat.dylib"
    assert profile.arch == "arm64"
    assert profile.process_uid == 501
    assert profile.process_started_at == "Thu Jul 30 16:52:05 2026"
    assert profile.dylib_uuid == EXPECTED_UUID
    assert profile.open_db_paths == (db_path.resolve(),)
    assert runner.identity_calls == 2
    assert all(isinstance(call[0], tuple) for call in runner.calls)


@pytest.mark.parametrize(
    ("system", "machine"),
    [("Linux", "arm64"), ("Darwin", "x86_64")],
)
def test_preflight_rejects_unsupported_host_before_running_commands(
    tmp_path,
    system,
    machine,
):
    from wechat_cli.core.send_preflight import verify_pre_injection

    bundle, db_dir, db_path = _make_bundle(tmp_path)
    runner = FakeRunner(bundle, db_path)

    with pytest.raises(SendUnavailableError, match="macOS arm64"):
        verify_pre_injection(
            SimpleNamespace(db_dir=str(db_dir)),
            inspector=_inspector(
                bundle,
                runner,
                system=lambda: system,
                machine=lambda: machine,
            ),
        )

    assert runner.calls == []


@pytest.mark.parametrize("pids", [(), (1, 2)])
def test_preflight_requires_exactly_one_main_wechat_process(tmp_path, pids):
    from wechat_cli.core.send_preflight import verify_pre_injection

    bundle, db_dir, db_path = _make_bundle(tmp_path)
    runner = FakeRunner(bundle, db_path, pids=pids)

    with pytest.raises(SendUnavailableError, match="恰好一个"):
        verify_pre_injection(
            SimpleNamespace(db_dir=str(db_dir)),
            inspector=_inspector(bundle, runner),
        )


def test_preflight_rejects_process_running_from_another_bundle(tmp_path):
    from wechat_cli.core.send_preflight import verify_pre_injection

    bundle, db_dir, db_path = _make_bundle(tmp_path)
    runner = FakeRunner(
        bundle,
        db_path,
        executable_path=tmp_path / "Other.app/Contents/MacOS/WeChat",
    )

    with pytest.raises(SendUnavailableError, match="可执行文件路径"):
        verify_pre_injection(
            SimpleNamespace(db_dir=str(db_dir)),
            inspector=_inspector(bundle, runner),
        )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("CFBundleIdentifier", "invalid.bundle"),
        ("CFBundleExecutable", "WeChatBeta"),
        ("CFBundleShortVersionString", "4.1.9"),
        ("CFBundleVersion", "36572"),
        ("WeChatBundleVersion", "4.1.8.29"),
    ],
)
def test_preflight_rejects_every_info_plist_profile_mismatch(
    tmp_path,
    key,
    value,
):
    from wechat_cli.core.send_preflight import verify_pre_injection

    bundle, db_dir, db_path = _make_bundle(tmp_path)
    plist_path = bundle / "Contents/Info.plist"
    with plist_path.open("rb") as file:
        info = plistlib.load(file)
    info[key] = value
    with plist_path.open("wb") as file:
        plistlib.dump(info, file)
    runner = FakeRunner(bundle, db_path)

    with pytest.raises(SendUnavailableError, match="Info.plist"):
        verify_pre_injection(
            SimpleNamespace(db_dir=str(db_dir)),
            inspector=_inspector(bundle, runner),
        )


def test_preflight_rejects_unapproved_dylib_hash_before_any_send(
    tmp_path,
    monkeypatch,
):
    from wechat_cli.core import send_preflight
    from wechat_cli.core.send_preflight import verify_pre_injection

    bundle, db_dir, db_path = _make_bundle(tmp_path)
    runner = FakeRunner(bundle, db_path)
    monkeypatch.setattr(send_preflight, "EXPECTED_DYLIB_SHA256", "0" * 64)

    with pytest.raises(SendUnavailableError, match="SHA-256"):
        verify_pre_injection(
            SimpleNamespace(db_dir=str(db_dir)),
            inspector=_inspector(bundle, runner),
        )


def test_preflight_rejects_symlinked_approved_bundle_file(tmp_path):
    from wechat_cli.core.send_preflight import verify_pre_injection

    bundle, db_dir, db_path = _make_bundle(tmp_path)
    dylib = bundle / "Contents/Frameworks/wechat.dylib"
    target = tmp_path / "copied-wechat.dylib"
    target.write_bytes(dylib.read_bytes())
    dylib.unlink()
    dylib.symlink_to(target)
    runner = FakeRunner(bundle, db_path)

    with pytest.raises(SendUnavailableError, match="安全读取"):
        verify_pre_injection(
            SimpleNamespace(db_dir=str(db_dir)),
            inspector=_inspector(bundle, runner),
        )


def test_preflight_rejects_symlinked_approved_bundle_directory(tmp_path):
    from wechat_cli.core.send_preflight import verify_pre_injection

    real_bundle, db_dir, db_path = _make_bundle(tmp_path / "real")
    linked_bundle = tmp_path / "Applications/WeChat.app"
    linked_bundle.parent.mkdir(parents=True)
    linked_bundle.symlink_to(real_bundle, target_is_directory=True)
    runner = FakeRunner(linked_bundle, db_path)

    with pytest.raises(SendUnavailableError, match="安全读取"):
        verify_pre_injection(
            SimpleNamespace(db_dir=str(db_dir)),
            inspector=_inspector(linked_bundle, runner),
        )


def test_preflight_rejects_missing_arm64_architecture_or_uuid(
    tmp_path,
    monkeypatch,
):
    from wechat_cli.core import send_preflight
    from wechat_cli.core.send_preflight import verify_pre_injection

    bundle, db_dir, db_path = _make_bundle(tmp_path)
    dylib = bundle / "Contents/Frameworks/wechat.dylib"
    dylib.write_bytes(
        _thin_macho(
            0x01000007,
            "00112233-4455-6677-8899-AABBCCDDEEFF",
            file_type=MH_DYLIB,
        )
    )
    monkeypatch.setattr(
        send_preflight,
        "EXPECTED_DYLIB_SHA256",
        hashlib.sha256(dylib.read_bytes()).hexdigest(),
    )
    runner = FakeRunner(bundle, db_path)

    with pytest.raises(SendUnavailableError, match="arm64"):
        verify_pre_injection(
            SimpleNamespace(db_dir=str(db_dir)),
            inspector=_inspector(bundle, runner),
        )


def test_preflight_requires_wechat_to_have_database_file_open_under_db_dir(
    tmp_path,
):
    from wechat_cli.core.send_preflight import verify_pre_injection

    bundle, db_dir, _ = _make_bundle(tmp_path)
    outside_db = tmp_path / "outside/message.db"
    outside_db.parent.mkdir()
    outside_db.write_bytes(b"db")
    runner = FakeRunner(bundle, outside_db)

    with pytest.raises(SendUnavailableError, match="数据库"):
        verify_pre_injection(
            SimpleNamespace(db_dir=str(db_dir)),
            inspector=_inspector(bundle, runner),
        )


def test_preflight_does_not_treat_directory_named_like_database_as_db_file(
    tmp_path,
):
    from wechat_cli.core.send_preflight import verify_pre_injection

    bundle, db_dir, _ = _make_bundle(tmp_path)
    fake_db_directory = db_dir / "not-a-file.db"
    fake_db_directory.mkdir()
    runner = FakeRunner(bundle, fake_db_directory)

    with pytest.raises(SendUnavailableError, match="数据库"):
        verify_pre_injection(
            SimpleNamespace(db_dir=str(db_dir)),
            inspector=_inspector(bundle, runner),
        )


@pytest.mark.parametrize(
    "bad_executable",
    [
        _thin_macho(is_64=False, file_type=1),
        _thin_macho(file_type=1),
        _thin_macho(cpu_subtype=2, file_type=MH_EXECUTE),
    ],
)
def test_preflight_rejects_non_arm64_all_64_bit_executable(
    tmp_path,
    monkeypatch,
    bad_executable,
):
    from wechat_cli.core import send_preflight
    from wechat_cli.core.send_preflight import verify_pre_injection

    bundle, db_dir, db_path = _make_bundle(tmp_path)
    dylib = bundle / "Contents/Frameworks/wechat.dylib"
    monkeypatch.setattr(
        send_preflight,
        "EXPECTED_DYLIB_SHA256",
        hashlib.sha256(dylib.read_bytes()).hexdigest(),
    )
    (bundle / "Contents/MacOS/WeChat").write_bytes(bad_executable)
    runner = FakeRunner(bundle, db_path)

    with pytest.raises(SendUnavailableError, match="arm64"):
        verify_pre_injection(
            SimpleNamespace(db_dir=str(db_dir)),
            inspector=_inspector(bundle, runner),
        )


def test_preflight_rejects_process_owned_by_another_uid(tmp_path):
    from wechat_cli.core.send_preflight import verify_pre_injection

    bundle, db_dir, db_path = _make_bundle(tmp_path)
    runner = FakeRunner(bundle, db_path, process_uid=502)

    with pytest.raises(SendUnavailableError, match="进程身份"):
        verify_pre_injection(
            SimpleNamespace(db_dir=str(db_dir)),
            inspector=_inspector(bundle, runner),
        )


def test_preflight_revalidates_process_start_identity_at_end(tmp_path):
    from wechat_cli.core.send_preflight import verify_pre_injection

    bundle, db_dir, db_path = _make_bundle(tmp_path)
    runner = FakeRunner(bundle, db_path, change_identity=True)

    with pytest.raises(SendUnavailableError, match="进程已变化"):
        verify_pre_injection(
            SimpleNamespace(db_dir=str(db_dir)),
            inspector=_inspector(bundle, runner),
        )

    assert runner.identity_calls == 2


def test_preflight_rejects_path_replaced_after_safe_open(
    tmp_path,
    monkeypatch,
):
    from wechat_cli.core import send_preflight
    from wechat_cli.core.send_preflight import verify_pre_injection

    bundle, db_dir, db_path = _make_bundle(tmp_path)
    dylib = bundle / "Contents/Frameworks/wechat.dylib"
    moved = tmp_path / "moved-wechat.dylib"
    approved_hash = hashlib.sha256(dylib.read_bytes()).hexdigest()
    monkeypatch.setattr(
        send_preflight,
        "EXPECTED_DYLIB_SHA256",
        approved_hash,
    )
    real_open = send_preflight.os.open
    raced = False

    def racing_open(path, flags, *, dir_fd=None):
        nonlocal raced
        if dir_fd is None:
            descriptor = real_open(path, flags)
        else:
            descriptor = real_open(path, flags, dir_fd=dir_fd)
        if Path(path).name == dylib.name and dir_fd is not None and not raced:
            raced = True
            dylib.rename(moved)
            dylib.symlink_to(moved)
        return descriptor

    monkeypatch.setattr(send_preflight.os, "open", racing_open)
    runner = FakeRunner(bundle, db_path)

    with pytest.raises(SendUnavailableError, match="安全读取"):
        verify_pre_injection(
            SimpleNamespace(db_dir=str(db_dir)),
            inspector=_inspector(bundle, runner),
        )
