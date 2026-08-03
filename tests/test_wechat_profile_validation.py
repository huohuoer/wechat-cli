import copy
import hashlib
import json
from pathlib import Path
import struct
import uuid

import pytest

from tools import validate_wechat_profile as validator


EXPECTED_UUID = "ABD88EC8-4590-3FDB-AAB5-4E5865B86B2A"
EXPECTED_SHA256 = (
    "b4a740135f3f1e937bca10caf0a95cff986ddf27fa6bb15ccaf64001fc651c93"
)
EXPECTED_ARM64_SLICE_SHA256 = (
    "0e8c932461b883a4e4dc90313a14a30ea69a190fedf1083d014259bec56da2e0"
)


def _measured_profile(*, adapter_ready=False):
    return {
        "schema_version": 2,
        "evidence_kind": "read_only_lldb",
        "adapter_ready": adapter_ready,
        "capture_sha256": "1" * 64,
        "marker_sha256": "2" * 64,
        "image": {
            "path": "/Applications/WeChat.app/Contents/Frameworks/wechat.dylib",
            "uuid": EXPECTED_UUID,
            "sha256": EXPECTED_SHA256,
            "arm64_slice_sha256": EXPECTED_ARM64_SLICE_SHA256,
        },
        "runtime_ready": {
            "entry_rva": 0x3EF9964,
            "signature": "e98202f029b143f9490000b420011fd6",
            "ready_value": 1,
        },
        "execution_context": {
            "thread_name": "coroutine",
            "queue_label": "owl.main",
            "dispatch_rva": 0x57B30,
            "signature": "f85fbca9f65701a9f44f02a9fd7b03a9",
        },
        "model": {
            "factory_rva": 0x1010,
            "factory_signature": "3" * 32,
            "recipient_setter_rva": 0x1020,
            "recipient_setter_signature": "4" * 32,
            "text_setter_rva": 0x1030,
            "text_setter_signature": "5" * 32,
            "client_id_setter_rva": 0x1040,
            "client_id_setter_signature": "6" * 32,
            "create_time_setter_rva": 0x1050,
            "create_time_setter_signature": "7" * 32,
            "ownership": "shared_ptr",
        },
        "insert": {
            "entry_rva": 0x26E6264,
            "signature": "e93c0390294d42f9490000b420011fd6",
            "local_id_before": 0,
            "local_id_after": 41,
            "client_id": 202608020001,
        },
        "mars": {"client_id": 202608020001, "submit_count": 1},
        "response": {
            "decode_rva": 0x372FD60,
            "signature": "8" * 32,
            "server_id": 99,
        },
        "update": {
            "entry_rva": 0x26EA4FC,
            "signature": "c93c0390296142f9490000b420011fd6",
            "local_id": 41,
            "server_id_before": 0,
            "server_id_after": 99,
        },
        "notification": {
            "entry_rva": 0x202906C,
            "signature": "9" * 32,
            "local_id": 41,
        },
    }


def test_measured_profile_is_valid_but_cannot_enable_adapter():
    assert validator.validate_profile(_measured_profile()) == (
        "profile_valid_not_ready"
    )
    assert validator.validate_profile(_measured_profile(adapter_ready=True)) == (
        "adapter_must_remain_disabled"
    )


@pytest.mark.parametrize(
    "section",
    [
        "image",
        "runtime_ready",
        "execution_context",
        "model",
        "insert",
        "mars",
        "response",
        "update",
        "notification",
    ],
)
def test_profile_rejects_every_incomplete_nested_section(section):
    profile = _measured_profile()
    profile[section].pop(next(iter(profile[section])))

    assert validator.validate_profile(profile) == f"invalid_{section}_fields"


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (("mars", "client_id", 202608020002), "client_id_disagreement"),
        (("update", "local_id", 42), "local_id_disagreement"),
        (("notification", "local_id", 42), "local_id_disagreement"),
        (("update", "server_id_after", 100), "server_id_disagreement"),
    ],
)
def test_profile_rejects_identifier_disagreement(mutation, expected):
    section, field, value = mutation
    profile = _measured_profile()
    profile[section][field] = value

    assert validator.validate_profile(profile) == expected


@pytest.mark.parametrize("unsafe_rva", [0x25CD228, 0x3399194])
def test_profile_rejects_unsafe_high_level_rvas(unsafe_rva):
    profile = _measured_profile()
    profile["insert"]["entry_rva"] = unsafe_rva

    assert validator.validate_profile(profile) == "unsafe_rva"


def test_profile_rejects_wrong_raw_capture_digest():
    profile = _measured_profile()

    assert validator.validate_profile(profile, raw_capture=b"raw capture") == (
        "capture_digest_mismatch"
    )


def _thin_macho(image_uuid):
    header = struct.pack(
        "<8I",
        validator.MACHO_64_MAGIC,
        0,
        0,
        0,
        1,
        24,
        0,
        0,
    )
    command = struct.pack(
        "<II16s",
        validator.LC_UUID,
        24,
        uuid.UUID(image_uuid).bytes,
    )
    return header + command


def test_macho_uuid_rejects_unaligned_load_commands(tmp_path):
    image = tmp_path / "unaligned-macho"
    image.write_bytes(
        struct.pack(
            "<8I",
            validator.MACHO_64_MAGIC,
            0,
            0,
            0,
            1,
            9,
            0,
            0,
        )
        + struct.pack("<II", 1, 9)
        + b"\0"
    )

    with pytest.raises(ValueError, match="invalid_load_command"):
        validator._macho_uuid(image)


def test_sanitizer_hashes_exact_input_and_omits_raw_secrets(monkeypatch, tmp_path):
    image = tmp_path / "wechat.dylib"
    arm64_slice = tmp_path / "wechat-arm64.dylib"
    image.write_bytes(b"universal image")
    arm64_slice.write_bytes(_thin_macho(EXPECTED_UUID))
    monkeypatch.setattr(validator, "EXPECTED_IMAGE_PATH", str(image))
    monkeypatch.setattr(
        validator,
        "EXPECTED_SHA256",
        hashlib.sha256(image.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        validator,
        "EXPECTED_ARM64_SLICE_SHA256",
        hashlib.sha256(arm64_slice.read_bytes()).hexdigest(),
    )
    observation = copy.deepcopy(_measured_profile())
    raw_capture = (
        json.dumps(
            {
                "label": "profile_observation",
                "profile": observation,
                "registers": {"x0": "secret-register"},
                "regions": {"x0": "secret-memory"},
                "backtrace": [{"function": "secret-frame"}],
                "marker": "secret-marker-text",
                "auth_token": "secret-auth-token",
            },
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )

    profile = validator.sanitize_capture(
        raw_capture,
        image_path=image,
        arm64_slice_path=arm64_slice,
        marker="WCPROFILE-20260802-01",
    )

    assert profile["capture_sha256"] == hashlib.sha256(raw_capture).hexdigest()
    assert profile["marker_sha256"] == hashlib.sha256(
        b"WCPROFILE-20260802-01"
    ).hexdigest()
    assert validator.validate_profile(profile, raw_capture=raw_capture) == (
        "profile_valid_not_ready"
    )
    serialized = json.dumps(profile, sort_keys=True)
    for secret in (
        "secret-register",
        "secret-memory",
        "secret-frame",
        "secret-marker-text",
        "secret-auth-token",
    ):
        assert secret not in serialized


def test_sanitizer_rejects_marker_text_in_retained_profile_fields(
    monkeypatch, tmp_path
):
    marker = "WCPROFILE-20260802-01"
    image = tmp_path / "wechat.dylib"
    arm64_slice = tmp_path / "wechat-arm64.dylib"
    image.write_bytes(b"universal image")
    arm64_slice.write_bytes(_thin_macho(EXPECTED_UUID))
    monkeypatch.setattr(validator, "EXPECTED_IMAGE_PATH", str(image))
    monkeypatch.setattr(
        validator,
        "EXPECTED_SHA256",
        hashlib.sha256(image.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        validator,
        "EXPECTED_ARM64_SLICE_SHA256",
        hashlib.sha256(arm64_slice.read_bytes()).hexdigest(),
    )
    observation = _measured_profile()
    observation["execution_context"]["queue_label"] = f"owl.main:{marker}"
    raw_capture = (
        json.dumps(
            {"label": "profile_observation", "profile": observation},
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )

    with pytest.raises(ValueError, match="marker_text_in_profile"):
        validator.sanitize_capture(
            raw_capture,
            image_path=image,
            arm64_slice_path=arm64_slice,
            marker=marker,
        )


def test_header_and_manifest_are_fail_closed_and_reproducible():
    profile = _measured_profile()

    header = validator.render_header(profile)
    for name in (
        "kRuntimeReadyRva",
        "kStorageDispatchRva",
        "kModelFactoryRva",
        "kRecipientSetterRva",
        "kTextSetterRva",
        "kClientIdSetterRva",
        "kCreateTimeSetterRva",
        "kLocalInsertRva",
        "kResponseDecodeRva",
        "kLocalUpdateRva",
        "kConversationNotifyRva",
    ):
        assert name in header
    assert "0x25cd228" not in header.lower()
    assert "0x3399194" not in header.lower()
    assert validator.render_manifest(
        profile,
        dylib_name="libwechat_local_visible_bridge_safe_v1.dylib",
        dylib_sha256="a" * 64,
    ) == {
        "version": 1,
        "profile_complete": True,
        "adapter_ready": False,
        "capture_sha256": "1" * 64,
        "image_uuid": EXPECTED_UUID,
        "image_sha256": EXPECTED_SHA256,
        "dylib": "libwechat_local_visible_bridge_safe_v1.dylib",
        "dylib_sha256": "a" * 64,
    }

    with pytest.raises(ValueError, match="adapter_must_remain_disabled"):
        validator.render_header(_measured_profile(adapter_ready=True))


@pytest.mark.parametrize(
    "dylib_name",
    ["libwechat_send_bridge.dylib", "../unsafe.dylib"],
)
def test_manifest_pins_safe_v1_bridge_name(dylib_name):
    with pytest.raises(ValueError, match="invalid_dylib_name"):
        validator.render_manifest(
            _measured_profile(),
            dylib_name=dylib_name,
            dylib_sha256="a" * 64,
        )
