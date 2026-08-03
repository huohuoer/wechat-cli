#!/usr/bin/env python3
"""Sanitize measured WeChat evidence and emit fail-closed profile artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import uuid


EXPECTED_IMAGE_PATH = "/Applications/WeChat.app/Contents/Frameworks/wechat.dylib"
EXPECTED_UUID = "ABD88EC8-4590-3FDB-AAB5-4E5865B86B2A"
EXPECTED_SHA256 = (
    "b4a740135f3f1e937bca10caf0a95cff986ddf27fa6bb15ccaf64001fc651c93"
)
EXPECTED_ARM64_SLICE_SHA256 = (
    "0e8c932461b883a4e4dc90313a14a30ea69a190fedf1083d014259bec56da2e0"
)
EXPECTED_BRIDGE_DYLIB_NAME = "libwechat_local_visible_bridge_safe_v1.dylib"
LC_UUID = 0x1B
MACHO_64_MAGIC = 0xFEEDFACF

_MAX_RVA = 0x10000000
_UNSAFE_RVAS = frozenset((0x25CD228, 0x3399194))
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SIGNATURE = re.compile(r"[0-9a-f]{32}")

_TOP_LEVEL_FIELDS = frozenset(
    (
        "schema_version",
        "evidence_kind",
        "adapter_ready",
        "capture_sha256",
        "marker_sha256",
        "image",
        "runtime_ready",
        "execution_context",
        "model",
        "insert",
        "mars",
        "response",
        "update",
        "notification",
    )
)
_SECTION_FIELDS = {
    "image": frozenset(("path", "uuid", "sha256", "arm64_slice_sha256")),
    "runtime_ready": frozenset(("entry_rva", "signature", "ready_value")),
    "execution_context": frozenset(
        ("thread_name", "queue_label", "dispatch_rva", "signature")
    ),
    "model": frozenset(
        (
            "factory_rva",
            "factory_signature",
            "recipient_setter_rva",
            "recipient_setter_signature",
            "text_setter_rva",
            "text_setter_signature",
            "client_id_setter_rva",
            "client_id_setter_signature",
            "create_time_setter_rva",
            "create_time_setter_signature",
            "ownership",
        )
    ),
    "insert": frozenset(
        ("entry_rva", "signature", "local_id_before", "local_id_after", "client_id")
    ),
    "mars": frozenset(("client_id", "submit_count")),
    "response": frozenset(("decode_rva", "signature", "server_id")),
    "update": frozenset(
        (
            "entry_rva",
            "signature",
            "local_id",
            "server_id_before",
            "server_id_after",
        )
    ),
    "notification": frozenset(("entry_rva", "signature", "local_id")),
}
_MEASURED_ENTRIES = (
    (
        "kRuntimeReadyRva",
        "kRuntimeReadySignature",
        "runtime_ready",
        "entry_rva",
        "signature",
    ),
    (
        "kStorageDispatchRva",
        "kStorageDispatchSignature",
        "execution_context",
        "dispatch_rva",
        "signature",
    ),
    (
        "kModelFactoryRva",
        "kModelFactorySignature",
        "model",
        "factory_rva",
        "factory_signature",
    ),
    (
        "kRecipientSetterRva",
        "kRecipientSetterSignature",
        "model",
        "recipient_setter_rva",
        "recipient_setter_signature",
    ),
    (
        "kTextSetterRva",
        "kTextSetterSignature",
        "model",
        "text_setter_rva",
        "text_setter_signature",
    ),
    (
        "kClientIdSetterRva",
        "kClientIdSetterSignature",
        "model",
        "client_id_setter_rva",
        "client_id_setter_signature",
    ),
    (
        "kCreateTimeSetterRva",
        "kCreateTimeSetterSignature",
        "model",
        "create_time_setter_rva",
        "create_time_setter_signature",
    ),
    (
        "kLocalInsertRva",
        "kLocalInsertSignature",
        "insert",
        "entry_rva",
        "signature",
    ),
    (
        "kResponseDecodeRva",
        "kResponseDecodeSignature",
        "response",
        "decode_rva",
        "signature",
    ),
    (
        "kLocalUpdateRva",
        "kLocalUpdateSignature",
        "update",
        "entry_rva",
        "signature",
    ),
    (
        "kConversationNotifyRva",
        "kConversationNotifySignature",
        "notification",
        "entry_rva",
        "signature",
    ),
)


def _positive_plain_int(value):
    return type(value) is int and value > 0


def _zero_plain_int(value):
    return type(value) is int and value == 0


def _valid_digest(value):
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _valid_signature(value):
    return isinstance(value, str) and _SIGNATURE.fullmatch(value) is not None


def validate_profile(profile, *, raw_capture=None):
    """Return ``profile_valid_not_ready`` or one stable failure reason."""

    if not isinstance(profile, dict) or set(profile) != _TOP_LEVEL_FIELDS:
        return "invalid_profile_fields"
    for section, expected_fields in _SECTION_FIELDS.items():
        value = profile[section]
        if not isinstance(value, dict) or set(value) != expected_fields:
            return f"invalid_{section}_fields"

    if type(profile["schema_version"]) is not int or profile["schema_version"] != 2:
        return "unsupported_schema_version"
    if profile["evidence_kind"] != "read_only_lldb":
        return "invalid_evidence_kind"
    if type(profile["adapter_ready"]) is not bool:
        return "invalid_adapter_ready"
    if profile["adapter_ready"]:
        return "adapter_must_remain_disabled"

    if not _valid_digest(profile["capture_sha256"]):
        return "invalid_capture_sha256"
    if raw_capture is not None:
        if type(raw_capture) is not bytes:
            return "invalid_raw_capture"
        if hashlib.sha256(raw_capture).hexdigest() != profile["capture_sha256"]:
            return "capture_digest_mismatch"
    if not _valid_digest(profile["marker_sha256"]):
        return "invalid_marker_sha256"

    image = profile["image"]
    if (
        image["path"] != EXPECTED_IMAGE_PATH
        or image["uuid"] != EXPECTED_UUID
        or image["sha256"] != EXPECTED_SHA256
        or image["arm64_slice_sha256"] != EXPECTED_ARM64_SLICE_SHA256
    ):
        return "unsupported_wechat_build"

    runtime_ready = profile["runtime_ready"]
    if type(runtime_ready["ready_value"]) is not int or runtime_ready["ready_value"] != 1:
        return "runtime_not_ready"

    context = profile["execution_context"]
    if not isinstance(context["thread_name"], str) or not context[
        "thread_name"
    ].strip():
        return "invalid_execution_context"
    if not isinstance(context["queue_label"], str) or not context[
        "queue_label"
    ].strip():
        return "invalid_execution_context"

    model = profile["model"]
    if model["ownership"] != "shared_ptr":
        return "invalid_model_ownership"

    for _, _, section, rva_field, signature_field in _MEASURED_ENTRIES:
        rva = profile[section][rva_field]
        if not _positive_plain_int(rva) or rva >= _MAX_RVA:
            return "invalid_rva"
        if rva in _UNSAFE_RVAS:
            return "unsafe_rva"
        if not _valid_signature(profile[section][signature_field]):
            return "invalid_signature"

    insert = profile["insert"]
    mars = profile["mars"]
    response = profile["response"]
    update = profile["update"]
    notification = profile["notification"]

    if not _zero_plain_int(insert["local_id_before"]):
        return "invalid_local_id_baseline"
    if not _zero_plain_int(update["server_id_before"]):
        return "invalid_server_id_baseline"

    if not _positive_plain_int(insert["client_id"]) or not _positive_plain_int(
        mars["client_id"]
    ):
        return "invalid_client_id"
    if insert["client_id"] != mars["client_id"]:
        return "client_id_disagreement"
    if type(mars["submit_count"]) is not int or mars["submit_count"] != 1:
        return "invalid_mars_submit_count"

    local_ids = (
        insert["local_id_after"],
        update["local_id"],
        notification["local_id"],
    )
    if not all(_positive_plain_int(value) for value in local_ids):
        return "invalid_local_id"
    if len(set(local_ids)) != 1:
        return "local_id_disagreement"

    server_ids = (response["server_id"], update["server_id_after"])
    if not all(_positive_plain_int(value) for value in server_ids):
        return "invalid_server_id"
    if len(set(server_ids)) != 1:
        return "server_id_disagreement"

    return "profile_valid_not_ready"


def _jsonl_records(raw_capture):
    if type(raw_capture) is not bytes or not raw_capture:
        raise ValueError("invalid_raw_capture")
    try:
        decoded = raw_capture.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("invalid_raw_capture_encoding") from error
    lines = decoded.splitlines()
    if not lines or any(not line for line in lines):
        raise ValueError("invalid_jsonl")
    records = []
    for line in lines:
        try:
            record = json.loads(
                line,
                parse_constant=lambda _value: (_ for _ in ()).throw(
                    ValueError("invalid_json_constant")
                ),
            )
        except (json.JSONDecodeError, ValueError) as error:
            raise ValueError("invalid_jsonl") from error
        if not isinstance(record, dict):
            raise ValueError("invalid_jsonl_record")
        records.append(record)
    return records


def _copy_profile_fields(observed):
    if not isinstance(observed, dict):
        raise ValueError("invalid_profile_observation")
    profile = {
        key: observed[key]
        for key in _TOP_LEVEL_FIELDS - frozenset(("image",))
        if key in observed
    }
    for section, fields in _SECTION_FIELDS.items():
        if section == "image" or section not in observed:
            continue
        value = observed[section]
        if not isinstance(value, dict):
            profile[section] = value
            continue
        profile[section] = {key: value[key] for key in fields if key in value}
    return profile


def _contains_string_fragment(value, fragment):
    if isinstance(value, str):
        return fragment in value
    if isinstance(value, dict):
        return any(
            _contains_string_fragment(item, fragment) for item in value.values()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_string_fragment(item, fragment) for item in value)
    return False


def sanitize_capture(raw_capture, *, image_path, arm64_slice_path, marker):
    """Return a schema-v2 profile reconstructed without raw capture secrets."""

    if not isinstance(marker, str) or not marker:
        raise ValueError("invalid_marker")
    records = _jsonl_records(raw_capture)
    observations = [
        record for record in records if record.get("label") == "profile_observation"
    ]
    if len(observations) != 1 or "profile" not in observations[0]:
        raise ValueError("invalid_profile_observation_count")

    image = Path(image_path)
    arm64_slice = Path(arm64_slice_path)
    if str(image) != EXPECTED_IMAGE_PATH:
        raise ValueError("unsupported_wechat_build")
    try:
        image_sha256 = hashlib.sha256(image.read_bytes()).hexdigest()
        slice_bytes = arm64_slice.read_bytes()
    except OSError as error:
        raise ValueError("unreadable_wechat_image") from error
    slice_sha256 = hashlib.sha256(slice_bytes).hexdigest()
    image_uuid = _macho_uuid_bytes(slice_bytes)
    if (
        image_sha256 != EXPECTED_SHA256
        or slice_sha256 != EXPECTED_ARM64_SLICE_SHA256
        or image_uuid != EXPECTED_UUID
    ):
        raise ValueError("unsupported_wechat_build")

    profile = _copy_profile_fields(observations[0]["profile"])
    profile["capture_sha256"] = hashlib.sha256(raw_capture).hexdigest()
    profile["marker_sha256"] = hashlib.sha256(marker.encode("utf-8")).hexdigest()
    profile["image"] = {
        "path": str(image),
        "uuid": image_uuid,
        "sha256": image_sha256,
        "arm64_slice_sha256": slice_sha256,
    }
    if _contains_string_fragment(profile, marker):
        raise ValueError("marker_text_in_profile")
    result = validate_profile(profile, raw_capture=raw_capture)
    if result != "profile_valid_not_ready":
        raise ValueError(result)
    return profile


def _signature_initializer(signature):
    values = ", ".join(f"0x{byte:02x}" for byte in bytes.fromhex(signature))
    return "{" + values + "}"


def render_header(profile):
    """Render every measured RVA/signature while keeping Phase 1 disabled."""

    result = validate_profile(profile)
    if result != "profile_valid_not_ready":
        raise ValueError(result)
    lines = [
        "#pragma once",
        "",
        "#include <array>",
        "#include <cstdint>",
        "",
        "namespace wechat_bridge::profile_4_1_8_28 {",
        "",
        "inline constexpr bool kAdapterReady = false;",
        f'inline constexpr char kImageUuid[] = "{profile["image"]["uuid"]}";',
        f'inline constexpr char kImageSha256[] = "{profile["image"]["sha256"]}";',
        "inline constexpr char kArm64SliceSha256[] = "
        f'"{profile["image"]["arm64_slice_sha256"]}";',
    ]
    for rva_name, signature_name, section, rva_field, signature_field in (
        _MEASURED_ENTRIES
    ):
        lines.extend(
            (
                f"inline constexpr std::uintptr_t {rva_name} = "
                f"0x{profile[section][rva_field]:x};",
                f"inline constexpr std::array<std::uint8_t, 16> {signature_name} =",
                f"    {_signature_initializer(profile[section][signature_field])};",
            )
        )
    lines.extend(("", "}  // namespace wechat_bridge::profile_4_1_8_28", ""))
    return "\n".join(lines)


def render_manifest(profile, *, dylib_name, dylib_sha256):
    """Render the complete-but-disabled Phase 1 runtime manifest."""

    result = validate_profile(profile)
    if result != "profile_valid_not_ready":
        raise ValueError(result)
    if dylib_name != EXPECTED_BRIDGE_DYLIB_NAME:
        raise ValueError("invalid_dylib_name")
    if not _valid_digest(dylib_sha256):
        raise ValueError("invalid_dylib_sha256")
    return {
        "version": 1,
        "profile_complete": True,
        "adapter_ready": False,
        "capture_sha256": profile["capture_sha256"],
        "image_uuid": profile["image"]["uuid"],
        "image_sha256": profile["image"]["sha256"],
        "dylib": dylib_name,
        "dylib_sha256": dylib_sha256,
    }


def _macho_uuid_bytes(data):
    if len(data) < 32:
        raise ValueError("invalid_macho")
    magic, _, _, _, command_count, command_bytes, _, _ = struct.unpack_from(
        "<8I", data, 0
    )
    if magic != MACHO_64_MAGIC:
        raise ValueError("unsupported_macho")
    if command_bytes > len(data) - 32:
        raise ValueError("truncated_load_commands")
    if command_count > command_bytes // 8:
        raise ValueError("invalid_load_commands")

    offset = 32
    commands_end = offset + command_bytes
    image_uuid = None
    for _ in range(command_count):
        if offset + 8 > commands_end:
            raise ValueError("truncated_load_commands")
        command, size = struct.unpack_from("<2I", data, offset)
        if size < 8 or size % 8 != 0 or offset + size > commands_end:
            raise ValueError("invalid_load_command")
        if command == LC_UUID:
            if size != 24:
                raise ValueError("invalid_uuid_command")
            if image_uuid is not None:
                raise ValueError("duplicate_macho_uuid")
            image_uuid = str(uuid.UUID(bytes=data[offset + 8 : offset + 24])).upper()
        offset += size
    if offset != commands_end:
        raise ValueError("invalid_load_commands")
    if image_uuid is None:
        raise ValueError("missing_macho_uuid")
    return image_uuid


def _macho_uuid(path):
    return _macho_uuid_bytes(Path(path).read_bytes())


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-capture", required=True, type=Path)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--arm64-slice", required=True, type=Path)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--header", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--bridge", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        profile = sanitize_capture(
            args.raw_capture.read_bytes(),
            image_path=args.image,
            arm64_slice_path=args.arm64_slice,
            marker=args.marker,
        )
        bridge_sha256 = hashlib.sha256(args.bridge.read_bytes()).hexdigest()
        manifest = render_manifest(
            profile,
            dylib_name=args.bridge.name,
            dylib_sha256=bridge_sha256,
        )
    except (OSError, ValueError) as error:
        print(str(error))
        return 1

    args.header.parent.mkdir(parents=True, exist_ok=True)
    _write_json(args.fixture, profile)
    args.header.write_text(render_header(profile), encoding="utf-8")
    _write_json(args.manifest, manifest)
    print("profile_valid_not_ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
