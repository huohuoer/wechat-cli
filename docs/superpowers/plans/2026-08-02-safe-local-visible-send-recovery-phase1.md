# Safe Local-Visible Send Recovery Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the deterministic WeChat crash path, make production sending fail before injection while evidence is incomplete, and produce a complete measured local-message profile from one explicitly approved read-only observation.

**Architecture:** Phase 1 deliberately ships no enabled sender. It replaces the unsafe high-level adapter with a fail-closed production stub, restores the strict identifier-based receipt contract, and builds an auditable capture/validation pipeline whose output remains `adapter_ready: false`. Phase 2 is written only after the measured profile supplies exact native types, entry signatures, ownership, execution context, and state transitions.

**Tech Stack:** Python 3.10+, pytest, C++17/Objective-C++, ARM64 Mach-O inspection, LLDB Python API in read-only mode, macOS code signing and process inspection.

---

## Evidence correction (2026-08-02)

Static verification after Tasks 1-4 invalidated the assumed complete probe map
used by Tasks 4-8 below. In particular, the model setters may be direct field
writes, `0x372FD60` is not proved to be the send-response decoder, and
`0x202906C` is inside a larger function rather than a notification entry.

The schema-v2 profile examples and the zero-RVA resolution instructions below
are retained as historical plan context, but they must not be used to sanitize
or generate artifacts from the first marker capture. The corrected discovery
capture installs only the four verified boundaries documented in
`docs/research/wechat-4.1.8.28-local-store-candidates.md`: insert wrapper, insert
implementation, Mars submit, and local update. Its purpose is to capture the
insert/update model data and backtraces needed to discover the actual response
and notification boundaries. No Task 8 profile artifact may be generated until
a revised schema removes every disproved role and a new failing-test-first plan
defines the evidence chain.

## Scope and sequencing

This plan covers the safety and evidence boundary only. It does not guess the
private local-message gateway ABI and does not perform `wechat-cli send`.

The phase is complete when:

- the crashing `OwlHighLevelSendAdapter` cannot be built or selected;
- `wechat-cli send` refuses before invoking the injector while
  `adapter_ready` is false or absent;
- Python accepts only an acknowledged receipt with matching positive IDs;
- one sanitized measured profile passes strict validation;
- the generated profile manifest still says `adapter_ready: false`;
- all tests and clean temporary builds pass without injecting WeChat.

Only then can a Phase 2 plan name exact typedefs and implement
`PinnedLocalMessageGateway` and `PinnedMarsGateway` without placeholders.

## File map

- `native/src/production_adapter.mm`: New fail-closed production factory used
  until the measured gateways are implemented in Phase 2.
- `native/src/wechat_local_visible.mm`: Delete the deterministic crash path.
- `wechat_cli/bin/libwechat_local_visible_bridge*.dylib`: Delete the untracked
  experimental local-visible artifacts so `wechat_cli = ["bin/*"]` cannot
  package v1/v3/v4/v5/v6 accidentally.
- `native/build.sh`: Stop compiling the unsafe source; compile the transaction,
  production stub, bridge service, and legacy Mars code into a safe-v1 artifact.
- `native/include/wechat_bridge.hpp`: Remove unsafe helper exports and the
  transient submitted ACK state; retain the committed gateway contracts.
- `native/src/bridge_entry.mm`: Use the stable `local-visible-safe-v1` endpoint.
- `native/src/bridge_service.mm`: Serialize only acknowledged/unknown receipts.
- `native/tests/fake_host.mm`: Remove forged high-level model/Owl probes and add
  production-stub contract coverage.
- `tests/test_native_bridge_host.py`: Crash regression, source/artifact ban, and
  production-stub tests.
- `wechat_cli/core/native_bridge_provider.py`: Validate a packaged profile
  manifest before running the injector.
- `tests/test_native_bridge_provider.py`: Prove missing/incomplete profiles stop
  before subprocess execution.
- `wechat_cli/core/send_bridge.py`: Restore acknowledged/unknown protocol only.
- `wechat_cli/core/native_sending.py`: Require receipt IDs and exact-ID database
  confirmation.
- `wechat_cli/core/send_confirmation.py`: Remove exact-text fallback lookup.
- `tests/test_send_bridge.py`: Reject submitted receipts.
- `tests/test_native_send_service.py`: Reject receipts without positive IDs.
- `tests/test_send_confirmation.py`: Retain exact-local-ID confirmation tests and
  remove fallback-only cases.
- `tools/wechat_profile_capture.py`: Bounded phased read-only LLDB capture.
- `tools/validate_wechat_profile.py`: Strict raw-evidence parser, sanitizer,
  profile validator, header and manifest generator.
- `tests/test_wechat_profile_capture.py`: Pure capture-plan and no-call tests.
- `tests/test_wechat_profile_validation.py`: Incomplete, inconsistent, unsafe,
  and measured-profile tests.
- `tests/fixtures/wechat_local_store_capture.json`: Sanitized measured output,
  created only after the approved marker observation.
- `native/include/wechat_4_1_8_28_profile.hpp`: Generated measured constants,
  created only after validation.
- `wechat_cli/bin/libwechat_local_visible_bridge_safe_v1.dylib`: Generated
  fail-closed Phase 1 bridge whose digest is pinned by the manifest.
- `wechat_cli/bin/wechat_local_visible_profile.json`: Generated profile gate with
  `adapter_ready: false` in Phase 1.
- `docs/research/wechat-4.1.8.28-local-store-profile.md`: Evidence table and raw
  capture digest, with no message text or memory dumps.

### Task 1: Quarantine the deterministic crash path

**Files:**
- Create: `native/src/production_adapter.mm`
- Delete: `native/src/wechat_local_visible.mm`
- Delete: `wechat_cli/bin/libwechat_local_visible_bridge.dylib`
- Delete: `wechat_cli/bin/libwechat_local_visible_bridge_v3.dylib`
- Delete: `wechat_cli/bin/libwechat_local_visible_bridge_v4.dylib`
- Delete: `wechat_cli/bin/libwechat_local_visible_bridge_v5.dylib`
- Delete: `wechat_cli/bin/libwechat_local_visible_bridge_v6.dylib`
- Modify: `native/build.sh`
- Modify: `native/include/wechat_bridge.hpp`
- Modify: `native/src/bridge_entry.mm`
- Modify: `native/tests/fake_host.mm`
- Modify: `tests/test_native_bridge_host.py`

- [ ] **Step 1: Write the crashing-symbol regression test**

Add this test to `tests/test_native_bridge_host.py`:

```python
def test_production_build_excludes_crashing_high_level_send(native_build):
    _, dylib = native_build
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
    assert "wechat_local_visible.mm" not in build_script
    assert "0x25cd228" not in source.lower()
    unsafe_artifacts = (
        "libwechat_local_visible_bridge.dylib",
        "libwechat_local_visible_bridge_v3.dylib",
        "libwechat_local_visible_bridge_v4.dylib",
        "libwechat_local_visible_bridge_v5.dylib",
        "libwechat_local_visible_bridge_v6.dylib",
    )
    assert all(not (ROOT / "wechat_cli" / "bin" / name).exists()
               for name in unsafe_artifacts)
```

Add a production-stub expectation:

```python
def test_production_factory_fails_closed_until_profile_is_composed(native_build):
    host, _ = native_build
    completed = subprocess.run(
        [str(host), "--verify-production-profile-incomplete"],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stderr
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
uv run --project . pytest -q tests/test_native_bridge_host.py \
  -k 'excludes_crashing or profile_incomplete'
```

Expected: the first test fails because the v6 symbol, source, and build entry
exist; the second fails because the fake-host mode does not exist.

- [ ] **Step 3: Add the fail-closed production factory**

Create `native/src/production_adapter.mm` with exactly:

```cpp
#include "wechat_bridge.hpp"

#include <memory>
#include <string>

namespace wechat_bridge {

std::shared_ptr<SendAdapter> CreateProductionWeChatAdapter(
    std::string* unsupported_reason) {
  if (unsupported_reason != nullptr) {
    *unsupported_reason = "unsupported_wechat_local_store_profile";
  }
  return nullptr;
}

}  // namespace wechat_bridge
```

In `native/build.sh`, remove `native/src/wechat_local_visible.mm`, add
`native/src/production_adapter.mm`, keep `native/src/local_visible_adapter.mm`,
and name the experimental output
`libwechat_local_visible_bridge_safe_v1.dylib` with the same install name.

Delete `native/src/wechat_local_visible.mm`. In
`native/include/wechat_bridge.hpp`, delete only these unsafe declarations:

```cpp
bool VerifyLocalVisibleTextLayout();
bool VerifyRelocatedMessageVtable(std::uintptr_t image_base,
                                  const void* bytes,
                                  std::size_t size);
bool VerifyOwlMainScopeRunner();
```

Delete the five exact experimental dylib paths listed in this task. Do not
delete the committed legacy Mars artifact `libwechat_send_bridge.dylib`.

Set the exact bridge tag in `native/src/bridge_entry.mm`:

```cpp
constexpr char kBridgeInstanceTag[] = "local-visible-safe-v1";
```

Remove the three matching fake-host modes and their JSON output. Add this mode:

```cpp
if (argc == 2 &&
    std::strcmp(argv[1], "--verify-production-profile-incomplete") == 0) {
  std::string reason;
  const auto adapter =
      wechat_bridge::CreateProductionWeChatAdapter(&reason);
  return adapter == nullptr &&
             reason == "unsupported_wechat_local_store_profile"
      ? 0
      : 14;
}
```

- [ ] **Step 4: Rebuild in a temporary directory and verify GREEN**

Run:

```bash
uv run --project . pytest -q tests/test_native_bridge_host.py
```

Expected: all native host tests pass; no command attaches to WeChat.

- [ ] **Step 5: Verify the unsafe source and symbol are absent**

Run:

```bash
rg -n 'OwlHighLevelSendAdapter|0x25cd228|wechat_local_visible\.mm' \
  native/src native/include native/build.sh wechat_cli/core
```

Expected: no production references. Historical design documents and crash
forensics are outside the searched paths.

- [ ] **Step 6: Commit the quarantine**

```bash
git add native/build.sh native/include/wechat_bridge.hpp \
  native/src/bridge_entry.mm native/src/production_adapter.mm \
  native/tests/fake_host.mm tests/test_native_bridge_host.py
git commit -m "fix: quarantine crashing local-visible adapter"
```

### Task 2: Stop before injection without a ready profile

**Files:**
- Modify: `wechat_cli/core/native_bridge_provider.py`
- Modify: `tests/test_native_bridge_provider.py`

- [ ] **Step 1: Write profile-manifest gate tests**

Add to `tests/test_native_bridge_provider.py`:

```python
import json
from types import SimpleNamespace

import pytest

from wechat_cli.core.sending import SendUnavailableError


def test_missing_profile_manifest_stops_before_injector(monkeypatch, tmp_path):
    called = False

    def forbidden_run(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("injector must not run")

    monkeypatch.setattr(native_bridge_provider, "_safe_bridge_directory", lambda: tmp_path)
    monkeypatch.setattr(native_bridge_provider, "_package_binary", lambda name: tmp_path / name)
    monkeypatch.setattr(native_bridge_provider.subprocess, "run", forbidden_run)

    with pytest.raises(SendUnavailableError, match="profile.*未完成"):
        native_bridge_provider.prepare_native_bridge(
            SimpleNamespace(pid=123), "12345678-1234-1234-1234-123456789abc"
        )

    assert called is False


@pytest.mark.parametrize(
    "payload",
    [
        {},
        [],
        {"version": "1", "profile_complete": True, "adapter_ready": True},
        {"version": 1, "profile_complete": True, "adapter_ready": False},
        {"version": 1, "profile_complete": False, "adapter_ready": True},
        {"version": 1, "profile_complete": True, "adapter_ready": True,
         "dylib": "../unsafe.dylib", "dylib_sha256": "0" * 64},
    ],
)
def test_incomplete_or_unsafe_manifest_stops_before_injector(
    monkeypatch, tmp_path, payload
):
    manifest = tmp_path / "wechat_local_visible_profile.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(native_bridge_provider, "_package_binary", lambda name: tmp_path / name)
    monkeypatch.setattr(
        native_bridge_provider.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("injector must not run"),
    )

    with pytest.raises(SendUnavailableError, match="profile.*未完成"):
        native_bridge_provider.prepare_native_bridge(
            SimpleNamespace(pid=123), "12345678-1234-1234-1234-123456789abc"
        )
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
uv run --project . pytest -q tests/test_native_bridge_provider.py \
  -k 'profile_manifest or unsafe_manifest'
```

Expected: failures because the provider reads no manifest.

- [ ] **Step 3: Implement strict manifest loading before `_safe_bridge_directory`**

Add these constants and helpers to `native_bridge_provider.py`:

```python
import hashlib
import json

BRIDGE_INSTANCE_TAG = "local-visible-safe-v1"
BRIDGE_DYLIB_NAME = "libwechat_local_visible_bridge_safe_v1.dylib"
PROFILE_MANIFEST_NAME = "wechat_local_visible_profile.json"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_UUID = re.compile(
    r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"
)


def _ready_profile():
    manifest_path = _package_binary(PROFILE_MANIFEST_NAME)
    try:
        info = manifest_path.lstat()
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SendUnavailableError("本地可见发送 profile 未完成，未发送任何消息") from error
    expected = {
        "version", "profile_complete", "adapter_ready", "capture_sha256",
        "image_uuid", "image_sha256", "dylib", "dylib_sha256",
    }
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid not in (0, os.geteuid())
        or info.st_mode & 0o022
        or not isinstance(payload, dict)
        or set(payload) != expected
        or payload["version"] != 1
        or payload["profile_complete"] is not True
        or payload["adapter_ready"] is not True
        or payload["dylib"] != BRIDGE_DYLIB_NAME
        or not isinstance(payload["capture_sha256"], str)
        or _SHA256.fullmatch(payload["capture_sha256"]) is None
        or not isinstance(payload["image_uuid"], str)
        or _UUID.fullmatch(payload["image_uuid"]) is None
        or not isinstance(payload["image_sha256"], str)
        or _SHA256.fullmatch(payload["image_sha256"]) is None
        or not isinstance(payload["dylib_sha256"], str)
        or _SHA256.fullmatch(payload["dylib_sha256"]) is None
    ):
        raise SendUnavailableError("本地可见发送 profile 未完成，未发送任何消息")
    dylib = _package_binary(BRIDGE_DYLIB_NAME)
    try:
        dylib_info = dylib.lstat()
        dylib_sha256 = hashlib.sha256(dylib.read_bytes()).hexdigest()
    except OSError as error:
        raise SendUnavailableError(
            "本地可见发送 profile 与 bridge 不匹配，未发送任何消息"
        ) from error
    if (
        not stat.S_ISREG(dylib_info.st_mode)
        or dylib_info.st_uid not in (0, os.geteuid())
        or dylib_info.st_mode & 0o022
        or dylib_sha256 != payload["dylib_sha256"]
    ):
        raise SendUnavailableError("本地可见发送 profile 与 bridge 不匹配，未发送任何消息")
    return payload
```

Call `_ready_profile()` as the first statement of `prepare_native_bridge`,
before creating the runtime directory or resolving the injector.

The manifest is intentionally absent until Task 8, and Task 8 writes
`adapter_ready: false`, so all Phase 1 production calls stop here.

- [ ] **Step 4: Run provider tests and verify GREEN**

Run:

```bash
uv run --project . pytest -q tests/test_native_bridge_provider.py
```

Expected: all provider tests pass and mocked injector calls remain zero.

- [ ] **Step 5: Commit the pre-injection gate**

```bash
git add wechat_cli/core/native_bridge_provider.py \
  tests/test_native_bridge_provider.py
git commit -m "fix: gate local-visible injection on measured profile"
```

### Task 3: Restore strict identifier-based confirmation

**Files:**
- Modify: `native/include/wechat_bridge.hpp`
- Modify: `native/src/bridge_service.mm`
- Modify: `wechat_cli/core/send_bridge.py`
- Modify: `wechat_cli/core/native_sending.py`
- Modify: `wechat_cli/core/send_confirmation.py`
- Modify: `tests/test_send_bridge.py`
- Modify: `tests/test_native_send_service.py`
- Modify: `tests/test_send_confirmation.py`

- [ ] **Step 1: Write strict receipt regressions**

In `tests/test_send_bridge.py`, replace the submitted-success case with:

```python
def test_client_rejects_submitted_receipt_without_ids_as_unknown(tmp_path):
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

    with pytest.raises(SendUnknownError):
        client.send_text(_request())
```

In `tests/test_native_send_service.py`, add:

```python
@pytest.mark.parametrize("local_id,server_id", [(None, None), (41, None), (None, 99)])
def test_native_send_never_accepts_receipt_without_both_ids(local_id, server_id):
    bridge = FakeBridge(
        receipt=_receipt(
            ack_state=BridgeAckState.ACKNOWLEDGED,
            local_id=local_id,
            server_id=server_id,
        )
    )
    service, _, store, _ = _service(bridge=bridge)

    result = service.send_text(_request())

    assert result.status is SendStatus.UNKNOWN
    assert store.poll_calls == []
```

In `tests/test_send_confirmation.py`, add:

```python
def test_confirmation_rejects_matching_id_with_different_text(tmp_path):
    db_path = tmp_path / "message.db"
    _create_message_db(
        db_path,
        rows=[(21, 201, 1, 7, 2, "另一条消息")],
        names=[(7, "wxid_me")],
    )
    store = MessageConfirmationStore(_locator_for(db_path))
    baseline = MessageBaseline(
        username=USERNAME,
        max_local_ids={_identity(db_path): 20},
    )

    confirmation = store.find_confirmation(
        username=USERNAME,
        self_username="wxid_me",
        local_id=21,
        text="预期消息",
        baseline=baseline,
    )

    assert confirmation is None
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
uv run --project . pytest -q tests/test_send_bridge.py \
  tests/test_native_send_service.py
```

Expected: submitted is currently accepted and the service polls by text for a
receipt without IDs, so the new expectations fail.

- [ ] **Step 3: Remove the transient submitted protocol and text fallback**

Make these exact contract changes:

```cpp
enum class AckState {
  kAcknowledged,
  kUnknown,
};
```

In `native/src/bridge_service.mm`, encode only `acknowledged` or `unknown`.

In `send_bridge.py`, remove `BridgeAckState.SUBMITTED`; require positive
`local_id` for acknowledged receipts and allow optional IDs only for unknown.

In `NativeSendService.send_text`, accept only
`BridgeAckState.ACKNOWLEDGED`, require positive `receipt.local_id` and
`receipt.server_id`, and call only:

```python
confirmation = self._confirmation_store.poll_confirmation(
    username=request.username,
    self_username=self_username,
    local_id=receipt.local_id,
    text=request.text,
    baseline=baseline,
    timeout=remaining,
)
```

Delete `find_confirmation_by_text` and `poll_confirmation_by_text` from
`send_confirmation.py`, their fake-store method, and their fallback-only tests.
Add a required `text` keyword to `find_confirmation` and `poll_confirmation`.
Select `message_content` in the same local-ID query and accept the row only when
`type(message_content) is str and message_content == text`. Update every direct
confirmation test call to pass the row's exact text; tests exercising invalid
rows or invalid baselines pass any non-empty string because they must fail
before content can establish success. In the native-service success test,
assert `store.poll_calls[0]["text"] == "你好 👋\n第二行"`.

- [ ] **Step 4: Run the focused confirmation suite and verify GREEN**

Run:

```bash
uv run --project . pytest -q tests/test_send_bridge.py \
  tests/test_native_send_service.py tests/test_send_confirmation.py tests/test_send.py
```

Expected: all focused tests pass.

- [ ] **Step 5: Commit the strict contract**

```bash
git add native/include/wechat_bridge.hpp native/src/bridge_service.mm \
  wechat_cli/core/send_bridge.py wechat_cli/core/native_sending.py \
  wechat_cli/core/send_confirmation.py tests/test_send_bridge.py \
  tests/test_native_send_service.py tests/test_send_confirmation.py
git commit -m "fix: require exact local IDs for send success"
```

### Task 4: Define the measured profile schema and generator

**Files:**
- Modify: `tools/validate_wechat_profile.py`
- Modify: `tests/test_wechat_profile_validation.py`

- [ ] **Step 1: Replace the fabricated flat fixture with a measured schema**

Use this exact top-level schema in tests:

```python
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
```

Add tests that remove one nested field at a time, disagree on IDs, use the
unsafe high-level RVAs `0x25CD228`/`0x3399194`, use `adapter_ready: true` in
Phase 1, or supply a wrong raw capture digest. Each must return a stable named
failure. Add a positive test that expects `profile_valid_not_ready`.

- [ ] **Step 2: Run validator tests and verify RED**

Run:

```bash
uv run --project . pytest -q tests/test_wechat_profile_validation.py
```

Expected: failures because the current validator accepts a small flat,
hand-written dictionary and can render an activation header from it.

- [ ] **Step 3: Implement strict nested validation**

Implement these public functions in `tools/validate_wechat_profile.py`:

```python
def validate_profile(profile, *, raw_capture=None):
    """Return profile_valid_not_ready or one stable failure reason."""


def sanitize_capture(raw_capture, *, image_path, arm64_slice_path, marker):
    """Parse exact JSONL bytes and return schema-v2 data without raw secrets."""


def render_header(profile):
    """Render measured constants; reject adapter_ready=True during Phase 1."""


def render_manifest(profile, *, dylib_name, dylib_sha256):
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
```

`sanitize_capture` must hash the exact raw JSONL bytes and marker UTF-8 bytes,
verify the universal image SHA-256
`b4a740135f3f1e937bca10caf0a95cff986ddf27fa6bb15ccaf64001fc651c93`,
verify the extracted ARM64 slice SHA-256
`0e8c932461b883a4e4dc90313a14a30ea69a190fedf1083d014259bec56da2e0`,
then omit `regions`, registers, backtraces, raw model bytes, marker text, and
auth material. `validate_profile` must require exact key sets at every level,
exact ID agreement, one Mars submission, the supported image and slice, 16-byte
lowercase signatures, positive bounded RVAs, and absence of unsafe RVAs.

- [ ] **Step 4: Run validator tests and verify GREEN**

Run:

```bash
uv run --project . pytest -q tests/test_wechat_profile_validation.py
```

Expected: all schema, sanitization, digest, and rendering tests pass.

- [ ] **Step 5: Commit the evidence schema**

```bash
git add tools/validate_wechat_profile.py tests/test_wechat_profile_validation.py
git commit -m "test: require measured local-store profile evidence"
```

### Task 5: Make the LLDB capture bounded, phased, and read-only

**Files:**
- Modify: `tools/wechat_profile_capture.py`
- Create: `tests/test_wechat_profile_capture.py`

- [ ] **Step 1: Write pure capture-plan tests**

Create `tests/test_wechat_profile_capture.py` with:

```python
import inspect

from tools import wechat_profile_capture as capture


def test_probe_plan_never_uses_more_than_four_hardware_breakpoints():
    phases = capture.build_probe_phases()
    assert phases
    assert all(1 <= len(phase.probes) <= 4 for phase in phases)
    assert {probe.label for phase in phases for probe in phase.probes} >= {
        "runtime_ready", "model_factory", "recipient_setter", "text_setter",
        "insert", "mars_submit", "response_decode", "update", "notification",
    }


def test_capture_source_cannot_call_or_evaluate_wechat_functions():
    source = inspect.getsource(capture)
    for forbidden in (
        "EvaluateExpression", "SBExpressionOptions", "CallFunction",
        "process.Call", "thread.Call", "write_memory", "WriteMemory",
    ):
        assert forbidden not in source


def test_lldb_arguments_auto_detach_and_never_send(tmp_path):
    arguments = capture.build_lldb_arguments(
        pid=123,
        marker="WCPROFILE-20260802-01",
        output=tmp_path / "events.jsonl",
    )
    lldb_commands = [
        arguments[index + 1]
        for index, value in enumerate(arguments[:-1])
        if value == "-o"
    ]
    assert "process continue" in lldb_commands
    assert any(command.startswith("wechat-profile-start ")
               for command in lldb_commands)
    assert all("process call" not in command.lower()
               for command in lldb_commands)
    assert all("expression" not in command.lower()
               for command in lldb_commands)
    assert any("detach" in command.lower() for command in lldb_commands)
```

- [ ] **Step 2: Run capture tests and verify RED**

Run:

```bash
uv run --project . pytest -q tests/test_wechat_profile_capture.py
```

Expected: import or attribute failures because phased probe objects and the
argument builder do not exist.

- [ ] **Step 3: Implement the pure plan and command builder**

Add:

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class Probe:
    label: str
    rva: int
    capture_return: bool = False


@dataclass(frozen=True)
class ProbePhase:
    name: str
    probes: tuple[Probe, ...]


def build_probe_phases():
    return (
        ProbePhase("model", (
            Probe("runtime_ready", 0x3EF9964, True),
            Probe("model_factory", 0, True),
            Probe("recipient_setter", 0, False),
            Probe("text_setter", 0, False),
        )),
        ProbePhase("insert", (
            Probe("client_id_setter", 0, False),
            Probe("create_time_setter", 0, False),
            Probe("insert", 0x26E6264, True),
            Probe("mars_submit", 0x498D2E0, False),
        )),
        ProbePhase("accept", (
            Probe("response_decode", 0, True),
            Probe("update", 0x26EA4FC, True),
            Probe("notification", 0, False),
        )),
    )
```

Zero RVAs are explicit unresolved candidates. `start_capture` must refuse a
phase containing a zero RVA and print the missing labels, so a marker is never
requested until static analysis has supplied every candidate.

Implement `build_lldb_arguments` to import this script, start the capture,
continue, and execute `process detach` after the script's bounded completion
command. It must validate PID, marker length, and an absolute output path.

- [ ] **Step 4: Implement return probes and bounded automatic detach**

For each `capture_return=True` entry hit, read LR, create a one-shot breakpoint
restricted to the same thread, disable that entry breakpoint before installing
the return breakpoint, and capture `x0` plus the same bounded memory regions on
return. This keeps the installed hardware-breakpoint count at four or fewer.
The first marker-reachable model/setter event arms the bounded lifecycle; later
insert/Mars/response/update/notification events may lack marker bytes and are
retained only inside that same lifecycle window for the same observed thread,
model pointer, client ID, or local ID. The sanitizer must reject the capture if
those identities do not form one unbroken chain. Stop after 30 seconds by using
LLDB's asynchronous process interrupt, remove all breakpoints, write one
`capture_terminal` event with `complete` or a sorted list of missing labels, and
detach. Never invoke a target expression.

Every raw event must contain only:

```python
{
    "label": str,
    "edge": "entry" | "return",
    "time": float,
    "rva": str,
    "signature": str,
    "marker_reachable": bool,
    "thread_id": int,
    "thread_name": str | None,
    "queue_name": str | None,
    "registers": dict[str, str],
    "regions": dict[str, str],
    "backtrace": list[dict[str, object]],
}
```

The final record has this separate exact schema:

```python
{
    "label": "capture_terminal",
    "status": "complete" | "incomplete" | "error",
    "missing_labels": list[str],
    "pid": int,
    "duration_ms": int,
}
```

- [ ] **Step 5: Run capture tests and verify GREEN**

Run:

```bash
uv run --project . pytest -q tests/test_wechat_profile_capture.py \
  tests/test_wechat_profile_validation.py
```

Expected: all pure tests pass; this command does not import LLDB or attach.

- [ ] **Step 6: Commit the bounded capture tool**

```bash
git add tools/wechat_profile_capture.py tests/test_wechat_profile_capture.py
git commit -m "feat: add bounded read-only WeChat profile capture"
```

### Task 6: Resolve all zero-RVA candidates offline

**Files:**
- Modify: `tools/wechat_profile_capture.py`
- Create: `docs/research/wechat-4.1.8.28-local-store-candidates.md`
- Modify: `tests/test_wechat_profile_capture.py`

- [ ] **Step 1: Add a failing no-zero-RVA test**

```python
def test_every_runtime_probe_has_a_resolved_positive_rva():
    probes = [probe for phase in capture.build_probe_phases() for probe in phase.probes]
    assert all(0 < probe.rva < 0x10000000 for probe in probes)
```

- [ ] **Step 2: Run it and verify RED**

Run:

```bash
uv run --project . pytest -q tests/test_wechat_profile_capture.py \
  -k resolved_positive
```

Expected: failure listing model factory, setters, response decode, and
notification candidates as zero.

- [ ] **Step 3: Resolve candidates using only the pinned image**

Use `/private/tmp/wechat-arm64-profile.dylib`. Before disassembly, run:

```bash
test "$(shasum -a 256 /private/tmp/wechat-arm64-profile.dylib | awk '{print $1}')" = \
  "0e8c932461b883a4e4dc90313a14a30ea69a190fedf1083d014259bec56da2e0"
dwarfdump --uuid /private/tmp/wechat-arm64-profile.dylib | \
  rg 'ABD88EC8-4590-3FDB-AAB5-4E5865B86B2A \(arm64\)'
```

Expected: both commands exit 0. Then disassemble the known normal-send call
chains around:

```text
UI trigger:       0x3399194
local insert:     0x26e6264
local update:     0x26ea4fc
Mars submit:      0x498d2e0
insert callers:   0x253b85c, 0x25634e4, 0x2533948, 0x260be0c,
                  0x2609e88, 0x25cf0e4, 0x25cc098, 0x25cbf0c,
                  0x25cd3b8
update callers:   0x253b01c, 0x2565ad8, 0x2536fbc, 0x265274c,
                  0x2651b1c, 0x3725be4
```

For each new RVA, record the 16 entry bytes, every call-site argument register,
the caller chain that ties it to the marker model, and why it is a factory,
setter, response decoder, or notification boundary. Do not infer a role from a
string alone.

Write the evidence table to
`docs/research/wechat-4.1.8.28-local-store-candidates.md` and replace every zero
RVA in `build_probe_phases()` with the measured candidate.

- [ ] **Step 4: Run the no-zero and full capture tests to verify GREEN**

```bash
uv run --project . pytest -q tests/test_wechat_profile_capture.py
```

Expected: all probe RVAs are positive and all capture tests pass.

- [ ] **Step 5: Commit the offline candidate map**

```bash
git add tools/wechat_profile_capture.py tests/test_wechat_profile_capture.py \
  docs/research/wechat-4.1.8.28-local-store-candidates.md
git commit -m "docs: map pinned local-store profile candidates"
```

### Task 7: Capture one explicitly approved normal marker send

**Files:**
- Runtime output only: `/private/tmp/wechat-local-store-events-v2.jsonl`

- [ ] **Step 1: Run all pre-capture safety checks**

Run:

```bash
uv run --project . pytest -q tests/test_wechat_profile_capture.py \
  tests/test_wechat_profile_validation.py tests/test_native_bridge_host.py
```

Expected: all tests pass.

Record the current WeChat PID and crash-report count without operating the UI:

```bash
wechat_profile_pid="$(pgrep -x WeChat)"
test "$(printf '%s\n' "$wechat_profile_pid" | awk 'NF {n++} END {print n+0}')" -eq 1
printf '%s\n' "$wechat_profile_pid"
find "$HOME/Library/Logs/DiagnosticReports" -name 'WeChat-*.ips' | wc -l
```

Expected: exactly one entered WeChat PID. If account readiness is not observable
without UI operation, ask the user to confirm that WeChat is entered before
attaching.

- [ ] **Step 2: Request action-time confirmation for the marker**

State exactly:

```text
The read-only profiler is ready. It requires you to manually send
"WCPROFILE-20260802-01" once to "AI聊天群". The tool will only observe and detach;
it will not send, click, focus, or type. May I start the capture?
```

Do not attach until the user confirms this distinct externally visible action.

- [ ] **Step 3: Start the bounded read-only capture**

Resolve exactly one PID again immediately before attach, then pass that exact
numeric value to the profiler:

```bash
wechat_profile_pid="$(pgrep -x WeChat)"
test "$(printf '%s\n' "$wechat_profile_pid" | awk 'NF {n++} END {print n+0}')" -eq 1
uv run --project . python tools/wechat_profile_capture.py \
  --pid "$wechat_profile_pid" \
  --marker WCPROFILE-20260802-01 \
  --output /private/tmp/wechat-local-store-events-v2.jsonl
```

Expected: `wechat_profile_ready`. Ask the user to manually send the exact marker
once. The capture must print `capture_complete` and detach within 30 seconds.

If it prints missing labels, do not request another marker. Stop and return to
Task 6 with the captured evidence; any second marker needs a new explicit
confirmation.

- [ ] **Step 4: Verify process health and capture completeness**

Run:

```bash
pgrep -x WeChat
find "$HOME/Library/Logs/DiagnosticReports" -name 'WeChat-*.ips' | wc -l
tail -n 1 /private/tmp/wechat-local-store-events-v2.jsonl
```

Expected: the PID and crash-report count are unchanged, and the terminal event
is complete. If WeChat exited or a new report exists, stop Phase 1.

### Task 8: Sanitize, validate, and generate a not-ready profile

**Files:**
- Create: `tests/fixtures/wechat_local_store_capture.json`
- Create: `native/include/wechat_4_1_8_28_profile.hpp`
- Create: `wechat_cli/bin/libwechat_local_visible_bridge_safe_v1.dylib`
- Create: `wechat_cli/bin/wechat_local_visible_profile.json`
- Create: `docs/research/wechat-4.1.8.28-local-store-profile.md`
- Modify: `tests/test_wechat_profile_validation.py`

- [ ] **Step 1: Add a fixture reproducibility test**

```python
def test_committed_profile_artifacts_are_reproducible():
    profile = json.loads(PROFILE_FIXTURE.read_text(encoding="utf-8"))
    assert validate_profile(profile) == "profile_valid_not_ready"
    assert PROFILE_HEADER.read_text(encoding="utf-8") == render_header(profile)
    manifest = json.loads(PROFILE_MANIFEST.read_text(encoding="utf-8"))
    assert manifest["profile_complete"] is True
    assert manifest["adapter_ready"] is False
    assert manifest["capture_sha256"] == profile["capture_sha256"]
```

- [ ] **Step 2: Run it and verify RED**

Run:

```bash
uv run --project . pytest -q tests/test_wechat_profile_validation.py \
  -k reproducible
```

Expected: failure because no measured fixture/header/manifest is committed.

- [ ] **Step 3: Generate sanitized artifacts from the raw capture**

Run:

```bash
phase1_package_build="$(mktemp -d /private/tmp/wechat-phase1-package.XXXXXX)"
./native/build.sh "$phase1_package_build"
install -m 755 \
  "$phase1_package_build/libwechat_local_visible_bridge_safe_v1.dylib" \
  wechat_cli/bin/libwechat_local_visible_bridge_safe_v1.dylib
uv run --project . python tools/validate_wechat_profile.py \
  --raw-capture /private/tmp/wechat-local-store-events-v2.jsonl \
  --image /Applications/WeChat.app/Contents/Frameworks/wechat.dylib \
  --arm64-slice /private/tmp/wechat-arm64-profile.dylib \
  --marker WCPROFILE-20260802-01 \
  --fixture tests/fixtures/wechat_local_store_capture.json \
  --header native/include/wechat_4_1_8_28_profile.hpp \
  --manifest wechat_cli/bin/wechat_local_visible_profile.json \
  --bridge wechat_cli/bin/libwechat_local_visible_bridge_safe_v1.dylib
```

Expected: `profile_valid_not_ready`. The command must never print the marker or
raw memory. The generated manifest must contain `adapter_ready: false`.

- [ ] **Step 4: Write the evidence document**

Document the exact image fingerprint, capture digest, every measured RVA and
signature, ABI argument/return observations, execution context, ownership,
local/client/server ID agreement, notification evidence, and unresolved Phase 2
work in `docs/research/wechat-4.1.8.28-local-store-profile.md`.

Do not include marker text, raw registers, memory dumps, decrypted database
paths, account IDs, or tokens.

- [ ] **Step 5: Run reproducibility and provider fail-closed tests**

Run:

```bash
uv run --project . pytest -q tests/test_wechat_profile_validation.py \
  tests/test_native_bridge_provider.py
```

Expected: all tests pass. Provider tests prove `adapter_ready: false` still
stops before injection.

- [ ] **Step 6: Commit measured evidence only**

```bash
git add tests/fixtures/wechat_local_store_capture.json \
  native/include/wechat_4_1_8_28_profile.hpp \
  wechat_cli/bin/libwechat_local_visible_bridge_safe_v1.dylib \
  wechat_cli/bin/wechat_local_visible_profile.json \
  docs/research/wechat-4.1.8.28-local-store-profile.md \
  tests/test_wechat_profile_validation.py
git commit -m "docs: pin measured local-store profile evidence"
```

Never add `/private/tmp/wechat-local-store-events-v2.jsonl`.

### Task 9: Verify Phase 1 remains fail closed

- [ ] **Step 1: Run the complete automated suite**

```bash
uv run --project . pytest -q
```

Expected: zero failures.

- [ ] **Step 2: Build and inspect temporary native artifacts**

```bash
phase1_build_dir=$(mktemp -d /private/tmp/wechat-phase1-build.XXXXXX)
./native/build.sh "$phase1_build_dir"
file "$phase1_build_dir"/*
codesign --verify --strict "$phase1_build_dir/libwechat_local_visible_bridge_safe_v1.dylib"
nm -nm "$phase1_build_dir/libwechat_local_visible_bridge_safe_v1.dylib" | \
  rg 'OwlHighLevelSendAdapter|VerifyOwlMainScopeRunner'
```

Expected: the build and code-sign commands exit 0; the final `rg` exits 1 with
no matches. Remove the explicit temporary directory after recording its exact
path; it contains reproducible build outputs only.

- [ ] **Step 3: Prove production still stops before injection**

Run:

```bash
uv run --project . python - <<'PY'
from wechat_cli.core.native_bridge_provider import _ready_profile
from wechat_cli.core.sending import SendUnavailableError

try:
    _ready_profile()
except SendUnavailableError as error:
    message = str(error)
    assert "profile" in message
    assert "未发送任何消息" in message
    print("profile_gate_fail_closed")
else:
    raise AssertionError("Phase 1 profile must not enable the adapter")
PY
```

Expected: exit 0 and print only `profile_gate_fail_closed`. This imports and
checks the packaged manifest directly; it does not invoke the CLI, injector,
bridge socket, or message store.

## Phase 1 completion gate

Do not claim the send feature is fixed at the end of this plan. Report only that
the crashing route is quarantined and the measured profile is ready for Phase
2. Start a separate `writing-plans` pass only after Task 9, using the generated
header and evidence table to write every Phase 2 typedef, RVA, ownership rule,
and call sequence exactly. `测试信息6` remains unsent until that evidence-derived
Phase 2 implementation, clean verification, and pre-send runtime checks all
pass.
