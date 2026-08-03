# Persistent Local-Visible Send Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the proven single `/newsendmsg` submission and add a persistent outgoing WeChat row that appears in the desktop conversation and `wechat-cli history` after restart.

**Architecture:** A transaction adapter coordinates two pinned gateways: `LocalMessageGateway` inserts and updates messages through WeChat's internal message-storage queue, while `MarsGateway` retains the working network task implementation from `feat/wechat-send`. The transaction reuses one client identifier across both gateways, returns success only after the same positive `local_id` has a positive `server_id`, and fails closed while any runtime profile field is unverified.

**Tech Stack:** C++17/Objective-C++, ARM64 assembly trampolines, macOS GCD/Mach APIs, Python 3, pytest, LLDB for read-only profiling.

---

## File map

- `native/include/wechat_bridge.hpp`: Existing bridge request/receipt contract; add internal gateway result types and factories without changing the socket JSON.
- `native/src/local_visible_adapter.mm`: New queue-independent transaction state machine, tested entirely with fake gateways.
- `native/src/wechat_adapter.mm`: Restore the proven Mars task implementation, then adapt it to the `MarsGateway` interface.
- `native/src/wechat_local_store.mm`: New strictly pinned WeChat storage/update gateway; no SQL and no direct database writes.
- `native/include/wechat_4_1_8_28_profile.hpp`: Generated constants for measured RVAs, entry signatures, ABI offsets, and queue boundary.
- `native/src/hook_trampolines.S`: Retain the proven request serialization hooks and add only a response hook if the measured virtual response boundary cannot complete directly.
- `native/build.sh`: Compile the new transaction and local-store translation units and retain hook trampolines.
- `native/tests/fake_host.mm`: Native fake gateway scenarios and process-level contract checks.
- `tests/test_native_bridge_host.py`: Red/green tests for local insert, single network submission, acknowledgement update, timeout, and fail-closed behavior.
- `tools/wechat_profile_capture.py`: Read-only LLDB capture helpers for one user-performed marker send.
- `tools/validate_wechat_profile.py`: Convert measured capture data into the pinned header only when all invariants agree.
- `tests/test_wechat_profile_validation.py`: Offline validation tests using sanitized capture fixtures.
- `docs/research/wechat-4.1.8.28-local-store-profile.md`: Human-readable evidence for every pinned field.
- `wechat_cli/core/native_sending.py`: No behavior change expected; regression tests prove it confirms the exact local row.

### Task 1: Restore the proven Mars baseline on the isolated branch

**Files:**
- Modify: `native/build.sh`
- Modify: `native/include/wechat_bridge.hpp`
- Modify: `native/src/wechat_adapter.mm`
- Modify: `native/tests/fake_host.mm`
- Modify: `tests/test_native_bridge_host.py`
- Delete: `codex_lldb_once.txt`
- Delete: `codex_map_functions.py`

- [ ] **Step 1: Record the expected baseline difference**

Run:

```bash
git diff --exit-code feat/wechat-send -- \
  native/build.sh native/include/wechat_bridge.hpp \
  native/src/wechat_adapter.mm native/tests/fake_host.mm \
  tests/test_native_bridge_host.py
```

Expected: non-zero because the unsafe direct UI-closure experiment differs from the working branch.

- [ ] **Step 2: Restore only the five experimental source/test files with `apply_patch`**

Use `git show feat/wechat-send:<path>` as the exact source for each file. Preserve the revised design and plan commits, and do not switch or modify `feat/wechat-send` itself. Remove the dead-PID LLDB command and the unused cross-build mapping helper; keep useful capture logic for Task 3.

- [ ] **Step 3: Verify exact source parity with the working adapter**

Run the same `git diff --exit-code` command from Step 1.

Expected: exit 0 with no output.

- [ ] **Step 4: Run the native bridge regression suite**

Run:

```bash
PYTHONPATH=. pytest -q tests/test_native_bridge_host.py
```

Expected: all tests pass and the fake host builds with `hook_trampolines.S` linked.

- [ ] **Step 5: Commit the clean baseline**

```bash
git add native/build.sh native/include/wechat_bridge.hpp \
  native/src/wechat_adapter.mm native/tests/fake_host.mm \
  tests/test_native_bridge_host.py
git commit -m "refactor: restore proven Mars send baseline"
```

### Task 2: Add the local-visible transaction contract

**Files:**
- Create: `native/src/local_visible_adapter.mm`
- Modify: `native/include/wechat_bridge.hpp`
- Modify: `native/build.sh`
- Modify: `native/tests/fake_host.mm`
- Modify: `tests/test_native_bridge_host.py`

- [ ] **Step 1: Write failing fake-gateway tests**

Add fake-host modes and Python tests for these exact cases:

```python
@pytest.mark.parametrize(
    ("scenario", "expected_local_calls", "expected_network_calls", "expected_update_calls"),
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
```

- [ ] **Step 2: Run the new tests and verify RED**

Run:

```bash
PYTHONPATH=. pytest -q tests/test_native_bridge_host.py -k local_visible_transaction
```

Expected: failures because the transaction factory and fake-host modes do not exist.

- [ ] **Step 3: Define the gateway interfaces**

Add these internal contracts to `native/include/wechat_bridge.hpp`:

```cpp
struct LocalMessageIdentity {
  std::int64_t local_id = 0;
  std::uint64_t client_id = 0;
  std::uint32_t create_time = 0;
};

struct NetworkAcceptance {
  bool accepted = false;
  std::int64_t server_id = 0;
};

using LocalInsertCompletion =
    std::function<void(std::optional<LocalMessageIdentity>)>;
using NetworkCompletion = std::function<void(NetworkAcceptance)>;
using LocalUpdateCompletion = std::function<void(bool)>;

class LocalMessageGateway {
 public:
  virtual ~LocalMessageGateway() = default;
  virtual void InsertOutgoing(const SendRequest& request,
                              std::uint64_t client_id,
                              std::uint32_t create_time,
                              LocalInsertCompletion completion) = 0;
  virtual void MarkAccepted(const LocalMessageIdentity& identity,
                            std::int64_t server_id,
                            LocalUpdateCompletion completion) = 0;
};

class MarsGateway {
 public:
  virtual ~MarsGateway() = default;
  virtual void Submit(const SendRequest& request,
                      const LocalMessageIdentity& identity,
                      NetworkCompletion completion) = 0;
};

std::shared_ptr<SendAdapter> CreateLocalVisibleAdapter(
    std::shared_ptr<LocalMessageGateway> local,
    std::shared_ptr<MarsGateway> mars);
```

- [ ] **Step 4: Implement the minimal transaction state machine**

In `native/src/local_visible_adapter.mm`, generate `client_id` and `create_time` once, call `InsertOutgoing`, call `MarsGateway::Submit` only after a positive local ID, and call `MarkAccepted` only after a positive server ID. All invalid or incomplete callbacks produce `AckState::kUnknown`; no branch calls `Submit` twice.

- [ ] **Step 5: Run RED tests to verify GREEN, then run all native tests**

```bash
PYTHONPATH=. pytest -q tests/test_native_bridge_host.py -k local_visible_transaction
PYTHONPATH=. pytest -q tests/test_native_bridge_host.py
```

Expected: both commands exit 0.

- [ ] **Step 6: Commit the transaction layer**

```bash
git add native/include/wechat_bridge.hpp native/src/local_visible_adapter.mm \
  native/build.sh native/tests/fake_host.mm tests/test_native_bridge_host.py
git commit -m "feat: add local-visible send transaction"
```

### Task 3: Produce a complete read-only WeChat storage profile

**Files:**
- Create: `tools/wechat_profile_capture.py`
- Create: `tools/validate_wechat_profile.py`
- Create: `tests/fixtures/wechat_local_store_capture.json`
- Create: `tests/test_wechat_profile_validation.py`
- Create: `docs/research/wechat-4.1.8.28-local-store-profile.md`
- Create: `native/include/wechat_4_1_8_28_profile.hpp`
- Delete: `codex_lldb_capture.py`

- [ ] **Step 1: Write failing profile-validation tests**

```python
def test_profile_rejects_missing_queue_or_identifier_evidence(tmp_path):
    capture = _valid_capture()
    capture.pop("storage_queue")
    assert validate_capture(capture) == "missing_storage_queue"


def test_profile_rejects_direct_gcd_ui_closure(tmp_path):
    capture = _valid_capture()
    capture["insert_entry_rva"] = 0x3399194
    assert validate_capture(capture) == "unsafe_await_closure"


def test_profile_emits_all_pinned_constants(tmp_path):
    header = render_header(_valid_capture())
    for name in (
        "kLocalInsertRva",
        "kLocalUpdateRva",
        "kConversationNotifyRva",
        "kStorageDispatchRva",
        "kResponseDecodeRva",
    ):
        assert name in header
```

- [ ] **Step 2: Run the validator tests and verify RED**

```bash
PYTHONPATH=. pytest -q tests/test_wechat_profile_validation.py
```

Expected: import failure because `tools/validate_wechat_profile.py` does not exist.

- [ ] **Step 3: Convert the existing capture helper into a bounded tool**

`tools/wechat_profile_capture.py` must:

- derive the loaded `wechat.dylib` base instead of hard-coding a PID or load address;
- filter every breakpoint by one exact marker present in the outgoing model;
- capture entry bytes, registers, queue/thread name, return value, and the same model before/after;
- include the observed candidates `0x26e6264` (local insert) and `0x26ea4fc` (local update), but label them candidates until validation proves their outputs;
- collect response decoding and conversation notification callers;
- automatically detach after the marker send and never invoke a send function.

- [ ] **Step 4: Implement strict offline validation**

`validate_capture()` returns a named failure unless all of these are measured in one manual marker send: positive local ID transition, identical client ID through request serialization, storage-queue identity, positive server ID update, conversation notification, current dylib UUID `ABD88EC8-4590-3FDB-AAB5-4E5865B86B2A`, and SHA-256 `b4a740135f3f1e937bca10caf0a95cff986ddf27fa6bb15ccaf64001fc651c93`.

On success, `render_header()` emits integer constants and byte signatures. It must reject RVA `0x3399194` for insert, update, dispatch, or notification.

- [ ] **Step 5: Run the offline tests to verify GREEN**

```bash
PYTHONPATH=. pytest -q tests/test_wechat_profile_validation.py
```

Expected: all tests pass.

- [ ] **Step 6: Capture one user-performed manual marker send**

Run LLDB in read-only observation mode, ask the user to manually send one unique marker to the dedicated test group, then detach automatically. The tool itself must not send, write WeChat memory, patch instructions, or keep the process stopped.

- [ ] **Step 7: Validate and generate the pinned header**

```bash
python3 tools/validate_wechat_profile.py \
  --capture /tmp/wechat-local-store-capture.json \
  --image /private/tmp/wechat-arm64-profile.dylib \
  --fixture tests/fixtures/wechat_local_store_capture.json \
  --header native/include/wechat_4_1_8_28_profile.hpp
```

Expected: `profile_valid`; otherwise keep production sending disabled and stop this task without a live bridge test.

- [ ] **Step 8: Record evidence and commit**

Document each generated constant, ABI argument, return value, queue, and signature in `docs/research/wechat-4.1.8.28-local-store-profile.md`.

```bash
git add tools/wechat_profile_capture.py tools/validate_wechat_profile.py \
  tests/fixtures/wechat_local_store_capture.json \
  tests/test_wechat_profile_validation.py \
  docs/research/wechat-4.1.8.28-local-store-profile.md \
  native/include/wechat_4_1_8_28_profile.hpp
git commit -m "docs: pin WeChat local message storage profile"
```

### Task 4: Implement the pinned local message gateway

**Files:**
- Create: `native/src/wechat_local_store.mm`
- Modify: `native/include/wechat_bridge.hpp`
- Modify: `native/build.sh`
- Modify: `native/tests/fake_host.mm`
- Modify: `tests/test_native_bridge_host.py`

- [ ] **Step 1: Write failing native layout and queue tests**

Add fake-host tests that verify:

```python
def test_local_store_builds_exact_outgoing_text_model(native_build):
    result = _run_local_store_contract(native_build, "insert")
    assert result["recipient"] == "59034084590@chatroom"
    assert result["text"] == "Unicode 👋\n$HOME `literal`"
    assert result["client_id"] == 202608020001
    assert result["local_id"] == 41


def test_local_store_dispatches_only_on_captured_storage_queue(native_build):
    result = _run_local_store_contract(native_build, "queue")
    assert result["socket_thread_calls"] == 0
    assert result["storage_queue_calls"] == 1
```

- [ ] **Step 2: Run the new tests and verify RED**

```bash
PYTHONPATH=. pytest -q tests/test_native_bridge_host.py -k local_store
```

Expected: failure because `wechat_local_store.mm` is absent.

- [ ] **Step 3: Implement the model, dispatch, insert, and update calls**

Use only generated constants from `wechat_4_1_8_28_profile.hpp`. Validate all entry signatures before constructing the gateway. Retain model and callback storage until completion. `InsertOutgoing` accepts only exact `@chatroom` recipients and returns `nullopt` unless WeChat reports a positive local ID. `MarkAccepted` updates the same local ID with the measured positive server ID and invokes the measured conversation notification on the same internal queue.

Expose this factory in `native/include/wechat_bridge.hpp`:

```cpp
std::shared_ptr<LocalMessageGateway> CreatePinnedLocalMessageGateway(
    std::string* unsupported_reason);
```

- [ ] **Step 4: Verify GREEN and all native regressions**

```bash
PYTHONPATH=. pytest -q tests/test_native_bridge_host.py -k local_store
PYTHONPATH=. pytest -q tests/test_native_bridge_host.py
```

Expected: both commands exit 0.

- [ ] **Step 5: Commit the local gateway**

```bash
git add native/src/wechat_local_store.mm native/include/wechat_bridge.hpp native/build.sh \
  native/tests/fake_host.mm tests/test_native_bridge_host.py
git commit -m "feat: add pinned local message gateway"
```

### Task 5: Adapt the proven Mars task to measured identifiers and ACK

**Files:**
- Modify: `native/include/wechat_bridge.hpp`
- Modify: `native/src/wechat_adapter.mm`
- Modify: `native/src/hook_trampolines.S`
- Modify: `native/tests/fake_host.mm`
- Modify: `tests/test_native_bridge_host.py`

- [ ] **Step 1: Write failing request and response tests**

```python
def test_mars_request_reuses_local_message_client_id(native_build):
    result = _run_mars_contract(native_build, "serialize")
    assert result["message_client_id"] == 202608020001
    assert result["network_submit_count"] == 1


def test_mars_ack_returns_server_id_once(native_build):
    result = _run_mars_contract(native_build, "accepted")
    assert result["completion_count"] == 1
    assert result["accepted"] is True
    assert result["server_id"] == 99


def test_mars_timeout_never_resubmits(native_build):
    result = _run_mars_contract(native_build, "timeout")
    assert result["network_submit_count"] == 1
    assert result["accepted"] is False
```

- [ ] **Step 2: Run the new tests and verify RED**

```bash
PYTHONPATH=. pytest -q tests/test_native_bridge_host.py -k mars
```

Expected: failures because the original adapter generates its own client ID and discards response data.

- [ ] **Step 3: Convert the original adapter into `MarsGateway`**

Preserve `BuildTextRequest`, `PrepareOpaqueObjects`, `MMStartTask`, and the working Req2Buf hook layout. Replace its task-generated client ID with `LocalMessageIdentity.client_id`. Decode the response through the measured profile boundary and complete once with `NetworkAcceptance{true, positive_server_id}`. Transport errors, parse failures, process exit, or missing IDs complete unknown and never call `MMStartTask` again.

Expose this factory in `native/include/wechat_bridge.hpp`:

```cpp
std::shared_ptr<MarsGateway> CreatePinnedMarsGateway(
    std::string* unsupported_reason);
```

- [ ] **Step 4: Verify GREEN and all native regressions**

```bash
PYTHONPATH=. pytest -q tests/test_native_bridge_host.py -k mars
PYTHONPATH=. pytest -q tests/test_native_bridge_host.py
```

Expected: both commands exit 0.

- [ ] **Step 5: Commit the Mars gateway**

```bash
git add native/include/wechat_bridge.hpp native/src/wechat_adapter.mm native/src/hook_trampolines.S \
  native/tests/fake_host.mm tests/test_native_bridge_host.py
git commit -m "feat: correlate Mars ACK with local message"
```

### Task 6: Wire the production factory and fail-closed profile gate

**Files:**
- Modify: `native/include/wechat_bridge.hpp`
- Modify: `native/src/bridge_service.mm`
- Modify: `native/src/wechat_adapter.mm`
- Modify: `native/src/bridge_entry.mm`
- Modify: `native/tests/fake_host.mm`
- Modify: `tests/test_native_bridge_host.py`
- Modify: `wechat_cli/core/native_bridge_provider.py`
- Modify: `tests/test_native_bridge_provider.py`

- [ ] **Step 1: Write failing production-factory tests**

```python
def test_production_factory_requires_complete_local_profile(native_build):
    result = _run_factory_contract(native_build, "missing-notify-signature")
    assert result == "unsupported_wechat_local_store_profile"


def test_production_factory_composes_local_and_mars_gateways(native_build):
    result = _run_factory_contract(native_build, "complete-fake-profile")
    assert result == "local-visible-adapter-ready"


def test_local_visible_endpoint_is_distinct_from_base_endpoint(tmp_path):
    paths = _bridge_paths(tmp_path, pid=8717)
    assert paths.metadata.name == "bridge-8717-local-visible.json"
    assert paths.socket.name == "wechat-bridge-8717-local-visible.sock"
    assert paths.error.name == "bridge-8717-local-visible.error"
```

- [ ] **Step 2: Run the tests and verify RED**

```bash
PYTHONPATH=. pytest -q tests/test_native_bridge_host.py -k production_factory
```

Expected: failures because production still constructs only the Mars adapter.

- [ ] **Step 3: Compose the production transaction**

`CreateProductionWeChatAdapter` must validate the image path, UUID, SHA-256 supplied by preflight, every generated entry signature, and the storage dispatcher before returning. It creates both gateways first, rejects either error, and then returns:

```cpp
return CreateLocalVisibleAdapter(
    std::move(local_gateway),
    std::move(mars_gateway));
```

Any missing component publishes `unsupported_wechat_local_store_profile` before the bridge socket starts. Do not retain the direct UI closure RVA in executable code.

Add `BridgeConfig.endpoint_suffix = "local-visible"`, accept only the literal
safe suffix in `BridgeService`, and use it consistently for metadata, socket,
startup-error, and Python provider paths. This prevents an already-loaded base
bridge in the same PID from being mistaken for the local-visible bridge and
permits hot loading without a WeChat restart.

Define the Python path helper with a stable return type:

```python
@dataclass(frozen=True)
class BridgePaths:
    metadata: Path
    socket: Path
    error: Path


def _bridge_paths(directory: Path, pid: int) -> BridgePaths:
    suffix = "local-visible"
    return BridgePaths(
        metadata=directory / f"bridge-{pid}-{suffix}.json",
        socket=directory / f"wechat-bridge-{pid}-{suffix}.sock",
        error=directory / f"bridge-{pid}-{suffix}.error",
    )
```

- [ ] **Step 4: Verify GREEN and run all native tests**

```bash
PYTHONPATH=. pytest -q tests/test_native_bridge_host.py -k production_factory
PYTHONPATH=. pytest -q tests/test_native_bridge_provider.py
PYTHONPATH=. pytest -q tests/test_native_bridge_host.py
```

Expected: both commands exit 0.

- [ ] **Step 5: Commit production composition**

```bash
git add native/include/wechat_bridge.hpp native/src/bridge_service.mm \
  native/src/wechat_adapter.mm native/src/bridge_entry.mm \
  native/tests/fake_host.mm tests/test_native_bridge_host.py \
  wechat_cli/core/native_bridge_provider.py tests/test_native_bridge_provider.py
git commit -m "feat: enable pinned local-visible send adapter"
```

### Task 7: Run Python transaction and confirmation regressions

**Files:**
- Test: `tests/test_native_send_service.py`
- Test: `tests/test_send_confirmation.py`
- Test: `tests/test_send.py`

- [ ] **Step 1: Add a regression for the persistent row contract if absent**

```python
def test_native_send_accepts_only_the_bridge_local_row():
    service, store = _service(
        receipt=_receipt(local_id=41, server_id=99),
        confirmation=MessageConfirmation(local_id=41, server_id=99),
    )
    result = service.send_text(_request())
    assert result.local_id == 41
    assert result.server_id == 99
    assert store.poll_calls[0]["local_id"] == 41
```

- [ ] **Step 2: Run the focused Python tests**

```bash
PYTHONPATH=. pytest -q \
  tests/test_native_send_service.py \
  tests/test_send_confirmation.py \
  tests/test_send.py
```

Expected: all tests pass; if the regression already exists, no Python production file changes are required.

- [ ] **Step 3: Commit only if a test was added**

```bash
git add tests/test_native_send_service.py
git commit -m "test: require exact persisted local message"
```

### Task 8: Package, verify, and perform one explicitly approved live test

**Files:**
- Modify: `wechat_cli/bin/libwechat_send_bridge.dylib`
- Modify: `wechat_cli/bin/wechat_send_injector`
- Modify: `README.md`
- Modify: `README_CN.md`

- [ ] **Step 1: Run the complete automated suite**

```bash
PYTHONPATH=. pytest -q
```

Expected: zero failures.

- [ ] **Step 2: Build and inspect packaged ARM64 artifacts**

```bash
./native/build.sh wechat_cli/bin
file wechat_cli/bin/libwechat_send_bridge.dylib \
  wechat_cli/bin/wechat_send_injector
codesign --verify --strict wechat_cli/bin/libwechat_send_bridge.dylib
codesign --verify --strict wechat_cli/bin/wechat_send_injector
```

Expected: both artifacts are ARM64 and both signature checks exit 0.

- [ ] **Step 3: Verify CLI and fail-closed behavior without sending**

```bash
PYTHONPATH=. python -m wechat_cli.main send --help
```

Expected: documented group/text/timeout/format options and no process attachment.

- [ ] **Step 4: Ask for a separate live-test confirmation**

State the exact group and one unique message. Do not reuse any earlier failed text. Submit exactly once only after the user confirms.

- [ ] **Step 5: Verify local persistence after that one submission**

Confirm all four observations without retrying: the CLI receipt contains positive `local_id/server_id`, the desktop conversation displays the text, `wechat-cli history` contains the exact outgoing row, and the row remains after a user-chosen WeChat restart. If any observation is incomplete, report `unknown` and stop.

- [ ] **Step 6: Update documentation and commit packaged output**

Document the pinned build, persistent local-row behavior, no-retry rule, and unsupported-profile failure.

```bash
git add README.md README_CN.md \
  wechat_cli/bin/libwechat_send_bridge.dylib \
  wechat_cli/bin/wechat_send_injector
git commit -m "feat: ship persistent local-visible group send"
```
