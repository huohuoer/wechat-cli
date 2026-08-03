# Safe Local-Visible Background Send Recovery Design

## Goal

Make `wechat-cli send` deliver one group text while creating the same persistent
outgoing row that desktop WeChat displays, without focusing, raising, clicking,
typing into, or otherwise operating any WeChat window. The path must also work
when WeChat is minimized or covered by another application.

The first approved live acceptance message is exactly `测试信息6` to the uniquely
resolved group `AI聊天群`. It may be submitted once only after every offline and
non-mutating runtime gate passes.

## Incident and root cause

The current uncommitted `local-visible v6` experiment is unsafe and must not be
used again. Crash reports at 14:03 and 18:02 on 2026-08-02 show the same
deterministic failure:

- WeChat 4.1.8 (36571) terminates itself with `SIGABRT` on the main thread.
- The stack returns directly to `OwlHighLevelSendAdapter` after its indirect call
  to WeChat RVA `0x25cd228`.
- The adapter passes a manually fabricated private message object to the high
  level send routine.
- WeChat reaches an internal fatal invariant and calls `abort()` before a local
  row or confirmed network result exists.

The exact rejected private field is not present in the stripped crash report,
but the call boundary and repeated failure are conclusive. This is not a login
transition, timeout, or random process crash.

The existing 212-test suite passes because its fake Owl runner executes a C++
lambda without modeling WeChat's private object and coroutine invariants. Those
tests do not establish live safety.

## Rejected approaches

### Patch the high-level private send object

Rejected. The private object layout and caller-owned invariants are incomplete,
and two live attempts produced the same fatal abort. Further field-by-field live
experiments would use the user's WeChat process as a crash probe.

### Directly write the WeChat database

Rejected. Direct writes can desynchronize WCDB indexes, conversation state,
notifications, encryption metadata, and server acknowledgement state. They also
cannot prove that the desktop client accepted and owns the row.

### UI automation

Rejected by the product requirement. The send path must not focus or operate a
window, clipboard, input field, or keyboard, even temporarily.

## Chosen architecture

Retain the committed queue-independent `LocalVisibleAdapter` transaction and
complete its two gateway dependencies:

1. `PinnedLocalMessageGateway` creates and updates an outgoing row through
   WeChat's measured internal message-storage API on its measured execution
   context.
2. `PinnedMarsGateway` retains the proven one-shot network task from
   `feat/wechat-send` and reuses the local message identity.
3. `LocalVisibleAdapter` sequences local insert, one network submission, and
   local acceptance update. It never retries or falls back.

The production factory composes these gateways only when an exact, complete,
measured profile is available for the running WeChat image. Otherwise `send`
fails before creating a local row or submitting a network task.

The unsafe `OwlHighLevelSendAdapter`, its source, its provider selection, and
all experimental v3-v6 packaged dylibs are removed from the production path.

## Profile evidence gate

Production constants must be generated from one sanitized, read-only capture
of a normal user-performed marker send on the exact supported build. Static
disassembly may explain captured calls but cannot substitute for runtime
evidence.

The capture must establish all of these in one message lifecycle:

- exact image path, ARM64 UUID, SHA-256, and entry signatures;
- the real message model ownership and required lifetime;
- the storage execution context and dispatch boundary;
- exact insert arguments and a zero-to-positive `local_id` transition;
- the same client identifier in local storage and the Mars request;
- the server response decode boundary and a positive `server_id`;
- update of the same local row to accepted status;
- the normal conversation refresh notification for that row;
- a non-mutating runtime-readiness probe that distinguishes an entered,
  send-capable account from the pre-entry login screen.

The validator emits a pinned header only when every invariant agrees. A
hand-written test fixture can test validator branches, but it can never enable
the production factory. Generated output records a digest of the sanitized raw
capture so fabricated constants or partial captures fail closed.

If another manual marker capture is required, it is a separate externally
visible action and requires explicit confirmation at action time. The capture
tool only observes and automatically detaches; it never calls a WeChat function
or sends a message.

## Send data flow

1. Resolve `GROUP` to one exact existing `@chatroom` contact and validate text.
2. Verify the pinned app path, bundle/build identifiers, image UUID/hash, code
   signatures, one live WeChat PID, and the measured send-capable account state.
3. Capture the target message-table baseline before any mutation.
4. Generate one request ID, client ID, and creation timestamp.
5. On the measured storage context, insert the outgoing text model and require a
   positive local ID that matches the transaction identity.
6. Submit the proven Mars task exactly once with the same recipient, text,
   client ID, timestamp, and supported local identifier fields.
7. Decode one positive server acceptance. On the measured storage context,
   update the same local row and publish the measured conversation notification.
8. Refresh the read cache and confirm exactly one new outgoing text row with the
   same local ID, positive server ID, sender identity, text, and accepted status.
9. Return `server_accepted` only after all checks pass.

No step operates the WeChat UI or changes the frontmost application.

## Failure semantics

Failures are classified by the last proven boundary:

- Before local insertion and before network submission: return `unavailable`
  and explicitly state that no message was sent.
- After a local row or any network bytes may exist: return `unknown`, preserve
  every known identifier, and prohibit automatic retry.
- Process exit, bridge disconnect, timeout, duplicate matching rows, identifier
  disagreement, missing notification, or an incomplete callback after a
  mutation boundary is always `unknown`.
- A stale bridge from another PID or profile is never reused.
- The tool never restarts, relaunches, re-enters, or foregrounds WeChat after a
  failure.

## Safety containment

- The build and source tests ban the high-level send RVA and
  `OwlHighLevelSendAdapter` from the production bridge.
- Profile validation occurs before the production adapter becomes reachable.
- All native argument, callback, model, and task storage remains owned through
  its final callback or process lifetime where the WeChat lifetime is unknown.
- The local and network gateways are single-flight for one group transaction.
- Injection permission failure is an `unavailable` result; the tool does not
  re-sign or restart WeChat during `send`.
- Runtime files use distinct PID- and implementation-scoped names and strict
  ownership/mode checks.
- Logs and receipts exclude message text, auth tokens, decrypted keys, and raw
  captured memory.

## Testing strategy

Implementation follows test-first red-green-refactor cycles.

### Static and profile tests

- Reject every missing capture invariant, synthesized production profile,
  wrong image, unsafe RVA, signature mismatch, or queue mismatch.
- Verify the generated header is reproducible from the sanitized capture.
- Verify production source and linked artifacts contain no reference to the
  unsafe adapter or high-level send entry.

### Native fake-gateway tests

- Insert failure performs zero network submissions.
- Success performs one insert, one network submission, and one update in order.
- Every stage reuses the same identity.
- Duplicate, late, invalid, timeout, and reentrant callbacks complete once and
  never resubmit.
- Model and callback ownership survives asynchronous completion.

### Python and bridge tests

- Only an acknowledged receipt with matching positive IDs and the exact new
  database row returns success.
- Pre-entry/login-not-ready state fails before message mutation.
- Stale endpoints, process replacement, and malformed receipts fail closed.
- Full CLI, bridge, confirmation, and packaging suites pass from a clean build.

### Live acceptance test

Before the one approved send, record the frontmost app, WeChat PID, crash-report
baseline, target history baseline, and absence of `测试信息6`. The user controls
whether WeChat is minimized; the tool does not change its window state.

Submit exactly once to `AI聊天群`, then require all of:

- CLI receipt contains matching positive `local_id` and `server_id`;
- `wechat-cli history` contains exactly one new outgoing `测试信息6` row;
- the desktop conversation displays `测试信息6` when inspected read-only;
- WeChat PID is unchanged and no new crash report exists;
- the previously frontmost application remains frontmost throughout send.

If the send result is `unknown`, do not retry even when a later observation is
missing. Report the evidence and stop.

## Non-goals

- Direct contacts, non-text messages, mentions, replies, and attachments.
- Supporting a different WeChat version or image fingerprint.
- Restarting WeChat to prove persistence during this recovery task.
- Generalizing private ABI discovery beyond the one pinned supported build.
- Hiding an unsupported or incomplete profile behind a best-effort fallback.

## Acceptance criteria

The recovery is complete only when the unsafe path is absent, the evidence gate
is complete, clean automated verification passes, and the single approved live
test satisfies every observation above. Passing fake tests without a complete
measured profile is not completion.
