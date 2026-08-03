# Local-Visible Background Send Design

## Goal

Make `wechat-cli send` create the same persistent outgoing text row that a
normal WeChat send creates, while retaining background operation, exact group
resolution, and the already-working network delivery path.

## Observed behavior

The adapter on `feat/wechat-send` submits one `/newsendmsg` Mars task. Group
members receive the text, but WeChat does not create an outgoing row in its
local message store. The message is therefore absent from the desktop
conversation and from `wechat-cli history`.

An experimental replacement called a captured UI send closure from the GCD
main queue. WeChat aborted before local persistence or network submission with
`await_noexcept() must be called from coroutine context`. That boundary cannot
be called directly and remains disabled.

## Chosen design

Retain the proven Mars adapter from `feat/wechat-send` and add a pinned local
persistence stage for WeChat 4.1.8.28 ARM64. Before the existing adapter submits
its one network task, the bridge asks WeChat's own MessageStore/MessageService
layer, on its required internal queue, to create the outgoing text row. The
returned positive `local_id` and the message's client identifier are reused by
the Mars request. A successful response updates that same row's status and
`server_id` through WeChat's internal message API and publishes the normal
conversation refresh notification.

This design does not call the UI send closure or replace the working network
path. The base `feat/wechat-send` branch remains unchanged. If local persistence
cannot be proven safe before any side effect, this branch fails before network
submission. After a local row or network task may exist, every incomplete
result is `unknown`; the bridge never falls back or retries.

## Data flow

1. Resolve an exact group and validate non-empty text as today.
2. Build one outgoing WeChat message model with a unique request/client ID.
3. Submit a local-insert operation to WeChat's message-storage queue and require
   a positive `local_id` before continuing.
4. Serialize the existing Mars task once, reusing the same recipient, text,
   client ID, timestamp, and local identifier where the pinned protocol fields
   support it.
5. On the internal response callback, update the same local row to the accepted
   state with a positive `server_id`, then notify the conversation model.
6. Refresh the existing read cache and confirm that exact outgoing row before
   reporting `server_accepted`.

If the local row exists but submission or acknowledgement is incomplete, the
row remains pending or failed according to WeChat's own state transition. It is
not deleted, rewritten directly, or automatically resent.

## Profile discovery

Use offline metadata, strings, disassembly, and instruction cross-references
first. Candidate storage and update boundaries must expose or lead to all of:

- an exact `@chatroom` recipient;
- UTF-8 text passed without rewriting;
- creation of a positive local message ID on WeChat's storage queue;
- an update of the same row by local/client identifier;
- a conversation refresh notification;
- a completion path that stores a positive server ID.

Any runtime observation remains read-only until the ABI, queue, ownership, and
instruction signatures are known. No diagnostic message is sent to a real group
without a separate explicit request.

## Bridge contract

Keep the existing authenticated Unix-socket request format and the Mars
adapter's single network submission. The native adapter returns `acknowledged`
only when it has a positive local ID and the corresponding internal response
updated the same message. Python then confirms the outgoing row has `status=2`
and a positive server ID before returning `server_accepted`.

The bridge remains single-flight. Timeout, process exit, incomplete callbacks,
or identifier disagreement returns `unknown` and forbids automatic retry.

## Hot loading

Build the experimental bridge with a distinct dylib/install name and distinct
PID-specific metadata/socket names. This permits loading without restarting
WeChat while preventing reuse of a bridge from a dead PID. The CLI on this
branch uses only the experimental endpoint and never falls back to the base
endpoint after a request begins.

## Non-goals

- No direct writes to WeChat databases.
- No UI input, clipboard use, or foreground-window switching.
- No external recreation of the WeChat network protocol.
- No direct invocation of an `await_noexcept` closure from a GCD queue.
- No automatic fallback or retry after a possible submission.
- No support for non-text messages, mentions, replies, attachments, or direct
  contacts.

## Failure containment and tests

Every pinned function has a build fingerprint and entry-instruction signature.
The storage queue, ownership rules, local-ID output, update callback, and
notification boundary must all be profiled; partial profiles remain disabled.
Unsupported or ambiguous profiles fail before local insertion or network
submission. All owned argument storage remains alive through completion.

Native fake-host tests cover local insert success/failure, exact identifier
reuse, acknowledgement updates, conversation notifications, timeouts, and the
rule that no network submission occurs when local insertion fails. CI never
attaches to WeChat. A real test is allowed only after those checks pass and the
user separately approves one uniquely identifiable message to a dedicated test
group.
