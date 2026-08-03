# WeChat 4.1.8.28 Local-Store Boundary Map

This note records only entry points verified against the pinned ARM64 slice.
It deliberately does not assign function roles to direct field writes or to
addresses that fall inside larger functions.

## Image identity

- Path: `/private/tmp/wechat-arm64-profile.dylib`
- SHA-256: `0e8c932461b883a4e4dc90313a14a30ea69a190fedf1083d014259bec56da2e0`
- UUID: `ABD88EC8-4590-3FDB-AAB5-4E5865B86B2A`
- Architecture: ARM64

## Active read-only probes

| Label | RVA | Entry bytes | Evidence |
| --- | ---: | --- | --- |
| `model_text_finalize` | `0x25634B0` | `00e1049121411491a45ce794a92240a9` | Final text assignment immediately before the verified insert call. The same function loads a pre-existing shared message model into `x8`, sets `x0 = x8 + 0x138`, and copies text from `x9 + 0x510`; the subsequent insert receives that model in `x1`. |
| `insert` | `0x26E620C` | `e93c0390294942f9490000b420011fd6` | Function prologue or runtime-patch branch. Caller at `0x253B858` sets `x8` to the sret destination, `x0` to the storage/service object, and leaves the shared message model in `x1`. The wrapper calls `0x44CB850(x1)`, then tail-calls `0x26E6264` with `x2` set to the extracted string and `w3 = 1`. |
| `insert_impl` | `0x26E6264` | `e93c0390294d42f9490000b420011fd6` | Tail-call target of the verified insert wrapper. Its prologue preserves the message model from `x1` and the sret pointer from `x8`. |
| `mars_submit` | `0x498D2E0` | `ff0305d1fc6f11a9f44f12a9fd7b13a9` | Function entry with a normal ARM64 prologue. Nearby literals identify `mars::mmext`, `MMStartTask`, and `mmstn_manager.cc`. This is the already measured Mars task-submission boundary. |

These four probes are installed together and stay within the capture tool's
conservative four-breakpoint ARM64 budget. The profiler only reads registers,
bounded memory, and backtraces. It never evaluates an expression, calls a
WeChat function, or writes target memory.

The approved `WCPROFILE-20260802-01`, `WCPROFILE-20260802-02`, and
`WCPROFILE-20260803-01` captures establish the observed transaction as
`insert -> insert_impl -> mars_submit`. The third capture recorded the exact
marker in the model passed as `insert` argument `x1`, while the constructor
probe did not fire at all. `model_text_finalize`, `insert`, or `insert_impl`
may establish the marker transaction identity. Text-finalize capture tracks
the model in `x8`; insert capture tracks the shared model pointer in `x1`;
Mars is correlated by the coroutine thread and marker reachability.

## Rejected candidates

| Candidate | Status | Reason |
| --- | --- | --- |
| Model constructors at `0x44C9EA8`, `0x44CAE3C`, and `0x44CB324` | Rejected for action-time capture | The first constructor did not fire during the exact marker send. Static data flow at `0x2562BFC` shows the send coroutine receives the model through an existing shared pointer, so construction may precede the bounded action window. The other variants decode or copy stored records and do not improve action-time identity. |
| Recipient/client-id/create-time setters | Unresolved and not probed | Static call chains show that some values are assigned with direct field writes. No distinct function entry has been proved for these roles. |
| `0x26EA4FC` update | Rejected | Its caller at `0x253B018` belongs to the function beginning near `0x253AF94`, while insert's caller at `0x253B858` belongs to the separate function beginning at `0x253B798`. Neither approved marker capture hit this boundary, so it is not part of the observed outgoing insert transaction. |
| `0x372FD60` response decoder | Rejected pending runtime evidence | It is a real function, but current static evidence only supports a generic decoder/parser role, not the send-response boundary. |
| `0x202906C` notification | Rejected | The address lies inside the function spanning approximately `0x2028478..0x2029CD4`; it is not a valid entry point. |
| `0x25CD228` high-level send | Forbidden | Direct calls have a deterministic crash path because the surrounding Owl coroutine context is missing. |
| `0x3399194` UI coroutine closure | Excluded from this capture | It is a real closure entry, but observing the insert/update transaction does not require triggering or probing UI send code. |

## Next evidence target

The inserted model's first pointer resolves to vtable RVA `0x8A0E138`. In the
send function beginning at `0x2562BB0`, `0x2562BFC` copies the pre-existing
shared model pointer into the stack slot later loaded by `0x25634A4`.
`0x25634B0` then assigns final text through that model's `+0x138` string before
the call leading to insert. Runtime evidence must now prove that
`model_text_finalize` register `x8` equals the model observed as insert and
insert-impl register `x1`. Response decode and conversation notification remain
unresolved and must not be inferred from the rejected update candidate.
