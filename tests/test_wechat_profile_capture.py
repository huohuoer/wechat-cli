import inspect
import stat
import sys
from types import SimpleNamespace

import pytest

from tools import wechat_profile_capture as capture


def test_probe_plan_never_uses_more_than_four_hardware_breakpoints():
    phases = capture.build_probe_phases()
    assert phases
    assert all(1 <= len(phase.probes) <= 4 for phase in phases)
    assert {
        (probe.label, probe.rva)
        for phase in phases
        for probe in phase.probes
    } == {
        ("insert", 0x26E620C),
        ("insert_return", 0x253B85C),
        ("insert_result_check", 0x253B904),
        ("mars_submit", 0x498D2E0),
    }


def test_snapshot_pointer_regions_include_the_frame_pointer():
    assert "x29" in capture._SNAPSHOT_POINTER_REGISTERS


def test_every_runtime_probe_has_a_resolved_positive_rva():
    probes = [
        probe
        for phase in capture.build_probe_phases()
        for probe in phase.probes
    ]
    assert all(0 < probe.rva < 0x10000000 for probe in probes)
    assert capture._unresolved_probe_labels() == []


def test_capture_source_cannot_call_or_evaluate_wechat_functions():
    source = inspect.getsource(capture)
    for forbidden in (
        "EvaluateExpression",
        "SBExpressionOptions",
        "CallFunction",
        "process.Call",
        "thread.Call",
        "write_memory",
        "WriteMemory",
    ):
        assert forbidden not in source


def test_capture_source_excludes_known_crashing_and_ui_trigger_rvas():
    source = inspect.getsource(capture).lower()
    assert "0x25cd228" not in source
    assert "0x3399194" not in source


def test_lldb_arguments_use_one_owned_lifecycle_command_and_never_send(tmp_path):
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
    assert len(lldb_commands) == 2
    assert lldb_commands[1].startswith("wechat-profile-run ")
    assert all("process call" not in command.lower() for command in lldb_commands)
    assert all("expression" not in command.lower() for command in lldb_commands)
    assert all(command != "process continue" for command in lldb_commands)
    assert all(command != "process detach" for command in lldb_commands)


def test_raw_capture_output_is_owner_only_and_rejects_symlinks(tmp_path):
    output = tmp_path / "events.jsonl"
    capture._prepare_output(output)

    assert stat.S_IMODE(output.stat().st_mode) == 0o600

    target = tmp_path / "target.jsonl"
    target.write_text("do not truncate", encoding="utf-8")
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)

    with pytest.raises(OSError):
        capture._prepare_output(link)

    assert target.read_text(encoding="utf-8") == "do not truncate"


def test_command_output_path_does_not_resolve_symlinks(tmp_path):
    target = tmp_path / "target.jsonl"
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)

    assert capture._command_output_path(str(link)) == link


class _CaptureResult:
    def __init__(self):
        self.error = None
        self.messages = []

    def SetError(self, message):
        self.error = message

    def AppendMessage(self, message):
        self.messages.append(message)


class _CommandDebugger:
    def __init__(self):
        self.commands = []

    def HandleCommand(self, command):
        self.commands.append(command)


def test_lldb_module_registers_owned_lifecycle_command():
    debugger = _CommandDebugger()

    capture.__lldb_init_module(debugger, {})

    assert debugger.commands == [
        f"command script add -f {capture.__name__}.run_capture "
        "wechat-profile-run",
    ]


class _Process:
    def __init__(self, *, interrupt_result=True, interrupt_error=None):
        self.interrupts = 0
        self.stops = 0
        self.interrupt_result = interrupt_result
        self.interrupt_error = interrupt_error

    def SendAsyncInterrupt(self):
        self.interrupts += 1
        if self.interrupt_error is not None:
            raise self.interrupt_error
        return self.interrupt_result

    def Stop(self):
        self.stops += 1
        return None


class _Timer:
    def __init__(self, interval, function, args):
        self.interval = interval
        self.function = function
        self.args = args
        self.daemon = False
        self.started = False

    def start(self):
        self.started = True


def test_capture_timeout_allows_a_two_minute_manual_send_window(monkeypatch):
    assert capture.CAPTURE_TIMEOUT_SECONDS == 120.0
    created = []

    def fake_timer(interval, function, args):
        timer = _Timer(interval, function, args)
        created.append(timer)
        return timer

    monkeypatch.setattr(capture.threading, "Timer", fake_timer)
    monkeypatch.setattr(capture, "_capture_deadline", 130.0)
    monkeypatch.setattr(capture.time, "monotonic", lambda: 10.0)
    process = _Process()

    timer = capture._schedule_interrupt(process)

    assert timer is created[0]
    assert timer.interval == 120.0
    assert timer.daemon is True
    assert timer.started is True
    timer.function(*timer.args)
    assert process.interrupts == 1


def test_capture_timeout_falls_back_to_process_stop():
    process = _Process(interrupt_result=False)

    capture._interrupt_process(process)

    assert process.interrupts == 1
    assert process.stops == 1


def test_capture_timeout_exception_also_falls_back_to_process_stop():
    process = _Process(interrupt_error=RuntimeError("interrupt failed"))

    capture._interrupt_process(process)

    assert process.interrupts == 1
    assert process.stops == 1


def test_capture_timeout_uses_only_remaining_deadline(monkeypatch):
    created = []

    def fake_timer(interval, function, args):
        timer = _Timer(interval, function, args)
        created.append(timer)
        return timer

    monkeypatch.setattr(capture.threading, "Timer", fake_timer)
    monkeypatch.setattr(capture, "_capture_deadline", 15.0)
    monkeypatch.setattr(capture.time, "monotonic", lambda: 10.0)

    capture._schedule_interrupt(_Process())

    assert created[0].interval == 5.0


def test_capture_refuses_to_continue_after_setup_consumes_deadline(monkeypatch):
    monkeypatch.setattr(capture, "_capture_deadline", 10.0)
    monkeypatch.setattr(capture.time, "monotonic", lambda: 10.0)

    with pytest.raises(RuntimeError, match="capture_deadline_expired"):
        capture._schedule_interrupt(_Process())


class _Breakpoint:
    def __init__(self, breakpoint_id):
        self.breakpoint_id = breakpoint_id

    def GetID(self):
        return self.breakpoint_id


class _BreakpointLocation:
    def __init__(self, breakpoint_id):
        self.breakpoint = _Breakpoint(breakpoint_id)

    def GetBreakpoint(self):
        return self.breakpoint


def test_expired_deadline_stops_callback_before_memory_scan(monkeypatch):
    monkeypatch.setattr(capture, "_capture_deadline", 10.0)
    monkeypatch.setattr(capture.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(capture, "_breakpoint_labels", {7: "insert"})
    monkeypatch.setattr(
        capture,
        "_marker_reachable",
        lambda _frame: pytest.fail("expired callback must not scan memory"),
    )

    assert capture.capture_breakpoint(
        object(), _BreakpointLocation(7), {}
    ) is True


class _ScanThread:
    def GetProcess(self):
        return object()


class _ScanFrame:
    def GetThread(self):
        return _ScanThread()

    def FindRegister(self, name):
        return _Register(0x100000000 if name == "x0" else 0)


def test_marker_scan_honors_absolute_deadline_before_each_read(monkeypatch):
    monkeypatch.setattr(capture, "_capture_deadline", 10.0)
    monkeypatch.setattr(capture.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(
        capture,
        "_read",
        lambda *_args: pytest.fail("expired scan must not read memory"),
    )

    assert capture._marker_reachable(_ScanFrame()) is False


class _Register:
    def __init__(self, value):
        self.value = value

    def GetValueAsUnsigned(self):
        return self.value


class _IdentityThread:
    def __init__(self, thread_id):
        self.thread_id = thread_id

    def GetThreadID(self):
        return self.thread_id

    def GetProcess(self):
        return object()


class _IdentityFrame:
    def __init__(self, *, thread_id, x1, x0=0, x8=0, sp=0):
        self.thread = _IdentityThread(thread_id)
        self.registers = {
            "x0": _Register(x0),
            "x1": _Register(x1),
            "x8": _Register(x8),
            "sp": _Register(sp),
        }

    def GetThread(self):
        return self.thread

    def FindRegister(self, name):
        return self.registers[name]


def test_marker_and_downstream_events_require_one_transaction_identity(monkeypatch):
    monkeypatch.setattr(capture, "_tracked_thread_id", 11)
    monkeypatch.setattr(capture, "_tracked_model_pointer", 0x1234)
    monkeypatch.setattr(
        capture,
        "_tracked_insert_sret_pointer",
        0x5678,
        raising=False,
    )
    monkeypatch.setattr(capture, "_seen_labels", {"insert"})
    same = _IdentityFrame(thread_id=11, x1=0x1234)
    other_thread = _IdentityFrame(thread_id=12, x1=0x1234)
    other_model = _IdentityFrame(thread_id=11, x1=0x9999)
    monkeypatch.setattr(capture, "_marker_reachable", lambda _frame: True)
    monkeypatch.setattr(capture, "_mars_task_command", lambda _frame: 0x20A)

    assert capture._can_arm_from_marker("insert") is True
    assert capture._can_arm_from_marker("insert_return") is False
    assert capture._can_arm_from_marker("insert_result_check") is False
    assert capture._can_arm_from_marker("mars_submit") is False
    assert capture._can_arm_from_marker("update") is False
    assert capture._event_is_correlated(same, "insert_return") is True
    assert capture._event_is_correlated(same, "mars_submit") is True
    assert capture._event_is_correlated(same, "update") is False
    assert capture._event_is_correlated(other_thread, "insert_return") is False
    assert capture._event_is_correlated(other_thread, "mars_submit") is False
    assert capture._event_is_correlated(other_model, "update") is False
    capture._seen_labels.add("insert_return")
    assert capture._event_is_correlated(same, "insert_return") is False
    assert capture._event_is_correlated(same, "insert_result_check") is True
    capture._seen_labels.add("insert_result_check")
    assert capture._event_is_correlated(same, "insert_result_check") is False
    monkeypatch.setattr(capture, "_marker_reachable", lambda _frame: False)
    assert capture._event_is_correlated(same, "mars_submit") is False


def test_mars_submit_rejects_non_newsendmsg_tasks(monkeypatch):
    frame = _IdentityFrame(thread_id=11, x1=0x1234)
    monkeypatch.setattr(capture, "_tracked_thread_id", 11)
    monkeypatch.setattr(capture, "_seen_labels", {"insert"})
    monkeypatch.setattr(capture, "_marker_reachable", lambda _frame: True)
    monkeypatch.setattr(capture, "_mars_task_command", lambda _frame: 0x5595)

    assert capture._event_is_correlated(frame, "mars_submit") is False

    monkeypatch.setattr(capture, "_mars_task_command", lambda _frame: 0x20A)
    assert capture._event_is_correlated(frame, "mars_submit") is True
    capture._seen_labels.add("mars_submit")
    assert capture._event_is_correlated(frame, "mars_submit") is False


def test_insert_marker_tracks_model_and_sret_for_one_correlated_return(monkeypatch):
    frame = _IdentityFrame(thread_id=11, x1=0x1234, x8=0x5678)
    monkeypatch.setattr(capture, "_capture_deadline", 100.0)
    monkeypatch.setattr(capture.time, "monotonic", lambda: 1.0)
    monkeypatch.setattr(capture, "_breakpoint_labels", {7: "insert"})
    monkeypatch.setattr(capture, "_marker_seen", False)
    monkeypatch.setattr(capture, "_capture_error", False)
    monkeypatch.setattr(capture, "_tracked_thread_id", 0)
    monkeypatch.setattr(capture, "_tracked_model_pointer", 0)
    monkeypatch.setattr(
        capture,
        "_tracked_insert_sret_pointer",
        0,
        raising=False,
    )
    monkeypatch.setattr(capture, "_seen_labels", set())
    monkeypatch.setattr(capture, "_active_until", 10.0)
    monkeypatch.setattr(capture, "_marker_reachable", lambda _frame: True)
    monkeypatch.setattr(capture, "_snapshot", lambda *_args: True)

    assert capture.capture_breakpoint(
        frame, _BreakpointLocation(7), {}
    ) is False
    assert capture._marker_seen is True
    assert capture._tracked_thread_id == 11
    assert capture._tracked_model_pointer == 0x1234
    assert capture._tracked_insert_sret_pointer == 0x5678
    assert capture._seen_labels == {"insert"}


def test_insert_return_snapshot_uses_tracked_model_and_sret(monkeypatch):
    frame = _IdentityFrame(thread_id=11, x1=0, x8=0)
    monkeypatch.setattr(capture, "_tracked_model_pointer", 0x1234)
    monkeypatch.setattr(
        capture,
        "_tracked_insert_sret_pointer",
        0x5678,
        raising=False,
    )

    assert capture._semantic_region_addresses(frame, "insert_return") == {
        "model": 0x1234,
        "insert_sret": 0x5678,
    }


def test_insert_result_check_reads_the_normalized_result_from_x8(monkeypatch):
    frame = _IdentityFrame(thread_id=11, x1=0, x8=0x100009000)
    monkeypatch.setattr(capture, "_tracked_model_pointer", 0x1234)

    assert capture._semantic_region_addresses(frame, "insert_result_check") == {
        "model": 0x1234,
        "insert_result": 0x100009000,
    }


def test_invalid_marker_snapshot_cannot_arm_or_count_transaction(monkeypatch):
    frame = _IdentityFrame(thread_id=11, x1=0x1234)
    monkeypatch.setattr(capture, "_capture_deadline", 100.0)
    monkeypatch.setattr(capture.time, "monotonic", lambda: 1.0)
    monkeypatch.setattr(capture, "_breakpoint_labels", {7: "insert"})
    monkeypatch.setattr(capture, "_marker_seen", False)
    monkeypatch.setattr(capture, "_capture_error", False)
    monkeypatch.setattr(capture, "_seen_labels", set())
    monkeypatch.setattr(capture, "_marker_reachable", lambda _frame: True)
    monkeypatch.setattr(
        capture,
        "_snapshot",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("missing_regions")),
    )

    assert capture.capture_breakpoint(
        frame, _BreakpointLocation(7), {}
    ) is False
    assert capture._capture_error is True
    assert capture._marker_seen is False
    assert capture._seen_labels == set()


class _SnapshotProcess:
    def GetTarget(self):
        return object()


class _SnapshotThread:
    def __init__(self):
        self.process = _SnapshotProcess()

    def GetProcess(self):
        return self.process

    def GetNumFrames(self):
        return 0

    def GetThreadID(self):
        return 11

    def GetName(self):
        return "worker"

    def GetQueueName(self):
        return "queue"


class _SnapshotFrame:
    def __init__(self):
        self.thread = _SnapshotThread()

    def GetThread(self):
        return self.thread

    def FindRegister(self, name):
        index = 29 if name == "sp" else int(name[1:])
        return _Register(0x100001000 + index * 0x1000)


def test_snapshot_rejects_empty_backtrace(monkeypatch):
    image_base = 0x100000000
    rva, signature = capture._EXPECTED_PROBES["insert"]
    monkeypatch.setattr(capture, "_wechat_base", image_base)
    monkeypatch.setattr(
        capture,
        "_read",
        lambda _process, address, size: (
            bytes.fromhex(signature)
            if address == image_base + rva
            else b"x" * size
        ),
    )
    monkeypatch.setattr(capture, "_append_record", lambda _record: None)

    with pytest.raises(RuntimeError, match="empty_backtrace:insert"):
        capture._snapshot(_SnapshotFrame(), "insert", True)


class _RuntimeModule:
    def __init__(self, image_uuid):
        self.image_uuid = image_uuid

    def GetUUIDString(self):
        return self.image_uuid


class _RuntimeTarget:
    def __init__(self, triple):
        self.triple = triple

    def GetTriple(self):
        return self.triple


def test_runtime_image_requires_pinned_uuid_architecture_and_signatures(monkeypatch):
    image_base = 0x100000000
    signatures = {
        image_base + rva: bytes.fromhex(signature)
        for _label, (rva, signature) in capture._EXPECTED_PROBES.items()
    }
    monkeypatch.setattr(
        capture,
        "_read",
        lambda _process, address, _size: signatures.get(address),
    )
    target = _RuntimeTarget("arm64-apple-macosx")
    module = _RuntimeModule(capture.EXPECTED_IMAGE_UUID)

    capture._validate_runtime_image(target, object(), module, image_base)

    with pytest.raises(RuntimeError, match="unsupported_wechat_image_uuid"):
        capture._validate_runtime_image(
            target,
            object(),
            _RuntimeModule("00000000-0000-0000-0000-000000000000"),
            image_base,
        )

    with pytest.raises(RuntimeError, match="unsupported_wechat_architecture"):
        capture._validate_runtime_image(
            _RuntimeTarget("x86_64-apple-macosx"),
            object(),
            module,
            image_base,
        )

    signatures[image_base + 0x26E620C] = b"\0" * 16
    with pytest.raises(RuntimeError, match="signature_mismatch:insert"):
        capture._validate_runtime_image(target, object(), module, image_base)


class _CommandReturn:
    def Succeeded(self):
        return True


class _CallbackError:
    def Fail(self):
        return True

    def GetCString(self):
        return "callback rejected"


class _CallbackBreakpoint:
    def GetID(self):
        return 42

    def SetScriptCallbackFunction(self, _callback):
        return _CallbackError()


class _InstallTarget:
    def __init__(self):
        self.breakpoint_count = 0

    def GetProcess(self):
        return object()

    def GetNumBreakpoints(self):
        return self.breakpoint_count

    def GetBreakpointAtIndex(self, _index):
        return _CallbackBreakpoint()


class _InstallInterpreter:
    def __init__(self, target):
        self.target = target

    def HandleCommand(self, _command, _result):
        self.target.breakpoint_count += 1


class _InstallDebugger:
    def __init__(self, target):
        self.interpreter = _InstallInterpreter(target)

    def GetCommandInterpreter(self):
        return self.interpreter


def test_partial_breakpoint_install_is_tracked_before_callback_setup(monkeypatch):
    target = _InstallTarget()
    monkeypatch.setattr(capture, "_installed_breakpoint_ids", set())
    monkeypatch.setattr(
        capture,
        "_find_wechat_module",
        lambda _target: (object(), 0x100000000),
    )
    monkeypatch.setattr(capture, "_validate_runtime_image", lambda *_args: None)
    monkeypatch.setitem(
        sys.modules,
        "lldb",
        SimpleNamespace(SBCommandReturnObject=_CommandReturn),
    )

    with pytest.raises(RuntimeError, match="breakpoint_callback:insert_failed"):
        capture._install_breakpoints(_InstallDebugger(target), target)

    assert capture._installed_breakpoint_ids == {42}


class _CancelableTimer:
    def __init__(self):
        self.cancelled = False

    def cancel(self):
        self.cancelled = True


class _FinishProcess:
    def __init__(self):
        self.continues = 0
        self.detaches = 0

    def GetProcessID(self):
        return 321

    def Continue(self):
        self.continues += 1
        return None

    def Detach(self):
        self.detaches += 1
        return None


class _FinishTarget:
    def __init__(self):
        self.process = _FinishProcess()
        self.deleted = []

    def GetProcess(self):
        return self.process

    def BreakpointDelete(self, breakpoint_id):
        self.deleted.append(breakpoint_id)
        return True


class _FinishDebugger:
    def __init__(self, target):
        self.target = target
        self.async_mode = True
        self.async_updates = []

    def GetSelectedTarget(self):
        return self.target

    def GetAsync(self):
        return self.async_mode

    def SetAsync(self, value):
        self.async_updates.append(value)
        self.async_mode = value


def test_owned_lifecycle_finalizes_and_detaches_after_setup_failure(monkeypatch):
    target = _FinishTarget()
    finalized = []
    monkeypatch.setattr(
        capture,
        "_install_breakpoints",
        lambda _debugger, _target: (_ for _ in ()).throw(
            RuntimeError("breakpoint_setup_failed")
        ),
    )
    monkeypatch.setattr(
        capture,
        "_finalize_capture",
        lambda _target, _process, *, force_error: finalized.append(force_error),
    )

    problems = capture._run_capture_lifecycle(object(), target, target.process)

    assert problems == ["breakpoint_setup_failed"]
    assert finalized == [True]
    assert target.process.continues == 0
    assert target.process.detaches == 1


def test_repeated_capture_refuses_before_truncating_output(monkeypatch, tmp_path):
    output = tmp_path / "events.jsonl"
    output.write_text("existing", encoding="utf-8")
    monkeypatch.setattr(capture, "_capture_active", True)

    with pytest.raises(RuntimeError, match="capture_already_active"):
        capture._initialize_capture_state(b"marker", output)

    assert output.read_text(encoding="utf-8") == "existing"


def test_owned_lifecycle_announces_ready_before_synchronous_continue(monkeypatch):
    target = _FinishTarget()
    debugger = _FinishDebugger(target)
    events = []
    monkeypatch.setattr(
        capture,
        "_install_breakpoints",
        lambda _debugger, _target: events.append("installed"),
    )
    monkeypatch.setattr(
        capture,
        "_schedule_interrupt",
        lambda _process: events.append("scheduled") or _CancelableTimer(),
    )
    monkeypatch.setattr(
        target.process,
        "Continue",
        lambda: events.append("continued"),
    )
    monkeypatch.setattr(
        capture,
        "_finalize_capture",
        lambda _target, _process, *, force_error: events.append("finalized"),
    )
    monkeypatch.setattr(
        target.process,
        "Detach",
        lambda: events.append("detached"),
    )

    problems = capture._run_capture_lifecycle(
        debugger,
        target,
        target.process,
        on_ready=lambda: events.append("ready"),
    )

    assert problems == []
    assert events == [
        "installed",
        "scheduled",
        "ready",
        "continued",
        "finalized",
        "detached",
    ]
    assert debugger.async_updates == [False, True]


def test_run_command_detaches_before_reporting_setup_error(monkeypatch):
    target = _FinishTarget()
    debugger = _FinishDebugger(target)
    result = _CaptureResult()
    monkeypatch.setattr(capture, "_capture_active", False)

    capture.run_capture(debugger, "invalid", result, {})

    assert target.process.detaches == 1
    assert result.error == "usage: wechat-profile-run MARKER_BASE64 OUTPUT"


def test_finish_capture_cleans_up_and_writes_complete_terminal(
    monkeypatch, tmp_path
):
    output = tmp_path / "events.jsonl"
    timer = _CancelableTimer()
    target = _FinishTarget()
    capture._prepare_output(output)
    monkeypatch.setattr(capture, "_output_path", str(output))
    monkeypatch.setattr(capture, "_capture_started_at", 10.0)
    monkeypatch.setattr(capture, "_capture_error", False)
    monkeypatch.setattr(capture, "_marker_seen", True)
    monkeypatch.setattr(
        capture,
        "_seen_labels",
        {"insert", "insert_return", "insert_result_check", "mars_submit"},
    )
    monkeypatch.setattr(capture, "_installed_breakpoint_ids", {8, 4})
    monkeypatch.setattr(capture, "_timeout_timer", timer)
    monkeypatch.setattr(capture, "_terminal_written", False)
    monkeypatch.setattr(capture.time, "monotonic", lambda: 10.25)

    status = capture._finalize_capture(
        target,
        target.process,
        force_error=False,
    )

    assert timer.cancelled is True
    assert target.deleted == [4, 8]
    assert status == "complete"
    assert output.read_text(encoding="utf-8") == (
        '{"label":"capture_terminal","status":"complete",'
        '"missing_labels":[],"pid":321,"duration_ms":250}\n'
    )


def test_main_executes_arguments_from_safe_builder(monkeypatch, tmp_path):
    expected = ["lldb", "--safe-test-arguments"]
    observed = {}
    monkeypatch.setattr(capture, "build_lldb_arguments", lambda **_kwargs: expected)

    def fake_execvp(executable, arguments):
        observed["executable"] = executable
        observed["arguments"] = arguments

    monkeypatch.setattr(capture.os, "execvp", fake_execvp)

    capture.main(
        [
            "--pid",
            "123",
            "--marker",
            "WCPROFILE-20260802-01",
            "--output",
            str(tmp_path / "events.jsonl"),
        ]
    )

    assert observed == {"executable": "lldb", "arguments": expected}


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"pid": 1}, "invalid_pid"),
        ({"marker": ""}, "invalid_marker"),
        ({"output": "events.jsonl"}, "output_must_be_absolute"),
    ],
)
def test_lldb_arguments_reject_unsafe_inputs(tmp_path, kwargs, message):
    arguments = {
        "pid": 123,
        "marker": "WCPROFILE-20260802-01",
        "output": tmp_path / "events.jsonl",
    }
    arguments.update(kwargs)

    with pytest.raises(ValueError, match=message):
        capture.build_lldb_arguments(**arguments)
