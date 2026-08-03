#!/usr/bin/env python3
"""Read-only LLDB capture for one user-performed WeChat marker send.

Run normally to attach LLDB. The imported command uses hardware breakpoints,
records candidate calls, and auto-continues. It never calls a WeChat function.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shlex
import stat
import struct
import threading
import time


ACTIVE_WINDOW_SECONDS = 20.0
CAPTURE_TIMEOUT_SECONDS = 120.0
_SNAPSHOT_POINTER_REGISTERS = (
    "x0",
    "x1",
    "x2",
    "x3",
    "x8",
    "x9",
    "x19",
    "x20",
    "x29",
    "sp",
)
_REQUIRED_CAPTURE_LABELS = frozenset(
    ("insert", "insert_return", "insert_result_check", "mars_submit")
)
EXPECTED_IMAGE_UUID = "ABD88EC8-4590-3FDB-AAB5-4E5865B86B2A"
_EXPECTED_PROBES = {
    "insert": (0x26E620C, "e93c0390294942f9490000b420011fd6"),
    "insert_return": (0x253B85C, "e8e30091e0030b91a14303d15f020094"),
    "insert_result_check": (
        0x253B904,
        "09cd40b9692b0034890240f9f43f41f9",
    ),
    "mars_submit": (0x498D2E0, "ff0305d1fc6f11a9f44f12a9fd7b13a9"),
}


@dataclass(frozen=True)
class Probe:
    label: str
    rva: int


@dataclass(frozen=True)
class ProbePhase:
    name: str
    probes: tuple[Probe, ...]


def build_probe_phases():
    return (
        ProbePhase(
            "message_transaction",
            tuple(
                Probe(label, rva)
                for label, (rva, _signature) in _EXPECTED_PROBES.items()
            ),
        ),
    )


def _probe_rvas():
    return {
        probe.label: probe.rva
        for phase in build_probe_phases()
        for probe in phase.probes
    }


def _unresolved_probe_labels():
    return sorted(label for label, rva in _probe_rvas().items() if rva == 0)


def build_lldb_arguments(*, pid, marker, output):
    if type(pid) is not int or pid <= 1:
        raise ValueError("invalid_pid")
    if not isinstance(marker, str):
        raise ValueError("invalid_marker")
    marker_bytes = marker.encode("utf-8")
    if not marker_bytes or len(marker_bytes) > 256:
        raise ValueError("invalid_marker")
    output = Path(output)
    if not output.is_absolute():
        raise ValueError("output_must_be_absolute")

    marker_base64 = base64.b64encode(marker_bytes).decode("ascii")
    script = Path(__file__).resolve()
    start_command = " ".join(
        (
            "wechat-profile-run",
            marker_base64,
            shlex.quote(str(output)),
        )
    )
    return [
        "lldb",
        "--no-lldbinit",
        "--batch",
        "-p",
        str(pid),
        "-o",
        f"command script import {shlex.quote(str(script))}",
        "-o",
        start_command,
    ]

_marker = b""
_output_path = ""
_wechat_base = 0
_active_until = 0.0
_breakpoint_labels = {}
_installed_breakpoint_ids = set()
_seen_labels = set()
_marker_seen = False
_capture_error = False
_capture_started_at = 0.0
_capture_deadline = 0.0
_timeout_timer = None
_tracked_thread_id = 0
_tracked_model_pointer = 0
_tracked_insert_sret_pointer = 0
_terminal_written = False
_capture_active = False


def _open_capture_output(path, flags):
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(os.fspath(path), flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise OSError("unsafe_capture_output")
        os.fchmod(descriptor, 0o600)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _prepare_output(path):
    descriptor = _open_capture_output(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
    )
    os.close(descriptor)


def _append_record(record):
    descriptor = _open_capture_output(_output_path, os.O_WRONLY | os.O_APPEND)
    with os.fdopen(descriptor, "a", encoding="utf-8") as output:
        output.write(json.dumps(record, separators=(",", ":")) + "\n")


def _command_output_path(value):
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError("output_must_be_absolute")
    return path


def _read(process, address, size):
    if not address:
        return None
    import lldb

    error = lldb.SBError()
    data = process.ReadMemory(address, size, error)
    return bytes(data) if error.Success() else None


def _register(frame, name):
    return frame.FindRegister(name).GetValueAsUnsigned()


def _semantic_region_addresses(frame, label):
    if label == "insert_return":
        return {
            "model": _tracked_model_pointer,
            "insert_sret": _tracked_insert_sret_pointer,
        }
    if label == "insert_result_check":
        result = _register(frame, "x8")
        if not 0x100000000 <= result < 0x800000000000:
            result = 0
        return {
            "model": _tracked_model_pointer,
            "insert_result": result,
        }
    return {}


def _mars_task_command(frame):
    task = _register(frame, "x1")
    raw_command = _read(frame.GetThread().GetProcess(), task + 4, 4)
    return struct.unpack("<I", raw_command)[0] if raw_command else 0


def _marker_reachable(frame):
    process = frame.GetThread().GetProcess()
    roots = [_register(frame, f"x{index}") for index in range(29)]
    roots.append(_register(frame, "sp"))
    pending = [(address, 0) for address in roots if address]
    visited = set()
    while pending and len(visited) < 768:
        if _capture_deadline and time.monotonic() >= _capture_deadline:
            return False
        address, depth = pending.pop(0)
        if address in visited or not 0x100000000 <= address < 0x800000000000:
            continue
        visited.add(address)
        data = _read(process, address, 0x800)
        if data is None:
            continue
        if _marker in data:
            return True
        if depth >= 4:
            continue
        for offset in range(0, min(len(data), 0x500) - 7, 8):
            pointer = struct.unpack_from("<Q", data, offset)[0]
            if 0x100000000 <= pointer < 0x800000000000:
                pending.append((pointer, depth + 1))
    return False


def _snapshot(frame, label, marker_reachable):
    process = frame.GetThread().GetProcess()
    target = process.GetTarget()
    thread = frame.GetThread()
    rva = _probe_rvas()[label]
    signature = _read(process, _wechat_base + rva, 16)
    expected_signature = bytes.fromhex(_EXPECTED_PROBES[label][1])
    if signature != expected_signature:
        raise RuntimeError(f"signature_mismatch:{label}")
    registers = {
        f"x{index}": hex(_register(frame, f"x{index}"))
        for index in range(30)
    }
    registers["sp"] = hex(_register(frame, "sp"))
    region_addresses = {
        name: int(registers[name], 16)
        for name in _SNAPSHOT_POINTER_REGISTERS
    }
    region_addresses.update(_semantic_region_addresses(frame, label))
    regions = {}
    for name, address in region_addresses.items():
        data = _read(process, address, 0x600)
        if data is not None:
            regions[name] = data.hex()
    required_regions = {
        "insert": {"x0", "x1", "x8"},
        "insert_return": {"model", "insert_sret"},
        "insert_result_check": {
            "model",
            "insert_result",
        },
        "mars_submit": {"x0", "x1"},
    }[label]
    missing_regions = sorted(required_regions - regions.keys())
    if missing_regions:
        raise RuntimeError(
            f"missing_regions:{label}:" + ",".join(missing_regions)
        )
    backtrace = []
    for index in range(min(thread.GetNumFrames(), 64)):
        current = thread.GetFrameAtIndex(index)
        address = current.GetPCAddress().GetLoadAddress(target)
        module = current.GetModule().GetFileSpec().GetFilename()
        backtrace.append(
            {
                "pc": hex(address),
                "rva": hex(address - _wechat_base)
                if module == "wechat.dylib"
                else None,
                "module": module,
                "function": current.GetFunctionName(),
            }
        )
    if not backtrace:
        raise RuntimeError(f"empty_backtrace:{label}")
    record = {
        "label": label,
        "edge": "entry" if label in ("insert", "mars_submit") else "return",
        "time": time.time(),
        "rva": hex(rva),
        "signature": signature.hex(),
        "marker_reachable": marker_reachable,
        "thread_id": thread.GetThreadID(),
        "thread_name": thread.GetName(),
        "queue_name": thread.GetQueueName(),
        "registers": registers,
        "regions": regions,
        "backtrace": backtrace,
    }
    _append_record(record)
    return True


def _can_arm_from_marker(label):
    return label == "insert"


def _model_pointer(frame, label):
    if label == "insert":
        return _register(frame, "x1")
    return 0


def _event_is_correlated(frame, label):
    thread_id = frame.GetThread().GetThreadID()
    if label == "insert_return":
        return (
            thread_id == _tracked_thread_id
            and bool(_tracked_insert_sret_pointer)
            and "insert_return" not in _seen_labels
        )
    if label == "insert_result_check":
        return (
            thread_id == _tracked_thread_id
            and "insert_return" in _seen_labels
            and "insert_result_check" not in _seen_labels
        )
    if label == "mars_submit":
        return (
            thread_id == _tracked_thread_id
            and "mars_submit" not in _seen_labels
            and _mars_task_command(frame) == 0x20A
            and _marker_reachable(frame)
        )
    if label == "insert":
        return _model_pointer(frame, label) == _tracked_model_pointer
    return False


def _record_seen_label(label):
    _seen_labels.add(label)


def capture_breakpoint(frame, breakpoint_location, _internal_dict):
    global _active_until, _capture_error, _marker_seen
    global _tracked_insert_sret_pointer
    global _tracked_model_pointer, _tracked_thread_id
    if _capture_deadline and time.monotonic() >= _capture_deadline:
        return True
    try:
        breakpoint_id = breakpoint_location.GetBreakpoint().GetID()
        label = _breakpoint_labels.get(breakpoint_id)
        if label is None:
            return False
        now = time.monotonic()
        if not _marker_seen:
            if not _can_arm_from_marker(label) or not _marker_reachable(frame):
                return time.monotonic() >= _capture_deadline
            thread_id = frame.GetThread().GetThreadID()
            model_pointer = _model_pointer(frame, label)
            if not thread_id or not model_pointer:
                raise RuntimeError("invalid_marker_identity")
            _snapshot(frame, label, True)
            _tracked_thread_id = thread_id
            _tracked_model_pointer = model_pointer
            _marker_seen = True
            _active_until = min(
                now + ACTIVE_WINDOW_SECONDS,
                _capture_deadline,
            )
            if label == "insert":
                _tracked_insert_sret_pointer = _register(frame, "x8")
            _record_seen_label(label)
        elif now <= _active_until and _event_is_correlated(frame, label):
            _snapshot(frame, label, False)
            if label == "insert":
                _tracked_insert_sret_pointer = _register(frame, "x8")
            _record_seen_label(label)
    except Exception:
        _capture_error = True
    return bool(_capture_deadline and time.monotonic() >= _capture_deadline)


def _find_wechat_module(target):
    for module in target.module_iter():
        if module.GetFileSpec().GetFilename() != "wechat.dylib":
            continue
        address = module.GetObjectFileHeaderAddress().GetLoadAddress(target)
        if address not in (0, -1):
            return module, address
    return None, 0


def _validate_runtime_image(target, process, module, image_base):
    if module.GetUUIDString().upper() != EXPECTED_IMAGE_UUID:
        raise RuntimeError("unsupported_wechat_image_uuid")
    architecture = target.GetTriple().split("-", 1)[0]
    if architecture != "arm64":
        raise RuntimeError("unsupported_wechat_architecture")
    for label, (rva, signature) in _EXPECTED_PROBES.items():
        if _read(process, image_base + rva, 16) != bytes.fromhex(signature):
            raise RuntimeError(f"signature_mismatch:{label}")


def _interrupt_process(process):
    global _capture_error
    try:
        interrupted = process.SendAsyncInterrupt()
        if interrupted is False:
            process.Stop()
    except Exception:
        try:
            process.Stop()
        except Exception:
            _capture_error = True


def _schedule_interrupt(process):
    remaining = _capture_deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("capture_deadline_expired")
    timer = threading.Timer(
        remaining,
        _interrupt_process,
        args=(process,),
    )
    timer.daemon = True
    timer.start()
    return timer


def _delete_installed_breakpoints(target):
    problems = []
    try:
        for breakpoint_id in sorted(_installed_breakpoint_ids):
            try:
                if target.BreakpointDelete(breakpoint_id) is False:
                    problems.append(f"breakpoint_delete_failed:{breakpoint_id}")
            except Exception:
                problems.append(f"breakpoint_delete_failed:{breakpoint_id}")
    finally:
        _installed_breakpoint_ids.clear()
        _breakpoint_labels.clear()
    return problems


def _cancel_timeout():
    global _timeout_timer
    timer = _timeout_timer
    _timeout_timer = None
    if timer is None:
        return []
    problems = []
    try:
        timer.cancel()
        join = getattr(timer, "join", None)
        if join is not None and timer is not threading.current_thread():
            join(timeout=1.0)
    except Exception:
        problems.append("timeout_cleanup_failed")
    return problems


def _sb_error_message(error, operation):
    if error is None:
        return None
    fail = getattr(error, "Fail", None)
    if fail is None or not fail():
        return None
    get_message = getattr(error, "GetCString", None)
    message = get_message() if get_message is not None else None
    return f"{operation}_failed" + (f":{message}" if message else "")


def _install_breakpoints(debugger, target):
    global _wechat_base
    process = target.GetProcess()
    module, image_base = _find_wechat_module(target)
    if module is None or not image_base:
        raise RuntimeError("wechat.dylib_not_loaded")
    _validate_runtime_image(target, process, module, image_base)
    _wechat_base = image_base
    probes = _probe_rvas()
    if len(probes) > 4:
        raise RuntimeError("too_many_hardware_breakpoints")
    callback = f"{__name__}.capture_breakpoint"
    import lldb

    interpreter = debugger.GetCommandInterpreter()
    for label, rva in probes.items():
        before = target.GetNumBreakpoints()
        command_result = lldb.SBCommandReturnObject()
        interpreter.HandleCommand(
            f"breakpoint set --hardware --address {image_base + rva:#x}",
            command_result,
        )
        if not command_result.Succeeded() or target.GetNumBreakpoints() != before + 1:
            raise RuntimeError(f"hardware_breakpoint_unavailable:{label}")
        breakpoint = target.GetBreakpointAtIndex(before)
        _installed_breakpoint_ids.add(breakpoint.GetID())
        callback_error = breakpoint.SetScriptCallbackFunction(callback)
        callback_problem = _sb_error_message(
            callback_error,
            f"breakpoint_callback:{label}",
        )
        if callback_problem:
            raise RuntimeError(callback_problem)
        _breakpoint_labels[breakpoint.GetID()] = label


def _finalize_capture(target, process, *, force_error):
    global _capture_error, _terminal_written
    cleanup_problems = _cancel_timeout()
    cleanup_problems.extend(_delete_installed_breakpoints(target))
    if cleanup_problems:
        _capture_error = True
    missing = sorted(_REQUIRED_CAPTURE_LABELS - _seen_labels)
    if force_error or _capture_error:
        status = "error"
    elif _marker_seen and not missing:
        status = "complete"
    else:
        status = "incomplete"
    if _terminal_written:
        return status
    duration_ms = max(0, int((time.monotonic() - _capture_started_at) * 1000))
    terminal = {
        "label": "capture_terminal",
        "status": status,
        "missing_labels": missing,
        "pid": process.GetProcessID(),
        "duration_ms": duration_ms,
    }
    _append_record(terminal)
    _terminal_written = True
    return status


def _run_capture_lifecycle(debugger, target, process, *, on_ready=None):
    global _capture_active, _timeout_timer
    problems = []
    previous_async = None
    try:
        get_async = getattr(debugger, "GetAsync", None)
        set_async = getattr(debugger, "SetAsync", None)
        if get_async is not None and set_async is not None:
            previous_async = get_async()
            set_async(False)
        _install_breakpoints(debugger, target)
        _timeout_timer = _schedule_interrupt(process)
        if on_ready is not None:
            on_ready()
        continue_problem = _sb_error_message(process.Continue(), "continue")
        if continue_problem:
            problems.append(continue_problem)
    except Exception as error:
        problems.append(str(error) or type(error).__name__)
    finally:
        try:
            _finalize_capture(target, process, force_error=bool(problems))
        except Exception as error:
            problems.append(f"finalize_failed:{error}")
        try:
            detach_problem = _sb_error_message(process.Detach(), "detach")
            if detach_problem:
                problems.append(detach_problem)
        except Exception as error:
            problems.append(f"detach_failed:{error}")
        if previous_async is not None:
            try:
                debugger.SetAsync(previous_async)
            except Exception as error:
                problems.append(f"async_restore_failed:{error}")
        _capture_active = False
    return problems


def _initialize_capture_state(marker, output_path):
    global _marker, _output_path, _active_until, _capture_active
    global _capture_deadline, _capture_error, _capture_started_at
    global _marker_seen, _terminal_written, _tracked_model_pointer
    global _tracked_insert_sret_pointer, _tracked_thread_id
    if _capture_active:
        raise RuntimeError("capture_already_active")
    _prepare_output(output_path)
    now = time.monotonic()
    _marker = marker
    _output_path = str(output_path)
    _active_until = 0.0
    _capture_deadline = now + CAPTURE_TIMEOUT_SECONDS
    _capture_error = False
    _capture_started_at = now
    _marker_seen = False
    _terminal_written = False
    _tracked_model_pointer = 0
    _tracked_insert_sret_pointer = 0
    _tracked_thread_id = 0
    _seen_labels.clear()
    _breakpoint_labels.clear()
    _installed_breakpoint_ids.clear()
    _capture_active = True


def _detach_after_command_error(process):
    try:
        return _sb_error_message(process.Detach(), "detach")
    except Exception as error:
        return f"detach_failed:{error}"


def run_capture(debugger, command, result, _internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    try:
        parts = shlex.split(command)
        if len(parts) != 2:
            raise ValueError("usage: wechat-profile-run MARKER_BASE64 OUTPUT")
        marker = base64.b64decode(parts[0], validate=True)
        if not marker or len(marker) > 256:
            raise ValueError("marker_must_be_1_to_256_bytes")
        unresolved = _unresolved_probe_labels()
        if unresolved:
            raise RuntimeError("unresolved_probe_rvas:" + ",".join(unresolved))
        output_path = _command_output_path(parts[1])
        _initialize_capture_state(marker, output_path)
    except Exception as error:
        problem = str(error) or type(error).__name__
        detach_problem = _detach_after_command_error(process)
        if detach_problem:
            problem += f";{detach_problem}"
        result.SetError(problem)
        return
    problems = _run_capture_lifecycle(
        debugger,
        target,
        process,
        on_ready=lambda: print(
            f"wechat_profile_ready base={_wechat_base:#x} output={_output_path}",
            flush=True,
        ),
    )
    if problems:
        result.SetError(";".join(problems))
        return
    missing = sorted(_REQUIRED_CAPTURE_LABELS - _seen_labels)
    status = "complete" if _marker_seen and not missing else "incomplete"
    result.AppendMessage(f"capture_{status}")


def __lldb_init_module(debugger, _internal_dict):
    debugger.HandleCommand(
        f"command script add -f {__name__}.run_capture wechat-profile-run"
    )


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--marker", required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/tmp/wechat-local-store-events.jsonl"),
    )
    args = parser.parse_args(argv)
    lldb_args = build_lldb_arguments(
        pid=args.pid,
        marker=args.marker,
        output=args.output.resolve(),
    )
    os.execvp(lldb_args[0], lldb_args)


if __name__ == "__main__":
    main()
