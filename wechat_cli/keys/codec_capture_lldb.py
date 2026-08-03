"""LLDB callback used by scanner_macos to capture transient codec keys."""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import shlex
import struct
import threading
import time

import lldb


STATE = {
    "initialized": False,
    "target_db": None,
    "target_rel": None,
    "output": None,
    "report": None,
    "page": None,
    "started_at": None,
    "timed_out": False,
    "events": 0,
    "candidate_pairs": 0,
    "matched": False,
    "breakpoint_locations": 0,
}


def _write_report():
    if not STATE["report"]:
        return
    payload = {
        "schema_version": 1,
        "mode": "transient_sqlcipher_codec_key_capture",
        "target_rel": STATE["target_rel"],
        "events": STATE["events"],
        "candidate_pairs": STATE["candidate_pairs"],
        "matched": STATE["matched"],
        "timed_out": STATE["timed_out"],
        "breakpoint_locations": STATE["breakpoint_locations"],
        "elapsed_seconds": round(time.time() - STATE["started_at"], 3),
    }
    temporary = STATE["report"] + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, indent=2)
        handle.write("\n")
    os.replace(temporary, STATE["report"])


def _read_memory(process, address, size):
    error = lldb.SBError()
    value = process.ReadMemory(address, size, error)
    if not error.Success() or len(value) != size:
        return None
    return bytes(value)


def _matches_target_page(process, frame):
    page_number = frame.FindRegister("w2").GetValueAsUnsigned()
    input_address = frame.FindRegister("x5").GetValueAsUnsigned()
    if not page_number or not input_address:
        return False
    live = _read_memory(process, input_address, 64)
    offset = (page_number - 1) * 4096 + (16 if page_number == 1 else 0)
    try:
        with open(STATE["target_db"], "rb") as handle:
            handle.seek(offset)
            expected = handle.read(64)
    except OSError:
        return False
    return len(expected) == 64 and live == expected


def _valid_pair(encryption_key, hmac_key):
    page = STATE["page"]
    hmac_start = 4096 - 64
    authenticated = page[16:hmac_start] + struct.pack("<I", 1)
    actual = hmac.new(hmac_key, authenticated, hashlib.sha512).digest()
    if not hmac.compare_digest(actual, page[hmac_start:4096]):
        return False

    iv_start = 4096 - 80
    ciphertext = page[16:iv_start]
    output = ctypes.create_string_buffer(len(ciphertext))
    moved = ctypes.c_size_t()
    crypt = ctypes.CDLL("/usr/lib/libSystem.B.dylib").CCCrypt
    crypt.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    crypt.restype = ctypes.c_int32
    status = crypt(
        1, 0, 0, encryption_key, len(encryption_key), page[iv_start:iv_start + 16],
        ciphertext, len(ciphertext), output, len(ciphertext), ctypes.byref(moved),
    )
    if status != 0 or moved.value != len(ciphertext):
        return False
    header = output.raw[:8]
    return (
        int.from_bytes(header[:2], "big") == 4096
        and header[2] in (1, 2)
        and header[3] in (1, 2)
        and header[4:] == b"\x50\x40\x20\x20"
    )


def _write_pair(encryption_key, hmac_key):
    payload = {
        STATE["target_rel"]: {
            "key_type": "sqlcipher_derived_pair",
            "derived_encryption_key": encryption_key.hex(),
            "derived_hmac_key": hmac_key.hex(),
            "salt": STATE["page"][:16].hex(),
            "page_size": 4096,
            "reserve_size": 80,
            "hmac_algorithm": "sha512",
        }
    }
    descriptor = os.open(
        STATE["output"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    try:
        os.write(descriptor, (json.dumps(payload, indent=2) + "\n").encode())
    finally:
        os.close(descriptor)


def capture_callback(frame, _location, _internal_dict):
    if not STATE["initialized"] or STATE["matched"]:
        return False
    STATE["events"] += 1
    process = frame.GetThread().GetProcess()
    context = frame.FindRegister("x19").GetValueAsUnsigned()
    key_context = frame.FindRegister("x26").GetValueAsUnsigned()
    length_bytes = _read_memory(process, context + 0x10, 4)
    pointers = _read_memory(process, key_context + 0x8, 16)
    if length_bytes is None or pointers is None:
        return False
    length = struct.unpack("<I", length_bytes)[0]
    encryption_address, hmac_address = struct.unpack("<QQ", pointers)
    if length != 32 or not encryption_address or not hmac_address:
        return False
    encryption_key = _read_memory(process, encryption_address, length)
    hmac_key = _read_memory(process, hmac_address, length)
    if encryption_key is None or hmac_key is None:
        return False
    STATE["candidate_pairs"] += 1
    if not _matches_target_page(process, frame):
        return False
    if not _valid_pair(encryption_key, hmac_key):
        return False
    _write_pair(encryption_key, hmac_key)
    STATE["matched"] = True
    _write_report()
    process.SendAsyncInterrupt()
    return True


def _timeout(process, seconds):
    time.sleep(seconds)
    if not STATE["matched"] and process.IsValid():
        STATE["timed_out"] = True
        _write_report()
        process.SendAsyncInterrupt()


def initialize_command(debugger, command, result, _internal_dict):
    arguments = shlex.split(command)
    if len(arguments) != 6:
        result.SetError(
            "usage: wechat-codec-key-init OFFSET DB REL OUTPUT REPORT TIMEOUT"
        )
        return
    offset_text, target_db, target_rel, output, report, timeout_text = arguments
    try:
        offset = int(offset_text, 0)
        timeout = float(timeout_text)
        with open(target_db, "rb") as handle:
            page = handle.read(4096)
        if len(page) != 4096:
            raise ValueError("target database page is shorter than 4096 bytes")
        if os.path.exists(output):
            raise FileExistsError(output)
    except (OSError, ValueError) as error:
        result.SetError(str(error))
        return

    target = debugger.GetSelectedTarget()
    modules = [
        item for item in target.module_iter()
        if item.GetFileSpec().GetFilename() == "wechat.dylib"
    ]
    module = next(
        (item for item in modules
         if item.GetFileSpec().GetDirectory().endswith("/Contents/Resources")),
        modules[0] if modules else None,
    )
    if module is None:
        result.SetError("wechat.dylib is not loaded")
        return
    base = module.GetObjectFileHeaderAddress().GetLoadAddress(target)
    breakpoint = target.BreakpointCreateByAddress(base + offset)
    breakpoint.SetScriptCallbackFunction(__name__ + ".capture_callback")
    breakpoint.SetAutoContinue(True)
    STATE.update({
        "initialized": True,
        "target_db": target_db,
        "target_rel": target_rel,
        "output": output,
        "report": report,
        "page": page,
        "started_at": time.time(),
        "timed_out": False,
        "events": 0,
        "candidate_pairs": 0,
        "matched": False,
        "breakpoint_locations": breakpoint.GetNumLocations(),
    })
    _write_report()
    threading.Thread(
        target=_timeout, args=(target.GetProcess(), timeout), daemon=True
    ).start()
    result.AppendMessage("Transient codec key capture armed")


def report_command(_debugger, _command, result, _internal_dict):
    _write_report()
    result.AppendMessage(
        "events={} pairs={} matched={} timed_out={}".format(
            STATE["events"], STATE["candidate_pairs"],
            STATE["matched"], STATE["timed_out"]
        )
    )


def __lldb_init_module(debugger, _internal_dict):
    debugger.HandleCommand(
        "command script add -f {}.initialize_command wechat-codec-key-init".format(
            __name__
        )
    )
    debugger.HandleCommand(
        "command script add -f {}.report_command wechat-codec-key-report".format(
            __name__
        )
    )
