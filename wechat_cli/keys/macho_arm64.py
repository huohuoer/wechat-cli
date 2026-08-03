"""Small Mach-O helper for locating WeChat's arm64 SQLCipher codec hook."""

from __future__ import annotations

import struct


CPU_TYPE_ARM64 = 0x0100000C
FAT_MAGIC = b"\xca\xfe\xba\xbe"
FAT_MAGIC_64 = b"\xca\xfe\xba\xbf"
MH_MAGIC_64 = b"\xcf\xfa\xed\xfe"
LC_SEGMENT_64 = 0x19

# Stack offsets may change between builds. The remaining register flow is the
# stable part of the page-codec routine that exposes both derived key pointers.
_CAPTURE_PATTERN = (
    (0xB90003E2, 0xFFC003FF),  # str w2, [sp, #imm]
    (0xAD000BE3, 0xFFC07FFF),  # stp q3, q2, [sp, #imm]
    (0xAA1503E9, 0xFFFFFFFF),  # mov x9, x21
    (0x93407D29, 0xFFFFFFFF),  # sxtw x9, w9
    (0xCB080139, 0xFFFFFFFF),  # sub x25, x9, x8
    (0x8B19029B, 0xFFFFFFFF),  # add x27, x20, x25
    (0x8B0F0368, 0xFFFFFFFF),  # add x8, x27, x15
)


def _arm64_slice(data: bytes) -> bytes:
    if data[:4] == MH_MAGIC_64:
        if len(data) < 12 or struct.unpack_from("<i", data, 4)[0] != CPU_TYPE_ARM64:
            raise ValueError("Mach-O image is not arm64")
        return data

    if data[:4] not in (FAT_MAGIC, FAT_MAGIC_64):
        raise ValueError("unsupported Mach-O format")
    is_64 = data[:4] == FAT_MAGIC_64
    arch_size = 32 if is_64 else 20
    count = struct.unpack_from(">I", data, 4)[0]
    cursor = 8
    for _ in range(count):
        if cursor + arch_size > len(data):
            raise ValueError("truncated universal Mach-O header")
        cpu_type = struct.unpack_from(">i", data, cursor)[0]
        if is_64:
            offset, size = struct.unpack_from(">QQ", data, cursor + 8)
        else:
            offset, size = struct.unpack_from(">II", data, cursor + 8)
        if cpu_type == CPU_TYPE_ARM64:
            end = offset + size
            if end > len(data):
                raise ValueError("truncated arm64 Mach-O slice")
            return data[offset:end]
        cursor += arch_size
    raise ValueError("universal Mach-O has no arm64 slice")


def _text_section(data: bytes) -> tuple[int, int, int]:
    if data[:4] != MH_MAGIC_64:
        raise ValueError("expected a thin arm64 Mach-O image")
    command_count = struct.unpack_from("<I", data, 16)[0]
    cursor = 32
    for _ in range(command_count):
        if cursor + 8 > len(data):
            raise ValueError("truncated Mach-O load commands")
        command, command_size = struct.unpack_from("<II", data, cursor)
        if command_size < 8 or cursor + command_size > len(data):
            raise ValueError("invalid Mach-O load command")
        if command == LC_SEGMENT_64:
            section_count = struct.unpack_from("<I", data, cursor + 64)[0]
            section_cursor = cursor + 72
            for _section in range(section_count):
                if section_cursor + 80 > cursor + command_size:
                    raise ValueError("truncated Mach-O section table")
                name, segment, address, size, offset = struct.unpack_from(
                    "<16s16sQQI", data, section_cursor
                )
                name = name.split(b"\0", 1)[0]
                segment = segment.split(b"\0", 1)[0]
                if name == b"__text" and segment == b"__TEXT":
                    return address, size, offset
                section_cursor += 80
        cursor += command_size
    raise ValueError("Mach-O __TEXT,__text section was not found")


def locate_codec_capture_offset(path: str) -> int:
    """Return the module-relative capture offset, requiring a unique match."""
    with open(path, "rb") as handle:
        data = _arm64_slice(handle.read())
    text_address, text_size, text_offset = _text_section(data)
    text = data[text_offset:text_offset + text_size]
    width = len(_CAPTURE_PATTERN) * 4
    matches = []
    for offset in range(0, len(text) - width + 1, 4):
        for index, (expected, mask) in enumerate(_CAPTURE_PATTERN):
            word = struct.unpack_from("<I", text, offset + index * 4)[0]
            if word & mask != expected & mask:
                break
        else:
            matches.append(text_address + offset)
    if len(matches) != 1:
        raise RuntimeError(
            "unable to locate a unique arm64 SQLCipher codec hook "
            f"(matches={len(matches)})"
        )
    return matches[0]
