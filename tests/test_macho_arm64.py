import os
import struct
import tempfile
import unittest

from wechat_cli.keys.macho_arm64 import (
    CPU_TYPE_ARM64,
    locate_codec_capture_offset,
)


PATTERN = struct.pack(
    "<7I",
    0xB9004FE2,
    0xAD010BE3,
    0xAA1503E9,
    0x93407D29,
    0xCB080139,
    0x8B19029B,
    0x8B0F0368,
)


def _thin_macho(text):
    command_size = 72 + 80
    text_offset = 0x200
    header = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, CPU_TYPE_ARM64, 0, 6, 1, command_size, 0, 0
    )
    segment = struct.pack(
        "<II16sQQQQiiII",
        0x19, command_size, b"__TEXT", 0, 0x4000,
        0, text_offset + len(text), 5, 5, 1, 0,
    )
    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text", b"__TEXT", 0x1000, len(text), text_offset,
        2, 0, 0, 0x80000400, 0, 0, 0,
    )
    prefix = header + segment + section
    return prefix + bytes(text_offset - len(prefix)) + text


class MachoLocatorTests(unittest.TestCase):
    def _write(self, data):
        handle = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(lambda: os.path.exists(handle.name) and os.unlink(handle.name))
        handle.write(data)
        handle.close()
        return handle.name

    def test_locates_unique_codec_signature(self):
        path = self._write(_thin_macho(b"\0" * 12 + PATTERN + b"\0" * 12))
        self.assertEqual(locate_codec_capture_offset(path), 0x100C)

    def test_rejects_ambiguous_signature(self):
        path = self._write(_thin_macho(PATTERN + b"\0" * 4 + PATTERN))
        with self.assertRaisesRegex(RuntimeError, "matches=2"):
            locate_codec_capture_offset(path)


if __name__ == "__main__":
    unittest.main()
