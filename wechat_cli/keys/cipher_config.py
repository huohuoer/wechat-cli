"""微信 Cipher 配置的有界只读解码；仅支持已知的 64 位引用链。"""

import re
import struct

from .common import verify_enc_key

CONFIG_CIPHER_NAME = b"com.Tencent.WCDB.Config.Cipher"
CONFIG_XOR_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b"
    "450048844c2448488944254048584c24"
)
HEX_LITERAL_RE = re.compile(rb"[xX]'([0-9a-fA-F]{64,192})'")
SCAN_CHUNK = 4 * 1024 * 1024
MAX_MARKERS = 64
MAX_REFERENCES = 4096
MAX_BLOB = 16384


def quiet_log(message):
    """共享传统扫描器仍可能输出密钥，扫描器边界仅放行非敏感日志。"""
    if "enc_key=" not in message and "passphrase" not in message.lower():
        print(message, flush=True)


def iter_memory_chunks(read, regions, overlap=195, chunk_size=SCAN_CHUNK):
    """向前重叠读取，失败不会跨越空洞拼接；每块主体为 chunk_size。"""
    for base, size in regions:
        for offset in range(0, size, chunk_size):
            data = read(base + offset, min(chunk_size + overlap, size - offset))
            if data:
                yield base + offset, data


def _find_addresses(read, regions, patterns, limit):
    hits = set()
    overlap = max(map(len, patterns)) - 1
    for base, data in iter_memory_chunks(read, regions, overlap):
        for pattern in patterns:
            pos = data.find(pattern)
            while pos >= 0:
                # 重叠区留给下一块，避免重复并保留跨块命中。
                if pos < SCAN_CHUNK:
                    hits.add(base + pos)
                    if len(hits) >= limit:
                        return sorted(hits)
                pos = data.find(pattern, pos + 1)
    return sorted(hits)


def _pointer(value):
    return 0x10000 <= value < 0x800000000000


def _read_exact(read, address, size):
    if not _pointer(address) or not _pointer(address + size - 1):
        return None
    data = read(address, size)
    return data if data is not None and len(data) == size else None


def _verify_literals(decoded, db_files, key_map, remaining_salts, tested):
    for match in HEX_LITERAL_RE.finditer(decoded):
        run = match.group(1)
        if len(run) % 2:
            continue
        starts = [0]
        if len(run) > 96:
            starts.extend(range(0, len(run) - 63, 32))
            starts.append(len(run) - 64)
        for start in dict.fromkeys(starts):
            candidate = bytes.fromhex(run[start:start + 64].decode("ascii"))
            if candidate in tested:
                continue
            tested.add(candidate)
            for _, _, _, salt, page in db_files:
                if salt in remaining_salts and len(page) == 4096 and verify_enc_key(candidate, page):
                    key_map[salt] = candidate.hex()
                    remaining_salts.discard(salt)


def scan_cipher_config(read, regions, db_files, key_map, remaining_salts):
    """标记 → [指针, 长度] 引用 → 配置对象 → 有界 blob → XOR → HMAC。

    固定偏移来自本地 keyring.py，有限对象探测来自 memory_probe.c；
    这些只是候选布局，不能据此断言所有微信 4.x 均兼容。
    """
    markers = _find_addresses(read, regions, [CONFIG_CIPHER_NAME], MAX_MARKERS)
    if not markers:
        return 0
    pairs = [struct.pack("<QQ", address, len(CONFIG_CIPHER_NAME)) for address in markers]
    references = _find_addresses(read, regions, pairs, MAX_REFERENCES)
    configs = set()
    for address in references:
        node = _read_exact(read, address - 0x10, 0x50)
        if node is None:
            continue
        marker, length = struct.unpack_from("<QQ", node, 0x10)
        config = struct.unpack_from("<Q", node, 0x28)[0]
        if marker in markers and length == len(CONFIG_CIPHER_NAME) and _pointer(config):
            configs.add(config)
    tested = set()
    blobs = 0
    for config in sorted(configs):
        # 优先已知布局，再探测对象范围内的相邻指针/长度，绝不无界解引用。
        known = _read_exact(read, config + 0x88, 0x28)
        locations = []
        if known:
            locations.append(struct.unpack_from("<QQ", known, 8))
        obj = _read_exact(read, config, 0x200)
        if obj:
            locations.extend(struct.unpack_from("<QQ", obj, off)
                             for off in range(0, len(obj) - 15, 8))
        for pointer, length in dict.fromkeys(locations):
            if not 0 < length <= MAX_BLOB:
                continue
            blob = _read_exact(read, pointer, length)
            if blob is None:
                continue
            blobs += 1
            for phase in range(len(CONFIG_XOR_MASK)):
                decoded = bytes(value ^ CONFIG_XOR_MASK[(i + phase) % len(CONFIG_XOR_MASK)]
                                for i, value in enumerate(blob))
                _verify_literals(decoded, db_files, key_map, remaining_salts, tested)
                if not remaining_salts:
                    return blobs
    return blobs
