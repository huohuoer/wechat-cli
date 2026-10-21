"""数据库解密 — SQLCipher 4，校验后原子发布。"""

import os
import shutil
import struct
import tempfile

from Crypto.Cipher import AES

from ..keys.common import verify_enc_key

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
RESERVE_SZ = 80  # IV(16) + HMAC-SHA512(64)
SQLITE_HDR = b'SQLite format 3\x00'
WAL_HEADER_SZ = 32
WAL_FRAME_HEADER_SZ = 24


def decrypt_page(enc_key, page_data, pgno):
    if len(enc_key) != KEY_SZ or len(page_data) != PAGE_SZ or pgno < 1:
        raise ValueError("密钥长度、数据库页长度或页号无效")
    if pgno == 1 and not verify_enc_key(enc_key, page_data):
        raise ValueError("数据库首页 HMAC 校验失败，请重新提取密钥")
    iv = page_data[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + 16]
    start = SALT_SZ if pgno == 1 else 0
    encrypted = page_data[start:PAGE_SZ - RESERVE_SZ]
    decrypted = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(encrypted)
    return (SQLITE_HDR if pgno == 1 else b'') + decrypted + b'\x00' * RESERVE_SZ


def _file_stamp(file):
    st = os.fstat(file.fileno())
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def _temporary_output(out_path):
    directory = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    return tempfile.mkstemp(prefix=".wechat-decrypt-", dir=directory)


def full_decrypt(db_path, out_path, enc_key):
    """校验首页与完整页长度，成功后替换输出；失败不破坏已有输出。"""
    with open(db_path, 'rb') as fin:
        before = _file_stamp(fin)
        file_size = before[2]
        if not file_size or file_size % PAGE_SZ:
            raise ValueError("数据库长度不是完整的 SQLCipher 页")
        first_page = decrypt_page(enc_key, fin.read(PAGE_SZ), 1)
        fd, temporary = _temporary_output(out_path)
        try:
            with os.fdopen(fd, 'wb') as fout:
                fout.write(first_page)
                for pgno in range(2, file_size // PAGE_SZ + 1):
                    fout.write(decrypt_page(enc_key, fin.read(PAGE_SZ), pgno))
                if _file_stamp(fin) != before:
                    raise ValueError("数据库在解密期间发生变化，请重试")
                fout.flush()
                os.fsync(fout.fileno())
            os.replace(temporary, out_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return file_size // PAGE_SZ


def _wal_checksum(data, byte_order, seed=(0, 0)):
    """SQLite WAL 的双 32 位滚动校验和，存储值始终使用大端。"""
    s1, s2 = seed
    for x1, x2 in struct.iter_unpack(byte_order + 'II', data):
        s1 = (s1 + x1 + s2) & 0xffffffff
        s2 = (s2 + x2 + s1) & 0xffffffff
    return s1, s2


def decrypt_wal(wal_path, out_path, enc_key):
    """验证整个 WAL，只应用最后提交边界前的帧并按提交页数截断。"""
    if not os.path.exists(wal_path):
        return 0
    with open(wal_path, 'rb') as wf:
        before = _file_stamp(wf)
        wal_size = before[2]
        if wal_size == 0:
            return 0
        frame_size = WAL_FRAME_HEADER_SZ + PAGE_SZ
        if wal_size < WAL_HEADER_SZ or (wal_size - WAL_HEADER_SZ) % frame_size:
            raise ValueError("WAL 含有不完整的头部或帧")
        wal_hdr = wf.read(WAL_HEADER_SZ)
        if len(wal_hdr) != WAL_HEADER_SZ:
            raise ValueError("WAL 头部读取不完整")
        magic, version, page_size = struct.unpack('>III', wal_hdr[:12])
        if magic not in (0x377f0682, 0x377f0683) or version != 3007000 or page_size != PAGE_SZ:
            raise ValueError("WAL 格式、版本或页大小无效")
        byte_order = '<' if magic == 0x377f0682 else '>'
        checksum = _wal_checksum(wal_hdr[:24], byte_order)
        if checksum != struct.unpack('>II', wal_hdr[24:32]):
            raise ValueError("WAL 头部 checksum 校验失败")
        frames = []
        committed = db_size = 0
        for _ in range((wal_size - WAL_HEADER_SZ) // frame_size):
            fh = wf.read(WAL_FRAME_HEADER_SZ)
            page_offset = wf.tell()
            page = wf.read(PAGE_SZ)
            if len(fh) != WAL_FRAME_HEADER_SZ or len(page) != PAGE_SZ:
                raise ValueError("WAL 帧读取不完整")
            pgno, commit_size = struct.unpack('>II', fh[:8])
            if not 0 < pgno <= 0xfffffffe or commit_size > 0xfffffffe:
                raise ValueError("WAL 页号或提交页数无效")
            if fh[8:16] != wal_hdr[16:24]:
                raise ValueError("WAL 帧 salt 与头部不匹配")
            checksum = _wal_checksum(fh[:8] + page, byte_order, checksum)
            if checksum != struct.unpack('>II', fh[16:24]):
                raise ValueError("WAL 帧滚动 checksum 校验失败")
            frames.append((pgno, page_offset))
            if commit_size:
                committed, db_size = len(frames), commit_size
        if _file_stamp(wf) != before:
            raise ValueError("WAL 在校验期间发生变化，请重试")
        if not committed:
            return 0

        fd, temporary = _temporary_output(out_path)
        try:
            with os.fdopen(fd, 'w+b') as df, open(out_path, 'rb') as original:
                original_size = os.fstat(original.fileno()).st_size
                if original_size % PAGE_SZ:
                    raise ValueError("待应用 WAL 的数据库页长度无效")
                base_pages = original_size // PAGE_SZ
                added_pages = {pgno for pgno, _ in frames[:committed] if base_pages < pgno <= db_size}
                if db_size > base_pages and len(added_pages) != db_size - base_pages:
                    raise ValueError("WAL 提交缺少扩展数据库所需的页")
                shutil.copyfileobj(original, df)
                patched = 0
                for pgno, page_offset in frames[:committed]:
                    if pgno > db_size:
                        continue  # 提交时已删除的页不再写回。
                    wf.seek(page_offset)
                    page = decrypt_page(enc_key, wf.read(PAGE_SZ), pgno)
                    df.seek((pgno - 1) * PAGE_SZ)
                    df.write(page)
                    patched += 1
                df.truncate(db_size * PAGE_SZ)
                if _file_stamp(wf) != before:
                    raise ValueError("WAL 在解密期间发生变化，请重试")
                df.flush()
                os.fsync(df.fileno())
            os.replace(temporary, out_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return patched
