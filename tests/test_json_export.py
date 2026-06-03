import json
import os
import sqlite3
import tempfile
import unittest
import hashlib
from types import SimpleNamespace
from datetime import datetime
from unittest.mock import patch

from click.testing import CliRunner
from Crypto.Cipher import AES

import wechat_cli.main as main
from wechat_cli.core.media_export import (
    decode_wechat_image_dat,
    decode_wxgf_image,
    detect_image_bytes,
    materialize_record_media,
    prepare_export_targets,
    readme_path_for_output,
    _sticker_cache_dir,
)
from wechat_cli.core.messages import collect_chat_export_records


CHAT_USERNAME = "room@chatroom"


class FakeCache:
    def __init__(self, mapping):
        self.mapping = mapping

    def get(self, rel_key):
        return self.mapping.get(rel_key)


class FakeApp:
    def __init__(self, db_dir, message_db, resource_db=None):
        self.db_dir = db_dir
        self.decrypted_dir = os.path.join(os.path.dirname(db_dir), "decrypted")
        mapping = {"message/message_0.db": message_db}
        if resource_db:
            mapping["message/message_resource.db"] = resource_db
        self.cache = FakeCache(mapping)
        self.msg_db_keys = ["message/message_0.db"]

    def display_name_fn(self, username, names):
        if username == "alice":
            return "Alice"
        if username == CHAT_USERNAME:
            return "Project Room"
        return names.get(username, username)


def _table_name(username=CHAT_USERNAME):
    import hashlib
    return "Msg_" + hashlib.md5(username.encode()).hexdigest()


def _write_sqlite(path, rows, username=CHAT_USERNAME):
    table = _table_name(username)
    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE TABLE Name2Id (user_name TEXT)")
        conn.execute("INSERT INTO Name2Id (rowid, user_name) VALUES (?, ?)", (1, "alice"))
        conn.execute(
            f"""
            CREATE TABLE [{table}] (
                local_id INTEGER,
                local_type INTEGER,
                create_time INTEGER,
                real_sender_id INTEGER,
                message_content BLOB,
                WCDB_CT_message_content INTEGER
            )
            """
        )
        conn.executemany(
            f"INSERT INTO [{table}] VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()
    return table


def _packed_resource_hash(resource_hash):
    return b"\x12\x22\x0a\x20" + resource_hash.encode("ascii")


def _write_resource_sqlite(path, rows, username=CHAT_USERNAME):
    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE TABLE ChatName2Id(user_name TEXT PRIMARY KEY, update_time INTEGER)")
        conn.execute("INSERT INTO ChatName2Id(rowid, user_name, update_time) VALUES (?, ?, ?)", (1, username, 0))
        conn.execute(
            """
            CREATE TABLE MessageResourceInfo(
                message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER,
                sender_id INTEGER,
                message_local_type INTEGER,
                message_create_time INTEGER,
                message_local_id INTEGER,
                message_svr_id INTEGER,
                message_origin_source INTEGER,
                packed_info BLOB
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE MessageResourceDetail(
                resource_id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER,
                type INTEGER,
                size INTEGER,
                create_time INTEGER,
                access_time INTEGER,
                status INTEGER,
                data_index TEXT,
                packed_info BLOB
            )
            """
        )
        for local_id, local_type, create_time, resource_hash in rows:
            cur = conn.execute(
                """
                INSERT INTO MessageResourceInfo(
                    chat_id, sender_id, message_local_type, message_create_time,
                    message_local_id, message_svr_id, message_origin_source, packed_info
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (1, 1, local_type, create_time, local_id, 1000 + local_id, 6, _packed_resource_hash(resource_hash)),
            )
            conn.execute(
                """
                INSERT INTO MessageResourceDetail(
                    message_id, type, size, create_time, access_time, status, data_index, packed_info
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (cur.lastrowid, 131073, 1234, create_time, 0, 1, "0", b""),
            )
        conn.commit()
    finally:
        conn.close()


def _xor(data, key=0x37):
    return bytes(b ^ key for b in data)


def _wechat_v2_dat():
    return bytes.fromhex("07085632080700040000d64f000001") + (b"\x00" * 128)


def _write_v2_media_context(tmp, filename, uin=352745915, wxid="catmoment123"):
    documents_dir = os.path.join(tmp, "Documents")
    kvcomm_dir = os.path.join(documents_dir, "app_data", "net", "kvcomm")
    os.makedirs(kvcomm_dir)
    with open(os.path.join(kvcomm_dir, f"key_{uin}_4066646122_1_1780465506_1339419274_3600_input.statistic"), "wb") as f:
        f.write(b"")

    media_dir = os.path.join(
        documents_dir, "xwechat_files", f"{wxid}_7e99",
        "msg", "attach", "0" * 32, "2026-06", "Img",
    )
    os.makedirs(media_dir)
    return os.path.join(media_dir, filename)


def _wechat_v2_image_dat(payload, uin=352745915, wxid="catmoment123", aes_len=16):
    aes_key = hashlib.md5((str(uin) + wxid).encode("utf-8")).hexdigest()[:16].encode("ascii")
    xor_key = uin & 0xff
    prefix = payload[:aes_len].ljust(aes_len, b"\x00")
    aes_plain = prefix + (b"\x00" * 16)
    aes_cipher = AES.new(aes_key, AES.MODE_ECB).encrypt(aes_plain)
    tail = bytes(b ^ xor_key for b in payload[aes_len:])
    return (
        b"\x07\x08V2\x08\x07"
        + aes_len.to_bytes(4, "little")
        + len(tail).to_bytes(4, "little")
        + b"\x01"
        + aes_cipher
        + tail
    )


def _wxgf_with_partition(payload):
    header = b"wxgf" + bytes([19]) + (b"\x00" * 14)
    return header + len(payload).to_bytes(4, "big") + payload


def _png_bytes(width=72, height=80):
    return (
        b"\x89PNG\r\n\x1a\n"
        + (13).to_bytes(4, "big")
        + b"IHDR"
        + width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + b"\x08\x02\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )


def _gif_bytes(width=300, height=304):
    return (
        b"GIF89a"
        + width.to_bytes(2, "little")
        + height.to_bytes(2, "little")
        + b"\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x00\x00\x00\x00\x00,"
        + b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
    )


def _sticker_xml(sticker_md5, aeskey="5fd76e9a49304191ab82949d45931e89", cdnurl="https://example.test/cdn", encrypturl="https://example.test/encrypt"):
    return (
        '<msg><emoji type="2" '
        f'md5="{sticker_md5}" len="{len(_gif_bytes())}" width="300" height="304" '
        f'aeskey="{aeskey}" cdnurl="{cdnurl}" encrypturl="{encrypturl}" /></msg>'
    )


def _aes_cbc_pkcs7_encrypt(data, aeskey):
    key = bytes.fromhex(aeskey)
    pad = 16 - (len(data) % 16)
    return AES.new(key, AES.MODE_CBC, iv=key).encrypt(data + bytes([pad]) * pad)


class JsonExportTests(unittest.TestCase):
    def setUp(self):
        self._sticker_cache_tmp = tempfile.TemporaryDirectory()
        self.sticker_cache_dir = os.path.join(self._sticker_cache_tmp.name, "stickers")
        self._sticker_cache_patcher = patch(
            "wechat_cli.core.media_export._sticker_cache_dir",
            return_value=self.sticker_cache_dir,
        )
        self._sticker_cache_patcher.start()

    def tearDown(self):
        self._sticker_cache_patcher.stop()
        self._sticker_cache_tmp.cleanup()

    def test_sticker_cache_dir_uses_macos_user_cache(self):
        with patch.dict(os.environ, {"HOME": "/Users/test"}, clear=True):
            with patch("wechat_cli.core.media_export.sys.platform", "darwin"):
                self.assertEqual(
                    _sticker_cache_dir(),
                    "/Users/test/Library/Caches/wechat-cli/stickers",
                )

    def test_sticker_cache_dir_uses_xdg_cache_on_non_macos(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"XDG_CACHE_HOME": tmp}, clear=True):
                with patch("wechat_cli.core.media_export.sys.platform", "linux"):
                    self.assertEqual(
                        _sticker_cache_dir(),
                        os.path.join(tmp, "wechat-cli", "stickers"),
                    )

    def test_sticker_cache_dir_allows_env_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            override = os.path.join(tmp, "custom-stickers")
            with patch.dict(os.environ, {"WECHAT_CLI_STICKER_CACHE_DIR": override}, clear=True):
                with patch("wechat_cli.core.media_export.sys.platform", "darwin"):
                    self.assertEqual(_sticker_cache_dir(), override)

    def test_decode_wechat_image_dat_detects_xor_jpeg(self):
        jpeg = bytes.fromhex("ffd8ffe000104a464946") + b"payload"
        decoded = decode_wechat_image_dat(_xor(jpeg))
        self.assertIsNotNone(decoded)
        data, ext, mime = decoded
        self.assertEqual(data, jpeg)
        self.assertEqual(ext, "jpg")
        self.assertEqual(mime, "image/jpeg")

    def test_decode_wxgf_image_uses_ffmpeg_partition(self):
        hevc = b"\x00\x00\x00\x01fake-hevc"
        wxgf = _wxgf_with_partition(hevc)
        jpeg = bytes.fromhex("ffd8ffe000104a464946") + b"payload"
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return SimpleNamespace(returncode=0, stdout=jpeg, stderr=b"")

        with patch("wechat_cli.core.media_export._ffmpeg_path", return_value="/usr/bin/ffmpeg"):
            with patch("wechat_cli.core.media_export.subprocess.run", side_effect=fake_run):
                decoded = decode_wxgf_image(wxgf)

        self.assertIsNotNone(decoded)
        decoded_data, ext, mime = decoded
        self.assertEqual(decoded_data, jpeg)
        self.assertEqual(ext, "jpg")
        self.assertEqual(mime, "image/jpeg")
        self.assertEqual(calls[0][1]["input"], hevc)

    def test_decode_wechat_image_dat_decodes_v2_wxgf_with_ffmpeg(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = _write_v2_media_context(tmp, "a" * 32 + ".dat")
            hevc = b"\x00\x00\x00\x01fake-hevc"
            wxgf = _wxgf_with_partition(hevc)
            data = _wechat_v2_image_dat(wxgf)
            jpeg = bytes.fromhex("ffd8ffe000104a464946") + b"payload"

            with patch("wechat_cli.core.media_export._ffmpeg_path", return_value="/usr/bin/ffmpeg"):
                with patch(
                    "wechat_cli.core.media_export.subprocess.run",
                    return_value=SimpleNamespace(returncode=0, stdout=jpeg, stderr=b""),
                ):
                    decoded = decode_wechat_image_dat(data, source_path=src)

            self.assertIsNotNone(decoded)
            decoded_data, ext, mime = decoded
            self.assertEqual(decoded_data, jpeg)
            self.assertEqual(ext, "jpg")
            self.assertEqual(mime, "image/jpeg")

    def test_decode_wechat_image_dat_rejects_wechat_v2_false_bmp(self):
        data = _wechat_v2_dat()
        false_bmp = _xor(data, key=0x45)

        self.assertTrue(false_bmp.startswith(b"BM"))
        self.assertIsNone(detect_image_bytes(false_bmp))
        self.assertIsNone(decode_wechat_image_dat(data))

    def test_decode_wechat_image_dat_decodes_v2_with_kvcomm_uin(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = _write_v2_media_context(tmp, "a" * 32 + ".dat")
            jpeg = bytes.fromhex("ffd8ffe000104a46494600010100004800480000") + b"payload\xff\xd9"
            data = _wechat_v2_image_dat(jpeg)
            with open(src, "wb") as f:
                f.write(data)

            decoded = decode_wechat_image_dat(data, source_path=src)

            self.assertIsNotNone(decoded)
            decoded_data, ext, mime = decoded
            self.assertEqual(decoded_data, jpeg)
            self.assertEqual(ext, "jpg")
            self.assertEqual(mime, "image/jpeg")

    def test_decode_wechat_image_dat_decodes_v2_with_radium_config_uin(self):
        with tempfile.TemporaryDirectory() as tmp:
            documents_dir = os.path.join(tmp, "Documents")
            net_kvcomm = os.path.join(documents_dir, "app_data", "net", "kvcomm")
            radium_kvcomm = os.path.join(
                documents_dir, "app_data", "radium", "ilink",
                "7e99a3705453335bbe64eb651661c573", "kvcomm",
            )
            os.makedirs(net_kvcomm)
            os.makedirs(radium_kvcomm)
            with open(os.path.join(net_kvcomm, "key_0_4066646122_1_1780474260_299727447_3600_input.statistic"), "wb") as f:
                f.write(b"")
            with open(os.path.join(radium_kvcomm, "config.ini"), "w", encoding="utf-8") as f:
                f.write("last_uin=MzUyNzQ1OTE1\n")

            media_dir = os.path.join(
                documents_dir, "xwechat_files", "catmoment123_7e99",
                "msg", "attach", "0" * 32, "2026-06", "Img",
            )
            os.makedirs(media_dir)
            src = os.path.join(media_dir, "a" * 32 + ".dat")
            png = _png_bytes(72, 80)
            data = _wechat_v2_image_dat(png)
            with open(src, "wb") as f:
                f.write(data)

            decoded = decode_wechat_image_dat(data, source_path=src)

            self.assertIsNotNone(decoded)
            decoded_data, ext, mime = decoded
            self.assertEqual(decoded_data, png)
            self.assertEqual(ext, "png")
            self.assertEqual(mime, "image/png")

    def test_materialize_media_decodes_dat_and_uses_relative_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "image.dat")
            png = _png_bytes(72, 80)
            with open(src, "wb") as f:
                f.write(_xor(png))

            output_path = os.path.join(tmp, "chat.json")
            assets_dir = os.path.join(tmp, "chat_assets")
            records = [{
                "local_id": 10,
                "time": "2026-06-03 10:15:00",
                "_media_sources": [{"kind": "image", "source_path": src, "original_filename": "image.dat"}],
            }]

            warnings = materialize_record_media(records, assets_dir, output_path)

            self.assertEqual(warnings, [])
            media = records[0]["media"][0]
            self.assertEqual(media["status"], "decoded")
            self.assertEqual(media["mime"], "image/png")
            self.assertEqual(media["width"], 72)
            self.assertEqual(media["height"], 80)
            self.assertTrue(media["path"].startswith("chat_assets/images/"))
            self.assertTrue(os.path.exists(os.path.join(tmp, media["path"])))
            self.assertNotIn("_media_sources", records[0])

    def test_materialize_media_copies_undecodable_dat_and_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "bad.dat")
            with open(src, "wb") as f:
                f.write(b"not an encoded image")

            output_path = os.path.join(tmp, "chat.json")
            assets_dir = os.path.join(tmp, "chat_assets")
            records = [{
                "local_id": 11,
                "time": "2026-06-03 10:16:00",
                "_media_sources": [{"kind": "image", "source_path": src, "original_filename": "bad.dat"}],
            }]

            warnings = materialize_record_media(records, assets_dir, output_path)

            media = records[0]["media"][0]
            self.assertEqual(media["status"], "undecodable")
            self.assertTrue(media["path"].endswith(".dat"))
            self.assertEqual(warnings[0]["status"], "undecodable")
            self.assertTrue(os.path.exists(os.path.join(tmp, media["path"])))

    def test_materialize_media_keeps_undecodable_wechat_v2_dat(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "v2.dat")
            data = _wechat_v2_dat()
            with open(src, "wb") as f:
                f.write(data)

            output_path = os.path.join(tmp, "chat.json")
            assets_dir = os.path.join(tmp, "chat_assets")
            records = [{
                "local_id": 12,
                "time": "2026-06-03 10:16:30",
                "_media_sources": [{"kind": "image", "source_path": src, "original_filename": "v2.dat"}],
            }]

            warnings = materialize_record_media(records, assets_dir, output_path)

            media = records[0]["media"][0]
            self.assertEqual(media["status"], "undecodable")
            self.assertTrue(media["path"].endswith(".dat"))
            self.assertEqual(media["mime"], "application/octet-stream")
            self.assertEqual(media["detail"], "WeChat image .dat could not be decoded")
            with open(os.path.join(tmp, media["path"]), "rb") as f:
                self.assertEqual(f.read(), data)
            self.assertEqual(warnings[0]["status"], "undecodable")

    def test_materialize_media_decodes_v2_sibling_when_base_is_wxgf(self):
        with tempfile.TemporaryDirectory() as tmp:
            resource_hash = "b" * 32
            src = _write_v2_media_context(tmp, f"{resource_hash}.dat")
            high_src = os.path.join(os.path.dirname(src), f"{resource_hash}_h.dat")
            wxgf_payload = b"wxgf" + (b"\x00" * 64)
            png = _png_bytes(640, 480)
            with open(src, "wb") as f:
                f.write(_wechat_v2_image_dat(wxgf_payload))
            with open(high_src, "wb") as f:
                f.write(_wechat_v2_image_dat(png))

            output_path = os.path.join(tmp, "chat.json")
            assets_dir = os.path.join(tmp, "chat_assets")
            records = [{
                "local_id": 13,
                "time": "2026-06-03 10:16:45",
                "_media_sources": [{"kind": "image", "source_path": src, "original_filename": f"{resource_hash}.dat"}],
            }]

            warnings = materialize_record_media(records, assets_dir, output_path)

            self.assertEqual(warnings, [])
            media = records[0]["media"][0]
            self.assertEqual(media["status"], "decoded")
            self.assertEqual(media["mime"], "image/png")
            self.assertEqual(media["width"], 640)
            self.assertEqual(media["height"], 480)
            self.assertTrue(media["path"].endswith(".png"))
            with open(os.path.join(tmp, media["path"]), "rb") as f:
                self.assertEqual(f.read(), png)

    def test_materialize_media_records_missing_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_path = os.path.join(tmp, "chat.json")
            assets_dir = os.path.join(tmp, "chat_assets")
            records = [{
                "local_id": 12,
                "time": "2026-06-03 10:17:00",
                "_media_sources": [{
                    "kind": "video",
                    "source_path": os.path.join(tmp, "missing.mp4"),
                    "original_filename": "missing.mp4",
                }],
            }]

            warnings = materialize_record_media(records, assets_dir, output_path)

            media = records[0]["media"][0]
            self.assertEqual(media["status"], "missing")
            self.assertEqual(media["original_filename"], "missing.mp4")
            self.assertEqual(warnings[0]["local_id"], 12)
            self.assertEqual(warnings[0]["status"], "missing")
            self.assertFalse(os.path.exists(assets_dir))

    def test_materialize_video_adds_ffprobe_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "clip.mp4")
            with open(src, "wb") as f:
                f.write(b"fake mp4")

            output_path = os.path.join(tmp, "chat.json")
            assets_dir = os.path.join(tmp, "chat_assets")
            records = [{
                "local_id": 43,
                "time": "2026-06-03 10:17:30",
                "_media_sources": [{"kind": "video", "source_path": src, "original_filename": "clip.mp4"}],
            }]

            with patch(
                "wechat_cli.core.media_export._probe_ffprobe_metadata",
                return_value=({"width": 1920, "height": 1080, "duration_ms": 1234}, ""),
            ):
                warnings = materialize_record_media(records, assets_dir, output_path)

            self.assertEqual(warnings, [])
            media = records[0]["media"][0]
            self.assertEqual(media["status"], "copied")
            self.assertEqual(media["width"], 1920)
            self.assertEqual(media["height"], 1080)
            self.assertEqual(media["duration_ms"], 1234)

    def test_materialize_audio_probe_failure_warns_without_failing(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "voice.aud")
            with open(src, "wb") as f:
                f.write(b"fake audio")

            output_path = os.path.join(tmp, "chat.json")
            assets_dir = os.path.join(tmp, "chat_assets")
            records = [{
                "local_id": 34,
                "time": "2026-06-03 10:17:45",
                "_media_sources": [{"kind": "voice", "source_path": src, "original_filename": "voice.aud"}],
            }]

            with patch(
                "wechat_cli.core.media_export._probe_ffprobe_metadata",
                return_value=({}, "ffprobe failed"),
            ):
                warnings = materialize_record_media(records, assets_dir, output_path)

            media = records[0]["media"][0]
            self.assertEqual(media["status"], "copied")
            self.assertNotIn("duration_ms", media)
            self.assertEqual(warnings[0]["local_id"], 34)
            self.assertEqual(warnings[0]["status"], "metadata_unavailable")
            self.assertIn("ffprobe failed", warnings[0]["detail"])

    def test_materialize_sticker_downloads_cdn_gif(self):
        with tempfile.TemporaryDirectory() as tmp:
            gif = _gif_bytes()
            sticker_md5 = hashlib.md5(gif).hexdigest()
            output_path = os.path.join(tmp, "chat.json")
            assets_dir = os.path.join(tmp, "chat_assets")
            records = [{
                "local_id": 47,
                "time": "2026-06-03 10:18:00",
                "_media_sources": [{
                    "kind": "sticker",
                    "original_filename": sticker_md5,
                    "sticker_md5": sticker_md5,
                    "expected_bytes": str(len(gif)),
                    "width": "300",
                    "height": "304",
                    "cdn_url": "https://example.test/cdn",
                }],
            }]

            with patch("wechat_cli.core.media_export._download_url", return_value=(gif, "")):
                warnings = materialize_record_media(
                    records, assets_dir, output_path, download_stickers=True
                )

            self.assertEqual(warnings, [])
            media = records[0]["media"][0]
            self.assertEqual(media["kind"], "sticker")
            self.assertEqual(media["status"], "downloaded")
            self.assertEqual(media["source"], "cdnurl")
            self.assertEqual(media["mime"], "image/gif")
            self.assertEqual(media["md5"], sticker_md5)
            self.assertEqual(media["width"], 300)
            self.assertEqual(media["height"], 304)
            self.assertTrue(media["path"].startswith("chat_assets/stickers/"))
            with open(os.path.join(tmp, media["path"]), "rb") as f:
                self.assertEqual(f.read(), gif)

    def test_materialize_sticker_writes_persistent_cache_after_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            gif = _gif_bytes()
            sticker_md5 = hashlib.md5(gif).hexdigest()
            output_path = os.path.join(tmp, "chat.json")
            assets_dir = os.path.join(tmp, "chat_assets")
            records = [{
                "local_id": 47,
                "time": "2026-06-03 10:18:00",
                "_media_sources": [{
                    "kind": "sticker",
                    "original_filename": sticker_md5,
                    "sticker_md5": sticker_md5,
                    "cdn_url": "https://example.test/cdn",
                }],
            }]

            with patch("wechat_cli.core.media_export._download_url", return_value=(gif, "")):
                warnings = materialize_record_media(
                    records, assets_dir, output_path, download_stickers=True
                )

            self.assertEqual(warnings, [])
            cache_path = os.path.join(self.sticker_cache_dir, f"{sticker_md5}.gif")
            self.assertTrue(os.path.exists(cache_path))
            with open(cache_path, "rb") as f:
                self.assertEqual(f.read(), gif)

    def test_materialize_sticker_uses_persistent_cache_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            gif = _gif_bytes()
            sticker_md5 = hashlib.md5(gif).hexdigest()
            os.makedirs(self.sticker_cache_dir)
            with open(os.path.join(self.sticker_cache_dir, f"{sticker_md5}.gif"), "wb") as f:
                f.write(gif)

            output_path = os.path.join(tmp, "chat.json")
            assets_dir = os.path.join(tmp, "chat_assets")
            records = [{
                "local_id": 50,
                "time": "2026-06-03 10:20:00",
                "_media_sources": [{
                    "kind": "sticker",
                    "original_filename": sticker_md5,
                    "sticker_md5": sticker_md5,
                    "cdn_url": "https://example.test/cdn",
                }],
            }]

            with patch("wechat_cli.core.media_export._download_url") as download:
                warnings = materialize_record_media(
                    records, assets_dir, output_path, download_stickers=False
                )

            download.assert_not_called()
            self.assertEqual(warnings, [])
            media = records[0]["media"][0]
            self.assertEqual(media["status"], "copied")
            self.assertTrue(media["cache_hit"])
            self.assertEqual(media["mime"], "image/gif")
            self.assertEqual(media["width"], 300)
            self.assertEqual(media["height"], 304)
            self.assertTrue(media["path"].startswith("chat_assets/stickers/"))
            with open(os.path.join(tmp, media["path"]), "rb") as f:
                self.assertEqual(f.read(), gif)

    def test_materialize_sticker_reuses_downloaded_asset_by_md5(self):
        with tempfile.TemporaryDirectory() as tmp:
            gif = _gif_bytes()
            sticker_md5 = hashlib.md5(gif).hexdigest()
            output_path = os.path.join(tmp, "chat.json")
            assets_dir = os.path.join(tmp, "chat_assets")
            source = {
                "kind": "sticker",
                "original_filename": sticker_md5,
                "sticker_md5": sticker_md5,
                "cdn_url": "https://example.test/cdn",
            }
            records = [
                {
                    "local_id": 47,
                    "time": "2026-06-03 10:18:00",
                    "_media_sources": [dict(source)],
                },
                {
                    "local_id": 48,
                    "time": "2026-06-03 10:19:00",
                    "_media_sources": [dict(source)],
                },
            ]
            calls = []

            def fake_download(url):
                calls.append(url)
                return gif, ""

            with patch("wechat_cli.core.media_export._download_url", side_effect=fake_download):
                warnings = materialize_record_media(
                    records, assets_dir, output_path, download_stickers=True
                )

            self.assertEqual(warnings, [])
            self.assertEqual(calls, ["https://example.test/cdn"])
            first = records[0]["media"][0]
            second = records[1]["media"][0]
            self.assertEqual(first["path"], second["path"])
            self.assertEqual(first["status"], "downloaded")
            self.assertEqual(second["status"], "downloaded")

    def test_materialize_sticker_enriches_sparse_earlier_record_by_md5(self):
        with tempfile.TemporaryDirectory() as tmp:
            gif = _gif_bytes()
            sticker_md5 = hashlib.md5(gif).hexdigest()
            thumb_path = os.path.join(tmp, f"{sticker_md5}.thumb")
            with open(thumb_path, "wb") as f:
                f.write(b"wechat-local-thumb-wrapper")

            output_path = os.path.join(tmp, "chat.json")
            assets_dir = os.path.join(tmp, "chat_assets")
            records = [
                {
                    "local_id": 11,
                    "time": "2024-11-29 13:37:31",
                    "_media_sources": [{
                        "kind": "sticker",
                        "source_path": thumb_path,
                        "original_filename": sticker_md5,
                        "sticker_md5": sticker_md5,
                        "expected_bytes": "0",
                        "width": "240",
                        "height": "240",
                    }],
                },
                {
                    "local_id": 245,
                    "time": "2024-12-09 17:15:05",
                    "_media_sources": [{
                        "kind": "sticker",
                        "source_path": thumb_path,
                        "original_filename": sticker_md5,
                        "sticker_md5": sticker_md5,
                        "expected_bytes": str(len(gif)),
                        "width": "240",
                        "height": "240",
                        "product_id": "com.tencent.xin.emoticon.person.test",
                        "cdn_url": "https://example.test/cdn",
                    }],
                },
            ]
            calls = []

            def fake_download(url):
                calls.append(url)
                return gif, ""

            with patch("wechat_cli.core.media_export._download_url", side_effect=fake_download):
                warnings = materialize_record_media(
                    records, assets_dir, output_path, download_stickers=True
                )

            self.assertEqual(warnings, [])
            self.assertEqual(calls, ["https://example.test/cdn"])
            first = records[0]["media"][0]
            second = records[1]["media"][0]
            self.assertEqual(first["status"], "downloaded")
            self.assertEqual(first["source"], "cdnurl")
            self.assertEqual(first["mime"], "image/gif")
            self.assertEqual(first["expected_bytes"], len(gif))
            self.assertEqual(first["product_id"], "com.tencent.xin.emoticon.person.test")
            self.assertEqual(first["path"], second["path"])
            with open(os.path.join(tmp, first["path"]), "rb") as f:
                self.assertEqual(f.read(), gif)

    def test_materialize_sticker_decrypts_encrypturl_gif(self):
        with tempfile.TemporaryDirectory() as tmp:
            gif = _gif_bytes()
            aeskey = "5fd76e9a49304191ab82949d45931e89"
            sticker_md5 = hashlib.md5(gif).hexdigest()
            encrypted = _aes_cbc_pkcs7_encrypt(gif, aeskey)
            output_path = os.path.join(tmp, "chat.json")
            assets_dir = os.path.join(tmp, "chat_assets")
            records = [{
                "local_id": 48,
                "time": "2026-06-03 10:18:30",
                "_media_sources": [{
                    "kind": "sticker",
                    "original_filename": sticker_md5,
                    "sticker_md5": sticker_md5,
                    "aeskey": aeskey,
                    "encrypt_url": "https://example.test/encrypt",
                }],
            }]

            with patch("wechat_cli.core.media_export._download_url", return_value=(encrypted, "")):
                warnings = materialize_record_media(
                    records, assets_dir, output_path, download_stickers=True
                )

            self.assertEqual(warnings, [])
            media = records[0]["media"][0]
            self.assertEqual(media["status"], "decoded")
            self.assertEqual(media["source"], "encrypturl")
            self.assertEqual(media["mime"], "image/gif")
            with open(os.path.join(tmp, media["path"]), "rb") as f:
                self.assertEqual(f.read(), gif)

    def test_materialize_sticker_download_disabled_reports_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_path = os.path.join(tmp, "chat.json")
            assets_dir = os.path.join(tmp, "chat_assets")
            records = [{
                "local_id": 49,
                "time": "2026-06-03 10:19:00",
                "_media_sources": [{
                    "kind": "sticker",
                    "original_filename": "missing-sticker",
                    "cdn_url": "https://example.test/cdn",
                }],
            }]

            warnings = materialize_record_media(records, assets_dir, output_path)

            media = records[0]["media"][0]
            self.assertEqual(media["status"], "missing")
            self.assertIn("--download-stickers", media["detail"])
            self.assertEqual(warnings[0]["kind"], "sticker")

    def test_prepare_export_targets_rejects_existing_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_path = os.path.join(tmp, "chat.json")
            assets_dir = os.path.join(tmp, "chat_assets")
            readme_path = os.path.join(tmp, "chat_export_readme.md")
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("{}")
            with open(readme_path, "w", encoding="utf-8") as f:
                f.write("stale")

            with self.assertRaises(FileExistsError):
                prepare_export_targets(output_path, assets_dir, readme_path=readme_path, overwrite=False)

            prepare_export_targets(output_path, assets_dir, readme_path=readme_path, overwrite=True)
            self.assertFalse(os.path.exists(output_path))
            self.assertFalse(os.path.exists(readme_path))
            self.assertTrue(os.path.isdir(assets_dir))

    def test_collect_chat_export_records_returns_all_messages_by_default_and_missing_media(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_dir = os.path.join(tmp, "xwechat", "db_storage")
            os.makedirs(db_dir)
            message_db = os.path.join(tmp, "message.db")
            ts = int(datetime(2026, 6, 3, 10, 0).timestamp())
            _write_sqlite(message_db, [
                (1, 1, ts, 1, "alice:\nhello", None),
                (2, 3, ts + 1, 1, "<msg><img path=\"missing.dat\" /></msg>", None),
                (3, 1, ts + 2, 1, "alice:\nbye", None),
            ])

            app = FakeApp(db_dir, message_db)
            ctx = {
                "query": CHAT_USERNAME,
                "username": CHAT_USERNAME,
                "display_name": "Project Room",
                "db_path": message_db,
                "table_name": _table_name(),
                "message_tables": [{"db_path": message_db, "table_name": _table_name()}],
                "is_group": True,
            }

            records, failures = collect_chat_export_records(
                ctx, {}, app.display_name_fn, limit=None, db_dir=db_dir
            )

            self.assertEqual(failures, [])
            self.assertEqual([r["local_id"] for r in records], [1, 2, 3])
            self.assertEqual(records[1]["type"], "image")
            self.assertEqual(records[1]["_media_sources"][0]["kind"], "image")
            self.assertEqual(records[1]["_media_sources"][0]["source_path"], None)

    def test_collect_chat_export_records_resolves_sticker_cache_and_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_dir = os.path.join(tmp, "xwechat", "db_storage")
            os.makedirs(db_dir)
            gif = _gif_bytes()
            sticker_md5 = hashlib.md5(gif).hexdigest()
            sticker_dir = os.path.join(tmp, "xwechat", "cache", "2026-06", "Emoticon", sticker_md5[:2])
            os.makedirs(sticker_dir)
            sticker_path = os.path.join(sticker_dir, sticker_md5)
            with open(sticker_path, "wb") as f:
                f.write(b"local-cache-wrapper")

            message_db = os.path.join(tmp, "message.db")
            ts = int(datetime(2026, 6, 3, 10, 0).timestamp())
            xml = _sticker_xml(sticker_md5)
            _write_sqlite(message_db, [(47, 47, ts, 1, f"alice:\n{xml}", None)])
            app = FakeApp(db_dir, message_db)
            ctx = {
                "query": CHAT_USERNAME,
                "username": CHAT_USERNAME,
                "display_name": "Project Room",
                "db_path": message_db,
                "table_name": _table_name(),
                "message_tables": [{"db_path": message_db, "table_name": _table_name()}],
                "is_group": True,
            }

            records, failures = collect_chat_export_records(
                ctx, {}, app.display_name_fn, limit=None, db_dir=db_dir
            )

            self.assertEqual(failures, [])
            self.assertEqual(records[0]["type"], "sticker")
            source = records[0]["_media_sources"][0]
            self.assertEqual(source["kind"], "sticker")
            self.assertEqual(source["source_path"], sticker_path)
            self.assertEqual(source["sticker_md5"], sticker_md5)
            self.assertEqual(source["cdn_url"], "https://example.test/cdn")
            self.assertEqual(source["encrypt_url"], "https://example.test/encrypt")

    def test_collect_chat_export_records_uses_resource_hash_for_ambiguous_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_dir = os.path.join(tmp, "xwechat", "db_storage")
            image_dir = os.path.join(
                tmp, "xwechat", "msg", "attach",
                __import__("hashlib").md5(CHAT_USERNAME.encode()).hexdigest(),
                "2026-06", "Img",
            )
            os.makedirs(image_dir)
            os.makedirs(db_dir)
            resource_hash = "0123456789abcdef0123456789abcdef"
            target_path = os.path.join(image_dir, f"{resource_hash}.dat")
            with open(target_path, "wb") as f:
                f.write(b"target")
            with open(os.path.join(image_dir, "other.dat"), "wb") as f:
                f.write(b"other")

            message_db = os.path.join(tmp, "message.db")
            resource_db = os.path.join(tmp, "message_resource.db")
            ts = int(datetime(2026, 6, 3, 10, 0).timestamp())
            _write_sqlite(message_db, [(2, 3, ts, 1, "<msg><img /></msg>", None)])
            _write_resource_sqlite(resource_db, [(2, 3, ts, resource_hash)])
            app = FakeApp(db_dir, message_db, resource_db=resource_db)
            ctx = {
                "query": CHAT_USERNAME,
                "username": CHAT_USERNAME,
                "display_name": "Project Room",
                "db_path": message_db,
                "table_name": _table_name(),
                "message_tables": [{"db_path": message_db, "table_name": _table_name()}],
                "is_group": True,
            }

            records, failures = collect_chat_export_records(
                ctx, {}, app.display_name_fn, limit=None, db_dir=db_dir, resource_db_path=resource_db
            )

            self.assertEqual(failures, [])
            source = records[0]["_media_sources"][0]
            self.assertEqual(source["kind"], "image")
            self.assertEqual(source["source_path"], target_path)

    def test_cli_json_export_writes_schema_and_copied_relative_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_dir = os.path.join(tmp, "xwechat", "db_storage")
            image_dir = os.path.join(
                tmp, "xwechat", "msg", "attach",
                __import__("hashlib").md5(CHAT_USERNAME.encode()).hexdigest(),
                "2026-06", "Img",
            )
            os.makedirs(image_dir)
            os.makedirs(db_dir)
            image_path = os.path.join(image_dir, "photo.dat")
            png = _png_bytes(72, 80)
            with open(image_path, "wb") as f:
                f.write(_xor(png))

            message_db = os.path.join(tmp, "message.db")
            ts = int(datetime(2026, 6, 3, 10, 0).timestamp())
            _write_sqlite(message_db, [
                (1, 1, ts, 1, "alice:\nhello", None),
                (2, 3, ts + 1, 1, "<msg><img path=\"photo.dat\" /></msg>", None),
            ])
            fake_app = FakeApp(db_dir, message_db)
            output_path = os.path.join(tmp, "chat.json")
            readme_path = readme_path_for_output(output_path)

            runner = CliRunner()
            with patch.object(main, "AppContext", return_value=fake_app):
                result = runner.invoke(main.cli, [
                    "export", CHAT_USERNAME,
                    "--format", "json",
                    "--output", output_path,
                ])

            self.assertEqual(result.exit_code, 0, result.output)
            with open(output_path, encoding="utf-8") as f:
                payload = json.load(f)

            self.assertEqual(payload["schema_version"], "wechat-cli.chat_export.v1")
            self.assertEqual(payload["count"], 2)
            self.assertEqual(payload["chat"]["username"], CHAT_USERNAME)
            media = payload["messages"][1]["media"][0]
            self.assertEqual(media["status"], "decoded")
            self.assertEqual(media["width"], 72)
            self.assertEqual(media["height"], 80)
            self.assertTrue(media["path"].startswith("chat_assets/images/"))
            self.assertTrue(os.path.exists(os.path.join(tmp, media["path"])))
            self.assertTrue(os.path.exists(readme_path))
            with open(readme_path, encoding="utf-8") as f:
                readme = f.read()
            self.assertIn("# WeChat JSON Export", readme)
            self.assertIn("schema_version`: `wechat-cli.chat_export.v1`", readme)
            self.assertIn("Resolve every `media[].path` relative to the directory containing `chat.json`.", readme)
            self.assertIn("`chat_assets/images/`", readme)

            with patch.object(main, "AppContext", return_value=fake_app):
                blocked = runner.invoke(main.cli, [
                    "export", CHAT_USERNAME,
                    "--format", "json",
                    "--output", output_path,
                ])
            self.assertNotEqual(blocked.exit_code, 0)
            self.assertIn("--overwrite", blocked.output)

    def test_cli_json_export_uses_resource_db_for_image_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_dir = os.path.join(tmp, "xwechat", "db_storage")
            image_dir = os.path.join(
                tmp, "xwechat", "msg", "attach",
                __import__("hashlib").md5(CHAT_USERNAME.encode()).hexdigest(),
                "2026-06", "Img",
            )
            os.makedirs(image_dir)
            os.makedirs(db_dir)
            resource_hash = "abcdef0123456789abcdef0123456789"
            png = _png_bytes(72, 80)
            with open(os.path.join(image_dir, f"{resource_hash}.dat"), "wb") as f:
                f.write(_xor(png))
            with open(os.path.join(image_dir, "unrelated.dat"), "wb") as f:
                f.write(b"unrelated")

            message_db = os.path.join(tmp, "message.db")
            resource_db = os.path.join(tmp, "message_resource.db")
            ts = int(datetime(2026, 6, 3, 10, 0).timestamp())
            _write_sqlite(message_db, [(2, 3, ts, 1, "<msg><img /></msg>", None)])
            _write_resource_sqlite(resource_db, [(2, 3, ts, resource_hash)])
            fake_app = FakeApp(db_dir, message_db, resource_db=resource_db)
            output_path = os.path.join(tmp, "chat.json")

            runner = CliRunner()
            with patch.object(main, "AppContext", return_value=fake_app):
                result = runner.invoke(main.cli, [
                    "export", CHAT_USERNAME,
                    "--format", "json",
                    "--output", output_path,
                ])

            self.assertEqual(result.exit_code, 0, result.output)
            with open(output_path, encoding="utf-8") as f:
                payload = json.load(f)

            media = payload["messages"][0]["media"][0]
            self.assertEqual(media["status"], "decoded")
            self.assertTrue(media["path"].startswith("chat_assets/images/"))
            self.assertTrue(os.path.exists(os.path.join(tmp, media["path"])))
            self.assertEqual(payload["warnings"], [])

    def test_cli_json_export_requires_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_dir = os.path.join(tmp, "xwechat", "db_storage")
            os.makedirs(db_dir)
            message_db = os.path.join(tmp, "message.db")
            ts = int(datetime(2026, 6, 3, 10, 0).timestamp())
            _write_sqlite(message_db, [(1, 1, ts, 1, "alice:\nhello", None)])
            fake_app = FakeApp(db_dir, message_db)

            runner = CliRunner()
            with patch.object(main, "AppContext", return_value=fake_app):
                result = runner.invoke(main.cli, [
                    "export", CHAT_USERNAME,
                    "--format", "json",
                ])

            self.assertEqual(result.exit_code, 2)
            self.assertIn("--output", result.output)

    def test_markdown_default_still_limits_to_500_messages(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_dir = os.path.join(tmp, "xwechat", "db_storage")
            os.makedirs(db_dir)
            message_db = os.path.join(tmp, "message.db")
            ts = int(datetime(2026, 6, 3, 10, 0).timestamp())
            rows = [
                (i, 1, ts + i, 1, f"alice:\nmessage {i}", None)
                for i in range(1, 502)
            ]
            _write_sqlite(message_db, rows)
            fake_app = FakeApp(db_dir, message_db)

            runner = CliRunner()
            with patch.object(main, "AppContext", return_value=fake_app):
                result = runner.invoke(main.cli, ["export", CHAT_USERNAME])

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(result.output.count("\n- "), 500)


if __name__ == "__main__":
    unittest.main()
