import hashlib
import hmac
import struct
import tempfile
import unittest
from pathlib import Path

from Crypto.Cipher import AES

from wechat_cli.core.crypto import SQLITE_HDR, decrypt_page
from wechat_cli.keys.common import verify_derived_keys
from wechat_cli.keys.scanner_macos import _validated_keys


class DerivedCryptoTests(unittest.TestCase):
    def setUp(self):
        self.encryption_key = bytes(range(32))
        self.hmac_key = bytes(range(32, 64))
        salt = b"s" * 16
        iv = b"i" * 16
        plaintext = b"\x10\x00\x01\x01\x50\x40\x20\x20" + bytes(3992)
        encrypted = AES.new(
            self.encryption_key, AES.MODE_CBC, iv
        ).encrypt(plaintext)
        authenticated = encrypted + iv + struct.pack("<I", 1)
        digest = hmac.new(self.hmac_key, authenticated, hashlib.sha512).digest()
        self.page = salt + encrypted + iv + digest

    def test_verifies_and_decrypts_derived_pair(self):
        self.assertTrue(
            verify_derived_keys(self.encryption_key, self.hmac_key, self.page)
        )
        decrypted = decrypt_page(
            self.encryption_key, self.page, 1, self.hmac_key
        )
        self.assertEqual(decrypted[:16], SQLITE_HDR)
        self.assertEqual(len(decrypted), 4096)

    def test_rejects_wrong_hmac_key(self):
        self.assertFalse(
            verify_derived_keys(self.encryption_key, bytes(32), self.page)
        )
        with self.assertRaisesRegex(ValueError, "HMAC verification failed"):
            decrypt_page(self.encryption_key, self.page, 1, bytes(32))

    def test_existing_derived_key_is_reverified_and_enriched(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory, "message", "message_7.db")
            db_path.parent.mkdir()
            db_path.write_bytes(self.page)
            payload = {
                "message/message_7.db": {
                    "key_type": "sqlcipher_derived_pair",
                    "derived_encryption_key": self.encryption_key.hex(),
                    "derived_hmac_key": self.hmac_key.hex(),
                },
                "message/missing.db": {"enc_key": bytes(32).hex()},
            }
            validated = _validated_keys(directory, payload)
        self.assertEqual(list(validated), ["message/message_7.db"])
        self.assertEqual(validated["message/message_7.db"]["salt"], (b"s" * 16).hex())


if __name__ == "__main__":
    unittest.main()
