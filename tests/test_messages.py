import unittest

from wechat_cli.core.messages import find_msg_db_keys


class MessageDatabaseDiscoveryTests(unittest.TestCase):
    def test_discovers_standard_and_business_message_shards(self):
        keys = {
            "message/message_7.db": {},
            "message/biz_message_2.db": {},
            "message/notmessage_9.db": {},
            "message/contact.db": {},
            "session/session.db": {},
        }
        self.assertEqual(
            find_msg_db_keys(keys),
            ["message/biz_message_2.db", "message/message_7.db"],
        )


if __name__ == "__main__":
    unittest.main()
