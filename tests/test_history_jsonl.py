"""测试 history 命令的 jsonl 输出格式。

不依赖真实 WeChat 数据库 — 直接测试 _build_history_record 与 output_jsonl
两个新增函数的契约。
"""

import io
import json
import unittest

from wechat_cli.core.messages import _build_history_record
from wechat_cli.output.formatter import output_jsonl


def _display_name_fn(username, names):
    return names.get(username, username)


class BuildHistoryRecordTest(unittest.TestCase):

    def _row(self, **kw):
        # (local_id, local_type, create_time, real_sender_id, content, ct)
        return (
            kw.get('local_id', 1),
            kw.get('local_type', 1),
            kw.get('create_time', 1714048200),
            kw.get('real_sender_id', 100),
            kw.get('content', '今晚发你 deck'),
            kw.get('ct', 0),
        )

    def test_one_to_one_self_message(self):
        ctx = {
            'username': 'wxid_zhangsicheng', 'display_name': '章师诚',
            'is_group': False,
        }
        # In 1:1, real_sender_id=100 maps to "wxid_me" (NOT chat_username) → is_self=True
        id_to_username = {100: 'wxid_me'}
        names = {'wxid_zhangsicheng': '章师诚', 'wxid_me': '我'}
        _, rec = _build_history_record(self._row(), ctx, names, id_to_username, _display_name_fn)
        self.assertEqual(rec['local_id'], 1)
        self.assertEqual(rec['create_time'], 1714048200)
        self.assertEqual(rec['msg_type'], '文本')
        self.assertEqual(rec['local_type'], 1)
        self.assertTrue(rec['is_self'])
        self.assertEqual(rec['sender_id'], 'wxid_me')
        self.assertEqual(rec['is_group'], False)
        self.assertEqual(rec['chat_username'], 'wxid_zhangsicheng')
        self.assertEqual(rec['chat_display'], '章师诚')
        self.assertEqual(rec['text'], '今晚发你 deck')

    def test_one_to_one_other_party_message(self):
        ctx = {
            'username': 'wxid_zhangsicheng', 'display_name': '章师诚',
            'is_group': False,
        }
        # real_sender_id maps back to chat_username → is_self=False, sender is the contact
        id_to_username = {100: 'wxid_zhangsicheng'}
        names = {'wxid_zhangsicheng': '章师诚'}
        _, rec = _build_history_record(self._row(), ctx, names, id_to_username, _display_name_fn)
        self.assertFalse(rec['is_self'])
        self.assertEqual(rec['sender_id'], 'wxid_zhangsicheng')
        self.assertEqual(rec['sender_display'], '章师诚')

    def test_group_message(self):
        ctx = {
            'username': '12345@chatroom', 'display_name': 'AI交流群',
            'is_group': True,
        }
        # group: content has "wxid_alice:\ntext" prefix; real_sender_id resolves
        # to wxid_alice via Name2Id (id_to_username).
        row = self._row(real_sender_id=100, content='wxid_alice:\n大家好')
        id_to_username = {100: 'wxid_alice'}
        names = {'wxid_alice': 'Alice', '12345@chatroom': 'AI交流群'}
        _, rec = _build_history_record(row, ctx, names, id_to_username, _display_name_fn)
        self.assertTrue(rec['is_group'])
        self.assertEqual(rec['chat_username'], '12345@chatroom')
        self.assertEqual(rec['sender_id'], 'wxid_alice')
        self.assertEqual(rec['sender_display'], 'Alice')
        self.assertFalse(rec['is_self'])
        self.assertEqual(rec['text'], '大家好')

    def test_group_self_message(self):
        ctx = {
            'username': '12345@chatroom', 'display_name': 'AI交流群',
            'is_group': True,
        }
        # group + self: real_sender_id is unknown to Name2Id and content has no
        # "sender:\n" prefix → both sender_username and sender_from_content empty.
        row = self._row(real_sender_id=999, content='我说的话')
        _, rec = _build_history_record(row, ctx, {}, {}, _display_name_fn)
        self.assertTrue(rec['is_self'])
        self.assertEqual(rec['sender_id'], '')
        self.assertEqual(rec['text'], '我说的话')

    def test_required_fields_present(self):
        ctx = {'username': 'wxid_x', 'display_name': 'X', 'is_group': False}
        _, rec = _build_history_record(
            self._row(), ctx, {}, {}, _display_name_fn,
        )
        for key in (
            'local_id', 'create_time', 'msg_type', 'local_type', 'is_self',
            'sender_id', 'sender_display', 'is_group', 'chat_username',
            'chat_display', 'text',
        ):
            self.assertIn(key, rec, f'missing field: {key}')


class OutputJsonlTest(unittest.TestCase):

    def test_one_object_per_line_and_valid_json(self):
        records = [
            {'local_id': 1, 'text': 'hello', 'is_self': False},
            {'local_id': 2, 'text': '中文消息', 'is_self': True},
            {'local_id': 3, 'text': 'line\nwith\nbreaks', 'is_self': False},
        ]
        buf = io.StringIO()
        output_jsonl(records, file=buf)
        lines = buf.getvalue().rstrip('\n').split('\n')
        self.assertEqual(len(lines), len(records))
        for line, expected in zip(lines, records):
            parsed = json.loads(line)
            self.assertEqual(parsed, expected)

    def test_unicode_not_escaped(self):
        buf = io.StringIO()
        output_jsonl([{'text': '章师诚'}], file=buf)
        self.assertIn('章师诚', buf.getvalue())


if __name__ == '__main__':
    unittest.main()
