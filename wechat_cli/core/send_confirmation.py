"""发送后的消息数据库交叉确认。

bridge 的内部回执只能证明微信开始或完成了对应任务；最终成功还必须由
当前账号的消息表证明同一个 local_id 已取得 server_id 并进入已发送状态。
"""

from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import sqlite3
import stat
import time

from .messages import _is_safe_msg_table_name


class MessageConfirmationUnavailable(RuntimeError):
    """无法安全读取发送基线或确认消息表。"""


@dataclass(frozen=True)
class MessageBaseline:
    """一次发送前，目标会话每个消息分表的最大 local_id。"""

    username: str
    max_local_ids: dict[tuple[str, str, int, int], int]


@dataclass(frozen=True)
class MessageConfirmation:
    """数据库足以确认服务器接受消息时返回的最小证据。"""

    local_id: int
    server_id: int


def _readonly_connection(path):
    resolved = Path(path).resolve(strict=True)
    return sqlite3.connect(f"{resolved.as_uri()}?mode=ro", uri=True)


def _expected_table_name(username):
    if not isinstance(username, str) or not username:
        return None
    return f"Msg_{hashlib.md5(username.encode('utf-8')).hexdigest()}"


def _table_identity(table, username):
    db_path = table.get("db_path") if isinstance(table, dict) else None
    table_name = table.get("table_name") if isinstance(table, dict) else None
    expected_table_name = _expected_table_name(username)
    if (
        not isinstance(db_path, str)
        or not db_path
        or not isinstance(table_name, str)
        or not _is_safe_msg_table_name(table_name)
        or table_name != expected_table_name
    ):
        return None
    try:
        resolved = Path(db_path).resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except (OSError, RuntimeError):
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_ino <= 0:
        return None
    return (
        str(resolved),
        table_name,
        metadata.st_dev,
        metadata.st_ino,
    )


def _validate_baseline(username, baseline):
    if (
        not isinstance(baseline, MessageBaseline)
        or baseline.username != username
    ):
        raise ValueError("发送基线目标与确认目标不一致")
    if not isinstance(baseline.max_local_ids, dict) or not baseline.max_local_ids:
        raise MessageConfirmationUnavailable("发送基线不包含目标消息表")

    expected_table_name = _expected_table_name(username)
    for identity, maximum in baseline.max_local_ids.items():
        if (
            not isinstance(identity, tuple)
            or len(identity) != 4
            or not isinstance(identity[0], str)
            or not identity[0]
            or identity[1] != expected_table_name
            or isinstance(identity[2], bool)
            or not isinstance(identity[2], int)
            or identity[2] < 0
            or isinstance(identity[3], bool)
            or not isinstance(identity[3], int)
            or identity[3] <= 0
        ):
            raise MessageConfirmationUnavailable("发送基线目标消息表无效")
        if (
            isinstance(maximum, bool)
            or not isinstance(maximum, int)
            or maximum < 0
        ):
            raise MessageConfirmationUnavailable("发送基线 local_id 无效")


class MessageConfirmationStore:
    """从可刷新消息表定位器读取发送基线并轮询最终状态。"""

    def __init__(
        self,
        table_locator,
        *,
        monotonic=time.monotonic,
        sleep=time.sleep,
        poll_interval=0.1,
    ):
        self._table_locator = table_locator
        self._monotonic = monotonic
        self._sleep = sleep
        self._poll_interval = poll_interval

    def _tables(self, username):
        try:
            located = self._table_locator(username)
            if located is None:
                return ()
            if isinstance(located, (str, bytes, bytearray, dict)):
                raise TypeError("invalid target table collection")
            return tuple(located)
        except Exception as error:
            raise MessageConfirmationUnavailable(
                "无法刷新目标消息表"
            ) from error

    def capture_baseline(self, username):
        maxima = {}
        tables = self._tables(username)
        if not tables:
            raise MessageConfirmationUnavailable("未找到目标消息表")
        for table in tables:
            identity = _table_identity(table, username)
            if identity is None:
                raise MessageConfirmationUnavailable(
                    "目标消息表描述无效"
                )
            if identity in maxima:
                raise MessageConfirmationUnavailable(
                    "目标消息表描述重复"
                )
            db_path, table_name, _, _ = identity
            try:
                with _readonly_connection(db_path) as conn:
                    row = conn.execute(
                        f"SELECT MAX(local_id) FROM [{table_name}]"
                    ).fetchone()
            except (OSError, sqlite3.Error) as error:
                raise MessageConfirmationUnavailable(
                    "无法读取目标消息基线"
                ) from error
            if _table_identity(table, username) != identity:
                raise MessageConfirmationUnavailable(
                    "目标消息表在记录基线期间发生变化"
                )
            maximum = row[0] if row else None
            if maximum is None:
                maximum = 0
            elif (
                isinstance(maximum, bool)
                or not isinstance(maximum, int)
                or maximum < 0
            ):
                raise MessageConfirmationUnavailable(
                    "目标消息基线 local_id 无效"
                )
            maxima[identity] = maximum
        return MessageBaseline(username=username, max_local_ids=maxima)

    def find_confirmation(
        self,
        *,
        username,
        self_username,
        local_id,
        text,
        baseline,
    ):
        if (
            (
                local_id is not None
                and (
                    isinstance(local_id, bool)
                    or not isinstance(local_id, int)
                    or local_id <= 0
                )
            )
            or not isinstance(self_username, str)
            or not self_username
            or type(text) is not str
            or not text
        ):
            return None

        _validate_baseline(username, baseline)
        confirmations = []
        tables = self._tables(username)
        if not tables:
            raise MessageConfirmationUnavailable("无法刷新目标消息表")
        seen = set()
        for table in tables:
            identity = _table_identity(table, username)
            if identity is None:
                raise MessageConfirmationUnavailable(
                    "目标消息表描述无效"
                )
            if identity in seen:
                raise MessageConfirmationUnavailable(
                    "目标消息表描述重复"
                )
            seen.add(identity)
            if identity not in baseline.max_local_ids:
                # 发送后新出现的分表没有提交前基线，绝不能用于证明成功。
                continue
            db_path, table_name, _, _ = identity
            maximum = baseline.max_local_ids[identity]
            if local_id is not None and local_id <= maximum:
                continue
            try:
                with _readonly_connection(db_path) as conn:
                    if local_id is None:
                        rows = conn.execute(
                            f"""
                            SELECT local_id, server_id, local_type,
                                   real_sender_id, status, message_content
                            FROM [{table_name}]
                            WHERE local_id > ? AND message_content = ?
                            """,
                            (maximum, text),
                        ).fetchall()
                    else:
                        rows = conn.execute(
                            f"""
                            SELECT local_id, server_id, local_type,
                                   real_sender_id, status, message_content
                            FROM [{table_name}]
                            WHERE local_id = ?
                            LIMIT 2
                            """,
                            (local_id,),
                        ).fetchall()
                        if len(rows) != 1:
                            continue

                    table_confirmations = []
                    for row in rows:
                        (
                            candidate_local_id,
                            server_id,
                            local_type,
                            sender_id,
                            status,
                            message_content,
                        ) = row
                        sender = conn.execute(
                            "SELECT user_name FROM Name2Id WHERE rowid = ?",
                            (sender_id,),
                        ).fetchone()
                        sender_username = (
                            sender[0] if sender and sender[0] else ""
                        )
                        is_text = (
                            isinstance(local_type, int)
                            and not isinstance(local_type, bool)
                            and (local_type & 0xFFFFFFFF) == 1
                        )
                        if (
                            isinstance(candidate_local_id, int)
                            and not isinstance(candidate_local_id, bool)
                            and candidate_local_id > maximum
                            and sender_username == self_username
                            and is_text
                            and status == 2
                            and type(message_content) is str
                            and message_content == text
                            and isinstance(server_id, int)
                            and not isinstance(server_id, bool)
                            and server_id > 0
                        ):
                            table_confirmations.append(
                                MessageConfirmation(
                                    local_id=candidate_local_id,
                                    server_id=server_id,
                                )
                            )
            except (OSError, sqlite3.Error):
                continue
            if _table_identity(table, username) != identity:
                raise MessageConfirmationUnavailable(
                    "目标消息表在确认期间发生变化"
                )
            confirmations.extend(table_confirmations)

        if len(confirmations) != 1:
            return None
        return confirmations[0]

    def poll_confirmation(
        self,
        *,
        username,
        self_username,
        local_id,
        text,
        baseline,
        timeout,
    ):
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout < 0
        ):
            raise ValueError("确认 timeout 必须是非负有限数")

        deadline = self._monotonic() + timeout
        while True:
            confirmation = self.find_confirmation(
                username=username,
                self_username=self_username,
                local_id=local_id,
                text=text,
                baseline=baseline,
            )
            if confirmation is not None:
                return confirmation

            now = self._monotonic()
            if now >= deadline:
                return None
            self._sleep(min(self._poll_interval, deadline - now))
