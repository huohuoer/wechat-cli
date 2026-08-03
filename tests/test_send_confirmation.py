import hashlib
import sqlite3

import pytest

from wechat_cli.core.send_confirmation import (
    MessageBaseline,
    MessageConfirmation,
    MessageConfirmationUnavailable,
    MessageConfirmationStore,
)


USERNAME = "room@chatroom"
TABLE = f"Msg_{hashlib.md5(USERNAME.encode()).hexdigest()}"
OTHER_TABLE = f"Msg_{hashlib.md5(b'other@chatroom').hexdigest()}"
MESSAGE_TEXT = "消息"


def _create_message_db(path, rows=(), names=(), table_name=TABLE):
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE Name2Id (user_name TEXT)"
        )
        for rowid, username in names:
            conn.execute(
                "INSERT INTO Name2Id(rowid, user_name) VALUES (?, ?)",
                (rowid, username),
            )
        conn.execute(
            f"""
            CREATE TABLE [{table_name}] (
                local_id INTEGER,
                server_id INTEGER,
                local_type INTEGER,
                real_sender_id INTEGER,
                status INTEGER,
                message_content TEXT
            )
            """
        )
        for row in rows:
            values = row if len(row) == 6 else (*row, MESSAGE_TEXT)
            conn.execute(
                f"""
                INSERT INTO [{table_name}]
                    (local_id, server_id, local_type, real_sender_id, status,
                     message_content)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                values,
            )
        conn.commit()
    finally:
        conn.close()


def _locator_for(path):
    return lambda username: [
        {"db_path": str(path), "table_name": TABLE}
    ]


def _identity(path, table_name=TABLE):
    resolved = path.resolve()
    metadata = resolved.stat()
    return (
        str(resolved),
        table_name,
        metadata.st_dev,
        metadata.st_ino,
    )


def test_capture_baseline_records_max_local_id_per_database_table(tmp_path):
    db_path = tmp_path / "message.db"
    _create_message_db(
        db_path,
        rows=[
            (10, 100, 1, 1, 2),
            (17, 101, 1, 1, 2),
        ],
        names=[(1, "wxid_me")],
    )
    store = MessageConfirmationStore(_locator_for(db_path))

    baseline = store.capture_baseline("room@chatroom")

    assert baseline == MessageBaseline(
        username="room@chatroom",
        max_local_ids={_identity(db_path): 17},
    )


def test_confirmation_requires_new_outgoing_text_status_and_server_id(tmp_path):
    db_path = tmp_path / "message.db"
    _create_message_db(
        db_path,
        rows=[
            (20, 200, 1, 7, 2),
            (21, 201, 1, 7, 2),
        ],
        names=[(7, "wxid_me")],
    )
    store = MessageConfirmationStore(_locator_for(db_path))
    baseline = MessageBaseline(
        username="room@chatroom",
        max_local_ids={_identity(db_path): 20},
    )

    confirmation = store.find_confirmation(
        username="room@chatroom",
        self_username="wxid_me",
        local_id=21,
        text=MESSAGE_TEXT,
        baseline=baseline,
    )

    assert confirmation == MessageConfirmation(local_id=21, server_id=201)


def test_confirmation_discovers_only_unique_new_matching_text_without_local_id(
    tmp_path,
):
    db_path = tmp_path / "message.db"
    _create_message_db(
        db_path,
        rows=[
            (20, 200, 1, 7, 2),
            (21, 201, 1, 8, 2),
            (22, 0, 1, 7, 2),
            (23, 203, 1, 7, 1),
            (24, 204, 3, 7, 2),
            (25, 205, 1, 7, 2, "另一条消息"),
            (26, 206, 1, 7, 2),
        ],
        names=[(7, "wxid_me"), (8, "wxid_other")],
    )
    store = MessageConfirmationStore(_locator_for(db_path))

    confirmation = store.find_confirmation(
        username=USERNAME,
        self_username="wxid_me",
        local_id=None,
        text=MESSAGE_TEXT,
        baseline=MessageBaseline(
            username=USERNAME,
            max_local_ids={_identity(db_path): 20},
        ),
    )

    assert confirmation == MessageConfirmation(local_id=26, server_id=206)


def test_confirmation_uses_each_table_baseline_when_local_id_is_missing(
    tmp_path,
):
    first_db = tmp_path / "first.db"
    second_db = tmp_path / "second.db"
    _create_message_db(
        first_db,
        rows=[(11, 101, 1, 7, 2)],
        names=[(7, "wxid_me")],
    )
    _create_message_db(
        second_db,
        rows=[(50, 500, 1, 7, 2)],
        names=[(7, "wxid_me")],
    )
    store = MessageConfirmationStore(
        lambda username: [
            {"db_path": str(first_db), "table_name": TABLE},
            {"db_path": str(second_db), "table_name": TABLE},
        ]
    )

    confirmation = store.find_confirmation(
        username=USERNAME,
        self_username="wxid_me",
        local_id=None,
        text=MESSAGE_TEXT,
        baseline=MessageBaseline(
            username=USERNAME,
            max_local_ids={
                _identity(first_db): 10,
                _identity(second_db): 50,
            },
        ),
    )

    assert confirmation == MessageConfirmation(local_id=11, server_id=101)


def test_confirmation_returns_none_when_missing_local_id_match_is_ambiguous(
    tmp_path,
):
    first_db = tmp_path / "first.db"
    second_db = tmp_path / "second.db"
    _create_message_db(
        first_db,
        rows=[(11, 101, 1, 7, 2)],
        names=[(7, "wxid_me")],
    )
    _create_message_db(
        second_db,
        rows=[(51, 501, 1, 7, 2)],
        names=[(7, "wxid_me")],
    )
    store = MessageConfirmationStore(
        lambda username: [
            {"db_path": str(first_db), "table_name": TABLE},
            {"db_path": str(second_db), "table_name": TABLE},
        ]
    )

    confirmation = store.find_confirmation(
        username=USERNAME,
        self_username="wxid_me",
        local_id=None,
        text=MESSAGE_TEXT,
        baseline=MessageBaseline(
            username=USERNAME,
            max_local_ids={
                _identity(first_db): 10,
                _identity(second_db): 50,
            },
        ),
    )

    assert confirmation is None


def test_confirmation_rejects_matching_id_with_different_text(tmp_path):
    db_path = tmp_path / "message.db"
    _create_message_db(
        db_path,
        rows=[(21, 201, 1, 7, 2, "另一条消息")],
        names=[(7, "wxid_me")],
    )
    store = MessageConfirmationStore(_locator_for(db_path))
    baseline = MessageBaseline(
        username=USERNAME,
        max_local_ids={_identity(db_path): 20},
    )

    confirmation = store.find_confirmation(
        username=USERNAME,
        self_username="wxid_me",
        local_id=21,
        text="预期消息",
        baseline=baseline,
    )

    assert confirmation is None


@pytest.mark.parametrize(
    "row",
    [
        (21, 201, 1, 8, 2),   # another sender
        (21, 0, 1, 7, 2),     # no server acknowledgement
        (21, 201, 1, 7, 1),   # not in final sent state
        (21, 201, 3, 7, 2),   # not a text message
        (20, 201, 1, 7, 2),   # existed at or before the baseline
    ],
)
def test_confirmation_fails_closed_for_non_matching_rows(tmp_path, row):
    db_path = tmp_path / "message.db"
    _create_message_db(
        db_path,
        rows=[row],
        names=[(7, "wxid_me"), (8, "wxid_other")],
    )
    store = MessageConfirmationStore(_locator_for(db_path))
    baseline = MessageBaseline(
        username="room@chatroom",
        max_local_ids={_identity(db_path): 20},
    )

    confirmation = store.find_confirmation(
        username="room@chatroom",
        self_username="wxid_me",
        local_id=row[0],
        text=MESSAGE_TEXT,
        baseline=baseline,
    )

    assert confirmation is None


def test_confirmation_rejects_wrong_target_baseline(tmp_path):
    db_path = tmp_path / "message.db"
    _create_message_db(
        db_path,
        rows=[(21, 201, 1, 7, 2)],
        names=[(7, "wxid_me")],
    )
    store = MessageConfirmationStore(_locator_for(db_path))

    with pytest.raises(ValueError, match="目标"):
        store.find_confirmation(
            username="room@chatroom",
            self_username="wxid_me",
            local_id=21,
            text=MESSAGE_TEXT,
            baseline=MessageBaseline(
                username="other@chatroom",
                max_local_ids={},
            ),
        )


def test_confirmation_rejects_unsafe_table_name_before_sql(tmp_path):
    db_path = tmp_path / "message.db"
    _create_message_db(db_path)
    store = MessageConfirmationStore(
        lambda username: [
            {
                "db_path": str(db_path),
                "table_name": f"{TABLE}] WHERE 1=1 --",
            }
        ]
    )

    with pytest.raises(MessageConfirmationUnavailable, match="消息表"):
        store.capture_baseline("room@chatroom")


def test_capture_baseline_rejects_safe_looking_table_for_another_target(tmp_path):
    db_path = tmp_path / "message.db"
    _create_message_db(
        db_path,
        rows=[(21, 201, 1, 7, 2)],
        names=[(7, "wxid_me")],
        table_name=OTHER_TABLE,
    )
    store = MessageConfirmationStore(
        lambda username: [
            {"db_path": str(db_path), "table_name": OTHER_TABLE}
        ]
    )

    with pytest.raises(MessageConfirmationUnavailable, match="目标"):
        store.capture_baseline(USERNAME)


def test_capture_baseline_rejects_empty_target_table_set():
    store = MessageConfirmationStore(lambda username: [])

    with pytest.raises(MessageConfirmationUnavailable, match="消息表"):
        store.capture_baseline(USERNAME)


def test_capture_baseline_rejects_empty_target_table_iterator():
    store = MessageConfirmationStore(lambda username: iter(()))

    with pytest.raises(MessageConfirmationUnavailable, match="消息表"):
        store.capture_baseline(USERNAME)


def test_capture_baseline_rejects_non_integer_maximum(tmp_path):
    db_path = tmp_path / "message.db"
    _create_message_db(
        db_path,
        rows=[("corrupt-local-id", 201, 1, 7, 2)],
        names=[(7, "wxid_me")],
    )
    store = MessageConfirmationStore(_locator_for(db_path))

    with pytest.raises(MessageConfirmationUnavailable, match="基线"):
        store.capture_baseline(USERNAME)


def test_confirmation_never_accepts_table_discovered_after_baseline(tmp_path):
    baseline_db = tmp_path / "baseline.db"
    late_db = tmp_path / "late.db"
    _create_message_db(
        baseline_db,
        rows=[(20, 200, 1, 7, 2)],
        names=[(7, "wxid_me")],
    )
    _create_message_db(
        late_db,
        rows=[(21, 201, 1, 7, 2)],
        names=[(7, "wxid_me")],
    )
    calls = 0

    def locator(username):
        nonlocal calls
        calls += 1
        path = baseline_db if calls == 1 else late_db
        return [{"db_path": str(path), "table_name": TABLE}]

    store = MessageConfirmationStore(locator)
    baseline = store.capture_baseline(USERNAME)

    assert store.find_confirmation(
        username=USERNAME,
        self_username="wxid_me",
        local_id=21,
        text=MESSAGE_TEXT,
        baseline=baseline,
    ) is None


def test_confirmation_never_accepts_database_replaced_at_baseline_path(tmp_path):
    db_path = tmp_path / "message.db"
    original_path = tmp_path / "message-before-send.db"
    _create_message_db(
        db_path,
        rows=[(20, 200, 1, 7, 2)],
        names=[(7, "wxid_me")],
    )
    store = MessageConfirmationStore(_locator_for(db_path))
    baseline = store.capture_baseline(USERNAME)

    db_path.rename(original_path)
    _create_message_db(
        db_path,
        rows=[(21, 999, 1, 7, 2)],
        names=[(7, "wxid_me")],
    )

    assert store.find_confirmation(
        username=USERNAME,
        self_username="wxid_me",
        local_id=21,
        text=MESSAGE_TEXT,
        baseline=baseline,
    ) is None


def test_confirmation_rejects_empty_refreshed_table_iterator(tmp_path):
    db_path = tmp_path / "message.db"
    _create_message_db(
        db_path,
        rows=[(20, 200, 1, 7, 2)],
        names=[(7, "wxid_me")],
    )
    calls = 0

    def locator(username):
        nonlocal calls
        calls += 1
        if calls == 1:
            return iter(({"db_path": str(db_path), "table_name": TABLE},))
        return iter(())

    store = MessageConfirmationStore(locator)
    baseline = store.capture_baseline(USERNAME)

    with pytest.raises(MessageConfirmationUnavailable, match="消息表"):
        store.find_confirmation(
            username=USERNAME,
            self_username="wxid_me",
            local_id=21,
            text=MESSAGE_TEXT,
            baseline=baseline,
        )


def test_confirmation_rejects_empty_or_wrong_table_baseline(tmp_path):
    db_path = tmp_path / "message.db"
    _create_message_db(
        db_path,
        rows=[(21, 201, 1, 7, 2)],
        names=[(7, "wxid_me")],
    )
    store = MessageConfirmationStore(_locator_for(db_path))

    with pytest.raises(MessageConfirmationUnavailable, match="基线"):
        store.find_confirmation(
            username=USERNAME,
            self_username="wxid_me",
            local_id=21,
            text=MESSAGE_TEXT,
            baseline=MessageBaseline(username=USERNAME, max_local_ids={}),
        )

    with pytest.raises(MessageConfirmationUnavailable, match="目标"):
        store.find_confirmation(
            username=USERNAME,
            self_username="wxid_me",
            local_id=21,
            text=MESSAGE_TEXT,
            baseline=MessageBaseline(
                username=USERNAME,
                max_local_ids={_identity(db_path, OTHER_TABLE): 20},
            ),
        )


def test_capture_baseline_surfaces_locator_failure_before_send():
    def fail_locator(username):
        raise PermissionError("cache unavailable")

    store = MessageConfirmationStore(fail_locator)

    with pytest.raises(MessageConfirmationUnavailable, match="消息表"):
        store.capture_baseline("room@chatroom")


def test_capture_baseline_surfaces_database_failure_before_send(tmp_path):
    db_path = tmp_path / "not-sqlite.db"
    db_path.write_text("not sqlite", encoding="utf-8")
    store = MessageConfirmationStore(_locator_for(db_path))

    with pytest.raises(MessageConfirmationUnavailable, match="基线"):
        store.capture_baseline("room@chatroom")


def test_poll_refreshes_locator_until_row_is_server_accepted(tmp_path):
    db_path = tmp_path / "message.db"
    _create_message_db(
        db_path,
        rows=[(21, 0, 1, 7, 1)],
        names=[(7, "wxid_me")],
    )
    calls = 0

    def locator(username):
        nonlocal calls
        calls += 1
        if calls == 3:
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    f"""
                    UPDATE [{TABLE}]
                    SET server_id = 501, status = 2
                    WHERE local_id = 21
                    """
                )
                conn.commit()
            finally:
                conn.close()
        return [{"db_path": str(db_path), "table_name": TABLE}]

    now = 0.0

    def monotonic():
        return now

    def sleep(seconds):
        nonlocal now
        now += seconds

    store = MessageConfirmationStore(
        locator,
        monotonic=monotonic,
        sleep=sleep,
        poll_interval=0.1,
    )

    confirmation = store.poll_confirmation(
        username="room@chatroom",
        self_username="wxid_me",
        local_id=21,
        text=MESSAGE_TEXT,
        baseline=MessageBaseline(
            username="room@chatroom",
            max_local_ids={_identity(db_path): 20},
        ),
        timeout=1.0,
    )

    assert confirmation == MessageConfirmation(local_id=21, server_id=501)
    assert calls == 3


def test_poll_timeout_returns_none_without_retrying_send(tmp_path):
    db_path = tmp_path / "message.db"
    _create_message_db(
        db_path,
        rows=[(21, 0, 1, 7, 1)],
        names=[(7, "wxid_me")],
    )
    calls = 0

    def locator(username):
        nonlocal calls
        calls += 1
        return [{"db_path": str(db_path), "table_name": TABLE}]

    now = 0.0

    def monotonic():
        return now

    def sleep(seconds):
        nonlocal now
        now += seconds

    store = MessageConfirmationStore(
        locator,
        monotonic=monotonic,
        sleep=sleep,
        poll_interval=0.1,
    )

    confirmation = store.poll_confirmation(
        username="room@chatroom",
        self_username="wxid_me",
        local_id=21,
        text=MESSAGE_TEXT,
        baseline=MessageBaseline(
            username="room@chatroom",
            max_local_ids={_identity(db_path): 20},
        ),
        timeout=0.25,
    )

    assert confirmation is None
    assert calls == 4


@pytest.mark.parametrize("local_id", [0, -1, True, "21"])
def test_confirmation_rejects_invalid_local_id_without_query(tmp_path, local_id):
    calls = []
    store = MessageConfirmationStore(
        lambda username: calls.append(username) or []
    )

    assert store.find_confirmation(
        username="room@chatroom",
        self_username="wxid_me",
        local_id=local_id,
        text=MESSAGE_TEXT,
        baseline=MessageBaseline(
            username="room@chatroom",
            max_local_ids={},
        ),
    ) is None
    assert calls == []
