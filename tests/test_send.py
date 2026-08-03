import importlib
import json
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

import wechat_cli.main as main_module


def _sending_module():
    try:
        return importlib.import_module("wechat_cli.core.sending")
    except ModuleNotFoundError:
        pytest.fail("wechat_cli.core.sending 尚未实现")


def _contact_rows(*rows):
    return [
        {"username": username, "nick_name": nick_name, "remark": remark}
        for username, nick_name, remark in rows
    ]


def _install_contacts(monkeypatch, names, full=None):
    sending = _sending_module()
    monkeypatch.setattr(sending, "get_contact_names", lambda cache, decrypted_dir: names)
    monkeypatch.setattr(
        sending,
        "get_contact_full",
        lambda cache, decrypted_dir: full if full is not None else [],
    )
    return sending


def _invoke_send(monkeypatch, service, args, names=None, full=None):
    _install_contacts(
        monkeypatch,
        names if names is not None else {"room@chatroom": "精确群名"},
        full=full,
    )
    app = SimpleNamespace(
        cache=object(),
        decrypted_dir="/unused",
        send_service=service,
    )
    monkeypatch.setattr(main_module, "AppContext", lambda config_path=None: app)
    return CliRunner().invoke(main_module.cli, ["send", *args])


class RecordingSendService:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.requests = []

    def send_text(self, request):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.result


def test_send_resolver_accepts_existing_chatroom_username(monkeypatch):
    sending = _install_contacts(
        monkeypatch,
        {"room@chatroom": "研发群", "wxid_alice": "Alice"},
    )

    target = sending.resolve_send_group(
        "room@chatroom",
        cache=object(),
        decrypted_dir="/unused",
    )

    assert target.group == "研发群"
    assert target.username == "room@chatroom"


def test_send_resolver_accepts_only_exact_group_display_name(monkeypatch):
    sending = _install_contacts(
        monkeypatch,
        {"room@chatroom": "研发群"},
    )

    target = sending.resolve_send_group("研发群", object(), "/unused")

    assert target.username == "room@chatroom"
    with pytest.raises(sending.SendTargetError):
        sending.resolve_send_group("研发", object(), "/unused")
    with pytest.raises(sending.SendTargetError):
        sending.resolve_send_group("研发群 ", object(), "/unused")


def test_send_resolver_rejects_duplicate_group_display_name(monkeypatch):
    sending = _install_contacts(
        monkeypatch,
        {
            "room-one@chatroom": "同名群",
            "room-two@chatroom": "同名群",
        },
    )

    with pytest.raises(sending.SendTargetError, match="多个群聊"):
        sending.resolve_send_group("同名群", object(), "/unused")


def test_send_resolver_deduplicates_repeated_contact_rows_by_username(monkeypatch):
    sending = _install_contacts(
        monkeypatch,
        {},
        full=_contact_rows(
            ("room@chatroom", "唯一群", ""),
            ("room@chatroom", "唯一群", ""),
        ),
    )

    target = sending.resolve_send_group("唯一群", object(), "/unused")

    assert target.username == "room@chatroom"


def test_send_resolver_uses_existing_remark_then_nickname_display_rule(monkeypatch):
    sending = _install_contacts(
        monkeypatch,
        {},
        full=_contact_rows(
            ("remark@chatroom", "昵称群", "备注群"),
            ("nick@chatroom", "昵称唯一群", ""),
        ),
    )

    remark_target = sending.resolve_send_group("备注群", object(), "/unused")
    nick_target = sending.resolve_send_group("昵称唯一群", object(), "/unused")

    assert remark_target.username == "remark@chatroom"
    assert nick_target.username == "nick@chatroom"


def test_send_resolver_rejects_forged_chatroom_username(monkeypatch):
    sending = _install_contacts(
        monkeypatch,
        {"real@chatroom": "fake@chatroom"},
    )

    with pytest.raises(sending.SendTargetError, match="联系人库"):
        sending.resolve_send_group("fake@chatroom", object(), "/unused")


@pytest.mark.parametrize("query", ["wxid_alice", "Alice"])
def test_send_resolver_rejects_non_group_contact(monkeypatch, query):
    sending = _install_contacts(
        monkeypatch,
        {"wxid_alice": "Alice"},
    )

    with pytest.raises(sending.SendTargetError):
        sending.resolve_send_group(query, object(), "/unused")


@pytest.mark.parametrize("text", ["", "   ", "\n\t"])
def test_send_rejects_empty_or_whitespace_text_with_exit_2(monkeypatch, text):
    service = RecordingSendService()

    result = _invoke_send(
        monkeypatch,
        service,
        ["精确群名", text, "--format", "json"],
    )

    assert result.exit_code == 2
    assert json.loads(result.stdout)["status"] == "input_error"
    assert result.stderr == ""
    assert service.requests == []


@pytest.mark.parametrize("timeout", ["0", "-1", "nan", "inf"])
def test_send_rejects_non_positive_or_non_finite_timeout_with_exit_2(
    monkeypatch,
    timeout,
):
    service = RecordingSendService()

    result = _invoke_send(
        monkeypatch,
        service,
        ["精确群名", "hello", "--timeout", timeout, "--format", "json"],
    )

    assert result.exit_code == 2
    assert json.loads(result.stdout)["status"] == "input_error"
    assert service.requests == []


def test_send_preserves_unicode_newlines_and_shell_special_characters(monkeypatch):
    sending = _sending_module()
    text = "你好 👋\n第二行 $HOME `echo nope` ; & | < > \" '"
    service = RecordingSendService(
        result=sending.SendResult.sent(
            request_id="req-1",
            group="精确群名",
            username="room@chatroom",
            local_id=123,
            server_id=456,
        )
    )

    result = _invoke_send(
        monkeypatch,
        service,
        ["精确群名", text, "--timeout", "2.5", "--format", "json"],
    )

    assert result.exit_code == 0
    assert len(service.requests) == 1
    assert service.requests[0].text == text
    assert service.requests[0].timeout == 2.5


def test_send_success_json_contract(monkeypatch):
    sending = _sending_module()
    service = RecordingSendService(
        result=sending.SendResult.sent(
            request_id="req-success",
            group="精确群名",
            username="room@chatroom",
            local_id=41,
            server_id=99,
        )
    )

    result = _invoke_send(
        monkeypatch,
        service,
        ["精确群名", "原样消息", "--format", "json"],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {
        "success": True,
        "status": "server_accepted",
        "request_id": "req-success",
        "group": "精确群名",
        "username": "room@chatroom",
        "local_id": 41,
        "server_id": 99,
    }
    assert result.stderr == ""


def test_send_target_error_is_json_and_exit_1(monkeypatch):
    service = RecordingSendService()

    result = _invoke_send(
        monkeypatch,
        service,
        ["不存在", "hello", "--format", "json"],
    )

    payload = json.loads(result.stdout)
    assert result.exit_code == 1
    assert payload["success"] is False
    assert payload["status"] == "target_error"
    assert service.requests == []


@pytest.mark.parametrize(
    "contact_failure",
    ["empty", "permission-error"],
)
def test_send_contact_store_failure_is_pre_send_unavailable_exit_3(
    monkeypatch,
    contact_failure,
):
    sending = _sending_module()
    service = RecordingSendService()
    if contact_failure == "permission-error":
        def fail_contact_names(cache, decrypted_dir):
            raise PermissionError("contact.db 不可读")

        monkeypatch.setattr(sending, "get_contact_names", fail_contact_names)
        monkeypatch.setattr(
            sending,
            "get_contact_full",
            lambda cache, decrypted_dir: [],
        )
    else:
        monkeypatch.setattr(
            sending,
            "get_contact_names",
            lambda cache, decrypted_dir: {},
        )
        monkeypatch.setattr(
            sending,
            "get_contact_full",
            lambda cache, decrypted_dir: [],
        )
    app = SimpleNamespace(
        cache=object(),
        decrypted_dir="/unused",
        send_service=service,
    )
    monkeypatch.setattr(main_module, "AppContext", lambda config_path=None: app)

    result = CliRunner().invoke(
        main_module.cli,
        ["send", "精确群名", "hello", "--format", "json"],
    )

    payload = json.loads(result.stdout)
    assert result.exit_code == 3
    assert payload["success"] is False
    assert payload["status"] == "unavailable"
    assert "联系人" in payload["error"]
    assert "未发送" in payload["error"]
    assert service.requests == []


def test_send_default_backend_fails_closed_with_exit_3(monkeypatch):
    _install_contacts(monkeypatch, {"room@chatroom": "精确群名"})
    app = SimpleNamespace(cache=object(), decrypted_dir="/unused")
    monkeypatch.setattr(main_module, "AppContext", lambda config_path=None: app)

    result = CliRunner().invoke(
        main_module.cli,
        ["send", "精确群名", "hello", "--format", "json"],
    )

    payload = json.loads(result.stdout)
    assert result.exit_code == 3
    assert payload["success"] is False
    assert payload["status"] == "unavailable"
    assert "当前构建" in payload["error"]
    assert "bridge" in payload["error"]
    assert "未发送" in payload["error"]


@pytest.mark.parametrize(
    "init_error",
    [
        FileNotFoundError("密钥文件不存在"),
        RuntimeError("配置损坏"),
    ],
    ids=["missing-keys", "unexpected-init-error"],
)
@pytest.mark.parametrize("fmt", ["json", "text"])
def test_send_app_context_failure_is_pre_send_unavailable_exit_3(
    monkeypatch,
    init_error,
    fmt,
):
    def fail_app_context(config_path=None):
        raise type(init_error)(str(init_error))

    service_lookups = []
    send_command = importlib.import_module("wechat_cli.commands.send")
    monkeypatch.setattr(main_module, "AppContext", fail_app_context)
    monkeypatch.setattr(
        send_command,
        "get_send_service",
        lambda app: service_lookups.append(app),
    )

    result = CliRunner().invoke(
        main_module.cli,
        ["send", "精确群名", "hello", "--format", fmt],
    )

    assert result.exit_code == 3
    assert service_lookups == []
    if fmt == "json":
        payload = json.loads(result.stdout)
        assert payload["success"] is False
        assert payload["status"] == "unavailable"
        assert "未发送" in payload["error"]
        assert result.stderr == ""
    else:
        assert result.stdout == ""
        assert "发送失败" in result.stderr
        assert "未发送" in result.stderr


def test_send_input_validation_precedes_app_context_failure(monkeypatch):
    def fail_app_context(config_path=None):
        raise FileNotFoundError("密钥文件不存在")

    monkeypatch.setattr(main_module, "AppContext", fail_app_context)

    result = CliRunner().invoke(
        main_module.cli,
        ["send", "精确群名", "   ", "--format", "json"],
    )

    assert result.exit_code == 2
    assert json.loads(result.stdout)["status"] == "input_error"
    assert result.stderr == ""


def test_other_commands_keep_existing_app_context_failure_exit_1(monkeypatch):
    def fail_app_context(config_path=None):
        raise FileNotFoundError("密钥文件不存在")

    monkeypatch.setattr(main_module, "AppContext", fail_app_context)

    result = CliRunner().invoke(main_module.cli, ["sessions"])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == "密钥文件不存在\n"


def test_send_unknown_result_exits_4_and_forbids_automatic_retry(monkeypatch):
    sending = _sending_module()
    service = RecordingSendService(
        result=sending.SendResult.unknown(
            request_id="req-unknown",
            group="精确群名",
            username="room@chatroom",
            local_id=7,
            server_id=None,
        )
    )

    result = _invoke_send(
        monkeypatch,
        service,
        ["精确群名", "hello", "--format", "json"],
    )

    payload = json.loads(result.stdout)
    assert result.exit_code == 4
    assert payload["success"] is False
    assert payload["status"] == "unknown"
    assert payload["auto_retry"] is False
    assert len(service.requests) == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_id", object()),
        ("request_id", ""),
        ("group", object()),
        ("group", "另一个群"),
        ("username", object()),
        ("username", "other@chatroom"),
        ("local_id", object()),
        ("local_id", 0),
        ("server_id", {"not": "serializable contract"}),
        ("server_id", -1),
    ],
)
def test_send_sanitizes_malformed_unknown_result_as_exit_4_json(
    monkeypatch,
    field,
    value,
):
    sending = _sending_module()
    receipt = {
        "request_id": "req-unknown",
        "group": "精确群名",
        "username": "room@chatroom",
        "local_id": 7,
        "server_id": None,
    }
    receipt[field] = value
    service = RecordingSendService(
        result=sending.SendResult.unknown(**receipt)
    )

    result = _invoke_send(
        monkeypatch,
        service,
        ["精确群名", "hello", "--format", "json"],
    )

    payload = json.loads(result.stdout)
    assert result.exit_code == 4
    assert payload["success"] is False
    assert payload["status"] == "unknown"
    assert payload["auto_retry"] is False
    assert "error" in payload
    assert result.stderr == ""
    assert len(service.requests) == 1


def test_send_sanitizes_unbounded_unknown_message_id_as_exit_4_json(monkeypatch):
    sending = _sending_module()
    service = RecordingSendService(
        result=sending.SendResult.unknown(
            request_id="req-unknown",
            group="精确群名",
            username="room@chatroom",
            local_id=10 ** 5000,
        )
    )

    result = _invoke_send(
        monkeypatch,
        service,
        ["精确群名", "hello", "--format", "json"],
    )

    payload = json.loads(result.stdout)
    assert result.exit_code == 4
    assert payload["status"] == "unknown"
    assert payload["auto_retry"] is False
    assert "error" in payload


def test_send_rejects_status_object_that_only_compares_equal_to_unknown(monkeypatch):
    sending = _sending_module()

    class PretendsToBeUnknown:
        def __eq__(self, other):
            return other is sending.SendStatus.UNKNOWN

        def __str__(self):
            raise RuntimeError("must never be serialized")

    service = RecordingSendService(
        result=sending.SendResult(
            success=False,
            status=PretendsToBeUnknown(),
            request_id="req-unknown",
            group="精确群名",
            username="room@chatroom",
            local_id=None,
            server_id=None,
        )
    )

    result = _invoke_send(
        monkeypatch,
        service,
        ["精确群名", "hello", "--format", "json"],
    )

    payload = json.loads(result.stdout)
    assert result.exit_code == 4
    assert payload["status"] == "unknown"
    assert payload["auto_retry"] is False
    assert "error" in payload


@pytest.mark.parametrize(
    ("error_name", "expected_exit", "expected_status"),
    [
        ("unavailable", 3, "unavailable"),
        ("unknown", 4, "unknown"),
        ("unexpected", 4, "unknown"),
    ],
)
def test_send_maps_injected_backend_errors(
    monkeypatch,
    error_name,
    expected_exit,
    expected_status,
):
    sending = _sending_module()
    errors = {
        "unavailable": sending.SendUnavailableError("bridge 不可用，未发送"),
        "unknown": sending.SendUnknownError("结果未知，禁止自动重试"),
        "unexpected": RuntimeError("bridge unexpected failure"),
    }
    service = RecordingSendService(error=errors[error_name])

    result = _invoke_send(
        monkeypatch,
        service,
        ["精确群名", "hello", "--format", "json"],
    )

    payload = json.loads(result.stdout)
    assert result.exit_code == expected_exit
    assert payload["success"] is False
    assert payload["status"] == expected_status
    if expected_exit == 4:
        assert payload["auto_retry"] is False
    assert len(service.requests) == 1


@pytest.mark.parametrize(
    "backend_result_kind",
    ["non-result", "unsupported-status"],
)
def test_send_rejects_unrecognized_backend_result_as_unknown(
    monkeypatch,
    backend_result_kind,
):
    sending = _sending_module()
    if backend_result_kind == "unsupported-status":
        backend_result = sending.SendResult(
            success=True,
            status="unsupported",
            request_id="req-bad",
            group="精确群名",
            username="room@chatroom",
            local_id=1,
            server_id=2,
        )
    else:
        backend_result = {"status": "server_accepted"}
    service = RecordingSendService(result=backend_result)

    result = _invoke_send(
        monkeypatch,
        service,
        ["精确群名", "hello", "--format", "json"],
    )

    payload = json.loads(result.stdout)
    assert result.exit_code == 4
    assert payload["status"] == "unknown"
    assert payload["auto_retry"] is False
    assert len(service.requests) == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_id", ""),
        ("group", "另一个群"),
        ("username", "other@chatroom"),
        ("local_id", None),
        ("server_id", None),
        ("local_id", 0),
        ("server_id", 0),
    ],
)
def test_send_rejects_malformed_or_mismatched_success_receipt_as_unknown(
    monkeypatch,
    field,
    value,
):
    sending = _sending_module()
    receipt = {
        "request_id": "req-valid",
        "group": "精确群名",
        "username": "room@chatroom",
        "local_id": 11,
        "server_id": 22,
    }
    receipt[field] = value
    service = RecordingSendService(result=sending.SendResult.sent(**receipt))

    result = _invoke_send(
        monkeypatch,
        service,
        ["精确群名", "hello", "--format", "json"],
    )

    payload = json.loads(result.stdout)
    assert result.exit_code == 4
    assert payload["success"] is False
    assert payload["status"] == "unknown"
    assert payload["auto_retry"] is False
    assert len(service.requests) == 1


def test_send_text_output_is_concise_chinese(monkeypatch):
    sending = _sending_module()
    service = RecordingSendService(
        result=sending.SendResult.sent(
            request_id="req-text",
            group="精确群名",
            username="room@chatroom",
            local_id=1,
            server_id=2,
        )
    )

    result = _invoke_send(
        monkeypatch,
        service,
        ["精确群名", "hello", "--format", "text"],
    )

    assert result.exit_code == 0
    expected = "服务器已接受发往“精确群名”的消息（request_id: req-text）\n"
    assert result.stdout == expected


def test_existing_query_resolver_remains_fuzzy(monkeypatch):
    from wechat_cli.core import contacts

    monkeypatch.setattr(
        contacts,
        "get_contact_names",
        lambda cache, decrypted_dir: {"room@chatroom": "研发交流群"},
    )

    assert contacts.resolve_username("研发", object(), "/unused") == "room@chatroom"


def test_send_is_registered_in_root_help_with_example():
    result = CliRunner().invoke(main_module.cli, ["--help"])

    assert result.exit_code == 0
    assert "send" in result.stdout
    assert 'wechat-cli send "AI交流群" "大家好"' in result.stdout


def test_send_help_documents_contract_without_confirmation_flag(monkeypatch):
    app = SimpleNamespace(cache=object(), decrypted_dir="/unused")
    monkeypatch.setattr(main_module, "AppContext", lambda config_path=None: app)

    result = CliRunner().invoke(main_module.cli, ["send", "--help"])

    assert result.exit_code == 0
    assert "GROUP TEXT" in result.stdout
    assert "--timeout" in result.stdout
    assert "--format" in result.stdout
    assert "--yes" not in result.stdout
