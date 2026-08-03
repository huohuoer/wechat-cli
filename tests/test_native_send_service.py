from types import SimpleNamespace

import pytest

from wechat_cli.core.send_bridge import BridgeAckState, BridgeReceipt
from wechat_cli.core.send_confirmation import (
    MessageBaseline,
    MessageConfirmation,
    MessageConfirmationUnavailable,
)
from wechat_cli.core.sending import (
    SendRequest,
    SendStatus,
    SendUnavailableError,
    SendUnknownError,
)


REQUEST_ID = "2d13ea6e-10e6-4706-8d84-39ca0998ace4"


def _request(timeout=15.0):
    return SendRequest(
        group="精确群名",
        username="room@chatroom",
        text="你好 👋\n第二行",
        timeout=timeout,
    )


def _receipt(**overrides):
    values = {
        "request_id": REQUEST_ID,
        "ack_state": BridgeAckState.ACKNOWLEDGED,
        "group": "精确群名",
        "username": "room@chatroom",
        "local_id": 41,
        "server_id": 99,
    }
    values.update(overrides)
    return BridgeReceipt(**values)


class FakeBridge:
    def __init__(self, *, receipt=None, error=None):
        self.receipt = receipt if receipt is not None else _receipt()
        self.error = error
        self.requests = []

    def send_text(self, request):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.receipt


class FakeConfirmationStore:
    def __init__(
        self,
        *,
        confirmation=None,
        baseline_error=None,
        poll_error=None,
        empty_baseline=False,
    ):
        self.confirmation = (
            confirmation
            if confirmation is not None
            else MessageConfirmation(local_id=41, server_id=99)
        )
        self.baseline_error = baseline_error
        self.poll_error = poll_error
        self.empty_baseline = empty_baseline
        self.baseline_calls = []
        self.poll_calls = []

    def capture_baseline(self, username):
        self.baseline_calls.append(username)
        if self.baseline_error is not None:
            raise self.baseline_error
        maxima = {} if self.empty_baseline else {("message.db", "table", 1, 2): 0}
        return MessageBaseline(username=username, max_local_ids=maxima)

    def poll_confirmation(self, **kwargs):
        self.poll_calls.append(kwargs)
        if self.poll_error is not None:
            raise self.poll_error
        return self.confirmation


def _service(
    *,
    bridge=None,
    confirmation_store=None,
    preflight=None,
    self_username_loader=None,
    bridge_provider=None,
    monotonic=None,
    request_id_factory=None,
):
    from wechat_cli.core.native_sending import NativeSendService

    bridge = bridge or FakeBridge()
    confirmation_store = confirmation_store or FakeConfirmationStore()
    profile = SimpleNamespace(pid=4242)
    provider_calls = []

    def default_provider(actual_profile, request_id):
        provider_calls.append((actual_profile, request_id))
        return bridge

    service = NativeSendService(
        app_context=SimpleNamespace(),
        preflight=preflight or (lambda app: profile),
        self_username_loader=self_username_loader or (lambda app: "wxid_me"),
        confirmation_store=confirmation_store,
        bridge_provider=bridge_provider or default_provider,
        request_id_factory=request_id_factory or (lambda: REQUEST_ID),
        monotonic=monotonic or (lambda: 100.0),
    )
    return service, bridge, confirmation_store, provider_calls


def test_native_send_reports_success_only_after_ack_and_database_confirmation():
    service, bridge, store, provider_calls = _service()

    result = service.send_text(_request())

    assert result.success is True
    assert result.status is SendStatus.SERVER_ACCEPTED
    assert result.request_id == REQUEST_ID
    assert result.group == "精确群名"
    assert result.username == "room@chatroom"
    assert result.local_id == 41
    assert result.server_id == 99
    assert store.baseline_calls == ["room@chatroom"]
    assert len(store.poll_calls) == 1
    assert store.poll_calls[0]["username"] == "room@chatroom"
    assert store.poll_calls[0]["self_username"] == "wxid_me"
    assert store.poll_calls[0]["local_id"] == 41
    assert store.poll_calls[0]["text"] == "你好 👋\n第二行"
    assert provider_calls[0][1] == REQUEST_ID
    assert len(bridge.requests) == 1
    assert bridge.requests[0].text == "你好 👋\n第二行"


def test_native_send_discovers_ids_after_submitted_receipt_without_ids():
    bridge = FakeBridge(
        receipt=_receipt(
            ack_state=BridgeAckState.SUBMITTED,
            local_id=None,
            server_id=None,
        )
    )
    store = FakeConfirmationStore(
        confirmation=MessageConfirmation(local_id=43, server_id=101)
    )
    service, _, _, _ = _service(
        bridge=bridge,
        confirmation_store=store,
    )

    result = service.send_text(_request())

    assert result.success is True
    assert result.status is SendStatus.SERVER_ACCEPTED
    assert result.local_id == 43
    assert result.server_id == 101
    assert len(bridge.requests) == 1
    assert len(store.poll_calls) == 1
    assert store.poll_calls[0]["local_id"] is None
    assert store.poll_calls[0]["text"] == "你好 👋\n第二行"
    assert store.poll_calls[0]["baseline"].max_local_ids == {
        ("message.db", "table", 1, 2): 0
    }


@pytest.mark.parametrize(
    "local_id,server_id",
    [(None, None), (41, None), (None, 99)],
)
def test_native_send_never_accepts_receipt_without_both_ids(
    local_id,
    server_id,
):
    bridge = FakeBridge(
        receipt=_receipt(
            ack_state=BridgeAckState.ACKNOWLEDGED,
            local_id=local_id,
            server_id=server_id,
        )
    )
    service, _, store, _ = _service(bridge=bridge)

    result = service.send_text(_request())

    assert result.status is SendStatus.UNKNOWN
    assert store.poll_calls == []


def test_native_send_passes_remaining_deadline_to_bridge_and_confirmation():
    times = iter([10.0, 11.25, 12.0])
    service, bridge, store, _ = _service(monotonic=lambda: next(times))

    result = service.send_text(_request(timeout=5.0))

    assert result.success is True
    assert bridge.requests[0].timeout == pytest.approx(3.75)
    assert store.poll_calls[0]["timeout"] == pytest.approx(3.0)


@pytest.mark.parametrize(
    "receipt",
    [
        _receipt(
            ack_state=BridgeAckState.UNKNOWN,
            local_id=None,
            server_id=None,
        ),
        _receipt(request_id="wrong-request"),
        _receipt(group="错误群"),
        _receipt(username="other@chatroom"),
        _receipt(local_id=None),
    ],
)
def test_native_send_maps_unconfirmed_or_mismatched_receipt_to_unknown(receipt):
    bridge = FakeBridge(receipt=receipt)
    service, _, store, _ = _service(bridge=bridge)

    result = service.send_text(_request())

    assert result.success is False
    assert result.status is SendStatus.UNKNOWN
    assert result.request_id == REQUEST_ID
    assert len(bridge.requests) == 1
    assert store.poll_calls == []


def test_native_send_keeps_request_id_when_transport_is_ambiguous():
    bridge = FakeBridge(
        error=SendUnknownError("提交状态未知，禁止自动重试")
    )
    service, _, store, _ = _service(bridge=bridge)

    result = service.send_text(_request())

    assert result.status is SendStatus.UNKNOWN
    assert result.request_id == REQUEST_ID
    assert result.local_id is None
    assert len(bridge.requests) == 1
    assert store.poll_calls == []


def test_native_send_propagates_confirmed_pre_submit_unavailable():
    bridge = FakeBridge(
        error=SendUnavailableError("一个字节都未提交，未发送任何消息")
    )
    service, _, store, _ = _service(bridge=bridge)

    with pytest.raises(SendUnavailableError, match="未发送"):
        service.send_text(_request())

    assert len(bridge.requests) == 1
    assert store.poll_calls == []


def test_native_send_database_timeout_after_ack_is_unknown_without_retry():
    store = FakeConfirmationStore(confirmation=None)
    store.confirmation = None
    service, bridge, _, _ = _service(confirmation_store=store)

    result = service.send_text(_request())

    assert result.status is SendStatus.UNKNOWN
    assert result.request_id == REQUEST_ID
    assert result.local_id == 41
    assert result.server_id == 99
    assert len(bridge.requests) == 1
    assert len(store.poll_calls) == 1


def test_native_send_submitted_confirmation_timeout_is_unknown_without_retry():
    bridge = FakeBridge(
        receipt=_receipt(
            ack_state=BridgeAckState.SUBMITTED,
            local_id=None,
            server_id=None,
        )
    )
    store = FakeConfirmationStore(confirmation=None)
    store.confirmation = None
    service, _, _, _ = _service(
        bridge=bridge,
        confirmation_store=store,
    )

    result = service.send_text(_request())

    assert result.status is SendStatus.UNKNOWN
    assert result.local_id is None
    assert result.server_id is None
    assert len(bridge.requests) == 1
    assert len(store.poll_calls) == 1


def test_native_send_database_error_after_ack_is_unknown_without_retry():
    store = FakeConfirmationStore(
        poll_error=MessageConfirmationUnavailable("刷新失败")
    )
    service, bridge, _, _ = _service(confirmation_store=store)

    result = service.send_text(_request())

    assert result.status is SendStatus.UNKNOWN
    assert result.request_id == REQUEST_ID
    assert len(bridge.requests) == 1


def test_native_send_rejects_bridge_and_database_server_id_disagreement():
    store = FakeConfirmationStore(
        confirmation=MessageConfirmation(local_id=41, server_id=100)
    )
    service, bridge, _, _ = _service(confirmation_store=store)

    result = service.send_text(_request())

    assert result.status is SendStatus.UNKNOWN
    assert result.server_id == 99
    assert len(bridge.requests) == 1


def test_native_send_preflight_failure_stops_before_baseline_and_bridge():
    bridge = FakeBridge()
    store = FakeConfirmationStore()

    def fail_preflight(app):
        raise SendUnavailableError("unsupported_wechat_build；未发送任何消息")

    service, _, _, provider_calls = _service(
        bridge=bridge,
        confirmation_store=store,
        preflight=fail_preflight,
    )

    with pytest.raises(SendUnavailableError, match="unsupported"):
        service.send_text(_request())

    assert store.baseline_calls == []
    assert provider_calls == []
    assert bridge.requests == []


def test_native_send_requires_current_account_identity_before_baseline():
    service, bridge, store, provider_calls = _service(
        self_username_loader=lambda app: "",
    )

    with pytest.raises(SendUnavailableError, match="账号"):
        service.send_text(_request())

    assert store.baseline_calls == []
    assert provider_calls == []
    assert bridge.requests == []


def test_native_send_baseline_failure_stops_before_bridge_injection():
    store = FakeConfirmationStore(
        baseline_error=MessageConfirmationUnavailable("无法读取基线")
    )
    service, bridge, _, provider_calls = _service(
        confirmation_store=store,
    )

    with pytest.raises(SendUnavailableError, match="基线"):
        service.send_text(_request())

    assert provider_calls == []
    assert bridge.requests == []


def test_native_send_empty_baseline_stops_before_bridge_injection():
    store = FakeConfirmationStore(empty_baseline=True)
    service, bridge, _, provider_calls = _service(
        confirmation_store=store,
    )

    with pytest.raises(SendUnavailableError, match="基线"):
        service.send_text(_request())

    assert provider_calls == []
    assert bridge.requests == []


def test_native_send_timeout_before_submission_is_unavailable():
    times = iter([10.0, 15.0])
    service, bridge, _, provider_calls = _service(
        monotonic=lambda: next(times),
    )

    with pytest.raises(SendUnavailableError, match="超时"):
        service.send_text(_request(timeout=5.0))

    assert provider_calls == []
    assert bridge.requests == []


@pytest.mark.parametrize("request_id", ["", "not-a-uuid", None, True])
def test_native_send_rejects_invalid_request_id_before_preflight(request_id):
    preflight_calls = []
    service, bridge, store, provider_calls = _service(
        request_id_factory=lambda: request_id,
        preflight=lambda app: preflight_calls.append(app),
    )

    with pytest.raises(SendUnavailableError, match="request_id"):
        service.send_text(_request())

    assert preflight_calls == []
    assert store.baseline_calls == []
    assert provider_calls == []
    assert bridge.requests == []
