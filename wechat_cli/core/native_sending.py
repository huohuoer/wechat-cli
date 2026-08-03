"""严格单次提交的原生发送事务编排。"""

from dataclasses import replace
import math
import time
import uuid

from .send_bridge import BridgeAckState, BridgeReceipt
from .send_confirmation import (
    MessageBaseline,
    MessageConfirmation,
    MessageConfirmationUnavailable,
)
from .sending import (
    SendRequest,
    SendResult,
    SendUnavailableError,
    SendUnknownError,
)


def _default_request_id():
    return str(uuid.uuid4())


def _valid_request_id(value):
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    return str(parsed) == value.lower()


def _positive_id(value):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


class NativeSendService:
    """把预检、单次 bridge 提交、ACK 与数据库确认组合成一个事务。"""

    def __init__(
        self,
        *,
        app_context,
        preflight,
        self_username_loader,
        confirmation_store,
        bridge_provider,
        request_id_factory=_default_request_id,
        monotonic=time.monotonic,
    ):
        self._app_context = app_context
        self._preflight = preflight
        self._self_username_loader = self_username_loader
        self._confirmation_store = confirmation_store
        self._bridge_provider = bridge_provider
        self._request_id_factory = request_id_factory
        self._monotonic = monotonic

    @staticmethod
    def _unknown(request, request_id, receipt=None):
        return SendResult.unknown(
            request_id=request_id,
            group=request.group,
            username=request.username,
            local_id=(
                _positive_id(receipt.local_id)
                if isinstance(receipt, BridgeReceipt)
                else None
            ),
            server_id=(
                _positive_id(receipt.server_id)
                if isinstance(receipt, BridgeReceipt)
                else None
            ),
        )

    def send_text(self, request):
        if not isinstance(request, SendRequest):
            raise SendUnavailableError(
                "发送请求类型无效，未发送任何消息"
            )
        if (
            isinstance(request.timeout, bool)
            or not isinstance(request.timeout, (int, float))
            or not math.isfinite(request.timeout)
            or request.timeout <= 0
        ):
            raise SendUnavailableError(
                "发送 timeout 无效，未发送任何消息"
            )

        started_at = self._monotonic()
        deadline = started_at + request.timeout
        try:
            request_id = self._request_id_factory()
        except Exception as error:
            raise SendUnavailableError(
                "无法生成发送 request_id，未发送任何消息"
            ) from error
        if not _valid_request_id(request_id):
            raise SendUnavailableError(
                "发送 request_id 无效，未发送任何消息"
            )

        try:
            profile = self._preflight(self._app_context)
        except SendUnavailableError:
            raise
        except Exception as error:
            raise SendUnavailableError(
                "发送前环境校验失败，未发送任何消息"
            ) from error

        try:
            self_username = self._self_username_loader(self._app_context)
        except Exception as error:
            raise SendUnavailableError(
                "无法确认当前微信账号，未发送任何消息"
            ) from error
        if type(self_username) is not str or not self_username:
            raise SendUnavailableError(
                "无法确认当前微信账号，未发送任何消息"
            )

        try:
            baseline = self._confirmation_store.capture_baseline(
                request.username
            )
        except MessageConfirmationUnavailable as error:
            raise SendUnavailableError(
                "无法记录发送前消息基线，未发送任何消息"
            ) from error
        except Exception as error:
            raise SendUnavailableError(
                "发送前消息基线不可用，未发送任何消息"
            ) from error
        if (
            not isinstance(baseline, MessageBaseline)
            or baseline.username != request.username
            or not isinstance(baseline.max_local_ids, dict)
            or not baseline.max_local_ids
        ):
            raise SendUnavailableError(
                "发送前消息基线无效，未发送任何消息"
            )

        remaining = deadline - self._monotonic()
        if remaining <= 0:
            raise SendUnavailableError(
                "发送在提交前超时，未发送任何消息"
            )
        try:
            bridge = self._bridge_provider(profile, request_id)
        except SendUnavailableError:
            raise
        except Exception as error:
            raise SendUnavailableError(
                "发送 bridge 无法准备，未发送任何消息"
            ) from error
        if not callable(getattr(bridge, "send_text", None)):
            raise SendUnavailableError(
                "发送 bridge 未正确加载，未发送任何消息"
            )

        bridge_request = replace(request, timeout=remaining)
        try:
            receipt = bridge.send_text(bridge_request)
        except SendUnavailableError:
            # 只有 bridge 能证明没有提交任何帧字节时，才允许退出 3。
            raise
        except SendUnknownError:
            return self._unknown(request, request_id)
        except Exception:
            # 一旦进入传输边界，异常也可能发生在消息已经提交之后。
            return self._unknown(request, request_id)

        if not isinstance(receipt, BridgeReceipt):
            return self._unknown(request, request_id)
        if (
            receipt.request_id != request_id
            or receipt.group != request.group
            or receipt.username != request.username
        ):
            return self._unknown(request, request_id, receipt)

        if receipt.ack_state is BridgeAckState.ACKNOWLEDGED:
            if (
                _positive_id(receipt.local_id) is None
                or _positive_id(receipt.server_id) is None
            ):
                return self._unknown(request, request_id, receipt)
        elif receipt.ack_state is BridgeAckState.SUBMITTED:
            if receipt.local_id is not None or receipt.server_id is not None:
                return self._unknown(request, request_id, receipt)
        else:
            return self._unknown(request, request_id, receipt)

        remaining = max(0.0, deadline - self._monotonic())
        try:
            confirmation = self._confirmation_store.poll_confirmation(
                username=request.username,
                self_username=self_username,
                local_id=receipt.local_id,
                text=request.text,
                baseline=baseline,
                timeout=remaining,
            )
        except Exception:
            return self._unknown(request, request_id, receipt)
        if (
            not isinstance(confirmation, MessageConfirmation)
            or _positive_id(confirmation.local_id) is None
            or _positive_id(confirmation.server_id) is None
        ):
            return self._unknown(request, request_id, receipt)
        if receipt.ack_state is BridgeAckState.ACKNOWLEDGED and (
            confirmation.local_id != receipt.local_id
            or confirmation.server_id != receipt.server_id
        ):
            return self._unknown(request, request_id, receipt)

        return SendResult.sent(
            request_id=request_id,
            group=request.group,
            username=request.username,
            local_id=confirmation.local_id,
            server_id=confirmation.server_id,
        )
