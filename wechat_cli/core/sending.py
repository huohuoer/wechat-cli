"""群消息发送公共契约、精确目标解析和结果校验。"""

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Protocol

from .contacts import get_contact_full, get_contact_names


SEND_INIT_ERROR_META_KEY = "wechat_cli.send_init_error"
MAX_MESSAGE_ID = (1 << 63) - 1
MAX_RECEIPT_TEXT_BYTES = 16 * 1024


class SendExitCode(IntEnum):
    """send 命令稳定退出码。"""

    SUCCESS = 0
    TARGET_ERROR = 1
    INPUT_ERROR = 2
    UNAVAILABLE = 3
    UNKNOWN = 4


class SendStatus(str, Enum):
    """发送服务可以明确返回的最终状态。"""

    SERVER_ACCEPTED = "server_accepted"
    UNKNOWN = "unknown"


class SendError(RuntimeError):
    """发送命令可安全映射为退出码的错误。"""

    exit_code = SendExitCode.UNKNOWN
    status = SendStatus.UNKNOWN.value
    auto_retry = False


class SendTargetError(SendError):
    """目标不存在、不唯一或不是群聊。"""

    exit_code = SendExitCode.TARGET_ERROR
    status = "target_error"


class SendInputError(SendError):
    """调用参数无效。"""

    exit_code = SendExitCode.INPUT_ERROR
    status = "input_error"


class SendUnavailableError(SendError):
    """发送实现或其运行环境不可用，且尚未尝试发送。"""

    exit_code = SendExitCode.UNAVAILABLE
    status = "unavailable"


class SendUnknownError(SendError):
    """无法确认消息是否已发送；调用方不得自动重试。"""

    exit_code = SendExitCode.UNKNOWN
    status = SendStatus.UNKNOWN.value


@dataclass(frozen=True)
class SendTarget:
    """已从联系人库精确解析出的群目标。"""

    group: str
    username: str


@dataclass(frozen=True)
class SendRequest:
    """发送服务的稳定输入。"""

    group: str
    username: str
    text: str
    timeout: float


@dataclass(frozen=True)
class SendResult:
    """发送服务的稳定输出。"""

    success: bool
    status: SendStatus
    request_id: str
    group: str
    username: str
    local_id: int | None
    server_id: int | None

    @classmethod
    def sent(
        cls,
        *,
        request_id,
        group,
        username,
        local_id,
        server_id,
    ):
        return cls(
            success=True,
            status=SendStatus.SERVER_ACCEPTED,
            request_id=request_id,
            group=group,
            username=username,
            local_id=local_id,
            server_id=server_id,
        )

    @classmethod
    def unknown(
        cls,
        *,
        request_id,
        group,
        username,
        local_id=None,
        server_id=None,
    ):
        return cls(
            success=False,
            status=SendStatus.UNKNOWN,
            request_id=request_id,
            group=group,
            username=username,
            local_id=local_id,
            server_id=server_id,
        )

    def as_dict(self):
        status = self.status.value if isinstance(self.status, SendStatus) else str(self.status)
        return {
            "success": self.success,
            "status": status,
            "request_id": self.request_id,
            "group": self.group,
            "username": self.username,
            "local_id": self.local_id,
            "server_id": self.server_id,
        }


class SendService(Protocol):
    """后续发送实现必须满足的最小接口。"""

    def send_text(self, request: SendRequest) -> SendResult:
        """发送一条群文本消息，或抛出分类后的 SendError。"""


class UnavailableSendService:
    """发送服务未配置时使用的 fail-closed 默认实现。"""

    def send_text(self, request):
        raise SendUnavailableError(
            "当前构建未安装或不支持发送 bridge，未发送任何消息"
        )


def _display_from_contact(contact):
    username = contact.get("username")
    if not username:
        return None, None
    display = (
        contact.get("remark")
        or contact.get("nick_name")
        or contact.get("display_name")
        or username
    )
    return username, display


def _load_unique_contacts(cache, decrypted_dir):
    """按 username 合并现有 names/full 两种联系人结构。"""

    try:
        names = get_contact_names(cache, decrypted_dir) or {}
        full = get_contact_full(cache, decrypted_dir) or []

        unique = {}
        for contact in full:
            if not isinstance(contact, dict):
                continue
            username, display = _display_from_contact(contact)
            if username and username not in unique:
                unique[username] = display

        # get_contact_names 使用项目统一的 remark > nick_name > username 规则，
        # 因此在两种结构同时存在时以它为准。
        for username, display in names.items():
            if username:
                unique[username] = display or username
    except Exception as error:
        raise SendUnavailableError(
            f"联系人库不可用: {error}；未发送任何消息"
        ) from error

    if not unique:
        raise SendUnavailableError("联系人库不可用或为空，未发送任何消息")
    return unique


def resolve_send_group(group, cache, decrypted_dir):
    """精确解析发送目标，不复用或改变查询命令的模糊解析器。"""

    contacts = _load_unique_contacts(cache, decrypted_dir)

    if group in contacts:
        if not group.endswith("@chatroom"):
            raise SendTargetError(f"{group} 不是群聊")
        return SendTarget(group=contacts[group], username=group)

    # 带 @chatroom 的输入被视为 username，禁止回退为显示名，
    # 从而拒绝伪造 ID。
    if "@chatroom" in group:
        raise SendTargetError(f"联系人库中不存在群聊 username: {group}")

    matches = [
        SendTarget(group=display, username=username)
        for username, display in contacts.items()
        if username.endswith("@chatroom") and display == group
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise SendTargetError(
            f'群名“{group}”匹配到多个群聊，请使用 @chatroom username'
        )

    if any(
        not username.endswith("@chatroom") and display == group
        for username, display in contacts.items()
    ):
        raise SendTargetError(f"{group} 不是群聊")
    raise SendTargetError(f"找不到群聊: {group}")


def get_send_service(app):
    """取得注入的发送服务；未注入时始终 fail-closed。"""

    service = getattr(app, "send_service", None)
    if service is None:
        return UnavailableSendService()
    if not callable(getattr(service, "send_text", None)):
        raise SendUnavailableError("发送服务未正确配置，未发送任何消息")
    return service


def validate_send_result(result, request):
    """验证 bridge 回执足以证明服务器已接受当前目标的消息。"""

    if not isinstance(result, SendResult):
        raise SendUnknownError("发送服务未返回可确认结果，禁止自动重试")

    def valid_text(value, *, max_bytes):
        if type(value) is not str or not value:
            return False
        try:
            encoded = value.encode("utf-8", "strict")
        except UnicodeError:
            return False
        return len(encoded) <= max_bytes

    if not valid_text(result.request_id, max_bytes=256):
        raise SendUnknownError("发送回执缺少有效 request_id，禁止自动重试")
    if (
        not valid_text(result.group, max_bytes=MAX_RECEIPT_TEXT_BYTES)
        or not valid_text(result.username, max_bytes=MAX_RECEIPT_TEXT_BYTES)
        or result.group != request.group
        or result.username != request.username
    ):
        raise SendUnknownError("发送回执目标与请求不一致，禁止自动重试")

    for field_name, value in (
        ("local_id", result.local_id),
        ("server_id", result.server_id),
    ):
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            or value > MAX_MESSAGE_ID
        ):
            raise SendUnknownError(
                f"发送回执包含无效 {field_name}，禁止自动重试"
            )

    if result.status is SendStatus.UNKNOWN:
        if result.success is not False:
            raise SendUnknownError("发送服务返回矛盾状态，禁止自动重试")
        return result

    if result.status is not SendStatus.SERVER_ACCEPTED or result.success is not True:
        raise SendUnknownError("发送服务返回未知状态，禁止自动重试")
    for field_name, value in (
        ("local_id", result.local_id),
        ("server_id", result.server_id),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            or value > MAX_MESSAGE_ID
        ):
            raise SendUnknownError(
                f"发送回执缺少有效 {field_name}，禁止自动重试"
            )
    return result
