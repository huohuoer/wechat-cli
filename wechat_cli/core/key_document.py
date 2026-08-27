"""微信数据库密钥文档及系统密钥后端。"""

import base64
import json
import os
import platform
import re
import subprocess
import uuid
from abc import ABC, abstractmethod

from .key_utils import _is_safe_rel_path
from .secure_files import atomic_write_json, read_private_json


_KEY_HEX = re.compile(r"^[0-9a-fA-F]{64}$")
_SALT_HEX = re.compile(r"^[0-9a-fA-F]{32}$")


def validate_key_document(document, source="密钥文档"):
    """返回规范化副本；拒绝含糊条目且永不在错误中包含值。"""
    if not isinstance(document, dict):
        raise ValueError(f"{source} 必须是对象")

    normalized = {}
    for rel_path, info in document.items():
        if not isinstance(rel_path, str):
            raise ValueError(f"{source} 包含非字符串路径")
        if rel_path.startswith("_"):
            continue
        if not rel_path or not _is_safe_rel_path(rel_path):
            raise ValueError(f"{source} 包含不安全的数据库相对路径")
        if not isinstance(info, dict):
            raise ValueError(f"{source} 中 {rel_path!r} 的条目必须是对象")

        enc_key = info.get("enc_key")
        if not isinstance(enc_key, str) or not _KEY_HEX.fullmatch(enc_key):
            raise ValueError(f"{source} 中 {rel_path!r} 的 enc_key 格式无效")
        salt = info.get("salt")
        if salt is not None and (not isinstance(salt, str) or not _SALT_HEX.fullmatch(salt)):
            raise ValueError(f"{source} 中 {rel_path!r} 的 salt 格式无效")

        normalized[rel_path] = dict(info)

    if not normalized:
        raise ValueError(f"{source} 没有可用的数据库密钥")
    return normalized


class DatabaseKeyProvider(ABC):
    """数据库密钥引用边界；调用方不能枚举或读取无关密钥值。"""

    @abstractmethod
    def references(self):
        """返回可用数据库相对路径，不返回密钥值。"""

    @abstractmethod
    def resolve(self, rel_path):
        """按一次操作解析一个数据库的密钥信息。"""

    @abstractmethod
    def replace(self, document):
        """原子替换 Provider 管理的完整密钥集合。"""

    @abstractmethod
    def describe(self, rel_path):
        """返回配置状态和来源，不返回密钥值。"""


class JsonDatabaseKeyProvider(DatabaseKeyProvider):
    """兼容 `all_keys.json` 的文件 Provider；每次操作重新读取。"""

    def __init__(self, path):
        self.path = path

    def _load(self):
        return validate_key_document(read_private_json(self.path), self.path)

    def references(self):
        return tuple(self._load())

    def resolve(self, rel_path):
        if not isinstance(rel_path, str) or not _is_safe_rel_path(rel_path):
            return None
        document = self._load()
        for candidate in (
            rel_path,
            rel_path.replace("\\", "/"),
            rel_path.replace("/", "\\"),
        ):
            if candidate in document:
                return dict(document[candidate])
        return None

    def replace(self, document):
        normalized = validate_key_document(document)
        atomic_write_json(self.path, normalized)

    def describe(self, rel_path):
        return {
            "configured": self.resolve(rel_path) is not None,
            "source": "file",
            "writable": True,
        }


def _dpapi_transform(data, *, protect):
    if os.name != "nt":
        raise RuntimeError("DPAPI 仅支持 Windows")
    import ctypes
    from ctypes import wintypes

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    source_buffer = ctypes.create_string_buffer(data)
    source = DataBlob(len(data), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_byte)))
    destination = DataBlob()
    description = wintypes.LPWSTR()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DataBlob), wintypes.LPCWSTR, ctypes.POINTER(DataBlob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DataBlob),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DataBlob), ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(DataBlob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DataBlob),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
    if protect:
        ok = crypt32.CryptProtectData(
            ctypes.byref(source), "wechat-cli", None, None, None, flags,
            ctypes.byref(destination),
        )
    else:
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(source), ctypes.byref(description), None, None, None, flags,
            ctypes.byref(destination),
        )
    if not ok:
        raise OSError(ctypes.get_last_error(), "DPAPI 操作失败")
    try:
        return ctypes.string_at(destination.pbData, destination.cbData)
    finally:
        if destination.pbData:
            kernel32.LocalFree(ctypes.cast(destination.pbData, ctypes.c_void_p))
        if description:
            kernel32.LocalFree(ctypes.cast(description, ctypes.c_void_p))


class DpapiDatabaseKeyProvider(DatabaseKeyProvider):
    """Windows CurrentUser DPAPI；清单只保存密文。"""

    backend = "dpapi-current-user"

    def __init__(self, path):
        self.path = path

    def _load(self):
        document = read_private_json(self.path)
        if not isinstance(document, dict) or document.get("_backend") != self.backend:
            raise ValueError("DPAPI 密钥清单格式无效")
        entries = document.get("_entries")
        if not isinstance(entries, dict) or not entries:
            raise ValueError("DPAPI 密钥清单没有条目")
        for rel_path, blob in entries.items():
            if not isinstance(rel_path, str) or not _is_safe_rel_path(rel_path):
                raise ValueError("DPAPI 密钥清单包含不安全路径")
            if not isinstance(blob, str):
                raise ValueError("DPAPI 密钥清单包含无效密文")
        return entries

    def references(self):
        return tuple(self._load())

    def resolve(self, rel_path):
        if not isinstance(rel_path, str) or not _is_safe_rel_path(rel_path):
            return None
        entries = self._load()
        for candidate in (rel_path, rel_path.replace("\\", "/"), rel_path.replace("/", "\\")):
            blob = entries.get(candidate)
            if blob is None:
                continue
            try:
                encrypted = base64.b64decode(blob, validate=True)
                payload = _dpapi_transform(encrypted, protect=False)
                info = json.loads(payload.decode("utf-8"))
            except Exception:
                raise ValueError("DPAPI 密钥条目无法解密或校验") from None
            return validate_key_document({candidate: info}, "DPAPI 密钥条目")[candidate]
        return None

    def replace(self, document):
        normalized = validate_key_document(document)
        entries = {}
        for rel_path, info in normalized.items():
            payload = json.dumps(info, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            encrypted = _dpapi_transform(payload, protect=True)
            entries[rel_path] = base64.b64encode(encrypted).decode("ascii")
        atomic_write_json(self.path, {"_backend": self.backend, "_entries": entries})

    def describe(self, rel_path):
        return {
            "configured": self.resolve(rel_path) is not None,
            "source": self.backend,
            "writable": True,
        }


class SecretServiceDatabaseKeyProvider(DatabaseKeyProvider):
    """Linux Secret Service 后端；密钥通过 stdin 交给 secret-tool。"""

    backend = "secret-service"
    tool_path = "/usr/bin/secret-tool"

    def __init__(self, path, namespace):
        self.path = path
        self.namespace = namespace
        if not isinstance(namespace, str) or not _GENERATION_TOKEN.fullmatch(namespace):
            raise ValueError("Secret Service namespace 无效")

    def _command(self, *args, input_text=None):
        if not os.path.isfile(self.tool_path):
            raise RuntimeError("未安装 /usr/bin/secret-tool")
        result = subprocess.run(
            [self.tool_path, *args],
            input=input_text,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("Secret Service 操作失败")
        return result.stdout

    def _load(self):
        document = read_private_json(self.path)
        if not isinstance(document, dict) or document.get("_backend") != self.backend:
            raise ValueError("Secret Service 密钥清单格式无效")
        if document.get("_namespace") != self.namespace:
            raise ValueError("Secret Service namespace 不匹配")
        entries = document.get("_entries")
        if not isinstance(entries, dict) or not entries:
            raise ValueError("Secret Service 密钥清单没有条目")
        for rel_path, token in entries.items():
            if not isinstance(rel_path, str) or not _is_safe_rel_path(rel_path):
                raise ValueError("Secret Service 密钥清单包含不安全路径")
            if not isinstance(token, str) or not _GENERATION_TOKEN.fullmatch(token):
                raise ValueError("Secret Service 密钥清单包含无效引用")
        return entries

    def _attributes(self, token):
        return ["application", "wechat-cli", "namespace", self.namespace, "entry", token]

    def references(self):
        return tuple(self._load())

    def resolve(self, rel_path):
        if not isinstance(rel_path, str) or not _is_safe_rel_path(rel_path):
            return None
        entries = self._load()
        for candidate in (rel_path, rel_path.replace("\\", "/"), rel_path.replace("/", "\\")):
            token = entries.get(candidate)
            if token is None:
                continue
            payload = self._command("lookup", *self._attributes(token))
            try:
                info = json.loads(payload)
            except json.JSONDecodeError:
                raise ValueError("Secret Service 密钥条目格式无效") from None
            return validate_key_document({candidate: info}, "Secret Service 密钥条目")[candidate]
        return None

    def replace(self, document):
        normalized = validate_key_document(document)
        previous = {}
        if os.path.exists(self.path):
            previous = self._load()
        created = {}
        try:
            for rel_path, info in normalized.items():
                token = uuid.uuid4().hex
                payload = json.dumps(info, ensure_ascii=False, separators=(",", ":"))
                self._command(
                    "store", "--label=WeChat CLI database key", *self._attributes(token),
                    input_text=payload,
                )
                created[rel_path] = token
            atomic_write_json(
                self.path,
                {"_backend": self.backend, "_namespace": self.namespace, "_entries": created},
            )
        except Exception:
            for token in created.values():
                try:
                    self._command("clear", *self._attributes(token))
                except Exception:
                    pass
            raise
        for token in previous.values():
            try:
                self._command("clear", *self._attributes(token))
            except Exception:
                pass

    def describe(self, rel_path):
        return {
            "configured": self.resolve(rel_path) is not None,
            "source": self.backend,
            "writable": True,
        }


class MacKeychainDatabaseKeyProvider(DatabaseKeyProvider):
    """macOS login Keychain；清单只保存随机引用。"""

    backend = "macos-keychain"

    def __init__(self, path, namespace):
        self.path = path
        self.namespace = namespace
        if not isinstance(namespace, str) or not _GENERATION_TOKEN.fullmatch(namespace):
            raise ValueError("Keychain namespace 无效")

    def _security(self):
        if platform.system().lower() != "darwin":
            raise RuntimeError("macOS Keychain 仅支持 macOS")
        import ctypes

        security = ctypes.CDLL(
            "/System/Library/Frameworks/Security.framework/Security"
        )
        core_foundation = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        )
        security.SecKeychainAddGenericPassword.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32,
            ctypes.c_char_p, ctypes.c_uint32, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        security.SecKeychainAddGenericPassword.restype = ctypes.c_int32
        security.SecKeychainFindGenericPassword.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32,
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ]
        security.SecKeychainFindGenericPassword.restype = ctypes.c_int32
        security.SecKeychainItemFreeContent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        security.SecKeychainItemFreeContent.restype = ctypes.c_int32
        security.SecKeychainItemDelete.argtypes = [ctypes.c_void_p]
        security.SecKeychainItemDelete.restype = ctypes.c_int32
        core_foundation.CFRelease.argtypes = [ctypes.c_void_p]
        return ctypes, security, core_foundation

    def _names(self, token):
        return f"wechat-cli:{self.namespace}".encode(), token.encode()

    def _store(self, token, payload):
        ctypes, security, core_foundation = self._security()
        service, account = self._names(token)
        item = ctypes.c_void_p()
        data = payload.encode("utf-8")
        data_buffer = ctypes.create_string_buffer(data)
        status = security.SecKeychainAddGenericPassword(
            None, len(service), service, len(account), account, len(data),
            ctypes.cast(data_buffer, ctypes.c_void_p),
            ctypes.byref(item),
        )
        if item:
            core_foundation.CFRelease(item)
        if status != 0:
            raise RuntimeError(f"Keychain 写入失败 (OSStatus {status})")

    def _find(self, token):
        ctypes, security, core_foundation = self._security()
        service, account = self._names(token)
        length = ctypes.c_uint32()
        data = ctypes.c_void_p()
        item = ctypes.c_void_p()
        status = security.SecKeychainFindGenericPassword(
            None, len(service), service, len(account), account,
            ctypes.byref(length), ctypes.byref(data), ctypes.byref(item),
        )
        if status != 0:
            raise RuntimeError(f"Keychain 读取失败 (OSStatus {status})")
        try:
            return ctypes.string_at(data, length.value), item
        except Exception:
            if item:
                core_foundation.CFRelease(item)
            raise
        finally:
            if data:
                security.SecKeychainItemFreeContent(None, data)

    def _lookup(self, token):
        payload, item = self._find(token)
        try:
            return payload.decode("utf-8")
        finally:
            if item:
                _ctypes, _security, core_foundation = self._security()
                core_foundation.CFRelease(item)

    def _clear(self, token):
        _payload, item = self._find(token)
        try:
            status = self._security()[1].SecKeychainItemDelete(item)
            if status != 0:
                raise RuntimeError(f"Keychain 删除失败 (OSStatus {status})")
        finally:
            if item:
                self._security()[2].CFRelease(item)

    def _load(self):
        document = read_private_json(self.path)
        if not isinstance(document, dict) or document.get("_backend") != self.backend:
            raise ValueError("Keychain 密钥清单格式无效")
        if document.get("_namespace") != self.namespace:
            raise ValueError("Keychain namespace 不匹配")
        entries = document.get("_entries")
        if not isinstance(entries, dict) or not entries:
            raise ValueError("Keychain 密钥清单没有条目")
        for rel_path, token in entries.items():
            if not isinstance(rel_path, str) or not _is_safe_rel_path(rel_path):
                raise ValueError("Keychain 密钥清单包含不安全路径")
            if not isinstance(token, str) or not _GENERATION_TOKEN.fullmatch(token):
                raise ValueError("Keychain 密钥清单包含无效引用")
        return entries

    def references(self):
        return tuple(self._load())

    def resolve(self, rel_path):
        if not isinstance(rel_path, str) or not _is_safe_rel_path(rel_path):
            return None
        entries = self._load()
        for candidate in (rel_path, rel_path.replace("\\", "/"), rel_path.replace("/", "\\")):
            token = entries.get(candidate)
            if token is None:
                continue
            try:
                info = json.loads(self._lookup(token))
            except json.JSONDecodeError:
                raise ValueError("Keychain 密钥条目格式无效") from None
            return validate_key_document({candidate: info}, "Keychain 密钥条目")[candidate]
        return None

    def replace(self, document):
        normalized = validate_key_document(document)
        previous = self._load() if os.path.exists(self.path) else {}
        created = {}
        try:
            for rel_path, info in normalized.items():
                token = uuid.uuid4().hex
                payload = json.dumps(info, ensure_ascii=False, separators=(",", ":"))
                self._store(token, payload)
                created[rel_path] = token
            atomic_write_json(
                self.path,
                {"_backend": self.backend, "_namespace": self.namespace, "_entries": created},
            )
        except Exception:
            for token in created.values():
                try:
                    self._clear(token)
                except Exception:
                    pass
            raise
        for token in previous.values():
            try:
                self._clear(token)
            except Exception:
                pass

    def describe(self, rel_path):
        return {
            "configured": self.resolve(rel_path) is not None,
            "source": self.backend,
            "writable": True,
        }


_GENERATION_TOKEN = re.compile(r"^[0-9a-f]{32}$")


def select_default_key_backend():
    system = platform.system().lower()
    if system == "windows":
        return DpapiDatabaseKeyProvider.backend
    if system == "linux" and os.path.isfile(SecretServiceDatabaseKeyProvider.tool_path):
        return SecretServiceDatabaseKeyProvider.backend
    if system == "darwin":
        return MacKeychainDatabaseKeyProvider.backend
    if os.environ.get("WECHAT_CLI_ALLOW_PLAINTEXT_KEYS") == "1":
        return "file"
    raise RuntimeError(
        "未找到系统密钥库；安装 secret-tool，或显式设置 WECHAT_CLI_ALLOW_PLAINTEXT_KEYS=1"
    )


def create_key_provider(path, backend=None, namespace=None):
    if backend is None and os.path.exists(path):
        document = read_private_json(path)
        backend = document.get("_backend") if isinstance(document, dict) else None
        if backend is None and os.environ.get("WECHAT_CLI_ALLOW_PLAINTEXT_KEYS") != "1":
            raise RuntimeError(
                "检测到旧版明文密钥文件；请运行 wechat-cli init --force 迁移到系统密钥库"
            )
    if backend in (None, "file"):
        return JsonDatabaseKeyProvider(path)
    if backend == DpapiDatabaseKeyProvider.backend:
        return DpapiDatabaseKeyProvider(path)
    if backend == SecretServiceDatabaseKeyProvider.backend:
        return SecretServiceDatabaseKeyProvider(path, namespace)
    if backend == MacKeychainDatabaseKeyProvider.backend:
        return MacKeychainDatabaseKeyProvider(path, namespace)
    raise ValueError("不支持的密钥后端")
