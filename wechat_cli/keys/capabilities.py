"""内存扫描能力清单与只读预检。

清单只允许精确匹配已经完成真实客户端验收的组合。未知版本必须在申请
进程内存读取权限之前失败关闭。
"""

import json
import os
import platform
import subprocess
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ScannerProfile:
    profile_id: str
    platform: str
    executable: str
    client_version: str
    publisher: str
    scanner_algorithm: str
    acceptance: str


# 安全默认值：尚无任何客户端版本完成平台真实验收。
# 新条目必须绑定精确版本、发布者和算法，并把 acceptance 设为 verified。
SCANNER_PROFILES: tuple[ScannerProfile, ...] = ()


def _process_running_without_memory_access(system):
    """只查询进程列表，不申请进程句柄或读取进程内存。"""
    try:
        if system == "windows":
            tasklist = os.path.join(
                os.environ.get("SystemRoot", r"C:\Windows"), "System32", "tasklist.exe"
            )
            result = subprocess.run(
                [tasklist, "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return "Weixin.exe" in result.stdout
        executable = "WeChat" if system == "darwin" else "wechat"
        result = subprocess.run(
            ["/usr/bin/pgrep", "-x", executable],
            capture_output=True,
            timeout=10,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _windows_signed_identity():
    """读取进程路径对应文件的版本和 Authenticode 签名，不读取进程内存。"""
    windows_powershell = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"),
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
    )
    powershell = windows_powershell
    script = (
        "$p=Get-Process -Name Weixin -ErrorAction SilentlyContinue|"
        "Select-Object -First 1;"
        "if($null -ne $p -and $p.Path){"
        "$f=Get-Item -LiteralPath $p.Path;"
        "$s=Get-AuthenticodeSignature -LiteralPath $p.Path;"
        "$u=$(if($null -ne $s.SignerCertificate){$s.SignerCertificate.Subject}else{'unknown'});"
        "[pscustomobject]@{version=$f.VersionInfo.FileVersion;publisher=$u;"
        "signature_status=$($s.Status.ToString())}|ConvertTo-Json -Compress}"
    )
    try:
        child_env = os.environ.copy()
        # PowerShell 7 的模块路径会使 Windows PowerShell 5.1 加载不兼容模块。
        for name in tuple(child_env):
            if name.lower() in {"psmodulepath", "pshome"}:
                child_env.pop(name, None)
        result = subprocess.run(
            [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            env=child_env,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        document = json.loads(result.stdout)
        version = document.get("version")
        publisher = document.get("publisher")
        status = document.get("signature_status")
        if not isinstance(version, str) or not isinstance(publisher, str):
            return None
        return {
            "client_version": version.strip() or "unknown",
            "publisher": publisher.strip() or "unknown",
            "signature_valid": status == "Valid",
        }
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


def detect_client_identity():
    """返回不含密钥且不读进程内存的客户端身份摘要。"""
    system = platform.system().lower()
    executable = {"windows": "Weixin.exe", "darwin": "WeChat", "linux": "wechat"}.get(
        system, "unknown"
    )
    identity = {
        "platform": system,
        "executable": executable,
        "client_version": "unknown",
        "publisher": "unknown",
        "signature_valid": False,
        "process_running": _process_running_without_memory_access(system),
    }
    if system == "windows" and identity["process_running"]:
        signed = _windows_signed_identity()
        if signed:
            identity.update(signed)
    return identity


def evaluate_scan_capability(identity=None, profiles=SCANNER_PROFILES):
    identity = dict(identity or detect_client_identity())
    for profile in profiles:
        if (
            profile.acceptance == "verified"
            and identity.get("platform") == profile.platform
            and identity.get("executable") == profile.executable
            and identity.get("client_version") == profile.client_version
            and identity.get("publisher") == profile.publisher
            and identity.get("signature_valid") is True
        ):
            return {
                "supported": True,
                "reason_code": "WXCLI_SCAN_PROFILE_VERIFIED",
                "profile": asdict(profile),
                "identity": identity,
            }
    return {
        "supported": False,
        "reason_code": "WXCLI_SCAN_UNSUPPORTED_CLIENT",
        "profile": None,
        "identity": identity,
    }


def require_supported_memory_scan():
    result = evaluate_scan_capability()
    if not result["supported"]:
        identity = result["identity"]
        raise RuntimeError(
            "[WXCLI_SCAN_UNSUPPORTED_CLIENT] 当前客户端没有通过内存扫描验收："
            f"platform={identity['platform']}, executable={identity['executable']}, "
            f"version={identity['client_version']}, publisher={identity['publisher']}"
        )
    return result
