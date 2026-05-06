import ctypes
import ctypes.wintypes as wt
import platform
import subprocess


_TRAY_TITLE = "WxTrayIconMessageWindow"
_TRAY_CLASS_MARK = "WxTrayIconMessageWindowClass"
_DEFAULT_PROCESS_WINDOWS = "Weixin.exe"


def detect_login_status():
    system = platform.system().lower()
    if system != "windows":
        return "unknown"

    try:
        running = _process_exists_windows(_DEFAULT_PROCESS_WINDOWS)
    except Exception:
        return "unknown"

    if not running:
        return "not_running"

    try:
        if _has_tray_window_windows():
            return "logged_in"
        return "logged_out"
    except Exception:
        return "unknown"


def _process_exists_windows(image_name):
    r = subprocess.run(
        ["tasklist", "/FI", f"IMAGENAME eq {image_name}", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
    )
    out = (r.stdout or "").strip()
    if not out:
        return False
    lower = out.lower()
    if "no tasks are running" in lower or "信息:" in out:
        return False
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.strip('"').split('","')
        if parts and parts[0].lower() == image_name.lower():
            return True
    return False


def _has_tray_window_windows():
    user32 = ctypes.windll.user32

    EnumWindows = user32.EnumWindows
    EnumWindows.argtypes = [ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM), wt.LPARAM]
    EnumWindows.restype = wt.BOOL

    GetClassNameW = user32.GetClassNameW
    GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
    GetClassNameW.restype = ctypes.c_int

    GetWindowTextW = user32.GetWindowTextW
    GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
    GetWindowTextW.restype = ctypes.c_int

    found = {"ok": False}

    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def _cb(hwnd, lparam):
        class_buf = ctypes.create_unicode_buffer(256)
        title_buf = ctypes.create_unicode_buffer(256)

        GetClassNameW(hwnd, class_buf, len(class_buf))
        GetWindowTextW(hwnd, title_buf, len(title_buf))

        title = title_buf.value or ""
        if title != _TRAY_TITLE:
            return True

        cls = class_buf.value or ""
        if _TRAY_CLASS_MARK in cls:
            found["ok"] = True
            return False

        return True

    EnumWindows(_cb, 0)
    return bool(found["ok"])

