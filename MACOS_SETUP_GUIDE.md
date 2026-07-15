# WeChat CLI — One-Time macOS Setup

> Do this when physically at the machine. After step 6, it never needs repeating.

---

## Step 1 — Find Your WeChat Data Directory

With WeChat logged in, run:

```bash
ls ~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/*/db_storage/
```

Note the full path (you'll need it in step 5).

## Step 2 — Quit WeChat

Cmd+Q

## Step 3 — Enter Recovery Mode

- **Apple Silicon**: Press and hold power button → click **Options** → **Continue**
- **Intel**: Restart and hold **Cmd+R**

## Step 4 — Disable SIP Debug Restriction

In Recovery Mode: **Utilities > Terminal**

```bash
csrutil enable --without debug
```

Then: Apple menu > Restart

## Step 5 — Launch WeChat & Extract Keys

Open WeChat from `/Applications`, scan QR code to log in.

Open Terminal and run (replace paths as needed):

```bash
sudo wechat-cli init \
  --db-dir "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/YOUR_WXID/db_storage"
```

The tool will auto-detect the directory if `--db-dir` is omitted and Full Disk Access is granted. If it auto-detects successfully, just run:

```bash
sudo wechat-cli init
```

Expected output shows `[+] 初始化完成!` with key count.

> **Note:** If `task_for_pid` still fails, the tool will automatically re-sign WeChat.app with `get-task-allow`. After re-signing, quit and relaunch WeChat, then run `sudo wechat-cli init` again with explicit `--db-dir`.

## Step 6 — Re-enable SIP Fully

Reboot back into Recovery Mode (same as step 3).

**Utilities > Terminal:**

```bash
csrutil enable
```

Restart normally.

## Done

The portal is ready. If using the web UI:

```bash
cd /path/to/wechat-cli
bash webui/ctrl.sh start
```

Open **http://127.0.0.1:5600** in your browser.

---

### Useful commands

| Command | What it does |
|---|---|
| `bash webui/ctrl.sh status` | Check if portal is running |
| `bash webui/ctrl.sh logs` | View server logs |
| `bash webui/ctrl.sh service install` | Install as launchd (autostart on login) |
| `bash webui/ctrl.sh service reload` | Restart after code changes |

### After setup

Keys are cached at `~/.wechat-cli/all_keys.json`. The portal and all CLI commands work even without WeChat running — they read locally decrypted files.
