"""应用上下文 — 单例持有配置、缓存、密钥等共享状态"""

import atexit
import json
import os

from .config import load_config, STATE_DIR
from .db_cache import DBCache
from .key_utils import strip_key_metadata
from .messages import find_msg_db_keys


class AppContext:
    """每次 CLI 调用初始化一次，被所有命令共享。"""

    def __init__(self, config_path=None):
        self.cfg = load_config(config_path)
        self.db_dir = self.cfg["db_dir"]
        self.decrypted_dir = self.cfg["decrypted_dir"]
        self.keys_file = self.cfg["keys_file"]

        if not os.path.exists(self.keys_file):
            raise FileNotFoundError(
                f"密钥文件不存在: {self.keys_file}\n"
                "请运行: wechat-cli init"
            )

        with open(self.keys_file, encoding="utf-8") as f:
            self.all_keys = strip_key_metadata(json.load(f))

        self.cache = DBCache(self.all_keys, self.db_dir)
        atexit.register(self.cache.cleanup)

        self.msg_db_keys = find_msg_db_keys(self.all_keys)

        # 发送服务只在 send 真正调用时执行严格预检和按需注入。
        from .contacts import get_self_username
        from .messages import _find_msg_tables_for_user
        from .native_bridge_provider import prepare_native_bridge
        from .native_sending import NativeSendService
        from .send_confirmation import MessageConfirmationStore
        from .send_preflight import verify_pre_injection

        confirmation_store = MessageConfirmationStore(
            lambda username: _find_msg_tables_for_user(
                username,
                self.msg_db_keys,
                self.cache,
            )
        )
        self.send_service = NativeSendService(
            app_context=self,
            preflight=verify_pre_injection,
            self_username_loader=lambda app: get_self_username(
                app.db_dir,
                app.cache,
                app.decrypted_dir,
            ),
            confirmation_store=confirmation_store,
            bridge_provider=prepare_native_bridge,
        )

        # 确保状态目录存在
        os.makedirs(STATE_DIR, exist_ok=True)

    def display_name_fn(self, username, names):
        from .contacts import display_name_for_username
        return display_name_for_username(username, names, self.db_dir, self.cache, self.decrypted_dir)
