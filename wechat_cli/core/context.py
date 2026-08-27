"""应用上下文 — 单例持有配置、缓存、密钥等共享状态"""

import atexit
import os

from .config import load_config, STATE_DIR
from .db_cache import DBCache
from .key_document import create_key_provider
from .messages import find_msg_db_keys
from .secure_files import ensure_private_directory


class AppContext:
    """每次 CLI 调用初始化一次，被所有命令共享。"""

    def __init__(self, config_path=None):
        ensure_private_directory(STATE_DIR, tighten_existing=True)
        self.cfg = load_config(config_path)
        self.db_dir = self.cfg["db_dir"]
        self.decrypted_dir = self.cfg["decrypted_dir"]
        self.keys_file = self.cfg["keys_file"]

        if not os.path.exists(self.keys_file):
            raise FileNotFoundError(
                f"密钥文件不存在: {self.keys_file}\n"
                "请运行: wechat-cli init"
            )

        self.key_provider = create_key_provider(
            self.keys_file,
            backend=self.cfg.get("key_backend"),
            namespace=self.cfg.get("key_namespace"),
        )

        self.cache = DBCache(self.key_provider, self.db_dir, STATE_DIR)
        atexit.register(self.cache.cleanup)

        self.msg_db_keys = find_msg_db_keys(self.key_provider.references())

    def display_name_fn(self, username, names):
        from .contacts import display_name_for_username
        return display_name_for_username(username, names, self.db_dir, self.cache, self.decrypted_dir)
