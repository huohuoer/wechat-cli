"""仅供 sudo 调用的密钥扫描 helper；密钥只写入父进程管道。"""

import json
import os
import sys
import tempfile
from contextlib import redirect_stdout

import click

from ..core.key_document import validate_key_document
from ..core.secure_files import read_private_json, redact_sensitive_text
from . import extract_keys


def run(db_dir):
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("helper 必须由 sudo 以 root 运行", file=sys.stderr)
        return 2

    output_path = None
    try:
        fd, output_path = tempfile.mkstemp(prefix="wechat-cli-keys-", suffix=".json")
        os.close(fd)
        os.chmod(output_path, 0o600)
        with redirect_stdout(sys.stderr):
            extract_keys(db_dir, output_path)
        document = validate_key_document(read_private_json(output_path), "扫描结果")
        json.dump(document, sys.stdout, ensure_ascii=False, separators=(",", ":"))
        sys.stdout.write("\n")
        sys.stdout.flush()
        return 0
    except Exception as error:
        message = redact_sensitive_text(str(error))
        print(f"扫描失败: {message}", file=sys.stderr)
        return 1
    finally:
        if output_path and os.path.exists(output_path):
            try:
                os.remove(output_path)
            except OSError:
                pass


@click.command(name="_elevated-scan-helper", hidden=True)
@click.argument("db_dir", type=click.Path(exists=True, file_okay=False))
@click.pass_context
def elevated_scan_helper(ctx, db_dir):
    """PyInstaller 单文件模式的内部提权入口。"""
    code = run(db_dir)
    if code:
        ctx.exit(code)


def main():
    if len(sys.argv) != 2:
        print("helper 参数无效", file=sys.stderr)
        return 2
    return run(sys.argv[1])


if __name__ == "__main__":
    raise SystemExit(main())
