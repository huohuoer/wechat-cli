#!/usr/bin/env node

const { execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const PLATFORM_PACKAGES = {
  'darwin-arm64': '@canghe_ai/wechat-cli-darwin-arm64',
  'darwin-x64':   '@canghe_ai/wechat-cli-darwin-x64',
  'linux-x64':    '@canghe_ai/wechat-cli-linux-x64',
  'linux-arm64':  '@canghe_ai/wechat-cli-linux-arm64',
  'win32-x64':    '@canghe_ai/wechat-cli-win32-x64',
};

const platformKey = `${process.platform}-${process.arch}`;
const ext = process.platform === 'win32' ? '.exe' : '';

function getBinaryPath() {
  // 1. 环境变量覆盖
  if (process.env.WECHAT_CLI_BINARY) {
    return process.env.WECHAT_CLI_BINARY;
  }

  // 2. 从平台包解析
  const pkg = PLATFORM_PACKAGES[platformKey];
  if (!pkg) {
    console.error(`wechat-cli: 暂不支持平台 ${platformKey}`);
    process.exit(1);
  }

  try {
    return require.resolve(`${pkg}/bin/wechat-cli${ext}`);
  } catch {
    // 3. 尝试从平台包目录查找，平台包缺失时也不能泄漏嵌套解析异常。
    try {
      const modPath = path.join(
        path.dirname(require.resolve(`${pkg}/package.json`)),
        `bin/wechat-cli${ext}`
      );
      if (fs.existsSync(modPath)) return modPath;
    } catch {
      // 可选平台包可能被 npm 忽略，统一输出下方安装提示。
    }
  }

  console.error(`wechat-cli: 未找到 ${platformKey} 平台包或可执行文件`);
  console.error('请重新安装: npm install --include=optional @canghe_ai/wechat-cli@0.3.0');
  process.exit(1);
}

try {
  execFileSync(getBinaryPath(), process.argv.slice(2), {
    stdio: 'inherit',
    env: { ...process.env },
  });
} catch (e) {
  if (e && e.status != null) process.exit(e.status);
  console.error(`wechat-cli: 无法启动可执行文件（${e.code || '未知错误'}），请检查安装路径和执行权限`);
  process.exit(1);
}
