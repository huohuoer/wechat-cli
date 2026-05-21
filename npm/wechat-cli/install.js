#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const PLATFORM_PACKAGES = {
  'darwin-arm64': '@canghe_ai/wechat-cli-darwin-arm64',
  'darwin-x64':   '@canghe_ai/wechat-cli-darwin-x64',
  'linux-x64':    '@canghe_ai/wechat-cli-linux-x64',
  'linux-arm64':  '@canghe_ai/wechat-cli-linux-arm64',
  'win32-x64':    '@canghe_ai/wechat-cli-win32-x64',
};

const platformKey = `${process.platform}-${process.arch}`;
const pkg = PLATFORM_PACKAGES[platformKey];

if (!pkg) {
  console.log(`wechat-cli: no binary for ${platformKey}, skipping`);
  process.exit(0);
}

// Try to find and chmod the binary
const ext = process.platform === 'win32' ? '.exe' : '';

try {
  const binaryPath = require.resolve(`${pkg}/bin/wechat-cli${ext}`);
  if (process.platform !== 'win32') {
    fs.chmodSync(binaryPath, 0o755);
    console.log(`wechat-cli: set executable permission for ${platformKey}`);
  }
  if (process.platform === 'darwin') {
    const binDir = path.dirname(binaryPath);
    spawnSync('xattr', ['-cr', binDir], { stdio: 'ignore' });
  }
} catch {
  // Platform package was not installed (npm --no-optional or unsupported)
  console.log(`wechat-cli: platform package ${pkg} not installed`);
  console.log('To fix: npm install --force @canghe_ai/wechat-cli');
}
