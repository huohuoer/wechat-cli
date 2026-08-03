#!/bin/bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
  echo "native bridge builds only on macOS ARM64" >&2
  exit 2
fi

if [[ $# -ne 1 || -z "$1" ]]; then
  echo "usage: native/build.sh OUTPUT_DIRECTORY" >&2
  exit 2
fi

script_directory="$(cd "$(dirname "$0")" && pwd)"
output_directory="$1"
compiler="$(xcrun --find clang++)"
sdk_path="$(xcrun --sdk macosx --show-sdk-path)"

mkdir -p "$output_directory"

common_flags=(
  -std=c++17
  -arch arm64
  -isysroot "$sdk_path"
  -I"$sdk_path/usr/include/c++/v1"
  -mmacosx-version-min=13.0
  -fobjc-arc
  -fblocks
  -Wall
  -Wextra
  -Werror
  -I"$script_directory/include"
)

"$compiler" "${common_flags[@]}" \
  -dynamiclib \
  -Wl,-install_name,@rpath/libwechat_bridge_core.dylib \
  "$script_directory/src/bridge_service.mm" \
  "$script_directory/src/local_visible_adapter.mm" \
  "$script_directory/src/official_task_adapter.mm" \
  "$script_directory/src/production_adapter.mm" \
  "$script_directory/src/wechat_adapter.mm" \
  "$script_directory/src/official_task_trampolines.S" \
  "$script_directory/src/hook_trampolines.S" \
  -framework Foundation \
  -framework Security \
  -o "$output_directory/libwechat_bridge_core.dylib"

"$compiler" "${common_flags[@]}" \
  "$script_directory/tests/fake_host.mm" \
  -L"$output_directory" \
  -lwechat_bridge_core \
  -Wl,-rpath,@loader_path \
  -framework Foundation \
  -o "$output_directory/native_fake_host"

"$compiler" "${common_flags[@]}" \
  -dynamiclib \
  -Wl,-install_name,@rpath/libwechat_official_task_bridge_v2.dylib \
  "$script_directory/src/bridge_service.mm" \
  "$script_directory/src/official_task_adapter.mm" \
  "$script_directory/src/production_adapter.mm" \
  "$script_directory/src/official_task_trampolines.S" \
  "$script_directory/src/bridge_entry.mm" \
  -framework Foundation \
  -framework Security \
  -o "$output_directory/libwechat_official_task_bridge_v2.dylib"

"$compiler" "${common_flags[@]}" \
  "$script_directory/src/injector.cc" \
  -o "$output_directory/wechat_send_injector"

codesign --force --sign - "$output_directory/libwechat_official_task_bridge_v2.dylib"
codesign --force --sign - "$output_directory/wechat_send_injector"
