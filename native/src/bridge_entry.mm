#include "wechat_bridge.hpp"

#import <Foundation/Foundation.h>

#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <string>

namespace {

constexpr char kExpectedExecutable[] =
    "/Applications/WeChat.app/Contents/MacOS/WeChat";
constexpr char kBridgeInstanceTag[] = "official-task-v1";

wechat_bridge::BridgeService* g_service = nullptr;

bool ExactWeChatProcess() {
  std::uint32_t size = 0;
  if (_NSGetExecutablePath(nullptr, &size) != -1 || size == 0) {
    return false;
  }
  std::string raw(size, '\0');
  if (_NSGetExecutablePath(raw.data(), &size) != 0) {
    return false;
  }
  char resolved[PATH_MAX];
  return realpath(raw.c_str(), resolved) != nullptr &&
      std::strcmp(resolved, kExpectedExecutable) == 0 &&
      [[[NSBundle mainBundle] bundleIdentifier]
          isEqualToString:@"com.tencent.xinWeChat"];
}

bool PrepareSafeDirectory(std::string* result) {
  const passwd* user = getpwuid(geteuid());
  if (user == nullptr || user->pw_dir == nullptr || user->pw_dir[0] != '/' ||
      geteuid() != getuid()) {
    return false;
  }
  const std::string directory =
      std::string(user->pw_dir) +
      "/Library/Containers/com.tencent.xinWeChat/Data/wcb";
  struct stat metadata {};
  if (lstat(directory.c_str(), &metadata) != 0) {
    if (errno != ENOENT || mkdir(directory.c_str(), 0700) != 0) {
      return false;
    }
  }
  if (lstat(directory.c_str(), &metadata) != 0 ||
      !S_ISDIR(metadata.st_mode) || metadata.st_uid != geteuid() ||
      chmod(directory.c_str(), 0700) != 0) {
    return false;
  }
  char resolved[PATH_MAX];
  if (realpath(directory.c_str(), resolved) == nullptr ||
      directory != resolved) {
    return false;
  }
  *result = directory;
  return true;
}

void PublishStartupError(const std::string& directory,
                         const std::string& reason) {
  if (reason.empty() || reason.size() > 128 ||
      reason.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_") !=
          std::string::npos) {
    return;
  }
  const std::string path = directory + "/bridge-" +
      kBridgeInstanceTag + "-" + std::to_string(getpid()) + ".error";
  const int descriptor = open(
      path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
      0600);
  if (descriptor < 0) {
    return;
  }
  const std::string payload = reason + "\n";
  (void)write(descriptor, payload.data(), payload.size());
  (void)fchmod(descriptor, 0600);
  close(descriptor);
}

void StartBridge() {
  @autoreleasepool {
    if (!ExactWeChatProcess() || g_service != nullptr) {
      return;
    }
    std::string safe_directory;
    if (!PrepareSafeDirectory(&safe_directory)) {
      return;
    }
    std::string adapter_error;
    auto adapter =
        wechat_bridge::CreateProductionWeChatAdapter(&adapter_error);
    if (adapter == nullptr) {
      PublishStartupError(safe_directory, adapter_error);
      return;
    }
    auto service = std::make_unique<wechat_bridge::BridgeService>();
    wechat_bridge::BridgeConfig config;
    config.safe_directory = safe_directory;
    config.instance_tag = kBridgeInstanceTag;
    config.adapter_timeout_ms = 15000;
    std::string service_error;
    if (!service->Start(config, std::move(adapter), &service_error)) {
      PublishStartupError(safe_directory, service_error);
      return;
    }
    g_service = service.release();
  }
}

__attribute__((constructor)) void WechatSendBridgeEntry() {
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    StartBridge();
  });
}

}  // namespace
