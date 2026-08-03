#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace wechat_bridge {

inline constexpr std::uint32_t kProtocolVersion = 1;
inline constexpr std::size_t kMaximumFrameBytes = 1024 * 1024;

struct SendRequest {
  std::string request_id;
  std::string group;
  std::string username;
  std::string text;
};

enum class AckState {
  kAcknowledged,
  kSubmitted,
  kUnknown,
};

struct SendReceipt {
  AckState ack_state = AckState::kUnknown;
  std::optional<std::int64_t> local_id;
  std::optional<std::int64_t> server_id;
};

using SendCompletion = std::function<void(SendReceipt)>;

// Implementations must enqueue work on their captured message queue and invoke
// completion asynchronously. The bridge itself never calls WeChat internals.
class SendAdapter {
 public:
  virtual ~SendAdapter() = default;
  virtual void Send(const SendRequest& request, SendCompletion completion) = 0;
};

struct LocalMessageIdentity {
  std::int64_t local_id = 0;
  std::uint64_t client_id = 0;
  std::uint32_t create_time = 0;
};

struct NetworkAcceptance {
  bool accepted = false;
  std::int64_t server_id = 0;
};

using LocalInsertCompletion =
    std::function<void(std::optional<LocalMessageIdentity>)>;
using NetworkCompletion = std::function<void(NetworkAcceptance)>;
using LocalUpdateCompletion = std::function<void(bool)>;

class LocalMessageGateway {
 public:
  virtual ~LocalMessageGateway() = default;
  virtual void InsertOutgoing(const SendRequest& request,
                              std::uint64_t client_id,
                              std::uint32_t create_time,
                              LocalInsertCompletion completion) = 0;
  virtual void MarkAccepted(const LocalMessageIdentity& identity,
                            std::int64_t server_id,
                            LocalUpdateCompletion completion) = 0;
};

class MarsGateway {
 public:
  virtual ~MarsGateway() = default;
  virtual void Submit(const SendRequest& request,
                      const LocalMessageIdentity& identity,
                      NetworkCompletion completion) = 0;
};

std::shared_ptr<SendAdapter> CreateLocalVisibleAdapter(
    std::shared_ptr<LocalMessageGateway> local,
    std::shared_ptr<MarsGateway> mars);

struct OfficialTaskBindings {
  std::uintptr_t image_base = 0;
  std::uintptr_t builder_address = 0;
  std::uintptr_t submit_address = 0;
  void* builder_service = nullptr;
  std::function<void(std::function<void()>)> main_dispatch;
};

// Exposed for the native fake host so the pinned ABI can be tested without
// loading WeChat. Production callers use CreateProductionWeChatAdapter.
std::shared_ptr<SendAdapter> CreateOfficialTaskAdapter(
    OfficialTaskBindings bindings);

struct BridgeConfig {
  std::string safe_directory;
  std::string instance_tag;
  std::uint32_t adapter_timeout_ms = 15000;
};

class BridgeService {
 public:
  BridgeService();
  ~BridgeService();

  BridgeService(const BridgeService&) = delete;
  BridgeService& operator=(const BridgeService&) = delete;

  bool Start(const BridgeConfig& config,
             std::shared_ptr<SendAdapter> adapter,
             std::string* error);
  void Stop();

  std::string metadata_path() const;
  std::string socket_path() const;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

// Creates the strictly pinned WeChat 4.1.8.28 ARM64 adapter. Any path,
// instruction signature, or build mismatch fails before sending is enabled.
std::shared_ptr<SendAdapter> CreateProductionWeChatAdapter(
    std::string* unsupported_reason);

// Shared by the pinned adapter and its native fake-host contract test.
bool VerifyUnusedHookIslandBytes(const void* bytes, std::size_t size);
int HookWriteProtection();
int EmptyTextResponseStatus();

}  // namespace wechat_bridge
