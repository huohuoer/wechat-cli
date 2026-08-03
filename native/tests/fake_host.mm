#include "wechat_bridge.hpp"

#import <Foundation/Foundation.h>

#include <dispatch/dispatch.h>
#include <mach/vm_prot.h>
#include <signal.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

volatile sig_atomic_t g_stop_requested = 0;

void HandleStop(int) {
  g_stop_requested = 1;
}

class FakeQueuedAdapter final : public wechat_bridge::SendAdapter {
 public:
  FakeQueuedAdapter(dispatch_queue_t message_queue,
                    wechat_bridge::AckState ack_state,
                    unsigned int delay_ms)
      : message_queue_(message_queue),
        ack_state_(ack_state),
        delay_ms_(delay_ms) {}

  void Send(const wechat_bridge::SendRequest&,
            wechat_bridge::SendCompletion completion) override {
    dispatch_async(message_queue_, ^{
      const int active = active_.fetch_add(1) + 1;
      calls_.fetch_add(1);
      int observed = max_active_.load();
      while (active > observed &&
             !max_active_.compare_exchange_weak(observed, active)) {
      }
      if (delay_ms_ > 0) {
        usleep(delay_ms_ * 1000);
      }
      wechat_bridge::SendReceipt receipt;
      receipt.ack_state = ack_state_;
      if (ack_state_ == wechat_bridge::AckState::kAcknowledged) {
        receipt.local_id = 41;
        receipt.server_id = 99;
      }
      active_.fetch_sub(1);
      completion(std::move(receipt));
    });
  }

  int calls() const { return calls_.load(); }
  int max_active() const { return max_active_.load(); }

 private:
  dispatch_queue_t message_queue_;
  wechat_bridge::AckState ack_state_;
  unsigned int delay_ms_;
  std::atomic<int> calls_{0};
  std::atomic<int> active_{0};
  std::atomic<int> max_active_{0};
};

enum class TransactionScenario {
  kInsertFailed,
  kNetworkUnknown,
  kAccepted,
};

struct TransactionStats {
  int insert_calls = 0;
  int network_calls = 0;
  int update_calls = 0;
  std::uint64_t insert_client_id = 0;
  std::uint64_t network_client_id = 0;
  std::int64_t insert_local_id = 0;
  std::int64_t update_local_id = 0;
};

class FakeLocalMessageGateway final
    : public wechat_bridge::LocalMessageGateway {
 public:
  FakeLocalMessageGateway(TransactionScenario scenario,
                          TransactionStats* stats)
      : scenario_(scenario), stats_(stats) {}

  void InsertOutgoing(const wechat_bridge::SendRequest&,
                      std::uint64_t client_id,
                      std::uint32_t create_time,
                      wechat_bridge::LocalInsertCompletion completion)
      override {
    ++stats_->insert_calls;
    stats_->insert_client_id = client_id;
    if (scenario_ == TransactionScenario::kInsertFailed) {
      completion(std::nullopt);
      return;
    }
    wechat_bridge::LocalMessageIdentity identity;
    identity.local_id = 41;
    identity.client_id = client_id;
    identity.create_time = create_time;
    stats_->insert_local_id = identity.local_id;
    completion(identity);
  }

  void MarkAccepted(const wechat_bridge::LocalMessageIdentity& identity,
                    std::int64_t,
                    wechat_bridge::LocalUpdateCompletion completion)
      override {
    ++stats_->update_calls;
    stats_->update_local_id = identity.local_id;
    completion(true);
  }

 private:
  TransactionScenario scenario_;
  TransactionStats* stats_;
};

class FakeMarsGateway final : public wechat_bridge::MarsGateway {
 public:
  FakeMarsGateway(TransactionScenario scenario, TransactionStats* stats)
      : scenario_(scenario), stats_(stats) {}

  void Submit(const wechat_bridge::SendRequest&,
              const wechat_bridge::LocalMessageIdentity& identity,
              wechat_bridge::NetworkCompletion completion) override {
    ++stats_->network_calls;
    stats_->network_client_id = identity.client_id;
    wechat_bridge::NetworkAcceptance acceptance;
    if (scenario_ == TransactionScenario::kAccepted) {
      acceptance.accepted = true;
      acceptance.server_id = 99;
    }
    completion(acceptance);
  }

 private:
  TransactionScenario scenario_;
  TransactionStats* stats_;
};

constexpr std::uintptr_t kFakeWechatBase = 0x100000000ULL;
constexpr std::uintptr_t kMessageVtableRva = 0x8a100f0;
constexpr std::uint64_t kTaskMarker = 0x4f4646494349414cULL;
constexpr std::uint64_t kHandleMarker = 0x5355424d49545445ULL;

struct alignas(8) FakeOfficialTask {
  std::array<std::uint8_t, 0x38> bytes{};
};

struct alignas(8) FakeOfficialHandle {
  std::array<std::uint8_t, 0x28> bytes{};
};

struct alignas(16) FakeEmptyCallback {
  std::array<std::uint8_t, 0x20> bytes{};
};

struct FakeSourceLocation {
  const char* file = nullptr;
  const char* function = nullptr;
  std::uint64_t line = 0;
  const void* return_address = nullptr;
};

static_assert(sizeof(FakeOfficialTask) == 0x38);
static_assert(sizeof(FakeOfficialHandle) == 0x28);
static_assert(sizeof(FakeEmptyCallback) == 0x20);
static_assert(sizeof(FakeSourceLocation) == 0x20);

enum class OfficialTaskScenario {
  kSubmitted,
  kBuilderThrows,
  kSubmitThrows,
  kInvalidRequest,
};

struct OfficialTaskStats {
  OfficialTaskScenario scenario = OfficialTaskScenario::kSubmitted;
  int dispatch_calls = 0;
  int builder_calls = 0;
  int submit_calls = 0;
  int completion_calls = 0;
  bool in_dispatch = false;
  bool builder_on_dispatch = false;
  bool submit_on_dispatch = false;
  bool single_message = false;
  bool service_matches = false;
  bool model_matches = false;
  bool task_matches = false;
  bool callbacks_empty = false;
  bool source_location_matches = false;
  std::weak_ptr<void> model_owner;
  std::vector<std::string> calls;
  std::optional<wechat_bridge::SendReceipt> receipt;
};

OfficialTaskStats* g_official_task_stats = nullptr;

template <typename T>
T LoadModelValue(const void* model, std::size_t offset) {
  T value{};
  std::memcpy(&value,
              static_cast<const std::uint8_t*>(model) + offset,
              sizeof(value));
  return value;
}

bool AllZero(const void* bytes, std::size_t size) {
  const auto* first = static_cast<const std::uint8_t*>(bytes);
  return std::all_of(first, first + size,
                     [](std::uint8_t value) { return value == 0; });
}

FakeOfficialTask FakeOfficialBuilder(
    void* service,
    std::vector<std::shared_ptr<void>>* messages,
    bool single_message) {
  OfficialTaskStats& stats = *g_official_task_stats;
  ++stats.builder_calls;
  stats.calls.emplace_back("builder");
  stats.builder_on_dispatch = stats.in_dispatch;
  stats.single_message = single_message;
  stats.service_matches = service == nullptr;
  if (messages != nullptr && messages->size() == 1 &&
      messages->front() != nullptr) {
    const auto& alias = messages->front();
    const void* model = alias.get();
    const auto* weak_self = reinterpret_cast<const std::weak_ptr<void>*>(
        static_cast<const std::uint8_t*>(model) + 0x08);
    const auto owned_self = weak_self->lock();
    const auto* recipient = reinterpret_cast<const std::string*>(
        static_cast<const std::uint8_t*>(model) + 0x90);
    const auto* request_id = reinterpret_cast<const std::string*>(
        static_cast<const std::uint8_t*>(model) + 0x4c8);
    const auto* text = reinterpret_cast<const std::string*>(
        static_cast<const std::uint8_t*>(model) + 0x510);
    const auto* trailing = reinterpret_cast<const std::string*>(
        static_cast<const std::uint8_t*>(model) + 0x528);
    stats.model_matches =
        LoadModelValue<std::uintptr_t>(model, 0) ==
            kFakeWechatBase + kMessageVtableRva &&
        owned_self.get() == model && alias.get() == model &&
        *recipient == "59034084590@chatroom" &&
        *request_id == "12345678-1234-1234-1234-123456789abc" &&
        *text == "测试" && trailing->empty() &&
        LoadModelValue<std::uint32_t>(model, 0x7c) == 1 &&
        LoadModelValue<std::uint32_t>(model, 0x84) == 7 &&
        LoadModelValue<std::uint64_t>(model, 0xb0) == 1 &&
        LoadModelValue<std::uint64_t>(model, 0x138) == text->size();
    stats.model_owner = alias;
  }
  if (stats.scenario == OfficialTaskScenario::kBuilderThrows) {
    throw std::runtime_error("fake builder failure");
  }
  FakeOfficialTask task;
  std::memcpy(task.bytes.data(), &kTaskMarker, sizeof(kTaskMarker));
  return task;
}

FakeOfficialHandle FakeOfficialSubmit(
    const FakeOfficialTask& task,
    const FakeEmptyCallback& first_callback,
    const FakeEmptyCallback& second_callback,
    const FakeEmptyCallback& third_callback,
    const FakeSourceLocation& location) {
  OfficialTaskStats& stats = *g_official_task_stats;
  ++stats.submit_calls;
  stats.calls.emplace_back("submit");
  stats.submit_on_dispatch = stats.in_dispatch;
  stats.task_matches =
      LoadModelValue<std::uint64_t>(&task, 0) == kTaskMarker;
  stats.callbacks_empty =
      AllZero(&first_callback, sizeof(first_callback)) &&
      AllZero(&second_callback, sizeof(second_callback)) &&
      AllZero(&third_callback, sizeof(third_callback));
  stats.source_location_matches =
      location.file != nullptr && location.file[0] != '\0' &&
      location.function != nullptr && location.function[0] != '\0' &&
      location.line != 0 && location.return_address != nullptr;
  if (stats.scenario == OfficialTaskScenario::kSubmitThrows) {
    throw std::runtime_error("fake submit failure");
  }
  FakeOfficialHandle handle;
  std::memcpy(handle.bytes.data(), &kHandleMarker, sizeof(kHandleMarker));
  return handle;
}

int VerifyOfficialTaskAdapter(const char* raw_scenario) {
  OfficialTaskStats stats;
  if (std::strcmp(raw_scenario, "submitted") == 0) {
    stats.scenario = OfficialTaskScenario::kSubmitted;
  } else if (std::strcmp(raw_scenario, "builder-throws") == 0) {
    stats.scenario = OfficialTaskScenario::kBuilderThrows;
  } else if (std::strcmp(raw_scenario, "submit-throws") == 0) {
    stats.scenario = OfficialTaskScenario::kSubmitThrows;
  } else if (std::strcmp(raw_scenario, "invalid-request") == 0) {
    stats.scenario = OfficialTaskScenario::kInvalidRequest;
  } else {
    return 2;
  }

  g_official_task_stats = &stats;
  wechat_bridge::OfficialTaskBindings bindings;
  bindings.image_base = kFakeWechatBase;
  bindings.builder_address =
      reinterpret_cast<std::uintptr_t>(&FakeOfficialBuilder);
  bindings.submit_address =
      reinterpret_cast<std::uintptr_t>(&FakeOfficialSubmit);
  bindings.main_dispatch = [&stats](std::function<void()> work) {
    ++stats.dispatch_calls;
    stats.in_dispatch = true;
    work();
    stats.in_dispatch = false;
  };
  auto adapter = wechat_bridge::CreateOfficialTaskAdapter(bindings);
  if (adapter == nullptr) {
    return 20;
  }

  wechat_bridge::SendRequest request;
  request.request_id = "12345678-1234-1234-1234-123456789abc";
  request.group = "AI聊天群";
  request.username = "59034084590@chatroom";
  request.text = "测试";
  if (stats.scenario == OfficialTaskScenario::kInvalidRequest) {
    request.username = "not-a-chatroom";
  }
  adapter->Send(request, [&stats](wechat_bridge::SendReceipt receipt) {
    ++stats.completion_calls;
    stats.receipt = std::move(receipt);
  });
  g_official_task_stats = nullptr;

  if (stats.scenario == OfficialTaskScenario::kInvalidRequest) {
    return stats.dispatch_calls == 0 && stats.builder_calls == 0 &&
            stats.submit_calls == 0 && stats.completion_calls == 1 &&
            stats.receipt.has_value() &&
            stats.receipt->ack_state == wechat_bridge::AckState::kUnknown
        ? 0
        : 21;
  }
  if (stats.dispatch_calls != 1 || stats.builder_calls != 1 ||
      stats.completion_calls != 1 || !stats.builder_on_dispatch ||
      !stats.single_message || !stats.service_matches ||
      !stats.model_matches || stats.model_owner.expired()) {
    return 22;
  }
  if (stats.scenario == OfficialTaskScenario::kBuilderThrows) {
    return stats.submit_calls == 0 && stats.calls == std::vector<std::string>{
               "builder"} && stats.receipt.has_value() &&
            stats.receipt->ack_state == wechat_bridge::AckState::kUnknown
        ? 0
        : 23;
  }
  if (stats.submit_calls != 1 || !stats.submit_on_dispatch ||
      stats.calls != std::vector<std::string>{"builder", "submit"} ||
      !stats.task_matches || !stats.callbacks_empty ||
      !stats.source_location_matches || !stats.receipt.has_value()) {
    return 24;
  }
  if (stats.scenario == OfficialTaskScenario::kSubmitThrows) {
    return stats.receipt->ack_state == wechat_bridge::AckState::kUnknown
        ? 0
        : 25;
  }
  return stats.receipt->ack_state == wechat_bridge::AckState::kSubmitted &&
          !stats.receipt->local_id.has_value() &&
          !stats.receipt->server_id.has_value()
      ? 0
      : 26;
}

void PrintOptionalId(const std::optional<std::int64_t>& value) {
  if (value.has_value()) {
    std::printf("%lld", static_cast<long long>(value.value()));
  } else {
    std::fputs("null", stdout);
  }
}

int VerifyLocalVisibleTransaction(const char* raw_scenario) {
  TransactionScenario scenario;
  if (std::strcmp(raw_scenario, "insert-failed") == 0) {
    scenario = TransactionScenario::kInsertFailed;
  } else if (std::strcmp(raw_scenario, "network-unknown") == 0) {
    scenario = TransactionScenario::kNetworkUnknown;
  } else if (std::strcmp(raw_scenario, "accepted") == 0) {
    scenario = TransactionScenario::kAccepted;
  } else {
    return 2;
  }

  TransactionStats stats;
  auto local = std::make_shared<FakeLocalMessageGateway>(scenario, &stats);
  auto mars = std::make_shared<FakeMarsGateway>(scenario, &stats);
  auto adapter = wechat_bridge::CreateLocalVisibleAdapter(local, mars);
  if (adapter == nullptr) {
    return 10;
  }
  wechat_bridge::SendRequest request;
  request.request_id = "12345678-1234-1234-1234-123456789abc";
  request.group = "AI聊天群";
  request.username = "59034084590@chatroom";
  request.text = "测试";
  std::optional<wechat_bridge::SendReceipt> receipt;
  adapter->Send(request, [&](wechat_bridge::SendReceipt value) {
    receipt = std::move(value);
  });
  if (!receipt.has_value()) {
    return 11;
  }

  std::printf(
      "{\"insert_calls\":%d,\"network_calls\":%d,"
      "\"update_calls\":%d,\"insert_client_id\":%llu,"
      "\"network_client_id\":%llu,\"insert_local_id\":%lld,"
      "\"update_local_id\":%lld,\"receipt\":{\"ack_state\":\"%s\","
      "\"local_id\":",
      stats.insert_calls, stats.network_calls, stats.update_calls,
      static_cast<unsigned long long>(stats.insert_client_id),
      static_cast<unsigned long long>(stats.network_client_id),
      static_cast<long long>(stats.insert_local_id),
      static_cast<long long>(stats.update_local_id),
      receipt->ack_state == wechat_bridge::AckState::kAcknowledged
          ? "acknowledged"
          : "unknown");
  PrintOptionalId(receipt->local_id);
  std::fputs(",\"server_id\":", stdout);
  PrintOptionalId(receipt->server_id);
  std::fputs("}}\n", stdout);
  return 0;
}

bool ParseUnsigned(const char* raw, unsigned int* value) {
  if (raw == nullptr || *raw == '\0') {
    return false;
  }
  char* end = nullptr;
  errno = 0;
  const unsigned long parsed = std::strtoul(raw, &end, 10);
  if (errno != 0 || *end != '\0' || parsed > 60000) {
    return false;
  }
  *value = static_cast<unsigned int>(parsed);
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  @autoreleasepool {
    if (argc == 2 &&
        std::strcmp(argv[1], "--verify-official-task-adapter") == 0) {
      const int result = VerifyOfficialTaskAdapter("submitted");
      if (result == 0) {
        std::fputs(
            "{\"dispatch_calls\":1,\"builder_calls\":1,"
            "\"submit_calls\":1,\"builder_before_submit\":true,"
            "\"builder_service_is_null\":true,\"builder_mode\":1,"
            "\"model_fields_valid\":true,"
            "\"vector_aliases_model\":true,"
            "\"vector_shares_ownership\":true,"
            "\"callbacks_empty\":true,"
            "\"source_location_valid\":true,"
            "\"receipt\":{\"ack_state\":\"submitted\","
            "\"local_id\":null,\"server_id\":null}}\n",
            stdout);
      }
      return result;
    }
    if (argc == 3 &&
        std::strcmp(argv[1], "--verify-official-task-adapter") == 0) {
      return VerifyOfficialTaskAdapter(argv[2]);
    }
    if (argc == 3 &&
        std::strcmp(argv[1], "--verify-local-visible-transaction") == 0) {
      return VerifyLocalVisibleTransaction(argv[2]);
    }
    if (argc == 2 &&
        std::strcmp(argv[1], "--verify-empty-response-status") == 0) {
      return wechat_bridge::EmptyTextResponseStatus() == 0 ? 0 : 8;
    }
    if (argc == 2 &&
        std::strcmp(argv[1], "--verify-hook-write-protection") == 0) {
      const int protection = wechat_bridge::HookWriteProtection();
      return (protection & VM_PROT_WRITE) != 0 &&
                     (protection & VM_PROT_EXECUTE) == 0
                 ? 0
                 : 7;
    }
    if (argc == 2 &&
        std::strcmp(argv[1], "--verify-hook-island-signature") == 0) {
      std::uint8_t unused[32] = {};
      std::uint8_t occupied[32] = {};
      occupied[17] = 1;
      return wechat_bridge::VerifyUnusedHookIslandBytes(
                     unused, sizeof(unused)) &&
                 !wechat_bridge::VerifyUnusedHookIslandBytes(
                     occupied, sizeof(occupied)) &&
                 !wechat_bridge::VerifyUnusedHookIslandBytes(
                     unused, sizeof(unused) - 1)
             ? 0
             : 6;
    }
    if (argc == 2 &&
        (std::strcmp(argv[1], "--verify-production-profile-incomplete") == 0 ||
         std::strcmp(argv[1], "--verify-production-image-rejected") == 0)) {
      std::string reason;
      const auto adapter =
          wechat_bridge::CreateProductionWeChatAdapter(&reason);
      return adapter == nullptr &&
                 reason == "unsupported_wechat_build_image"
          ? 0
          : 14;
    }
    std::string safe_directory;
    wechat_bridge::AckState ack_state =
        wechat_bridge::AckState::kAcknowledged;
    unsigned int delay_ms = 0;
    unsigned int adapter_timeout_ms = 3000;
    std::string instance_tag;
    bool start_once = false;
    for (int index = 1; index < argc; ++index) {
      if (std::strcmp(argv[index], "--safe-directory") == 0 &&
          index + 1 < argc) {
        safe_directory = argv[++index];
      } else if (std::strcmp(argv[index], "--ack-state") == 0 &&
                 index + 1 < argc) {
        const char* value = argv[++index];
        if (std::strcmp(value, "acknowledged") == 0) {
          ack_state = wechat_bridge::AckState::kAcknowledged;
        } else if (std::strcmp(value, "submitted") == 0) {
          ack_state = wechat_bridge::AckState::kSubmitted;
        } else if (std::strcmp(value, "unknown") == 0) {
          ack_state = wechat_bridge::AckState::kUnknown;
        } else {
          return 2;
        }
      } else if (std::strcmp(argv[index], "--delay-ms") == 0 &&
                 index + 1 < argc) {
        if (!ParseUnsigned(argv[++index], &delay_ms)) {
          return 2;
        }
      } else if (std::strcmp(argv[index], "--adapter-timeout-ms") == 0 &&
                 index + 1 < argc) {
        if (!ParseUnsigned(argv[++index], &adapter_timeout_ms) ||
            adapter_timeout_ms == 0) {
          return 2;
        }
      } else if (std::strcmp(argv[index], "--instance-tag") == 0 &&
                 index + 1 < argc) {
        instance_tag = argv[++index];
      } else if (std::strcmp(argv[index], "--start-once") == 0) {
        start_once = true;
      } else {
        return 2;
      }
    }
    if (safe_directory.empty()) {
      return 2;
    }

    struct sigaction action {};
    action.sa_handler = HandleStop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, nullptr) != 0 ||
        sigaction(SIGINT, &action, nullptr) != 0) {
      return 3;
    }

    dispatch_queue_t message_queue =
        dispatch_queue_create("wechat.bridge.fake-message-queue",
                              DISPATCH_QUEUE_SERIAL);
    auto adapter = std::make_shared<FakeQueuedAdapter>(
        message_queue, ack_state, delay_ms);
    wechat_bridge::BridgeService service;
    wechat_bridge::BridgeConfig config;
    config.safe_directory = safe_directory;
    config.instance_tag = instance_tag;
    config.adapter_timeout_ms = adapter_timeout_ms;
    std::string error;
    if (!service.Start(config, adapter, &error)) {
      std::fputs("native fake host could not start\n", stderr);
      return 4;
    }
    if (start_once) {
      service.Stop();
      return 0;
    }

    while (!g_stop_requested) {
      usleep(10000);
    }
    service.Stop();
    std::printf("STATS %d %d\n", adapter->calls(), adapter->max_active());
    std::fflush(stdout);
    return 0;
  }
}
