#include "wechat_bridge.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <utility>
#include <vector>

namespace wechat_bridge {
namespace {

constexpr std::uintptr_t kMessageVtableRva = 0x8a100f0;
constexpr std::size_t kMessageBytes = 0x540;
constexpr std::size_t kMaximumTextBytes = 512 * 1024;

constexpr std::size_t kWeakSelfOffset = 0x08;
constexpr std::size_t kRecipientOffset = 0x90;
constexpr std::size_t kRequestIdOffset = 0x4c8;
constexpr std::size_t kTextOffset = 0x510;
constexpr std::size_t kTrailingStringOffset = 0x528;

struct alignas(8) OpaqueTask {
  std::array<std::uint8_t, 0x38> bytes{};
};

struct alignas(8) OpaqueHandle {
  std::array<std::uint8_t, 0x28> bytes{};
};

struct alignas(16) EmptyCallback {
  std::array<std::uint8_t, 0x20> bytes{};
};

struct SourceLocation {
  const char* file = nullptr;
  const char* function = nullptr;
  std::uint64_t line = 0;
  const void* return_address = nullptr;
};

static_assert(sizeof(OpaqueTask) == 0x38);
static_assert(sizeof(OpaqueHandle) == 0x28);
static_assert(sizeof(EmptyCallback) == 0x20);
static_assert(sizeof(SourceLocation) == 0x20);

extern "C" void WechatBridgeInvokeOfficialTaskBuilder(
    std::uintptr_t function,
    void* output,
    void* service,
    void* messages,
    bool single_message);
extern "C" void WechatBridgeInvokeOfficialTaskSubmit(
    std::uintptr_t function,
    void* output,
    const void* task,
    const void* first_callback,
    const void* second_callback,
    const void* third_callback,
    const void* source_location);

struct alignas(16) MessageStorage {
  MessageStorage() {
    bytes.fill(0);
    new (At<std::weak_ptr<void>>(kWeakSelfOffset)) std::weak_ptr<void>();
    new (At<std::string>(kRecipientOffset)) std::string();
    new (At<std::string>(kRequestIdOffset)) std::string();
    new (At<std::string>(kTextOffset)) std::string();
    new (At<std::string>(kTrailingStringOffset)) std::string();
  }

  ~MessageStorage() {
    At<std::string>(kTrailingStringOffset)->~basic_string();
    At<std::string>(kTextOffset)->~basic_string();
    At<std::string>(kRequestIdOffset)->~basic_string();
    At<std::string>(kRecipientOffset)->~basic_string();
    At<std::weak_ptr<void>>(kWeakSelfOffset)->~weak_ptr();
  }

  template <typename T>
  T* At(std::size_t offset) {
    return reinterpret_cast<T*>(bytes.data() + offset);
  }

  std::array<std::uint8_t, kMessageBytes> bytes{};
};

static_assert(sizeof(MessageStorage) == kMessageBytes);

struct PendingOfficialSend {
  std::mutex completion_mutex;
  bool completed = false;
  std::shared_ptr<MessageStorage> storage;
  std::vector<std::shared_ptr<void>> messages;
  OpaqueTask task;
  OpaqueHandle handle;
  EmptyCallback first_callback;
  EmptyCallback second_callback;
  EmptyCallback third_callback;
  SourceLocation source_location;
  SendCompletion completion;
};

std::mutex g_retained_mutex;
std::vector<std::shared_ptr<PendingOfficialSend>> g_retained_sends;

bool EndsWithChatroom(const std::string& username) {
  static constexpr char kSuffix[] = "@chatroom";
  constexpr std::size_t kSuffixSize = sizeof(kSuffix) - 1;
  return username.size() >= kSuffixSize &&
      username.compare(username.size() - kSuffixSize,
                       kSuffixSize, kSuffix) == 0;
}

template <typename T>
void Store(MessageStorage* storage, std::size_t offset, T value) {
  std::memcpy(storage->bytes.data() + offset, &value, sizeof(value));
}

std::shared_ptr<MessageStorage> BuildMessage(
    std::uintptr_t image_base,
    const SendRequest& request) {
  auto storage = std::make_shared<MessageStorage>();
  Store(storage.get(), 0, image_base + kMessageVtableRva);
  *storage->At<std::string>(kRecipientOffset) = request.username;
  *storage->At<std::string>(kRequestIdOffset) = request.request_id;
  *storage->At<std::string>(kTextOffset) = request.text;
  Store<std::uint32_t>(storage.get(), 0x7c, 1);
  Store<std::uint32_t>(storage.get(), 0x84, 7);
  Store<std::uint64_t>(storage.get(), 0xb0, 1);
  Store<std::uint64_t>(storage.get(), 0x138, request.text.size());

  std::shared_ptr<void> alias(storage, storage.get());
  *storage->At<std::weak_ptr<void>>(kWeakSelfOffset) = alias;
  return storage;
}

void Retain(const std::shared_ptr<PendingOfficialSend>& pending) {
  std::lock_guard<std::mutex> lock(g_retained_mutex);
  g_retained_sends.push_back(pending);
}

void Complete(const std::shared_ptr<PendingOfficialSend>& pending,
              AckState ack_state) {
  SendCompletion completion;
  {
    std::lock_guard<std::mutex> lock(pending->completion_mutex);
    if (pending->completed) {
      return;
    }
    pending->completed = true;
    completion = std::move(pending->completion);
  }
  if (completion) {
    SendReceipt receipt;
    receipt.ack_state = ack_state;
    completion(std::move(receipt));
  }
}

const void* SourceReturnAddress() {
  const void* address = __builtin_return_address(0);
  return address == nullptr
      ? reinterpret_cast<const void*>(&SourceReturnAddress)
      : address;
}

class OfficialTaskAdapter final : public SendAdapter {
 public:
  explicit OfficialTaskAdapter(OfficialTaskBindings bindings)
      : bindings_(std::move(bindings)) {}

  void Send(const SendRequest& request, SendCompletion completion) override {
    if (request.request_id.empty() || request.request_id.size() > 256 ||
        request.text.empty() || request.text.size() > kMaximumTextBytes ||
        !EndsWithChatroom(request.username)) {
      if (completion) {
        SendReceipt receipt;
        receipt.ack_state = AckState::kUnknown;
        completion(std::move(receipt));
      }
      return;
    }

    auto pending = std::make_shared<PendingOfficialSend>();
    pending->storage = BuildMessage(bindings_.image_base, request);
    pending->messages.emplace_back(pending->storage,
                                   pending->storage.get());
    pending->source_location.file = "official_task_adapter.mm";
    pending->source_location.function = "OfficialTaskAdapter::Send";
    pending->source_location.line = __LINE__;
    pending->source_location.return_address = SourceReturnAddress();
    pending->completion = std::move(completion);

    const OfficialTaskBindings bindings = bindings_;
    bindings.main_dispatch([pending, bindings] {
      // Builder/submit may hand ownership to asynchronous WeChat work. Keep
      // every attempted send alive for the process lifetime rather than guess
      // opaque destructors or retry an uncertain submission.
      Retain(pending);
      try {
        WechatBridgeInvokeOfficialTaskBuilder(
            bindings.builder_address, &pending->task,
            bindings.builder_service, &pending->messages, true);
        WechatBridgeInvokeOfficialTaskSubmit(
            bindings.submit_address, &pending->handle, &pending->task,
            &pending->first_callback, &pending->second_callback,
            &pending->third_callback, &pending->source_location);
        Complete(pending, AckState::kSubmitted);
      } catch (...) {
        Complete(pending, AckState::kUnknown);
      }
    });
  }

 private:
  OfficialTaskBindings bindings_;
};

}  // namespace

std::shared_ptr<SendAdapter> CreateOfficialTaskAdapter(
    OfficialTaskBindings bindings) {
  if (bindings.image_base == 0 || bindings.builder_address == 0 ||
      bindings.submit_address == 0 || !bindings.main_dispatch) {
    return nullptr;
  }
  return std::make_shared<OfficialTaskAdapter>(std::move(bindings));
}

}  // namespace wechat_bridge
