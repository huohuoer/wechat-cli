#include "wechat_bridge.hpp"

#import <Foundation/Foundation.h>

#include <dispatch/dispatch.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace wechat_bridge {
namespace {

// Strict profile for WeChat 4.1.8.28 (36571), arm64.
constexpr std::uintptr_t kReq2BufEnterRva = 0x3806b30;
constexpr std::uintptr_t kReq2BufExitRva = 0x3807c44;
constexpr std::uintptr_t kReq2BufEnterIslandRva = 0x4e12cc8;
constexpr std::uintptr_t kReq2BufExitIslandRva = 0x4e12cd8;
constexpr std::uintptr_t kSerializeBytesRva = 0x382d820;
constexpr std::uintptr_t kContextLookupRva = 0x490f494;
constexpr std::uintptr_t kNetworkCoreGetterRva = 0x4964574;
constexpr std::uintptr_t kStartTaskRva = 0x498d2e0;
constexpr std::uintptr_t kOriginalTaskVtableRva = 0x8915f28;

constexpr std::uint32_t kReq2BufEnterSignature = 0xf8460f09;
constexpr std::uint32_t kReq2BufExitSignature = 0xa8c66ffc;
constexpr std::uint32_t kStartTaskSignature = 0xd10503ff;
constexpr std::uint32_t kContextLookupSignature = 0xd10643ff;
constexpr std::uint32_t kNetworkCoreGetterSignature = 0xd10103ff;
constexpr std::uint32_t kFirstTaskId = 0x20010000;
constexpr std::size_t kTriggerBytes = 1024;
constexpr std::size_t kTaskObjectBytes = 0x120;
constexpr std::size_t kWrapperBytes = 0x30;
constexpr std::size_t kMaximumTextBytes = 512 * 1024;

extern "C" void WechatBridgeReq2BufEnterHook();
extern "C" void WechatBridgeReq2BufExitHook();
extern "C" std::uintptr_t WechatBridgeReq2BufEnterContinue;
extern "C" std::uintptr_t WechatBridgeReq2BufExitContinue;

using SerializeBytesFn = void (*)(void*, const void*, std::uint32_t);
using ContextLookupFn = void* (*)(const std::string*);
using NetworkCoreGetterFn = void* (*)(void*);
using StartTaskFn = std::int64_t (*)(void*, void*);

struct PendingSend {
  std::uint32_t task_id = 0;
  std::array<std::uint8_t, kTriggerBytes> trigger{};
  std::array<std::uint8_t, kTaskObjectBytes> task_object{};
  std::array<std::uint8_t, kWrapperBytes> wrapper{};
  std::array<std::uintptr_t, 8> vtable{};
  std::array<char, 64> cgi{};
  std::vector<std::uint8_t> protobuf;
  void** inserted_slot = nullptr;
  SendCompletion completion;
};

std::mutex g_pending_mutex;
std::shared_ptr<PendingSend> g_pending;
// Mars may retain the task object for Resp2Buf/cleanup after Req2Buf returns.
// The bridge is process-scoped, so keeping completed task storage until WeChat
// exits is safer than guessing an asynchronous lifetime and risking UAF.
std::vector<std::shared_ptr<PendingSend>> g_retired_tasks;
std::uintptr_t g_wechat_base = 0;
SerializeBytesFn g_serialize_bytes = nullptr;
std::atomic<std::uint32_t> g_next_task_id{kFirstTaskId};

bool EndsWith(const char* value, const char* suffix) {
  if (value == nullptr || suffix == nullptr) {
    return false;
  }
  const std::size_t value_size = std::strlen(value);
  const std::size_t suffix_size = std::strlen(suffix);
  return value_size >= suffix_size &&
      std::memcmp(value + value_size - suffix_size, suffix, suffix_size) == 0;
}

std::uintptr_t FindPinnedWeChatImage() {
  static constexpr char kExpectedPath[] =
      "/Applications/WeChat.app/Contents/Frameworks/wechat.dylib";
  for (std::uint32_t index = 0; index < _dyld_image_count(); ++index) {
    const char* name = _dyld_get_image_name(index);
    if (name != nullptr && std::strcmp(name, kExpectedPath) == 0) {
      return reinterpret_cast<std::uintptr_t>(_dyld_get_image_header(index));
    }
  }
  return 0;
}

bool WordMatches(std::uintptr_t address, std::uint32_t expected) {
  std::uint32_t actual = 0;
  std::memcpy(&actual, reinterpret_cast<const void*>(address), sizeof(actual));
  return actual == expected;
}

std::uint32_t BranchInstruction(std::uintptr_t source,
                                std::uintptr_t destination) {
  const std::int64_t delta = static_cast<std::int64_t>(destination) -
      static_cast<std::int64_t>(source);
  if ((delta & 3) != 0 || delta < -(1LL << 27) || delta >= (1LL << 27)) {
    return 0;
  }
  return 0x14000000u |
      (static_cast<std::uint32_t>(delta >> 2) & 0x03ffffffu);
}

void WriteAbsoluteJump(std::uintptr_t island, std::uintptr_t destination) {
  // ldr x17, #8; br x17; .quad destination
  const std::array<std::uint32_t, 2> instructions = {
      0x58000051u,
      0xd61f0220u,
  };
  std::memcpy(reinterpret_cast<void*>(island), instructions.data(),
              sizeof(instructions));
  std::memcpy(reinterpret_cast<void*>(island + sizeof(instructions)),
              &destination, sizeof(destination));
}

bool PatchHookBranches(std::uintptr_t enter,
                       std::uintptr_t enter_island,
                       std::uintptr_t exit,
                       std::uintptr_t exit_island) {
  const std::uint32_t enter_branch = BranchInstruction(enter, enter_island);
  const std::uint32_t exit_branch = BranchInstruction(exit, exit_island);
  if (enter_branch == 0 || exit_branch == 0) {
    return false;
  }
  const mach_vm_size_t page_size = static_cast<mach_vm_size_t>(getpagesize());
  const mach_vm_address_t first_page = enter & ~(page_size - 1);
  const mach_vm_address_t last_page = exit & ~(page_size - 1);
  const mach_vm_size_t span = last_page - first_page + page_size;
  if (mach_vm_protect(mach_task_self(), first_page, span, false,
                      HookWriteProtection()) != KERN_SUCCESS) {
    return false;
  }
  std::memcpy(reinterpret_cast<void*>(enter), &enter_branch,
              sizeof(enter_branch));
  std::memcpy(reinterpret_cast<void*>(exit), &exit_branch,
              sizeof(exit_branch));
  sys_icache_invalidate(reinterpret_cast<void*>(enter), sizeof(enter_branch));
  sys_icache_invalidate(reinterpret_cast<void*>(exit), sizeof(exit_branch));
  return mach_vm_protect(mach_task_self(), first_page, span, false,
                         VM_PROT_READ | VM_PROT_EXECUTE) == KERN_SUCCESS;
}

bool InstallReq2BufHooks(std::string* error) {
  const std::uintptr_t enter = g_wechat_base + kReq2BufEnterRva;
  const std::uintptr_t exit = g_wechat_base + kReq2BufExitRva;
  const std::uintptr_t enter_island =
      g_wechat_base + kReq2BufEnterIslandRva;
  const std::uintptr_t exit_island =
      g_wechat_base + kReq2BufExitIslandRva;
  if (!VerifyUnusedHookIslandBytes(
          reinterpret_cast<const void*>(enter_island), 32)) {
    if (error != nullptr) {
      *error = "wechat_hook_island_signature_failed";
    }
    return false;
  }
  if (BranchInstruction(enter, enter_island) == 0 ||
      BranchInstruction(exit, exit_island) == 0) {
    if (error != nullptr) {
      *error = "wechat_hook_island_out_of_range";
    }
    return false;
  }
  const mach_vm_size_t page_size = static_cast<mach_vm_size_t>(getpagesize());
  const mach_vm_address_t island_page = enter_island & ~(page_size - 1);
  if (mach_vm_protect(mach_task_self(), island_page, page_size, false,
                      HookWriteProtection()) != KERN_SUCCESS) {
    if (error != nullptr) {
      *error = "wechat_hook_island_protection_failed";
    }
    return false;
  }
  WriteAbsoluteJump(
      enter_island,
      reinterpret_cast<std::uintptr_t>(&WechatBridgeReq2BufEnterHook));
  WriteAbsoluteJump(
      exit_island,
      reinterpret_cast<std::uintptr_t>(&WechatBridgeReq2BufExitHook));
  sys_icache_invalidate(reinterpret_cast<void*>(island_page), 32);
  if (mach_vm_protect(mach_task_self(), island_page,
                      page_size, false,
                      VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS) {
    if (error != nullptr) {
      *error = "wechat_hook_island_restore_failed";
    }
    return false;
  }
  WechatBridgeReq2BufEnterContinue = enter + 4;
  WechatBridgeReq2BufExitContinue = exit + 4;
  if (!PatchHookBranches(enter, enter_island, exit, exit_island)) {
    if (error != nullptr) {
      *error = "wechat_hook_target_patch_failed";
    }
    return false;
  }
  return true;
}

void AppendVarint(std::vector<std::uint8_t>* output, std::uint64_t value) {
  while (value >= 0x80) {
    output->push_back(static_cast<std::uint8_t>(value) | 0x80);
    value >>= 7;
  }
  output->push_back(static_cast<std::uint8_t>(value));
}

void AppendBytesField(std::vector<std::uint8_t>* output,
                      std::uint8_t tag,
                      const std::uint8_t* bytes,
                      std::size_t size) {
  output->push_back(tag);
  AppendVarint(output, size);
  output->insert(output->end(), bytes, bytes + size);
}

std::vector<std::uint8_t> BuildTextRequest(const SendRequest& request,
                                           std::uint32_t task_id) {
  const auto* username = reinterpret_cast<const std::uint8_t*>(
      request.username.data());
  const auto* text = reinterpret_cast<const std::uint8_t*>(request.text.data());

  std::vector<std::uint8_t> builtin_username;
  AppendBytesField(&builtin_username, 0x0a, username, request.username.size());

  std::vector<std::uint8_t> message;
  AppendBytesField(&message, 0x0a, builtin_username.data(),
                   builtin_username.size());
  AppendBytesField(&message, 0x12, text, request.text.size());
  message.push_back(0x18);
  message.push_back(0x01);
  message.push_back(0x20);
  AppendVarint(&message, static_cast<std::uint64_t>(
      [[NSDate date] timeIntervalSince1970]));
  message.push_back(0x28);
  AppendVarint(&message,
               (static_cast<std::uint64_t>(task_id) << 1) |
                   static_cast<std::uint32_t>(arc4random_uniform(2)));
  static constexpr char kMessageSource[] =
      "<msgsource><alnode><fr>1</fr></alnode></msgsource>\0";
  AppendBytesField(&message, 0x32,
                   reinterpret_cast<const std::uint8_t*>(kMessageSource),
                   sizeof(kMessageSource) - 1);

  std::vector<std::uint8_t> request_bytes;
  request_bytes.push_back(0x08);
  request_bytes.push_back(0x01);
  AppendBytesField(&request_bytes, 0x12, message.data(), message.size());
  return request_bytes;
}

void NoopDestructor(void*) {}

bool SerializeTextTask(void* self, void* output, void*, std::uint8_t* error) {
  if (error != nullptr) {
    *error = 0;
  }
  std::shared_ptr<PendingSend> pending;
  {
    std::lock_guard<std::mutex> lock(g_pending_mutex);
    if (g_pending != nullptr && g_pending->task_object.data() == self) {
      pending = g_pending;
    }
  }
  if (pending == nullptr || g_serialize_bytes == nullptr ||
      pending->protobuf.empty() || pending->protobuf.size() > UINT32_MAX) {
    return false;
  }
  g_serialize_bytes(output, pending->protobuf.data(),
                    static_cast<std::uint32_t>(pending->protobuf.size()));
  return true;
}

int IgnoreTextResponse(void*, void*) {
  return EmptyTextResponseStatus();
}

void* RequestStorage(void* self) {
  return static_cast<std::uint8_t*>(self) + 0xb8;
}

void* ResponseStorage(void* self) {
  return static_cast<std::uint8_t*>(self) + 0xe8;
}

void StorePointer(void* bytes, std::size_t offset, const void* value) {
  std::memcpy(static_cast<std::uint8_t*>(bytes) + offset, &value,
              sizeof(value));
}

template <typename T>
void StoreValue(void* bytes, std::size_t offset, T value) {
  std::memcpy(static_cast<std::uint8_t*>(bytes) + offset, &value,
              sizeof(value));
}

// Opaque MMStartTask request layout for the pinned build. These bytes describe
// task scheduling metadata only; recipient and text are serialized separately.
constexpr std::array<std::uint8_t, 420> kTriggerTemplate = {
    0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x40, 0xec, 0x0e, 0x12, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x01, 0x01, 0x01,
    0x00, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xaa, 0xaa, 0xaa, 0xff, 0xff, 0xff, 0xff,
    0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x2d, 0x6c, 0x6f, 0x6e, 0x67,
    0x6c, 0x69, 0x6e, 0x6b, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

void PrepareOpaqueObjects(const std::shared_ptr<PendingSend>& pending) {
  std::memcpy(pending->trigger.data() + 4, kTriggerTemplate.data(),
              kTriggerTemplate.size());
  StoreValue(pending->trigger.data(), 0, pending->task_id);
  static constexpr char kCgi[] = "/cgi-bin/micromsg-bin/newsendmsg";
  std::memcpy(pending->cgi.data(), kCgi, sizeof(kCgi));
  StorePointer(pending->trigger.data(), 0x18, pending->cgi.data());
  StorePointer(pending->trigger.data(), 0xb8,
               pending->trigger.data() + 0xc0);
  StorePointer(pending->trigger.data(), 0x190,
               pending->trigger.data() + 0x198);

  pending->vtable[0] = 0;
  std::memcpy(
      &pending->vtable[1],
      reinterpret_cast<const void*>(
          g_wechat_base + kOriginalTaskVtableRva - sizeof(std::uintptr_t)),
      sizeof(std::uintptr_t));
  pending->vtable[2] = reinterpret_cast<std::uintptr_t>(&NoopDestructor);
  pending->vtable[3] = reinterpret_cast<std::uintptr_t>(&NoopDestructor);
  pending->vtable[4] = reinterpret_cast<std::uintptr_t>(&SerializeTextTask);
  pending->vtable[5] = reinterpret_cast<std::uintptr_t>(&IgnoreTextResponse);
  pending->vtable[6] = reinterpret_cast<std::uintptr_t>(&RequestStorage);
  pending->vtable[7] = reinterpret_cast<std::uintptr_t>(&ResponseStorage);
  const void* vtable_pointer = pending->vtable.data() + 2;
  StorePointer(pending->task_object.data(), 0, vtable_pointer);
  StoreValue(pending->task_object.data(), 0x08, pending->task_id);
  StoreValue<std::uint32_t>(pending->task_object.data(), 0x0c, 0x20a);
  StoreValue<std::uint64_t>(pending->task_object.data(), 0x10, 3);
  StorePointer(pending->task_object.data(), 0x18, pending->cgi.data());
  StoreValue<std::uint64_t>(pending->task_object.data(), 0x20, 0x20);

  StoreValue<std::uint64_t>(pending->wrapper.data(), 0x18, 1);
  StoreValue(pending->wrapper.data(), 0x20, pending->task_id);
  StorePointer(pending->wrapper.data(), 0x28, pending->task_object.data());
}

void CompleteUnknown(const std::shared_ptr<PendingSend>& pending) {
  if (pending == nullptr || !pending->completion) {
    return;
  }
  SendReceipt receipt;
  receipt.ack_state = AckState::kUnknown;
  auto completion = std::move(pending->completion);
  completion(std::move(receipt));
}

class MarsTextSendAdapter final : public SendAdapter {
 public:
  void Send(const SendRequest& request, SendCompletion completion) override {
    if (request.username.empty() || request.text.empty() ||
        request.text.size() > kMaximumTextBytes ||
        !EndsWith(request.username.c_str(), "@chatroom")) {
      SendReceipt receipt;
      receipt.ack_state = AckState::kUnknown;
      completion(std::move(receipt));
      return;
    }

    auto pending = std::make_shared<PendingSend>();
    pending->task_id = g_next_task_id.fetch_add(1);
    if (pending->task_id < kFirstTaskId) {
      pending->task_id = kFirstTaskId;
      g_next_task_id.store(kFirstTaskId + 1);
    }
    pending->completion = std::move(completion);
    pending->protobuf = BuildTextRequest(request, pending->task_id);
    PrepareOpaqueObjects(pending);

    bool already_sending = false;
    {
      std::lock_guard<std::mutex> lock(g_pending_mutex);
      if (g_pending != nullptr) {
        already_sending = true;
      } else {
        g_pending = pending;
      }
    }
    if (already_sending) {
      CompleteUnknown(pending);
      return;
    }

    dispatch_async(dispatch_get_main_queue(), ^{
      const auto context_lookup = reinterpret_cast<ContextLookupFn>(
          g_wechat_base + kContextLookupRva);
      const auto getter = reinterpret_cast<NetworkCoreGetterFn>(
          g_wechat_base + kNetworkCoreGetterRva);
      const auto start = reinterpret_cast<StartTaskFn>(
          g_wechat_base + kStartTaskRva);
      const std::string context_name("default");
      void* context = context_lookup(&context_name);
      void* core = context == nullptr ? nullptr : getter(context);
      if (core == nullptr || start(core, pending->trigger.data()) == 0) {
        std::shared_ptr<PendingSend> failed;
        {
          std::lock_guard<std::mutex> lock(g_pending_mutex);
          if (g_pending == pending) {
            failed = std::move(g_pending);
          }
        }
        CompleteUnknown(failed);
      }
    });
  }
};

}  // namespace

bool VerifyUnusedHookIslandBytes(const void* bytes, std::size_t size) {
  if (bytes == nullptr || size != 32) {
    return false;
  }
  const auto* value = static_cast<const std::uint8_t*>(bytes);
  return std::all_of(value, value + size,
                     [](std::uint8_t byte) { return byte == 0; });
}

int HookWriteProtection() {
  return VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY;
}

int EmptyTextResponseStatus() {
  // Mars Buf2Resp returns zero for a successfully decoded response.
  return 0;
}

extern "C" {
std::uintptr_t WechatBridgeReq2BufEnterContinue = 0;
std::uintptr_t WechatBridgeReq2BufExitContinue = 0;
}

extern "C" void WechatBridgeHandleReq2BufEnter(std::uint64_t task_id,
                                                void* x24) {
  std::lock_guard<std::mutex> lock(g_pending_mutex);
  if (g_pending == nullptr ||
      static_cast<std::uint32_t>(task_id) != g_pending->task_id ||
      x24 == nullptr) {
    return;
  }
  auto** slot = reinterpret_cast<void**>(
      static_cast<std::uint8_t*>(x24) + 0x60);
  *slot = g_pending->wrapper.data();
  g_pending->inserted_slot = slot;
}

extern "C" void WechatBridgeHandleReq2BufExit(std::uint64_t task_id) {
  std::shared_ptr<PendingSend> completed;
  {
    std::lock_guard<std::mutex> lock(g_pending_mutex);
    if (g_pending == nullptr ||
        static_cast<std::uint32_t>(task_id) != g_pending->task_id) {
      return;
    }
    if (g_pending->inserted_slot != nullptr &&
        *g_pending->inserted_slot == g_pending->wrapper.data()) {
      *g_pending->inserted_slot = nullptr;
    }
    completed = std::move(g_pending);
    g_retired_tasks.push_back(completed);
  }
  CompleteUnknown(completed);
}

std::shared_ptr<SendAdapter> CreateLegacyMarsWeChatAdapter(
    std::string* unsupported_reason) {
  g_wechat_base = FindPinnedWeChatImage();
  if (g_wechat_base == 0 ||
      !WordMatches(g_wechat_base + kReq2BufEnterRva,
                   kReq2BufEnterSignature) ||
      !WordMatches(g_wechat_base + kReq2BufExitRva,
                   kReq2BufExitSignature) ||
      !WordMatches(g_wechat_base + kStartTaskRva, kStartTaskSignature) ||
      !WordMatches(g_wechat_base + kContextLookupRva,
                   kContextLookupSignature) ||
      !WordMatches(g_wechat_base + kNetworkCoreGetterRva,
                   kNetworkCoreGetterSignature)) {
    if (unsupported_reason != nullptr) {
      *unsupported_reason = "unsupported_wechat_build";
    }
    return nullptr;
  }
  g_serialize_bytes = reinterpret_cast<SerializeBytesFn>(
      g_wechat_base + kSerializeBytesRva);
  std::string hook_error;
  if (!InstallReq2BufHooks(&hook_error)) {
    if (unsupported_reason != nullptr) {
      *unsupported_reason = hook_error.empty()
          ? "wechat_hook_install_failed"
          : hook_error;
    }
    return nullptr;
  }
  return std::make_shared<MarsTextSendAdapter>();
}

}  // namespace wechat_bridge
