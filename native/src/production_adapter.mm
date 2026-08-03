#include "wechat_bridge.hpp"

#include <dispatch/dispatch.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <utility>

namespace wechat_bridge {
namespace {

constexpr char kExpectedImagePath[] =
    "/Applications/WeChat.app/Contents/Frameworks/wechat.dylib";
constexpr std::uintptr_t kBuilderRva = 0x33729fc;
constexpr std::uintptr_t kSubmitRva = 0x695e08;
constexpr std::uintptr_t kMessageVtableRva = 0x8a100f0;
constexpr std::uintptr_t kMessageDestructorRva = 0x2ce5520;
constexpr std::uintptr_t kMessageDeletingDestructorRva = 0x4513d18;

constexpr std::array<std::uint8_t, 16> kBuilderSignature = {
    0x29, 0xdb, 0x02, 0x90, 0x29, 0x55, 0x41, 0xf9,
    0x49, 0x00, 0x00, 0xb4, 0x20, 0x01, 0x1f, 0xd6,
};
constexpr std::array<std::uint8_t, 16> kSubmitSignature = {
    0xff, 0x03, 0x03, 0xd1, 0xf8, 0x5f, 0x08, 0xa9,
    0xf6, 0x57, 0x09, 0xa9, 0xf4, 0x4f, 0x0a, 0xa9,
};
constexpr std::array<std::uint8_t, 16> kExpectedUuid = {
    0xab, 0xd8, 0x8e, 0xc8, 0x45, 0x90, 0x3f, 0xdb,
    0xaa, 0xb5, 0x4e, 0x58, 0x65, 0xb8, 0x6b, 0x2a,
};

void SetError(std::string* error, const char* value) {
  if (error != nullptr) {
    *error = value;
  }
}

std::uintptr_t FindPinnedImage() {
  for (std::uint32_t index = 0; index < _dyld_image_count(); ++index) {
    const char* name = _dyld_get_image_name(index);
    if (name != nullptr && std::strcmp(name, kExpectedImagePath) == 0) {
      return reinterpret_cast<std::uintptr_t>(
          _dyld_get_image_header(index));
    }
  }
  return 0;
}

bool UuidMatches(std::uintptr_t image_base) {
  const auto* header = reinterpret_cast<const mach_header_64*>(image_base);
  if (header == nullptr || header->magic != MH_MAGIC_64 ||
      header->cputype != CPU_TYPE_ARM64 ||
      header->sizeofcmds > 16 * 1024 * 1024) {
    return false;
  }
  const auto* command_bytes = reinterpret_cast<const std::uint8_t*>(
      header + 1);
  std::size_t offset = 0;
  for (std::uint32_t index = 0; index < header->ncmds; ++index) {
    if (offset + sizeof(load_command) > header->sizeofcmds) {
      return false;
    }
    const auto* command = reinterpret_cast<const load_command*>(
        command_bytes + offset);
    if (command->cmdsize < sizeof(load_command) ||
        command->cmdsize > header->sizeofcmds - offset) {
      return false;
    }
    if (command->cmd == LC_UUID) {
      if (command->cmdsize < sizeof(uuid_command)) {
        return false;
      }
      const auto* uuid = reinterpret_cast<const uuid_command*>(command);
      return std::memcmp(uuid->uuid, kExpectedUuid.data(),
                         kExpectedUuid.size()) == 0;
    }
    offset += command->cmdsize;
  }
  return false;
}

template <std::size_t Size>
bool SignatureMatches(std::uintptr_t address,
                      const std::array<std::uint8_t, Size>& signature) {
  return address != 0 &&
      std::memcmp(reinterpret_cast<const void*>(address),
                  signature.data(), signature.size()) == 0;
}

bool MessageVtableMatches(std::uintptr_t image_base) {
  std::array<std::uintptr_t, 2> entries{};
  std::memcpy(entries.data(),
              reinterpret_cast<const void*>(
                  image_base + kMessageVtableRva),
              sizeof(entries));
  return entries[0] == image_base + kMessageDestructorRva &&
      entries[1] == image_base + kMessageDeletingDestructorRva;
}

}  // namespace

std::shared_ptr<SendAdapter> CreateProductionWeChatAdapter(
    std::string* unsupported_reason) {
  const std::uintptr_t image_base = FindPinnedImage();
  if (image_base == 0) {
    SetError(unsupported_reason, "unsupported_wechat_build_image");
    return nullptr;
  }
  if (!UuidMatches(image_base)) {
    SetError(unsupported_reason, "unsupported_wechat_build_uuid");
    return nullptr;
  }
  if (!SignatureMatches(image_base + kBuilderRva, kBuilderSignature)) {
    SetError(unsupported_reason, "unsupported_wechat_build_builder");
    return nullptr;
  }
  if (!SignatureMatches(image_base + kSubmitRva, kSubmitSignature)) {
    SetError(unsupported_reason, "unsupported_wechat_build_submit");
    return nullptr;
  }
  if (!MessageVtableMatches(image_base)) {
    SetError(unsupported_reason, "unsupported_wechat_build_message_vtable");
    return nullptr;
  }

  OfficialTaskBindings bindings;
  bindings.image_base = image_base;
  bindings.builder_address = image_base + kBuilderRva;
  bindings.submit_address = image_base + kSubmitRva;
  bindings.main_dispatch = [](std::function<void()> work) {
    dispatch_async(dispatch_get_main_queue(), ^{
      work();
    });
  };
  auto adapter = CreateOfficialTaskAdapter(std::move(bindings));
  if (adapter == nullptr) {
    SetError(unsupported_reason, "unsupported_wechat_official_task_adapter");
  } else if (unsupported_reason != nullptr) {
    unsupported_reason->clear();
  }
  return adapter;
}

}  // namespace wechat_bridge
