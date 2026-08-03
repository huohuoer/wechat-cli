#include <dlfcn.h>
#include <libproc.h>
#include <mach/arm/thread_status.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits.h>
#include <string>
#include <vector>

namespace {

constexpr char kExpectedExecutable[] =
    "/Applications/WeChat.app/Contents/MacOS/WeChat";
constexpr mach_vm_size_t kRemoteStackBytes = 1024 * 1024;
constexpr std::size_t kDlopenAddressOffset = 24;
constexpr std::size_t kPthreadExitAddressOffset = 32;
constexpr std::size_t kBootstrapParkOffset = 40;
constexpr std::size_t kLoaderStubBytes = 44;

struct RemoteMemory {
  mach_vm_size_t page_size = 0;
  mach_vm_address_t data = 0;
  mach_vm_address_t code = 0;
  mach_vm_address_t stack = 0;
};

void PrintError(const char* value) {
  std::fprintf(stderr, "%s\n", value);
}

bool ParsePid(const char* value, pid_t* pid) {
  if (value == nullptr || *value == '\0') {
    return false;
  }
  char* end = nullptr;
  errno = 0;
  const long parsed = std::strtol(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed <= 1 ||
      parsed > INT32_MAX) {
    return false;
  }
  *pid = static_cast<pid_t>(parsed);
  return true;
}

bool ExactRegularDylib(const char* supplied, std::string* resolved_path) {
  if (supplied == nullptr || supplied[0] != '/') {
    return false;
  }
  char resolved[PATH_MAX];
  if (realpath(supplied, resolved) == nullptr ||
      std::strcmp(supplied, resolved) != 0) {
    return false;
  }
  struct stat metadata {};
  if (lstat(resolved, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
      metadata.st_nlink != 1 ||
      (metadata.st_uid != geteuid() && metadata.st_uid != 0) ||
      (metadata.st_mode & 0022) != 0 || metadata.st_size <= 0) {
    return false;
  }
  const std::string path(resolved);
  if (path.size() < 6 || path.compare(path.size() - 6, 6, ".dylib") != 0) {
    return false;
  }
  *resolved_path = path;
  return true;
}

bool ExactTarget(pid_t pid) {
  char path[PROC_PIDPATHINFO_MAXSIZE] = {};
  const int size = proc_pidpath(pid, path, sizeof(path));
  if (size <= 0 || std::strcmp(path, kExpectedExecutable) != 0) {
    return false;
  }
  proc_bsdinfo info {};
  const int info_size = proc_pidinfo(
      pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
  return info_size == sizeof(info) && info.pbi_uid == geteuid();
}

bool WriteRemote(task_t task,
                 mach_vm_address_t destination,
                 const void* bytes,
                 mach_vm_size_t size) {
  return mach_vm_write(
             task, destination,
             reinterpret_cast<vm_offset_t>(bytes),
             static_cast<mach_msg_type_number_t>(size)) == KERN_SUCCESS;
}

bool AllocateRemoteMemory(task_t task, RemoteMemory* memory) {
  memory->page_size = static_cast<mach_vm_size_t>(getpagesize());
  return memory->page_size >= 4096 &&
      mach_vm_allocate(task, &memory->data, memory->page_size * 2,
                       VM_FLAGS_ANYWHERE) == KERN_SUCCESS &&
      mach_vm_allocate(task, &memory->code, memory->page_size,
                       VM_FLAGS_ANYWHERE) == KERN_SUCCESS &&
      mach_vm_allocate(task, &memory->stack, kRemoteStackBytes,
                       VM_FLAGS_ANYWHERE) == KERN_SUCCESS;
}

bool VerifyMemoryLayout() {
  RemoteMemory memory;
  if (!AllocateRemoteMemory(mach_task_self(), &memory)) {
    return false;
  }
  const mach_vm_address_t pthread_storage =
      memory.data + memory.page_size;
  const bool separate_pages =
      memory.code / memory.page_size !=
          pthread_storage / memory.page_size;
  const bool protected_code =
      mach_vm_protect(mach_task_self(), memory.code, memory.page_size, false,
                      VM_PROT_READ | VM_PROT_EXECUTE) == KERN_SUCCESS;
  const std::uint64_t marker = 0x7763627061676573ULL;
  const bool writable_storage =
      WriteRemote(mach_task_self(), pthread_storage, &marker,
                  sizeof(marker));
  mach_vm_deallocate(mach_task_self(), memory.data, memory.page_size * 2);
  mach_vm_deallocate(mach_task_self(), memory.code, memory.page_size);
  mach_vm_deallocate(mach_task_self(), memory.stack, kRemoteStackBytes);
  return separate_pages && protected_code && writable_storage;
}

std::vector<std::uint8_t> BuildLoaderStub(
    std::uintptr_t dlopen_address,
    std::uintptr_t pthread_exit_address) {
  // dlopen(path, RTLD_NOW | RTLD_LOCAL), then terminate the created pthread.
  // pthread_create_from_mach_thread does not provide a return address that a
  // raw `ret` start routine can safely use on every supported macOS build.
  std::vector<std::uint8_t> stub(kLoaderStubBytes, 0);
  const std::uint32_t instructions[] = {
      0xd28000c1u,  // mov x1, #6
      0x580000b0u,  // ldr x16, dlopen address
      0xd63f0200u,  // blr x16
      0xd2800000u,  // mov x0, #0
      0x58000090u,  // ldr x16, pthread_exit address
      0xd61f0200u,  // br x16
  };
  const std::uint32_t park = 0x14000000u;
  std::memcpy(stub.data(), instructions, sizeof(instructions));
  std::memcpy(
      stub.data() + kDlopenAddressOffset,
      &dlopen_address,
      sizeof(dlopen_address));
  std::memcpy(
      stub.data() + kPthreadExitAddressOffset,
      &pthread_exit_address,
      sizeof(pthread_exit_address));
  std::memcpy(stub.data() + kBootstrapParkOffset, &park, sizeof(park));
  return stub;
}

bool VerifyLoaderStub() {
  constexpr std::uintptr_t kDlopenMarker = 0x1122334455667788ULL;
  constexpr std::uintptr_t kPthreadExitMarker = 0x8877665544332211ULL;
  const std::vector<std::uint8_t> stub =
      BuildLoaderStub(kDlopenMarker, kPthreadExitMarker);
  std::uintptr_t observed_dlopen = 0;
  std::uintptr_t observed_pthread_exit = 0;
  std::uint32_t exit_branch = 0;
  std::uint32_t park = 0;
  if (stub.size() != kLoaderStubBytes) {
    return false;
  }
  std::memcpy(
      &observed_dlopen,
      stub.data() + kDlopenAddressOffset,
      sizeof(observed_dlopen));
  std::memcpy(
      &observed_pthread_exit,
      stub.data() + kPthreadExitAddressOffset,
      sizeof(observed_pthread_exit));
  std::memcpy(&exit_branch, stub.data() + 20, sizeof(exit_branch));
  std::memcpy(&park, stub.data() + kBootstrapParkOffset, sizeof(park));
  return observed_dlopen == kDlopenMarker &&
      observed_pthread_exit == kPthreadExitMarker &&
      exit_branch == 0xd61f0200u && park == 0x14000000u;
}

int Inject(pid_t pid, const std::string& dylib_path) {
  if (!ExactTarget(pid)) {
    PrintError("target_wechat_identity_mismatch");
    return 3;
  }

  mach_port_t task = MACH_PORT_NULL;
  kern_return_t status = task_for_pid(mach_task_self(), pid, &task);
  if (status != KERN_SUCCESS || task == MACH_PORT_NULL) {
    PrintError("task_for_pid_denied_re_sign_wechat_with_debug_entitlements");
    return 3;
  }

  void* pthread_entry =
      dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
  void* dlopen_entry = dlsym(RTLD_DEFAULT, "dlopen");
  void* pthread_exit_entry = dlsym(RTLD_DEFAULT, "pthread_exit");
  if (pthread_entry == nullptr || dlopen_entry == nullptr ||
      pthread_exit_entry == nullptr) {
    PrintError("required_system_loader_symbols_unavailable");
    mach_port_deallocate(mach_task_self(), task);
    return 3;
  }

  RemoteMemory memory;
  if (!AllocateRemoteMemory(task, &memory)) {
    PrintError("remote_memory_allocation_failed");
    mach_port_deallocate(mach_task_self(), task);
    return 3;
  }

  const mach_vm_address_t remote_path = memory.data;
  const mach_vm_address_t remote_pthread = memory.data + memory.page_size;
  const mach_vm_address_t remote_stub = memory.code;
  const mach_vm_address_t remote_loop =
      remote_stub + kBootstrapParkOffset;
  if (!WriteRemote(task, remote_path, dylib_path.c_str(),
                   dylib_path.size() + 1)) {
    PrintError("remote_path_write_failed");
    mach_port_deallocate(mach_task_self(), task);
    return 3;
  }

  const std::uintptr_t dlopen_address =
      reinterpret_cast<std::uintptr_t>(dlopen_entry);
  const std::uintptr_t pthread_exit_address =
      reinterpret_cast<std::uintptr_t>(pthread_exit_entry);
  const std::vector<std::uint8_t> stub =
      BuildLoaderStub(dlopen_address, pthread_exit_address);
  if (!WriteRemote(task, remote_stub, stub.data(), stub.size()) ||
      mach_vm_protect(task, remote_stub, memory.page_size, false,
                      VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS) {
    PrintError("remote_loader_stub_write_failed");
    mach_port_deallocate(mach_task_self(), task);
    return 3;
  }

  arm_thread_state64_t thread_state {};
  thread_state.__x[0] = remote_pthread;
  thread_state.__x[1] = 0;
  thread_state.__x[2] = remote_stub;
  thread_state.__x[3] = remote_path;
  arm_thread_state64_set_pc_fptr(
      thread_state, reinterpret_cast<void (*)()>(pthread_entry));
  arm_thread_state64_set_lr_fptr(
      thread_state, reinterpret_cast<void (*)()>(remote_loop));
  arm_thread_state64_set_sp(
      thread_state, memory.stack + kRemoteStackBytes - 0x100);

  thread_act_t bootstrap_thread = MACH_PORT_NULL;
  status = thread_create_running(
      task, ARM_THREAD_STATE64,
      reinterpret_cast<thread_state_t>(&thread_state),
      ARM_THREAD_STATE64_COUNT, &bootstrap_thread);
  if (status != KERN_SUCCESS) {
    PrintError("remote_loader_thread_creation_failed");
    mach_port_deallocate(mach_task_self(), task);
    return 3;
  }

  // The bootstrap thread only creates a real pthread and then parks. Wait
  // until it reaches that safe point before terminating the bootstrap.
  bool parked = false;
  for (int attempt = 0; attempt < 100; ++attempt) {
    arm_thread_state64_t observed {};
    mach_msg_type_number_t observed_count = ARM_THREAD_STATE64_COUNT;
    if (thread_get_state(
            bootstrap_thread, ARM_THREAD_STATE64,
            reinterpret_cast<thread_state_t>(&observed),
            &observed_count) == KERN_SUCCESS &&
        arm_thread_state64_get_pc(observed) == remote_loop) {
      parked = true;
      break;
    }
    usleep(10000);
  }
  if (parked) {
    thread_terminate(bootstrap_thread);
  }
  mach_port_deallocate(mach_task_self(), bootstrap_thread);
  mach_port_deallocate(mach_task_self(), task);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 2 &&
      std::strcmp(argv[1], "--verify-memory-layout") == 0) {
    return VerifyMemoryLayout() ? 0 : 5;
  }
  if (argc == 2 &&
      std::strcmp(argv[1], "--verify-loader-stub") == 0) {
    return VerifyLoaderStub() ? 0 : 5;
  }
  if (argc != 3) {
    PrintError("usage: wechat_send_injector PID ABSOLUTE_DYLIB_PATH");
    return 2;
  }
  pid_t pid = 0;
  std::string dylib_path;
  if (!ParsePid(argv[1], &pid) ||
      !ExactRegularDylib(argv[2], &dylib_path)) {
    PrintError("invalid_injector_arguments");
    return 2;
  }
  return Inject(pid, dylib_path);
}
