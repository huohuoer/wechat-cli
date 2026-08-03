#include "wechat_bridge.hpp"

#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/stdio.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <utility>

namespace wechat_bridge {
namespace {

bool ValidInstanceTag(const std::string& value) {
  if (value.size() > 32) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](unsigned char byte) {
    return (byte >= 'a' && byte <= 'z') ||
        (byte >= '0' && byte <= '9') || byte == '-';
  });
}

constexpr std::size_t kTokenBytes = 32;
constexpr int kClientIoTimeoutSeconds = 5;
constexpr std::size_t kMaximumJsonDepth = 64;
constexpr std::size_t kMaximumGroupBytes = 16 * 1024;
constexpr std::size_t kMaximumUsernameBytes = 4096;

bool WriteAll(int descriptor, const std::uint8_t* bytes, std::size_t size) {
  std::size_t written = 0;
  while (written < size) {
    const ssize_t count =
        write(descriptor, bytes + written, size - written);
    if (count > 0) {
      written += static_cast<std::size_t>(count);
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    return false;
  }
  return true;
}

bool ReadAll(int descriptor, std::uint8_t* bytes, std::size_t size) {
  std::size_t received = 0;
  while (received < size) {
    const ssize_t count =
        read(descriptor, bytes + received, size - received);
    if (count > 0) {
      received += static_cast<std::size_t>(count);
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    return false;
  }
  return true;
}

bool IsIntegerNumber(NSNumber* value) {
  if (value == nil || CFGetTypeID((__bridge CFTypeRef)value) ==
                          CFBooleanGetTypeID()) {
    return false;
  }
  const char type = value.objCType[0];
  return std::strchr("cCsSiIlLqQ", type) != nullptr;
}

std::string Utf8(NSString* value) {
  NSData* data = [value dataUsingEncoding:NSUTF8StringEncoding];
  return std::string(static_cast<const char*>(data.bytes), data.length);
}

class JsonSyntaxScanner {
 public:
  JsonSyntaxScanner(const std::uint8_t* bytes, std::size_t size)
      : bytes_(bytes), size_(size) {}

  bool Parse() {
    SkipWhitespace();
    if (!ParseValue(0)) {
      return false;
    }
    SkipWhitespace();
    return position_ == size_;
  }

 private:
  bool ParseValue(std::size_t depth) {
    if (position_ >= size_ || depth > kMaximumJsonDepth) {
      return false;
    }
    switch (bytes_[position_]) {
      case '{':
        return ParseObject(depth + 1);
      case '[':
        return ParseArray(depth + 1);
      case '"': {
        std::size_t ignored_start = 0;
        std::size_t ignored_end = 0;
        return ParseString(&ignored_start, &ignored_end);
      }
      case 't':
        return ParseLiteral("true");
      case 'f':
        return ParseLiteral("false");
      case 'n':
        return ParseLiteral("null");
      default:
        return ParseNumber();
    }
  }

  bool ParseObject(std::size_t depth) {
    ++position_;
    SkipWhitespace();
    if (Consume('}')) {
      return true;
    }
    std::set<std::string> keys;
    while (true) {
      std::size_t start = 0;
      std::size_t end = 0;
      if (!ParseString(&start, &end)) {
        return false;
      }
      std::string decoded_key;
      if (!DecodeString(start, end, &decoded_key) ||
          !keys.insert(decoded_key).second) {
        return false;
      }
      SkipWhitespace();
      if (!Consume(':')) {
        return false;
      }
      SkipWhitespace();
      if (!ParseValue(depth)) {
        return false;
      }
      SkipWhitespace();
      if (Consume('}')) {
        return true;
      }
      if (!Consume(',')) {
        return false;
      }
      SkipWhitespace();
    }
  }

  bool ParseArray(std::size_t depth) {
    ++position_;
    SkipWhitespace();
    if (Consume(']')) {
      return true;
    }
    while (true) {
      if (!ParseValue(depth)) {
        return false;
      }
      SkipWhitespace();
      if (Consume(']')) {
        return true;
      }
      if (!Consume(',')) {
        return false;
      }
      SkipWhitespace();
    }
  }

  bool ParseString(std::size_t* start, std::size_t* end) {
    if (position_ >= size_ || bytes_[position_] != '"') {
      return false;
    }
    *start = position_++;
    while (position_ < size_) {
      const std::uint8_t byte = bytes_[position_++];
      if (byte == '"') {
        *end = position_;
        return true;
      }
      if (byte < 0x20) {
        return false;
      }
      if (byte != '\\') {
        continue;
      }
      if (position_ >= size_) {
        return false;
      }
      const std::uint8_t escape = bytes_[position_++];
      if (std::strchr("\"\\/bfnrt", escape) != nullptr) {
        continue;
      }
      if (escape != 'u' || position_ + 4 > size_) {
        return false;
      }
      for (int index = 0; index < 4; ++index) {
        const std::uint8_t digit = bytes_[position_++];
        if (!((digit >= '0' && digit <= '9') ||
              (digit >= 'a' && digit <= 'f') ||
              (digit >= 'A' && digit <= 'F'))) {
          return false;
        }
      }
    }
    return false;
  }

  bool DecodeString(std::size_t start,
                    std::size_t end,
                    std::string* decoded) {
    NSMutableData* wrapped = [NSMutableData data];
    const std::uint8_t prefix = '[';
    const std::uint8_t suffix = ']';
    [wrapped appendBytes:&prefix length:1];
    [wrapped appendBytes:bytes_ + start length:end - start];
    [wrapped appendBytes:&suffix length:1];
    NSError* error = nil;
    id value = [NSJSONSerialization JSONObjectWithData:wrapped
                                               options:0
                                                 error:&error];
    if (error != nil || ![value isKindOfClass:[NSArray class]] ||
        [value count] != 1 ||
        ![[value objectAtIndex:0] isKindOfClass:[NSString class]]) {
      return false;
    }
    *decoded = Utf8([value objectAtIndex:0]);
    return true;
  }

  bool ParseNumber() {
    const std::size_t start = position_;
    Consume('-');
    if (position_ >= size_) {
      return false;
    }
    if (Consume('0')) {
      if (position_ < size_ && bytes_[position_] >= '0' &&
          bytes_[position_] <= '9') {
        return false;
      }
    } else {
      if (bytes_[position_] < '1' || bytes_[position_] > '9') {
        return false;
      }
      while (position_ < size_ && bytes_[position_] >= '0' &&
             bytes_[position_] <= '9') {
        ++position_;
      }
    }
    if (Consume('.')) {
      if (!ConsumeDigits()) {
        return false;
      }
    }
    if (position_ < size_ &&
        (bytes_[position_] == 'e' || bytes_[position_] == 'E')) {
      ++position_;
      if (position_ < size_ &&
          (bytes_[position_] == '+' || bytes_[position_] == '-')) {
        ++position_;
      }
      if (!ConsumeDigits()) {
        return false;
      }
    }
    return position_ > start;
  }

  bool ConsumeDigits() {
    const std::size_t start = position_;
    while (position_ < size_ && bytes_[position_] >= '0' &&
           bytes_[position_] <= '9') {
      ++position_;
    }
    return position_ > start;
  }

  bool ParseLiteral(const char* literal) {
    const std::size_t length = std::strlen(literal);
    if (position_ + length > size_ ||
        std::memcmp(bytes_ + position_, literal, length) != 0) {
      return false;
    }
    position_ += length;
    return true;
  }

  bool Consume(std::uint8_t expected) {
    if (position_ >= size_ || bytes_[position_] != expected) {
      return false;
    }
    ++position_;
    return true;
  }

  void SkipWhitespace() {
    while (position_ < size_ &&
           (bytes_[position_] == ' ' || bytes_[position_] == '\t' ||
            bytes_[position_] == '\r' || bytes_[position_] == '\n')) {
      ++position_;
    }
  }

  const std::uint8_t* bytes_;
  std::size_t size_;
  std::size_t position_ = 0;
};

bool ConstantTimeTokenMatch(NSString* supplied,
                            const std::array<std::uint8_t, kTokenBytes>& token) {
  NSData* data = [supplied dataUsingEncoding:NSASCIIStringEncoding
                         allowLossyConversion:NO];
  const std::size_t length = data == nil ? 0 : data.length;
  const auto* bytes = static_cast<const std::uint8_t*>(data.bytes);
  std::size_t difference = length ^ (kTokenBytes * 2);

  // The published token is hexadecimal, so compare against its encoded form.
  static constexpr char kHex[] = "0123456789abcdef";
  for (std::size_t index = 0; index < kTokenBytes * 2; ++index) {
    const std::uint8_t expected =
        static_cast<std::uint8_t>(kHex[(index % 2 == 0)
                                           ? token[index / 2] >> 4
                                           : token[index / 2] & 0x0f]);
    const std::uint8_t actual =
        index < length ? bytes[index] : static_cast<std::uint8_t>(0);
    difference |= expected ^ actual;
  }
  return difference == 0;
}

std::string HexToken(const std::array<std::uint8_t, kTokenBytes>& token) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string encoded(kTokenBytes * 2, '0');
  for (std::size_t index = 0; index < token.size(); ++index) {
    encoded[index * 2] = kHex[token[index] >> 4];
    encoded[index * 2 + 1] = kHex[token[index] & 0x0f];
  }
  return encoded;
}

std::string CompactSocketName(const std::string& instance_tag,
                              const std::string& pid) {
  constexpr std::uint64_t kFnvOffset = 14695981039346656037ULL;
  constexpr std::uint64_t kFnvPrime = 1099511628211ULL;
  static constexpr char kHex[] = "0123456789abcdef";
  std::uint64_t hash = kFnvOffset;
  for (const unsigned char byte : instance_tag) {
    hash ^= byte;
    hash *= kFnvPrime;
  }
  std::string encoded(16, '0');
  for (std::size_t index = 0; index < encoded.size(); ++index) {
    encoded[encoded.size() - index - 1] = kHex[hash & 0x0f];
    hash >>= 4;
  }
  return "w" + encoded + "p" + pid;
}

bool ExactRequestKeys(NSDictionary* object) {
  static NSSet<NSString*>* expected = [NSSet
      setWithArray:@[
        @"version", @"type", @"auth_token", @"request_id", @"group",
        @"username", @"text"
      ]];
  return object.count == expected.count &&
         [[NSSet setWithArray:object.allKeys] isEqualToSet:expected];
}

bool ContainsNul(NSString* value) {
  for (NSUInteger index = 0; index < value.length; ++index) {
    if ([value characterAtIndex:index] == 0) {
      return true;
    }
  }
  return false;
}

bool ParseRequest(const std::uint8_t* bytes,
                  std::size_t size,
                  const std::array<std::uint8_t, kTokenBytes>& token,
                  SendRequest* request) {
  if (!JsonSyntaxScanner(bytes, size).Parse()) {
    return false;
  }
  NSData* data = [NSData dataWithBytes:bytes length:size];
  if ([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ==
      nil) {
    return false;
  }
  NSError* error = nil;
  id value = [NSJSONSerialization JSONObjectWithData:data
                                             options:0
                                               error:&error];
  if (error != nil || ![value isKindOfClass:[NSDictionary class]]) {
    return false;
  }
  NSDictionary* object = value;
  if (!ExactRequestKeys(object)) {
    return false;
  }
  NSNumber* version = object[@"version"];
  NSString* type = object[@"type"];
  NSString* auth_token = object[@"auth_token"];
  NSString* request_id = object[@"request_id"];
  NSString* group = object[@"group"];
  NSString* username = object[@"username"];
  NSString* text = object[@"text"];
  if (!IsIntegerNumber(version) || version.longLongValue != kProtocolVersion ||
      ![type isKindOfClass:[NSString class]] ||
      ![type isEqualToString:@"send_text"] ||
      ![auth_token isKindOfClass:[NSString class]] ||
      ![request_id isKindOfClass:[NSString class]] ||
      ![group isKindOfClass:[NSString class]] ||
      ![username isKindOfClass:[NSString class]] ||
      ![text isKindOfClass:[NSString class]] ||
      !ConstantTimeTokenMatch(auth_token, token)) {
    return false;
  }
  const std::size_t request_id_size =
      [request_id lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
  const std::size_t group_size =
      [group lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
  const std::size_t username_size =
      [username lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
  const std::size_t text_size =
      [text lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
  NSString* trimmed_text = [text
      stringByTrimmingCharactersInSet:
          [NSCharacterSet whitespaceAndNewlineCharacterSet]];
  if (request_id_size == 0 || request_id_size > 256 ||
      group_size == 0 || group_size > kMaximumGroupBytes ||
      username_size == 0 || username_size > kMaximumUsernameBytes ||
      text_size == 0 || text_size > kMaximumFrameBytes ||
      trimmed_text.length == 0 ||
      ![username hasSuffix:@"@chatroom"] ||
      ContainsNul(request_id) || ContainsNul(group) ||
      ContainsNul(username) || ContainsNul(text)) {
    return false;
  }
  request->request_id = Utf8(request_id);
  request->group = Utf8(group);
  request->username = Utf8(username);
  request->text = Utf8(text);
  return true;
}

NSData* EncodeReceipt(const SendRequest& request, SendReceipt receipt) {
  if (receipt.local_id.has_value() && receipt.local_id.value() <= 0) {
    receipt.local_id.reset();
    receipt.server_id.reset();
    receipt.ack_state = AckState::kUnknown;
  }
  if (receipt.server_id.has_value() && receipt.server_id.value() <= 0) {
    receipt.server_id.reset();
  }
  if (receipt.ack_state == AckState::kAcknowledged &&
      !receipt.local_id.has_value()) {
    receipt.ack_state = AckState::kUnknown;
  }
  if (receipt.ack_state == AckState::kSubmitted &&
      (receipt.local_id.has_value() || receipt.server_id.has_value())) {
    receipt.local_id.reset();
    receipt.server_id.reset();
    receipt.ack_state = AckState::kUnknown;
  }
  NSString* request_id =
      [[NSString alloc] initWithBytes:request.request_id.data()
                              length:request.request_id.size()
                            encoding:NSUTF8StringEncoding];
  NSString* group = [[NSString alloc] initWithBytes:request.group.data()
                                             length:request.group.size()
                                           encoding:NSUTF8StringEncoding];
  NSString* username =
      [[NSString alloc] initWithBytes:request.username.data()
                              length:request.username.size()
                            encoding:NSUTF8StringEncoding];
  if (request_id == nil || group == nil || username == nil) {
    return nil;
  }
  NSDictionary* object = @{
    @"version" : @(kProtocolVersion),
    @"type" : @"send_receipt",
    @"ack_state" : receipt.ack_state == AckState::kAcknowledged
        ? @"acknowledged"
        : receipt.ack_state == AckState::kSubmitted
            ? @"submitted"
            : @"unknown",
    @"request_id" : request_id,
    @"group" : group,
    @"username" : username,
    @"local_id" : receipt.local_id.has_value()
        ? @(receipt.local_id.value())
        : [NSNull null],
    @"server_id" : receipt.server_id.has_value()
        ? @(receipt.server_id.value())
        : [NSNull null],
  };
  NSError* error = nil;
  NSData* data = [NSJSONSerialization dataWithJSONObject:object
                                                 options:0
                                                   error:&error];
  return error == nil ? data : nil;
}

bool SameFile(const std::string& path,
              dev_t device,
              ino_t inode,
              mode_t type) {
  struct stat metadata {};
  return lstat(path.c_str(), &metadata) == 0 &&
         metadata.st_dev == device && metadata.st_ino == inode &&
         (metadata.st_mode & S_IFMT) == type;
}

bool SameFileAt(int directory_fd,
                const std::string& name,
                dev_t device,
                ino_t inode,
                mode_t type) {
  struct stat metadata {};
  return directory_fd >= 0 &&
         fstatat(directory_fd, name.c_str(), &metadata,
                 AT_SYMLINK_NOFOLLOW) == 0 &&
         metadata.st_dev == device && metadata.st_ino == inode &&
         (metadata.st_mode & S_IFMT) == type;
}

}  // namespace

class BridgeService::Impl {
 public:
  ~Impl() { Stop(); }

  bool Start(const BridgeConfig& config,
             std::shared_ptr<SendAdapter> adapter,
             std::string* error) {
    std::lock_guard<std::mutex> lock(lifecycle_mutex_);
    if (running_ || adapter == nullptr || config.safe_directory.empty() ||
        config.safe_directory.front() != '/' ||
        config.adapter_timeout_ms == 0) {
      SetError(error, "invalid_or_already_running_bridge_configuration");
      return false;
    }

    struct stat supplied_directory {};
    char resolved[PATH_MAX];
    char symlink_target[PATH_MAX];
    const ssize_t symlink_size = readlink(
        config.safe_directory.c_str(), symlink_target,
        sizeof(symlink_target));
    if (symlink_size >= 0 ||
        lstat(config.safe_directory.c_str(), &supplied_directory) != 0 ||
        !S_ISDIR(supplied_directory.st_mode) ||
        realpath(config.safe_directory.c_str(), resolved) == nullptr) {
      SetError(error, "unsafe_bridge_directory");
      return false;
    }
    if (config.safe_directory != std::string(resolved)) {
      SetError(error, "unsafe_bridge_directory");
      return false;
    }
    directory_ = resolved;
    directory_fd_ =
        open(directory_.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                     O_CLOEXEC);
    struct stat directory_metadata {};
    if (directory_fd_ < 0 ||
        fstat(directory_fd_, &directory_metadata) != 0 ||
        !S_ISDIR(directory_metadata.st_mode) ||
        directory_metadata.st_uid != geteuid() ||
        (directory_metadata.st_mode & 0077) != 0) {
      SetError(error, "unsafe_bridge_directory");
      CloseDirectory();
      return false;
    }
    directory_identity_.device = directory_metadata.st_dev;
    directory_identity_.inode = directory_metadata.st_ino;
    directory_identity_.type = S_IFDIR;
    if (!SameDirectoryPath()) {
      SetError(error, "unsafe_bridge_directory");
      ResetPathsAndDirectory();
      return false;
    }

    if (!ValidInstanceTag(config.instance_tag)) {
      SetError(error, "invalid_bridge_instance_tag");
      ResetPathsAndDirectory();
      return false;
    }
    const std::string pid = std::to_string(getpid());
    const std::string tag = config.instance_tag.empty()
        ? std::string()
        : "-" + config.instance_tag;
    socket_name_ = "wechat-bridge" + tag + "-" + pid + ".sock";
    metadata_name_ = "bridge" + tag + "-" + pid + ".json";
    socket_path_ = directory_ + "/" + socket_name_;
    if (socket_path_.size() >= sizeof(sockaddr_un::sun_path)) {
      socket_name_ = CompactSocketName(config.instance_tag, pid);
      socket_path_ = directory_ + "/" + socket_name_;
    }
    metadata_path_ = directory_ + "/" + metadata_name_;
    if (socket_path_.size() >= sizeof(sockaddr_un::sun_path) ||
        RelativePathExists(socket_name_) ||
        RelativePathExists(metadata_name_)) {
      SetError(error, "bridge_paths_unavailable");
      ResetPathsAndDirectory();
      return false;
    }

    if (SecRandomCopyBytes(kSecRandomDefault, token_.size(), token_.data()) !=
        errSecSuccess) {
      SetError(error, "secure_token_generation_failed");
      ResetPathsAndDirectory();
      return false;
    }

    listen_fd_.store(socket(AF_UNIX, SOCK_STREAM, 0));
    if (listen_fd_.load() < 0) {
      SetError(error, "bridge_socket_creation_failed");
      ResetPathsAndDirectory();
      return false;
    }
    fcntl(listen_fd_.load(), F_SETFD, FD_CLOEXEC);
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, socket_path_.c_str(),
                socket_path_.size() + 1);
    if (bind(listen_fd_.load(), reinterpret_cast<sockaddr*>(&address),
             sizeof(address)) != 0) {
      SetError(error, "bridge_socket_bind_failed");
      CloseListenSocket();
      ResetPathsAndDirectory();
      return false;
    }
    if (!SameDirectoryPath() ||
        !CaptureOwnedRelativePath(socket_name_, S_IFSOCK,
                                  &socket_identity_)) {
      SetError(error, "bridge_socket_bind_failed");
      CloseListenSocket();
      ResetPathsAndDirectory();
      return false;
    }
    owns_socket_ = true;
    if (chmod(socket_path_.c_str(), 0600) != 0 ||
        listen(listen_fd_.load(), 8) != 0 ||
        !SameDirectoryPath() ||
        !SameFileAt(directory_fd_, socket_name_, socket_identity_.device,
                    socket_identity_.inode, socket_identity_.type)) {
      SetError(error, "bridge_socket_bind_failed");
      CloseListenSocket();
      CleanupOwnedPaths();
      ResetPathsAndDirectory();
      return false;
    }

    const std::string token = HexToken(token_);
    NSString* socket_path_value =
        [[NSString alloc] initWithUTF8String:socket_path_.c_str()];
    NSString* token_value = [NSString stringWithUTF8String:token.c_str()];
    if (socket_path_value == nil || token_value == nil) {
      SetError(error, "bridge_metadata_publish_failed");
      CleanupOwnedPaths();
      CloseListenSocket();
      ResetPathsAndDirectory();
      return false;
    }
    NSDictionary* metadata = @{
      @"version" : @(kProtocolVersion),
      @"pid" : @(getpid()),
      @"socket_path" : socket_path_value,
      @"token" : token_value,
    };
    NSError* json_error = nil;
    NSData* metadata_data =
        [NSJSONSerialization dataWithJSONObject:metadata
                                         options:0
                                           error:&json_error];
    if (json_error != nil || metadata_data == nil ||
        metadata_data.length == 0 || !SameDirectoryPath()) {
      SetError(error, "bridge_metadata_publish_failed");
      CleanupOwnedPaths();
      CloseListenSocket();
      ResetPathsAndDirectory();
      return false;
    }
    const std::string metadata_temp_name =
        "." + metadata_name_ + "." + token.substr(0, 16) + ".tmp";
    if (RelativePathExists(metadata_temp_name)) {
      SetError(error, "bridge_metadata_publish_failed");
      CleanupOwnedPaths();
      CloseListenSocket();
      ResetPathsAndDirectory();
      return false;
    }
    const int metadata_fd =
        openat(directory_fd_, metadata_temp_name.c_str(),
               O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (metadata_fd < 0) {
      SetError(error, "bridge_metadata_publish_failed");
      CleanupOwnedPaths();
      CloseListenSocket();
      ResetPathsAndDirectory();
      return false;
    }
    struct stat metadata_file {};
    if (fstat(metadata_fd, &metadata_file) != 0 ||
        !S_ISREG(metadata_file.st_mode) ||
        metadata_file.st_uid != geteuid()) {
      close(metadata_fd);
      SetError(error, "bridge_metadata_publish_failed");
      CleanupOwnedPaths();
      CloseListenSocket();
      ResetPathsAndDirectory();
      return false;
    }
    PathIdentity metadata_temp_identity;
    metadata_temp_identity.device = metadata_file.st_dev;
    metadata_temp_identity.inode = metadata_file.st_ino;
    metadata_temp_identity.type = S_IFREG;
    if (fchmod(metadata_fd, 0600) != 0 ||
        !WriteAll(metadata_fd,
                  static_cast<const std::uint8_t*>(metadata_data.bytes),
                  metadata_data.length) ||
        fsync(metadata_fd) != 0) {
      close(metadata_fd);
      if (SameFileAt(directory_fd_, metadata_temp_name,
                     metadata_temp_identity.device,
                     metadata_temp_identity.inode,
                     metadata_temp_identity.type)) {
        unlinkat(directory_fd_, metadata_temp_name.c_str(), 0);
      }
      SetError(error, "bridge_metadata_publish_failed");
      CleanupOwnedPaths();
      CloseListenSocket();
      ResetPathsAndDirectory();
      return false;
    }
    close(metadata_fd);
    if (!SameDirectoryPath() ||
        !SameFileAt(directory_fd_, metadata_temp_name,
                    metadata_temp_identity.device,
                    metadata_temp_identity.inode,
                    metadata_temp_identity.type) ||
        renameatx_np(directory_fd_, metadata_temp_name.c_str(),
                     directory_fd_, metadata_name_.c_str(),
                     RENAME_EXCL) != 0) {
      if (SameFileAt(directory_fd_, metadata_temp_name,
                     metadata_temp_identity.device,
                     metadata_temp_identity.inode,
                     metadata_temp_identity.type)) {
        unlinkat(directory_fd_, metadata_temp_name.c_str(), 0);
      }
      SetError(error, "bridge_metadata_publish_failed");
      CleanupOwnedPaths();
      CloseListenSocket();
      ResetPathsAndDirectory();
      return false;
    }
    metadata_identity_ = metadata_temp_identity;
    owns_metadata_ = true;
    if (!SameDirectoryPath() ||
        !SameFileAt(directory_fd_, metadata_name_, metadata_identity_.device,
                    metadata_identity_.inode, metadata_identity_.type)) {
      SetError(error, "bridge_metadata_publish_failed");
      CleanupOwnedPaths();
      CloseListenSocket();
      ResetPathsAndDirectory();
      return false;
    }
    adapter_ = std::move(adapter);
    adapter_timeout_ms_ = config.adapter_timeout_ms;
    stopping_.store(false);
    running_ = true;
    try {
      server_thread_ = std::thread([this] { ServerLoop(); });
    } catch (...) {
      running_ = false;
      adapter_.reset();
      CloseListenSocket();
      CleanupOwnedPaths();
      ResetPathsAndDirectory();
      SetError(error, "bridge_server_thread_creation_failed");
      return false;
    }
    return true;
  }

  void Stop() {
    std::unique_lock<std::mutex> lock(lifecycle_mutex_);
    if (!running_ && !owns_socket_ && !owns_metadata_) {
      return;
    }
    stopping_.store(true);
    const int descriptor = listen_fd_.exchange(-1);
    if (descriptor >= 0) {
      shutdown(descriptor, SHUT_RDWR);
      close(descriptor);
    }
    {
      std::lock_guard<std::mutex> client_lock(client_mutex_);
      if (active_client_fd_ >= 0) {
        shutdown(active_client_fd_, SHUT_RDWR);
      }
      if (const auto pending = active_pending_.lock()) {
        std::lock_guard<std::mutex> pending_lock(pending->mutex);
        pending->cancelled = true;
        pending->condition.notify_one();
      }
    }
    lock.unlock();
    if (server_thread_.joinable()) {
      server_thread_.join();
    }
    lock.lock();
    CleanupOwnedPaths();
    adapter_.reset();
    running_ = false;
    ResetPathsAndDirectory();
  }

  std::string metadata_path() const {
    std::lock_guard<std::mutex> lock(lifecycle_mutex_);
    return metadata_path_;
  }

  std::string socket_path() const {
    std::lock_guard<std::mutex> lock(lifecycle_mutex_);
    return socket_path_;
  }

 private:
  struct PathIdentity {
    dev_t device = 0;
    ino_t inode = 0;
    mode_t type = 0;
  };

  struct PendingReceipt {
    std::mutex mutex;
    std::condition_variable condition;
    bool completed = false;
    bool cancelled = false;
    SendReceipt receipt;
  };

  static void SetError(std::string* error, const char* value) {
    if (error != nullptr) {
      *error = value;
    }
  }

  bool SameDirectoryPath() const {
    return SameFile(directory_, directory_identity_.device,
                    directory_identity_.inode, directory_identity_.type);
  }

  bool RelativePathExists(const std::string& name) const {
    struct stat metadata {};
    if (fstatat(directory_fd_, name.c_str(), &metadata,
                AT_SYMLINK_NOFOLLOW) == 0) {
      return true;
    }
    return errno != ENOENT;
  }

  bool CaptureOwnedRelativePath(const std::string& name,
                                mode_t type,
                                PathIdentity* identity) const {
    struct stat metadata {};
    if (fstatat(directory_fd_, name.c_str(), &metadata,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        (metadata.st_mode & S_IFMT) != type ||
        metadata.st_uid != geteuid()) {
      return false;
    }
    identity->device = metadata.st_dev;
    identity->inode = metadata.st_ino;
    identity->type = type;
    return true;
  }

  void ServerLoop() {
    while (!stopping_.load()) {
      const int descriptor = listen_fd_.load();
      if (descriptor < 0) {
        break;
      }
      const int client = accept(descriptor, nullptr, nullptr);
      if (client < 0) {
        if (errno == EINTR) {
          continue;
        }
        if (stopping_.load() || errno == EBADF || errno == EINVAL) {
          break;
        }
        continue;
      }
      fcntl(client, F_SETFD, FD_CLOEXEC);
      int no_sigpipe = 1;
      setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe,
                 sizeof(no_sigpipe));
      timeval timeout {};
      timeout.tv_sec = kClientIoTimeoutSeconds;
      setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
      setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
      {
        std::lock_guard<std::mutex> client_lock(client_mutex_);
        active_client_fd_ = client;
      }
      uid_t peer_euid = static_cast<uid_t>(-1);
      gid_t peer_egid = static_cast<gid_t>(-1);
      if (!stopping_.load() &&
          getpeereid(client, &peer_euid, &peer_egid) == 0 &&
          peer_euid == geteuid()) {
        HandleClient(client);
      }
      {
        std::lock_guard<std::mutex> client_lock(client_mutex_);
        active_client_fd_ = -1;
      }
      close(client);
    }
  }

  void HandleClient(int client) {
    std::uint32_t network_size = 0;
    if (!ReadAll(client, reinterpret_cast<std::uint8_t*>(&network_size),
                 sizeof(network_size))) {
      return;
    }
    const std::uint32_t size = ntohl(network_size);
    if (size == 0 || size > kMaximumFrameBytes) {
      return;
    }
    std::unique_ptr<std::uint8_t[]> bytes(new std::uint8_t[size]);
    if (!ReadAll(client, bytes.get(), size)) {
      return;
    }
    SendRequest request;
    if (!ParseRequest(bytes.get(), size, token_, &request)) {
      return;
    }

    auto pending = std::make_shared<PendingReceipt>();
    const auto adapter = adapter_;
    {
      std::lock_guard<std::mutex> client_lock(client_mutex_);
      if (stopping_.load() || adapter == nullptr) {
        return;
      }
      active_pending_ = pending;
      try {
        adapter->Send(
            request,
            [pending, adapter](SendReceipt receipt) {
              (void)adapter;
              std::lock_guard<std::mutex> lock(pending->mutex);
              if (pending->completed || pending->cancelled) {
                return;
              }
              pending->receipt = std::move(receipt);
              pending->completed = true;
              pending->condition.notify_one();
            });
      } catch (...) {
        active_pending_.reset();
        return;
      }
    }

    SendReceipt receipt;
    bool adapter_timed_out = false;
    bool adapter_cancelled = false;
    {
      std::unique_lock<std::mutex> lock(pending->mutex);
      if (!pending->condition.wait_for(
              lock, std::chrono::milliseconds(adapter_timeout_ms_),
              [this, &pending] {
                return pending->completed || pending->cancelled ||
                       stopping_.load();
              })) {
        receipt.ack_state = AckState::kUnknown;
        pending->cancelled = true;
        adapter_timed_out = true;
      } else if (pending->cancelled || stopping_.load()) {
        pending->cancelled = true;
        adapter_cancelled = true;
      } else {
        receipt = pending->receipt;
      }
    }
    {
      std::lock_guard<std::mutex> client_lock(client_mutex_);
      if (active_pending_.lock() == pending) {
        active_pending_.reset();
      }
    }
    if (adapter_cancelled) {
      return;
    }
    NSData* payload = EncodeReceipt(request, receipt);
    if (payload == nil || payload.length == 0 ||
        payload.length > kMaximumFrameBytes) {
      if (adapter_timed_out) {
        DisableListening();
      }
      return;
    }
    const std::uint32_t response_size =
        htonl(static_cast<std::uint32_t>(payload.length));
    if (!WriteAll(client,
                  reinterpret_cast<const std::uint8_t*>(&response_size),
                  sizeof(response_size))) {
      if (adapter_timed_out) {
        DisableListening();
      }
      return;
    }
    WriteAll(client, static_cast<const std::uint8_t*>(payload.bytes),
             payload.length);
    if (adapter_timed_out) {
      DisableListening();
    }
  }

  void DisableListening() {
    stopping_.store(true);
    CloseListenSocket();
    std::lock_guard<std::mutex> lock(lifecycle_mutex_);
    CleanupOwnedPaths();
  }

  void CloseListenSocket() {
    const int descriptor = listen_fd_.exchange(-1);
    if (descriptor >= 0) {
      close(descriptor);
    }
  }

  void CloseDirectory() {
    if (directory_fd_ >= 0) {
      close(directory_fd_);
      directory_fd_ = -1;
    }
  }

  void CleanupOwnedPaths() {
    if (owns_metadata_ &&
        SameFileAt(directory_fd_, metadata_name_, metadata_identity_.device,
                   metadata_identity_.inode, metadata_identity_.type)) {
      unlinkat(directory_fd_, metadata_name_.c_str(), 0);
    }
    owns_metadata_ = false;
    if (owns_socket_ &&
        SameFileAt(directory_fd_, socket_name_, socket_identity_.device,
                   socket_identity_.inode, socket_identity_.type)) {
      unlinkat(directory_fd_, socket_name_.c_str(), 0);
    }
    owns_socket_ = false;
  }

  void ResetPathsAndDirectory() {
    CloseDirectory();
    directory_.clear();
    socket_name_.clear();
    metadata_name_.clear();
    socket_path_.clear();
    metadata_path_.clear();
  }

  mutable std::mutex lifecycle_mutex_;
  std::mutex client_mutex_;
  std::atomic<bool> stopping_{false};
  bool running_ = false;
  bool owns_socket_ = false;
  bool owns_metadata_ = false;
  std::atomic<int> listen_fd_{-1};
  int active_client_fd_ = -1;
  std::weak_ptr<PendingReceipt> active_pending_;
  int directory_fd_ = -1;
  std::uint32_t adapter_timeout_ms_ = 15000;
  std::array<std::uint8_t, kTokenBytes> token_{};
  std::string directory_;
  std::string socket_name_;
  std::string metadata_name_;
  std::string socket_path_;
  std::string metadata_path_;
  PathIdentity socket_identity_;
  PathIdentity metadata_identity_;
  PathIdentity directory_identity_;
  std::shared_ptr<SendAdapter> adapter_;
  std::thread server_thread_;
};

BridgeService::BridgeService() : impl_(std::make_unique<Impl>()) {}

BridgeService::~BridgeService() = default;

bool BridgeService::Start(const BridgeConfig& config,
                          std::shared_ptr<SendAdapter> adapter,
                          std::string* error) {
  return impl_->Start(config, std::move(adapter), error);
}

void BridgeService::Stop() {
  impl_->Stop();
}

std::string BridgeService::metadata_path() const {
  return impl_->metadata_path();
}

std::string BridgeService::socket_path() const {
  return impl_->socket_path();
}

}  // namespace wechat_bridge
