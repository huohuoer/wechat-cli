#include "wechat_bridge.hpp"

#include <atomic>
#include <ctime>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

namespace wechat_bridge {
namespace {

enum class TransactionStage {
  kWaitingForInsert,
  kWaitingForNetwork,
  kWaitingForUpdate,
  kFinished,
};

struct TransactionState {
  std::mutex mutex;
  TransactionStage stage = TransactionStage::kWaitingForInsert;
  SendCompletion completion;
};

std::atomic<std::uint32_t> g_client_sequence{1};

bool EndsWithChatroom(const std::string& username) {
  static constexpr char kSuffix[] = "@chatroom";
  constexpr std::size_t kSuffixSize = sizeof(kSuffix) - 1;
  return username.size() >= kSuffixSize &&
      username.compare(username.size() - kSuffixSize,
                       kSuffixSize, kSuffix) == 0;
}

std::uint64_t NextClientId(std::uint32_t create_time) {
  const auto sequence = g_client_sequence.fetch_add(1);
  return (static_cast<std::uint64_t>(create_time) << 32) |
      (sequence == 0 ? 1 : sequence);
}

bool Advance(const std::shared_ptr<TransactionState>& state,
             TransactionStage expected,
             TransactionStage next) {
  std::lock_guard<std::mutex> lock(state->mutex);
  if (state->stage != expected) {
    return false;
  }
  state->stage = next;
  return true;
}

void Finish(const std::shared_ptr<TransactionState>& state,
            SendReceipt receipt) {
  SendCompletion completion;
  {
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->stage == TransactionStage::kFinished) {
      return;
    }
    state->stage = TransactionStage::kFinished;
    completion = std::move(state->completion);
  }
  if (completion) {
    completion(std::move(receipt));
  }
}

SendReceipt UnknownReceipt(
    const std::optional<LocalMessageIdentity>& identity = std::nullopt,
    std::optional<std::int64_t> server_id = std::nullopt) {
  SendReceipt receipt;
  receipt.ack_state = AckState::kUnknown;
  if (identity.has_value() && identity->local_id > 0) {
    receipt.local_id = identity->local_id;
  }
  if (server_id.has_value() && server_id.value() > 0) {
    receipt.server_id = server_id;
  }
  return receipt;
}

class LocalVisibleAdapter final : public SendAdapter {
 public:
  LocalVisibleAdapter(std::shared_ptr<LocalMessageGateway> local,
                      std::shared_ptr<MarsGateway> mars)
      : local_(std::move(local)), mars_(std::move(mars)) {}

  void Send(const SendRequest& request, SendCompletion completion) override {
    if (local_ == nullptr || mars_ == nullptr || request.request_id.empty() ||
        request.text.empty() || !EndsWithChatroom(request.username)) {
      if (completion) {
        completion(UnknownReceipt());
      }
      return;
    }

    const auto now = std::time(nullptr);
    if (now <= 0 ||
        static_cast<std::uint64_t>(now) > UINT32_MAX) {
      if (completion) {
        completion(UnknownReceipt());
      }
      return;
    }
    const auto create_time = static_cast<std::uint32_t>(now);
    const auto client_id = NextClientId(create_time);
    auto state = std::make_shared<TransactionState>();
    state->completion = std::move(completion);
    auto local = local_;
    auto mars = mars_;

    local->InsertOutgoing(
        request, client_id, create_time,
        [state, local, mars, request, client_id, create_time](
            std::optional<LocalMessageIdentity> identity) mutable {
          if (!identity.has_value() || identity->local_id <= 0 ||
              identity->client_id != client_id ||
              identity->create_time != create_time) {
            Finish(state, UnknownReceipt(identity));
            return;
          }
          if (!Advance(state, TransactionStage::kWaitingForInsert,
                       TransactionStage::kWaitingForNetwork)) {
            return;
          }
          mars->Submit(
              request, identity.value(),
              [state, local, identity](NetworkAcceptance acceptance) mutable {
                if (!acceptance.accepted || acceptance.server_id <= 0) {
                  Finish(state, UnknownReceipt(identity));
                  return;
                }
                if (!Advance(state, TransactionStage::kWaitingForNetwork,
                             TransactionStage::kWaitingForUpdate)) {
                  return;
                }
                local->MarkAccepted(
                    identity.value(), acceptance.server_id,
                    [state, identity, acceptance](bool updated) mutable {
                      if (!updated) {
                        Finish(state, UnknownReceipt(
                            identity, acceptance.server_id));
                        return;
                      }
                      if (!Advance(state,
                                   TransactionStage::kWaitingForUpdate,
                                   TransactionStage::kFinished)) {
                        return;
                      }
                      SendReceipt receipt;
                      receipt.ack_state = AckState::kAcknowledged;
                      receipt.local_id = identity->local_id;
                      receipt.server_id = acceptance.server_id;
                      SendCompletion completion;
                      {
                        std::lock_guard<std::mutex> lock(state->mutex);
                        completion = std::move(state->completion);
                      }
                      if (completion) {
                        completion(std::move(receipt));
                      }
                    });
              });
        });
  }

 private:
  std::shared_ptr<LocalMessageGateway> local_;
  std::shared_ptr<MarsGateway> mars_;
};

}  // namespace

std::shared_ptr<SendAdapter> CreateLocalVisibleAdapter(
    std::shared_ptr<LocalMessageGateway> local,
    std::shared_ptr<MarsGateway> mars) {
  if (local == nullptr || mars == nullptr) {
    return nullptr;
  }
  return std::make_shared<LocalVisibleAdapter>(
      std::move(local), std::move(mars));
}

}  // namespace wechat_bridge
