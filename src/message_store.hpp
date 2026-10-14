#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace renegade {

inline constexpr std::size_t kMessageLineCharacterLimit = 78;
inline constexpr std::size_t kMessageLineCountLimit = 500;
inline constexpr std::size_t kMessageBodyByteLimit =
    kMessageLineCharacterLimit * 4 * kMessageLineCountLimit + 2 * kMessageLineCountLimit;

[[nodiscard]] std::size_t utf8_codepoint_count(std::string_view text) noexcept;
[[nodiscard]] bool valid_message_body(std::string_view body) noexcept;

enum class AnonymousMode : int {
    Disabled = 0,
    Optional = 1,
    Forced = 2,
    DearAbby = 3,
    AnyName = 4,
};

enum class MessageSearchField : int {
    From = 1,
    To = 2,
    Subject = 3,
    AllText = 4,
    ToMe = 5,
    Yours = 6,
};

struct BoardMessage {
    long long id{};
    std::string author;
    std::string subject;
    std::string body;
    std::string created_at;
    std::optional<long long> reply_to;
    bool allow_mci{};
    bool deleted{};
    bool unvalidated{};
    bool permanent{};
    bool unread{};
    std::string recipient;
    std::string owner_handle;
    std::string posted_as;
    int anonymous_type{};
};

struct LocatedBoardMessage {
    BoardMessage message;
    std::string area_name;
};

struct BoardArea {
    long long id{};
    std::string name;
    std::size_t unread_total{};
    std::string access_acs;
    std::string post_acs;
    std::string mci_acs;
    std::string sysop_acs;
    AnonymousMode anonymous_mode{AnonymousMode::Disabled};
    bool new_scan_enabled{true};
    bool force_read{};
    bool use_real_names{};
    bool password_protected{};
    bool add_tagline{};
    bool filter_public_text{};
    bool accessible{true};
    bool unhidden{};
    bool add_tearline{};
    std::string origin_line;
    std::string origin_address;
    std::string quote_start;
    std::string quote_end;
};

struct MessageQuoteTemplates {
    std::string start;
    std::string end;
};

struct RemovedBoardArea {
    long long id{};
    std::string name;
    std::size_t message_count{};
};

struct BoardMessagePage {
    std::vector<BoardMessage> messages;
    std::size_t page{};
    std::size_t page_count{1};
    std::size_t total{};
    std::size_t unread_total{};
};

struct UnreadBoardMessage {
    BoardMessage message;
    std::string area_name;
};

struct UnreadBoardPage {
    std::vector<UnreadBoardMessage> messages;
    std::size_t page{};
    std::size_t page_count{1};
    std::size_t total{};
};

struct PrivateMessage {
    long long id{};
    std::string sender;
    std::string recipient;
    std::string subject;
    std::string body;
    std::string created_at;
    std::optional<long long> reply_to;
    bool unread{};
    bool deleted{};
    std::string sender_handle;
    int anonymous_type{};
    std::string posted_as;
    bool anonymous_details_visible{true};
};

struct AnonymousAcsSettings {
    std::string public_post;
    std::string public_read;
    std::string private_post;
    std::string private_read;
};

struct MessagePostLimits {
    int public_per_call{255};
    int private_per_call{255};
};

struct PrivateMailWaitingLimits {
    int normal_users{255};
    int sysops{255};
};

struct MessageCreditCosts {
    int public_post{};
    int private_mail{};
};

enum class PrivateMailbox {
    Inbox,
    Outbox,
};

struct PrivateMessagePage {
    std::vector<PrivateMessage> messages;
    std::size_t page{};
    std::size_t page_count{1};
    std::size_t total{};
    std::size_t unread_total{};
};

struct MessageUserUsage {
    std::uint64_t public_posts{};
    std::uint64_t private_sent{};
};

class MessageStore {
public:
    explicit MessageStore(std::string database_path);

    void initialize() const;
    [[nodiscard]] std::string initial_area(std::string_view viewer) const;
    void set_last_area(std::string_view viewer, std::string_view area) const;
    [[nodiscard]] std::vector<BoardArea> areas(
        std::string_view viewer,
        bool include_restricted = false,
        bool include_unhidden = false) const;
    void set_message_scan_date(std::string_view viewer, std::string_view mmddyyyy) const;
    void set_area_access(
        long long area_id,
        std::string_view access_acs,
        std::string_view post_acs,
        std::string_view mci_acs,
        std::string_view sysop_acs) const;
    void set_area_force_read(long long area_id, bool enabled) const;
    void set_area_password(long long area_id, std::string_view password) const;
    [[nodiscard]] bool verify_area_password(
        std::string_view viewer, long long area_id, std::string_view password) const;
    void set_area_real_name_search(long long area_id, bool enabled) const;
    void set_area_taglines_enabled(long long area_id, bool enabled) const;
    void set_area_public_text_filter(long long area_id, bool enabled) const;
    void set_area_unhidden(long long area_id, bool enabled) const;
    void set_area_tearline_enabled(long long area_id, bool enabled) const;
    void set_area_origin(
        long long area_id, std::string_view origin_line, std::string_view origin_address) const;
    void set_area_quote_templates(
        long long area_id,
        std::string_view quote_start,
        std::string_view quote_end) const;
    [[nodiscard]] MessageQuoteTemplates area_quote_templates(
        std::string_view viewer, std::string_view area) const;
    [[nodiscard]] std::string area_real_name_label(
        std::string_view viewer, std::string_view area, std::string_view handle) const;
    void set_private_quote_templates(
        std::string_view quote_start, std::string_view quote_end) const;
    [[nodiscard]] MessageQuoteTemplates private_quote_templates() const;
    [[nodiscard]] bool toggle_area_new_scan(std::string_view viewer, std::string_view area) const;
    void set_all_area_new_scans(std::string_view viewer, bool enabled) const;
    void set_area_anonymous_mode(long long area_id, AnonymousMode mode) const;
    [[nodiscard]] AnonymousMode area_anonymous_mode(
        std::string_view viewer, std::string_view area) const;
    void set_anonymous_acs(
        std::string_view public_post, std::string_view public_read,
        std::string_view private_post, std::string_view private_read) const;
    void set_normal_post_acs(std::string_view public_post, std::string_view private_post) const;
    [[nodiscard]] std::pair<std::string, std::string> normal_post_acs() const;
    void set_submission_acs(std::string_view quote, std::string_view one_liner) const;
    [[nodiscard]] std::pair<std::string, std::string> submission_acs() const;
    [[nodiscard]] bool can_submit_quote(std::string_view caller) const;
    [[nodiscard]] bool can_submit_one_liner(std::string_view caller) const;
    [[nodiscard]] bool passes_access_rule(
        std::string_view caller, std::string_view expression, int node_number = 0,
        int remaining_minutes = 32767, int online_minutes = 0, bool invisible = false) const;
    void set_invisibility_acs(std::string_view expression) const;
    [[nodiscard]] std::string invisibility_acs() const;
    [[nodiscard]] bool can_toggle_invisibility(std::string_view caller) const;
    void set_validation_eligibility(bool key_active, int new_security_level) const;
    [[nodiscard]] std::pair<bool, int> validation_eligibility() const;
    void set_post_limits(int public_per_call, int private_per_call) const;
    [[nodiscard]] MessagePostLimits post_limits() const;
    void set_post_ratio_range(int minimum_security_level, int maximum_security_level, int percent) const;
    void set_private_mail_waiting_limits(int normal_users, int sysops) const;
    [[nodiscard]] PrivateMailWaitingLimits private_mail_waiting_limits() const;
    void set_credit_costs(int public_post, int private_mail) const;
    [[nodiscard]] MessageCreditCosts credit_costs() const;
    [[nodiscard]] AnonymousAcsSettings anonymous_acs() const;
    [[nodiscard]] bool can_post_public(
        std::string_view viewer, std::string_view area, int posts_this_call = 0) const;
    [[nodiscard]] bool can_send_private(std::string_view sender, int sent_this_call = 0) const;
    [[nodiscard]] bool can_post_public_anonymously(std::string_view viewer) const;
    [[nodiscard]] bool can_read_public_anonymously(std::string_view viewer) const;
    [[nodiscard]] bool can_post_private_anonymously(std::string_view sender) const;
    [[nodiscard]] bool can_read_private_anonymously(std::string_view viewer) const;
    [[nodiscard]] bool can_use_area_mci(std::string_view viewer, std::string_view area) const;
    [[nodiscard]] bool can_moderate_area(std::string_view viewer, std::string_view area) const;
    [[nodiscard]] bool toggle_message_deleted(
        std::string_view actor, std::string_view area, long long message_id) const;
    [[nodiscard]] bool toggle_message_validation(
        std::string_view actor, std::string_view area, long long message_id) const;
    [[nodiscard]] bool toggle_message_permanent(
        std::string_view actor, std::string_view area, long long message_id) const;
    [[nodiscard]] std::size_t validate_all_messages(
        std::string_view actor, std::string_view area) const;
    void edit_message_body(
        std::string_view actor, std::string_view area, long long message_id, std::string_view body) const;
    void edit_private_message_body(
        std::string_view actor, long long message_id, std::string_view body) const;
    [[nodiscard]] long long move_message(
        std::string_view actor,
        std::string_view source_area,
        std::string_view target_area,
        long long message_id) const;
    [[nodiscard]] long long move_private_message_to_area(
        std::string_view actor, std::string_view target_area, long long message_id) const;
    [[nodiscard]] long long move_public_message_to_private(
        std::string_view actor,
        std::string_view source_area,
        long long message_id) const;
    [[nodiscard]] MessageUserUsage user_usage(std::string_view handle) const;
    [[nodiscard]] BoardMessagePage board_page(
        std::string_view area,
        std::string_view viewer,
        std::size_t page = 0,
        std::size_t page_size = 10,
        bool unread_only = false) const;
    [[nodiscard]] BoardMessagePage search_page(
        std::string_view area,
        std::string_view viewer,
        std::string_view query,
        MessageSearchField field,
        bool unread_only = false,
        std::size_t page = 0,
        std::size_t page_size = 10) const;
    [[nodiscard]] UnreadBoardPage unread_messages(
        std::string_view viewer,
        std::size_t page = 0,
        std::size_t page_size = 10,
        const std::vector<long long>& unlocked_area_ids = {}) const;
    [[nodiscard]] std::optional<BoardMessage> find(
        std::string_view viewer,
        std::string_view area,
        long long message_id) const;
    [[nodiscard]] std::optional<LocatedBoardMessage> find_with_area(
        std::string_view viewer, long long message_id) const;
    void mark_read(std::string_view viewer, std::string_view area, long long message_id) const;
    void create_area(std::string_view name) const;
    void rename_area(long long area_id, std::string_view name) const;
    [[nodiscard]] RemovedBoardArea remove_area(long long area_id) const;
    void post(
        std::string_view author,
        std::string_view area,
        std::string_view subject,
        std::string_view body,
        std::optional<long long> reply_to = std::nullopt,
        bool allow_mci = true,
        std::string_view recipient = "All",
        int anonymous_type = 0,
        std::string_view posted_as = {},
        int posts_this_call = 0) const;
    [[nodiscard]] PrivateMessagePage private_mail_page(
        std::string_view viewer,
        PrivateMailbox mailbox,
        std::size_t page = 0,
        std::size_t page_size = 10) const;
    [[nodiscard]] std::optional<PrivateMessage> find_private(
        std::string_view viewer,
        long long message_id) const;
    void mark_private_read(std::string_view viewer, long long message_id) const;
    [[nodiscard]] bool toggle_private_deleted(std::string_view actor, long long message_id) const;
    void send_private(
        std::string_view sender,
        std::string_view recipient,
        std::string_view subject,
        std::string_view body,
        std::optional<long long> reply_to = std::nullopt,
        bool anonymous = false,
        int sent_this_call = 0) const;
    void forward_private(
        std::string_view actor,
        std::string_view recipient,
        long long original_message_id,
        std::string_view forwarding_header) const;
    void forward_public_private(
        std::string_view actor,
        std::string_view recipient,
        std::string_view area,
        long long original_message_id,
        std::string_view forwarding_header) const;

private:
    std::string database_path_;
    mutable std::once_flag initialization_;
};

} // namespace renegade
