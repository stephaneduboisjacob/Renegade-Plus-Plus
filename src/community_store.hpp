#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace renegade {

struct OneLiner {
    std::int64_t id{};
    std::string author;
    std::string text;
    bool anonymous{};
    std::string created_at;
    std::string edited_at;
};

struct OneLinerPage {
    std::vector<OneLiner> entries;
    std::size_t page{};
    std::size_t page_count{1};
    std::uint64_t total{};
};

struct PollOption {
    std::int64_t id{};
    std::string text;
    std::uint64_t votes{};
};

struct Poll {
    std::int64_t id{};
    std::string question;
    std::string subtitle;
    std::string created_by;
    std::string created_at;
    bool allow_new_choices{};
    bool allow_vote_changes{};
    std::vector<PollOption> options;
    std::uint64_t total_votes{};
    std::optional<std::int64_t> caller_vote;
};

struct CallerSession {
    std::int64_t id{};
    std::string handle;
    int node{};
    std::string connected_at;
    std::string disconnected_at;
};

struct CallerSessionPage {
    std::vector<CallerSession> entries;
    std::size_t page{};
    std::size_t page_count{1};
    std::uint64_t total{};
};

struct AccountUsage {
    std::uint64_t total_calls{};
    std::uint64_t calls_today{};
    std::uint64_t total_online_seconds{};
    std::uint64_t online_seconds_today{};
    std::string last_on;
    std::string previous_on;
};

struct AutoMessage {
    std::string author;
    std::string text;
    bool anonymous{};
    std::string created_at;
    int anonymous_type{};
};

struct StatisticLeader {
    std::string handle;
    std::uint64_t value{};
};

struct FileDownloadLeader {
    std::string area;
    std::string filename;
    std::uint64_t downloads{};
};

struct CommunityQuote {
    std::int64_t id{};
    std::string author;
    std::string text;
    std::string created_at;
};

// Renegade's BBSLIST record, stored with a stable SQLite id and owning handle.
struct BbsListing {
    std::int64_t id{};
    std::string owner;
    std::string bbs_name;
    std::string sysop_name;
    std::string telnet_url;
    std::string website_url;
    std::string phone_number;
    std::string software;
    std::string speed;
    std::string description;
    std::string description2;
    std::string xa;
    std::string xb;
    std::string xc;
    std::string xd;
    std::string xe;
    std::string xf;
    std::string date_added;
    std::string date_edited;
};

struct BbsListingPage {
    std::vector<BbsListing> entries;
    std::size_t page{};
    std::size_t page_count{1};
    std::uint64_t total{};
};

struct ShortMessage {
    std::int64_t id{};
    std::string text;
    std::string created_at;
};

struct ScheduledEvent {
    int slot{};
    std::string description;
    std::string type{"logon"};
    bool active{};
    bool monthly{};
    int day_mask{};
    int day_of_month{};
    int start_minute{};
    int finish_minute{};
    int pre_warning_minutes{};
    int node{};
    std::string access_acs;
    int max_time_minutes{60};
    char set_ar_flag{};
    char clear_ar_flag{};
    int low_baud{};
    int high_baud{115200};
    bool soft{};
    bool run_if_missed{};
    std::string last_run_date;
};

struct SysopAuditEntry {
    std::int64_t id{};
    std::string actor;
    std::string action;
    std::string subject;
    std::string created_at;
};

struct SysopAuditPage {
    std::vector<SysopAuditEntry> entries;
    std::size_t page{};
    std::size_t page_count{1};
    std::uint64_t total{};
};

struct QuoteSubmissionPage {
    std::vector<CommunityQuote> entries;
    std::size_t page{};
    std::size_t page_count{1};
    std::uint64_t total{};
};

struct CommunityStatistics {
    std::uint64_t accounts{};
    std::uint64_t public_messages{};
    std::uint64_t private_messages{};
    std::uint64_t public_files{};
    std::uint64_t downloads{};
    std::uint64_t callers_today{};
    std::uint64_t one_liners{};
    std::uint64_t polls{};
    std::vector<StatisticLeader> top_public_posters;
    std::vector<StatisticLeader> top_callers;
    std::vector<StatisticLeader> top_private_mail_senders;
    std::vector<StatisticLeader> top_online_minutes;
    std::vector<StatisticLeader> top_uploaders;
    std::vector<StatisticLeader> top_downloaders;
    std::vector<StatisticLeader> top_uploaded_kib;
    std::vector<StatisticLeader> top_downloaded_kib;
    std::vector<FileDownloadLeader> top_downloads;
};

class CommunityStore {
public:
    explicit CommunityStore(std::string database_path);
    void initialize() const;
    [[nodiscard]] OneLinerPage one_liners(std::size_t page, std::size_t page_size = 10) const;
    void add_one_liner(std::string_view author, std::string_view text, bool anonymous) const;
    void update_one_liner(std::int64_t id, std::string_view text) const;
    void delete_one_liner(std::int64_t id) const;
    [[nodiscard]] std::optional<OneLiner> random_one_liner() const;
    [[nodiscard]] std::vector<Poll> polls(std::string_view caller) const;
    [[nodiscard]] Poll poll(std::int64_t id, std::string_view caller) const;
    void create_poll(
        std::string_view author,
        std::string_view question,
        std::string_view subtitle,
        bool allow_new_choices,
        bool allow_vote_changes,
        const std::vector<std::string>& options) const;
    void add_poll_choice(std::int64_t poll_id, std::string_view caller, std::string_view choice) const;
    void vote(std::int64_t poll_id, std::int64_t option_id, std::string_view caller) const;
    [[nodiscard]] std::vector<std::string> poll_voters(
        std::int64_t poll_id,
        std::int64_t option_id) const;
    [[nodiscard]] std::int64_t record_caller_login(
        std::string_view handle, int node, std::optional<int> remaining_seconds = std::nullopt) const;
    void update_caller_session_time(std::int64_t session_id, std::optional<int> remaining_seconds) const;
    void update_caller_session_invisible(std::int64_t session_id, bool invisible) const;
    void update_caller_session_availability(std::int64_t session_id, bool available) const;
    void record_caller_logout(std::int64_t session_id) const;
    [[nodiscard]] CallerSessionPage today_callers(std::size_t page, std::size_t page_size = 10) const;
    [[nodiscard]] AccountUsage account_usage(std::string_view handle) const;
    [[nodiscard]] std::optional<AutoMessage> auto_message() const;
    void set_auto_message(
        std::string_view author, std::string_view text, bool anonymous, bool sysop_anonymous = false) const;
    [[nodiscard]] CommunityStatistics statistics() const;
    [[nodiscard]] std::vector<CommunityQuote> approved_quotes() const;
    [[nodiscard]] QuoteSubmissionPage quote_submissions(std::size_t page, std::size_t page_size = 10) const;
    void submit_quote(std::string_view author, std::string_view text) const;
    void approve_quote_submission(std::int64_t id) const;
    void delete_quote_submission(std::int64_t id) const;
    [[nodiscard]] BbsListingPage bbs_listings(std::size_t page, std::size_t page_size = 8) const;
    [[nodiscard]] std::size_t bbs_listing_page_for(std::int64_t id, std::size_t page_size = 8) const;
    [[nodiscard]] std::int64_t add_bbs_listing(std::string_view owner, const BbsListing& listing) const;
    void update_bbs_listing(
        std::int64_t id,
        std::string_view caller,
        bool sysop,
        const BbsListing& listing) const;
    void delete_bbs_listing(std::int64_t id, std::string_view caller, bool sysop) const;
    void send_short_message(
        std::string_view recipient, std::string_view text, bool allow_pending_account = false) const;
    [[nodiscard]] std::vector<ShortMessage> claim_short_messages(std::string_view recipient) const;
    [[nodiscard]] std::vector<ScheduledEvent> scheduled_events() const;
    void set_scheduled_event(const ScheduledEvent& event) const;
    void delete_scheduled_event(int slot) const;
    void record_sysop_action(
        std::string_view actor, std::string_view action, std::string_view subject) const;
    [[nodiscard]] SysopAuditPage sysop_audit(std::size_t page, std::size_t page_size = 10) const;

private:
    void initialize_schema() const;
    std::string database_path_;
    mutable std::once_flag initialize_once_;
};

} // namespace renegade
