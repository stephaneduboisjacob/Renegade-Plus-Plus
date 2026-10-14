#include "server.hpp"

#include "account_store.hpp"
#include "archive_store.hpp"
#include "community_store.hpp"
#include "file_store.hpp"
#include "legacy_mci.hpp"
#include "message_store.hpp"
#include "secure_sftp.hpp"
#include "terminal.hpp"

#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <poll.h>
#include <random>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <strings.h>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <unistd.h>

namespace renegade {
namespace {

volatile std::sig_atomic_t stop_requested = 0;
constexpr std::size_t kMaxPendingOutputBytes = 4U * 1024U * 1024U;
constexpr std::size_t kOutputBudgetPerPoll = 64U * 1024U;
constexpr char kTerminalArrowUp = '\x1c';
constexpr char kTerminalArrowDown = '\x1d';
constexpr char kTerminalArrowRight = '\x1e';
constexpr char kTerminalArrowLeft = '\x1f';

struct ArchiveFrame {
    std::string name;
    std::vector<std::uint8_t> contents;
    ArchiveListing listing;
    std::string prefix;
    std::vector<ArchiveEntry> visible_entries;
    std::size_t page{};
    std::size_t selection_index{};
};

enum class ApplicationAnswerField {
    RealName,
    Country,
    Street,
    CityState,
    PostalCode,
    Phone,
    BirthDate,
    Sex,
    UserAnswer1,
    UserAnswer2,
    UserAnswer3,
    ForgotPasswordAnswer,
    Signature,
    AnsiColor,
    ClearScreen,
    PagePause,
    Hotkeys,
    ExpertMode,
    Mailbox,
};

struct ApplicationQuestion {
    int source_number{};
    std::string_view prompt;
    std::size_t maximum{};
    ApplicationAnswerField field{};
    bool secret{};
};

constexpr std::array<ApplicationQuestion, 19> kApplicationQuestionCatalog{{
    {2, "Real name", 36, ApplicationAnswerField::RealName, false},
    {3, "Country (1 USA, 2 Canada, 3 other)", 1, ApplicationAnswerField::Country, false},
    {4, "Street address", 30, ApplicationAnswerField::Street, false},
    {5, "City and state / province", 30, ApplicationAnswerField::CityState, false},
    {6, "ZIP or postal code", 10, ApplicationAnswerField::PostalCode, false},
    {7, "Phone number", 12, ApplicationAnswerField::Phone, false},
    {8, "Birth date (YYYY-MM-DD)", 10, ApplicationAnswerField::BirthDate, false},
    {9, "Gender (M/F)", 1, ApplicationAnswerField::Sex, false},
    {10, "SysOp-defined answer 1", 35, ApplicationAnswerField::UserAnswer1, false},
    {11, "SysOp-defined answer 2", 35, ApplicationAnswerField::UserAnswer2, false},
    {12, "SysOp-defined answer 3", 35, ApplicationAnswerField::UserAnswer3, false},
    {14, "Password-recovery answer", 40, ApplicationAnswerField::ForgotPasswordAnswer, true},
    {100, "Signature (Renegade C++ extension)", 80, ApplicationAnswerField::Signature, false},
    {16, "Enable ANSI color? (Y/N)", 1, ApplicationAnswerField::AnsiColor, false},
    {19, "Clear screens? (Y/N)", 1, ApplicationAnswerField::ClearScreen, false},
    {20, "Pause at screenfuls? (Y/N)", 1, ApplicationAnswerField::PagePause, false},
    {21, "Use hotkey input? (Y/N)", 1, ApplicationAnswerField::Hotkeys, false},
    {22, "Use expert mode? (Y/N)", 1, ApplicationAnswerField::ExpertMode, false},
    {25, "Keep your mailbox open? (Y/N)", 1, ApplicationAnswerField::Mailbox, false},
}};

ArchiveListing visible_archive_listing(const ArchiveFrame& frame) {
    ArchiveListing visible;
    visible.format = frame.listing.format;
    visible.truncated = frame.listing.truncated;
    if (!frame.prefix.empty()) {
        visible.entries.push_back({std::numeric_limits<std::size_t>::max(), "../", 0, {}, true, false, true});
    }
    std::unordered_set<std::string> directories;
    for (const ArchiveEntry& entry : frame.listing.entries) {
        if (!entry.name.starts_with(frame.prefix)) {
            continue;
        }
        const std::string_view remainder(entry.name.data() + frame.prefix.size(),
            entry.name.size() - frame.prefix.size());
        if (remainder.empty()) {
            continue;
        }
        const std::size_t slash = remainder.find('/');
        if (slash != std::string_view::npos) {
            const std::string directory = frame.prefix + std::string(remainder.substr(0, slash + 1));
            if (directories.insert(directory).second) {
                visible.entries.push_back({std::numeric_limits<std::size_t>::max(), directory,
                    0, {}, true, false, false});
            }
        } else if (entry.directory) {
            const std::string directory = frame.prefix + std::string(remainder) + "/";
            if (directories.insert(directory).second) {
                ArchiveEntry item = entry;
                item.name = directory;
                visible.entries.push_back(std::move(item));
            }
        } else {
            visible.entries.push_back(entry);
        }
        if (visible.entries.size() >= ArchiveStore::max_entries) {
            visible.truncated = true;
            break;
        }
    }
    return visible;
}

class ScopedFileDescriptor final {
public:
    explicit ScopedFileDescriptor(int value = -1) noexcept : value_(value) {}
    ~ScopedFileDescriptor() { if (value_ >= 0) (void)::close(value_); }
    ScopedFileDescriptor(const ScopedFileDescriptor&) = delete;
    ScopedFileDescriptor& operator=(const ScopedFileDescriptor&) = delete;
    [[nodiscard]] int get() const noexcept { return value_; }
private:
    int value_{};
};

void on_signal(int) {
    stop_requested = 1;
}

class LoginRateLimiter final {
public:
    LoginRateLimiter(std::size_t failure_limit, std::chrono::seconds failure_window)
        : failure_limit_(failure_limit), failure_window_(failure_window) {}

    bool blocked(std::string_view address) {
        if (address.empty()) {
            return false;
        }
        const auto now = Clock::now();
        std::lock_guard lock(mutex_);
        const auto found = failures_.find(std::string(address));
        if (found == failures_.end()) {
            return false;
        }
        prune(found->second, now);
        found->second.last_seen = now;
        const bool result = found->second.attempts.size() >= failure_limit_;
        if (found->second.attempts.empty()) {
            failures_.erase(found);
        }
        return result;
    }

    bool record_failure(std::string_view address) {
        if (address.empty()) {
            return false;
        }
        const auto now = Clock::now();
        std::lock_guard lock(mutex_);
        auto& entry = failures_[std::string(address)];
        prune(entry, now);
        entry.attempts.push_back(now);
        entry.last_seen = now;
        const bool result = entry.attempts.size() >= failure_limit_;
        trim(now);
        return result;
    }

    void record_success(std::string_view address) {
        if (address.empty()) {
            return;
        }
        std::lock_guard lock(mutex_);
        failures_.erase(std::string(address));
    }

    bool record_signup(std::string_view address) {
        if (address.empty()) {
            return false;
        }
        const auto now = Clock::now();
        std::lock_guard lock(mutex_);
        auto& entry = signups_[std::string(address)];
        while (!entry.attempts.empty() && now - entry.attempts.front() >= std::chrono::hours(24)) {
            entry.attempts.pop_front();
        }
        entry.last_seen = now;
        if (entry.attempts.size() >= 3) {
            return false;
        }
        entry.attempts.push_back(now);
        trim_signups(now);
        return true;
    }

private:
    using Clock = std::chrono::steady_clock;
    static constexpr std::size_t kMaximumAddresses = 4096;

    struct FailureWindow {
        std::deque<Clock::time_point> attempts;
        Clock::time_point last_seen{};
    };

    struct SignupWindow {
        std::deque<Clock::time_point> attempts;
        Clock::time_point last_seen{};
    };

    void prune(FailureWindow& entry, Clock::time_point now) const {
        while (!entry.attempts.empty() && now - entry.attempts.front() >= failure_window_) {
            entry.attempts.pop_front();
        }
    }

    void trim(Clock::time_point now) {
        if (failures_.size() <= kMaximumAddresses) {
            return;
        }
        for (auto iterator = failures_.begin(); iterator != failures_.end();) {
            prune(iterator->second, now);
            if (iterator->second.attempts.empty()) {
                iterator = failures_.erase(iterator);
            } else {
                ++iterator;
            }
        }
        while (failures_.size() > kMaximumAddresses) {
            const auto oldest = std::min_element(
                failures_.begin(), failures_.end(), [](const auto& left, const auto& right) {
                    return left.second.last_seen < right.second.last_seen;
                });
            if (oldest == failures_.end()) {
                break;
            }
            failures_.erase(oldest);
        }
    }

    void trim_signups(Clock::time_point now) {
        if (signups_.size() <= kMaximumAddresses) {
            return;
        }
        for (auto iterator = signups_.begin(); iterator != signups_.end();) {
            while (!iterator->second.attempts.empty() &&
                now - iterator->second.attempts.front() >= std::chrono::hours(24)) {
                iterator->second.attempts.pop_front();
            }
            if (iterator->second.attempts.empty()) {
                iterator = signups_.erase(iterator);
            } else {
                ++iterator;
            }
        }
        while (signups_.size() > kMaximumAddresses) {
            const auto oldest = std::min_element(
                signups_.begin(), signups_.end(), [](const auto& left, const auto& right) {
                    return left.second.last_seen < right.second.last_seen;
                });
            if (oldest == signups_.end()) {
                break;
            }
            signups_.erase(oldest);
        }
    }

    std::mutex mutex_;
    std::unordered_map<std::string, FailureWindow> failures_;
    std::unordered_map<std::string, SignupWindow> signups_;
    std::size_t failure_limit_{};
    std::chrono::seconds failure_window_{};
};

struct SupplementalScreenArt {
    std::string time_bank;
    std::string polls;
    std::string auto_message;
    std::string quotes;
    std::string one_liners;
    std::string uploads;
    std::string quote_review;
    std::string new_files;
    std::string file_validation;
    std::string download_queue;
    std::string archive;
    std::string message_move;
    std::string sysop_accounts;
    std::string sysop_account;
    std::string sysop_areas;
    std::string sysop_audit;
    std::string signup_questions;
    std::string validation_levels;
    std::string message_search;
    std::string message_scan;
    std::string unread_messages;
    std::string private_reader;
};

struct ClientContext {
    enum class AreaAdminKind { Message, File };
    enum class AdminPolicyEdit {
        None, Ratios, LevelRatios, DailyLimits, Points, UploadValidation, UnvalidatedAccess, AreaNoRatio,
        PostRatio, SubmissionAcs, InvisibleAcs, ValidationEligibility
    };
    enum class TimeBankAction { None, Deposit, Withdraw };

    AccountStore* accounts{};
    FileStore* files{};
    class SessionRegistry* registry{};
    LoginRateLimiter* login_rate_limiter{};
    std::string peer_address;
    std::string handle;
    int node_number{};
    int failed_auth_attempts{};
    bool authenticated{};
    bool allow_signup{};
    bool registration_pending{};
    bool collecting_application_profile{};
    std::size_t application_profile_field{};
    std::string application_profile_input;
    std::string application_recovery_question;
    std::array<std::string, 3> custom_user_questions;
    std::vector<ApplicationQuestion> application_questions;
    bool is_sysop{};
    bool invisible{};
    bool sysop_available{};
    bool shell_requested{};
    bool sftp_requested{};
    bool channel_closed{};
    std::atomic_bool in_chat{};
    bool drawn{};
    bool welcome_menu_active{};
    std::size_t welcome_selection_index{};
    bool waiting_for_return{};
    bool showing_nodes{};
    bool resize_pending{};
    bool ignore_line_feed{};
    bool close_requested{};
    bool viewing_art{};
    bool viewing_bulletins{};
    bool reading_bulletin{};
    bool viewing_polls{};
    bool viewing_callers{};
    bool viewing_statistics{};
    bool reading_poll{};
    bool showing_poll_results{};
    bool viewing_auto_message{};
    bool viewing_quote{};
    bool viewing_quote_queue{};
    bool viewing_short_messages{};
    bool short_messages_checked{};
    bool entrance_checked{};
    bool viewing_entrance{};
    bool once_only_checked{};
    bool viewing_once_only{};
    bool event_access_checked{};
    bool birthday_notice_checked{};
    bool birthday_check_required{};
    bool checking_birth_date{};
    std::string birthday_check_input;
    unsigned int birthday_check_frequency{};
    bool viewing_bbs_directory{};
    bool viewing_bbs_detail{};
    bool editing_bbs_listing{};
    bool confirming_bbs_delete{};
    bool changing_poll_vote{};
    bool creating_poll{};
    bool poll_question_entered{};
    bool poll_subtitle_entered{};
    bool poll_choice_policy_entered{};
    bool allow_poll_new_choices{};
    bool poll_vote_policy_entered{};
    bool allow_poll_vote_changes{};
    bool adding_poll_choice{};
    bool viewing_areas{};
    bool viewing_message_scan_settings{};
    bool entering_message_area_password{};
    bool viewing_messages{};
    bool confirming_message_validation{};
    bool selecting_message_move_area{};
    bool confirming_message_move{};
    bool moving_private_message{};
    bool moving_to_private_message{};
    bool searching_messages{};
    bool entering_message_search_query{};
    bool choosing_message_search_field{};
    std::size_t message_search_selection_index{};
    bool message_search_new_only{};
    bool message_search_all_areas{};
    bool confirming_message_extract{};
    bool extracting_private_message{};
    bool unread_only_messages{};
    bool viewing_new_scan{};
    bool reading_from_new_scan{};
    bool viewing_private_mail{};
    bool viewing_sysop{};
    bool viewing_signup_question_admin{};
    int editing_custom_user_question{};
    std::string custom_user_question_input;
    bool viewing_validation_admin{};
    char validation_admin_operation{};
    bool signup_preferences_page{};
    std::size_t signup_question_selection_index{};
    std::size_t signup_question_prompt_selection_index{};
    bool viewing_sysop_account_detail{};
    bool editing_sysop_security_levels{};
    bool editing_sysop_acs_flags{};
    bool editing_sysop_credits{};
    bool editing_sysop_file_points{};
    bool editing_sysop_short_message{};
    bool editing_sysop_profile{};
    char editing_sysop_profile_field{};
    std::string sysop_password_new;
    bool editing_sysop_birth_date{};
    bool editing_sysop_sex{};
    bool editing_sysop_expiration_date{};
    bool editing_sysop_validation_level{};
    bool confirming_sysop_validation{};
    bool viewing_sysop_audit{};
    bool viewing_sysop_areas{};
    bool viewing_profile{};
    bool viewing_profile_contacts{};
    std::size_t profile_selection_index{};
    bool viewing_time_bank{};
    std::size_t time_bank_selection_index{};
    bool viewing_files{};
    bool viewing_new_files{};
    bool viewing_file_validation{};
    bool confirming_bulk_file_validation{};
    bool choosing_file_scan_area{};
    bool return_to_new_files{};
    bool return_to_file_validation{};
    bool viewing_file_list{};
    bool viewing_file_detail{};
    bool confirming_public_file_delete{};
    bool confirming_public_file_credit_withdrawal{};
    bool entering_file_rename{};
    bool entering_file_download_count{};
    bool entering_file_points{};
    bool entering_file_point_validation{};
    bool entering_file_owner_point_adjustment{};
    bool entering_file_owner{};
    bool entering_file_date{};
    bool viewing_extended_file_description{};
    bool editing_file_description{};
    bool editing_file_extended_description{};
    bool viewing_download_queue{};
    bool confirming_download_queue_clear{};
    bool viewing_archive{};
    bool viewing_archive_entry_detail{};
    bool viewing_archive_text{};
    bool viewing_archive_art{};
    bool searching_files{};
    bool viewing_uploads{};
    bool viewing_upload_detail{};
    bool selecting_upload_area{};
    bool confirming_upload_delete{};
    bool viewing_one_liners{};
    bool adding_one_liner{};
    bool editing_one_liner{};
    bool prompting_one_liner_anonymous{};
    bool confirming_one_liner_post{};
    bool confirming_one_liner_delete{};
    bool one_liner_anonymous{};
    bool editing_profile{};
    bool reading_message{};
    bool reading_private_message{};
    bool writing_message{};
    bool writing_message_body{};
    bool entering_private_recipient{};
    bool entering_private_anonymous{};
    bool entering_private_goto{};
    bool forwarding_private_message{};
    std::optional<long long> forwarding_private_message_id;
    std::optional<std::string> forwarding_public_area;
    bool entering_auto_anonymous{};
    bool entering_message_recipient{};
    bool entering_message_anonymous{};
    bool entering_message_goto{};
    bool entering_message_tagline{};
    AnonymousMode pending_anonymous_mode{AnonymousMode::Disabled};
    bool message_is_private{};
    bool message_is_auto{};
    bool message_is_quote{};
    bool editing_public_message{};
    bool editing_private_message{};
    long long editing_message_id{};
    bool message_mci_available{};
    bool message_mci_enabled{};
    std::size_t art_index{};
    std::size_t bulletin_index{};
    std::size_t quote_index{};
    std::size_t quote_content_page{};
    std::size_t quote_content_page_count{1};
    std::size_t quote_submission_page{};
    std::size_t poll_page{};
    std::size_t poll_choice_page{};
    std::size_t poll_selection_index{};
    std::size_t poll_choice_selection_index{};
    std::size_t caller_page{};
    std::size_t statistics_page{};
    std::size_t auto_message_page{};
    std::size_t auto_message_page_count{1};
    std::size_t bbs_listing_page_index{};
    std::size_t bbs_listing_selection_index{};
    std::size_t bbs_detail_page{};
    std::size_t bbs_edit_field{};
    BbsListingPage bbs_listing_page;
    std::optional<std::int64_t> selected_bbs_listing_id;
    std::optional<std::int64_t> editing_bbs_listing_id;
    BbsListing bbs_listing_draft;
    std::string bbs_listing_input;
    std::vector<FileAreaSummary> file_areas;
    std::size_t file_area_page{};
    std::size_t file_area_selection_index{};
    std::size_t new_file_selection_index{};
    std::size_t file_validation_selection_index{};
    NewFilePage new_file_page;
    std::size_t new_file_page_index{};
    FileValidationPage file_validation_page;
    std::size_t file_validation_page_index{};
    std::string new_file_since;
    bool entering_file_scan_date{};
    std::string file_scan_date_input;
    std::string file_rename_input;
    std::string file_download_count_input;
    std::string file_points_input;
    std::string validation_file_points_input;
    std::string owner_point_adjustment_input;
    std::uint64_t validation_file_points{};
    std::string file_owner_input;
    std::string file_date_input;
    bool entering_file_move_area{};
    std::string file_move_area_input;
    int file_area_id{};
    std::string file_area_name;
    std::string file_search;
    std::string file_search_input;
    FilePage file_page;
    std::size_t file_list_page{};
    std::size_t file_list_selection_index{};
    std::optional<FileEntry> selected_public_file;
    std::size_t extended_file_description_page{};
    std::string file_description_input;
    std::vector<std::string> file_extended_description_draft;
    std::string file_extended_description_input;
    std::vector<DownloadQueueEntry> download_queue;
    std::size_t download_queue_page{};
    std::size_t download_queue_selection_index{};
    std::vector<ArchiveFrame> archive_stack;
    std::vector<std::string> archive_text_lines;
    std::string archive_text_name;
    std::size_t archive_text_page{};
    std::string archive_art_name;
    std::string archive_art_contents;
    std::optional<ArchiveEntry> selected_archive_entry;
    std::vector<IncomingFile> incoming_files;
    std::size_t incoming_files_page{};
    std::size_t incoming_file_selection_index{};
    std::optional<IncomingFile> selected_upload;
    std::vector<FileAreaSummary> upload_publish_areas;
    std::size_t upload_publish_area_page{};
    std::size_t upload_publish_area_selection_index{};
    OneLinerPage one_liner_page;
    std::size_t one_liner_selection_index{};
    std::vector<Poll> poll_list;
    QuoteSubmissionPage quote_submissions;
    std::optional<std::int64_t> selected_quote_submission_id;
    std::size_t quote_submission_selection_index{};
    CallerSessionPage caller_sessions;
    std::optional<AutoMessage> current_auto_message;
    std::vector<ShortMessage> short_messages;
    std::size_t short_message_page{};
    std::optional<std::int64_t> caller_session_id;
    std::optional<std::int64_t> selected_poll_id;
    Poll active_poll;
    CommunityStatistics community_statistics;
    std::string poll_question;
    std::string poll_subtitle;
    std::string poll_input;
    std::vector<std::string> poll_options;
    std::optional<std::int64_t> selected_one_liner_id;
    std::optional<std::int64_t> editing_one_liner_id;
    std::string one_liner_input;
    std::string pending_one_liner_text;
    std::vector<AccountSummary> sysop_accounts;
    std::size_t sysop_page{};
    std::optional<std::size_t> sysop_selected_index;
    std::size_t sysop_account_action_selection_index{};
    std::string sysop_account_input;
    std::optional<ValidationLevel> pending_sysop_validation;
    std::vector<ValidationLevel> validation_levels;
    std::size_t validation_admin_page{};
    std::size_t validation_admin_selection_index{};
    std::string validation_admin_input;
    std::string validation_admin_notice;
    SysopAuditPage sysop_audit;
    std::size_t sysop_audit_page{};
    std::string_view welcome_art;
    std::string_view entrance_art;
    std::string_view new_caller_art;
    std::string_view sysop_art;
    std::string_view profile_art;
    std::string_view once_only_art;
    std::string_view once_only_art_modified;
    std::string_view birthday_art;
    std::string_view birthday_late_art;
    std::string_view nodes_art;
    std::string_view callers_art;
    std::string_view stats_art;
    std::string_view help_art;
    std::string_view bbs_art;
    std::string_view file_areas_art;
    std::string_view chat_art;
    std::string_view bulletin_art;
    std::string_view areas_art;
    std::string_view board_art;
    std::string_view mailbox_art;
    std::string_view reader_art;
    std::string_view editor_art;
    const SupplementalScreenArt* supplemental_art{};
    const std::vector<AnsiArtwork>* art_catalog{};
    const std::vector<AnsiArtwork>* bulletin_catalog{};
    const std::vector<AnsiArtwork>* quote_catalog{};
    const std::vector<AnsiArtwork>* tagline_catalog{};
    std::vector<AnsiArtwork> quote_options;
    LegacyMciPositions legacy_mci_positions;
    MessageStore* messages{};
    CommunityStore* community{};
    std::unique_ptr<SecureSftpSession> sftp;
    std::deque<std::string> sftp_output;
    std::size_t sftp_output_bytes{};
    std::vector<BoardArea> board_areas;
    std::unordered_set<long long> unlocked_message_areas;
    std::optional<long long> pending_message_area_id;
    std::optional<long long> pending_parent_message_id;
    std::size_t area_page{};
    std::size_t message_area_selection_index{};
    std::size_t area_admin_action_selection_index{};
    std::string current_area{"General"};
    bool entering_message_scan_date{};
    std::string message_scan_date_input;
    int public_posts_this_call{};
    int private_messages_this_call{};
    AccountProfile profile;
    enum class ProfileField {
        RealName, Location, Signature, BirthDate, Sex,
        Country, Street, CityState, PostalCode, Phone,
        UserAnswer1, UserAnswer2, UserAnswer3, ForgotPasswordAnswer,
        CurrentPassword, NewPassword, ConfirmPassword
    };
    bool profile_completion_checked{};
    bool profile_completion_active{};
    std::vector<ProfileField> profile_completion_fields;
    std::size_t profile_completion_index{};
    std::optional<ProfileField> profile_field;
    std::string profile_input;
    bool changing_password{};
    std::string password_change_current;
    std::string password_change_new;
    TimeBankStatus time_bank;
    TimeBankAction time_bank_action{TimeBankAction::None};
    std::string time_bank_input;
    int time_bank_max_minutes{};
    int time_bank_deposit_daily_limit{};
    int time_bank_withdrawal_daily_limit{};
    std::optional<AreaAdminKind> area_admin_kind;
    AdminPolicyEdit admin_policy_edit{AdminPolicyEdit::None};
    bool area_admin_renaming_file{};
    bool area_admin_renaming_message{};
    bool editing_file_area_access{};
    bool editing_message_area_access{};
    bool editing_message_force_read{};
    bool editing_message_area_password{};
    bool editing_message_taglines{};
    bool editing_message_filter{};
    bool editing_message_unhidden{};
    bool editing_message_tearline{};
    bool editing_message_origin{};
    bool editing_message_real_names{};
    bool editing_message_quote_templates{};
    bool editing_private_quote_templates{};
    bool editing_global_anonymous_acs{};
    bool editing_global_post_acs{};
    bool editing_global_post_limits{};
    bool editing_global_credit_costs{};
    bool editing_global_mail_limits{};
    bool area_admin_deleting_file{};
    bool area_admin_confirming_file_deletion{};
    bool area_admin_deleting_message{};
    bool area_admin_confirming_message_deletion{};
    long long area_admin_delete_id{};
    std::string area_admin_delete_name;
    std::string area_admin_input;
    std::string area_admin_notice;
    std::string menu_command_input;
    std::string pending_terminal_escape;
    std::chrono::steady_clock::time_point terminal_escape_started{};
    std::vector<BoardMessage> board_messages;
    std::vector<std::string> board_message_areas;
    std::vector<PrivateMessage> private_messages;
    PrivateMailbox private_mailbox{PrivateMailbox::Inbox};
    std::optional<PrivateMessage> private_message;
    struct ReaderFrame {
        BoardMessage message;
        std::size_t page{};
        std::string area;
    };
    std::optional<BoardMessage> reader_message;
    std::vector<ReaderFrame> reader_backstack;
    std::size_t message_list_page{};
    std::size_t message_list_page_count{1};
    std::size_t message_list_selection_index{};
    std::size_t message_index{};
    std::size_t new_scan_page_index{};
    std::size_t new_scan_selection_index{};
    UnreadBoardPage new_scan_page;
    std::size_t message_page{};
    std::size_t message_page_count{1};
    std::size_t message_move_page{};
    std::size_t message_move_selection_index{};
    long long moving_message_id{};
    std::string message_move_target;
    MessageSearchField message_search_field{MessageSearchField::AllText};
    std::string message_search_query;
    std::size_t private_mail_list_page{};
    std::size_t private_mail_list_page_count{1};
    std::size_t private_message_index{};
    std::size_t private_message_page{};
    std::size_t private_message_page_count{1};
    std::string message_subject;
    std::string message_subject_default;
    std::optional<long long> reply_to;
    std::string private_recipient;
    std::string message_recipient;
    std::string message_recipient_default;
    std::string message_body;
    std::string message_line;
    std::size_t message_line_count{};
    int columns{80};
    int rows{25};
    std::string terminal{"xterm"};
    std::chrono::steady_clock::time_point connected_at{std::chrono::steady_clock::now()};
    std::chrono::steady_clock::time_point authenticated_at{};
    std::chrono::system_clock::time_point authenticated_wall_clock{};
    std::chrono::steady_clock::time_point last_activity_at{connected_at};
    std::optional<std::chrono::steady_clock::time_point> session_deadline;
    unsigned int session_time_limit_minutes{};
    unsigned int idle_timeout_seconds{1800};
    std::string incoming;
    std::string chat_input;
    std::mutex outgoing_mutex;
    std::deque<std::string> outgoing;
    std::deque<std::string> pending_output;
    struct PausedOutput {
        std::string bytes;
        bool pause_after{};
    };
    std::deque<PausedOutput> paused_output;
    std::size_t pending_output_offset{};
    std::size_t pending_output_bytes{};
    bool waiting_for_display_pause{};
    ssh_channel channel{};
    ssh_channel_callbacks_struct channel_callbacks{};

    ~ClientContext() {
        if (channel != nullptr) {
            if (ssh_channel_is_open(channel)) {
                (void)ssh_channel_send_eof(channel);
                (void)ssh_channel_close(channel);
            }
            ssh_channel_free(channel);
        }
    }

    void queue(std::string message) {
        std::lock_guard lock(outgoing_mutex);
        if (outgoing.size() < 256) {
            outgoing.push_back(std::move(message));
        }
    }
};

void record_sysop_action(ClientContext& client, std::string_view action, std::string_view subject);

struct BbsDirectoryField {
    std::string_view label;
    std::size_t maximum;
    std::string BbsListing::*value;
};

constexpr std::array<BbsDirectoryField, 15> kBbsDirectoryFields{{
    {"BBS name", 30, &BbsListing::bbs_name},
    {"SysOp name", 30, &BbsListing::sysop_name},
    {"Telnet / SSH address", 60, &BbsListing::telnet_url},
    {"Web site URL", 60, &BbsListing::website_url},
    {"Phone number", 20, &BbsListing::phone_number},
    {"Software", 8, &BbsListing::software},
    {"Speed", 8, &BbsListing::speed},
    {"Description 1", 60, &BbsListing::description},
    {"Description 2", 60, &BbsListing::description2},
    {"Custom field XA", 8, &BbsListing::xa},
    {"Custom field XB", 30, &BbsListing::xb},
    {"Custom field XC", 30, &BbsListing::xc},
    {"Custom field XD", 40, &BbsListing::xd},
    {"Custom field XE", 60, &BbsListing::xe},
    {"Custom field XF", 60, &BbsListing::xf},
}};

class SessionRegistry final {
public:
    explicit SessionRegistry(int max_nodes) : max_nodes_(max_nodes) {}

    int join(ClientContext& client, std::string handle) {
        std::lock_guard lock(mutex_);
        for (int index = 0; index < max_nodes_; ++index) {
            if (nodes_[static_cast<std::size_t>(index)] == nullptr) {
                client.handle = std::move(handle);
                client.node_number = index + 1;
                nodes_[static_cast<std::size_t>(index)] = &client;
                return client.node_number;
            }
        }
        return 0;
    }

    void leave(ClientContext& client) {
        std::lock_guard lock(mutex_);
        for (ClientContext*& node : nodes_) {
            if (node == &client) {
                node = nullptr;
            }
        }
    }

    [[nodiscard]] std::vector<NodeInfo> snapshot(int viewer_node, bool may_see_invisible) const {
        std::vector<NodeInfo> result;
        std::lock_guard lock(mutex_);
        for (int index = 0; index < max_nodes_; ++index) {
            const ClientContext* node = nodes_[static_cast<std::size_t>(index)];
            if (node != nullptr && (!node->invisible || may_see_invisible || index + 1 == viewer_node)) {
                result.push_back({index + 1, node->handle, node->in_chat.load(), node->invisible});
            }
        }
        return result;
    }

    void set_invisible(ClientContext& client, bool invisible) {
        std::lock_guard lock(mutex_);
        client.invisible = invisible;
    }

    void broadcast(const ClientContext& sender, std::string message) const {
        std::lock_guard lock(mutex_);
        for (ClientContext* node : nodes_) {
            if (node != nullptr && node != &sender && node->in_chat.load()) {
                node->queue(message);
            }
        }
    }

private:
    int max_nodes_{};
    mutable std::mutex mutex_;
    std::array<ClientContext*, 32> nodes_{};
};

std::string format_local_time(std::chrono::system_clock::time_point point, const char* format) {
    if (point == std::chrono::system_clock::time_point{}) {
        return {};
    }
    const std::time_t raw = std::chrono::system_clock::to_time_t(point);
    std::tm local{};
    if (::localtime_r(&raw, &local) == nullptr) {
        return {};
    }
    std::array<char, 64> buffer{};
    if (std::strftime(buffer.data(), buffer.size(), format, &local) == 0) {
        return {};
    }
    return buffer.data();
}

std::string first_word(std::string_view name) {
    const std::size_t start = name.find_first_not_of(" \t");
    if (start == std::string_view::npos) {
        return {};
    }
    const std::size_t end = name.find_first_of(" \t", start);
    return std::string(name.substr(start, end == std::string_view::npos ? end : end - start));
}

std::string last_word(std::string_view name) {
    const std::size_t start = name.find_first_not_of(" \t");
    const std::size_t end = name.find_last_not_of(" \t");
    if (start == std::string_view::npos || end == std::string_view::npos) {
        return {};
    }
    const std::size_t separator = name.find_last_of(" \t", end);
    const std::size_t word_start = separator == std::string_view::npos
        ? start
        : separator + 1;
    return std::string(name.substr(word_start, end - word_start + 1));
}

std::string mci_on_off(bool enabled) {
    return enabled ? "On " : "Off";
}

LegacyMciValues screen_mci_values(const ClientContext& client) {
    const std::string real_name = client.profile.real_name.empty()
        ? client.handle
        : client.profile.real_name;
    const std::int64_t online_minutes = client.authenticated_at == std::chrono::steady_clock::time_point{}
        ? 0
        : std::max<std::int64_t>(0, std::chrono::duration_cast<std::chrono::minutes>(
            std::chrono::steady_clock::now() - client.authenticated_at).count());
    const std::uint64_t online_seconds = client.authenticated_at == std::chrono::steady_clock::time_point{}
        ? 0
        : static_cast<std::uint64_t>(std::max<std::int64_t>(0,
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - client.authenticated_at).count()));
    AccountUsage usage;
    if (client.community != nullptr) {
        try {
            usage = client.community->account_usage(client.handle);
        } catch (const std::exception& error) {
            std::cerr << "Could not read account statistics for MCI rendering: " << error.what() << '\n';
        }
    }
    const std::uint64_t session_today_seconds =
        format_local_time(client.authenticated_wall_clock, "%Y-%m-%d") ==
            format_local_time(std::chrono::system_clock::now(), "%Y-%m-%d")
        ? online_seconds
        : 0;
    std::string day_period;
    const std::string hour_text = format_local_time(std::chrono::system_clock::now(), "%H");
    if (!hour_text.empty()) {
        const int hour = std::stoi(hour_text);
        day_period = hour >= 18 ? "evening" : (hour >= 12 ? "afternoon" : "morning");
    }

    std::vector<BoardArea> message_areas = client.board_areas;
    std::size_t message_area_count = message_areas.size();
    int lowest_message_area = 0;
    int highest_message_area = 0;
    if (message_area_count == 0 && client.messages != nullptr) {
        try {
            message_areas = client.messages->areas(client.handle);
            message_area_count = message_areas.size();
        } catch (const std::exception& error) {
            std::cerr << "Could not count message areas for MCI rendering: " << error.what() << '\n';
        }
    }
    for (const BoardArea& area : message_areas) {
        const int id = static_cast<int>(area.id);
        if (lowest_message_area == 0 || id < lowest_message_area) {
            lowest_message_area = id;
        }
        highest_message_area = std::max(highest_message_area, id);
    }
    std::vector<FileAreaSummary> file_areas = client.file_areas;
    std::size_t file_area_count = file_areas.size();
    int lowest_file_area = 0;
    int highest_file_area = 0;
    if (file_area_count == 0 && client.files != nullptr) {
        try {
            file_area_count = client.files->areas().size();
            file_areas = client.files->areas();
            file_area_count = file_areas.size();
        } catch (const std::exception& error) {
            std::cerr << "Could not count file areas for MCI rendering: " << error.what() << '\n';
        }
    }
    for (const FileAreaSummary& area : file_areas) {
        if (lowest_file_area == 0 || area.id < lowest_file_area) {
            lowest_file_area = area.id;
        }
        highest_file_area = std::max(highest_file_area, area.id);
    }
    std::size_t current_message_count = 0;
    long long highest_message_id = 0;
    if (client.messages != nullptr && !client.current_area.empty()) {
        try {
            const BoardMessagePage current_messages = client.messages->board_page(
                client.current_area, client.handle, 0, 1);
            current_message_count = current_messages.total;
            if (!current_messages.messages.empty()) {
                highest_message_id = current_messages.messages.front().id;
            }
        } catch (const std::exception& error) {
            std::cerr << "Could not count current-area messages for MCI rendering: " << error.what() << '\n';
        }
    }
    std::size_t current_file_count = 0;
    const int current_file_area_id = client.file_area_id > 0
        ? client.file_area_id
        : (file_areas.empty() ? 0 : file_areas.front().id);
    if (client.files != nullptr && current_file_area_id > 0) {
        try {
            current_file_count = client.files->files(
                client.handle, current_file_area_id, std::string_view{}, 0, 1).total;
        } catch (const std::exception& error) {
            std::cerr << "Could not count current-area files for MCI rendering: " << error.what() << '\n';
        }
    }
    FileUserUsage file_usage;
    if (client.files != nullptr) {
        try {
            file_usage = client.files->user_usage(client.handle);
        } catch (const std::exception& error) {
            std::cerr << "Could not read file-transfer totals for MCI rendering: " << error.what() << '\n';
        }
    }
    MessageUserUsage message_usage;
    std::uint64_t unread_private_messages = 0;
    if (client.messages != nullptr) {
        try {
            message_usage = client.messages->user_usage(client.handle);
            unread_private_messages = client.messages->private_mail_page(
                client.handle, PrivateMailbox::Inbox, 0, 1).unread_total;
        } catch (const std::exception& error) {
            std::cerr << "Could not read message totals for MCI rendering: " << error.what() << '\n';
        }
    }
    const std::string last_call_date = usage.previous_on.size() >= 10
        ? usage.previous_on.substr(0, 10)
        : std::string{};

    LegacyMciValues values{
        {"UN", client.handle},
        {"RN", real_name},
        {"LO", client.profile.location},
        {"A1", std::to_string(lowest_file_area)},
        {"A2", std::to_string(highest_file_area)},
        {"A3", std::to_string(lowest_message_area)},
        {"A4", std::to_string(highest_message_area)},
        {"ND", std::to_string(client.node_number)},
        {"BN", "Renegade"},
        {"VR", "Renegade C++ SSH"},
        {"BD", "SSH"},
        {"O1", "ANSI"},
        {"O2", std::to_string(client.columns) + "x" + std::to_string(client.rows)},
        {"MM", std::to_string(message_area_count)},
        {"MA", std::to_string(message_area_count)},
        {"FA", std::to_string(file_area_count)},
        {"M#", std::to_string(current_message_count)},
        {"F#", std::to_string(current_file_count)},
        {"BF", std::to_string(highest_file_area)},
        {"BM", std::to_string(highest_message_area)},
        {"HM", std::to_string(highest_message_id)},
        {"MR", std::to_string(client.reader_message.has_value() &&
                highest_message_id > client.reader_message->id
                    ? highest_message_id - client.reader_message->id
                    : 0)},
        {"MS", client.unread_only_messages ? "" : "not "},
        {"CL", "\f"},
        {"LF", "\r\n"},
        {"MB", client.current_area},
        {"FB", client.file_area_name},
        {"DA", format_local_time(std::chrono::system_clock::now(), "%Y-%m-%d")},
        {"LC", last_call_date},
        {"DT", day_period},
        {"ED", "Never"},
        {"EX", "Never"},
        {"FN", first_word(real_name)},
        {"LN", last_word(real_name)},
        {"IP", client.peer_address},
        {"ES", std::to_string(message_usage.private_sent)},
        {"EW", std::to_string(unread_private_messages)},
        {"DL", std::to_string(file_usage.downloads)},
        {"DK", std::to_string(file_usage.downloaded_bytes / 1024)},
        {"UL", std::to_string(file_usage.uploads)},
        {"UK", std::to_string(file_usage.uploaded_bytes / 1024)},
        {"MO", std::to_string(online_minutes)},
        {"PS", std::to_string(message_usage.public_posts)},
        {"TC", std::to_string(usage.total_calls)},
        {"UC", std::to_string(usage.calls_today)},
        {"TT", std::to_string((usage.total_online_seconds + online_seconds) / 60)},
        {"TO", std::to_string((usage.online_seconds_today + session_today_seconds) / 60)},
        {"O3", mci_on_off(client.profile.clear_screen)},
        {"O4", "Off"},
        {"O5", mci_on_off(client.profile.pause_screens)},
        {"O6", mci_on_off(client.profile.hotkeys)},
        {"O7", mci_on_off(client.profile.expert_mode)},
        {"O8", "Open"},
        {"O9", mci_on_off(client.profile.ansi_color)},
        {"OL", "Off"},
        {"TI", format_local_time(client.authenticated_wall_clock, "%H:%M")},
    };
    if (client.accounts != nullptr) {
        try {
            values.emplace("TU", std::to_string(client.accounts->count_approved_accounts()));
        } catch (const std::exception& error) {
            std::cerr << "Could not count BBS accounts for MCI rendering: " << error.what() << '\n';
        }
    }
    if (file_usage.downloads > 0) {
        std::array<char, 32> ratio{};
        (void)std::snprintf(ratio.data(), ratio.size(), "%.3f",
            static_cast<double>(file_usage.uploads) / static_cast<double>(file_usage.downloads));
        values.emplace("NR", ratio.data());
    } else {
        values.emplace("NR", "0");
    }
    if (usage.total_calls > 0) {
        std::array<char, 32> posting_ratio{};
        (void)std::snprintf(posting_ratio.data(), posting_ratio.size(), "%.2f",
            static_cast<double>(message_usage.public_posts) /
                static_cast<double>(usage.total_calls) * 100.0);
        values.emplace("PC", posting_ratio.data());
    } else {
        values.emplace("PC", "0");
    }
    if (client.reader_message.has_value()) {
        values.emplace("CM", std::to_string(client.reader_message->id));
    }
    return values;
}

std::string render_screen_art(ClientContext& client, std::string_view artwork) {
    if (artwork.empty()) {
        return {};
    }
    return render_legacy_display(
        artwork, screen_mci_values(client), client.columns, client.rows,
        &client.legacy_mci_positions);
}

std::string_view supplemental_screen_art(
    const ClientContext& client,
    const std::string SupplementalScreenArt::*member) {
    return client.supplemental_art == nullptr
        ? std::string_view{}
        : std::string_view(client.supplemental_art->*member);
}

std::string_view sysop_screen_art(
    const ClientContext& client,
    const std::string SupplementalScreenArt::*member) {
    const std::string_view specific = supplemental_screen_art(client, member);
    return specific.empty() ? client.sysop_art : specific;
}

std::string get_peer_address(ssh_session session) {
    const int descriptor = ssh_get_fd(session);
    if (descriptor < 0) {
        return {};
    }
    sockaddr_storage address{};
    socklen_t address_size = sizeof(address);
    if (::getpeername(descriptor, reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
        return {};
    }

    std::array<char, INET6_ADDRSTRLEN> text{};
    if (address.ss_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&address);
        if (::inet_ntop(AF_INET, &ipv4->sin_addr, text.data(), text.size()) != nullptr) {
            return text.data();
        }
    } else if (address.ss_family == AF_INET6) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(&address);
        if (IN6_IS_ADDR_V4MAPPED(&ipv6->sin6_addr)) {
            const auto* ipv4_bytes = reinterpret_cast<const unsigned char*>(&ipv6->sin6_addr) + 12;
            if (::inet_ntop(AF_INET, ipv4_bytes, text.data(), text.size()) != nullptr) {
                return text.data();
            }
        }
        if (::inet_ntop(AF_INET6, &ipv6->sin6_addr, text.data(), text.size()) != nullptr) {
            return text.data();
        }
    }
    return {};
}

int authenticate_password(ssh_session, const char* user, const char* password, void* userdata) {
    auto* client = static_cast<ClientContext*>(userdata);
    if (client == nullptr || client->accounts == nullptr || user == nullptr || password == nullptr) {
        return SSH_AUTH_DENIED;
    }
    if (client->authenticated) {
        return SSH_AUTH_SUCCESS;
    }
    if (client->close_requested || client->failed_auth_attempts >= 5) {
        client->close_requested = true;
        return SSH_AUTH_DENIED;
    }
    if (client->login_rate_limiter != nullptr &&
        client->login_rate_limiter->blocked(client->peer_address)) {
        client->close_requested = true;
        return SSH_AUTH_DENIED;
    }

    try {
        const auto account = client->accounts->authenticate(user, password);
        if (!account.has_value()) {
            const bool password_acceptable = password[0] != '\0' && std::strlen(password) >= 12 &&
                std::strlen(password) <= 128;
            if (client->allow_signup && valid_handle(user) && password_acceptable &&
                client->login_rate_limiter != nullptr &&
                client->login_rate_limiter->record_signup(client->peer_address)) {
                try {
                    if (client->accounts->create_pending_user(user, password)) {
                        client->handle = user;
                        client->registration_pending = true;
                        client->profile = client->accounts->profile(user);
                        client->custom_user_questions = client->accounts->custom_user_questions();
                        client->application_questions.clear();
                        const auto question_states = client->accounts->signup_question_states();
                        client->application_recovery_question =
                            client->accounts->forgot_password_question();
                        const bool country_needed = question_states[3] || question_states[5] ||
                            question_states[6] || question_states[7];
                        for (const ApplicationQuestion& source_question : kApplicationQuestionCatalog) {
                            ApplicationQuestion question = source_question;
                            if (question.source_number == 100 ||
                                (question.source_number == 3 && country_needed) ||
                                (question.source_number != 3 &&
                                    question.source_number < static_cast<int>(question_states.size()) &&
                                    question_states[static_cast<std::size_t>(question.source_number)] &&
                                    (question.source_number != 14 ||
                                        !client->application_recovery_question.empty()))) {
                                if (question.source_number >= 10 && question.source_number <= 12) {
                                    const std::string& custom = client->custom_user_questions[
                                        static_cast<std::size_t>(question.source_number - 10)];
                                    if (!custom.empty()) {
                                        question.prompt = custom;
                                    }
                                }
                                client->application_questions.push_back(question);
                            }
                        }
                        client->collecting_application_profile =
                            !client->application_questions.empty();
                        client->authenticated = true;
                        client->authenticated_at = std::chrono::steady_clock::now();
                        if (client->session_time_limit_minutes > 0) {
                            client->session_deadline = client->authenticated_at +
                                std::chrono::minutes(client->session_time_limit_minutes);
                        }
                        client->authenticated_wall_clock = std::chrono::system_clock::now();
                        client->last_activity_at = client->authenticated_at;
                        if (client->login_rate_limiter != nullptr) {
                            client->login_rate_limiter->record_success(client->peer_address);
                        }
                        return SSH_AUTH_SUCCESS;
                    }
                } catch (const std::invalid_argument&) {
                    // Invalid handles and weak passwords follow the same denial
                    // path as other failed authentication attempts.
                }
            }
            ++client->failed_auth_attempts;
            const bool ip_limited = client->login_rate_limiter != nullptr &&
                client->login_rate_limiter->record_failure(client->peer_address);
            if (client->failed_auth_attempts >= 5) {
                client->close_requested = true;
            }
            if (ip_limited) {
                client->close_requested = true;
                std::cerr << "SSH password failures reached the per-address limit for "
                          << client->peer_address << ".\n";
            }
            return SSH_AUTH_DENIED;
        }
        client->handle = account->handle;
        client->new_file_since = account->previous_login;
        if (client->login_rate_limiter != nullptr) {
            client->login_rate_limiter->record_success(client->peer_address);
        }
        client->authenticated = true;
        client->is_sysop = client->accounts->is_sysop(account->handle);
        client->sysop_available = client->is_sysop;
        client->profile = client->accounts->profile(account->handle);
        client->custom_user_questions = client->accounts->custom_user_questions();
        if (client->birthday_check_frequency > 0 &&
            account->login_count % client->birthday_check_frequency == 0) {
            const auto question_states = client->accounts->signup_question_states();
            client->birthday_check_required = question_states[8] &&
                client->profile.birth_date.size() == 10;
        }
        if (client->messages != nullptr) {
            client->current_area = client->messages->initial_area(account->handle);
        }
        client->authenticated_at = std::chrono::steady_clock::now();
        if (client->session_time_limit_minutes > 0) {
            client->session_deadline = client->authenticated_at +
                std::chrono::minutes(client->session_time_limit_minutes);
        }
        client->authenticated_wall_clock = std::chrono::system_clock::now();
        client->last_activity_at = client->authenticated_at;
        return SSH_AUTH_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "Account verification failed: " << error.what() << '\n';
        client->close_requested = true;
        return SSH_AUTH_DENIED;
    }
}

int deny_passwordless_auth(ssh_session, const char*, void*) {
    return SSH_AUTH_DENIED;
}

ssh_channel open_session_channel(ssh_session session, void* userdata) {
    auto* client = static_cast<ClientContext*>(userdata);
    if (client == nullptr || !client->authenticated || client->channel != nullptr) {
        return nullptr;
    }

    client->channel = ssh_channel_new(session);
    if (client->channel == nullptr) {
        return nullptr;
    }

    client->channel_callbacks = {};
    client->channel_callbacks.userdata = client;
    client->channel_callbacks.channel_data_function = [](ssh_session, ssh_channel,
        void* data, std::uint32_t length, int is_stderr, void* channel_userdata) -> int {
        auto* state = static_cast<ClientContext*>(channel_userdata);
        if (state == nullptr || is_stderr != 0) {
            return static_cast<int>(length);
        }
        if (state->sftp_requested && state->sftp != nullptr) {
            try {
                const std::string response = state->sftp->consume(
                    std::string_view(static_cast<const char*>(data), length));
                if (!response.empty()) {
                    if (response.size() > kMaxPendingOutputBytes ||
                        state->sftp_output_bytes > kMaxPendingOutputBytes - response.size()) {
                        state->close_requested = true;
                    } else {
                        state->sftp_output.push_back(response);
                        state->sftp_output_bytes += response.size();
                    }
                }
            } catch (const std::exception& error) {
                std::cerr << "SFTP session ended: " << error.what() << '\n';
                state->close_requested = true;
            } catch (...) {
                state->close_requested = true;
            }
            state->last_activity_at = std::chrono::steady_clock::now();
            return static_cast<int>(length);
        }
        if (state->incoming.size() + length > 4096) {
            state->close_requested = true;
            return static_cast<int>(length);
        }
        state->incoming.append(static_cast<const char*>(data), length);
        state->last_activity_at = std::chrono::steady_clock::now();
        return static_cast<int>(length);
    };
    client->channel_callbacks.channel_eof_function = [](ssh_session, ssh_channel, void* channel_userdata) {
        static_cast<ClientContext*>(channel_userdata)->channel_closed = true;
    };
    client->channel_callbacks.channel_close_function = [](ssh_session, ssh_channel, void* channel_userdata) {
        static_cast<ClientContext*>(channel_userdata)->channel_closed = true;
    };
    client->channel_callbacks.channel_pty_request_function = [](
        ssh_session, ssh_channel, const char* term, int width, int height, int, int, void* channel_userdata) -> int {
        auto* state = static_cast<ClientContext*>(channel_userdata);
        if (state != nullptr) {
            if (term != nullptr) {
                state->terminal.assign(term, std::min<std::size_t>(std::strlen(term), 64));
            }
            state->columns = std::clamp(width, 40, 200);
            state->rows = std::clamp(height, 23, 80);
        }
        return 0;
    };
    client->channel_callbacks.channel_shell_request_function = [](ssh_session, ssh_channel, void* channel_userdata) -> int {
        auto* state = static_cast<ClientContext*>(channel_userdata);
        if (state == nullptr || !state->authenticated || state->sftp_requested) {
            return 1;
        }
        if (!state->registration_pending && state->node_number == 0 &&
            state->registry->join(*state, state->handle) == 0) {
            return 1;
        }
        if (!state->registration_pending && !state->caller_session_id.has_value() &&
            state->community != nullptr) {
            try {
                std::optional<int> remaining_seconds;
                if (state->session_deadline.has_value()) {
                    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                        *state->session_deadline - std::chrono::steady_clock::now()).count();
                    remaining_seconds = static_cast<int>(std::clamp<std::int64_t>(seconds, 0, 32767 * 60));
                }
                state->caller_session_id = state->community->record_caller_login(
                    state->handle, state->node_number, remaining_seconds);
            } catch (const std::exception& error) {
                std::cerr << "Could not record BBS caller login: " << error.what() << '\n';
            }
        }
        state->shell_requested = true;
        state->last_activity_at = std::chrono::steady_clock::now();
        return 0;
    };
    client->channel_callbacks.channel_pty_window_change_function = [](
        ssh_session, ssh_channel, int width, int height, int, int, void* channel_userdata) -> int {
        auto* state = static_cast<ClientContext*>(channel_userdata);
        if (state != nullptr) {
            state->columns = std::clamp(width, 40, 200);
            state->rows = std::clamp(height, 23, 80);
            state->resize_pending = true;
        }
        return 0;
    };
    client->channel_callbacks.channel_exec_request_function = [](ssh_session, ssh_channel, const char*, void*) -> int {
        return 1;
    };
    client->channel_callbacks.channel_env_request_function = [](ssh_session, ssh_channel, const char*, const char*, void*) -> int {
        return 1;
    };
    client->channel_callbacks.channel_subsystem_request_function = [](
        ssh_session, ssh_channel, const char* subsystem, void* channel_userdata) -> int {
        auto* state = static_cast<ClientContext*>(channel_userdata);
        if (state == nullptr || !state->authenticated || state->registration_pending ||
            state->shell_requested || state->sftp_requested || state->files == nullptr ||
            subsystem == nullptr || std::strcmp(subsystem, "sftp") != 0) {
            return 1;
        }
        try {
            CommunityStore* community = state->community;
            state->sftp = std::make_unique<SecureSftpSession>(
                *state->files, state->handle,
                [community](const FilePointReward& reward) {
                    if (community == nullptr) {
                        return;
                    }
                    std::string notice = "You received " + std::to_string(reward.points) +
                        (reward.points == 1 ? " file point" : " file points") +
                        " for the download of " + reward.filename;
                    if (notice.size() > 80) {
                        notice.resize(80);
                    }
                    try {
                        community->send_short_message(reward.owner_handle, notice, true);
                    } catch (const std::exception& error) {
                        std::cerr << "Could not queue file-point reward notice for "
                                  << reward.owner_handle << ": " << error.what() << '\n';
                    }
                });
            state->sftp_requested = true;
            state->last_activity_at = std::chrono::steady_clock::now();
            return 0;
        } catch (const std::exception& error) {
            std::cerr << "Could not start SFTP session: " << error.what() << '\n';
            return 1;
        }
    };
    ssh_callbacks_init(&client->channel_callbacks);
    if (ssh_set_channel_callbacks(client->channel, &client->channel_callbacks) != SSH_OK) {
        ssh_channel_free(client->channel);
        client->channel = nullptr;
        return nullptr;
    }
    return client->channel;
}

bool write_channel(ClientContext& client, std::string_view bytes) {
    if (client.channel == nullptr || !ssh_channel_is_open(client.channel)) {
        client.close_requested = true;
        return false;
    }
    if (bytes.empty()) {
        return true;
    }
    std::string filtered;
    filtered.reserve(bytes.size());
    for (std::size_t index = 0; index < bytes.size();) {
        if (!client.profile.clear_screen && bytes.substr(index).starts_with("\x1b[2J")) {
            index += 4;
            continue;
        }
        if (!client.profile.clear_screen && bytes[index] == '\x1b' &&
            index + 2 < bytes.size() && bytes[index + 1] == '[') {
            std::size_t end = index + 2;
            while (end < bytes.size() && bytes[end] >= 0x20 && bytes[end] <= 0x3f) {
                ++end;
            }
            if (end < bytes.size() && bytes[end] == 'H') {
                filtered.append(bytes.substr(index, end - index + 1));
                filtered += "\x1b[K";
                index = end + 1;
                continue;
            }
        }
        if (!client.profile.ansi_color && bytes[index] == '\x1b' &&
            index + 2 < bytes.size() && bytes[index + 1] == '[') {
            std::size_t end = index + 2;
            while (end < bytes.size() &&
                ((bytes[end] >= '0' && bytes[end] <= '9') || bytes[end] == ';' || bytes[end] == ':')) {
                ++end;
            }
            if (end < bytes.size() && bytes[end] == 'm') {
                index = end + 1;
                continue;
            }
        }
        if (!client.profile.pause_screens && bytes[index] == '\x01') {
            ++index;
            continue;
        }
        filtered.push_back(bytes[index++]);
    }
    bytes = filtered;
    if (bytes.empty()) {
        return true;
    }
    const auto enqueue = [&client](std::string_view chunk) {
        if (chunk.size() > kMaxPendingOutputBytes ||
            client.pending_output_bytes > kMaxPendingOutputBytes - chunk.size()) {
            client.close_requested = true;
            return false;
        }
        client.pending_output.emplace_back(chunk);
        client.pending_output_bytes += chunk.size();
        return true;
    };
    const auto append_paused = [&client](std::string_view chunk, bool pause_after) {
        if (chunk.size() > kMaxPendingOutputBytes ||
            client.pending_output_bytes > kMaxPendingOutputBytes - chunk.size()) {
            client.close_requested = true;
            return false;
        }
        client.paused_output.push_back({std::string(chunk), pause_after});
        client.pending_output_bytes += chunk.size();
        return true;
    };

    constexpr char kPauseMarker = '\x01';
    const std::size_t first_pause = bytes.find(kPauseMarker);
    if (first_pause == std::string_view::npos) {
        if (client.waiting_for_display_pause || !client.paused_output.empty()) {
            return append_paused(bytes, false);
        }
        return enqueue(bytes);
    }

    std::size_t start = 0;
    bool first_segment = true;
    while (start <= bytes.size()) {
        const std::size_t pause = bytes.find(kPauseMarker, start);
        const bool pause_after = pause != std::string_view::npos;
        const std::size_t end = pause_after ? pause : bytes.size();
        const std::string_view segment = bytes.substr(start, end - start);
        if (first_segment && !client.waiting_for_display_pause && client.paused_output.empty()) {
            if (!enqueue(segment)) {
                return false;
            }
            client.waiting_for_display_pause = pause_after;
        } else if (!append_paused(segment, pause_after)) {
            return false;
        }
        first_segment = false;
        if (!pause_after) {
            break;
        }
        start = pause + 1;
    }
    return true;
}

bool write_binary_channel(ClientContext& client, std::string_view bytes) {
    if (client.channel == nullptr || !ssh_channel_is_open(client.channel)) {
        client.close_requested = true;
        return false;
    }
    if (bytes.empty()) {
        return true;
    }
    if (bytes.size() > kMaxPendingOutputBytes ||
        client.pending_output_bytes > kMaxPendingOutputBytes - bytes.size()) {
        client.close_requested = true;
        return false;
    }
    client.pending_output.emplace_back(bytes);
    client.pending_output_bytes += bytes.size();
    return true;
}

void resume_display_after_pause(ClientContext& client, char character) {
    if (character == '\r') {
        client.ignore_line_feed = true;
    }
    client.waiting_for_display_pause = false;
    while (!client.paused_output.empty()) {
        ClientContext::PausedOutput segment = std::move(client.paused_output.front());
        client.paused_output.pop_front();
        if (!segment.bytes.empty()) {
            client.pending_output.push_back(std::move(segment.bytes));
        }
        if (segment.pause_after) {
            client.waiting_for_display_pause = true;
            break;
        }
    }
}

bool flush_channel_output(ClientContext& client) {
    std::size_t budget = kOutputBudgetPerPoll;
    while (!client.pending_output.empty() && budget > 0) {
        const std::string& current = client.pending_output.front();
        const std::size_t remaining = current.size() - client.pending_output_offset;
        const auto request_size = static_cast<std::uint32_t>(
            std::min({remaining, budget, static_cast<std::size_t>(16384)}));
        const int written = ssh_channel_write(
            client.channel, current.data() + client.pending_output_offset, request_size);
        if (written == SSH_AGAIN) {
            return true;
        }
        if (written <= 0) {
            return false;
        }
        const std::size_t sent = static_cast<std::size_t>(written);
        client.pending_output_offset += sent;
        client.pending_output_bytes -= sent;
        budget -= sent;
        if (client.pending_output_offset == current.size()) {
            client.pending_output.pop_front();
            client.pending_output_offset = 0;
        }
    }
    return true;
}

void flush_before_disconnect(ClientContext& client, ssh_event event, std::chrono::milliseconds budget) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!client.pending_output.empty() && std::chrono::steady_clock::now() < deadline) {
        if (!flush_channel_output(client)) {
            return;
        }
        if (!client.pending_output.empty() && ssh_event_dopoll(event, 20) == SSH_ERROR) {
            return;
        }
    }
}

void show_new_file_scan(ClientContext& client) {
    if (client.files == nullptr) {
        client.close_requested = true;
        return;
    }
    try {
        client.new_file_page = client.files->new_files_since(
            client.handle, client.new_file_since, client.new_file_page_index);
        client.new_file_page_index = client.new_file_page.page;
        if (client.new_file_page.files.empty()) {
            client.new_file_selection_index = 0;
        } else {
            client.new_file_selection_index = std::min(
                client.new_file_selection_index, client.new_file_page.files.size() - 1);
        }
        if (!write_channel(client, new_file_scan_screen(
                client.new_file_page, client.new_file_page.since_date,
                client.columns, client.rows,
                render_screen_art(client, supplemental_screen_art(
                    client, &SupplementalScreenArt::new_files)),
                client.new_file_selection_index))) {
            client.close_requested = true;
            return;
        }
        client.return_to_new_files = true;
        client.return_to_file_validation = false;
        client.viewing_file_validation = false;
        client.viewing_new_files = true;
        client.viewing_files = false;
        client.viewing_file_list = false;
        client.viewing_file_detail = false;
        client.viewing_download_queue = false;
        client.viewing_archive = false;
        client.viewing_archive_entry_detail = false;
        client.viewing_archive_text = false;
        client.viewing_archive_art = false;
        client.waiting_for_return = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not scan for new files for " << client.handle << ": " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read the new-file scan.\r\nPress any key to continue.");
        client.viewing_new_files = false;
        client.waiting_for_return = true;
    }
}

void show_file_validation_queue(ClientContext& client) {
    if (!client.is_sysop || client.files == nullptr) {
        (void)write_channel(client, "\a");
        return;
    }
    try {
        client.file_validation_page = client.files->unvalidated_files(
            client.handle, client.file_validation_page_index);
        client.file_validation_page_index = client.file_validation_page.page;
        if (client.file_validation_page.files.empty()) {
            client.file_validation_selection_index = 0;
        } else {
            client.file_validation_selection_index = std::min(
                client.file_validation_selection_index,
                client.file_validation_page.files.size() - 1);
        }
        if (!write_channel(client, file_validation_screen(
                client.file_validation_page, client.confirming_bulk_file_validation,
                client.columns, client.rows,
                render_screen_art(client, supplemental_screen_art(
                    client, &SupplementalScreenArt::file_validation)),
                client.file_validation_selection_index))) {
            client.close_requested = true;
            return;
        }
        client.return_to_file_validation = true;
        client.return_to_new_files = false;
        client.viewing_file_validation = true;
        client.viewing_files = false;
        client.viewing_new_files = false;
        client.viewing_file_list = false;
        client.viewing_file_detail = false;
        client.viewing_download_queue = false;
        client.viewing_archive = false;
        client.viewing_archive_entry_detail = false;
        client.viewing_archive_text = false;
        client.viewing_archive_art = false;
        client.waiting_for_return = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not list unvalidated files for " << client.handle << ": "
                  << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read the file validation queue.\r\nPress any key to continue.");
        client.viewing_file_validation = false;
        client.waiting_for_return = true;
    }
}

void show_file_listing(ClientContext& client) {
    if (client.files == nullptr || client.file_area_id < 1) {
        client.close_requested = true;
        return;
    }
    try {
        client.file_page = client.files->files(
            client.handle, client.file_area_id, client.file_search, client.file_list_page);
        client.file_list_page = client.file_page.page;
        if (client.file_page.files.empty()) {
            client.file_list_selection_index = 0;
        } else {
            client.file_list_selection_index = std::min(
                client.file_list_selection_index, client.file_page.files.size() - 1);
        }
        std::string screen = file_listing_screen(
            client.file_page, client.file_area_id, client.file_area_name,
            client.file_search, client.columns, client.rows,
            render_screen_art(client, client.file_areas_art), client.file_list_selection_index);
        if (client.searching_files) {
            screen += "\x1b[" + std::to_string(client.rows - 1) + ";3H\x1b[97mSearch> " +
                client.file_search_input + "\x1b[0m\x1b[?25h";
        }
        if (!write_channel(client, screen)) {
            client.close_requested = true;
            return;
        }
        client.viewing_files = true;
        client.viewing_file_validation = false;
        client.viewing_new_files = false;
        client.viewing_file_list = true;
        client.viewing_file_detail = false;
        client.viewing_extended_file_description = false;
        client.viewing_download_queue = false;
        client.confirming_download_queue_clear = false;
        client.viewing_archive = false;
        client.viewing_archive_entry_detail = false;
        client.viewing_archive_text = false;
        client.viewing_archive_art = false;
        client.selected_public_file.reset();
        client.selected_archive_entry.reset();
        client.archive_stack.clear();
        client.viewing_art = false;
        client.viewing_areas = false;
        client.viewing_messages = false;
        client.viewing_private_mail = false;
        client.viewing_sysop = false;
        client.viewing_sysop_account_detail = false;
        client.editing_sysop_security_levels = false;
        client.editing_sysop_acs_flags = false;
        client.editing_sysop_credits = false;
        client.editing_sysop_file_points = false;
        client.editing_sysop_short_message = false;
        client.editing_sysop_profile = false;
        client.editing_sysop_profile_field = '\0';
        client.sysop_password_new.clear();
        client.editing_sysop_birth_date = false;
        client.editing_sysop_sex = false;
        client.editing_sysop_expiration_date = false;
        client.editing_sysop_validation_level = false;
        client.confirming_sysop_validation = false;
        client.pending_sysop_validation.reset();
        client.viewing_sysop_audit = false;
        client.viewing_sysop_areas = false;
        client.viewing_profile = false;
        client.waiting_for_return = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not list file area " << client.file_area_id << ": " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read this file area.\r\nPress any key to continue.");
        client.viewing_files = false;
        client.waiting_for_return = true;
    }
}

void return_from_file_browser(ClientContext& client) {
    if (client.return_to_new_files) {
        show_new_file_scan(client);
    } else if (client.return_to_file_validation) {
        show_file_validation_queue(client);
    } else {
        show_file_listing(client);
    }
}

void show_public_file_detail(ClientContext& client) {
    if (!client.selected_public_file.has_value()) {
        return_from_file_browser(client);
        return;
    }
    bool tagged = false;
    if (client.files != nullptr) {
        try {
            const auto queue = client.files->download_queue(client.handle);
            for (const DownloadQueueEntry& queued : queue) {
                if (queued.area_id == client.file_area_id &&
                    ::strcasecmp(queued.filename.c_str(), client.selected_public_file->name.c_str()) == 0) {
                    tagged = true;
                    break;
                }
            }
        } catch (const std::exception& error) {
            std::cerr << "Could not read download queue for " << client.handle << ": " << error.what() << '\n';
        }
    }
    std::string screen = file_detail_screen(
        *client.selected_public_file, client.file_area_name, tagged, client.is_sysop,
        client.confirming_public_file_delete, client.confirming_public_file_credit_withdrawal,
        client.columns, client.rows, render_screen_art(client, client.file_areas_art));
    if (client.entering_file_move_area || client.entering_file_rename ||
        client.entering_file_download_count || client.entering_file_points ||
        client.entering_file_point_validation || client.entering_file_owner_point_adjustment ||
        client.entering_file_owner || client.entering_file_date) {
        std::string prompt;
        std::string input;
        if (client.entering_file_owner_point_adjustment) {
            prompt = "Owner balance adjustment (-balance to +999; Enter skips): ";
            input = client.owner_point_adjustment_input;
        } else if (client.entering_file_point_validation) {
            prompt = "File point cost (0-999; 0 uses auto): ";
            input = client.validation_file_points_input;
        } else if (client.entering_file_move_area) {
            prompt = "Move to area ID (Esc cancels): ";
            input = client.file_move_area_input;
        } else if (client.entering_file_rename) {
            prompt = "New file name (Esc cancels): ";
            input = client.file_rename_input;
        } else if (client.entering_file_download_count) {
            prompt = "Completed downloads (Esc cancels): ";
            input = client.file_download_count_input;
        } else if (client.entering_file_points) {
            prompt = "File points (Esc cancels): ";
            input = client.file_points_input;
        } else if (client.entering_file_owner) {
            prompt = "New owner handle (Esc cancels): ";
            input = client.file_owner_input;
        } else {
            prompt = "Upload date MM-DD-YYYY (Esc cancels): ";
            input = client.file_date_input;
        }
        const int row = std::max(1, client.rows - 2);
        const int column = std::min(client.columns,
            4 + static_cast<int>(prompt.size() + input.size()));
        screen += "\x1b[" + std::to_string(row) + ";4H\x1b[2K" + prompt +
            input + "\x1b[" + std::to_string(row) + ";" +
            std::to_string(column) + "H\x1b[?25h";
    }
    if (!write_channel(client, screen)) {
        client.close_requested = true;
        return;
    }
    client.viewing_files = false;
    client.viewing_file_validation = false;
    client.viewing_new_files = false;
    client.viewing_file_list = false;
    client.viewing_file_detail = true;
    client.viewing_extended_file_description = false;
    client.editing_file_description = false;
    client.editing_file_extended_description = false;
    client.viewing_download_queue = false;
    client.viewing_archive = false;
    client.viewing_archive_entry_detail = false;
    client.viewing_archive_text = false;
    client.viewing_archive_art = false;
    client.waiting_for_return = false;
}

void show_extended_file_description(ClientContext& client) {
    if (!client.selected_public_file.has_value() ||
        client.selected_public_file->extended_description.empty()) {
        show_public_file_detail(client);
        return;
    }
    const std::size_t line_count = static_cast<std::size_t>(
        std::count(client.selected_public_file->extended_description.begin(),
            client.selected_public_file->extended_description.end(), '\n')) + 1;
    const bool use_art = !client.file_areas_art.empty() && client.columns >= 80 && client.rows >= 24;
    const std::size_t page_size = static_cast<std::size_t>(
        std::max(1, client.rows - (use_art ? 13 : 11)));
    const std::size_t page_count = std::max<std::size_t>(1,
        (line_count + page_size - 1) / page_size);
    client.extended_file_description_page = std::min(
        client.extended_file_description_page, page_count - 1);
    if (!write_channel(client, extended_file_description_screen(
            *client.selected_public_file, client.file_area_name,
            client.extended_file_description_page, client.is_sysop,
            client.columns, client.rows,
            render_screen_art(client, client.file_areas_art)))) {
        client.close_requested = true;
        return;
    }
    client.viewing_files = false;
    client.viewing_new_files = false;
    client.viewing_file_detail = false;
    client.viewing_extended_file_description = true;
    client.viewing_download_queue = false;
    client.viewing_archive = false;
    client.viewing_archive_entry_detail = false;
    client.viewing_archive_text = false;
    client.viewing_archive_art = false;
    client.waiting_for_return = false;
}

void redraw_file_description_editor(ClientContext& client) {
    if (client.files == nullptr || !client.selected_public_file.has_value() || !client.is_sysop) {
        client.editing_file_description = false;
        client.editing_file_extended_description = false;
        return_from_file_browser(client);
        return;
    }
    const std::string screen = client.editing_file_description
        ? file_description_edit_screen(*client.selected_public_file,
            client.file_description_input, client.columns, client.rows,
            render_screen_art(client, client.file_areas_art))
        : extended_file_description_edit_screen(*client.selected_public_file,
            client.file_extended_description_draft, client.file_extended_description_input,
            client.columns, client.rows,
            render_screen_art(client, client.file_areas_art));
    if (!write_channel(client, screen)) {
        client.close_requested = true;
    }
}

void show_download_queue(ClientContext& client) {
    if (client.files == nullptr) {
        client.close_requested = true;
        return;
    }
    try {
        client.download_queue = client.files->download_queue(client.handle);
        const std::size_t page_count = std::max<std::size_t>(
            1, (client.download_queue.size() + 9) / 10);
        client.download_queue_page = std::min(client.download_queue_page, page_count - 1);
        if (client.download_queue.empty()) {
            client.download_queue_selection_index = 0;
        } else {
            client.download_queue_selection_index = std::min(
                client.download_queue_selection_index, client.download_queue.size() - 1);
            client.download_queue_page = client.download_queue_selection_index / 10;
        }
        if (!write_channel(client, download_queue_screen(
                client.download_queue, client.download_queue_page,
                client.confirming_download_queue_clear, client.columns, client.rows,
                render_screen_art(client, supplemental_screen_art(
                    client, &SupplementalScreenArt::download_queue)),
                client.download_queue_selection_index))) {
            client.close_requested = true;
            return;
        }
        client.viewing_files = false;
        client.viewing_new_files = false;
        client.viewing_file_list = false;
        client.viewing_file_detail = false;
        client.viewing_extended_file_description = false;
        client.viewing_download_queue = true;
        client.viewing_archive = false;
        client.viewing_archive_entry_detail = false;
        client.viewing_archive_text = false;
        client.viewing_archive_art = false;
        client.waiting_for_return = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not read download queue for " << client.handle << ": " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read the download queue.\r\nPress any key to continue.");
        client.viewing_download_queue = false;
        client.waiting_for_return = true;
    }
}

void show_archive_listing(ClientContext& client) {
    if (client.archive_stack.empty()) {
        return_from_file_browser(client);
        return;
    }
    ArchiveFrame& frame = client.archive_stack.back();
    const ArchiveListing visible = visible_archive_listing(frame);
    frame.visible_entries = visible.entries;
    const std::size_t page_count = std::max<std::size_t>(1, (visible.entries.size() + 9) / 10);
    frame.page = std::min(frame.page, page_count - 1);
    if (visible.entries.empty()) {
        frame.selection_index = 0;
    } else {
        frame.selection_index = std::min(frame.selection_index, visible.entries.size() - 1);
        frame.page = frame.selection_index / 10;
    }
    if (!write_channel(client, archive_listing_screen(
            visible, frame.prefix.empty() ? frame.name : frame.name + ":/" + frame.prefix,
            frame.page, client.columns, client.rows,
            render_screen_art(client, supplemental_screen_art(
                client, &SupplementalScreenArt::archive)), frame.selection_index))) {
        client.close_requested = true;
        return;
    }
    client.viewing_files = false;
    client.viewing_new_files = false;
    client.viewing_file_list = false;
    client.viewing_file_detail = false;
    client.viewing_archive = true;
    client.viewing_archive_entry_detail = false;
    client.viewing_archive_text = false;
    client.viewing_archive_art = false;
    client.waiting_for_return = false;
}

void show_archive_entry_detail(ClientContext& client) {
    if (client.archive_stack.empty() || !client.selected_archive_entry.has_value()) {
        show_archive_listing(client);
        return;
    }
    if (!write_channel(client, archive_entry_detail_screen(
            *client.selected_archive_entry, client.archive_stack.back().name,
            client.columns, client.rows,
            render_screen_art(client, client.file_areas_art)))) {
        client.close_requested = true;
        return;
    }
    client.viewing_archive = false;
    client.viewing_new_files = false;
    client.viewing_archive_entry_detail = true;
    client.viewing_archive_text = false;
    client.viewing_archive_art = false;
    client.waiting_for_return = false;
}

void show_archive_text(ClientContext& client) {
    if (!write_channel(client, archive_text_screen(
            client.archive_text_name, client.archive_text_lines, client.archive_text_page,
            client.columns, client.rows,
            render_screen_art(client, client.file_areas_art)))) {
        client.close_requested = true;
        return;
    }
    client.viewing_archive = false;
    client.viewing_new_files = false;
    client.viewing_archive_entry_detail = false;
    client.viewing_archive_text = true;
    client.viewing_archive_art = false;
    client.waiting_for_return = false;
}

void show_archive_art(ClientContext& client) {
    const AnsiArtwork artwork{client.archive_art_name, client.archive_art_contents};
    if (!write_channel(client, artwork_screen(artwork, 1, 1, client.columns, client.rows))) {
        client.close_requested = true;
        return;
    }
    client.viewing_archive = false;
    client.viewing_new_files = false;
    client.viewing_archive_entry_detail = false;
    client.viewing_archive_text = false;
    client.viewing_archive_art = true;
    client.waiting_for_return = false;
}

std::vector<std::uint8_t> read_public_archive(ClientContext& client, std::string_view filename) {
    if (client.files == nullptr) {
        throw std::runtime_error("file-area storage is unavailable");
    }
    ScopedFileDescriptor file(client.files->open_public_file(client.handle, client.file_area_id, filename));
    struct stat status{};
    if (::fstat(file.get(), &status) != 0) {
        throw std::runtime_error("could not inspect the public file");
    }
    if (status.st_size <= 0 || static_cast<std::uint64_t>(status.st_size) > ArchiveStore::max_archive_bytes) {
        throw std::runtime_error("archive is empty or exceeds the 100 MiB browsing limit");
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(status.st_size));
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t amount = ::pread(file.get(), bytes.data() + offset, bytes.size() - offset,
            static_cast<off_t>(offset));
        if (amount < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error("could not read the public archive");
        }
        if (amount == 0) {
            throw std::runtime_error("public archive changed while being read");
        }
        offset += static_cast<std::size_t>(amount);
    }
    return bytes;
}

bool has_extension(std::string_view filename, std::initializer_list<std::string_view> extensions) {
    const std::size_t dot = filename.find_last_of('.');
    if (dot == std::string_view::npos) {
        return false;
    }
    std::string extension(filename.substr(dot));
    std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    return std::find(extensions.begin(), extensions.end(), extension) != extensions.end();
}

std::vector<std::string> split_archive_text(std::string_view text) {
    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start <= text.size() && lines.size() < 20000) {
        const std::size_t newline = text.find_first_of("\r\n", start);
        const std::size_t end = newline == std::string_view::npos ? text.size() : newline;
        lines.emplace_back(text.substr(start, end - start));
        if (newline == std::string_view::npos) {
            break;
        }
        start = newline + 1;
        if (text[newline] == '\r' && start < text.size() && text[start] == '\n') {
            ++start;
        }
    }
    if (start < text.size()) {
        lines.emplace_back("[content clipped after 20,000 lines]");
    }
    return lines;
}

void open_selected_public_file(ClientContext& client, const FileEntry& file) {
    client.selected_public_file = file;
    client.confirming_public_file_delete = false;
    client.confirming_public_file_credit_withdrawal = false;
    client.entering_file_point_validation = false;
    client.entering_file_owner_point_adjustment = false;
    client.validation_file_points = 0;
    client.validation_file_points_input.clear();
    client.owner_point_adjustment_input.clear();
    if (!ArchiveStore::supports_filename(file.name)) {
        show_public_file_detail(client);
        return;
    }
    try {
        std::vector<std::uint8_t> contents = read_public_archive(client, file.name);
        ArchiveListing listing = ArchiveStore::list(contents);
        client.archive_stack.clear();
        client.archive_stack.push_back({file.name, std::move(contents), std::move(listing), {}, {}, 0});
        show_archive_listing(client);
    } catch (const std::exception& error) {
        std::cerr << "Could not open archive " << file.name << ": " << error.what() << '\n';
        (void)write_channel(client, "\a");
        return_from_file_browser(client);
    }
}

void open_archive_entry(ClientContext& client, std::size_t row) {
    if (client.archive_stack.empty()) {
        return_from_file_browser(client);
        return;
    }
    ArchiveFrame& frame = client.archive_stack.back();
    const std::size_t index = frame.page * 10 + row;
    if (index >= frame.visible_entries.size()) {
        (void)write_channel(client, "\a");
        return;
    }
    const ArchiveEntry entry = frame.visible_entries[index];
    client.selected_archive_entry = entry;
    if (entry.directory) {
        if (entry.parent_directory) {
            if (!frame.prefix.empty()) {
                const std::size_t without_trailing = frame.prefix.size() - 1;
                const std::size_t slash = frame.prefix.rfind('/', without_trailing == 0
                    ? 0
                    : without_trailing - 1);
                frame.prefix = slash == std::string::npos ? std::string{} : frame.prefix.substr(0, slash + 1);
            }
        } else {
            frame.prefix = entry.name;
            if (frame.prefix.empty() || frame.prefix.back() != '/') {
                frame.prefix.push_back('/');
            }
        }
        frame.page = 0;
        show_archive_listing(client);
        return;
    }
    if (entry.encrypted) {
        show_archive_entry_detail(client);
        return;
    }
    const std::string entry_name = entry.name;
    try {
        if (ArchiveStore::supports_filename(entry_name)) {
            if (client.archive_stack.size() >= 4) {
                throw std::runtime_error("nested archive depth is limited to four levels");
            }
            std::vector<std::uint8_t> contents = ArchiveStore::read_entry(
                frame.contents, entry.index, ArchiveStore::max_nested_archive_bytes);
            ArchiveListing listing = ArchiveStore::list(contents);
            client.archive_stack.push_back({entry_name, std::move(contents), std::move(listing), {}, {}, 0});
            show_archive_listing(client);
        } else if (has_extension(entry_name, {".ans", ".ansi", ".asc", ".nfo"})) {
            const std::vector<std::uint8_t> bytes = ArchiveStore::read_entry(
                frame.contents, entry.index, ArchiveStore::max_view_bytes);
            const std::string raw(bytes.begin(), bytes.end());
            client.archive_art_name = entry_name;
            client.archive_art_contents = sanitize_terminal_art(raw);
            show_archive_art(client);
        } else if (has_extension(entry_name, {".txt", ".diz", ".doc", ".readme", ".me"})) {
            const std::vector<std::uint8_t> bytes = ArchiveStore::read_entry(
                frame.contents, entry.index, ArchiveStore::max_view_bytes);
            const std::string raw(bytes.begin(), bytes.end());
            client.archive_text_name = entry_name;
            client.archive_text_lines = split_archive_text(sanitize_terminal_text(raw));
            client.archive_text_page = 0;
            show_archive_text(client);
        } else {
            show_archive_entry_detail(client);
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not view archive entry " << entry_name << ": " << error.what() << '\n';
        (void)write_channel(client, "\a");
        show_archive_listing(client);
    }
}

void show_file_areas(ClientContext& client) {
    if (client.files == nullptr) {
        client.close_requested = true;
        return;
    }
    try {
        client.file_areas = client.files->areas(client.handle);
        const std::size_t page_count = std::max<std::size_t>(1, (client.file_areas.size() + 9) / 10);
        client.file_area_page = std::min(client.file_area_page, page_count - 1);
        if (client.file_areas.empty()) {
            client.file_area_selection_index = 0;
        } else {
            client.file_area_selection_index = std::min(
                client.file_area_selection_index, client.file_areas.size() - 1);
            if (client.file_area_selection_index / 10 != client.file_area_page) {
                client.file_area_selection_index = client.file_area_page * 10;
            }
        }
        const std::string screen = file_areas_screen(
            client.file_areas, client.file_area_page, client.choosing_file_scan_area,
            client.is_sysop, client.columns, client.rows,
            render_screen_art(client, client.file_areas_art), client.file_area_selection_index);
        if (!write_channel(client, screen)) {
            client.close_requested = true;
            return;
        }
        client.viewing_files = true;
        client.viewing_file_validation = false;
        client.viewing_new_files = false;
        client.viewing_file_list = false;
        client.viewing_file_detail = false;
        client.viewing_extended_file_description = false;
        client.viewing_download_queue = false;
        client.confirming_download_queue_clear = false;
        client.searching_files = false;
        client.viewing_art = false;
        client.viewing_areas = false;
        client.viewing_messages = false;
        client.viewing_private_mail = false;
        client.viewing_sysop = false;
        client.viewing_profile = false;
        client.waiting_for_return = false;
        client.return_to_new_files = false;
        client.return_to_file_validation = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not read file-area catalog: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read the file-area catalog.\r\nPress any key to continue.");
        client.viewing_files = false;
        client.waiting_for_return = true;
    }
}

void show_sysop_area_admin(ClientContext& client) {
    if (!client.is_sysop || client.messages == nullptr || client.files == nullptr) {
        (void)write_channel(client, "\a");
        return;
    }
    try {
        client.board_areas = client.messages->areas(client.handle, true);
        client.file_areas = client.files->areas();
        const bool entering_name = client.area_admin_kind.has_value() || client.area_admin_renaming_file ||
            client.area_admin_renaming_message ||
            client.area_admin_deleting_file || client.area_admin_deleting_message ||
            client.editing_file_area_access || client.editing_message_area_access ||
            client.editing_message_force_read || client.editing_message_area_password ||
            client.editing_message_taglines || client.editing_message_filter ||
            client.editing_message_unhidden || client.editing_message_tearline ||
            client.editing_message_origin ||
            client.editing_message_real_names ||
            client.editing_message_quote_templates || client.editing_private_quote_templates ||
            client.editing_global_anonymous_acs || client.editing_global_post_acs ||
            client.editing_global_post_limits || client.editing_global_credit_costs ||
            client.editing_global_mail_limits ||
            client.admin_policy_edit != ClientContext::AdminPolicyEdit::None;
        const bool is_file_area = client.area_admin_renaming_file || client.area_admin_deleting_file ||
            client.area_admin_confirming_file_deletion ||
            client.editing_file_area_access ||
            client.area_admin_kind == ClientContext::AreaAdminKind::File;
        const std::string displayed_input = client.editing_message_area_password
            ? std::string(client.area_admin_input.size(), '*')
            : client.area_admin_input;
        std::string_view file_policy_prompt;
        switch (client.admin_policy_edit) {
        case ClientContext::AdminPolicyEdit::Ratios:
            file_policy_prompt = "File ratios (on|off;DLRatio;DLKRatio;NoDLRatio ACS) > ";
            break;
        case ClientContext::AdminPolicyEdit::LevelRatios:
            file_policy_prompt = "SL ratios (SL_MIN;SL_MAX;DLRatio;DLKRatio) > ";
            break;
        case ClientContext::AdminPolicyEdit::DailyLimits:
            file_policy_prompt = "Daily caps (on|off;SL_MIN;SL_MAX;FILES;KIB) > ";
            break;
        case ClientContext::AdminPolicyEdit::Points:
            file_policy_prompt = "File points (on|off;BASE_KIB;UPLOAD_COMP;REWARD;NOFILECREDITS ACS) > ";
            break;
        case ClientContext::AdminPolicyEdit::UploadValidation:
            file_policy_prompt = "Upload validation (AUTO_VALIDATE ACS;ValidateAll on|off) > ";
            break;
        case ClientContext::AdminPolicyEdit::UnvalidatedAccess:
            file_policy_prompt = "Unvalidated access (SEEUNVAL ACS;DLUNVAL ACS) > ";
            break;
        case ClientContext::AdminPolicyEdit::AreaNoRatio:
            file_policy_prompt = "File area ratio exemption (AREA_ID;on|off) > ";
            break;
        case ClientContext::AdminPolicyEdit::PostRatio:
            file_policy_prompt = "Post-call ratio (SL_MIN;SL_MAX;PERCENT 0-100) > ";
            break;
        case ClientContext::AdminPolicyEdit::SubmissionAcs:
            file_policy_prompt = "Submission ACS (ADDQUOTE;ADDONELINER, - means open) > ";
            break;
        case ClientContext::AdminPolicyEdit::InvisibleAcs:
            file_policy_prompt = "Invisible-mode ACS (- means open) > ";
            break;
        case ClientContext::AdminPolicyEdit::ValidationEligibility:
            file_policy_prompt = "Validation key (on|off;NewSL 0-255) > ";
            break;
        case ClientContext::AdminPolicyEdit::None:
            break;
        }
        if (!write_channel(client, sysop_area_admin_screen(
            client.board_areas, client.file_areas, entering_name, is_file_area,
                client.area_admin_renaming_file, client.area_admin_renaming_message,
                client.area_admin_deleting_file,
                client.editing_file_area_access,
                client.editing_message_area_access,
                client.editing_message_force_read,
                client.editing_message_area_password,
                client.editing_message_taglines,
                client.editing_message_filter,
                client.editing_message_unhidden,
                client.editing_message_tearline,
                client.editing_message_origin,
                client.editing_message_real_names,
                client.editing_message_quote_templates,
                client.editing_private_quote_templates,
                client.editing_global_anonymous_acs,
                client.editing_global_post_acs,
                client.editing_global_post_limits,
                client.editing_global_credit_costs,
                client.editing_global_mail_limits,
                file_policy_prompt,
                client.area_admin_confirming_file_deletion, client.area_admin_deleting_message,
                client.area_admin_confirming_message_deletion,
                client.area_admin_delete_id, client.area_admin_delete_name,
                displayed_input, client.area_admin_notice,
                client.columns, client.rows,
                render_screen_art(client,
                    sysop_screen_art(client, &SupplementalScreenArt::sysop_areas)),
                client.area_admin_action_selection_index))) {
            client.close_requested = true;
            return;
        }
        client.viewing_sysop_areas = true;
        client.viewing_sysop = false;
        client.viewing_files = false;
        client.viewing_areas = false;
        client.viewing_messages = false;
        client.viewing_private_mail = false;
        client.viewing_profile = false;
        client.waiting_for_return = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not read SysOp area configuration: " << error.what() << '\n';
        client.area_admin_notice = "Could not load area lists.";
        (void)write_channel(client, "\r\nCould not load area configuration.\r\nPress any key to return.");
        client.viewing_sysop_areas = false;
        client.waiting_for_return = true;
    }
}

void select_file_area(ClientContext& client, std::size_t index) {
    if (index >= client.file_areas.size()) {
        (void)write_channel(client, "\a");
        return;
    }
    client.file_area_id = client.file_areas[index].id;
    client.file_area_name = client.file_areas[index].name;
    client.return_to_new_files = false;
    client.choosing_file_scan_area = false;
    client.file_list_page = 0;
    client.file_list_selection_index = 0;
    client.file_search.clear();
    client.searching_files = false;
    show_file_listing(client);
}

void show_upload_review(ClientContext& client) {
    if (!client.is_sysop || client.files == nullptr) {
        (void)write_channel(client, "\a");
        return;
    }
    try {
        client.incoming_files = client.files->incoming_files();
        const std::size_t page_count = std::max<std::size_t>(
            1, (client.incoming_files.size() + 9) / 10);
        client.incoming_files_page = std::min(client.incoming_files_page, page_count - 1);
        if (client.incoming_files.empty()) {
            client.incoming_file_selection_index = 0;
        } else {
            client.incoming_file_selection_index = std::min(
                client.incoming_file_selection_index, client.incoming_files.size() - 1);
            client.incoming_files_page = client.incoming_file_selection_index / 10;
        }
        if (!write_channel(client, upload_review_screen(
                client.incoming_files, client.incoming_files_page, client.columns, client.rows,
                render_screen_art(client, supplemental_screen_art(
                    client, &SupplementalScreenArt::uploads)),
                client.incoming_file_selection_index))) {
            client.close_requested = true;
            return;
        }
        client.viewing_uploads = true;
        client.viewing_upload_detail = false;
        client.selecting_upload_area = false;
        client.selected_upload.reset();
        client.confirming_upload_delete = false;
        client.viewing_files = false;
        client.viewing_art = false;
        client.viewing_areas = false;
        client.viewing_messages = false;
        client.viewing_private_mail = false;
        client.viewing_sysop = false;
        client.viewing_profile = false;
        client.waiting_for_return = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not read incoming uploads: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read incoming uploads.\r\nPress any key to continue.");
        client.viewing_uploads = false;
        client.waiting_for_return = true;
    }
}

void show_upload_detail(ClientContext& client) {
    if (!client.is_sysop || !client.selected_upload.has_value()) {
        client.viewing_upload_detail = false;
        return;
    }
    if (!write_channel(client, upload_detail_screen(
            *client.selected_upload, client.confirming_upload_delete,
            client.columns, client.rows,
            render_screen_art(client, supplemental_screen_art(
                client, &SupplementalScreenArt::uploads))))) {
        client.close_requested = true;
        return;
    }
    client.viewing_uploads = true;
    client.viewing_upload_detail = true;
    client.selecting_upload_area = false;
}

void show_upload_publish_areas(ClientContext& client) {
    if (!client.is_sysop || client.files == nullptr || !client.selected_upload.has_value()) {
        client.viewing_upload_detail = true;
        return;
    }
    try {
        client.upload_publish_areas = client.files->areas();
        const std::size_t page_count = std::max<std::size_t>(
            1, (client.upload_publish_areas.size() + 9) / 10);
        client.upload_publish_area_page = std::min(client.upload_publish_area_page, page_count - 1);
        if (client.upload_publish_areas.empty()) {
            client.upload_publish_area_selection_index = 0;
        } else {
            client.upload_publish_area_selection_index = std::min(
                client.upload_publish_area_selection_index, client.upload_publish_areas.size() - 1);
            client.upload_publish_area_page = client.upload_publish_area_selection_index / 10;
        }
        if (!write_channel(client, upload_publish_area_screen(
                *client.selected_upload, client.upload_publish_areas,
                client.upload_publish_area_page, client.columns, client.rows,
                render_screen_art(client, supplemental_screen_art(
                    client, &SupplementalScreenArt::uploads)),
                client.upload_publish_area_selection_index))) {
            client.close_requested = true;
            return;
        }
        client.viewing_uploads = true;
        client.viewing_upload_detail = false;
        client.selecting_upload_area = true;
        client.confirming_upload_delete = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not load file areas for upload review: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read public file areas.\r\nPress any key to continue.");
        client.viewing_uploads = false;
        client.waiting_for_return = true;
    }
}

void publish_selected_upload(ClientContext& client, int area_id) {
    if (!client.selected_upload.has_value() || client.files == nullptr) {
        show_upload_review(client);
        return;
    }
    const IncomingFile upload = *client.selected_upload;
    try {
        client.files->publish_upload(upload.handle, upload.name, area_id);
        record_sysop_action(client, "published upload",
            upload.handle + "/" + upload.name + " -> area " + std::to_string(area_id));
        std::clog << "SysOp " << client.handle << " published upload " << upload.handle << '/'
                  << upload.name << " into file area " << area_id << ".\n";
        client.selected_upload.reset();
        client.incoming_files_page = 0;
        show_upload_review(client);
    } catch (const std::exception& error) {
        std::cerr << "Could not publish incoming upload: " << error.what() << '\n';
        show_upload_detail(client);
        (void)write_channel(client, "\r\nCould not publish it: the upload may still be active or that name may already exist.\r\n");
    }
}

void delete_selected_upload(ClientContext& client) {
    if (!client.selected_upload.has_value() || client.files == nullptr) {
        show_upload_review(client);
        return;
    }
    const IncomingFile upload = *client.selected_upload;
    try {
        client.files->delete_upload(upload.handle, upload.name);
        record_sysop_action(client, "deleted incoming upload", upload.handle + "/" + upload.name);
        std::clog << "SysOp " << client.handle << " deleted upload " << upload.handle << '/'
                  << upload.name << ".\n";
        client.selected_upload.reset();
        show_upload_review(client);
    } catch (const std::exception& error) {
        std::cerr << "Could not delete incoming upload: " << error.what() << '\n';
        show_upload_detail(client);
        (void)write_channel(client, "\r\nCould not delete it while the upload is active.\r\n");
    }
}

void show_one_liners(ClientContext& client) {
    if (client.community == nullptr) {
        client.close_requested = true;
        return;
    }
    try {
        const bool may_read_anonymous = client.messages != nullptr &&
            client.messages->can_read_public_anonymously(client.handle);
        client.one_liner_page = client.community->one_liners(client.one_liner_page.page);
        if (client.selected_one_liner_id.has_value() &&
            std::none_of(client.one_liner_page.entries.begin(), client.one_liner_page.entries.end(),
                [&](const OneLiner& entry) { return entry.id == *client.selected_one_liner_id; })) {
            client.selected_one_liner_id.reset();
        }
        if (client.selected_one_liner_id.has_value()) {
            const auto selected = std::find_if(client.one_liner_page.entries.begin(),
                client.one_liner_page.entries.end(), [&](const OneLiner& entry) {
                    return entry.id == *client.selected_one_liner_id;
                });
            client.one_liner_selection_index = static_cast<std::size_t>(
                std::distance(client.one_liner_page.entries.begin(), selected));
        } else if (client.one_liner_page.entries.empty()) {
            client.one_liner_selection_index = 0;
        } else {
            client.one_liner_selection_index = std::min(
                client.one_liner_selection_index, client.one_liner_page.entries.size() - 1);
            if (client.is_sysop && !client.selected_one_liner_id.has_value()) {
                client.selected_one_liner_id = client.one_liner_page.entries[
                    client.one_liner_selection_index].id;
            }
        }
        std::string screen = one_liners_screen(
            client.one_liner_page, client.is_sysop, may_read_anonymous,
            client.selected_one_liner_id, client.columns, client.rows,
            render_screen_art(client, supplemental_screen_art(
                client, &SupplementalScreenArt::one_liners)));
        if (client.adding_one_liner || client.editing_one_liner) {
            const std::string label = client.editing_one_liner ? "Edit: " : "> ";
            screen += "\x1b[" + std::to_string(client.rows - 1) + ";3H\x1b[97m" + label +
                client.one_liner_input + "\x1b[?25h";
        } else if (client.confirming_one_liner_delete) {
            screen += "\x1b[" + std::to_string(client.rows - 1) + ";3H\x1b[97mDelete selected one-liner? Y/N "
                "\x1b[?25h";
        } else if (client.prompting_one_liner_anonymous) {
            screen += "\x1b[" + std::to_string(client.rows - 1) + ";3H\x1b[97mPost anonymously? Y/N "
                "\x1b[?25h";
        } else if (client.confirming_one_liner_post) {
            screen += "\x1b[" + std::to_string(client.rows - 3) + ";3H\x1b[97mPreview: " +
                client.pending_one_liner_text + "\x1b[0m";
            screen += "\x1b[" + std::to_string(client.rows - 1) + ";3H\x1b[97mPost this one-liner? Y/N "
                "\x1b[?25h";
        }
        if (!write_channel(client, screen)) {
            client.close_requested = true;
            return;
        }
        client.viewing_one_liners = true;
        client.viewing_uploads = false;
        client.viewing_files = false;
        client.viewing_art = false;
        client.viewing_areas = false;
        client.viewing_messages = false;
        client.viewing_private_mail = false;
        client.viewing_sysop = false;
        client.viewing_profile = false;
        client.waiting_for_return = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not load one-liners: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read the one-liner list.\r\nPress any key to continue.");
        client.viewing_one_liners = false;
        client.waiting_for_return = true;
    }
}

void show_polls(ClientContext& client) {
    if (client.community == nullptr) {
        client.close_requested = true;
        return;
    }
    try {
        client.poll_list = client.community->polls(client.handle);
        std::string screen;
        if (client.reading_poll && client.selected_poll_id.has_value()) {
            client.active_poll = client.community->poll(*client.selected_poll_id, client.handle);
            const std::size_t page_count = std::max<std::size_t>(
                1, (client.active_poll.options.size() + 9) / 10);
            client.poll_choice_page = std::min(client.poll_choice_page, page_count - 1);
            if (client.active_poll.options.empty()) {
                client.poll_choice_selection_index = 0;
            } else {
                client.poll_choice_selection_index = std::min(
                    client.poll_choice_selection_index, client.active_poll.options.size() - 1);
                if (client.poll_choice_selection_index / 10 != client.poll_choice_page) {
                    client.poll_choice_selection_index = client.poll_choice_page * 10;
                }
            }
            screen = poll_detail_screen(client.active_poll, client.poll_choice_page,
                client.showing_poll_results, client.is_sysop, client.changing_poll_vote,
                client.columns, client.rows, render_screen_art(client, supplemental_screen_art(
                    client, &SupplementalScreenArt::polls)),
                client.poll_choice_selection_index);
        } else {
            client.reading_poll = false;
            client.selected_poll_id.reset();
            const std::size_t page_count = std::max<std::size_t>(
                1, (client.poll_list.size() + 9) / 10);
            client.poll_page = std::min(client.poll_page, page_count - 1);
            if (client.poll_list.empty()) {
                client.poll_selection_index = 0;
            } else {
                client.poll_selection_index = std::min(
                    client.poll_selection_index, client.poll_list.size() - 1);
                if (client.poll_selection_index / 10 != client.poll_page) {
                    client.poll_selection_index = client.poll_page * 10;
                }
            }
            screen = polls_screen(client.poll_list, client.poll_page,
                client.columns, client.rows, client.is_sysop,
                render_screen_art(client, supplemental_screen_art(
                    client, &SupplementalScreenArt::polls)), client.poll_selection_index);
        }
        if (client.creating_poll) {
            std::string prompt;
            if (!client.poll_question_entered) {
                prompt = "Topic: ";
            } else if (!client.poll_subtitle_entered) {
                prompt = "Second topic line (Enter to skip): ";
            } else if (!client.poll_choice_policy_entered) {
                prompt = "Allow callers to add choices? Y/N: ";
            } else if (!client.poll_vote_policy_entered) {
                prompt = "Allow callers to change votes? Y/N: ";
            } else {
                prompt = "Choice " + std::to_string(client.poll_options.size() + 1) +
                    " (blank saves): ";
            }
            screen += "\x1b[" + std::to_string(client.rows - 1) + ";3H\x1b[97m" + prompt +
                client.poll_input + "\x1b[?25h";
        } else if (client.adding_poll_choice) {
            screen += "\x1b[" + std::to_string(client.rows - 1) + ";3H\x1b[97mNew choice: " +
                client.poll_input + "\x1b[?25h";
        }
        if (!write_channel(client, screen)) {
            client.close_requested = true;
            return;
        }
        client.viewing_polls = true;
        client.viewing_callers = false;
        client.viewing_bulletins = false;
        client.viewing_art = false;
        client.viewing_one_liners = false;
        client.viewing_uploads = false;
        client.viewing_files = false;
        client.viewing_areas = false;
        client.viewing_messages = false;
        client.viewing_private_mail = false;
        client.viewing_sysop = false;
        client.viewing_profile = false;
        client.waiting_for_return = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not load voting topics: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not load the voting topics.\r\nPress any key to continue.");
        client.viewing_polls = false;
        client.viewing_callers = false;
        client.viewing_auto_message = false;
        client.waiting_for_return = true;
    }
}

void cast_selected_poll_vote(ClientContext& client, std::size_t option_index) {
    if (option_index >= client.active_poll.options.size() ||
        (client.active_poll.caller_vote.has_value() && !client.changing_poll_vote) ||
        client.community == nullptr) {
        (void)write_channel(client, "\a");
        return;
    }
    const PollOption& option = client.active_poll.options[option_index];
    try {
        client.community->vote(client.active_poll.id, option.id, client.handle);
        client.showing_poll_results = true;
        client.changing_poll_vote = false;
        std::clog << "User " << client.handle << " voted in poll "
                  << client.active_poll.id << ".\n";
        show_polls(client);
    } catch (const std::exception& error) {
        std::cerr << "Could not record poll vote: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not record that vote.\r\n");
        show_polls(client);
    }
}

void show_callers(ClientContext& client) {
    if (client.community == nullptr) {
        client.close_requested = true;
        return;
    }
    try {
        client.caller_sessions = client.community->today_callers(client.caller_page);
        const std::string screen = callers_screen(
            client.caller_sessions, client.columns, client.rows,
            render_screen_art(client, client.callers_art));
        if (write_channel(client, screen)) {
            client.viewing_callers = true;
            client.viewing_polls = false;
            client.viewing_bulletins = false;
            client.viewing_art = false;
            client.viewing_one_liners = false;
            client.viewing_uploads = false;
            client.viewing_files = false;
            client.viewing_areas = false;
            client.viewing_messages = false;
            client.viewing_private_mail = false;
            client.viewing_sysop = false;
            client.viewing_profile = false;
            client.waiting_for_return = false;
        } else {
            client.close_requested = true;
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not read today's caller history: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read caller history.\r\nPress any key to continue.");
        client.viewing_callers = false;
        client.waiting_for_return = true;
    }
}

void show_statistics(ClientContext& client) {
    if (client.community == nullptr) {
        client.close_requested = true;
        return;
    }
    try {
        client.community_statistics = client.community->statistics();
        const std::string screen = statistics_screen(
            client.community_statistics, client.statistics_page, client.columns, client.rows,
            render_screen_art(client, client.stats_art));
        if (write_channel(client, screen)) {
            client.viewing_statistics = true;
            client.viewing_callers = false;
            client.viewing_auto_message = false;
            client.viewing_polls = false;
            client.viewing_bulletins = false;
            client.viewing_art = false;
            client.viewing_one_liners = false;
            client.viewing_uploads = false;
            client.viewing_files = false;
            client.viewing_areas = false;
            client.viewing_messages = false;
            client.viewing_private_mail = false;
            client.viewing_sysop = false;
            client.viewing_profile = false;
            client.waiting_for_return = false;
        } else {
            client.close_requested = true;
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not read community statistics: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read community statistics.\r\nPress any key to continue.");
        client.viewing_statistics = false;
        client.waiting_for_return = true;
    }
}

void show_auto_message(ClientContext& client) {
    if (client.community == nullptr) {
        client.close_requested = true;
        return;
    }
    try {
        const bool may_read_anonymous = client.messages != nullptr &&
            client.messages->can_read_public_anonymously(client.handle);
        client.current_auto_message = client.community->auto_message();
        const RenderedAutoMessagePage page = auto_message_screen(
            client.current_auto_message, may_read_anonymous, client.is_sysop,
        client.auto_message_page, client.columns, client.rows,
        render_screen_art(client, supplemental_screen_art(
            client, &SupplementalScreenArt::auto_message)));
        client.auto_message_page = std::min(client.auto_message_page, page.page_count - 1);
        client.auto_message_page_count = page.page_count;
        if (write_channel(client, page.screen)) {
            client.viewing_auto_message = true;
            client.viewing_callers = false;
            client.viewing_polls = false;
            client.viewing_bulletins = false;
            client.viewing_art = false;
            client.viewing_one_liners = false;
            client.viewing_uploads = false;
            client.viewing_files = false;
            client.viewing_areas = false;
            client.viewing_messages = false;
            client.viewing_private_mail = false;
            client.viewing_sysop = false;
            client.viewing_profile = false;
            client.waiting_for_return = false;
        } else {
            client.close_requested = true;
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not read auto-message: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read the auto-message.\r\nPress any key to continue.");
        client.viewing_auto_message = false;
        client.waiting_for_return = true;
    }
}

std::string birthday_notice(ClientContext& client) {
    const std::string_view birth_date(client.profile.birth_date);
    if (birth_date.size() != 10 || birth_date[4] != '-' || birth_date[7] != '-' ||
        client.new_file_since.size() < 10) {
        return {};
    }
    const std::time_t now = std::time(nullptr);
    std::tm local{};
    if (::localtime_r(&now, &local) == nullptr) {
        return {};
    }
    std::array<char, 16> today_buffer{};
    if (std::strftime(today_buffer.data(), today_buffer.size(), "%Y-%m-%d", &local) == 0) {
        return {};
    }
    const std::string today(today_buffer.data());
    const std::string previous_login = client.new_file_since.substr(0, 10);
    const std::string birthday = today.substr(0, 4) + std::string(birth_date.substr(4));
    if (birthday <= previous_login || birthday > today) {
        return {};
    }
    int birth_year{};
    int current_year{};
    const auto parse_year = [](std::string_view input, int& value) {
        const auto parsed = std::from_chars(input.data(), input.data() + input.size(), value);
        return parsed.ec == std::errc{} && parsed.ptr == input.data() + input.size();
    };
    if (!parse_year(birth_date.substr(0, 4), birth_year) ||
        !parse_year(std::string_view(today).substr(0, 4), current_year)) {
        return {};
    }
    const int age = current_year - birth_year;
    const bool late = birthday < today;
    std::string message = "\r\n";
    const std::string_view birthday_art = late && !client.birthday_late_art.empty()
        ? client.birthday_late_art : client.birthday_art;
    if (!birthday_art.empty()) {
        message += render_screen_art(client, birthday_art);
        if (message.back() != '\n') {
            message += "\r\n";
        }
    }
    if (client.profile.ansi_color) {
        message += "\x1b[96m";
    }
    message += "Happy Birthday, " + client.handle + "!\r\n";
    message += late
        ? "(A little late, but it's the thought that counts.)\r\n"
        : "You turned " + std::to_string(age) + " today!\r\n";
    if (client.profile.ansi_color) {
        message += "\x1b[0m";
    }
    message += "\r\n";
    return message;
}

void show_welcome(ClientContext& client) {
    client.menu_command_input.clear();
    std::string_view tagline;
    if (client.tagline_catalog != nullptr && !client.tagline_catalog->empty()) {
        static thread_local std::mt19937 generator(std::random_device{}());
        std::uniform_int_distribution<std::size_t> choose(0, client.tagline_catalog->size() - 1);
        tagline = (*client.tagline_catalog)[choose(generator)].contents;
    }
    if (write_channel(client, welcome_screen(
            client.handle, client.node_number, client.columns, client.rows,
            render_screen_art(client, client.welcome_art), client.is_sysop, tagline,
            client.profile.hotkeys, client.profile.expert_mode, client.welcome_selection_index))) {
        client.drawn = true;
        client.welcome_menu_active = true;
        client.in_chat.store(false);
        client.waiting_for_return = false;
        client.showing_nodes = false;
        client.viewing_art = false;
        client.viewing_bulletins = false;
        client.reading_bulletin = false;
        client.viewing_polls = false;
        client.viewing_callers = false;
        client.viewing_statistics = false;
        client.viewing_quote = false;
        client.viewing_quote_queue = false;
        client.viewing_short_messages = false;
        client.viewing_entrance = false;
        client.viewing_once_only = false;
        client.viewing_bbs_directory = false;
        client.viewing_bbs_detail = false;
        client.editing_bbs_listing = false;
        client.confirming_bbs_delete = false;
        client.selected_bbs_listing_id.reset();
        client.editing_bbs_listing_id.reset();
        client.bbs_listing_input.clear();
        client.viewing_auto_message = false;
        client.reading_poll = false;
        client.showing_poll_results = false;
        client.changing_poll_vote = false;
        client.creating_poll = false;
        client.poll_question_entered = false;
        client.poll_subtitle_entered = false;
        client.poll_choice_policy_entered = false;
        client.allow_poll_new_choices = false;
        client.poll_vote_policy_entered = false;
        client.allow_poll_vote_changes = false;
        client.adding_poll_choice = false;
        client.selected_poll_id.reset();
        client.poll_question.clear();
        client.poll_subtitle.clear();
        client.poll_input.clear();
        client.poll_options.clear();
        client.message_is_auto = false;
        client.message_is_quote = false;
        client.selected_quote_submission_id.reset();
        client.viewing_areas = false;
        client.viewing_messages = false;
        client.unread_only_messages = false;
        client.viewing_new_scan = false;
        client.reading_from_new_scan = false;
        client.viewing_private_mail = false;
        client.viewing_sysop = false;
        client.viewing_sysop_account_detail = false;
        client.viewing_sysop_audit = false;
        client.viewing_sysop_areas = false;
        client.area_admin_kind.reset();
        client.area_admin_renaming_file = false;
        client.area_admin_renaming_message = false;
        client.editing_file_area_access = false;
        client.editing_message_area_access = false;
        client.editing_message_force_read = false;
        client.editing_message_real_names = false;
        client.editing_message_quote_templates = false;
        client.editing_private_quote_templates = false;
        client.area_admin_deleting_file = false;
        client.area_admin_confirming_file_deletion = false;
        client.area_admin_deleting_message = false;
        client.area_admin_confirming_message_deletion = false;
        client.area_admin_delete_id = 0;
        client.area_admin_delete_name.clear();
        client.area_admin_input.clear();
        client.sysop_account_input.clear();
        client.area_admin_notice.clear();
        client.viewing_profile = false;
        client.viewing_time_bank = false;
        client.time_bank_action = ClientContext::TimeBankAction::None;
        client.time_bank_input.clear();
        client.viewing_files = false;
        client.viewing_file_list = false;
        client.searching_files = false;
        client.viewing_uploads = false;
        client.viewing_upload_detail = false;
        client.selecting_upload_area = false;
        client.confirming_upload_delete = false;
        client.selected_upload.reset();
        client.viewing_one_liners = false;
        client.adding_one_liner = false;
        client.editing_one_liner = false;
        client.confirming_one_liner_post = false;
        client.confirming_one_liner_delete = false;
        client.selected_one_liner_id.reset();
        client.editing_one_liner_id.reset();
        client.one_liner_input.clear();
        client.pending_one_liner_text.clear();
        client.editing_profile = false;
        client.profile_field.reset();
        client.reading_message = false;
        client.reading_private_message = false;
        client.reader_message.reset();
        client.private_message.reset();
        client.reader_backstack.clear();
        client.writing_message = false;
        client.entering_private_recipient = false;
        client.message_is_private = false;
        if (!client.birthday_notice_checked) {
            client.birthday_notice_checked = true;
            const std::string notice = birthday_notice(client);
            if (!notice.empty()) {
                (void)write_channel(client, notice);
            }
        }
    } else {
        client.close_requested = true;
    }
}

void show_pending_application(ClientContext& client);
void show_new_user_questionnaire(ClientContext& client);
void begin_profile_completion(ClientContext& client);

void show_short_messages(ClientContext& client) {
    try {
        client.short_messages = client.community == nullptr
            ? std::vector<ShortMessage>{}
            : client.community->claim_short_messages(client.handle);
        if (client.short_messages.empty()) {
            show_welcome(client);
            return;
        }
        client.short_message_page = 0;
        if (write_channel(client, short_messages_screen(client.short_messages,
                client.short_message_page, client.columns, client.rows,
                render_screen_art(client, client.mailbox_art)))) {
            client.viewing_short_messages = true;
            client.drawn = true;
            client.waiting_for_return = false;
        } else {
            client.close_requested = true;
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not deliver short messages to " << client.handle << ": "
                  << error.what() << '\n';
        show_welcome(client);
    }
}

bool once_only_notice_is_new(const ClientContext& client) {
    if (client.once_only_art.empty() || client.once_only_art_modified.empty() ||
        client.new_file_since.size() < 10) {
        return false;
    }
    std::string previous_login = client.new_file_since.substr(0, 19);
    if (previous_login.size() == 10) {
        previous_login += " 00:00:00";
    }
    return client.once_only_art_modified > previous_login;
}

bool scheduled_event_is_active_now(
    const ScheduledEvent& event, int node_number, const std::tm& local_time, int seconds_since_midnight) {
    if (!event.active || (event.node != 0 && event.node != node_number)) {
        return false;
    }
    if (event.monthly) {
        if (event.day_of_month != local_time.tm_mday) {
            return false;
        }
    } else if ((event.day_mask & (1 << local_time.tm_wday)) == 0) {
        return false;
    }

    std::array<char, 16> date_buffer{};
    if (std::strftime(date_buffer.data(), date_buffer.size(), "%Y-%m-%d", &local_time) == 0) {
        return false;
    }
    if (event.last_run_date.size() >= 10 &&
        event.last_run_date.compare(0, 10, date_buffer.data(), 10) == 0) {
        return false;
    }

    const int start_seconds = event.start_minute * 60;
    const int finish_seconds = (event.start_minute + event.finish_minute) * 60;
    if (start_seconds == finish_seconds) {
        return true;
    }
    if (finish_seconds > start_seconds) {
        return seconds_since_midnight > start_seconds && seconds_since_midnight < finish_seconds;
    }
    return !(seconds_since_midnight <= start_seconds && seconds_since_midnight >= finish_seconds);
}

std::optional<ScheduledEvent> active_logon_event(ClientContext& client) {
    if (client.community == nullptr) {
        return std::nullopt;
    }
    const std::time_t now = std::time(nullptr);
    std::tm local_time{};
    if (::localtime_r(&now, &local_time) == nullptr) {
        throw std::runtime_error("could not read local time for event schedule");
    }
    const int seconds_since_midnight = local_time.tm_hour * 3600 + local_time.tm_min * 60 +
        local_time.tm_sec;
    std::optional<ScheduledEvent> selected;
    for (const ScheduledEvent& event : client.community->scheduled_events()) {
        if (event.type == "logon" && scheduled_event_is_active_now(
                event, client.node_number, local_time, seconds_since_midnight)) {
            selected = event;
        }
    }
    return selected;
}

void show_once_only_notice(ClientContext& client) {
    std::string screen = "\x1b[2J\x1b[H\x1b[0m";
    screen += render_screen_art(client, client.once_only_art);
    if (!screen.empty() && screen.back() != '\n') {
        screen += "\r\n";
    }
    screen += "\r\n\x1b[96mPress any key to continue.\x1b[0m";
    if (write_channel(client, screen)) {
        client.viewing_once_only = true;
        client.waiting_for_return = true;
        client.drawn = true;
    } else {
        client.close_requested = true;
    }
}

void show_login_entrance(ClientContext& client) {
    if (!write_channel(client, entrance_screen(
            client.handle, client.node_number, client.columns, client.rows,
            render_screen_art(client, client.entrance_art)))) {
        client.close_requested = true;
        return;
    }
    client.viewing_entrance = true;
    client.waiting_for_return = true;
    client.drawn = true;
}

void show_initial_screen(ClientContext& client) {
    if (!client.event_access_checked) {
        client.event_access_checked = true;
        try {
            const auto event = active_logon_event(client);
            int remaining_minutes = 32767;
            if (client.session_deadline.has_value()) {
                const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                    *client.session_deadline - std::chrono::steady_clock::now()).count();
                remaining_minutes = static_cast<int>(std::clamp<std::int64_t>(
                    seconds / 60, 0, 32767));
            }
            const int online_minutes = static_cast<int>(std::clamp<std::int64_t>(
                std::chrono::duration_cast<std::chrono::minutes>(
                    std::chrono::steady_clock::now() - client.authenticated_at).count(),
                0, 32767));
            if (event.has_value() && client.messages != nullptr &&
                !client.messages->passes_access_rule(client.handle, event->access_acs,
                    client.node_number, remaining_minutes, online_minutes, client.invisible)) {
                std::string notice = "\x1b[2J\x1b[H\x1b[0m\x1b[91m"
                    "This BBS is currently restricted by a scheduled access event.\r\n\r\n"
                    "Event: \x1b[97m" + event->description +
                    "\r\n\x1b[91mYour account does not meet its access requirements.\r\n"
                    "Please reconnect outside the scheduled access window.\r\n\x1b[0m";
                if (write_channel(client, notice)) {
                    client.drawn = true;
                    client.close_requested = true;
                } else {
                    client.close_requested = true;
                }
                return;
            }
        } catch (const std::exception& error) {
            std::cerr << "Could not evaluate scheduled logon access for " << client.handle
                      << ": " << error.what() << '\n';
            (void)write_channel(client,
                "\r\nScheduled access could not be verified. Please try again later.\r\n");
            client.drawn = true;
            client.close_requested = true;
            return;
        }
    }
    if (client.birthday_check_required) {
        std::string screen = "\x1b[2J\x1b[H\x1b[0m";
        if (client.profile.ansi_color) {
            screen += "\x1b[96m";
        }
        screen += "SECURITY CHECK\r\n\r\n";
        if (client.profile.ansi_color) {
            screen += "\x1b[0m";
        }
        screen += "Please verify your date of birth (MM/DD/YYYY): ";
        screen.append(client.birthday_check_input.size(), '*');
        if (write_channel(client, screen)) {
            client.checking_birth_date = true;
            client.drawn = true;
            client.waiting_for_return = false;
        } else {
            client.close_requested = true;
        }
        return;
    }
    if (client.registration_pending) {
        if (client.collecting_application_profile) {
            show_new_user_questionnaire(client);
        } else {
            show_pending_application(client);
        }
    } else {
        if (!client.entrance_checked) {
            client.entrance_checked = true;
            if (!client.entrance_art.empty()) {
                show_login_entrance(client);
                return;
            }
        }
        if (!client.once_only_checked) {
            client.once_only_checked = true;
            if (once_only_notice_is_new(client)) {
                show_once_only_notice(client);
                return;
            }
        }

        if (!client.profile_completion_checked) {
            client.profile_completion_checked = true;
            const auto enabled = client.accounts->signup_question_states();
            const auto add_if_missing = [&client, &enabled](int question, bool missing,
                    ClientContext::ProfileField field) {
                if (enabled[static_cast<std::size_t>(question)] && missing) {
                    client.profile_completion_fields.push_back(field);
                }
            };
            add_if_missing(2, client.profile.real_name.empty(), ClientContext::ProfileField::RealName);
            add_if_missing(4, client.profile.street.empty(), ClientContext::ProfileField::Street);
            add_if_missing(5, client.profile.city_state.empty(), ClientContext::ProfileField::CityState);
            add_if_missing(6, client.profile.postal_code.empty(), ClientContext::ProfileField::PostalCode);
            add_if_missing(7, client.profile.phone.empty(), ClientContext::ProfileField::Phone);
            add_if_missing(8, client.profile.birth_date.empty(), ClientContext::ProfileField::BirthDate);
            add_if_missing(9, client.profile.sex == '\0', ClientContext::ProfileField::Sex);
            add_if_missing(10, client.profile.user_answers[0].empty(), ClientContext::ProfileField::UserAnswer1);
            add_if_missing(11, client.profile.user_answers[1].empty(), ClientContext::ProfileField::UserAnswer2);
            add_if_missing(12, client.profile.user_answers[2].empty(), ClientContext::ProfileField::UserAnswer3);
            if (enabled[14] && !client.accounts->forgot_password_question().empty() &&
                !client.profile.forgot_password_answer_set) {
                client.profile_completion_fields.push_back(ClientContext::ProfileField::ForgotPasswordAnswer);
            }
            if (!client.profile_completion_fields.empty()) {
                begin_profile_completion(client);
                return;
            }
        }
    }
    if (!client.short_messages_checked) {
        client.short_messages_checked = true;
        show_short_messages(client);
    } else {
        show_welcome(client);
    }
}

void show_sysop_accounts(ClientContext& client) {
    try {
        client.editing_custom_user_question = 0;
        client.custom_user_question_input.clear();
        client.editing_sysop_security_levels = false;
        client.editing_sysop_acs_flags = false;
        client.editing_sysop_credits = false;
        client.editing_sysop_file_points = false;
        client.editing_sysop_short_message = false;
        client.editing_sysop_profile = false;
        client.editing_sysop_profile_field = '\0';
        client.sysop_password_new.clear();
        client.editing_sysop_birth_date = false;
        client.editing_sysop_sex = false;
        client.editing_sysop_expiration_date = false;
        client.editing_sysop_validation_level = false;
        client.sysop_account_input.clear();
        client.viewing_validation_admin = false;
        client.validation_admin_operation = '\0';
        client.validation_admin_input.clear();
        client.sysop_accounts = client.accounts->list_accounts();
        const std::size_t page_count = std::max<std::size_t>(
            1, (client.sysop_accounts.size() + 9) / 10);
        client.sysop_page = std::min(client.sysop_page, page_count - 1);
        if (client.sysop_selected_index.has_value() &&
            *client.sysop_selected_index >= client.sysop_accounts.size()) {
            client.sysop_selected_index.reset();
        }
        const std::string screen = account_admin_screen(
            client.sysop_accounts, client.sysop_page, client.sysop_selected_index,
            client.columns, client.rows, render_screen_art(client,
                sysop_screen_art(client, &SupplementalScreenArt::sysop_accounts)));
        if (write_channel(client, screen)) {
            client.viewing_sysop = true;
            client.viewing_signup_question_admin = false;
            client.viewing_validation_admin = false;
            client.signup_preferences_page = false;
            client.viewing_sysop_account_detail = false;
            client.viewing_sysop_audit = false;
            client.viewing_sysop_areas = false;
            client.viewing_art = false;
            client.viewing_areas = false;
            client.viewing_messages = false;
            client.viewing_private_mail = false;
            client.waiting_for_return = false;
        } else {
            client.close_requested = true;
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not read SysOp account list: " << error.what() << '\n';
        client.close_requested = true;
    }
}

void show_signup_question_admin(ClientContext& client) {
    try {
        const auto enabled = client.accounts->signup_question_states();
        const std::string recovery_question = client.accounts->forgot_password_question();
        const auto user_questions = client.accounts->custom_user_questions();
        if (!write_channel(client, signup_question_admin_screen(
                enabled, recovery_question, user_questions, client.editing_custom_user_question,
                client.custom_user_question_input, client.signup_preferences_page,
                client.columns, client.rows,
                render_screen_art(client,
                    sysop_screen_art(client, &SupplementalScreenArt::signup_questions)),
                client.signup_question_selection_index,
                client.signup_question_prompt_selection_index))) {
            client.close_requested = true;
            return;
        }
        client.viewing_sysop = true;
        client.viewing_sysop_account_detail = false;
        client.viewing_sysop_audit = false;
        client.viewing_sysop_areas = false;
        client.viewing_validation_admin = false;
        client.viewing_signup_question_admin = true;
        client.waiting_for_return = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not read signup questions: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read signup questions.\r\n");
        show_sysop_accounts(client);
    }
}

ValidationLevel parse_validation_admin_record(std::string_view input) {
    std::vector<std::string_view> fields;
    std::size_t start = 0;
    for (;;) {
        const std::size_t separator = input.find(';', start);
        fields.push_back(separator == std::string_view::npos
            ? input.substr(start)
            : input.substr(start, separator - start));
        if (separator == std::string_view::npos) {
            break;
        }
        start = separator + 1;
    }
    if (fields.size() != 14 || fields[0].size() != 1) {
        throw std::invalid_argument("Use 14 semicolon-separated fields: KEY;DESC;SL;DSL;MENU;DAYS;EXPIRE_TO;AR;AC;SOFT_AR;SOFT_AC;FP;CREDITS;MESSAGE.");
    }
    const auto number = [&](std::size_t index, std::string_view name, unsigned int maximum) {
        unsigned int value{};
        const auto parsed = std::from_chars(fields[index].data(),
            fields[index].data() + fields[index].size(), value);
        if (fields[index].empty() || parsed.ec != std::errc{} ||
            parsed.ptr != fields[index].data() + fields[index].size() || value > maximum) {
            throw std::invalid_argument(std::string(name) + " is outside its supported range");
        }
        return value;
    };
    const auto soft = [&](std::size_t index, std::string_view name) {
        if (fields[index] == "on") return true;
        if (fields[index] == "off") return false;
        throw std::invalid_argument(std::string(name) + " must be on or off");
    };
    ValidationLevel level;
    level.key = fields[0].front();
    level.description = fields[1] == "-" ? "" : std::string(fields[1]);
    level.security_level = static_cast<int>(number(2, "validation SL", 255));
    level.download_security_level = static_cast<int>(number(3, "validation DSL", 255));
    level.start_menu = static_cast<int>(number(4, "validation menu", 255));
    level.expiration_days = static_cast<int>(number(5, "expiration days", 65535));
    if (fields[6] != "-") {
        if (fields[6].size() != 1) {
            throw std::invalid_argument("expire-to key must be one character or '-'");
        }
        level.expire_to_key = fields[6].front();
    }
    level.ar_flags = fields[7] == "-" ? "" : std::string(fields[7]);
    level.ac_flags = fields[8] == "-" ? "" : std::string(fields[8]);
    level.soft_ar_flags = soft(9, "SoftAR");
    level.soft_ac_flags = soft(10, "SoftAC");
    level.file_points = static_cast<int>(number(11, "file-point award", 2147483647U));
    level.credits = number(12, "credit award", 2147483647U);
    level.user_message = fields[13] == "-" ? "" : std::string(fields[13]);
    return level;
}

std::string format_validation_admin_record(const ValidationLevel& level) {
    const auto value_or_dash = [](std::string_view value) {
        return value.empty() ? std::string("-") : std::string(value);
    };
    std::array<std::string, 14> fields{
        std::string(1, level.key), value_or_dash(level.description),
        std::to_string(level.security_level), std::to_string(level.download_security_level),
        std::to_string(level.start_menu), std::to_string(level.expiration_days),
        level.expire_to_key == ' ' ? "-" : std::string(1, level.expire_to_key),
        value_or_dash(level.ar_flags), value_or_dash(level.ac_flags),
        level.soft_ar_flags ? "on" : "off", level.soft_ac_flags ? "on" : "off",
        std::to_string(level.file_points), std::to_string(level.credits),
        value_or_dash(level.user_message),
    };
    std::string result;
    for (const std::string& field : fields) {
        if (field.find(';') != std::string::npos) {
            throw std::invalid_argument("This record contains a semicolon and cannot be edited in the terminal form.");
        }
        if (!result.empty()) {
            result.push_back(';');
        }
        result += field;
    }
    return result;
}

void show_validation_level_admin(ClientContext& client) {
    try {
        client.validation_levels = client.accounts->validation_levels();
        const std::size_t pages = std::max<std::size_t>(
            1, (client.validation_levels.size() + 9) / 10);
        client.validation_admin_page = std::min(client.validation_admin_page, pages - 1);
        if (client.validation_levels.empty()) {
            client.validation_admin_selection_index = 0;
        } else {
            client.validation_admin_selection_index = std::min(
                client.validation_admin_selection_index, client.validation_levels.size() - 1);
            client.validation_admin_page = client.validation_admin_selection_index / 10;
        }
        if (!write_channel(client, validation_level_admin_screen(
                client.validation_levels, client.validation_admin_page,
                client.validation_admin_selection_index,
                client.validation_admin_operation, client.validation_admin_input,
                client.validation_admin_notice, client.columns, client.rows,
                render_screen_art(client,
                    sysop_screen_art(client, &SupplementalScreenArt::validation_levels))))) {
            client.close_requested = true;
            return;
        }
        client.viewing_sysop = true;
        client.viewing_sysop_account_detail = false;
        client.viewing_sysop_audit = false;
        client.viewing_sysop_areas = false;
        client.viewing_signup_question_admin = false;
        client.viewing_validation_admin = true;
        client.waiting_for_return = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not read validation levels: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read validation levels.\r\n");
        show_sysop_accounts(client);
    }
}

void record_sysop_action(
    ClientContext& client, std::string_view action, std::string_view subject) {
    if (client.community == nullptr) {
        return;
    }
    try {
        std::size_t end = std::min<std::size_t>(subject.size(), 256);
        while (end > 0 && end < subject.size() &&
            (static_cast<unsigned char>(subject[end]) & 0xc0U) == 0x80U) {
            --end;
        }
        std::string safe_subject(subject.substr(0, end));
        for (char& value : safe_subject) {
            const unsigned char byte = static_cast<unsigned char>(value);
            if (byte < 0x20 || byte == 0x7f) {
                value = ' ';
            }
        }
        client.community->record_sysop_action(client.handle, action, safe_subject);
    } catch (const std::exception& error) {
        std::cerr << "Could not persist SysOp audit action for " << client.handle << ": "
                  << error.what() << '\n';
    }
}

void show_sysop_audit(ClientContext& client) {
    if (client.community == nullptr) {
        (void)write_channel(client, "\r\nSysOp audit history is unavailable.\r\n");
        show_sysop_accounts(client);
        return;
    }
    try {
        client.sysop_audit = client.community->sysop_audit(client.sysop_audit_page);
        client.sysop_audit_page = client.sysop_audit.page;
        if (!write_channel(client, sysop_audit_screen(client.sysop_audit,
                client.columns, client.rows, render_screen_art(client,
                    sysop_screen_art(client, &SupplementalScreenArt::sysop_audit))))) {
            client.close_requested = true;
            return;
        }
        client.viewing_sysop = true;
        client.viewing_sysop_account_detail = false;
        client.viewing_sysop_audit = true;
        client.viewing_sysop_areas = false;
        client.waiting_for_return = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not read SysOp audit history: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read SysOp audit history.\r\n");
        show_sysop_accounts(client);
    }
}

std::string validation_preview_flags(
    std::string current, std::string_view added, bool soft) {
    if (!soft) {
        return std::string(added);
    }
    for (const char flag : added) {
        if (current.find(flag) == std::string::npos) {
            current.push_back(flag);
        }
    }
    return current;
}

void show_sysop_account_review(ClientContext& client) {
    if (!client.sysop_selected_index.has_value() ||
        *client.sysop_selected_index >= client.sysop_accounts.size()) {
        (void)write_channel(client, "\a");
        return;
    }
    const AccountSummary& account = client.sysop_accounts[*client.sysop_selected_index];
    const std::string screen = client.confirming_sysop_validation && client.pending_sysop_validation.has_value()
        ? validation_preview_screen(account, *client.pending_sysop_validation,
            validation_preview_flags(account.acs_ar_flags, client.pending_sysop_validation->ar_flags,
                client.pending_sysop_validation->soft_ar_flags),
            validation_preview_flags(account.acs_ac_flags, client.pending_sysop_validation->ac_flags,
                client.pending_sysop_validation->soft_ac_flags),
            account.credits + client.pending_sysop_validation->credits,
            account.file_points + client.pending_sysop_validation->file_points,
            client.columns, client.rows, render_screen_art(client,
                sysop_screen_art(client, &SupplementalScreenArt::sysop_account)))
        : account_review_screen(account,
            client.editing_sysop_security_levels, client.editing_sysop_acs_flags,
            client.editing_sysop_credits,
            client.editing_sysop_file_points,
            client.editing_sysop_birth_date,
            client.editing_sysop_sex,
            client.editing_sysop_expiration_date,
            client.editing_sysop_validation_level,
            client.confirming_sysop_validation,
            client.editing_sysop_profile,
            client.editing_sysop_profile_field,
            client.editing_sysop_short_message,
            client.sysop_account_input,
            client.columns, client.rows, render_screen_art(client,
                sysop_screen_art(client, &SupplementalScreenArt::sysop_account)),
            client.sysop_account_action_selection_index);
    if (write_channel(client, screen)) {
        client.viewing_sysop = true;
        client.viewing_sysop_account_detail = true;
        client.viewing_sysop_areas = false;
        client.waiting_for_return = false;
    } else {
        client.close_requested = true;
    }
}

void show_profile(ClientContext& client) {
    if (!client.viewing_profile) {
        client.viewing_profile_contacts = false;
        client.profile_selection_index = 0;
    }
    if (write_channel(client, profile_screen(
            client.profile, client.viewing_profile_contacts, client.columns, client.rows,
            render_screen_art(client, client.profile_art), client.profile_selection_index))) {
        client.viewing_profile = true;
        client.editing_profile = false;
        client.profile_field.reset();
        client.viewing_sysop = false;
        client.viewing_art = false;
        client.viewing_areas = false;
        client.viewing_messages = false;
        client.viewing_private_mail = false;
        client.waiting_for_return = false;
    } else {
        client.close_requested = true;
    }
}

std::optional<int> remaining_session_minutes(const ClientContext& client) {
    if (!client.session_deadline.has_value()) {
        return std::nullopt;
    }
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
        *client.session_deadline - std::chrono::steady_clock::now()).count();
    return static_cast<int>(std::clamp<std::int64_t>(seconds / 60, 0, 32767));
}

void redraw_time_bank(ClientContext& client) {
    const auto remaining = remaining_session_minutes(client);
    const std::string_view art = supplemental_screen_art(
        client, &SupplementalScreenArt::time_bank);
    if (!write_channel(client, time_bank_screen(
            client.time_bank, remaining, client.time_bank_max_minutes,
            client.time_bank_deposit_daily_limit, client.time_bank_withdrawal_daily_limit,
            client.time_bank_action != ClientContext::TimeBankAction::None,
            client.time_bank_action == ClientContext::TimeBankAction::Deposit,
            client.time_bank_input, client.columns, client.rows,
            render_screen_art(client, art.empty() ? client.profile_art : art),
            client.time_bank_selection_index))) {
        client.close_requested = true;
    }
}

void show_time_bank(ClientContext& client) {
    try {
        client.time_bank = client.accounts->time_bank_status(client.handle);
        client.time_bank_action = ClientContext::TimeBankAction::None;
        client.time_bank_input.clear();
        client.time_bank_selection_index = 0;
        client.viewing_time_bank = true;
        client.viewing_profile = false;
        client.viewing_sysop = false;
        client.viewing_art = false;
        client.viewing_areas = false;
        client.viewing_messages = false;
        client.viewing_private_mail = false;
        client.waiting_for_return = false;
        redraw_time_bank(client);
    } catch (const std::exception& error) {
        std::cerr << "Could not read time bank for " << client.handle << ": " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read the time bank.\r\n");
        show_welcome(client);
    }
}

void start_time_bank_transfer(ClientContext& client, ClientContext::TimeBankAction action) {
    if (!client.session_deadline.has_value()) {
        (void)write_channel(client, "\r\nSet --session-time-limit to enable time bank transfers.\r\n");
        return;
    }
    client.time_bank_action = action;
    client.time_bank_input.clear();
    redraw_time_bank(client);
}

void persist_caller_session_deadline(ClientContext& client) {
    if (client.community == nullptr || !client.caller_session_id.has_value()) {
        return;
    }
    std::optional<int> remaining_seconds;
    if (client.session_deadline.has_value()) {
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
            *client.session_deadline - std::chrono::steady_clock::now()).count();
        remaining_seconds = static_cast<int>(std::clamp<std::int64_t>(seconds, 0, 32767 * 60));
    }
    try {
        client.community->update_caller_session_time(*client.caller_session_id, remaining_seconds);
    } catch (const std::exception& error) {
        std::cerr << "Could not update caller-session time limit for " << client.handle
                  << ": " << error.what() << '\n';
    }
}

void finish_time_bank_transfer(ClientContext& client) {
    int minutes = 0;
    for (const char digit : client.time_bank_input) {
        if (digit < '0' || digit > '9' || minutes > 3276) {
            (void)write_channel(client, "\a");
            client.time_bank_input.clear();
            client.time_bank_action = ClientContext::TimeBankAction::None;
            redraw_time_bank(client);
            return;
        }
        minutes = minutes * 10 + (digit - '0');
    }
    const ClientContext::TimeBankAction action = client.time_bank_action;
    try {
        if (minutes < 1 || minutes > 32767) {
            throw std::invalid_argument("enter a value from 1 to 32767 minutes");
        }
        if (action == ClientContext::TimeBankAction::Deposit) {
            const auto now = std::chrono::steady_clock::now();
            if (!client.session_deadline.has_value() ||
                *client.session_deadline - now < std::chrono::minutes(minutes)) {
                throw std::invalid_argument("not enough online time remains for that deposit");
            }
            client.time_bank = client.accounts->deposit_time(
                client.handle, minutes, client.time_bank_max_minutes,
                client.time_bank_deposit_daily_limit);
            *client.session_deadline -= std::chrono::minutes(minutes);
            std::clog << "User " << client.handle << " deposited " << minutes << " minutes into the time bank.\n";
        } else if (action == ClientContext::TimeBankAction::Withdraw) {
            client.time_bank = client.accounts->withdraw_time(
                client.handle, minutes, client.time_bank_withdrawal_daily_limit);
            const auto now = std::chrono::steady_clock::now();
            *client.session_deadline = std::max(*client.session_deadline, now) +
                std::chrono::minutes(minutes);
            std::clog << "User " << client.handle << " withdrew " << minutes << " minutes from the time bank.\n";
        }
        persist_caller_session_deadline(client);
    } catch (const std::exception& error) {
        (void)write_channel(client, "\r\n\x1b[91m" + std::string(error.what()) + "\x1b[0m\r\n");
    }
    client.time_bank_input.clear();
    client.time_bank_action = ClientContext::TimeBankAction::None;
    redraw_time_bank(client);
}

void redraw_profile_editor(ClientContext& client) {
    if (!client.profile_field.has_value()) {
        show_profile(client);
        return;
    }
    std::string_view label;
    std::size_t maximum{};
    bool secret = false;
    switch (*client.profile_field) {
    case ClientContext::ProfileField::RealName:
        label = "Real name";
        maximum = 48;
        break;
    case ClientContext::ProfileField::Location:
        label = "Location";
        maximum = 80;
        break;
    case ClientContext::ProfileField::Signature:
        label = "Signature";
        maximum = 80;
        break;
    case ClientContext::ProfileField::BirthDate:
        label = "Birth date (YYYY-MM-DD)";
        maximum = 10;
        break;
    case ClientContext::ProfileField::Sex:
        label = "Gender (M/F)";
        maximum = 1;
        break;
    case ClientContext::ProfileField::Country:
        label = "Country";
        maximum = 16;
        break;
    case ClientContext::ProfileField::Street:
        label = "Street address";
        maximum = 30;
        break;
    case ClientContext::ProfileField::CityState:
        label = "City and state / province";
        maximum = 30;
        break;
    case ClientContext::ProfileField::PostalCode:
        label = "ZIP / postal code";
        maximum = 10;
        break;
    case ClientContext::ProfileField::Phone:
        label = "Phone number";
        maximum = 12;
        break;
    case ClientContext::ProfileField::UserAnswer1:
        label = client.custom_user_questions[0].empty()
            ? std::string_view("SysOp-defined answer 1") : std::string_view(client.custom_user_questions[0]);
        maximum = 35;
        break;
    case ClientContext::ProfileField::UserAnswer2:
        label = client.custom_user_questions[1].empty()
            ? std::string_view("SysOp-defined answer 2") : std::string_view(client.custom_user_questions[1]);
        maximum = 35;
        break;
    case ClientContext::ProfileField::UserAnswer3:
        label = client.custom_user_questions[2].empty()
            ? std::string_view("SysOp-defined answer 3") : std::string_view(client.custom_user_questions[2]);
        maximum = 35;
        break;
    case ClientContext::ProfileField::ForgotPasswordAnswer:
        label = "Password-recovery answer";
        maximum = 40;
        secret = true;
        break;
    case ClientContext::ProfileField::CurrentPassword:
        label = "Current password";
        maximum = 128;
        secret = true;
        break;
    case ClientContext::ProfileField::NewPassword:
        label = "New password (12-128 characters)";
        maximum = 128;
        secret = true;
        break;
    case ClientContext::ProfileField::ConfirmPassword:
        label = "Confirm new password";
        maximum = 128;
        secret = true;
        break;
    }
    std::string prompt = profile_screen(
        client.profile, client.viewing_profile_contacts, client.columns, client.rows,
        render_screen_art(client, client.profile_art));
    prompt += "\x1b[" + std::to_string(std::max(1, client.rows - 5)) + ";4H\x1b[K";
    const std::string displayed_input = secret
        ? std::string(client.profile_input.size(), '*') : client.profile_input;
    prompt += std::string(label) + " (max " + std::to_string(maximum) +
        " bytes; /cancel to " + (client.changing_password ? "abort" : "keep current") +
        ") > " + displayed_input;
    prompt += "\x1b[?25h";
    if (!write_channel(client, prompt)) {
        client.close_requested = true;
    }
}

void start_profile_edit(ClientContext& client, ClientContext::ProfileField field) {
    client.profile_field = field;
    client.profile_input.clear();
    client.editing_profile = true;
    redraw_profile_editor(client);
}

void start_password_change(ClientContext& client) {
    client.changing_password = true;
    client.password_change_current.clear();
    client.password_change_new.clear();
    start_profile_edit(client, ClientContext::ProfileField::CurrentPassword);
}

void begin_profile_completion(ClientContext& client) {
    client.profile_completion_active = true;
    client.profile_completion_index = 0;
    client.viewing_profile = true;
    client.viewing_profile_contacts = false;
    (void)write_channel(client,
        "\r\n\x1b[96mPlease update the enabled profile information below. Leave a field blank to skip it.\x1b[0m\r\n");
    start_profile_edit(client, client.profile_completion_fields.front());
}

void save_profile_edit(ClientContext& client) {
    if (!client.profile_field.has_value()) {
        client.editing_profile = false;
        show_profile(client);
        return;
    }
    std::string command = client.profile_input;
    std::transform(command.begin(), command.end(), command.begin(), [](unsigned char value) {
        return static_cast<char>(std::toupper(value));
    });
    const ClientContext::ProfileField field = *client.profile_field;
    const bool password_field = field == ClientContext::ProfileField::CurrentPassword ||
        field == ClientContext::ProfileField::NewPassword ||
        field == ClientContext::ProfileField::ConfirmPassword;
    if (password_field) {
        if (command == "/CANCEL") {
            client.password_change_current.clear();
            client.password_change_new.clear();
            client.changing_password = false;
            client.profile_input.clear();
            client.editing_profile = false;
            client.profile_field.reset();
            show_profile(client);
            return;
        }
        if (field == ClientContext::ProfileField::CurrentPassword) {
            if (!client.accounts->verify_password(client.handle, client.profile_input)) {
                client.profile_input.clear();
                (void)write_channel(client, "\r\n\x1b[91mCurrent password is incorrect.\x1b[0m\r\n");
                redraw_profile_editor(client);
                return;
            }
            client.password_change_current = client.profile_input;
            start_profile_edit(client, ClientContext::ProfileField::NewPassword);
            return;
        }
        if (field == ClientContext::ProfileField::NewPassword) {
            if (client.profile_input.size() < 12 || client.profile_input.size() > 128) {
                client.profile_input.clear();
                (void)write_channel(client,
                    "\r\n\x1b[91mNew passwords must be 12-128 characters.\x1b[0m\r\n");
                redraw_profile_editor(client);
                return;
            }
            if (client.profile_input == client.handle ||
                client.profile_input == client.profile.real_name) {
                client.profile_input.clear();
                (void)write_channel(client,
                    "\r\n\x1b[91mThe new password cannot be your handle or real name.\x1b[0m\r\n");
                redraw_profile_editor(client);
                return;
            }
            client.password_change_new = client.profile_input;
            start_profile_edit(client, ClientContext::ProfileField::ConfirmPassword);
            return;
        }
        if (client.profile_input != client.password_change_new) {
            client.profile_input.clear();
            client.password_change_new.clear();
            (void)write_channel(client, "\r\n\x1b[91mPasswords do not match.\x1b[0m\r\n");
            start_profile_edit(client, ClientContext::ProfileField::NewPassword);
            return;
        }
        try {
            client.accounts->change_password(
                client.handle, client.password_change_current, client.password_change_new);
            std::clog << "User " << client.handle << " changed their password.\n";
            client.password_change_current.clear();
            client.password_change_new.clear();
            client.changing_password = false;
            client.profile_input.clear();
            client.editing_profile = false;
            client.profile_field.reset();
            (void)write_channel(client, "\r\n\x1b[92mPassword changed.\x1b[0m\r\n");
            show_profile(client);
        } catch (const std::exception& error) {
            client.password_change_current.clear();
            client.password_change_new.clear();
            client.profile_input.clear();
            (void)write_channel(client, "\r\n\x1b[91mPassword change failed: " +
                std::string(error.what()) + "\x1b[0m\r\n");
            start_password_change(client);
        }
        return;
    }
    if (command != "/CANCEL") {
        AccountProfile updated = client.profile;
        const bool recovery_answer =
            *client.profile_field == ClientContext::ProfileField::ForgotPasswordAnswer;
        switch (*client.profile_field) {
        case ClientContext::ProfileField::RealName:
            updated.real_name = client.profile_input;
            break;
        case ClientContext::ProfileField::Location:
            updated.location = client.profile_input;
            break;
        case ClientContext::ProfileField::Signature:
            updated.signature = client.profile_input;
            break;
        case ClientContext::ProfileField::BirthDate:
            updated.birth_date = client.profile_input;
            break;
        case ClientContext::ProfileField::Sex:
            updated.sex = client.profile_input.empty() ? '\0' : client.profile_input.front();
            break;
        case ClientContext::ProfileField::Country:
            updated.country = client.profile_input;
            break;
        case ClientContext::ProfileField::Street:
            updated.street = client.profile_input;
            break;
        case ClientContext::ProfileField::CityState:
            updated.city_state = client.profile_input;
            updated.location = client.profile_input;
            break;
        case ClientContext::ProfileField::PostalCode:
            updated.postal_code = client.profile_input;
            break;
        case ClientContext::ProfileField::Phone:
            updated.phone = client.profile_input;
            break;
        case ClientContext::ProfileField::UserAnswer1:
            updated.user_answers[0] = client.profile_input;
            break;
        case ClientContext::ProfileField::UserAnswer2:
            updated.user_answers[1] = client.profile_input;
            break;
        case ClientContext::ProfileField::UserAnswer3:
            updated.user_answers[2] = client.profile_input;
            break;
        case ClientContext::ProfileField::ForgotPasswordAnswer:
            break;
        case ClientContext::ProfileField::CurrentPassword:
        case ClientContext::ProfileField::NewPassword:
        case ClientContext::ProfileField::ConfirmPassword:
            break;
        }
        try {
            if (recovery_answer) {
                client.accounts->set_forgot_password_answer(client.handle, client.profile_input);
                client.profile.forgot_password_answer_set = !client.profile_input.empty();
            } else {
                client.accounts->update_profile(updated);
                client.profile = std::move(updated);
            }
        } catch (const std::exception& error) {
            std::cerr << "Could not update account profile: " << error.what() << '\n';
            (void)write_channel(client, "\r\nProfile update failed: " + std::string(error.what()) + "\r\n");
            redraw_profile_editor(client);
            return;
        }
    }
    client.profile_input.clear();
    client.editing_profile = false;
    client.profile_field.reset();
    if (client.profile_completion_active) {
        ++client.profile_completion_index;
        if (client.profile_completion_index < client.profile_completion_fields.size()) {
            start_profile_edit(client,
                client.profile_completion_fields[client.profile_completion_index]);
            return;
        }
        client.profile_completion_active = false;
        client.profile_completion_fields.clear();
        client.profile_completion_index = 0;
        client.viewing_profile = false;
        client.viewing_profile_contacts = false;
        show_initial_screen(client);
        return;
    }
    show_profile(client);
}

void show_pending_application(ClientContext& client) {
    std::string screen = "\x1b[2J\x1b[H\x1b[?25l\x1b[0m";
    const bool use_art = !client.new_caller_art.empty() && client.columns >= 80 && client.rows >= 24;
    if (use_art) {
        screen += render_screen_art(client, client.new_caller_art);
        screen += "\x1b[0m";
    } else {
        screen += "\x1b[96m+" + std::string(static_cast<std::size_t>(std::max(0, client.columns - 2)), '-') + "+\x1b[0m\r\n";
        screen += "\x1b[96m|\x1b[0m  RENEGADE NEW USER APPLICATION\r\n";
    }
    screen += "\x1b[96m|\x1b[0m\r\n";
    screen += "\x1b[96m|\x1b[0m  Handle: " + client.handle + "\r\n";
    screen += "\x1b[96m|\x1b[0m\r\n";
    screen += "\x1b[96m|\x1b[0m  Your account is waiting for SysOp approval.\r\n";
    screen += "\x1b[96m|\x1b[0m  No BBS node has been assigned yet.\r\n";
    screen += "\x1b[96m|\x1b[0m  After approval, reconnect with this handle and password.\r\n";
    screen += "\x1b[96m|\x1b[0m\r\n";
    screen += "\x1b[96m|\x1b[0m  Press Q to disconnect.\r\n";
    screen += "\x1b[96m+" + std::string(static_cast<std::size_t>(std::max(0, client.columns - 2)), '-') + "+\x1b[0m\r\n";
    screen += "\x1b[?25h";
    if (write_channel(client, screen)) {
        client.drawn = true;
    } else {
        client.close_requested = true;
    }
}

void show_new_user_questionnaire(ClientContext& client) {
    if (client.application_questions.empty()) {
        client.collecting_application_profile = false;
        show_pending_application(client);
        return;
    }
    const std::size_t field = std::min(
        client.application_profile_field, client.application_questions.size() - 1);
    const ApplicationQuestion& question = client.application_questions[field];
    std::string displayed_input = client.application_profile_input;
    if (question.secret) {
        displayed_input.assign(client.application_profile_input.size(), '*');
    }
    std::string screen = "\x1b[2J\x1b[H\x1b[?25l\x1b[0m";
    const std::size_t border_width = static_cast<std::size_t>(std::max(0, client.columns - 2));
    const bool use_art = !client.new_caller_art.empty() && client.columns >= 80 && client.rows >= 24;
    if (use_art) {
        screen += render_screen_art(client, client.new_caller_art);
        screen += "\x1b[0m";
    } else {
        screen += "\x1b[96m+" + std::string(border_width, '-') + "+\x1b[0m\r\n";
        screen += "\x1b[96m|\x1b[0m  RENEGADE NEW USER APPLICATION\r\n";
    }
    screen += "\x1b[96m|\x1b[0m  Profile " + std::to_string(field + 1) + " of " +
        std::to_string(client.application_questions.size()) + "\r\n";
    screen += "\x1b[96m|\x1b[0m\r\n";
    screen += "\x1b[96m|\x1b[0m  Handle: \x1b[97m" + client.handle + "\x1b[0m\r\n";
    screen += "\x1b[96m|\x1b[0m  Your account will remain pending until a SysOp approves it.\r\n";
    screen += "\x1b[96m|\x1b[0m  Leave optional details blank to skip.\r\n";
    screen += "\x1b[96m|\x1b[0m\r\n";
    std::string prompt(question.prompt);
    if (question.field == ApplicationAnswerField::ForgotPasswordAnswer) {
        prompt += ": " + client.application_recovery_question;
    }
    const bool yes_no_question = question.field == ApplicationAnswerField::AnsiColor ||
        question.field == ApplicationAnswerField::ClearScreen ||
        question.field == ApplicationAnswerField::PagePause ||
        question.field == ApplicationAnswerField::Hotkeys ||
        question.field == ApplicationAnswerField::ExpertMode ||
        question.field == ApplicationAnswerField::Mailbox;
    screen += "\x1b[96m|\x1b[0m  " + prompt +
        " (optional, up to " + std::to_string(question.maximum) + " characters)\r\n";
    screen += yes_no_question
        ? "\x1b[96m|\x1b[0m  Enter Y or N; blank keeps the current setting.\r\n"
        : "\x1b[96m|\x1b[0m  Press Enter to continue; blank skips.\r\n";
    screen += "\x1b[96m|\x1b[0m\r\n";
    screen += "\x1b[96m|\x1b[0m  > \x1b[97m" + displayed_input + "\x1b[0m\r\n";
    screen += "\x1b[96m+" + std::string(border_width, '-') + "+\x1b[0m\r\n\x1b[?25h";
    if (!write_channel(client, screen)) {
        client.close_requested = true;
    }
}

void handle_new_user_questionnaire_input(ClientContext& client, char character) {
    if (client.application_questions.empty()) {
        client.collecting_application_profile = false;
        show_pending_application(client);
        return;
    }
    if (character == '\r' || character == '\n') {
        client.ignore_line_feed = character == '\r';
        if (client.application_profile_field >= client.application_questions.size()) {
            client.collecting_application_profile = false;
            show_pending_application(client);
            return;
        }
        const ApplicationQuestion& question =
            client.application_questions[client.application_profile_field];
        AccountProfile updated = client.profile;
        try {
            const auto parse_yes_no = [](std::string_view answer) {
                if (answer.empty()) {
                    return std::optional<bool>{};
                }
                const char value = static_cast<char>(
                    std::toupper(static_cast<unsigned char>(answer.front())));
                if (value == 'Y') {
                    return std::optional<bool>{true};
                }
                if (value == 'N') {
                    return std::optional<bool>{false};
                }
                throw std::invalid_argument("enter Y, N, or leave the setting unchanged");
            };
            switch (question.field) {
            case ApplicationAnswerField::RealName:
                updated.real_name = client.application_profile_input;
                break;
            case ApplicationAnswerField::Country:
                if (client.application_profile_input.empty()) {
                    updated.country.clear();
                } else if (client.application_profile_input == "1") {
                    updated.country = "USA";
                } else if (client.application_profile_input == "2") {
                    updated.country = "Canada";
                } else if (client.application_profile_input == "3") {
                    updated.country = "Other";
                } else {
                    throw std::invalid_argument("choose 1 for USA, 2 for Canada, or 3 for other");
                }
                break;
            case ApplicationAnswerField::Street:
                updated.street = client.application_profile_input;
                break;
            case ApplicationAnswerField::CityState:
                updated.city_state = client.application_profile_input;
                updated.location = client.application_profile_input;
                break;
            case ApplicationAnswerField::PostalCode:
                updated.postal_code = client.application_profile_input;
                break;
            case ApplicationAnswerField::Phone:
                updated.phone = client.application_profile_input;
                break;
            case ApplicationAnswerField::BirthDate:
                updated.birth_date = client.application_profile_input;
                break;
            case ApplicationAnswerField::Sex:
                updated.sex = client.application_profile_input.empty()
                    ? '\0' : client.application_profile_input.front();
                break;
            case ApplicationAnswerField::UserAnswer1:
                updated.user_answers[0] = client.application_profile_input;
                break;
            case ApplicationAnswerField::UserAnswer2:
                updated.user_answers[1] = client.application_profile_input;
                break;
            case ApplicationAnswerField::UserAnswer3:
                updated.user_answers[2] = client.application_profile_input;
                break;
            case ApplicationAnswerField::ForgotPasswordAnswer:
                client.accounts->set_forgot_password_answer(
                    client.handle, client.application_profile_input);
                break;
            case ApplicationAnswerField::Signature:
                updated.signature = client.application_profile_input;
                break;
            case ApplicationAnswerField::AnsiColor:
                if (const auto choice = parse_yes_no(client.application_profile_input)) {
                    updated.ansi_color = *choice;
                }
                break;
            case ApplicationAnswerField::ClearScreen:
                if (const auto choice = parse_yes_no(client.application_profile_input)) {
                    updated.clear_screen = *choice;
                }
                break;
            case ApplicationAnswerField::PagePause:
                if (const auto choice = parse_yes_no(client.application_profile_input)) {
                    updated.pause_screens = *choice;
                }
                break;
            case ApplicationAnswerField::Hotkeys:
                if (const auto choice = parse_yes_no(client.application_profile_input)) {
                    updated.hotkeys = *choice;
                }
                break;
            case ApplicationAnswerField::ExpertMode:
                if (const auto choice = parse_yes_no(client.application_profile_input)) {
                    updated.expert_mode = *choice;
                }
                break;
            case ApplicationAnswerField::Mailbox:
                if (const auto choice = parse_yes_no(client.application_profile_input)) {
                    updated.mailbox_closed = !*choice;
                }
                break;
            }
            if (question.field != ApplicationAnswerField::ForgotPasswordAnswer) {
                client.accounts->update_profile(updated);
                client.profile = std::move(updated);
            }
        } catch (const std::exception& error) {
            std::cerr << "Could not save new-user profile for " << client.handle << ": "
                      << error.what() << '\n';
            (void)write_channel(client, "\r\nProfile answer could not be saved: " +
                std::string(error.what()) + "\r\n");
            show_new_user_questionnaire(client);
            return;
        }
        client.application_profile_input.clear();
        ++client.application_profile_field;
        if (client.application_profile_field >= client.application_questions.size()) {
            client.collecting_application_profile = false;
            show_pending_application(client);
        } else {
            show_new_user_questionnaire(client);
        }
        return;
    }
    if (character == '\b' || character == 127) {
        if (!client.application_profile_input.empty()) {
            client.application_profile_input.pop_back();
            show_new_user_questionnaire(client);
        }
        return;
    }
    const unsigned char byte = static_cast<unsigned char>(character);
    const std::size_t field = std::min(
        client.application_profile_field, client.application_questions.size() - 1);
    if (byte >= 32 && byte != 127 && client.application_profile_input.size() <
        client.application_questions[field].maximum) {
        client.application_profile_input.push_back(character);
        if (client.application_questions[field].secret) {
            (void)write_channel(client, "*");
        } else {
            (void)write_channel(client, std::string_view(&character, 1));
        }
    }
}

void show_artwork(ClientContext& client) {
    if (client.art_catalog == nullptr || client.art_catalog->empty()) {
        (void)write_channel(client, "\a");
        return;
    }
    client.art_index %= client.art_catalog->size();
    const AnsiArtwork& artwork = (*client.art_catalog)[client.art_index];
    if (write_channel(client, artwork_screen(
            artwork, client.art_index + 1, client.art_catalog->size(), client.columns, client.rows))) {
        client.viewing_art = true;
        client.waiting_for_return = false;
    } else {
        client.close_requested = true;
    }
}

void show_bulletins(ClientContext& client) {
    if (client.bulletin_catalog == nullptr || client.bulletin_catalog->empty()) {
        (void)write_channel(client, "\r\nNo bulletin files are available.\r\n");
        client.viewing_bulletins = false;
        client.waiting_for_return = true;
        return;
    }
    const std::size_t count = std::min<std::size_t>(client.bulletin_catalog->size(), 26);
    client.bulletin_index %= count;
    const std::string screen = client.reading_bulletin
        ? bulletin_article_screen((*client.bulletin_catalog)[client.bulletin_index],
            client.bulletin_index + 1, count, client.columns, client.rows)
        : bulletin_list_screen(*client.bulletin_catalog, client.columns, client.rows,
            render_screen_art(client, client.bulletin_art), client.bulletin_index);
    if (write_channel(client, screen)) {
        client.viewing_bulletins = true;
        client.viewing_art = false;
        client.viewing_areas = false;
        client.viewing_messages = false;
        client.viewing_private_mail = false;
        client.viewing_sysop = false;
        client.viewing_profile = false;
        client.viewing_one_liners = false;
        client.viewing_uploads = false;
        client.viewing_files = false;
        client.waiting_for_return = false;
    } else {
        client.close_requested = true;
    }
}

void show_quote(ClientContext& client, bool choose_random = false) {
    client.quote_options.clear();
    if (client.quote_catalog != nullptr) {
        client.quote_options = *client.quote_catalog;
    }
    if (client.community != nullptr) {
        try {
            for (const CommunityQuote& quote : client.community->approved_quotes()) {
                client.quote_options.push_back({quote.author, quote.text});
            }
        } catch (const std::exception& error) {
            std::cerr << "Could not load caller quotes: " << error.what() << '\n';
        }
    }
    const std::size_t count = client.quote_options.size();
    if (choose_random && count > 0) {
        static thread_local std::mt19937 generator(std::random_device{}());
        std::uniform_int_distribution<std::size_t> choose(0, count - 1);
        client.quote_index = choose(generator);
        client.quote_content_page = 0;
    }
    if (count > 0) {
        client.quote_index %= count;
    } else {
        client.quote_index = 0;
    }
    const AnsiArtwork empty_quote{"", ""};
    const RenderedQuotePage page = quote_screen(
        count > 0 ? client.quote_options[client.quote_index] : empty_quote,
        client.quote_index, count, client.quote_content_page,
        client.columns, client.rows, render_screen_art(client, supplemental_screen_art(
            client, &SupplementalScreenArt::quotes)));
    client.quote_content_page = page.page;
    client.quote_content_page_count = page.page_count;
    if (write_channel(client, page.screen)) {
        client.viewing_quote = true;
        client.viewing_quote_queue = false;
        client.viewing_art = false;
        client.viewing_bulletins = false;
        client.viewing_callers = false;
        client.viewing_statistics = false;
        client.viewing_auto_message = false;
        client.viewing_polls = false;
        client.viewing_one_liners = false;
        client.viewing_uploads = false;
        client.viewing_files = false;
        client.viewing_areas = false;
        client.viewing_messages = false;
        client.viewing_private_mail = false;
        client.viewing_sysop = false;
        client.viewing_profile = false;
        client.waiting_for_return = false;
    } else {
        client.close_requested = true;
    }
}

void show_quote_queue(ClientContext& client) {
    if (!client.is_sysop || client.community == nullptr) {
        (void)write_channel(client, "\a");
        return;
    }
    try {
        client.quote_submissions = client.community->quote_submissions(client.quote_submission_page);
        client.quote_submission_page = client.quote_submissions.page;
        if (client.quote_submissions.entries.empty()) {
            client.quote_submission_selection_index = 0;
            client.selected_quote_submission_id.reset();
        } else {
            client.quote_submission_selection_index = std::min(
                client.quote_submission_selection_index,
                client.quote_submissions.entries.size() - 1);
            if (client.selected_quote_submission_id.has_value() &&
                std::none_of(client.quote_submissions.entries.begin(), client.quote_submissions.entries.end(),
                    [&client](const CommunityQuote& quote) {
                        return quote.id == *client.selected_quote_submission_id;
                    })) {
                client.selected_quote_submission_id.reset();
            }
        }
        if (!client.selected_quote_submission_id.has_value() &&
            !client.quote_submissions.entries.empty()) {
            client.selected_quote_submission_id = client.quote_submissions.entries[
                client.quote_submission_selection_index].id;
        }
        if (write_channel(client, quote_review_screen(client.quote_submissions,
                client.selected_quote_submission_id, client.columns, client.rows,
                render_screen_art(client, supplemental_screen_art(
                    client, &SupplementalScreenArt::quote_review))))) {
            client.viewing_quote_queue = true;
            client.viewing_quote = false;
            client.viewing_callers = false;
            client.viewing_statistics = false;
            client.viewing_auto_message = false;
            client.viewing_polls = false;
            client.viewing_bulletins = false;
            client.viewing_art = false;
            client.viewing_one_liners = false;
            client.viewing_uploads = false;
            client.viewing_files = false;
            client.viewing_areas = false;
            client.viewing_messages = false;
            client.viewing_private_mail = false;
            client.viewing_sysop = false;
            client.viewing_profile = false;
            client.waiting_for_return = false;
        } else {
            client.close_requested = true;
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not load quote submissions: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not load quote submissions.\r\nPress any key to continue.");
        client.viewing_quote_queue = false;
        client.waiting_for_return = true;
    }
}

BbsListing* selected_bbs_listing(ClientContext& client) {
    if (!client.selected_bbs_listing_id.has_value()) {
        return nullptr;
    }
    const auto found = std::find_if(client.bbs_listing_page.entries.begin(),
        client.bbs_listing_page.entries.end(), [&](const BbsListing& listing) {
            return listing.id == *client.selected_bbs_listing_id;
        });
    return found == client.bbs_listing_page.entries.end() ? nullptr : &*found;
}

bool can_manage_bbs_listing(const ClientContext& client, const BbsListing& listing) {
    if (client.is_sysop || listing.owner.size() != client.handle.size()) {
        return client.is_sysop;
    }
    return std::equal(listing.owner.begin(), listing.owner.end(), client.handle.begin(),
        [](unsigned char left, unsigned char right) {
            return std::tolower(left) == std::tolower(right);
        });
}

void show_bbs_directory(ClientContext& client) {
    if (client.community == nullptr) {
        client.close_requested = true;
        return;
    }
    try {
        client.bbs_listing_page = client.community->bbs_listings(client.bbs_listing_page_index);
        client.bbs_listing_page_index = client.bbs_listing_page.page;
        if (client.selected_bbs_listing_id.has_value()) {
            const auto selected = std::find_if(client.bbs_listing_page.entries.begin(),
                client.bbs_listing_page.entries.end(), [&](const BbsListing& entry) {
                    return entry.id == *client.selected_bbs_listing_id;
                });
            if (selected == client.bbs_listing_page.entries.end()) {
                client.selected_bbs_listing_id.reset();
                client.bbs_listing_selection_index = 0;
            } else {
                client.bbs_listing_selection_index = static_cast<std::size_t>(
                    std::distance(client.bbs_listing_page.entries.begin(), selected));
            }
        } else if (!client.bbs_listing_page.entries.empty()) {
            client.bbs_listing_selection_index = std::min(
                client.bbs_listing_selection_index, client.bbs_listing_page.entries.size() - 1);
            client.selected_bbs_listing_id = client.bbs_listing_page.entries[
                client.bbs_listing_selection_index].id;
        }
        const std::string screen = bbs_directory_screen(client.bbs_listing_page,
            client.selected_bbs_listing_id, client.columns, client.rows,
            render_screen_art(client, client.bbs_art));
        if (!write_channel(client, screen)) {
            client.close_requested = true;
            return;
        }
        client.viewing_bbs_directory = true;
        client.viewing_bbs_detail = false;
        client.editing_bbs_listing = false;
        client.confirming_bbs_delete = false;
        client.viewing_art = false;
        client.viewing_bulletins = false;
        client.viewing_polls = false;
        client.viewing_callers = false;
        client.viewing_statistics = false;
        client.viewing_quote = false;
        client.viewing_quote_queue = false;
        client.viewing_auto_message = false;
        client.viewing_one_liners = false;
        client.waiting_for_return = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not read BBS directory: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read the BBS directory.\r\nPress any key to continue.");
        client.viewing_bbs_directory = false;
        client.waiting_for_return = true;
    }
}

void show_bbs_detail(ClientContext& client) {
    BbsListing* listing = selected_bbs_listing(client);
    if (listing == nullptr) {
        (void)write_channel(client, "\a");
        return;
    }
    std::string screen = bbs_listing_detail_screen(*listing, client.bbs_detail_page,
        can_manage_bbs_listing(client, *listing), client.columns, client.rows,
        render_screen_art(client, client.bbs_art));
    if (client.confirming_bbs_delete) {
        screen += "\x1b[" + std::to_string(client.rows - 1) + ";4H\x1b[KDelete " +
            listing->bbs_name + "? Press Y or N.";
    }
    if (!write_channel(client, screen)) {
        client.close_requested = true;
        return;
    }
    client.viewing_bbs_directory = true;
    client.viewing_bbs_detail = true;
    client.waiting_for_return = false;
}

void redraw_bbs_listing_editor(ClientContext& client) {
    if (client.bbs_edit_field >= kBbsDirectoryFields.size()) {
        return;
    }
    std::string screen;
    BbsListing* existing = selected_bbs_listing(client);
    if (client.editing_bbs_listing_id.has_value() && existing != nullptr) {
        screen = bbs_listing_detail_screen(*existing, client.bbs_detail_page,
            can_manage_bbs_listing(client, *existing), client.columns, client.rows,
            render_screen_art(client, client.bbs_art));
    } else {
        screen = bbs_directory_screen(client.bbs_listing_page,
            client.selected_bbs_listing_id, client.columns, client.rows,
            render_screen_art(client, client.bbs_art));
    }
    const BbsDirectoryField& field = kBbsDirectoryFields[client.bbs_edit_field];
    const std::string& current = client.bbs_listing_draft.*(field.value);
    screen += "\x1b[" + std::to_string(client.rows - 1) + ";4H\x1b[K" +
        std::string(field.label) + " (" + std::to_string(client.bbs_edit_field + 1) + "/" +
        std::to_string(kBbsDirectoryFields.size()) + ", max " + std::to_string(field.maximum) +
        "; Enter keeps current, /clear empties, Esc cancels)";
    if (!current.empty()) {
        screen += " [" + current + "]";
    }
    screen += " > " + client.bbs_listing_input + "\x1b[?25h";
    if (!write_channel(client, screen)) {
        client.close_requested = true;
    }
}

void start_bbs_listing_edit(ClientContext& client, bool create_new) {
    if (!create_new) {
        BbsListing* listing = selected_bbs_listing(client);
        if (listing == nullptr || !can_manage_bbs_listing(client, *listing)) {
            (void)write_channel(client, "\a");
            return;
        }
        client.bbs_listing_draft = *listing;
        client.editing_bbs_listing_id = listing->id;
    } else {
        client.bbs_listing_draft = {};
        client.editing_bbs_listing_id.reset();
        client.selected_bbs_listing_id.reset();
    }
    client.bbs_edit_field = 0;
    client.bbs_listing_input.clear();
    client.editing_bbs_listing = true;
    client.confirming_bbs_delete = false;
    redraw_bbs_listing_editor(client);
}

void save_bbs_listing(ClientContext& client) {
    try {
        if (client.editing_bbs_listing_id.has_value()) {
            client.community->update_bbs_listing(*client.editing_bbs_listing_id,
                client.handle, client.is_sysop, client.bbs_listing_draft);
            client.selected_bbs_listing_id = client.editing_bbs_listing_id;
            client.bbs_listing_page_index = client.community->bbs_listing_page_for(
                *client.editing_bbs_listing_id);
            std::clog << "Caller " << client.handle << " updated BBS directory entry "
                      << *client.editing_bbs_listing_id << ".\n";
        } else {
            const std::int64_t id = client.community->add_bbs_listing(
                client.handle, client.bbs_listing_draft);
            client.selected_bbs_listing_id = id;
            client.bbs_listing_page_index = client.community->bbs_listing_page_for(id);
            std::clog << "Caller " << client.handle << " added BBS directory entry " << id << ".\n";
        }
        client.editing_bbs_listing = false;
        client.editing_bbs_listing_id.reset();
        client.bbs_listing_input.clear();
        show_bbs_directory(client);
    } catch (const std::exception& error) {
        std::cerr << "Could not save BBS directory entry: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not save listing: " + std::string(error.what()) + "\r\n");
        client.bbs_edit_field = 0;
        client.bbs_listing_input.clear();
        redraw_bbs_listing_editor(client);
    }
}

void show_message_areas(ClientContext& client) {
    if (client.messages == nullptr) {
        client.close_requested = true;
        return;
    }
    client.reader_message.reset();
    client.reader_backstack.clear();
    client.reading_message = false;
    try {
        client.board_areas = client.messages->areas(client.handle, false, true);
        const std::size_t page_count = std::max<std::size_t>(1, (client.board_areas.size() + 9) / 10);
        client.area_page = std::min(client.area_page, page_count - 1);
        if (client.board_areas.empty()) {
            client.message_area_selection_index = 0;
        } else {
            client.message_area_selection_index = std::min(
                client.message_area_selection_index, client.board_areas.size() - 1);
            if (client.message_area_selection_index / 10 != client.area_page) {
                client.message_area_selection_index = client.area_page * 10;
            }
        }
        const RenderedAreaPage page = message_areas_screen(
            client.board_areas, client.area_page, client.current_area, client.columns, client.rows,
            render_screen_art(client, client.areas_art), client.message_area_selection_index);
        if (write_channel(client, page.screen)) {
            client.viewing_areas = true;
            client.viewing_message_scan_settings = false;
            client.viewing_messages = false;
            client.viewing_new_scan = false;
            client.reading_from_new_scan = false;
            client.viewing_private_mail = false;
            client.reading_message = false;
            client.reading_private_message = false;
            client.reader_message.reset();
            client.reader_backstack.clear();
            client.waiting_for_return = false;
        } else {
            client.close_requested = true;
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not read message areas: " << error.what() << '\n';
        client.close_requested = true;
    }
}

void show_message_scan_settings(ClientContext& client) {
    if (client.messages == nullptr) {
        client.close_requested = true;
        return;
    }
    try {
        client.board_areas = client.messages->areas(client.handle);
        const std::size_t page_count = std::max<std::size_t>(
            1, (client.board_areas.size() + 9) / 10);
        client.area_page = std::min(client.area_page, page_count - 1);
        if (client.board_areas.empty()) {
            client.message_area_selection_index = 0;
        } else {
            client.message_area_selection_index = std::min(
                client.message_area_selection_index, client.board_areas.size() - 1);
            client.area_page = client.message_area_selection_index / 10;
        }
        const std::string screen = message_scan_settings_screen(
            client.board_areas, client.area_page, client.columns, client.rows,
            render_screen_art(client, supplemental_screen_art(
                client, &SupplementalScreenArt::message_scan)), client.message_area_selection_index);
        if (write_channel(client, screen)) {
            client.viewing_areas = false;
            client.viewing_message_scan_settings = true;
            client.viewing_messages = false;
            client.viewing_new_scan = false;
            client.viewing_private_mail = false;
            client.reading_message = false;
            client.reading_private_message = false;
            client.waiting_for_return = false;
        } else {
            client.close_requested = true;
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not read message scan settings: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not read message scan settings.\r\n");
        show_message_areas(client);
    }
}

void apply_area_real_name_display(
    ClientContext& client, BoardMessage& message, std::string_view area);

void remember_message_area(ClientContext& client, std::string_view area) {
    if (client.messages == nullptr) {
        return;
    }
    try {
        client.messages->set_last_area(client.handle, area);
    } catch (const std::exception& error) {
        std::cerr << "Could not save last message area for " << client.handle << ": "
                  << error.what() << '\n';
    }
}

void show_message_board(ClientContext& client) {
    if (client.messages == nullptr) {
        client.close_requested = true;
        return;
    }
    try {
        const auto accessible_areas = client.messages->areas(client.handle);
        const auto current = std::find_if(accessible_areas.begin(), accessible_areas.end(),
            [&client](const BoardArea& area) {
                return ::strcasecmp(area.name.c_str(), client.current_area.c_str()) == 0;
            });
        if (current != accessible_areas.end() && current->password_protected &&
            !client.unlocked_message_areas.contains(current->id)) {
            client.pending_message_area_id = current->id;
            client.pending_parent_message_id.reset();
            client.entering_message_area_password = true;
            client.message_line.clear();
            (void)write_channel(client, "\r\nMessage area: " + current->name + "\r\nPassword: ");
            return;
        }
        client.reader_message.reset();
        client.reader_backstack.clear();
        client.reading_message = false;
        BoardMessagePage page;
        std::vector<std::string> result_areas;
        if (client.searching_messages && client.message_search_all_areas) {
            std::vector<BoardArea> areas = client.messages->areas(client.handle);
            std::sort(areas.begin(), areas.end(), [](const BoardArea& left, const BoardArea& right) {
                return left.id < right.id;
            });
            std::vector<LocatedBoardMessage> results;
            std::size_t unread_total{};
            for (const BoardArea& area : areas) {
                if (area.password_protected && !client.unlocked_message_areas.contains(area.id)) {
                    continue;
                }
                std::size_t subpage = 0;
                BoardMessagePage area_page = client.messages->search_page(
                    area.name, client.handle, client.message_search_query, client.message_search_field,
                    client.message_search_new_only, subpage, 50);
                unread_total += area_page.unread_total;
                for (;;) {
                    for (BoardMessage& message : area_page.messages) {
                        results.push_back({std::move(message), area.name});
                    }
                    if (subpage + 1 >= area_page.page_count) {
                        break;
                    }
                    area_page = client.messages->search_page(
                        area.name, client.handle, client.message_search_query, client.message_search_field,
                        client.message_search_new_only, ++subpage, 50);
                }
            }
            const std::size_t total = results.size();
            const std::size_t page_count = total / 10 + (total % 10 == 0 ? 0 : 1);
            const std::size_t selected_page = std::min(
                client.message_list_page, page_count == 0 ? 0 : page_count - 1);
            const std::size_t first = selected_page * 10;
            const std::size_t last = std::min(first + 10, total);
            std::vector<BoardMessage> selected_messages;
            for (std::size_t index = first; index < last; ++index) {
                result_areas.push_back(results[index].area_name);
                selected_messages.push_back(std::move(results[index].message));
            }
            page = {std::move(selected_messages), selected_page,
                std::max<std::size_t>(1, page_count), total, unread_total};
        } else if (client.searching_messages) {
            page = client.messages->search_page(client.current_area, client.handle,
                client.message_search_query, client.message_search_field,
                client.message_search_new_only, client.message_list_page, 10);
        } else {
            page = client.messages->board_page(client.current_area, client.handle,
                client.message_list_page, 10, client.unread_only_messages);
        }
        client.board_message_areas = std::move(result_areas);
        client.board_areas = client.messages->areas(client.handle);
        const bool can_validate_all = !client.message_search_all_areas &&
            client.messages->can_moderate_area(client.handle, client.current_area);
        client.board_messages = std::move(page.messages);
        std::vector<BoardMessage> displayed_messages = client.board_messages;
        for (std::size_t index = 0; index < displayed_messages.size(); ++index) {
            const std::string_view area_name = client.message_search_all_areas &&
                    index < client.board_message_areas.size()
                ? std::string_view(client.board_message_areas[index])
                : std::string_view(client.current_area);
            const auto area = std::find_if(client.board_areas.begin(), client.board_areas.end(),
                [area_name](const BoardArea& item) {
                    return ::strcasecmp(item.name.c_str(), area_name.data()) == 0;
                });
            if (area != client.board_areas.end() && area->use_real_names) {
                apply_area_real_name_display(client, displayed_messages[index], area_name);
            }
        }
        client.message_list_page = page.page;
        client.message_list_page_count = page.page_count;
        if (client.board_messages.empty()) {
            client.message_list_selection_index = 0;
        } else {
            client.message_list_selection_index = std::min(
                client.message_list_selection_index, client.board_messages.size() - 1);
        }
        if (write_channel(client, message_board_screen(
                displayed_messages, client.board_message_areas,
                client.searching_messages && client.message_search_all_areas
                    ? std::string_view("All accessible areas") : std::string_view(client.current_area),
                client.message_list_page,
                client.message_list_page_count, page.total, page.unread_total,
                client.searching_messages ? client.message_search_new_only : client.unread_only_messages,
                client.searching_messages, can_validate_all, client.columns, client.rows,
                render_screen_art(client, client.board_art), client.message_list_selection_index))) {
            client.viewing_areas = false;
            client.viewing_messages = true;
            client.viewing_new_scan = false;
            client.reading_from_new_scan = false;
            client.viewing_private_mail = false;
            client.reading_message = false;
            client.reading_private_message = false;
            client.reader_message.reset();
            client.reader_backstack.clear();
            client.waiting_for_return = false;
        } else {
            client.close_requested = true;
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not read message board: " << error.what() << '\n';
        client.close_requested = true;
    }
}

void show_message_search_prompt(ClientContext& client, bool entering_query) {
    client.viewing_areas = false;
    client.viewing_messages = true;
    client.viewing_private_mail = false;
    client.reading_message = false;
    client.reader_message.reset();
    if (!write_channel(client, message_search_screen(
            client.message_search_all_areas ? "All accessible areas" : client.current_area,
            entering_query ? client.message_line : client.message_search_query,
            entering_query, client.message_search_new_only, client.message_search_all_areas,
            client.columns, client.rows, render_screen_art(client, supplemental_screen_art(
                client, &SupplementalScreenArt::message_search)),
            client.message_search_selection_index))) {
        client.close_requested = true;
    }
}

void begin_message_search(ClientContext& client) {
    client.searching_messages = false;
    client.entering_message_search_query = true;
    client.choosing_message_search_field = false;
    client.message_search_new_only = false;
    client.message_search_all_areas = false;
    client.message_search_selection_index = 0;
    client.message_search_query.clear();
    client.message_line.clear();
    client.message_list_page = 0;
    show_message_search_prompt(client, true);
}

void cancel_message_search(ClientContext& client) {
    client.searching_messages = false;
    client.entering_message_search_query = false;
    client.choosing_message_search_field = false;
    client.message_search_new_only = false;
    client.message_search_all_areas = false;
    client.message_search_query.clear();
    client.message_line.clear();
    client.message_list_page = 0;
    show_message_board(client);
}

void show_selected_message(ClientContext& client);

void select_board_message(ClientContext& client, std::size_t index) {
    if (index >= client.board_messages.size()) {
        (void)write_channel(client, "\a");
        return;
    }
    client.message_list_selection_index = index;
    client.message_index = index;
    client.message_page = 0;
    client.reader_backstack.clear();
    if (client.searching_messages && client.message_search_all_areas &&
        index < client.board_message_areas.size()) {
        client.current_area = client.board_message_areas[index];
        remember_message_area(client, client.current_area);
    }
    client.reader_message = client.board_messages[index];
    show_selected_message(client);
}

std::string single_line_export_text(std::string_view value) {
    std::string result = sanitize_terminal_text(value);
    for (char& character : result) {
        if (character == '\r' || character == '\n') {
            character = ' ';
        }
    }
    return result;
}

std::string strip_message_color_codes(std::string_view body) {
    std::string result;
    result.reserve(body.size());
    for (std::size_t index = 0; index < body.size();) {
        if (body[index] == '\x1b') {
            ++index;
            if (index < body.size() && body[index] == '[') {
                ++index;
                while (index < body.size() &&
                    !(static_cast<unsigned char>(body[index]) >= 0x40 &&
                      static_cast<unsigned char>(body[index]) <= 0x7e)) {
                    ++index;
                }
                if (index < body.size()) {
                    ++index;
                }
            } else if (index < body.size()) {
                ++index;
            }
            continue;
        }
        if (body[index] == '^' && index + 1 < body.size()) {
            index += 2;
            continue;
        }
        result.push_back(body[index++]);
    }
    return sanitize_terminal_text(result);
}

std::string export_message_to_sftp_inbox(
    ClientContext& client,
    std::string_view message_kind,
    long long message_id,
    std::string_view content) {
    if (client.files == nullptr || !valid_handle(client.handle) || message_id < 1) {
        throw std::runtime_error("the private SFTP inbox is unavailable");
    }
    const std::string incoming_path = client.files->root_path() + "/incoming";
    ScopedFileDescriptor incoming(::open(incoming_path.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (incoming.get() < 0) {
        throw std::runtime_error("could not open the private SFTP inbox: " +
            std::string(std::strerror(errno)));
    }
    if (::mkdirat(incoming.get(), client.handle.c_str(), S_IRWXU) != 0 && errno != EEXIST) {
        throw std::runtime_error("could not prepare the private SFTP inbox: " +
            std::string(std::strerror(errno)));
    }
    ScopedFileDescriptor user_directory(::openat(incoming.get(), client.handle.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (user_directory.get() < 0) {
        throw std::runtime_error("could not open the private SFTP inbox: " +
            std::string(std::strerror(errno)));
    }

    const std::string stem = "renegade-" + std::string(message_kind) + "-message-" +
        std::to_string(message_id);
    for (int suffix = 1; suffix <= 100; ++suffix) {
        const std::string filename = stem + (suffix == 1 ? "" : "-" + std::to_string(suffix)) + ".txt";
        ScopedFileDescriptor output(::openat(user_directory.get(), filename.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR));
        if (output.get() < 0) {
            if (errno == EEXIST) {
                continue;
            }
            throw std::runtime_error("could not create the SFTP export: " +
                std::string(std::strerror(errno)));
        }
        std::size_t written = 0;
        while (written < content.size()) {
            const ssize_t count = ::write(output.get(), content.data() + written, content.size() - written);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                const int error = errno;
                (void)::unlinkat(user_directory.get(), filename.c_str(), 0);
                throw std::runtime_error("could not write the SFTP export: " +
                    std::string(std::strerror(error)));
            }
            written += static_cast<std::size_t>(count);
        }
        if (::fsync(output.get()) != 0) {
            const int error = errno;
            (void)::unlinkat(user_directory.get(), filename.c_str(), 0);
            throw std::runtime_error("could not save the SFTP export: " +
                std::string(std::strerror(error)));
        }
        return "/incoming/" + filename;
    }
    throw std::runtime_error("too many exports already exist for this message");
}

void show_unread_messages(ClientContext& client) {
    if (client.messages == nullptr) {
        client.close_requested = true;
        return;
    }
    try {
        const std::vector<long long> unlocked(
            client.unlocked_message_areas.begin(), client.unlocked_message_areas.end());
        client.new_scan_page = client.messages->unread_messages(
            client.handle, client.new_scan_page_index, 10, unlocked);
        client.new_scan_page_index = client.new_scan_page.page;
        if (client.new_scan_page.messages.empty()) {
            client.new_scan_selection_index = 0;
        } else {
            client.new_scan_selection_index = std::min(
                client.new_scan_selection_index, client.new_scan_page.messages.size() - 1);
        }
        if (!write_channel(client, unread_messages_screen(
                client.new_scan_page, client.columns, client.rows,
                render_screen_art(client, supplemental_screen_art(
                    client, &SupplementalScreenArt::unread_messages)), client.new_scan_selection_index))) {
            client.close_requested = true;
            return;
        }
        client.viewing_new_scan = true;
        client.viewing_areas = false;
        client.viewing_messages = false;
        client.reading_message = false;
        client.viewing_private_mail = false;
        client.viewing_sysop = false;
        client.viewing_sysop_areas = false;
        client.viewing_profile = false;
        client.viewing_files = false;
        client.viewing_uploads = false;
        client.waiting_for_return = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not scan unread messages: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not scan unread messages.\r\nPress any key to continue.");
        client.viewing_new_scan = false;
        client.waiting_for_return = true;
    }
}

void select_message_area(ClientContext& client, std::size_t index) {
    if (index >= client.board_areas.size()) {
        (void)write_channel(client, "\a");
        return;
    }
    BoardArea selected = client.board_areas[index];
    try {
        const std::vector<BoardArea> current_areas = client.messages->areas(client.handle, false, true);
        const auto current = std::find_if(current_areas.begin(), current_areas.end(), [&selected](const BoardArea& area) {
            return area.id == selected.id;
        });
        if (current == current_areas.end()) {
            (void)write_channel(client, "\r\nThat message area is no longer available.\r\n");
            show_message_areas(client);
            return;
        }
        selected = *current;
    } catch (const std::exception& error) {
        std::cerr << "Could not recheck message-area access: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not verify message-area access.\r\n");
        show_message_areas(client);
        return;
    }
    if (!selected.accessible) {
        (void)write_channel(client, "\r\nThis area is visible, but its access rule prevents entry.\r\n");
        show_message_areas(client);
        return;
    }
    if (selected.password_protected && !client.unlocked_message_areas.contains(selected.id)) {
        client.pending_message_area_id = selected.id;
        client.pending_parent_message_id.reset();
        client.entering_message_area_password = true;
        client.message_line.clear();
        (void)write_channel(client, "\r\nMessage area: " + selected.name + "\r\nPassword: ");
        return;
    }
    client.current_area = selected.name;
    remember_message_area(client, client.current_area);
    client.message_list_page = 0;
    client.message_list_selection_index = 0;
    client.unread_only_messages = false;
    client.searching_messages = false;
    client.entering_message_search_query = false;
    client.choosing_message_search_field = false;
    client.message_search_all_areas = false;
    client.message_search_query.clear();
    client.message_line.clear();
    show_message_board(client);
}

void open_parent_message(ClientContext& client, long long message_id) {
    if (client.messages == nullptr || !client.reader_message.has_value()) {
        (void)write_channel(client, "\a");
        return;
    }
    try {
        const auto parent = client.messages->find_with_area(client.handle, message_id);
        if (!parent.has_value()) {
            (void)write_channel(client, "\a");
            return;
        }
        const auto areas = client.messages->areas(client.handle);
        const auto area = std::find_if(areas.begin(), areas.end(), [&parent](const BoardArea& item) {
            return ::strcasecmp(item.name.c_str(), parent->area_name.c_str()) == 0;
        });
        if (area == areas.end()) {
            (void)write_channel(client, "\a");
            return;
        }
        if (area->password_protected && !client.unlocked_message_areas.contains(area->id)) {
            client.pending_message_area_id = area->id;
            client.pending_parent_message_id = message_id;
            client.entering_message_area_password = true;
            client.message_line.clear();
            (void)write_channel(client, "\r\nMessage area: " + area->name + "\r\nPassword: ");
            return;
        }
        client.reader_backstack.push_back(
            {*client.reader_message, client.message_page, client.current_area});
        client.reader_message = parent->message;
        client.current_area = parent->area_name;
        remember_message_area(client, client.current_area);
        client.message_page = 0;
        show_selected_message(client);
    } catch (const std::exception& error) {
        std::cerr << "Could not open parent message: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not open that parent message.\r\n");
    }
}

std::string render_message_mci(ClientContext& client, std::string_view body) {
    std::string safe_source;
    safe_source.reserve(body.size());
    for (std::size_t index = 0; index < body.size();) {
        if (body[index] == '\x1b') {
            ++index;
            if (index < body.size() && body[index] == '[') {
                ++index;
                while (index < body.size() && !(body[index] >= 0x40 && body[index] <= 0x7e)) {
                    ++index;
                }
                if (index < body.size()) {
                    ++index;
                }
            }
            continue;
        }
        if (body[index] == '%' && index + 2 < body.size()) {
            const char first = static_cast<char>(std::toupper(static_cast<unsigned char>(body[index + 1])));
            const char second = static_cast<char>(std::toupper(static_cast<unsigned char>(body[index + 2])));
            if ((first == 'P' && second == 'A') || (first == '0' && second >= '0' && second <= '9')) {
                index += 3;
                continue;
            }
            if (first == 'X' && second == 'Y') {
                const std::size_t end = body.find('%', index + 3);
                if (end != std::string_view::npos && end - index <= 12) {
                    index = end + 1;
                    continue;
                }
            }
        }
        const unsigned char byte = static_cast<unsigned char>(body[index++]);
        if (byte >= 0x20 || byte == '\r' || byte == '\n' || byte == '\t') {
            safe_source.push_back(static_cast<char>(byte));
        }
    }

    const std::string expanded = render_legacy_display(
        safe_source, screen_mci_values(client), client.columns, client.rows);
    std::string result;
    result.reserve(std::min<std::size_t>(expanded.size(), 16000));
    for (std::size_t index = 0; index < expanded.size() && result.size() < 16000;) {
        const unsigned char byte = static_cast<unsigned char>(expanded[index]);
        if (byte == 0x1b) {
            ++index;
            if (index < expanded.size() && expanded[index] == '[') {
                ++index;
                while (index < expanded.size() && !(expanded[index] >= 0x40 && expanded[index] <= 0x7e)) {
                    ++index;
                }
                if (index < expanded.size()) {
                    ++index;
                }
            }
            continue;
        }
        if ((byte < 0x20 && byte != '\r' && byte != '\n' && byte != '\t') || byte == 0x7f) {
            ++index;
            continue;
        }
        result.push_back(static_cast<char>(byte));
        ++index;
    }
    return result;
}

void apply_area_real_name_display(
    ClientContext& client, BoardMessage& message, std::string_view area) {
    if (client.messages == nullptr) {
        return;
    }
    const bool author_identity_visible = message.anonymous_type == 0 ||
        (!message.owner_handle.empty() &&
            ::strcasecmp(message.author.c_str(), message.owner_handle.c_str()) == 0);
    if (author_identity_visible && valid_handle(message.owner_handle)) {
        message.author = client.messages->area_real_name_label(
            client.handle, area, message.owner_handle);
    }
    if (valid_handle(message.recipient) && ::strcasecmp(message.recipient.c_str(), "All") != 0) {
        message.recipient = client.messages->area_real_name_label(
            client.handle, area, message.recipient);
    }
}

void show_selected_message(ClientContext& client) {
    if (!client.reader_message.has_value()) {
        (void)write_channel(client, "\a");
        return;
    }
    BoardMessage displayed_message = *client.reader_message;
    apply_area_real_name_display(client, displayed_message, client.current_area);
    if (displayed_message.allow_mci) {
        displayed_message.body = render_message_mci(client, displayed_message.body);
    }
    const bool can_toggle_deleted = client.messages != nullptr &&
        !displayed_message.permanent && (::strcasecmp(displayed_message.owner_handle.c_str(), client.handle.c_str()) == 0 ||
            client.messages->can_moderate_area(client.handle, client.current_area));
    const bool can_validate = client.messages != nullptr &&
        client.messages->can_moderate_area(client.handle, client.current_area);
    const bool can_edit = can_validate ||
        ::strcasecmp(displayed_message.owner_handle.c_str(), client.handle.c_str()) == 0;
    const RenderedMessagePage page = message_reader_screen(
        displayed_message, can_toggle_deleted, can_validate, can_edit, client.message_page,
        client.columns, client.rows, render_screen_art(client, client.reader_art));
    if (write_channel(client, page.screen)) {
        try {
            client.messages->mark_read(client.handle, client.current_area, client.reader_message->id);
        } catch (const std::exception& error) {
            std::cerr << "Could not update message read marker: " << error.what() << '\n';
        }
        client.reading_message = true;
        client.message_page_count = page.page_count;
        client.waiting_for_return = false;
    } else {
        client.close_requested = true;
    }
}

std::vector<BoardArea> message_move_targets(ClientContext& client) {
    std::vector<BoardArea> targets = client.messages == nullptr
        ? std::vector<BoardArea>{}
        : client.messages->areas(client.handle);
    if (!client.moving_private_message) {
        targets.erase(std::remove_if(targets.begin(), targets.end(), [&client](const BoardArea& area) {
            return ::strcasecmp(area.name.c_str(), client.current_area.c_str()) == 0;
        }), targets.end());
    }
    return targets;
}

void show_private_mailbox(ClientContext& client);
void show_selected_private_message(ClientContext& client);

void show_message_move_picker(ClientContext& client) {
    if ((client.moving_private_message && !client.private_message.has_value()) ||
        (!client.moving_private_message && !client.reader_message.has_value())) {
        const bool private_source = client.moving_private_message;
        client.selecting_message_move_area = false;
        client.confirming_message_move = false;
        client.moving_private_message = false;
        client.moving_to_private_message = false;
        client.moving_message_id = 0;
        client.message_move_target.clear();
        (void)write_channel(client, "\a");
        if (private_source) {
            show_private_mailbox(client);
        } else {
            show_message_board(client);
        }
        return;
    }
    try {
        const std::vector<BoardArea> targets = message_move_targets(client);
        const bool private_target_available = !client.moving_private_message;
        const std::size_t page_size = private_target_available ? 9 : 10;
        const std::size_t page_count = std::max<std::size_t>(
            1, (targets.size() + page_size - 1) / page_size);
        client.message_move_page = std::min(client.message_move_page, page_count - 1);
        const std::size_t selection_count = targets.size() +
            (private_target_available ? 1 : 0);
        if (selection_count > 0) {
            client.message_move_selection_index = std::min(
                client.message_move_selection_index, selection_count - 1);
            client.message_move_page = private_target_available &&
                    client.message_move_selection_index > 0
                ? (client.message_move_selection_index - 1) / page_size
                : (private_target_available ? 0 : client.message_move_selection_index / page_size);
        } else {
            client.message_move_selection_index = 0;
        }
        const std::string_view source_area = client.moving_private_message
            ? std::string_view("Private mail") : std::string_view(client.current_area);
        if (!write_channel(client, message_move_screen(
                targets, source_area, client.moving_message_id, client.message_move_page,
                page_count, client.confirming_message_move, private_target_available,
                client.message_move_target,
                client.columns, client.rows,
                render_screen_art(client, supplemental_screen_art(
                    client, &SupplementalScreenArt::message_move)),
                client.message_move_selection_index))) {
            client.close_requested = true;
            return;
        }
        client.viewing_messages = !client.moving_private_message;
        client.viewing_private_mail = client.moving_private_message;
        client.reading_message = false;
        client.reading_private_message = false;
        client.waiting_for_return = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not prepare message move: " << error.what() << '\n';
        client.selecting_message_move_area = false;
        client.confirming_message_move = false;
        client.moving_to_private_message = false;
        (void)write_channel(client, "\r\nCould not list destination message areas.\r\n");
        if (client.moving_private_message) {
            client.moving_private_message = false;
            client.moving_message_id = 0;
            client.message_move_target.clear();
            show_selected_private_message(client);
        } else {
            client.moving_message_id = 0;
            client.message_move_target.clear();
            show_selected_message(client);
        }
    }
}

void begin_message_move(ClientContext& client) {
    if (client.messages == nullptr || !client.reader_message.has_value() ||
        !client.messages->can_moderate_area(client.handle, client.current_area)) {
        (void)write_channel(client, "\a");
        return;
    }
    client.selecting_message_move_area = true;
    client.confirming_message_move = false;
    client.moving_private_message = false;
    client.moving_to_private_message = false;
    client.message_move_page = 0;
    client.message_move_selection_index = 0;
    client.moving_message_id = client.reader_message->id;
    client.message_move_target.clear();
    show_message_move_picker(client);
}

void begin_private_message_move(ClientContext& client) {
    if (client.messages == nullptr || !client.private_message.has_value() || !client.is_sysop) {
        (void)write_channel(client, "\a");
        return;
    }
    client.selecting_message_move_area = true;
    client.confirming_message_move = false;
    client.moving_private_message = true;
    client.moving_to_private_message = false;
    client.message_move_page = 0;
    client.message_move_selection_index = 0;
    client.moving_message_id = client.private_message->id;
    client.message_move_target.clear();
    show_message_move_picker(client);
}

void handle_message_move_input(ClientContext& client, char character) {
    const char command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
    const auto cancel = [&client] {
        client.selecting_message_move_area = false;
        client.confirming_message_move = false;
        client.moving_to_private_message = false;
        client.moving_message_id = 0;
        client.message_move_target.clear();
        client.viewing_messages = !client.moving_private_message;
        client.viewing_private_mail = client.moving_private_message;
        if (client.moving_private_message) {
            client.moving_private_message = false;
            show_selected_private_message(client);
        } else {
            show_selected_message(client);
        }
    };
    if (client.confirming_message_move) {
        if (command == 'Y') {
            try {
                const bool private_source = client.moving_private_message;
                const bool private_destination = client.moving_to_private_message;
                const std::string source_area = private_source ? "Private mail" : client.current_area;
                const std::string target_area = private_destination ? "Private mail" : client.message_move_target;
                const long long new_message_id = private_source
                    ? client.messages->move_private_message_to_area(
                        client.handle, client.message_move_target, client.moving_message_id)
                    : (private_destination
                        ? client.messages->move_public_message_to_private(
                            client.handle, client.current_area, client.moving_message_id)
                        : client.messages->move_message(
                            client.handle, client.current_area, client.message_move_target,
                            client.moving_message_id));
                record_sysop_action(client,
                    private_source ? "moved private message to public area"
                        : (private_destination ? "moved public message to private mail" : "moved public message"),
                    "#" + std::to_string(client.moving_message_id) + " " + source_area +
                        " -> " + target_area + " #" + std::to_string(new_message_id));
                std::clog << (private_source ? "SysOp " : "Area moderator ") << client.handle << " moved "
                          << (private_source ? "private" : "public") << " message #"
                          << client.moving_message_id << " from " << source_area << " to "
                          << target_area << " as #" << new_message_id << ".\n";
                if (private_source) {
                    client.private_message->deleted = true;
                } else {
                    client.reader_message->deleted = true;
                }
                client.selecting_message_move_area = false;
                client.confirming_message_move = false;
                client.moving_private_message = false;
                client.moving_to_private_message = false;
                client.moving_message_id = 0;
                client.message_move_target.clear();
                (void)write_channel(client, "\r\nMessage moved.\r\n");
                if (private_source) {
                    client.viewing_messages = false;
                    client.viewing_private_mail = true;
                    show_selected_private_message(client);
                } else {
                    show_selected_message(client);
                }
            } catch (const std::exception& error) {
                client.confirming_message_move = false;
                client.moving_to_private_message = false;
                client.message_move_target.clear();
                const std::string reason = error.what();
                show_message_move_picker(client);
                (void)write_channel(client, "\r\nMessage could not be moved: " + reason +
                    "\r\nChoose another destination or Q to return.");
            }
        } else if (command == 'N') {
            client.confirming_message_move = false;
            client.moving_to_private_message = false;
            client.message_move_target.clear();
            show_message_move_picker(client);
        } else if (command == 'Q' || character == 27) {
            cancel();
        }
        return;
    }

    if (command == 'Q' || character == 27) {
        cancel();
        return;
    }
    const std::vector<BoardArea> targets = message_move_targets(client);
    const bool private_target_available = !client.moving_private_message;
    const std::size_t page_size = private_target_available ? 9 : 10;
    const std::size_t page_count = std::max<std::size_t>(
        1, (targets.size() + page_size - 1) / page_size);
    if ((character == '\r' || character == '\n') &&
        client.message_move_selection_index < targets.size() +
            (private_target_available ? 1 : 0)) {
        if (private_target_available && client.message_move_selection_index == 0) {
            client.message_move_target = "Private mail";
            client.moving_to_private_message = true;
        } else {
            const std::size_t target_index = client.message_move_selection_index -
                (private_target_available ? 1 : 0);
            if (target_index >= targets.size()) {
                (void)write_channel(client, "\a");
                return;
            }
            client.message_move_target = targets[target_index].name;
            client.moving_to_private_message = false;
        }
        client.confirming_message_move = true;
        show_message_move_picker(client);
        return;
    }
    if (command == 'N' && client.message_move_page + 1 < page_count) {
        ++client.message_move_page;
        client.message_move_selection_index = private_target_available
            ? client.message_move_page * page_size + 1
            : client.message_move_page * page_size;
        show_message_move_picker(client);
    } else if (command == 'P' && client.message_move_page > 0) {
        --client.message_move_page;
        client.message_move_selection_index = private_target_available
            ? client.message_move_page * page_size + 1
            : client.message_move_page * page_size;
        show_message_move_picker(client);
    } else if (private_target_available && character == '0') {
        client.message_move_target = "Private mail";
        client.message_move_selection_index = 0;
        client.moving_to_private_message = true;
        client.confirming_message_move = true;
        show_message_move_picker(client);
    } else if ((character >= '1' && character <= '9') || (!private_target_available && character == '0')) {
        const std::size_t slot = character == '0' ? 9 : static_cast<std::size_t>(character - '1');
        const std::size_t index = client.message_move_page * page_size + slot;
        if (index >= targets.size()) {
            (void)write_channel(client, "\a");
            return;
        }
        client.message_move_selection_index = index + (private_target_available ? 1 : 0);
        client.message_move_target = targets[index].name;
        client.moving_to_private_message = false;
        client.confirming_message_move = true;
        show_message_move_picker(client);
    }
}

void show_private_mailbox(ClientContext& client) {
    if (client.messages == nullptr) {
        client.close_requested = true;
        return;
    }
    try {
        PrivateMessagePage page = client.messages->private_mail_page(
            client.handle, client.private_mailbox, client.private_mail_list_page, 10);
        client.private_messages = std::move(page.messages);
        client.private_mail_list_page = page.page;
        client.private_mail_list_page_count = page.page_count;
        if (client.private_messages.empty()) {
            client.private_message_index = 0;
        } else {
            client.private_message_index = std::min(
                client.private_message_index, client.private_messages.size() - 1);
        }
        if (write_channel(client, private_mailbox_screen(
                client.private_messages, client.private_mailbox, client.private_mail_list_page,
                client.private_mail_list_page_count, page.total, page.unread_total,
                client.columns, client.rows, render_screen_art(client, client.mailbox_art),
                client.private_message_index))) {
            client.viewing_areas = false;
            client.viewing_messages = false;
            client.viewing_private_mail = true;
            client.reading_message = false;
            client.reading_private_message = false;
            client.reader_message.reset();
            client.private_message.reset();
            client.reader_backstack.clear();
            client.waiting_for_return = false;
        } else {
            client.close_requested = true;
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not read private mailbox: " << error.what() << '\n';
        client.close_requested = true;
    }
}

bool private_reply_allowed(ClientContext& client, const PrivateMessage& message) {
    if (client.private_mailbox != PrivateMailbox::Inbox || message.deleted) {
        return false;
    }
    if (message.anonymous_type == 2) {
        return client.is_sysop;
    }
    if (message.anonymous_type == 1) {
        try {
            return client.messages != nullptr &&
                client.messages->can_read_private_anonymously(client.handle);
        } catch (const std::exception& error) {
            std::cerr << "Could not check anonymous private-mail reply access: " << error.what() << '\n';
            return false;
        }
    }
    return true;
}

void show_selected_private_message(ClientContext& client) {
    if (client.messages == nullptr || !client.private_message.has_value()) {
        (void)write_channel(client, "\a");
        return;
    }
    try {
        const auto message = client.messages->find_private(client.handle, client.private_message->id);
        if (!message.has_value()) {
            (void)write_channel(client, "\a");
            show_private_mailbox(client);
            return;
        }
        client.private_message = *message;
        const bool is_inbox_message = client.private_mailbox == PrivateMailbox::Inbox;
        const bool allow_reply = private_reply_allowed(client, *client.private_message);
        const bool allow_edit = !is_inbox_message;
        const RenderedMessagePage page = private_message_reader_screen(
            *client.private_message, allow_reply, true, allow_edit, client.is_sysop, client.is_sysop,
            client.private_message_page,
            client.columns, client.rows, render_screen_art(client, supplemental_screen_art(
                client, &SupplementalScreenArt::private_reader)));
        if (!write_channel(client, page.screen)) {
            client.close_requested = true;
            return;
        }
        if (is_inbox_message && !client.private_message->deleted) {
            const bool was_unread = client.private_message->unread;
            try {
                client.messages->mark_private_read(client.handle, client.private_message->id);
                client.private_message->unread = false;
                if (was_unread && client.community != nullptr) {
                    std::string notice = client.handle + " read: " + client.private_message->subject;
                    if (notice.size() > 80) {
                        notice.resize(80);
                    }
                    try {
                        client.community->send_short_message(client.private_message->sender_handle, notice);
                    } catch (const std::exception& error) {
                        std::cerr << "Could not queue private-mail read notice: " << error.what() << '\n';
                    }
                }
            } catch (const std::exception& error) {
                std::cerr << "Could not update private-message read marker: " << error.what() << '\n';
            }
        }
        client.reading_private_message = true;
        client.private_message_page_count = page.page_count;
        client.waiting_for_return = false;
    } catch (const std::exception& error) {
        std::cerr << "Could not read private message: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not open that private message.\r\n");
        show_private_mailbox(client);
    }
}

std::string message_export_document(
    std::string_view kind,
    long long message_id,
    std::string_view area,
    std::string_view sender,
    std::string_view recipient,
    std::string_view subject,
    std::string_view created_at,
    std::string_view body,
    bool strip_colors) {
    std::string document = "Renegade " + std::string(kind) + " message #" +
        std::to_string(message_id) + "\r\n";
    if (!area.empty()) {
        document += "Area: " + single_line_export_text(area) + "\r\n";
    }
    document += "From: " + single_line_export_text(sender) + "\r\n";
    document += "To: " + single_line_export_text(recipient) + "\r\n";
    document += "Subject: " + single_line_export_text(subject) + "\r\n";
    document += "Date: " + single_line_export_text(created_at) + "\r\n\r\n";
    document += strip_colors
        ? strip_message_color_codes(body)
        : sanitize_terminal_art(body);
    if (document.empty() || (document.back() != '\n' && document.back() != '\r')) {
        document += "\r\n";
    }
    document += "\r\n";
    return document;
}

void begin_message_extract(ClientContext& client, bool private_message) {
    if (private_message) {
        if (!client.is_sysop || !client.private_message.has_value()) {
            (void)write_channel(client, "\a");
            return;
        }
    } else if (!client.reader_message.has_value() || client.messages == nullptr ||
        !client.messages->can_moderate_area(client.handle, client.current_area)) {
        (void)write_channel(client, "\a");
        return;
    }
    client.confirming_message_extract = true;
    client.extracting_private_message = private_message;
    (void)write_channel(client,
        "\r\nExport to your SFTP inbox? Y strips color codes, N keeps colors, Q cancels: ");
}

void handle_message_extract_input(ClientContext& client, char character) {
    const char command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
    if (command != 'Y' && command != 'N' && command != 'Q' && character != 27) {
        (void)write_channel(client, "\a");
        return;
    }
    const bool private_source = client.extracting_private_message;
    client.confirming_message_extract = false;
    client.extracting_private_message = false;
    if (command == 'Q' || character == 27) {
        if (private_source) {
            show_selected_private_message(client);
        } else {
            show_selected_message(client);
        }
        return;
    }
    try {
        const bool strip_colors = command == 'Y';
        std::string document;
        const long long message_id = private_source
            ? client.private_message->id : client.reader_message->id;
        if (private_source) {
            const PrivateMessage& message = *client.private_message;
            document = message_export_document("private", message.id, {}, message.sender,
                message.recipient, message.subject,
                message.anonymous_details_visible ? message.created_at : "[Unknown]",
                message.body, strip_colors);
        } else {
            const BoardMessage& message = *client.reader_message;
            document = message_export_document("public", message.id, client.current_area,
                message.author, message.recipient, message.subject, message.created_at,
                message.body, strip_colors);
        }
        const std::string path = export_message_to_sftp_inbox(
            client, private_source ? "private" : "public", message_id, document);
        try {
            record_sysop_action(client,
                private_source ? "exported private message" : "exported public message",
                "#" + std::to_string(message_id) + " to " + path);
        } catch (const std::exception& error) {
            std::cerr << "Could not audit message export: " << error.what() << '\n';
        }
        (void)write_channel(client,
            "\r\nMessage exported to " + path + ". Download it over SFTP.\r\n");
    } catch (const std::exception& error) {
        (void)write_channel(client, "\r\nMessage export failed: " + std::string(error.what()) + "\r\n");
    }
    if (private_source) {
        show_selected_private_message(client);
    } else {
        show_selected_message(client);
    }
}

void enter_private_mail(ClientContext& client) {
    client.private_mailbox = PrivateMailbox::Inbox;
    client.private_mail_list_page = 0;
    client.private_message_index = 0;
    show_private_mailbox(client);
}

void select_private_message(ClientContext& client, std::size_t index) {
    if (index >= client.private_messages.size()) {
        (void)write_channel(client, "\a");
        return;
    }
    client.private_message_index = index;
    client.private_message_page = 0;
    client.private_message = client.private_messages[index];
    show_selected_private_message(client);
}

std::string make_prefixed_subject(std::string_view prefix, std::string_view subject) {
    std::string result(prefix);
    result.append(subject);
    if (result.size() > 80) {
        std::size_t end = 80;
        while (end > 0 && end < result.size() &&
            (static_cast<unsigned char>(result[end]) & 0xc0U) == 0x80U) {
            --end;
        }
        result.resize(end);
    }
    return result;
}

std::string make_reply_subject(std::string_view subject) {
    return make_prefixed_subject("Re: ", subject);
}

std::string make_forwarding_header(std::string_view sender) {
    std::string sender_name(sender);
    bool previous_character_was_letter = false;
    for (char& character : sender_name) {
        const unsigned char value = static_cast<unsigned char>(character);
        const bool is_letter = (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
        if (is_letter) {
            character = static_cast<char>(previous_character_was_letter
                ? std::tolower(value)
                : std::toupper(value));
        }
        previous_character_was_letter = is_letter;
    }
    const auto now = std::chrono::system_clock::now();
    std::string body = "Message forwarded from " + sender_name + "\n";
    body += "Message forwarded on " + format_local_time(now, "%m/%d/%y") + " at " +
        format_local_time(now, "%H:%M") + "\n\n";
    return body;
}

std::string make_reply_quote(
    std::string_view sender,
    std::string_view recipient,
    std::string_view created_at,
    std::string_view original_body,
    int anonymous_type,
    std::string_view posted_as = {},
    std::string_view area_name = {},
    std::string_view quote_start = "^0Quoting message from ^1@F ^0to ^1@T^0",
    std::string_view quote_end = "^0on ^1@D ^0...",
    std::string_view original_subject = {}) {
    if (original_body.empty()) {
        return {};
    }
    std::string display_sender(sender);
    switch (anonymous_type) {
    case 1:
    case 2:
        display_sender = "Anonymous";
        break;
    case 3:
        display_sender = "Abby";
        break;
    case 4:
        display_sender = "Problemed Person";
        break;
    case 5:
        display_sender = posted_as.empty() ? "Anonymous" : std::string(posted_as);
        break;
    default:
        break;
    }
    std::string quote_date(created_at);
    static constexpr std::array<std::string_view, 12> month_names{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    if (created_at.size() >= 16 && created_at[4] == '-' && created_at[7] == '-' &&
        created_at[10] == ' ') {
        unsigned int month{};
        const auto parsed_month = std::from_chars(
            created_at.data() + 5, created_at.data() + 7, month);
        if (parsed_month.ec == std::errc{} && month >= 1 && month <= month_names.size()) {
            quote_date = std::string(created_at.substr(8, 2)) + " " +
                std::string(month_names[month - 1]) + " " +
                std::string(created_at.substr(2, 2)) + "  " +
                std::string(created_at.substr(11, 5));
        }
    }
    const auto expand = [&](std::string_view source) {
        std::string result(source);
        const std::array<std::pair<std::string_view, std::string_view>, 5> substitutions{{
            {"@F", display_sender},
            {"@T", recipient},
            {"@D", quote_date},
            {"@S", original_subject},
            {"@B", area_name},
        }};
        for (const auto& [token, value] : substitutions) {
            std::size_t position = 0;
            while ((position = result.find(token, position)) != std::string::npos) {
                result.replace(position, token.size(), value);
                position += value.size();
            }
        }
        return result;
    };
    const auto truncate_to_codepoints = [](std::string_view value, std::size_t limit) {
        std::size_t bytes = 0;
        std::size_t characters = 0;
        while (bytes < value.size()) {
            const unsigned char byte = static_cast<unsigned char>(value[bytes]);
            if ((byte & 0xc0U) != 0x80U) {
                if (characters == limit) {
                    break;
                }
                ++characters;
            }
            ++bytes;
        }
        return std::string(value.substr(0, bytes));
    };
    std::string quote;
    const std::string expanded_start = expand(quote_start);
    if (!expanded_start.empty()) {
        quote += truncate_to_codepoints(expanded_start, kMessageLineCharacterLimit) + "\n";
    }
    const std::string expanded_end = expand(quote_end);
    if (!expanded_end.empty()) {
        quote += truncate_to_codepoints(expanded_end, kMessageLineCharacterLimit) + "\n";
    }
    quote += "\n";
    std::string prefix = "> ";
    if (anonymous_type == 0 && !sender.empty()) {
        prefix.clear();
        prefix.push_back(static_cast<char>(std::toupper(
            static_cast<unsigned char>(sender.front()))));
        const std::size_t separator = sender.find(' ');
        if (separator != std::string_view::npos && separator + 1 < sender.size()) {
            prefix.push_back(static_cast<char>(std::toupper(
                static_cast<unsigned char>(sender[separator + 1]))));
        } else if (sender.size() > 1) {
            prefix.push_back(static_cast<char>(std::toupper(
                static_cast<unsigned char>(sender[1]))));
        }
        prefix += "> ";
    }
    std::size_t line_count = static_cast<std::size_t>(std::count(quote.begin(), quote.end(), '\n'));
    std::size_t start = 0;
    bool truncated = false;
    while (start < original_body.size()) {
        const std::size_t end = original_body.find('\n', start);
        std::string_view line(original_body.data() + start,
            (end == std::string::npos ? original_body.size() : end) - start);
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
        const std::size_t prefix_check_length = std::min<std::size_t>(4, line.size());
        const bool already_quoted = line.substr(0, prefix_check_length).find("> ") != std::string_view::npos;
        const std::string_view line_prefix = already_quoted ? std::string_view{} : std::string_view(prefix);
        if (line_count >= kMessageLineCountLimit - 1) {
            truncated = true;
            break;
        }
        quote += line_prefix;
        quote += truncate_to_codepoints(line,
            kMessageLineCharacterLimit - utf8_codepoint_count(line_prefix));
        quote.push_back('\n');
        ++line_count;
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    if (truncated) {
        quote += "> ... quote truncated ...\n";
    }
    return quote;
}

void redraw_message_editor(ClientContext& client);

void start_message_post(
    ClientContext& client,
    std::optional<long long> reply_to = std::nullopt,
    std::string_view original_subject = {},
    std::string_view original_recipient = {},
    const BoardMessage* original = nullptr) {
    try {
        if (client.messages == nullptr || !client.messages->can_post_public(
                client.handle, client.current_area, client.public_posts_this_call)) {
            (void)write_channel(client,
                "\r\nPublic posting is unavailable under your area, ACS, per-call, or credit rules.\r\n");
            show_message_board(client);
            return;
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not check public-post policy: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not check posting access.\r\n");
        show_message_board(client);
        return;
    }
    client.viewing_areas = false;
    client.viewing_messages = false;
    client.viewing_private_mail = false;
    client.reading_message = false;
    client.reading_private_message = false;
    client.writing_message = true;
    client.writing_message_body = false;
    client.entering_private_recipient = false;
    client.entering_message_recipient = true;
    client.entering_message_anonymous = false;
    client.entering_message_goto = false;
    client.entering_message_tagline = false;
    client.pending_anonymous_mode = AnonymousMode::Disabled;
    client.message_is_private = false;
    client.message_is_auto = false;
    client.message_is_quote = false;
    client.editing_public_message = false;
    client.editing_private_message = false;
    client.editing_message_id = 0;
    client.message_mci_available = client.messages != nullptr &&
        client.messages->can_use_area_mci(client.handle, client.current_area);
    client.message_mci_enabled = client.message_mci_available;
    client.message_subject.clear();
    client.message_subject_default = reply_to.has_value() ? make_reply_subject(original_subject) : std::string{};
    client.message_recipient_default = reply_to.has_value() && !original_recipient.empty()
        ? std::string(original_recipient)
        : std::string("All");
    client.message_recipient = client.message_recipient_default;
    client.reply_to = reply_to;
    client.private_recipient.clear();
    MessageQuoteTemplates quote_templates{
        "^0Quoting message from ^1@F ^0to ^1@T^0", "^0on ^1@D ^0..."};
    if (reply_to.has_value() && original != nullptr && client.messages != nullptr) {
        try {
            quote_templates = client.messages->area_quote_templates(client.handle, client.current_area);
        } catch (const std::exception& error) {
            std::cerr << "Could not load area quote templates: " << error.what() << '\n';
        }
    }
    std::optional<BoardMessage> quote_source;
    if (reply_to.has_value() && original != nullptr) {
        quote_source = *original;
        apply_area_real_name_display(client, *quote_source, client.current_area);
    }
    client.message_body = reply_to.has_value() && original != nullptr
        ? make_reply_quote(quote_source->author, quote_source->recipient, quote_source->created_at,
            quote_source->body, quote_source->anonymous_type, quote_source->posted_as, client.current_area,
            quote_templates.start, quote_templates.end, original->subject)
        : std::string{};
    client.message_line.clear();
    client.message_line_count = client.message_body.empty() ? 0
        : static_cast<std::size_t>(std::count(client.message_body.begin(), client.message_body.end(), '\n')) +
            static_cast<std::size_t>(client.message_body.back() != '\n');
    redraw_message_editor(client);
}

void start_message_edit(ClientContext& client) {
    if (!client.reader_message.has_value()) {
        (void)write_channel(client, "\a");
        return;
    }
    client.viewing_messages = false;
    client.reading_message = false;
    client.writing_message = true;
    client.writing_message_body = true;
    client.entering_private_recipient = false;
    client.entering_message_recipient = false;
    client.entering_message_anonymous = false;
    client.entering_message_goto = false;
    client.entering_message_tagline = false;
    client.pending_anonymous_mode = AnonymousMode::Disabled;
    client.message_is_private = false;
    client.message_is_auto = false;
    client.message_is_quote = false;
    client.editing_public_message = true;
    client.editing_private_message = false;
    client.editing_message_id = client.reader_message->id;
    client.message_mci_available = false;
    client.message_mci_enabled = false;
    client.message_subject = client.reader_message->subject;
    client.message_subject_default.clear();
    client.message_recipient = client.reader_message->recipient;
    client.message_recipient_default.clear();
    client.reply_to = client.reader_message->reply_to;
    client.private_recipient.clear();
    client.message_body = client.reader_message->body;
    client.message_line.clear();
    client.message_line_count = client.message_body.empty() ? 0
        : static_cast<std::size_t>(std::count(client.message_body.begin(), client.message_body.end(), '\n')) +
            static_cast<std::size_t>(client.message_body.back() != '\n');
    redraw_message_editor(client);
}

void start_private_message_edit(ClientContext& client) {
    if (!client.private_message.has_value() || client.private_mailbox != PrivateMailbox::Outbox) {
        (void)write_channel(client, "\a");
        return;
    }
    client.viewing_private_mail = false;
    client.reading_private_message = false;
    client.writing_message = true;
    client.writing_message_body = true;
    client.message_is_private = true;
    client.message_is_auto = false;
    client.message_is_quote = false;
    client.editing_public_message = false;
    client.editing_private_message = true;
    client.editing_message_id = client.private_message->id;
    client.message_mci_available = false;
    client.message_mci_enabled = false;
    client.entering_private_recipient = false;
    client.entering_private_anonymous = false;
    client.entering_private_goto = false;
    client.entering_message_tagline = false;
    client.forwarding_private_message = false;
    client.forwarding_private_message_id.reset();
    client.forwarding_public_area.reset();
    client.private_recipient = client.private_message->recipient;
    client.message_subject = client.private_message->subject;
    client.message_subject_default.clear();
    client.reply_to = client.private_message->reply_to;
    client.message_body = client.private_message->body;
    client.message_line.clear();
    client.message_line_count = client.message_body.empty() ? 0
        : static_cast<std::size_t>(std::count(client.message_body.begin(), client.message_body.end(), '\n')) +
            static_cast<std::size_t>(client.message_body.back() != '\n');
    redraw_message_editor(client);
}

void start_private_message(
    ClientContext& client,
    const PrivateMessage* original = nullptr,
    bool forwarding = false) {
    try {
        if (client.messages == nullptr || (!forwarding && !client.messages->can_send_private(
                client.handle, client.private_messages_this_call))) {
            (void)write_channel(client,
                "\r\nPrivate mail is unavailable under your account, ACS, per-call, or credit rules.\r\n");
            show_private_mailbox(client);
            return;
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not check private-mail policy: " << error.what() << '\n';
        (void)write_channel(client, "\r\nCould not check private-mail access.\r\n");
        show_private_mailbox(client);
        return;
    }
    client.viewing_private_mail = false;
    client.reading_private_message = false;
    client.writing_message = true;
    client.writing_message_body = false;
    client.message_is_private = true;
    client.entering_message_recipient = false;
    client.message_is_auto = false;
    client.message_is_quote = false;
    client.editing_public_message = false;
    client.editing_private_message = false;
    client.editing_message_id = 0;
    client.message_mci_available = false;
    client.message_mci_enabled = false;
    client.entering_private_recipient = original == nullptr || forwarding;
    client.entering_private_anonymous = false;
    client.entering_private_goto = false;
    client.entering_message_tagline = false;
    client.forwarding_private_message = forwarding;
    client.forwarding_private_message_id = forwarding && original != nullptr
        ? std::optional<long long>(original->id)
        : std::nullopt;
    client.forwarding_public_area.reset();
    client.private_recipient = original == nullptr || forwarding
        ? std::string{}
        : original->sender_handle;
    client.message_recipient.clear();
    client.message_recipient_default.clear();
    client.message_subject.clear();
    client.message_subject_default = original == nullptr || forwarding
        ? std::string{}
        : make_reply_subject(original->subject);
    client.reply_to = original == nullptr || forwarding
        ? std::nullopt
        : std::optional<long long>(original->id);
    client.message_body = original != nullptr && !forwarding
        ? [&] {
            MessageQuoteTemplates templates{
                "^0Quoting message from ^1@F ^0to ^1@T^0", "^0on ^1@D ^0..."};
            try {
                templates = client.messages->private_quote_templates();
            } catch (const std::exception& error) {
                std::cerr << "Could not load private quote templates: " << error.what() << '\n';
            }
            return make_reply_quote(original->sender, original->recipient, original->created_at,
                original->body, original->anonymous_type, original->posted_as,
                "Email", templates.start, templates.end, original->subject);
        }()
        : std::string{};
    client.message_line.clear();
    client.message_line_count = client.message_body.empty() ? 0
        : static_cast<std::size_t>(std::count(client.message_body.begin(), client.message_body.end(), '\n')) +
            static_cast<std::size_t>(client.message_body.back() != '\n');
    redraw_message_editor(client);
}

void start_public_message_forward(ClientContext& client) {
    if (client.messages == nullptr || !client.reader_message.has_value()) {
        (void)write_channel(client, "\a");
        return;
    }
    client.viewing_messages = false;
    client.reading_message = false;
    client.viewing_private_mail = false;
    client.reading_private_message = false;
    client.writing_message = true;
    client.writing_message_body = false;
    client.message_is_private = true;
    client.entering_message_recipient = false;
    client.entering_private_recipient = true;
    client.entering_private_anonymous = false;
    client.entering_private_goto = false;
    client.forwarding_private_message = true;
    client.forwarding_private_message_id = client.reader_message->id;
    client.forwarding_public_area = client.current_area;
    client.message_is_auto = false;
    client.message_is_quote = false;
    client.editing_public_message = false;
    client.editing_private_message = false;
    client.message_mci_available = false;
    client.message_mci_enabled = false;
    client.private_recipient.clear();
    client.message_subject.clear();
    client.message_subject_default.clear();
    client.reply_to.reset();
    client.message_body.clear();
    client.message_line.clear();
    client.message_line_count = 0;
    redraw_message_editor(client);
}

void start_auto_message_write(ClientContext& client) {
    client.viewing_auto_message = false;
    client.writing_message = true;
    client.writing_message_body = true;
    client.entering_private_recipient = false;
    client.message_is_private = false;
    client.message_mci_available = false;
    client.message_mci_enabled = false;
    client.message_is_auto = true;
    client.entering_auto_anonymous = false;
    client.message_is_quote = false;
    client.message_subject = "Auto-Message";
    client.message_subject_default.clear();
    client.reply_to.reset();
    client.private_recipient.clear();
    client.message_body.clear();
    client.message_line.clear();
    client.message_line_count = 0;
    redraw_message_editor(client);
}

void start_quote_write(ClientContext& client) {
    client.viewing_quote = false;
    client.writing_message = true;
    client.writing_message_body = true;
    client.entering_private_recipient = false;
    client.message_is_private = false;
    client.message_mci_available = false;
    client.message_mci_enabled = false;
    client.message_is_auto = false;
    client.message_is_quote = true;
    client.message_subject = "Quote";
    client.message_subject_default.clear();
    client.reply_to.reset();
    client.private_recipient.clear();
    client.message_body.clear();
    client.message_line.clear();
    client.message_line_count = 0;
    redraw_message_editor(client);
}

void start_auto_message_reply(ClientContext& client) {
    if (!client.current_auto_message.has_value()) {
        return;
    }
    client.viewing_auto_message = false;
    client.writing_message = true;
    client.writing_message_body = false;
    client.entering_private_recipient = false;
    client.message_is_private = true;
    client.message_mci_available = false;
    client.message_mci_enabled = false;
    client.message_is_auto = false;
    client.message_is_quote = false;
    client.private_recipient = client.current_auto_message->author;
    client.message_subject.clear();
    client.message_subject_default = "Re: Auto-Message";
    client.reply_to.reset();
    client.message_body.clear();
    client.message_line.clear();
    client.message_line_count = 0;
    redraw_message_editor(client);
}

void redraw_message_editor(ClientContext& client) {
    const bool use_art = !client.editor_art.empty() && client.columns >= 80 && client.rows >= 24;
    std::string prompt = "\x1b[2J\x1b[H\x1b[?25l";
    if (use_art) {
        prompt += render_screen_art(client, client.editor_art);
        prompt += "\x1b[0m\x1b[9;1H\x1b[J\x1b[1;96mMESSAGE COMPOSER\x1b[0m\r\n\x1b[10;4H";
    }
    prompt += "\x1b[96m";
    const auto append_body = [&prompt, &client, use_art] {
        const std::size_t visible_lines = static_cast<std::size_t>(
            std::max(1, client.rows - (use_art ? 15 : 9)));
        const std::size_t first_visible = client.message_line_count > visible_lines
            ? client.message_line_count - visible_lines
            : 0;
        if (first_visible > 0) {
            prompt += "... earlier lines remain in this message ...\r\n";
        }
        std::size_t line_number = 0;
        std::size_t start = 0;
        while (start < client.message_body.size()) {
            const std::size_t end = client.message_body.find('\n', start);
            if (line_number >= first_visible) {
                prompt += "> ";
                prompt.append(client.message_body, start,
                    end == std::string::npos ? std::string::npos : end - start);
                prompt += "\r\n";
            }
            ++line_number;
            if (end == std::string::npos) {
                break;
            }
            start = end + 1;
        }
    };
    if (client.message_is_private) {
        prompt += client.forwarding_private_message
            ? "Forward message to another user"
            : (client.editing_private_message
                ? "Edit sent private message #" + std::to_string(client.editing_message_id)
                : (client.reply_to.has_value()
                    ? "Private reply to #" + std::to_string(*client.reply_to)
                    : "New private message"));
    } else if (client.message_is_auto) {
        prompt += "Update Auto-Message";
    } else if (client.message_is_quote) {
        prompt += "Submit Quote for SysOp Review";
    } else if (client.entering_message_goto) {
        prompt += "Goto public message";
    } else if (client.editing_public_message) {
        prompt += "Edit message #" + std::to_string(client.editing_message_id) + " in " + client.current_area;
    } else {
        prompt += client.reply_to.has_value()
            ? "Reply to #" + std::to_string(*client.reply_to) + " in " + client.current_area
            : "New message in " + client.current_area;
    }
    prompt += "\x1b[0m\r\nEnter /cancel at any prompt to discard.\r\n";
    if (client.message_is_private) {
        if (!client.private_recipient.empty()) {
            prompt += "To: " + client.private_recipient + "\r\n";
        }
        if (client.entering_private_recipient) {
            prompt += "To handle (1-32 letters, digits, ._-)> ";
        } else if (client.entering_private_goto) {
            prompt += "Private message ID to open> ";
        } else if (client.entering_message_tagline) {
            prompt += "Add a tagline to your message? (Y/N) [Y]> ";
        } else if (client.entering_private_anonymous) {
            prompt += "Send anonymously? (Y/N)> ";
        } else if (client.writing_message_body) {
            prompt += "Subject: " + client.message_subject + "\r\n";
            prompt += client.forwarding_private_message
                ? "Body: forwarded text is included; append lines, /clear to replace, /save to send.\r\n"
                : (client.editing_private_message
                    ? "Body: append lines, /clear to replace all text, /save to keep edits.\r\n"
                    : (client.reply_to.has_value()
                        ? "Body: quoted original is included; append lines, /clear to remove quote, /save to send.\r\n"
                        : "Body: enter a line at a time; use /save to send.\r\n"));
            append_body();
            prompt += "> ";
        } else if (!client.message_subject_default.empty()) {
            prompt += "Subject [" + client.message_subject_default + "]> ";
        } else {
            prompt += "Subject (1-80 characters)> ";
        }
    } else if (client.message_is_auto) {
        if (client.entering_auto_anonymous) {
            prompt += "Post anonymously? (Y/N)> ";
        } else {
            prompt += "Body: enter a line at a time; use /save to publish or /cancel to discard.\r\n";
            append_body();
            prompt += "> ";
        }
    } else if (client.message_is_quote) {
        prompt += "Quote: enter one line at a time; use /save to submit for review.\r\n";
        append_body();
        prompt += "> ";
    } else if (client.entering_message_goto) {
        prompt += "Message ID to open> ";
    } else if (client.entering_message_recipient) {
        prompt += "To [" + client.message_recipient_default + "]> ";
    } else if (client.entering_message_tagline) {
        prompt += "Add a tagline to your message? (Y/N) [Y]> ";
    } else if (client.entering_message_anonymous) {
        switch (client.pending_anonymous_mode) {
        case AnonymousMode::Optional:
            prompt += "Post anonymously? (Y/N)> ";
            break;
        case AnonymousMode::DearAbby:
            prompt += "Post as (1) Abby, (2) Problemed Person, or (3) your name> ";
            break;
        case AnonymousMode::AnyName:
            prompt += "Name to display (up to 36 characters)> ";
            break;
        default:
            prompt += "Anonymous posting choice> ";
            break;
        }
    } else if (client.writing_message_body) {
        prompt += "Subject: " + client.message_subject + "\r\n";
        if (client.editing_public_message) {
            prompt += "Body: append lines, /clear to replace all text, /save to keep edits.\r\n";
        } else if (client.reply_to.has_value()) {
            prompt += "Body: quoted original is included; append lines, /clear to remove quote, /save to post.\r\n";
        } else if (client.message_mci_available) {
            prompt += "Body: use /mci off to disable message MCI; /mci on enables it.\r\n";
        } else {
            prompt += "Body: enter a line at a time; use /save to post.\r\n";
        }
        if (client.message_mci_available) {
            prompt += std::string("Message MCI: ") + (client.message_mci_enabled ? "on\r\n" : "off\r\n");
        }
        append_body();
        prompt += "> ";
    } else if (!client.message_subject_default.empty()) {
        prompt += "Subject [" + client.message_subject_default + "]> ";
    } else {
        prompt += "Subject (1-80 characters)> ";
    }
    prompt += client.message_line;
    prompt += "\x1b[?25h";
    if (!write_channel(client, prompt)) {
        client.close_requested = true;
    }
}

void cancel_message_post(ClientContext& client) {
    const bool was_private = client.message_is_private;
    const bool was_private_goto = client.entering_private_goto;
    const bool was_public_goto = client.entering_message_goto;
    const bool was_auto = client.message_is_auto;
    const bool was_quote = client.message_is_quote;
    const bool was_editing = client.editing_public_message;
    const bool was_editing_private = client.editing_private_message;
    client.writing_message = false;
    client.writing_message_body = false;
    client.entering_private_recipient = false;
    client.entering_private_anonymous = false;
    client.entering_private_goto = false;
    client.entering_message_tagline = false;
    client.forwarding_private_message = false;
    client.forwarding_private_message_id.reset();
    client.forwarding_public_area.reset();
    client.entering_auto_anonymous = false;
    client.entering_message_recipient = false;
    client.entering_message_anonymous = false;
    client.entering_message_goto = false;
    client.entering_message_tagline = false;
    client.pending_anonymous_mode = AnonymousMode::Disabled;
    client.message_is_private = false;
    client.message_is_auto = false;
    client.message_is_quote = false;
    client.editing_public_message = false;
    client.editing_private_message = false;
    client.editing_message_id = 0;
    client.message_mci_available = false;
    client.message_mci_enabled = false;
    client.message_subject.clear();
    client.message_subject_default.clear();
    client.reply_to.reset();
    client.private_recipient.clear();
    client.message_recipient.clear();
    client.message_recipient_default.clear();
    client.pending_anonymous_mode = AnonymousMode::Disabled;
    client.message_body.clear();
    client.message_line.clear();
    if (was_private_goto) {
        client.viewing_private_mail = true;
        show_selected_private_message(client);
    } else if (was_public_goto && client.reader_message.has_value()) {
        client.viewing_messages = true;
        show_selected_message(client);
    } else if (was_editing_private) {
        client.viewing_private_mail = true;
        show_selected_private_message(client);
    } else if (was_private) {
        show_private_mailbox(client);
    } else if (was_auto) {
        show_auto_message(client);
    } else if (was_quote) {
        show_quote(client);
    } else if (was_editing && client.reader_message.has_value()) {
        client.viewing_messages = true;
        show_selected_message(client);
    } else {
        show_message_board(client);
    }
}

void complete_private_message_edit(ClientContext& client) {
    if (client.messages == nullptr || !client.editing_private_message ||
        client.editing_message_id < 1) {
        cancel_message_post(client);
        return;
    }
    try {
        const long long message_id = client.editing_message_id;
        client.messages->edit_private_message_body(client.handle, message_id, client.message_body);
        if (client.private_message.has_value() && client.private_message->id == message_id) {
            client.private_message->body = client.message_body;
        }
        std::clog << "Caller " << client.handle << " edited private message #" << message_id << ".\n";
        client.writing_message = false;
        client.writing_message_body = false;
        client.message_is_private = false;
        client.editing_private_message = false;
        client.editing_message_id = 0;
        client.message_subject.clear();
        client.message_subject_default.clear();
        client.reply_to.reset();
        client.private_recipient.clear();
        client.message_body.clear();
        client.message_line.clear();
        client.message_line_count = 0;
        client.viewing_private_mail = true;
        (void)write_channel(client, "\r\nPrivate message text updated.\r\n");
        show_selected_private_message(client);
    } catch (const std::exception& error) {
        std::cerr << "Could not edit private message: " << error.what() << '\n';
        (void)write_channel(client, "\r\nPrivate message could not be updated: " +
            std::string(error.what()) + "\r\n");
        redraw_message_editor(client);
    }
}

void complete_private_message(ClientContext& client, bool anonymous) {
    try {
        const bool is_reply = client.reply_to.has_value();
        const std::string recipient = client.private_recipient;
        std::string reply_notice = client.handle + " replied: " + client.message_subject;
        if (reply_notice.size() > 80) {
            reply_notice.resize(80);
        }
        client.messages->send_private(
            client.handle, client.private_recipient, client.message_subject,
            client.message_body, client.reply_to, anonymous, client.private_messages_this_call);
        client.private_messages_this_call = std::min(255, client.private_messages_this_call + 1);
        if (is_reply && client.community != nullptr) {
            try {
                client.community->send_short_message(recipient, reply_notice);
            } catch (const std::exception& error) {
                std::cerr << "Could not queue private-mail reply notice: " << error.what() << '\n';
            }
        }
        client.writing_message = false;
        client.writing_message_body = false;
        client.entering_private_recipient = false;
        client.entering_private_anonymous = false;
        client.entering_private_goto = false;
        client.entering_message_tagline = false;
        client.forwarding_private_message = false;
        client.forwarding_private_message_id.reset();
        client.forwarding_public_area.reset();
        client.message_is_private = false;
        client.editing_private_message = false;
        client.message_subject.clear();
        client.message_subject_default.clear();
        client.reply_to.reset();
        client.private_recipient.clear();
        client.message_body.clear();
        client.private_mailbox = PrivateMailbox::Outbox;
        client.private_mail_list_page = 0;
        (void)write_channel(client, "\r\nPrivate message sent.\r\n");
        show_private_mailbox(client);
    } catch (const std::exception& error) {
        std::cerr << "Could not send private message: " << error.what() << '\n';
        (void)write_channel(client, "\r\nPrivate message could not be sent: " +
            std::string(error.what()) + "\r\n");
        client.entering_private_anonymous = false;
        client.entering_private_recipient = true;
        redraw_message_editor(client);
    }
}

std::string truncate_tagline(std::string_view text, std::size_t maximum_codepoints) {
    std::size_t bytes = 0;
    std::size_t codepoints = 0;
    while (bytes < text.size()) {
        const unsigned char byte = static_cast<unsigned char>(text[bytes]);
        if ((byte & 0xc0U) != 0x80U) {
            if (codepoints == maximum_codepoints) {
                break;
            }
            ++codepoints;
        }
        ++bytes;
    }
    return std::string(text.substr(0, bytes));
}

void append_random_message_tagline(ClientContext& client) {
    std::vector<std::string> candidates;
    if (client.tagline_catalog != nullptr) {
        for (const AnsiArtwork& entry : *client.tagline_catalog) {
            std::size_t start = 0;
            while (start <= entry.contents.size()) {
                const std::size_t end = entry.contents.find('\n', start);
                std::string_view line(entry.contents.data() + start,
                    (end == std::string::npos ? entry.contents.size() : end) - start);
                if (!line.empty() && line.back() == '\r') {
                    line.remove_suffix(1);
                }
                while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
                    line.remove_prefix(1);
                }
                while (!line.empty() && (line.back() == ' ' || line.back() == '\t')) {
                    line.remove_suffix(1);
                }
                if (!line.empty()) {
                    candidates.push_back(truncate_tagline(line, 74));
                }
                if (end == std::string::npos) {
                    break;
                }
                start = end + 1;
            }
        }
    }
    if (candidates.empty()) {
        (void)write_channel(client,
            "\r\nNo usable taglines are loaded; continuing without one.\r\n");
        return;
    }
    static thread_local std::mt19937 generator(std::random_device{}());
    std::uniform_int_distribution<std::size_t> choose(0, candidates.size() - 1);
    const std::string& tagline = candidates[choose(generator)];
    const std::string addition = "\n\n... " + tagline;
    if (client.message_line_count + 2 > kMessageLineCountLimit ||
        client.message_body.size() + addition.size() > kMessageBodyByteLimit) {
        (void)write_channel(client,
            "\r\nThere is no room for a tagline within the message limits; continuing without one.\r\n");
        return;
    }
    client.message_body += addition;
    client.message_line_count += 2;
}

bool prompt_for_area_tagline(ClientContext& client) {
    if (client.messages == nullptr) {
        return false;
    }
    try {
        const std::vector<BoardArea> areas = client.messages->areas(client.handle);
        const auto current = std::find_if(areas.begin(), areas.end(), [&client](const BoardArea& area) {
            return ::strcasecmp(area.name.c_str(), client.current_area.c_str()) == 0;
        });
        if (current == areas.end() || !current->add_tagline ||
            (current->password_protected && !client.unlocked_message_areas.contains(current->id))) {
            return false;
        }
        client.entering_message_tagline = true;
        client.message_line.clear();
        redraw_message_editor(client);
        return true;
    } catch (const std::exception& error) {
        std::cerr << "Could not read message-area tagline setting: " << error.what() << '\n';
        return false;
    }
}

void begin_private_message_save(ClientContext& client) {
    try {
        if (client.messages->can_post_private_anonymously(client.handle)) {
            client.entering_private_anonymous = true;
            redraw_message_editor(client);
        } else {
            complete_private_message(client, false);
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not check anonymous private-mail policy: " << error.what() << '\n';
        (void)write_channel(client, "\r\nPrivate message could not be saved.\r\n");
        cancel_message_post(client);
    }
}

void complete_private_forward(ClientContext& client, std::string_view recipient) {
    if (client.messages == nullptr || !client.forwarding_private_message_id.has_value()) {
        cancel_message_post(client);
        return;
    }
    try {
        const bool from_public_message = client.forwarding_public_area.has_value();
        if (from_public_message) {
            client.messages->forward_public_private(
                client.handle, recipient, *client.forwarding_public_area,
                *client.forwarding_private_message_id, make_forwarding_header(client.handle));
        } else {
            client.messages->forward_private(
                client.handle, recipient, *client.forwarding_private_message_id,
                make_forwarding_header(client.handle));
        }
        std::clog << "Caller " << client.handle << " forwarded private message #"
                  << *client.forwarding_private_message_id << " to " << recipient << ".\n";
        client.writing_message = false;
        client.writing_message_body = false;
        client.entering_private_recipient = false;
        client.forwarding_private_message = false;
        client.entering_private_goto = false;
        client.forwarding_private_message_id.reset();
        client.forwarding_public_area.reset();
        client.message_is_private = false;
        client.editing_private_message = false;
        client.message_subject.clear();
        client.message_subject_default.clear();
        client.private_recipient.clear();
        client.message_body.clear();
        if (from_public_message) {
            client.viewing_messages = true;
            show_selected_message(client);
        } else {
            client.viewing_private_mail = true;
            show_selected_private_message(client);
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not forward private message: " << error.what() << '\n';
        (void)write_channel(client, "\r\nPrivate message could not be forwarded: " +
            std::string(error.what()) + "\r\n");
        client.entering_private_recipient = true;
        redraw_message_editor(client);
    }
}

void submit_private_message_line(ClientContext& client) {
    std::string line = std::move(client.message_line);
    client.message_line.clear();
    std::string command = line;
    std::transform(command.begin(), command.end(), command.begin(), [](unsigned char value) {
        return static_cast<char>(std::toupper(value));
    });
    if (command == "/CANCEL") {
        cancel_message_post(client);
        return;
    }

    if (client.entering_message_tagline) {
        if (line.empty() || command == "Y") {
            append_random_message_tagline(client);
        } else if (command != "N") {
            (void)write_channel(client,
                "\r\nAnswer Y or N.\r\nAdd a tagline to your message? (Y/N) [Y]> ");
            return;
        }
        client.entering_message_tagline = false;
        begin_private_message_save(client);
        return;
    }

    if (command == "/CLEAR" &&
        (client.editing_private_message || client.forwarding_private_message ||
            (client.message_is_private && client.reply_to.has_value()))) {
        client.message_body.clear();
        client.message_line_count = 0;
        redraw_message_editor(client);
        return;
    }

    if (client.entering_private_goto) {
        long long message_id{};
        const auto parsed = std::from_chars(
            line.data(), line.data() + line.size(), message_id);
        if (line.empty() || parsed.ec != std::errc{} || parsed.ptr != line.data() + line.size() ||
            message_id < 1) {
            (void)write_channel(client, "\r\nEnter a positive private-message ID.\r\n");
            redraw_message_editor(client);
            return;
        }
        try {
            const auto message = client.messages->find_private(client.handle, message_id);
            const bool belongs_to_mailbox = message.has_value() &&
                (client.private_mailbox == PrivateMailbox::Inbox
                    ? (!message->deleted &&
                        strcasecmp(message->recipient.c_str(), client.handle.c_str()) == 0)
                    : strcasecmp(message->sender_handle.c_str(), client.handle.c_str()) == 0);
            if (!belongs_to_mailbox) {
                (void)write_channel(client, "\r\nThat message is not in this mailbox.\r\n");
                redraw_message_editor(client);
                return;
            }
            client.entering_private_goto = false;
            client.writing_message = false;
            client.message_is_private = false;
            client.viewing_private_mail = true;
            client.private_message = *message;
            client.private_message_page = 0;
            show_selected_private_message(client);
        } catch (const std::exception& error) {
            std::cerr << "Could not locate private message: " << error.what() << '\n';
            (void)write_channel(client, "\r\nCould not open that private message.\r\n");
            redraw_message_editor(client);
        }
        return;
    }

    if (client.entering_private_anonymous) {
        if (line.empty() || command == "N") {
            client.entering_private_anonymous = false;
            complete_private_message(client, false);
        } else if (command == "Y") {
            client.entering_private_anonymous = false;
            complete_private_message(client, true);
        } else {
            (void)write_channel(client, "\r\nAnswer Y or N.\r\nSend anonymously? (Y/N)> ");
        }
        return;
    }

    if (client.entering_private_recipient) {
        if (!valid_handle(line)) {
            (void)write_channel(client,
                "\r\nEnter a valid account handle (1-32 letters, digits, dot, dash, or underscore).\r\nTo handle> ");
            return;
        }
        client.private_recipient = std::move(line);
        client.entering_private_recipient = false;
        if (client.forwarding_private_message) {
            complete_private_forward(client, client.private_recipient);
            return;
        }
        redraw_message_editor(client);
        return;
    }

    if (!client.writing_message_body) {
        if (line.empty()) {
            if (client.message_subject_default.empty()) {
                (void)write_channel(client, "\r\nSubject is required.\r\nSubject> ");
                return;
            }
            line = client.message_subject_default;
        }
        client.message_subject = std::move(line);
        client.writing_message_body = true;
        redraw_message_editor(client);
        return;
    }

    if (command == "/SAVE") {
        while (!client.message_body.empty() && client.message_body.back() == '\n') {
            client.message_body.pop_back();
        }
        if (client.editing_private_message) {
            if (client.message_body.empty()) {
                (void)write_channel(client, "\r\nA private message needs a body.\r\n> ");
                return;
            }
            complete_private_message_edit(client);
            return;
        }
        if (client.message_body.empty()) {
            (void)write_channel(client, "\r\nA private message needs a body.\r\n> ");
            return;
        }
        if (!client.forwarding_private_message && prompt_for_area_tagline(client)) {
            return;
        }
        begin_private_message_save(client);
        return;
    }

    if (utf8_codepoint_count(line) > kMessageLineCharacterLimit ||
        client.message_body.size() + line.size() + 1 > kMessageBodyByteLimit ||
        client.message_line_count >= kMessageLineCountLimit) {
        (void)write_channel(client,
            "\r\nPrivate message limit reached (78 characters per line, 500 lines). Use /save or /cancel.\r\n> ");
        return;
    }
    client.message_body += line;
    client.message_body.push_back('\n');
    ++client.message_line_count;
    (void)write_channel(client, "\r\n> ");
}

void save_public_message(ClientContext& client, int anonymous_type, std::string_view posted_as = {}) {
    try {
        client.messages->post(
            client.handle, client.current_area, client.message_subject, client.message_body,
            client.reply_to, client.message_mci_enabled, client.message_recipient,
            anonymous_type, posted_as, client.public_posts_this_call);
        client.public_posts_this_call = std::min(255, client.public_posts_this_call + 1);
        client.writing_message = false;
        client.writing_message_body = false;
        client.entering_message_recipient = false;
        client.entering_message_anonymous = false;
        client.entering_message_goto = false;
        client.entering_message_tagline = false;
        client.message_mci_available = false;
        client.message_mci_enabled = false;
        client.pending_anonymous_mode = AnonymousMode::Disabled;
        client.message_subject.clear();
        client.message_subject_default.clear();
        client.message_recipient.clear();
        client.message_recipient_default.clear();
        client.reply_to.reset();
        client.message_body.clear();
        client.message_line.clear();
        client.message_line_count = 0;
        client.message_list_page = 0;
        client.unread_only_messages = false;
        (void)write_channel(client, "\r\nMessage posted.\r\n");
        show_message_board(client);
    } catch (const std::exception& error) {
        std::cerr << "Could not post message: " << error.what() << '\n';
        (void)write_channel(client, "\r\nMessage could not be saved: " +
            std::string(error.what()) + "\r\n");
        cancel_message_post(client);
    }
}

void save_auto_message(ClientContext& client, bool anonymous) {
    try {
        client.community->set_auto_message(client.handle, client.message_body, anonymous, client.is_sysop);
        client.writing_message = false;
        client.writing_message_body = false;
        client.message_is_auto = false;
        client.entering_auto_anonymous = false;
        client.message_subject.clear();
        client.message_subject_default.clear();
        client.message_body.clear();
        client.message_line.clear();
        client.message_line_count = 0;
        client.auto_message_page = 0;
        std::clog << "User " << client.handle << " updated the auto-message.\n";
        show_auto_message(client);
    } catch (const std::exception& error) {
        std::cerr << "Could not update auto-message: " << error.what() << '\n';
        (void)write_channel(client, "\r\nAuto-message could not be saved.\r\n");
        client.entering_auto_anonymous = false;
        redraw_message_editor(client);
    }
}

void begin_public_message_save(ClientContext& client) {
    try {
        const AnonymousMode mode = client.messages->area_anonymous_mode(client.handle, client.current_area);
        if (mode == AnonymousMode::Disabled) {
            save_public_message(client, 0);
        } else if (mode == AnonymousMode::Forced) {
            save_public_message(client, client.is_sysop ? 2 : 1);
        } else {
            client.pending_anonymous_mode = mode;
            client.entering_message_anonymous = true;
            client.message_line.clear();
            redraw_message_editor(client);
        }
    } catch (const std::exception& error) {
        std::cerr << "Could not check message-area anonymous policy: " << error.what() << '\n';
        (void)write_channel(client, "\r\nMessage could not be saved.\r\n");
        cancel_message_post(client);
    }
}

void submit_message_line(ClientContext& client) {
    if (client.message_is_private) {
        submit_private_message_line(client);
        return;
    }
    std::string line = std::move(client.message_line);
    client.message_line.clear();
    std::string command = line;
    std::transform(command.begin(), command.end(), command.begin(), [](unsigned char value) {
        return static_cast<char>(std::toupper(value));
    });
    if (command == "/CANCEL") {
        cancel_message_post(client);
        return;
    }

    if (client.entering_message_tagline) {
        if (line.empty() || command == "Y") {
            append_random_message_tagline(client);
        } else if (command != "N") {
            (void)write_channel(client,
                "\r\nAnswer Y or N.\r\nAdd a tagline to your message? (Y/N) [Y]> ");
            return;
        }
        client.entering_message_tagline = false;
        begin_public_message_save(client);
        return;
    }

    if (client.entering_message_goto) {
        long long message_id{};
        const auto parsed = std::from_chars(line.data(), line.data() + line.size(), message_id);
        if (line.empty() || parsed.ec != std::errc{} || parsed.ptr != line.data() + line.size() ||
            message_id < 1) {
            (void)write_channel(client, "\r\nEnter a positive message ID.\r\n");
            redraw_message_editor(client);
            return;
        }
        try {
            const auto message = client.messages->find(client.handle, client.current_area, message_id);
            if (!message.has_value()) {
                (void)write_channel(client, "\r\nThat message is not available in this area.\r\n");
                redraw_message_editor(client);
                return;
            }
            client.entering_message_goto = false;
            client.writing_message = false;
            client.viewing_messages = true;
            client.reader_message = *message;
            client.message_page = 0;
            show_selected_message(client);
        } catch (const std::exception& error) {
            std::cerr << "Could not locate public message: " << error.what() << '\n';
            (void)write_channel(client, "\r\nCould not open that message.\r\n");
            redraw_message_editor(client);
        }
        return;
    }

    if (client.message_is_auto && client.entering_auto_anonymous) {
        if (line.empty() || command == "N") {
            save_auto_message(client, false);
        } else if (command == "Y") {
            save_auto_message(client, true);
        } else {
            (void)write_channel(client, "\r\nAnswer Y or N.\r\nPost anonymously? (Y/N)> ");
        }
        return;
    }

    if (client.entering_message_anonymous) {
        int anonymous_type = 0;
        std::string posted_as;
        const char choice = line.empty() ? '\0'
            : static_cast<char>(std::toupper(static_cast<unsigned char>(line.front())));
        if (client.pending_anonymous_mode == AnonymousMode::Optional) {
            if (line.empty() || choice == 'N') {
                anonymous_type = 0;
            } else if (choice == 'Y') {
                anonymous_type = client.is_sysop ? 2 : 1;
            } else {
                (void)write_channel(client, "\r\nAnswer Y or N.\r\nPost anonymously? (Y/N)> ");
                return;
            }
        } else if (client.pending_anonymous_mode == AnonymousMode::DearAbby) {
            if (line == "1") {
                anonymous_type = 3;
            } else if (line == "2") {
                anonymous_type = 4;
            } else if (line == "3") {
                anonymous_type = 0;
            } else {
                (void)write_channel(client,
                    "\r\nChoose 1, 2, or 3.\r\nPost as (1) Abby, (2) Problemed Person, or (3) your name> ");
                return;
            }
        } else if (client.pending_anonymous_mode == AnonymousMode::AnyName) {
            if (line.empty() || line.size() > 36) {
                (void)write_channel(client, "\r\nEnter a display name of 1-36 characters.\r\nName to display> ");
                return;
            }
            posted_as = std::move(line);
            anonymous_type = ::strcasecmp(posted_as.c_str(), client.handle.c_str()) == 0 ? 0 : 5;
            if (anonymous_type == 0) {
                posted_as.clear();
            }
        } else {
            (void)write_channel(client, "\r\nAnonymous posting is unavailable here.\r\n");
            cancel_message_post(client);
            return;
        }
        client.entering_message_anonymous = false;
        client.pending_anonymous_mode = AnonymousMode::Disabled;
        save_public_message(client, anonymous_type, posted_as);
        return;
    }

    if (client.entering_message_recipient) {
        if (line.empty()) {
            line = client.message_recipient_default;
        }
        if (line.empty() || line.size() > 36) {
            (void)write_channel(client, "\r\nRecipient must be 1-36 characters.\r\nTo> ");
            return;
        }
        client.message_recipient = std::move(line);
        client.entering_message_recipient = false;
        redraw_message_editor(client);
        return;
    }

    if (!client.message_is_auto && !client.message_is_quote && !client.editing_public_message &&
        (command == "/MCI OFF" || command == "/MCI ON")) {
        if (command == "/MCI ON" && !client.message_mci_available) {
            (void)write_channel(client, "\r\nThis area does not allow message MCI.\r\n> ");
            return;
        }
        client.message_mci_enabled = command == "/MCI ON";
        redraw_message_editor(client);
        return;
    }

    if ((client.editing_public_message ||
        (!client.message_is_private && client.reply_to.has_value())) && command == "/CLEAR") {
        client.message_body.clear();
        client.message_line_count = 0;
        redraw_message_editor(client);
        return;
    }

    if (!client.writing_message_body) {
        if (line.empty()) {
            if (client.message_subject_default.empty()) {
                (void)write_channel(client, "\r\nSubject is required.\r\nSubject> ");
                return;
            }
            line = client.message_subject_default;
        }
        client.message_subject = std::move(line);
        client.writing_message_body = true;
        redraw_message_editor(client);
        return;
    }

    if (command == "/SAVE") {
        while (!client.message_body.empty() && client.message_body.back() == '\n') {
            client.message_body.pop_back();
        }
        if (client.message_body.empty()) {
            (void)write_channel(client, "\r\nA message needs a body.\r\n> ");
            return;
        }
        if (client.message_is_quote) {
            try {
                if (client.messages == nullptr || !client.messages->can_submit_quote(client.handle)) {
                    throw std::invalid_argument("account does not pass AddQuote ACS");
                }
                client.community->submit_quote(client.handle, client.message_body);
                client.writing_message = false;
                client.writing_message_body = false;
                client.message_is_quote = false;
                client.message_subject.clear();
                client.message_subject_default.clear();
                client.message_body.clear();
                client.message_line.clear();
                client.message_line_count = 0;
                std::clog << "User " << client.handle << " submitted a quote for SysOp review.\n";
                (void)write_channel(client, "\r\nQuote submitted for SysOp review.\r\n");
                show_quote(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not submit quote: " << error.what() << '\n';
                (void)write_channel(client, "\r\nQuote could not be submitted.\r\n");
                redraw_message_editor(client);
            }
            return;
        }
        if (client.message_is_auto) {
            try {
                if (client.messages != nullptr &&
                    client.messages->can_post_public_anonymously(client.handle)) {
                    client.entering_auto_anonymous = true;
                    redraw_message_editor(client);
                } else {
                    save_auto_message(client, false);
                }
            } catch (const std::exception& error) {
                std::cerr << "Could not check auto-message anonymous policy: " << error.what() << '\n';
                (void)write_channel(client, "\r\nAuto-message could not be saved.\r\n");
                redraw_message_editor(client);
            }
            return;
        }
        if (client.editing_public_message) {
            try {
                const long long message_id = client.editing_message_id;
                client.messages->edit_message_body(
                    client.handle, client.current_area, message_id, client.message_body);
                if (client.reader_message.has_value() && client.reader_message->id == message_id) {
                    client.reader_message->body = client.message_body;
                }
                if (client.messages->can_moderate_area(client.handle, client.current_area)) {
                    record_sysop_action(client, "edited public message text",
                        "#" + std::to_string(message_id) + " " + client.message_subject);
                }
                std::clog << (client.messages->can_moderate_area(client.handle, client.current_area)
                    ? "Area moderator " : "Caller ") << client.handle
                          << " edited public message #" << message_id << " in " << client.current_area << ".\n";
                client.writing_message = false;
                client.writing_message_body = false;
                client.editing_public_message = false;
                client.editing_message_id = 0;
                client.message_subject.clear();
                client.message_subject_default.clear();
                client.reply_to.reset();
                client.message_body.clear();
                client.message_line.clear();
                client.message_line_count = 0;
                client.viewing_messages = true;
                client.reading_message = false;
                (void)write_channel(client, "\r\nMessage text updated.\r\n");
                show_selected_message(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not edit public message: " << error.what() << '\n';
                (void)write_channel(client, "\r\nMessage could not be updated: " + std::string(error.what()) + "\r\n");
                redraw_message_editor(client);
            }
            return;
        }
        if (prompt_for_area_tagline(client)) {
            return;
        }
        begin_public_message_save(client);
        return;
    }

    const bool legacy_message_body = !client.message_is_auto && !client.message_is_quote;
    const std::size_t line_character_limit = legacy_message_body ? kMessageLineCharacterLimit : 200;
    const std::size_t body_byte_limit = legacy_message_body ? kMessageBodyByteLimit : 4000;
    const std::size_t body_line_limit = legacy_message_body ? kMessageLineCountLimit : 25;
    if (utf8_codepoint_count(line) > line_character_limit ||
        client.message_body.size() + line.size() + 1 > body_byte_limit ||
        client.message_line_count >= body_line_limit) {
        (void)write_channel(client, legacy_message_body
            ? "\r\nMessage limit reached (78 characters per line, 500 lines). Use /save or /cancel.\r\n> "
            : "\r\nMessage limit reached. Use /save or /cancel.\r\n> ");
        return;
    }
    if (!client.message_body.empty() && client.message_body.back() != '\n') {
        client.message_body.push_back('\n');
    }
    client.message_body += line;
    client.message_body.push_back('\n');
    ++client.message_line_count;
    (void)write_channel(client, "\r\n> ");
}

void show_nodes(ClientContext& client) {
    if (!write_channel(client, nodes_screen(
            client.registry->snapshot(client.node_number, client.is_sysop), client.node_number,
            client.columns, client.rows,
            client.messages != nullptr && client.messages->can_toggle_invisibility(client.handle),
            client.invisible,
            client.is_sysop,
            client.sysop_available,
            render_screen_art(client, client.nodes_art)))) {
        client.close_requested = true;
    } else {
        client.waiting_for_return = true;
        client.showing_nodes = true;
    }
}

void show_help(ClientContext& client) {
    if (!write_channel(client, help_screen(
            client.columns, client.rows, render_screen_art(client, client.help_art)))) {
        client.close_requested = true;
    } else {
        client.waiting_for_return = true;
        client.showing_nodes = false;
    }
}

void enter_chat(ClientContext& client) {
    client.in_chat.store(true);
    client.waiting_for_return = false;
    client.chat_input.clear();
    if (!write_channel(client, chat_screen(
            client.handle, client.node_number, client.columns, client.rows,
            render_screen_art(client, client.chat_art), client.chat_input))) {
        client.close_requested = true;
    } else {
        client.registry->broadcast(client, "Node " + std::to_string(client.node_number) +
            " - " + client.handle + " joined chat.");
    }
}

void redraw_active_screen(ClientContext& client) {
    if (client.checking_birth_date) {
        client.drawn = false;
        show_initial_screen(client);
    } else if (client.registration_pending) {
        if (client.collecting_application_profile) {
            show_new_user_questionnaire(client);
        } else {
            show_pending_application(client);
        }
    } else if (client.editing_file_description || client.editing_file_extended_description) {
        redraw_file_description_editor(client);
    } else if (client.viewing_archive_art) {
        show_archive_art(client);
    } else if (client.viewing_file_validation) {
        show_file_validation_queue(client);
    } else if (client.viewing_new_files) {
        show_new_file_scan(client);
    } else if (client.viewing_download_queue) {
        show_download_queue(client);
    } else if (client.viewing_archive_text) {
        show_archive_text(client);
    } else if (client.viewing_archive_entry_detail) {
        show_archive_entry_detail(client);
    } else if (client.viewing_archive) {
        show_archive_listing(client);
    } else if (client.viewing_file_detail) {
        show_public_file_detail(client);
    } else if (client.viewing_extended_file_description) {
        show_extended_file_description(client);
    } else if (client.viewing_time_bank) {
        redraw_time_bank(client);
    } else if (client.writing_message) {
        redraw_message_editor(client);
    } else if (client.in_chat.load()) {
        if (!write_channel(client, chat_screen(
                client.handle, client.node_number, client.columns, client.rows,
                render_screen_art(client, client.chat_art), client.chat_input))) {
            client.close_requested = true;
        }
    } else if (client.viewing_short_messages) {
        if (!write_channel(client, short_messages_screen(client.short_messages,
                client.short_message_page, client.columns, client.rows,
                render_screen_art(client, client.mailbox_art)))) {
            client.close_requested = true;
        }
    } else if (client.viewing_bbs_directory && client.editing_bbs_listing) {
        redraw_bbs_listing_editor(client);
    } else if (client.viewing_bbs_directory && client.viewing_bbs_detail) {
        show_bbs_detail(client);
    } else if (client.viewing_bbs_directory) {
        show_bbs_directory(client);
    } else if (client.viewing_callers) {
        show_callers(client);
    } else if (client.viewing_statistics) {
        show_statistics(client);
    } else if (client.viewing_quote_queue) {
        show_quote_queue(client);
    } else if (client.viewing_quote) {
        show_quote(client);
    } else if (client.viewing_auto_message) {
        show_auto_message(client);
    } else if (client.viewing_polls) {
        show_polls(client);
    } else if (client.viewing_bulletins) {
        show_bulletins(client);
    } else if (client.viewing_art) {
        show_artwork(client);
    } else if (client.viewing_sysop && client.viewing_sysop_audit) {
        show_sysop_audit(client);
    } else if (client.viewing_sysop && client.viewing_sysop_account_detail &&
        client.sysop_selected_index.has_value() &&
        *client.sysop_selected_index < client.sysop_accounts.size()) {
        show_sysop_account_review(client);
    } else if (client.viewing_sysop) {
        show_sysop_accounts(client);
    } else if (client.viewing_sysop_areas) {
        show_sysop_area_admin(client);
    } else if (client.viewing_profile) {
        if (client.editing_profile) {
            redraw_profile_editor(client);
        } else {
            show_profile(client);
        }
    } else if (client.viewing_one_liners) {
        show_one_liners(client);
    } else if (client.viewing_once_only) {
        show_once_only_notice(client);
    } else if (client.viewing_entrance) {
        show_login_entrance(client);
    } else if (client.viewing_uploads && client.selecting_upload_area) {
        show_upload_publish_areas(client);
    } else if (client.viewing_uploads && client.viewing_upload_detail) {
        show_upload_detail(client);
    } else if (client.viewing_uploads) {
        show_upload_review(client);
    } else if (client.viewing_files && client.viewing_file_list) {
        show_file_listing(client);
    } else if (client.viewing_files) {
        show_file_areas(client);
    } else if (client.viewing_new_scan) {
        show_unread_messages(client);
    } else if (client.viewing_message_scan_settings) {
        show_message_scan_settings(client);
    } else if (client.viewing_areas) {
        show_message_areas(client);
    } else if (client.viewing_private_mail && client.reading_private_message) {
        show_selected_private_message(client);
    } else if (client.viewing_private_mail) {
        show_private_mailbox(client);
    } else if (client.viewing_messages && client.reading_message) {
        show_selected_message(client);
    } else if (client.viewing_messages) {
        show_message_board(client);
    } else if (client.waiting_for_return && client.showing_nodes) {
        show_nodes(client);
    } else if (client.waiting_for_return) {
        show_help(client);
    } else if (client.drawn) {
        show_welcome(client);
    }
}

void leave_chat(ClientContext& client) {
    client.registry->broadcast(client, "Node " + std::to_string(client.node_number) +
        " - " + client.handle + " left chat.");
    client.in_chat.store(false);
    client.chat_input.clear();
    show_welcome(client);
}

std::string printable_chat_text(std::string_view text) {
    std::string result;
    result.reserve(text.size());
    for (const unsigned char character : text) {
        if (character >= 32 && character != 127) {
            result.push_back(static_cast<char>(character));
        }
    }
    return result;
}

void submit_chat_line(ClientContext& client) {
    const std::string message = printable_chat_text(client.chat_input);
    client.chat_input.clear();
    if (message == "/quit" || message == "/q") {
        leave_chat(client);
        return;
    }
    if (!message.empty()) {
        const std::string line = "[" + std::to_string(client.node_number) + "] " + client.handle + ": " + message;
        client.registry->broadcast(client, line);
        if (!write_channel(client, "\r\n" + line + "\r\nChat> ")) {
            client.close_requested = true;
        }
    } else if (!write_channel(client, "\r\nChat> ")) {
        client.close_requested = true;
    }
}

bool client_accepts_menu_commands(const ClientContext& client) {
    return client.authenticated && client.drawn && !client.registration_pending &&
        !client.waiting_for_return && !client.in_chat.load() &&
        !client.editing_profile && !client.viewing_profile && !client.viewing_time_bank &&
        !client.editing_bbs_listing && !client.creating_poll &&
        !client.adding_poll_choice && !client.searching_files && !client.adding_one_liner &&
        !client.editing_one_liner && !client.entering_message_scan_date &&
        !client.entering_file_scan_date && !client.entering_file_move_area && !client.entering_file_rename &&
        !client.entering_file_download_count && !client.entering_file_owner && !client.entering_file_date &&
        !client.writing_message && !client.writing_message_body &&
        !client.editing_file_description && !client.editing_file_extended_description &&
        !client.entering_private_recipient && !client.area_admin_kind.has_value();
}

bool is_terminal_arrow(char character) {
    return character == kTerminalArrowUp || character == kTerminalArrowDown ||
        character == kTerminalArrowRight || character == kTerminalArrowLeft;
}

void move_linear_selection(std::size_t& selection, std::size_t count, char direction) {
    if (count == 0) {
        return;
    }
    if (direction == kTerminalArrowDown || direction == kTerminalArrowRight) {
        selection = (selection + 1) % count;
    } else {
        selection = (selection + count - 1) % count;
    }
}

void move_welcome_selection(ClientContext& client, char direction) {
    const std::size_t count = welcome_menu_keys(client.is_sysop).size();
    if (count == 0) {
        return;
    }
    if (client.columns < 80) {
        move_linear_selection(client.welcome_selection_index, count, direction);
        return;
    }
    const std::size_t row_count = (count + 3) / 4;
    std::size_t row = client.welcome_selection_index / 4;
    std::size_t column = client.welcome_selection_index % 4;
    const auto row_width = [count](std::size_t target_row) {
        return std::min<std::size_t>(4, count - target_row * 4);
    };
    if (direction == kTerminalArrowLeft || direction == kTerminalArrowRight) {
        const std::size_t width = row_width(row);
        column = direction == kTerminalArrowRight
            ? (column + 1) % width
            : (column + width - 1) % width;
    } else {
        row = direction == kTerminalArrowDown
            ? (row + 1) % row_count
            : (row + row_count - 1) % row_count;
        column = std::min(column, row_width(row) - 1);
    }
    client.welcome_selection_index = row * 4 + column;
}

bool sysop_account_action_menu_active(const ClientContext& client) {
    return client.viewing_sysop && client.viewing_sysop_account_detail &&
        !client.editing_sysop_security_levels && !client.editing_sysop_acs_flags &&
        !client.editing_sysop_credits && !client.editing_sysop_file_points &&
        !client.editing_sysop_birth_date && !client.editing_sysop_sex &&
        !client.editing_sysop_expiration_date && !client.editing_sysop_validation_level &&
        !client.confirming_sysop_validation && !client.editing_sysop_profile &&
        !client.editing_sysop_short_message;
}

bool sysop_area_action_menu_active(const ClientContext& client) {
    return client.viewing_sysop_areas && !client.area_admin_kind.has_value() &&
        !client.area_admin_renaming_file && !client.area_admin_renaming_message &&
        !client.area_admin_deleting_file && !client.area_admin_deleting_message &&
        !client.editing_file_area_access && !client.editing_message_area_access &&
        !client.editing_message_force_read && !client.editing_message_area_password &&
        !client.editing_message_taglines && !client.editing_message_filter &&
        !client.editing_message_unhidden && !client.editing_message_tearline &&
        !client.editing_message_origin && !client.editing_message_real_names &&
        !client.editing_message_quote_templates && !client.editing_private_quote_templates &&
        !client.editing_global_anonymous_acs && !client.editing_global_post_acs &&
        !client.editing_global_post_limits && !client.editing_global_credit_costs &&
        !client.editing_global_mail_limits &&
        client.admin_policy_edit == ClientContext::AdminPolicyEdit::None &&
        !client.area_admin_confirming_file_deletion &&
        !client.area_admin_confirming_message_deletion;
}

bool is_file_area_menu(const ClientContext& client) {
    return client.viewing_files && !client.viewing_file_list && !client.viewing_file_detail &&
        !client.viewing_new_files && !client.viewing_file_validation &&
        !client.viewing_extended_file_description && !client.viewing_download_queue &&
        !client.viewing_archive && !client.viewing_archive_entry_detail &&
        !client.viewing_archive_text && !client.viewing_archive_art && !client.viewing_uploads &&
        !client.entering_file_scan_date;
}

bool handle_arrow_navigation(ClientContext& client, char direction) {
    client.menu_command_input.clear();
    if (client.choosing_message_search_field) {
        move_linear_selection(client.message_search_selection_index, 8, direction);
        show_message_search_prompt(client, false);
        return true;
    }
    if (client.welcome_menu_active) {
        move_welcome_selection(client, direction);
        client.menu_command_input.clear();
        show_welcome(client);
        return true;
    }
    if (client.viewing_time_bank &&
        client.time_bank_action == ClientContext::TimeBankAction::None) {
        move_linear_selection(client.time_bank_selection_index, 3, direction);
        redraw_time_bank(client);
        return true;
    }
    if (client.viewing_profile && !client.editing_profile) {
        const std::size_t count = client.viewing_profile_contacts ? 11 : 14;
        move_linear_selection(client.profile_selection_index, count, direction);
        show_profile(client);
        return true;
    }
    if (sysop_account_action_menu_active(client)) {
        constexpr std::size_t action_count = 12;
        const std::size_t current = client.sysop_account_action_selection_index % action_count;
        std::size_t row = current / 6;
        std::size_t column = current % 6;
        if (direction == kTerminalArrowLeft || direction == kTerminalArrowRight) {
            column = direction == kTerminalArrowRight
                ? (column + 1) % 6 : (column + 5) % 6;
        } else {
            row = (row + 1) % 2;
        }
        client.sysop_account_action_selection_index = row * 6 + column;
        show_sysop_account_review(client);
        return true;
    }
    if (sysop_area_action_menu_active(client)) {
        constexpr std::size_t action_count = 35;
        const std::size_t current = client.area_admin_action_selection_index % action_count;
        std::size_t row = current / 7;
        std::size_t column = current % 7;
        if (direction == kTerminalArrowLeft || direction == kTerminalArrowRight) {
            column = direction == kTerminalArrowRight
                ? (column + 1) % 7 : (column + 6) % 7;
        } else {
            row = (row + 1) % 5;
        }
        client.area_admin_action_selection_index = row * 7 + column;
        show_sysop_area_admin(client);
        return true;
    }
    const bool forward = direction == kTerminalArrowDown || direction == kTerminalArrowRight;
    if (client.viewing_art && client.art_catalog != nullptr && !client.art_catalog->empty()) {
        const std::size_t count = client.art_catalog->size();
        client.art_index = forward ? (client.art_index + 1) % count
                                   : (client.art_index + count - 1) % count;
        show_artwork(client);
        return true;
    }
    if (client.viewing_bulletins && client.bulletin_catalog != nullptr &&
        !client.bulletin_catalog->empty()) {
        const std::size_t count = std::min<std::size_t>(client.bulletin_catalog->size(), 26);
        client.bulletin_index = forward ? (client.bulletin_index + 1) % count
                                        : (client.bulletin_index + count - 1) % count;
        show_bulletins(client);
        return true;
    }
    if (client.viewing_quote_queue) {
        if (client.quote_submissions.entries.empty()) {
            (void)write_channel(client, "\a");
            return true;
        }
        const std::size_t count = client.quote_submissions.entries.size();
        if (forward && client.quote_submission_selection_index + 1 >= count &&
            client.quote_submission_page + 1 < client.quote_submissions.page_count) {
            ++client.quote_submission_page;
            client.quote_submission_selection_index = 0;
        } else if (!forward && client.quote_submission_selection_index == 0 &&
            client.quote_submission_page > 0) {
            --client.quote_submission_page;
            client.quote_submission_selection_index = 9;
        } else {
            move_linear_selection(client.quote_submission_selection_index, count, direction);
        }
        client.selected_quote_submission_id.reset();
        show_quote_queue(client);
        return true;
    }
    if (client.viewing_uploads && !client.viewing_upload_detail &&
        !client.confirming_upload_delete) {
        if (client.selecting_upload_area) {
            if (client.upload_publish_areas.empty()) {
                (void)write_channel(client, "\a");
                return true;
            }
            move_linear_selection(client.upload_publish_area_selection_index,
                client.upload_publish_areas.size(), direction);
            client.upload_publish_area_page = client.upload_publish_area_selection_index / 10;
            show_upload_publish_areas(client);
        } else {
            if (client.incoming_files.empty()) {
                (void)write_channel(client, "\a");
                return true;
            }
            move_linear_selection(client.incoming_file_selection_index,
                client.incoming_files.size(), direction);
            client.incoming_files_page = client.incoming_file_selection_index / 10;
            show_upload_review(client);
        }
        return true;
    }
    if (client.viewing_file_validation && !client.confirming_bulk_file_validation) {
        if (client.file_validation_page.files.empty()) {
            (void)write_channel(client, "\a");
            return true;
        }
        const std::size_t count = client.file_validation_page.files.size();
        if (forward && client.file_validation_selection_index + 1 >= count &&
            client.file_validation_page_index + 1 < client.file_validation_page.page_count) {
            ++client.file_validation_page_index;
            client.file_validation_selection_index = 0;
        } else if (!forward && client.file_validation_selection_index == 0 &&
            client.file_validation_page_index > 0) {
            --client.file_validation_page_index;
            client.file_validation_selection_index = 9;
        } else {
            move_linear_selection(client.file_validation_selection_index, count, direction);
        }
        show_file_validation_queue(client);
        return true;
    }
    if (client.viewing_new_files) {
        if (client.new_file_page.files.empty()) {
            (void)write_channel(client, "\a");
            return true;
        }
        const std::size_t count = client.new_file_page.files.size();
        if (forward && client.new_file_selection_index + 1 >= count &&
            client.new_file_page_index + 1 < client.new_file_page.page_count) {
            ++client.new_file_page_index;
            client.new_file_selection_index = 0;
        } else if (!forward && client.new_file_selection_index == 0 &&
            client.new_file_page_index > 0) {
            --client.new_file_page_index;
            client.new_file_selection_index = 9;
        } else {
            move_linear_selection(client.new_file_selection_index, count, direction);
        }
        show_new_file_scan(client);
        return true;
    }
    if (client.viewing_download_queue && !client.confirming_download_queue_clear) {
        if (client.download_queue.empty()) {
            (void)write_channel(client, "\a");
            return true;
        }
        move_linear_selection(client.download_queue_selection_index,
            client.download_queue.size(), direction);
        client.download_queue_page = client.download_queue_selection_index / 10;
        show_download_queue(client);
        return true;
    }
    if (client.viewing_archive && !client.archive_stack.empty() &&
        !client.archive_stack.back().visible_entries.empty()) {
        ArchiveFrame& frame = client.archive_stack.back();
        move_linear_selection(frame.selection_index, frame.visible_entries.size(), direction);
        frame.page = frame.selection_index / 10;
        show_archive_listing(client);
        return true;
    }
    if (client.selecting_message_move_area && !client.confirming_message_move) {
        const std::vector<BoardArea> targets = message_move_targets(client);
        const bool private_target_available = !client.moving_private_message;
        const std::size_t option_count = targets.size() +
            (private_target_available ? 1 : 0);
        if (option_count == 0) {
            (void)write_channel(client, "\a");
            return true;
        }
        move_linear_selection(client.message_move_selection_index, option_count, direction);
        const std::size_t page_size = private_target_available ? 9 : 10;
        client.message_move_page = private_target_available &&
                client.message_move_selection_index > 0
            ? (client.message_move_selection_index - 1) / page_size
            : (private_target_available ? 0 : client.message_move_selection_index / page_size);
        show_message_move_picker(client);
        return true;
    }
    if (client.viewing_sysop_audit) {
        if (forward && client.sysop_audit_page + 1 < client.sysop_audit.page_count) {
            ++client.sysop_audit_page;
            show_sysop_audit(client);
        } else if (!forward && client.sysop_audit_page > 0) {
            --client.sysop_audit_page;
            show_sysop_audit(client);
        }
        return true;
    }
    if (client.viewing_validation_admin && client.validation_admin_operation == '\0') {
        if (client.validation_levels.empty()) {
            (void)write_channel(client, "\a");
            return true;
        }
        move_linear_selection(client.validation_admin_selection_index,
            client.validation_levels.size(), direction);
        client.validation_admin_page = client.validation_admin_selection_index / 10;
        show_validation_level_admin(client);
        return true;
    }
    if (client.viewing_signup_question_admin && client.editing_custom_user_question == -1) {
        move_linear_selection(client.signup_question_prompt_selection_index, 3, direction);
        show_signup_question_admin(client);
        return true;
    }
    if (client.viewing_signup_question_admin && client.editing_custom_user_question == 0) {
        const std::size_t count = client.signup_preferences_page ? 6 : 12;
        if (client.columns >= 80 && client.rows >= 24 && !client.signup_preferences_page) {
            std::size_t row = client.signup_question_selection_index % 6;
            std::size_t column = client.signup_question_selection_index / 6;
            if (direction == kTerminalArrowUp || direction == kTerminalArrowDown) {
                row = direction == kTerminalArrowDown ? (row + 1) % 6 : (row + 5) % 6;
            } else {
                column = column == 0 ? 1 : 0;
            }
            client.signup_question_selection_index = column * 6 + row;
        } else {
            move_linear_selection(client.signup_question_selection_index, count, direction);
        }
        show_signup_question_admin(client);
        return true;
    }
    if (client.viewing_auto_message && !client.writing_message) {
        if (forward && client.auto_message_page + 1 < client.auto_message_page_count) {
            ++client.auto_message_page;
            show_auto_message(client);
        } else if (!forward && client.auto_message_page > 0) {
            --client.auto_message_page;
            show_auto_message(client);
        }
        return true;
    }
    if (client.viewing_callers) {
        if (forward && client.caller_sessions.page + 1 < client.caller_sessions.page_count) {
            ++client.caller_page;
            show_callers(client);
        } else if (!forward && client.caller_page > 0) {
            --client.caller_page;
            show_callers(client);
        }
        return true;
    }
    if (client.viewing_statistics) {
        if (forward && client.statistics_page < 3) {
            ++client.statistics_page;
            show_statistics(client);
        } else if (!forward && client.statistics_page > 0) {
            --client.statistics_page;
            show_statistics(client);
        }
        return true;
    }
    if (client.viewing_quote) {
        if (direction == kTerminalArrowUp || direction == kTerminalArrowDown) {
            if (forward && client.quote_content_page + 1 < client.quote_content_page_count) {
                ++client.quote_content_page;
                show_quote(client);
            } else if (!forward && client.quote_content_page > 0) {
                --client.quote_content_page;
                show_quote(client);
            }
        } else if (!client.quote_options.empty()) {
            client.quote_index = forward
                ? (client.quote_index + 1) % client.quote_options.size()
                : (client.quote_index + client.quote_options.size() - 1) % client.quote_options.size();
            client.quote_content_page = 0;
            show_quote(client);
        }
        return true;
    }
    if (client.viewing_short_messages) {
        const std::size_t page_count = std::max<std::size_t>(
            1, (client.short_messages.size() + 9) / 10);
        if (forward && client.short_message_page + 1 < page_count) {
            ++client.short_message_page;
        } else if (!forward && client.short_message_page > 0) {
            --client.short_message_page;
        }
        if (!write_channel(client, short_messages_screen(client.short_messages,
                client.short_message_page, client.columns, client.rows,
                render_screen_art(client, client.mailbox_art)))) {
            client.close_requested = true;
        }
        return true;
    }
    if (client.viewing_messages && client.reading_message) {
        if (direction == kTerminalArrowDown || direction == kTerminalArrowRight) {
            if (client.message_page + 1 < client.message_page_count) {
                ++client.message_page;
                show_selected_message(client);
            }
        } else if (client.message_page > 0) {
            --client.message_page;
            show_selected_message(client);
        }
        return true;
    }
    if (client.viewing_private_mail && client.reading_private_message) {
        if (forward && client.private_message_page + 1 < client.private_message_page_count) {
            ++client.private_message_page;
            show_selected_private_message(client);
        } else if (!forward && client.private_message_page > 0) {
            --client.private_message_page;
            show_selected_private_message(client);
        }
        return true;
    }
    if (client.viewing_private_mail && !client.reading_private_message &&
        !client.writing_message && !client.selecting_message_move_area) {
        if (client.private_messages.empty()) {
            (void)write_channel(client, "\a");
            return true;
        }
        if (forward && client.private_message_index + 1 >= client.private_messages.size()) {
            if (client.private_mail_list_page + 1 < client.private_mail_list_page_count) {
                ++client.private_mail_list_page;
                client.private_message_index = 0;
            } else {
                client.private_message_index = 0;
            }
        } else if (!forward && client.private_message_index == 0) {
            if (client.private_mail_list_page > 0) {
                --client.private_mail_list_page;
                client.private_message_index = 9;
            } else {
                client.private_message_index = client.private_messages.size() - 1;
            }
        } else {
            move_linear_selection(client.private_message_index,
                client.private_messages.size(), direction);
        }
        show_private_mailbox(client);
        return true;
    }
    if (client.viewing_bbs_directory && client.viewing_bbs_detail &&
        !client.confirming_bbs_delete) {
        if ((forward && client.bbs_detail_page == 0) || (!forward && client.bbs_detail_page > 0)) {
            client.bbs_detail_page = forward ? 1 : 0;
            show_bbs_detail(client);
        } else {
            (void)write_channel(client, "\a");
        }
        return true;
    }
    if (client.viewing_bbs_directory && !client.viewing_bbs_detail &&
        !client.editing_bbs_listing && !client.confirming_bbs_delete) {
        if (client.bbs_listing_page.entries.empty()) {
            (void)write_channel(client, "\a");
            return true;
        }
        const std::size_t count = client.bbs_listing_page.entries.size();
        if (client.selected_bbs_listing_id.has_value() && forward &&
            client.bbs_listing_selection_index + 1 >= count &&
            client.bbs_listing_page_index + 1 < client.bbs_listing_page.page_count) {
            ++client.bbs_listing_page_index;
            client.bbs_listing_selection_index = 0;
            client.selected_bbs_listing_id.reset();
        } else if (client.selected_bbs_listing_id.has_value() && !forward &&
            client.bbs_listing_selection_index == 0 && client.bbs_listing_page_index > 0) {
            --client.bbs_listing_page_index;
            client.bbs_listing_selection_index = 9;
            client.selected_bbs_listing_id.reset();
        } else if (!client.selected_bbs_listing_id.has_value()) {
            client.bbs_listing_selection_index = 0;
        } else {
            move_linear_selection(client.bbs_listing_selection_index, count, direction);
        }
        if (client.selected_bbs_listing_id.has_value()) {
            client.bbs_listing_selection_index %= count;
            client.selected_bbs_listing_id = client.bbs_listing_page.entries[
                client.bbs_listing_selection_index].id;
        }
        show_bbs_directory(client);
        return true;
    }
    if (client.viewing_polls && !client.creating_poll && !client.adding_poll_choice) {
        if (client.reading_poll) {
            const std::size_t count = client.active_poll.options.size();
            if (count == 0) {
                (void)write_channel(client, "\a");
                return true;
            }
            move_linear_selection(client.poll_choice_selection_index, count, direction);
            client.poll_choice_page = client.poll_choice_selection_index / 10;
        } else {
            const std::size_t count = client.poll_list.size();
            if (count == 0) {
                (void)write_channel(client, "\a");
                return true;
            }
            move_linear_selection(client.poll_selection_index, count, direction);
            client.poll_page = client.poll_selection_index / 10;
        }
        show_polls(client);
        return true;
    }
    if (client.viewing_one_liners && !client.is_sysop &&
        !client.adding_one_liner && !client.editing_one_liner &&
        !client.confirming_one_liner_post && !client.confirming_one_liner_delete &&
        !client.prompting_one_liner_anonymous) {
        if (forward && client.one_liner_page.page + 1 < client.one_liner_page.page_count) {
            ++client.one_liner_page.page;
            show_one_liners(client);
        } else if (!forward && client.one_liner_page.page > 0) {
            --client.one_liner_page.page;
            show_one_liners(client);
        }
        return true;
    }
    if (client.viewing_one_liners && client.is_sysop &&
        !client.adding_one_liner && !client.editing_one_liner &&
        !client.confirming_one_liner_post && !client.confirming_one_liner_delete &&
        !client.prompting_one_liner_anonymous) {
        const std::size_t count = client.one_liner_page.entries.size();
        if (count == 0) {
            (void)write_channel(client, "\a");
            return true;
        }
        if (client.selected_one_liner_id.has_value() && forward &&
            client.one_liner_selection_index + 1 >= count &&
            client.one_liner_page.page + 1 < client.one_liner_page.page_count) {
            ++client.one_liner_page.page;
            client.one_liner_selection_index = 0;
            client.selected_one_liner_id.reset();
        } else if (client.selected_one_liner_id.has_value() && !forward &&
            client.one_liner_selection_index == 0 && client.one_liner_page.page > 0) {
            --client.one_liner_page.page;
            client.one_liner_selection_index = 9;
            client.selected_one_liner_id.reset();
        } else if (client.selected_one_liner_id.has_value()) {
            move_linear_selection(client.one_liner_selection_index, count, direction);
        } else {
            client.one_liner_selection_index = 0;
        }
        if (client.selected_one_liner_id.has_value()) {
            client.selected_one_liner_id =
                client.one_liner_page.entries[client.one_liner_selection_index].id;
        }
        show_one_liners(client);
        return true;
    }
    if (client.viewing_sysop && !client.viewing_sysop_account_detail &&
        !client.viewing_sysop_audit && !client.viewing_signup_question_admin &&
        !client.viewing_validation_admin && !client.editing_sysop_profile) {
        if (client.sysop_accounts.empty()) {
            (void)write_channel(client, "\a");
            return true;
        }
        const std::size_t current = client.sysop_selected_index.value_or(
            std::min(client.sysop_page * 10, client.sysop_accounts.size() - 1));
        std::size_t next = current;
        if (client.sysop_selected_index.has_value()) {
            move_linear_selection(next, client.sysop_accounts.size(), direction);
        }
        client.sysop_selected_index = next;
        client.sysop_page = next / 10;
        show_sysop_accounts(client);
        return true;
    }
    if (client.viewing_messages && !client.reading_message &&
        !client.entering_message_search_query && !client.choosing_message_search_field &&
        !client.writing_message && !client.confirming_message_validation &&
        !client.selecting_message_move_area) {
        if (client.board_messages.empty()) {
            (void)write_channel(client, "\a");
            return true;
        }
        if (forward && client.message_list_selection_index + 1 >= client.board_messages.size()) {
            if (client.message_list_page + 1 < client.message_list_page_count) {
                ++client.message_list_page;
                client.message_list_selection_index = 0;
            } else {
                client.message_list_selection_index = 0;
            }
        } else if (!forward && client.message_list_selection_index == 0) {
            if (client.message_list_page > 0) {
                --client.message_list_page;
                client.message_list_selection_index = 9;
            } else {
                client.message_list_selection_index = client.board_messages.size() - 1;
            }
        } else {
            move_linear_selection(client.message_list_selection_index,
                client.board_messages.size(), direction);
        }
        show_message_board(client);
        return true;
    }
    if (client.viewing_new_scan) {
        if (client.new_scan_page.messages.empty()) {
            (void)write_channel(client, "\a");
            return true;
        }
        if (forward && client.new_scan_selection_index + 1 >= client.new_scan_page.messages.size()) {
            if (client.new_scan_page_index + 1 < client.new_scan_page.page_count) {
                ++client.new_scan_page_index;
                client.new_scan_selection_index = 0;
            } else {
                client.new_scan_selection_index = 0;
            }
        } else if (!forward && client.new_scan_selection_index == 0) {
            if (client.new_scan_page_index > 0) {
                --client.new_scan_page_index;
                client.new_scan_selection_index = 9;
            } else {
                client.new_scan_selection_index = client.new_scan_page.messages.size() - 1;
            }
        } else {
            move_linear_selection(client.new_scan_selection_index,
                client.new_scan_page.messages.size(), direction);
        }
        show_unread_messages(client);
        return true;
    }
    if (client.viewing_areas) {
        move_linear_selection(client.message_area_selection_index,
            client.board_areas.size(), direction);
        client.area_page = client.message_area_selection_index / 10;
        show_message_areas(client);
        return true;
    }
    if (client.viewing_message_scan_settings) {
        if (client.board_areas.empty()) {
            (void)write_channel(client, "\a");
            return true;
        }
        move_linear_selection(client.message_area_selection_index,
            client.board_areas.size(), direction);
        client.area_page = client.message_area_selection_index / 10;
        show_message_scan_settings(client);
        return true;
    }
    if (client.viewing_files && client.viewing_file_list && !client.searching_files) {
        if (client.file_page.files.empty()) {
            (void)write_channel(client, "\a");
            return true;
        }
        if (forward && client.file_list_selection_index + 1 >= client.file_page.files.size()) {
            if (client.file_list_page + 1 < client.file_page.page_count) {
                ++client.file_list_page;
                client.file_list_selection_index = 0;
            } else {
                client.file_list_selection_index = 0;
            }
        } else if (!forward && client.file_list_selection_index == 0) {
            if (client.file_list_page > 0) {
                --client.file_list_page;
                client.file_list_selection_index = 9;
            } else {
                client.file_list_selection_index = client.file_page.files.size() - 1;
            }
        } else {
            move_linear_selection(client.file_list_selection_index,
                client.file_page.files.size(), direction);
        }
        show_file_listing(client);
        return true;
    }
    if (is_file_area_menu(client)) {
        move_linear_selection(client.file_area_selection_index,
            client.file_areas.size(), direction);
        client.file_area_page = client.file_area_selection_index / 10;
        show_file_areas(client);
        return true;
    }
    return true;
}

void handle_input(ClientContext& client, char input_character) {
    if (client.waiting_for_display_pause) {
        resume_display_after_pause(client, input_character);
        return;
    }
    if (client.ignore_line_feed && input_character == '\n') {
        client.ignore_line_feed = false;
        return;
    }
    if (is_terminal_arrow(input_character)) {
        (void)handle_arrow_navigation(client, input_character);
        return;
    }
    if (client.viewing_time_bank &&
        client.time_bank_action == ClientContext::TimeBankAction::None &&
        (input_character == '\r' || input_character == '\n')) {
        static constexpr std::string_view time_bank_keys{"DWQ"};
        if (client.time_bank_selection_index < time_bank_keys.size()) {
            client.ignore_line_feed = input_character == '\r';
            handle_input(client, time_bank_keys[client.time_bank_selection_index]);
            return;
        }
    }
    if (client.viewing_profile && !client.editing_profile &&
        (input_character == '\r' || input_character == '\n')) {
        static constexpr std::string_view profile_keys{"RLSBGCXPHEMWNQ"};
        static constexpr std::string_view contact_keys{"CALZP123RMQ"};
        const std::string_view keys = client.viewing_profile_contacts
            ? contact_keys : profile_keys;
        if (client.profile_selection_index < keys.size()) {
            client.ignore_line_feed = input_character == '\r';
            handle_input(client, keys[client.profile_selection_index]);
            return;
        }
    }
    if ((input_character == '\r' || input_character == '\n') &&
        (client.profile.hotkeys || client.menu_command_input.empty())) {
        const auto select_numbered_row = [&](std::size_t row) {
            client.ignore_line_feed = input_character == '\r';
            handle_input(client, row == 9 ? '0' : static_cast<char>('1' + row));
        };
        if (client.viewing_quote_queue && !client.quote_submissions.entries.empty()) {
            select_numbered_row(client.quote_submission_selection_index);
            return;
        }
        if (client.viewing_signup_question_admin && client.editing_custom_user_question == 0) {
            static constexpr std::string_view personal_keys{"BCDEFGHIJKLM"};
            static constexpr std::string_view preference_keys{"OSTUVY"};
            const std::string_view keys = client.signup_preferences_page
                ? preference_keys : personal_keys;
            if (client.signup_question_selection_index < keys.size()) {
                handle_input(client, keys[client.signup_question_selection_index]);
                return;
            }
        }
        if (client.viewing_message_scan_settings && !client.board_areas.empty()) {
            select_numbered_row(client.message_area_selection_index % 10);
            return;
        }
        if (client.viewing_polls && client.reading_poll && !client.creating_poll &&
            !client.adding_poll_choice &&
            (!client.active_poll.caller_vote.has_value() || client.changing_poll_vote) &&
            !client.active_poll.options.empty()) {
            select_numbered_row(client.poll_choice_selection_index % 10);
            return;
        }
        if (client.viewing_one_liners && client.is_sysop &&
            !client.adding_one_liner && !client.editing_one_liner &&
            !client.confirming_one_liner_post && !client.confirming_one_liner_delete &&
            !client.prompting_one_liner_anonymous &&
            !client.one_liner_page.entries.empty()) {
            select_numbered_row(client.one_liner_selection_index % 10);
            return;
        }
        if (client.viewing_uploads && !client.viewing_upload_detail &&
            !client.confirming_upload_delete) {
            if (client.selecting_upload_area && !client.upload_publish_areas.empty()) {
                select_numbered_row(client.upload_publish_area_selection_index % 10);
                return;
            }
            if (!client.selecting_upload_area && !client.incoming_files.empty()) {
                select_numbered_row(client.incoming_file_selection_index % 10);
                return;
            }
        }
        if (client.viewing_file_validation && !client.confirming_bulk_file_validation &&
            !client.file_validation_page.files.empty()) {
            select_numbered_row(client.file_validation_selection_index);
            return;
        }
        if (client.viewing_new_files && !client.new_file_page.files.empty()) {
            select_numbered_row(client.new_file_selection_index);
            return;
        }
        if (client.viewing_download_queue && !client.confirming_download_queue_clear &&
            !client.download_queue.empty()) {
            select_numbered_row(client.download_queue_selection_index % 10);
            return;
        }
        if (client.viewing_archive && !client.archive_stack.empty() &&
            !client.archive_stack.back().visible_entries.empty()) {
            select_numbered_row(client.archive_stack.back().selection_index % 10);
            return;
        }
    }
    if ((input_character == '\r' || input_character == '\n') && client.viewing_areas &&
        (client.profile.hotkeys || client.menu_command_input.empty())) {
        client.ignore_line_feed = input_character == '\r';
        if (client.message_area_selection_index < client.board_areas.size()) {
            select_message_area(client, client.message_area_selection_index);
        } else {
            (void)write_channel(client, "\a");
        }
        return;
    }
    if ((input_character == '\r' || input_character == '\n') &&
        client.viewing_messages && !client.reading_message &&
        !client.entering_message_search_query && !client.choosing_message_search_field &&
        !client.writing_message && !client.confirming_message_validation &&
        !client.selecting_message_move_area &&
        (client.profile.hotkeys || client.menu_command_input.empty())) {
        client.ignore_line_feed = input_character == '\r';
        select_board_message(client, client.message_list_selection_index);
        return;
    }
    if ((input_character == '\r' || input_character == '\n') && client.viewing_new_scan &&
        (client.profile.hotkeys || client.menu_command_input.empty())) {
        client.ignore_line_feed = input_character == '\r';
        if (client.new_scan_selection_index < client.new_scan_page.messages.size()) {
            const UnreadBoardMessage& entry =
                client.new_scan_page.messages[client.new_scan_selection_index];
            client.current_area = entry.area_name;
            remember_message_area(client, client.current_area);
            client.reader_message = entry.message;
            client.message_page = 0;
            client.reader_backstack.clear();
            client.reading_from_new_scan = true;
            client.viewing_new_scan = false;
            client.viewing_messages = true;
            show_selected_message(client);
        } else {
            (void)write_channel(client, "\a");
        }
        return;
    }
    if ((input_character == '\r' || input_character == '\n') &&
        client.viewing_private_mail && !client.reading_private_message &&
        !client.writing_message && !client.selecting_message_move_area &&
        (client.profile.hotkeys || client.menu_command_input.empty())) {
        client.ignore_line_feed = input_character == '\r';
        select_private_message(client, client.private_message_index);
        return;
    }
    if ((input_character == '\r' || input_character == '\n') &&
        client.viewing_files && client.viewing_file_list && !client.searching_files &&
        (client.profile.hotkeys || client.menu_command_input.empty())) {
        client.ignore_line_feed = input_character == '\r';
        if (client.file_list_selection_index < client.file_page.files.size()) {
            open_selected_public_file(client, client.file_page.files[client.file_list_selection_index]);
        } else {
            (void)write_channel(client, "\a");
        }
        return;
    }
    if ((input_character == '\r' || input_character == '\n') && is_file_area_menu(client) &&
        (client.profile.hotkeys || client.menu_command_input.empty())) {
        client.ignore_line_feed = input_character == '\r';
        if (client.file_area_selection_index >= client.file_areas.size()) {
            (void)write_channel(client, "\a");
        } else if (client.choosing_file_scan_area && client.files != nullptr) {
            try {
                (void)client.files->toggle_new_file_scan(
                    client.handle, client.file_areas[client.file_area_selection_index].id);
                client.choosing_file_scan_area = false;
                show_file_areas(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not change new-file scan area for "
                          << client.handle << ": " << error.what() << '\n';
                (void)write_channel(client, "\a");
                show_file_areas(client);
            }
        } else {
            select_file_area(client, client.file_area_selection_index);
        }
        return;
    }
    if ((input_character == '\r' || input_character == '\n') &&
        client.viewing_bbs_directory && !client.viewing_bbs_detail &&
        !client.editing_bbs_listing && !client.confirming_bbs_delete &&
        (client.profile.hotkeys || client.menu_command_input.empty())) {
        client.ignore_line_feed = input_character == '\r';
        if (!client.bbs_listing_page.entries.empty()) {
            client.bbs_listing_selection_index = std::min(
                client.bbs_listing_selection_index,
                client.bbs_listing_page.entries.size() - 1);
            const BbsListing& selected = client.bbs_listing_page.entries[
                client.bbs_listing_selection_index];
            client.selected_bbs_listing_id = selected.id;
            client.viewing_bbs_detail = true;
            client.bbs_detail_page = 0;
            show_bbs_detail(client);
        } else {
            (void)write_channel(client, "\a");
        }
        return;
    }
    if ((input_character == '\r' || input_character == '\n') &&
        client.viewing_validation_admin && client.validation_admin_operation == '\0' &&
        !client.validation_levels.empty() &&
        (client.profile.hotkeys || client.menu_command_input.empty())) {
        client.ignore_line_feed = input_character == '\r';
        client.validation_admin_selection_index = std::min(
            client.validation_admin_selection_index, client.validation_levels.size() - 1);
        client.validation_admin_input = format_validation_admin_record(
            client.validation_levels[client.validation_admin_selection_index]);
        client.validation_admin_operation = 'S';
        client.validation_admin_notice = "Edit the selected record, then press Enter to save.";
        show_validation_level_admin(client);
        return;
    }
    if ((input_character == '\r' || input_character == '\n') &&
        sysop_account_action_menu_active(client) &&
        (client.profile.hotkeys || client.menu_command_input.empty())) {
        static constexpr std::string_view actions{"VEIDGXSFCPMQ"};
        client.ignore_line_feed = input_character == '\r';
        const std::size_t index = client.sysop_account_action_selection_index % actions.size();
        handle_input(client, actions[index]);
        return;
    }
    if ((input_character == '\r' || input_character == '\n') &&
        sysop_area_action_menu_active(client) &&
        (client.profile.hotkeys || client.menu_command_input.empty())) {
        static constexpr std::string_view actions{"MFENHIOBAGLWKRJYTUVZ1234567890CXDPQ"};
        static_assert(actions.size() == 35);
        client.ignore_line_feed = input_character == '\r';
        const std::size_t index = client.area_admin_action_selection_index % 35;
        handle_input(client, actions[index]);
        return;
    }
    if ((input_character == '\r' || input_character == '\n') &&
        client.viewing_sysop && !client.viewing_sysop_account_detail &&
        !client.viewing_sysop_audit && !client.viewing_signup_question_admin &&
        !client.viewing_validation_admin && !client.editing_sysop_profile &&
        (client.profile.hotkeys || client.menu_command_input.empty())) {
        client.ignore_line_feed = input_character == '\r';
        if (!client.sysop_accounts.empty()) {
            const std::size_t index = std::min(
                client.sysop_selected_index.value_or(client.sysop_page * 10),
                client.sysop_accounts.size() - 1);
            client.sysop_selected_index = index;
            client.sysop_page = index / 10;
            show_sysop_account_review(client);
        } else {
            (void)write_channel(client, "\a");
        }
        return;
    }
    if ((input_character == '\r' || input_character == '\n') && client.viewing_polls &&
        !client.creating_poll && !client.adding_poll_choice && !client.reading_poll &&
        (client.profile.hotkeys || client.menu_command_input.empty())) {
        client.ignore_line_feed = input_character == '\r';
        if (client.poll_selection_index < client.poll_list.size()) {
            client.selected_poll_id = client.poll_list[client.poll_selection_index].id;
            client.reading_poll = true;
            client.poll_choice_page = 0;
            client.poll_choice_selection_index = 0;
            client.showing_poll_results = false;
            client.changing_poll_vote = false;
            show_polls(client);
        } else {
            (void)write_channel(client, "\a");
        }
        return;
    }
    if ((input_character == '\r' || input_character == '\n') && client.viewing_bulletins &&
        !client.reading_bulletin && (client.profile.hotkeys || client.menu_command_input.empty())) {
        client.ignore_line_feed = input_character == '\r';
        client.reading_bulletin = true;
        show_bulletins(client);
        return;
    }
    if ((input_character == '\r' || input_character == '\n') && client.viewing_polls &&
        client.reading_poll && !client.creating_poll && !client.adding_poll_choice &&
        (!client.active_poll.caller_vote.has_value() || client.changing_poll_vote) &&
        (client.profile.hotkeys || client.menu_command_input.empty())) {
        client.ignore_line_feed = input_character == '\r';
        cast_selected_poll_vote(client, client.poll_choice_selection_index);
        return;
    }
    client.ignore_line_feed = false;

    if (client.checking_birth_date) {
        if (input_character == '\r' || input_character == '\n') {
            client.ignore_line_feed = input_character == '\r';
            const std::string_view stored(client.profile.birth_date);
            const bool stored_date_valid = stored.size() == 10 && stored[4] == '-' && stored[7] == '-';
            const bool input_valid = client.birthday_check_input.size() == 10 &&
                client.birthday_check_input[2] == '/' && client.birthday_check_input[5] == '/' &&
                std::all_of(client.birthday_check_input.begin(), client.birthday_check_input.end(),
                    [index = std::size_t{0}](char value) mutable {
                        const std::size_t position = index++;
                        return position == 2 || position == 5
                            ? value == '/'
                            : value >= '0' && value <= '9';
                    });
            const std::string expected = stored_date_valid
                ? std::string(stored.substr(5, 2)) + "/" + std::string(stored.substr(8, 2)) + "/" +
                    std::string(stored.substr(0, 4))
                : std::string{};
            if (input_valid && client.birthday_check_input == expected) {
                client.checking_birth_date = false;
                client.birthday_check_required = false;
                client.birthday_check_input.clear();
                client.drawn = false;
                show_initial_screen(client);
            } else {
                (void)write_channel(client, "\r\nDate of birth verification failed. Disconnecting.\r\n");
                std::clog << "Caller " << client.handle << " failed birthday verification.\n";
                client.birthday_check_input.clear();
                client.checking_birth_date = false;
                client.close_requested = true;
            }
        } else if (input_character == 27) {
            (void)write_channel(client, "\r\nDate of birth verification cancelled. Disconnecting.\r\n");
            client.birthday_check_input.clear();
            client.checking_birth_date = false;
            client.close_requested = true;
        } else if (input_character == '\b' || input_character == 127) {
            if (!client.birthday_check_input.empty()) {
                client.birthday_check_input.pop_back();
                (void)write_channel(client, "\b \b");
            }
        } else {
            const unsigned char byte = static_cast<unsigned char>(input_character);
            if (((byte >= '0' && byte <= '9') || byte == '/') &&
                client.birthday_check_input.size() < 10) {
                client.birthday_check_input.push_back(input_character);
                (void)write_channel(client, "*");
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.entering_message_scan_date) {
        if (input_character == '\r' || input_character == '\n') {
            client.ignore_line_feed = input_character == '\r';
            try {
                client.messages->set_message_scan_date(client.handle, client.message_scan_date_input);
                client.entering_message_scan_date = false;
                client.message_scan_date_input.clear();
                (void)write_channel(client, "\r\nMessage scan date saved.\r\n");
                show_message_areas(client);
            } catch (const std::exception& error) {
                client.message_scan_date_input.clear();
                (void)write_channel(client, "\r\n" + std::string(error.what()) +
                    "\r\nEnter oldest date for new messages (MM/DD/YYYY), or Esc to cancel: ");
            }
        } else if (input_character == 27) {
            client.entering_message_scan_date = false;
            client.message_scan_date_input.clear();
            show_message_areas(client);
        } else if (input_character == '\b' || input_character == 127) {
            if (!client.message_scan_date_input.empty()) {
                client.message_scan_date_input.pop_back();
                (void)write_channel(client, "\b \b");
            }
        } else {
            const unsigned char byte = static_cast<unsigned char>(input_character);
            if (((byte >= '0' && byte <= '9') || byte == '/') &&
                client.message_scan_date_input.size() < 10) {
                client.message_scan_date_input.push_back(input_character);
                (void)write_channel(client, std::string_view(&input_character, 1));
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.entering_file_scan_date) {
        if (input_character == '\r' || input_character == '\n') {
            client.ignore_line_feed = input_character == '\r';
            try {
                client.files->set_new_file_scan_date(client.handle, client.file_scan_date_input);
                client.entering_file_scan_date = false;
                client.file_scan_date_input.clear();
                (void)write_channel(client, "\r\nNew-file scan date saved.\r\n");
                show_file_areas(client);
            } catch (const std::exception& error) {
                client.file_scan_date_input.clear();
                (void)write_channel(client, "\r\n" + std::string(error.what()) +
                    "\r\nEnter oldest date for new files (MM/DD/YYYY), or Esc to cancel: ");
            }
        } else if (input_character == 27) {
            client.entering_file_scan_date = false;
            client.file_scan_date_input.clear();
            show_file_areas(client);
        } else if (input_character == '\b' || input_character == 127) {
            if (!client.file_scan_date_input.empty()) {
                client.file_scan_date_input.pop_back();
                (void)write_channel(client, "\b \b");
            }
        } else {
            const unsigned char byte = static_cast<unsigned char>(input_character);
            if (((byte >= '0' && byte <= '9') || byte == '/') &&
                client.file_scan_date_input.size() < 10) {
                client.file_scan_date_input.push_back(input_character);
                (void)write_channel(client, std::string_view(&input_character, 1));
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.entering_file_move_area) {
        if (input_character == '\r' || input_character == '\n') {
            client.ignore_line_feed = input_character == '\r';
            int target_area_id = 0;
            const auto parsed = std::from_chars(client.file_move_area_input.data(),
                client.file_move_area_input.data() + client.file_move_area_input.size(), target_area_id);
            if (client.file_move_area_input.empty() || parsed.ec != std::errc{} ||
                parsed.ptr != client.file_move_area_input.data() + client.file_move_area_input.size() ||
                target_area_id < 1) {
                (void)write_channel(client, "\a");
                return;
            }
            try {
                const std::string filename = client.selected_public_file.has_value()
                    ? client.selected_public_file->name : std::string{};
                const int source_area_id = client.file_area_id;
                client.files->move_public_file(client.handle, source_area_id, filename, target_area_id);
                client.file_area_id = target_area_id;
                client.file_area_name = "#" + std::to_string(target_area_id);
                client.entering_file_move_area = false;
                client.file_move_area_input.clear();
                try {
                    for (const FileAreaSummary& area : client.files->areas(client.handle)) {
                        if (area.id == target_area_id) {
                            client.file_area_name = area.name;
                            break;
                        }
                    }
                } catch (const std::exception& error) {
                    std::cerr << "Could not reload file-area names after move: " << error.what() << '\n';
                }
                record_sysop_action(client, "moved public file", filename + " from area " +
                    std::to_string(source_area_id) + " to area " + std::to_string(target_area_id));
                show_public_file_detail(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not move public file for " << client.handle << ": "
                          << error.what() << '\n';
                (void)write_channel(client, "\r\n" + std::string(error.what()) +
                    "\r\nMove to area ID (Esc cancels): ");
                client.file_move_area_input.clear();
            }
        } else if (input_character == 27) {
            client.entering_file_move_area = false;
            client.file_move_area_input.clear();
            show_public_file_detail(client);
        } else if (input_character == '\b' || input_character == 127) {
            if (!client.file_move_area_input.empty()) {
                client.file_move_area_input.pop_back();
                (void)write_channel(client, "\b \b");
            }
        } else {
            const unsigned char byte = static_cast<unsigned char>(input_character);
            if (byte >= '0' && byte <= '9' && client.file_move_area_input.size() < 10) {
                client.file_move_area_input.push_back(input_character);
                (void)write_channel(client, std::string_view(&input_character, 1));
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.entering_file_rename) {
        if (input_character == '\r' || input_character == '\n') {
            client.ignore_line_feed = input_character == '\r';
            try {
                if (client.files == nullptr || !client.selected_public_file.has_value()) {
                    throw std::invalid_argument("file rename lost its selected file");
                }
                const std::string old_name = client.selected_public_file->name;
                client.files->rename_public_file(client.handle, client.file_area_id,
                    old_name, client.file_rename_input);
                client.selected_public_file->name = client.file_rename_input;
                record_sysop_action(client, "renamed public file",
                    old_name + " to " + client.file_rename_input + " in area " +
                    std::to_string(client.file_area_id));
                client.entering_file_rename = false;
                client.file_rename_input.clear();
                show_public_file_detail(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not rename public file for " << client.handle << ": "
                          << error.what() << '\n';
                (void)write_channel(client, "\r\n" + std::string(error.what()) +
                    "\r\nNew file name (Esc cancels): ");
                client.file_rename_input.clear();
            }
        } else if (input_character == 27) {
            client.entering_file_rename = false;
            client.file_rename_input.clear();
            show_public_file_detail(client);
        } else if (input_character == '\b' || input_character == 127) {
            if (!client.file_rename_input.empty()) {
                client.file_rename_input.pop_back();
                (void)write_channel(client, "\b \b");
            }
        } else {
            const unsigned char byte = static_cast<unsigned char>(input_character);
            if (byte >= 32 && byte != 127 && byte != 27 && client.file_rename_input.size() < 255) {
                client.file_rename_input.push_back(input_character);
                (void)write_channel(client, std::string_view(&input_character, 1));
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.entering_file_download_count) {
        if (input_character == '\r' || input_character == '\n') {
            client.ignore_line_feed = input_character == '\r';
            unsigned long long count = 0;
            const auto parsed = std::from_chars(client.file_download_count_input.data(),
                client.file_download_count_input.data() + client.file_download_count_input.size(), count);
            if (client.file_download_count_input.empty() || parsed.ec != std::errc{} ||
                parsed.ptr != client.file_download_count_input.data() + client.file_download_count_input.size() ||
                count > static_cast<unsigned long long>(INT_MAX)) {
                (void)write_channel(client, "\a");
                return;
            }
            try {
                if (client.files == nullptr || !client.selected_public_file.has_value()) {
                    throw std::invalid_argument("download-count editor lost its selected file");
                }
                const std::string filename = client.selected_public_file->name;
                client.files->set_download_count(client.handle, client.file_area_id, filename, count);
                client.selected_public_file->download_count = static_cast<std::uint64_t>(count);
                record_sysop_action(client, "changed public-file download count",
                    filename + " in area " + std::to_string(client.file_area_id) + " to " +
                    std::to_string(count));
                client.entering_file_download_count = false;
                client.file_download_count_input.clear();
                show_public_file_detail(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not change file download count for " << client.handle << ": "
                          << error.what() << '\n';
                (void)write_channel(client, "\r\n" + std::string(error.what()) +
                    "\r\nCompleted downloads (Esc cancels): ");
                client.file_download_count_input.clear();
            }
        } else if (input_character == 27) {
            client.entering_file_download_count = false;
            client.file_download_count_input.clear();
            show_public_file_detail(client);
        } else if (input_character == '\b' || input_character == 127) {
            if (!client.file_download_count_input.empty()) {
                client.file_download_count_input.pop_back();
                (void)write_channel(client, "\b \b");
            }
        } else {
            const unsigned char byte = static_cast<unsigned char>(input_character);
            if (byte >= '0' && byte <= '9' && client.file_download_count_input.size() < 10) {
                client.file_download_count_input.push_back(input_character);
                (void)write_channel(client, std::string_view(&input_character, 1));
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.entering_file_point_validation) {
        if (input_character == '\r' || input_character == '\n') {
            client.ignore_line_feed = input_character == '\r';
            unsigned long long points = 0;
            const auto parsed = std::from_chars(client.validation_file_points_input.data(),
                client.validation_file_points_input.data() + client.validation_file_points_input.size(), points);
            if (client.validation_file_points_input.empty()) {
                client.entering_file_point_validation = false;
                client.validation_file_points_input.clear();
                show_public_file_detail(client);
            } else if (parsed.ec != std::errc{} ||
                parsed.ptr != client.validation_file_points_input.data() +
                    client.validation_file_points_input.size() || points > 999ULL) {
                (void)write_channel(client, "\a");
            } else {
                client.validation_file_points = static_cast<std::uint64_t>(points);
                client.entering_file_point_validation = false;
                client.entering_file_owner_point_adjustment = true;
                client.validation_file_points_input.clear();
                client.owner_point_adjustment_input.clear();
                show_public_file_detail(client);
            }
        } else if (input_character == 27) {
            client.entering_file_point_validation = false;
            client.validation_file_points_input.clear();
            show_public_file_detail(client);
        } else if (input_character == '\b' || input_character == 127) {
            if (!client.validation_file_points_input.empty()) {
                client.validation_file_points_input.pop_back();
                (void)write_channel(client, "\b \b");
            }
        } else {
            const unsigned char byte = static_cast<unsigned char>(input_character);
            if (byte >= '0' && byte <= '9' && client.validation_file_points_input.size() < 3) {
                client.validation_file_points_input.push_back(input_character);
                (void)write_channel(client, std::string_view(&input_character, 1));
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.entering_file_owner_point_adjustment) {
        if (input_character == '\r' || input_character == '\n') {
            client.ignore_line_feed = input_character == '\r';
            std::int64_t adjustment = 0;
            if (!client.owner_point_adjustment_input.empty()) {
                const auto parsed = std::from_chars(client.owner_point_adjustment_input.data(),
                    client.owner_point_adjustment_input.data() + client.owner_point_adjustment_input.size(),
                    adjustment);
                if (parsed.ec != std::errc{} || parsed.ptr != client.owner_point_adjustment_input.data() +
                    client.owner_point_adjustment_input.size() || adjustment < -2147483647LL || adjustment > 999) {
                    (void)write_channel(client, "\a");
                    return;
                }
            }
            try {
                if (client.files == nullptr || !client.selected_public_file.has_value()) {
                    throw std::invalid_argument("point-entry validation lost its selected file");
                }
                const std::string filename = client.selected_public_file->name;
                client.files->validate_file_with_points(client.handle, client.file_area_id, filename,
                    client.validation_file_points, adjustment);
                client.selected_public_file->file_points = client.validation_file_points;
                client.selected_public_file->validated = true;
                record_sysop_action(client, "validated public file with point entry",
                    filename + " in area " + std::to_string(client.file_area_id) +
                        " at " + std::to_string(client.validation_file_points) + " points; owner adjustment " +
                        std::to_string(adjustment));
                client.entering_file_owner_point_adjustment = false;
                client.validation_file_points = 0;
                client.owner_point_adjustment_input.clear();
                (void)write_channel(client, "\r\nValidated file and updated the uploader's point balance.\r\n");
                show_public_file_detail(client);
            } catch (const std::exception& error) {
                client.owner_point_adjustment_input.clear();
                (void)write_channel(client, "\r\nCould not complete point-entry validation: " +
                    std::string(error.what()) + "\r\n");
                show_public_file_detail(client);
            }
        } else if (input_character == 27) {
            client.entering_file_owner_point_adjustment = false;
            client.validation_file_points = 0;
            client.owner_point_adjustment_input.clear();
            show_public_file_detail(client);
        } else if (input_character == '\b' || input_character == 127) {
            if (!client.owner_point_adjustment_input.empty()) {
                client.owner_point_adjustment_input.pop_back();
                (void)write_channel(client, "\b \b");
            }
        } else {
            const unsigned char byte = static_cast<unsigned char>(input_character);
            if ((byte >= '0' && byte <= '9') || (byte == '-' && client.owner_point_adjustment_input.empty())) {
                if (client.owner_point_adjustment_input.size() < 11) {
                    client.owner_point_adjustment_input.push_back(input_character);
                    (void)write_channel(client, std::string_view(&input_character, 1));
                } else {
                    (void)write_channel(client, "\a");
                }
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.entering_file_points) {
        if (input_character == '\r' || input_character == '\n') {
            client.ignore_line_feed = input_character == '\r';
            unsigned long long points = 0;
            const auto parsed = std::from_chars(client.file_points_input.data(),
                client.file_points_input.data() + client.file_points_input.size(), points);
            if (client.file_points_input.empty() || parsed.ec != std::errc{} ||
                parsed.ptr != client.file_points_input.data() + client.file_points_input.size() ||
                points > 32767ULL) {
                (void)write_channel(client, "\a");
                return;
            }
            try {
                if (client.files == nullptr || !client.selected_public_file.has_value()) {
                    throw std::invalid_argument("file-point editor lost its selected file");
                }
                const std::string filename = client.selected_public_file->name;
                client.files->set_file_points(client.handle, client.file_area_id, filename, points);
                client.selected_public_file->file_points = points;
                record_sysop_action(client, "changed public-file point cost",
                    filename + " in area " + std::to_string(client.file_area_id) + " to " +
                    std::to_string(points));
                client.entering_file_points = false;
                client.file_points_input.clear();
                show_public_file_detail(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not change file-point cost for " << client.handle << ": "
                          << error.what() << '\n';
                (void)write_channel(client, "\r\n" + std::string(error.what()) +
                    "\r\nFile points (Esc cancels): ");
                client.file_points_input.clear();
            }
        } else if (input_character == 27) {
            client.entering_file_points = false;
            client.file_points_input.clear();
            show_public_file_detail(client);
        } else if (input_character == '\b' || input_character == 127) {
            if (!client.file_points_input.empty()) {
                client.file_points_input.pop_back();
                (void)write_channel(client, "\b \b");
            }
        } else {
            const unsigned char byte = static_cast<unsigned char>(input_character);
            if (byte >= '0' && byte <= '9' && client.file_points_input.size() < 5) {
                client.file_points_input.push_back(input_character);
                (void)write_channel(client, std::string_view(&input_character, 1));
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.entering_file_owner) {
        if (input_character == '\r' || input_character == '\n') {
            client.ignore_line_feed = input_character == '\r';
            try {
                if (client.files == nullptr || !client.selected_public_file.has_value()) {
                    throw std::invalid_argument("file-owner editor lost its selected file");
                }
                const std::string filename = client.selected_public_file->name;
                client.files->set_file_owner(client.handle, client.file_area_id, filename,
                    client.file_owner_input);
                client.selected_public_file->owner_handle = client.file_owner_input;
                record_sysop_action(client, "changed public-file owner", filename + " in area " +
                    std::to_string(client.file_area_id) + " to " + client.file_owner_input);
                client.entering_file_owner = false;
                client.file_owner_input.clear();
                show_public_file_detail(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not change file owner for " << client.handle << ": "
                          << error.what() << '\n';
                (void)write_channel(client, "\r\n" + std::string(error.what()) +
                    "\r\nNew owner handle (Esc cancels): ");
                client.file_owner_input.clear();
            }
        } else if (input_character == 27) {
            client.entering_file_owner = false;
            client.file_owner_input.clear();
            show_public_file_detail(client);
        } else if (input_character == '\b' || input_character == 127) {
            if (!client.file_owner_input.empty()) {
                client.file_owner_input.pop_back();
                (void)write_channel(client, "\b \b");
            }
        } else {
            const unsigned char byte = static_cast<unsigned char>(input_character);
            if (byte >= 32 && byte != 127 && byte != 27 && client.file_owner_input.size() < 36) {
                client.file_owner_input.push_back(input_character);
                (void)write_channel(client, std::string_view(&input_character, 1));
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.entering_file_date) {
        if (input_character == '\r' || input_character == '\n') {
            client.ignore_line_feed = input_character == '\r';
            try {
                if (client.files == nullptr || !client.selected_public_file.has_value()) {
                    throw std::invalid_argument("file-date editor lost its selected file");
                }
                const std::string filename = client.selected_public_file->name;
                client.files->set_file_date(client.handle, client.file_area_id,
                    filename, client.file_date_input);
                client.selected_public_file->modified_at = client.file_date_input.substr(6, 4) + "-" +
                    client.file_date_input.substr(0, 2) + "-" + client.file_date_input.substr(3, 2) + " 00:00";
                record_sysop_action(client, "changed public-file date",
                    filename + " in area " + std::to_string(client.file_area_id) + " to " +
                    client.file_date_input);
                client.entering_file_date = false;
                client.file_date_input.clear();
                show_public_file_detail(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not change file date for " << client.handle << ": "
                          << error.what() << '\n';
                (void)write_channel(client, "\r\n" + std::string(error.what()) +
                    "\r\nUpload date MM-DD-YYYY (Esc cancels): ");
                client.file_date_input.clear();
            }
        } else if (input_character == 27) {
            client.entering_file_date = false;
            client.file_date_input.clear();
            show_public_file_detail(client);
        } else if (input_character == '\b' || input_character == 127) {
            if (!client.file_date_input.empty()) {
                client.file_date_input.pop_back();
                (void)write_channel(client, "\b \b");
            }
        } else {
            const unsigned char byte = static_cast<unsigned char>(input_character);
            if (((byte >= '0' && byte <= '9') || byte == '-') && client.file_date_input.size() < 10) {
                client.file_date_input.push_back(input_character);
                (void)write_channel(client, std::string_view(&input_character, 1));
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    char character = input_character;
    bool selected_welcome_command = false;
    if (client.welcome_menu_active && (input_character == '\r' || input_character == '\n') &&
        (client.profile.hotkeys || client.menu_command_input.empty())) {
        const std::string_view menu_keys = welcome_menu_keys(client.is_sysop);
        if (!menu_keys.empty()) {
            client.welcome_selection_index %= menu_keys.size();
            character = menu_keys[client.welcome_selection_index];
            selected_welcome_command = true;
            client.ignore_line_feed = input_character == '\r';
        }
    }
    if (!selected_welcome_command && !client.profile.hotkeys && client_accepts_menu_commands(client)) {
        if (input_character == '\r' || input_character == '\n') {
            client.ignore_line_feed = input_character == '\r';
            if (client.menu_command_input.empty()) {
                return;
            }
            character = client.menu_command_input.front();
            client.menu_command_input.clear();
            (void)write_channel(client, "\r\n");
        } else if (input_character == 27) {
            client.menu_command_input.clear();
            return;
        } else if (input_character == '\b' || input_character == 127) {
            if (!client.menu_command_input.empty()) {
                client.menu_command_input.clear();
                (void)write_channel(client, "\b \b");
            }
            return;
        } else {
            const unsigned char byte = static_cast<unsigned char>(input_character);
            if (byte < 32 || byte == 127) {
                return;
            }
            if (!client.menu_command_input.empty()) {
                (void)write_channel(client, "\a");
                return;
            }
            client.menu_command_input.push_back(input_character);
            (void)write_channel(client, std::string_view(&input_character, 1));
            return;
        }
    }

    if (client.registration_pending) {
        if (client.collecting_application_profile) {
            handle_new_user_questionnaire_input(client, character);
        } else if (std::toupper(static_cast<unsigned char>(character)) == 'Q') {
            client.close_requested = true;
        }
        return;
    }

    if (client.viewing_time_bank) {
        if (client.time_bank_action != ClientContext::TimeBankAction::None) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                finish_time_bank_transfer(client);
            } else if (character == 27) {
                client.time_bank_action = ClientContext::TimeBankAction::None;
                client.time_bank_input.clear();
                redraw_time_bank(client);
            } else if (character == '\b' || character == 127) {
                if (!client.time_bank_input.empty()) {
                    client.time_bank_input.pop_back();
                    redraw_time_bank(client);
                }
            } else if (character >= '0' && character <= '9' && client.time_bank_input.size() < 5) {
                client.time_bank_input.push_back(character);
                redraw_time_bank(client);
            }
        } else {
            const char bank_command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
            if (bank_command == 'D') {
                start_time_bank_transfer(client, ClientContext::TimeBankAction::Deposit);
            } else if (bank_command == 'W') {
                start_time_bank_transfer(client, ClientContext::TimeBankAction::Withdraw);
            } else if (bank_command == 'Q') {
                show_welcome(client);
            }
        }
        return;
    }

    if (client.viewing_short_messages) {
        const char command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        const std::size_t page_count = std::max<std::size_t>(1,
            (client.short_messages.size() + 9) / 10);
        if (command == 'N' && client.short_message_page + 1 < page_count) {
            ++client.short_message_page;
            if (!write_channel(client, short_messages_screen(client.short_messages,
                    client.short_message_page, client.columns, client.rows,
                    render_screen_art(client, client.mailbox_art)))) {
                client.close_requested = true;
            }
        } else if (command == 'P' && client.short_message_page > 0) {
            --client.short_message_page;
            if (!write_channel(client, short_messages_screen(client.short_messages,
                    client.short_message_page, client.columns, client.rows,
                    render_screen_art(client, client.mailbox_art)))) {
                client.close_requested = true;
            }
        } else {
            show_welcome(client);
        }
        return;
    }

    if (client.viewing_bbs_directory) {
        if (client.editing_bbs_listing) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                std::string command = client.bbs_listing_input;
                std::transform(command.begin(), command.end(), command.begin(), [](unsigned char value) {
                    return static_cast<char>(std::toupper(value));
                });
                if (command == "/CANCEL") {
                    client.editing_bbs_listing = false;
                    client.editing_bbs_listing_id.reset();
                    client.bbs_listing_input.clear();
                    if (client.selected_bbs_listing_id.has_value()) {
                        show_bbs_detail(client);
                    } else {
                        show_bbs_directory(client);
                    }
                    return;
                }
                const BbsDirectoryField& field = kBbsDirectoryFields[client.bbs_edit_field];
                if (command == "/CLEAR") {
                    (client.bbs_listing_draft.*(field.value)).clear();
                } else if (!client.bbs_listing_input.empty()) {
                    client.bbs_listing_draft.*(field.value) = client.bbs_listing_input;
                }
                client.bbs_listing_input.clear();
                ++client.bbs_edit_field;
                if (client.bbs_edit_field >= kBbsDirectoryFields.size()) {
                    save_bbs_listing(client);
                } else {
                    redraw_bbs_listing_editor(client);
                }
            } else if (character == 27) {
                client.editing_bbs_listing = false;
                client.editing_bbs_listing_id.reset();
                client.bbs_listing_input.clear();
                if (client.selected_bbs_listing_id.has_value()) {
                    show_bbs_detail(client);
                } else {
                    show_bbs_directory(client);
                }
            } else if (character == '\b' || character == 127) {
                if (!client.bbs_listing_input.empty()) {
                    client.bbs_listing_input.pop_back();
                    (void)write_channel(client, "\b \b");
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= 32 && byte != 127 && client.bbs_edit_field < kBbsDirectoryFields.size() &&
                    client.bbs_listing_input.size() < kBbsDirectoryFields[client.bbs_edit_field].maximum) {
                    client.bbs_listing_input.push_back(character);
                    (void)write_channel(client, std::string_view(&character, 1));
                }
            }
            return;
        }

        if (client.confirming_bbs_delete) {
            const char answer = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
            if (answer == 'Y' && client.selected_bbs_listing_id.has_value()) {
                const std::int64_t id = *client.selected_bbs_listing_id;
                try {
                    client.community->delete_bbs_listing(id, client.handle, client.is_sysop);
                    std::clog << "Caller " << client.handle << " deleted BBS directory entry " << id << ".\n";
                    client.selected_bbs_listing_id.reset();
                    client.confirming_bbs_delete = false;
                    client.viewing_bbs_detail = false;
                    show_bbs_directory(client);
                } catch (const std::exception& error) {
                    std::cerr << "Could not delete BBS directory entry: " << error.what() << '\n';
                    client.confirming_bbs_delete = false;
                    show_bbs_detail(client);
                }
            } else if (answer == 'N' || answer == 'Q' || answer == 27) {
                client.confirming_bbs_delete = false;
                show_bbs_detail(client);
            }
            return;
        }

        const char directory_command = static_cast<char>(
            std::toupper(static_cast<unsigned char>(character)));
        if (client.viewing_bbs_detail) {
            BbsListing* selected = selected_bbs_listing(client);
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                client.bbs_detail_page = client.bbs_detail_page == 0 ? 1 : 0;
                show_bbs_detail(client);
            } else if (directory_command == 'Q') {
                show_welcome(client);
            } else if (directory_command == 'B') {
                show_bbs_directory(client);
            } else if (directory_command == 'N' && client.bbs_detail_page == 0) {
                ++client.bbs_detail_page;
                show_bbs_detail(client);
            } else if (directory_command == 'P' && client.bbs_detail_page > 0) {
                --client.bbs_detail_page;
                show_bbs_detail(client);
            } else if (directory_command == 'E' && selected != nullptr &&
                can_manage_bbs_listing(client, *selected)) {
                start_bbs_listing_edit(client, false);
            } else if (directory_command == 'D' && selected != nullptr &&
                can_manage_bbs_listing(client, *selected)) {
                client.confirming_bbs_delete = true;
                show_bbs_detail(client);
            }
            return;
        }

        if (directory_command == 'Q') {
            show_welcome(client);
        } else if (directory_command == 'A') {
            start_bbs_listing_edit(client, true);
        } else if (directory_command == 'N' &&
            client.bbs_listing_page.page + 1 < client.bbs_listing_page.page_count) {
            ++client.bbs_listing_page_index;
            client.selected_bbs_listing_id.reset();
            client.bbs_listing_selection_index = 0;
            show_bbs_directory(client);
        } else if (directory_command == 'P' && client.bbs_listing_page_index > 0) {
            --client.bbs_listing_page_index;
            client.selected_bbs_listing_id.reset();
            client.bbs_listing_selection_index = 0;
            show_bbs_directory(client);
        } else if (character >= '1' && character <= '8') {
            const std::size_t row = static_cast<std::size_t>(character - '1');
            if (row < client.bbs_listing_page.entries.size()) {
                client.bbs_listing_selection_index = row;
                client.selected_bbs_listing_id = client.bbs_listing_page.entries[row].id;
                client.bbs_detail_page = 0;
                client.viewing_bbs_detail = true;
                show_bbs_detail(client);
            } else {
                (void)write_channel(client, "\a");
            }
        } else if (directory_command == 'E' && selected_bbs_listing(client) != nullptr) {
            start_bbs_listing_edit(client, false);
        } else if (directory_command == 'D' && selected_bbs_listing(client) != nullptr) {
            BbsListing* selected = selected_bbs_listing(client);
            if (can_manage_bbs_listing(client, *selected)) {
                client.viewing_bbs_detail = true;
                client.confirming_bbs_delete = true;
                show_bbs_detail(client);
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.viewing_auto_message) {
        const char auto_command = static_cast<char>(
            std::toupper(static_cast<unsigned char>(character)));
        if (auto_command == 'Q') {
            show_welcome(client);
        } else if (auto_command == 'W') {
            start_auto_message_write(client);
        } else if (auto_command == 'R' && client.current_auto_message.has_value() &&
            (!client.current_auto_message->anonymous ||
                (client.current_auto_message->anonymous_type == 2 ? client.is_sysop :
                    (client.messages != nullptr &&
                        client.messages->can_read_public_anonymously(client.handle))))) {
            start_auto_message_reply(client);
        } else if (auto_command == 'N' && client.auto_message_page + 1 < client.auto_message_page_count) {
            ++client.auto_message_page;
            show_auto_message(client);
        } else if (auto_command == 'P' && client.auto_message_page > 0) {
            --client.auto_message_page;
            show_auto_message(client);
        }
        return;
    }

    if (client.viewing_callers) {
        const char caller_command = static_cast<char>(
            std::toupper(static_cast<unsigned char>(character)));
        if (caller_command == 'Q') {
            show_welcome(client);
        } else if (caller_command == 'N' &&
            client.caller_sessions.page + 1 < client.caller_sessions.page_count) {
            ++client.caller_page;
            show_callers(client);
        } else if (caller_command == 'P' && client.caller_page > 0) {
            --client.caller_page;
            show_callers(client);
        }
        return;
    }

    if (client.viewing_statistics) {
        const char statistics_command = static_cast<char>(
            std::toupper(static_cast<unsigned char>(character)));
        if (statistics_command == 'Q') {
            show_welcome(client);
        } else if (statistics_command == 'N' && client.statistics_page < 3) {
            ++client.statistics_page;
            show_statistics(client);
        } else if (statistics_command == 'P' && client.statistics_page > 0) {
            --client.statistics_page;
            show_statistics(client);
        }
        return;
    }

    if (client.viewing_quote) {
        const char quote_command = static_cast<char>(
            std::toupper(static_cast<unsigned char>(character)));
        if (quote_command == 'Q') {
            show_welcome(client);
        } else if (quote_command == 'A') {
            if (client.messages != nullptr && client.messages->can_submit_quote(client.handle)) {
                start_quote_write(client);
            } else {
                (void)write_channel(client, "\r\nYour account does not pass the quote-submission ACS.\r\n");
                show_quote(client);
            }
        } else if (quote_command == 'R') {
            show_quote(client, true);
        } else if (quote_command == 'N' &&
            client.quote_content_page + 1 < client.quote_content_page_count) {
            ++client.quote_content_page;
            show_quote(client);
        } else if (quote_command == 'P' && client.quote_content_page > 0) {
            --client.quote_content_page;
            show_quote(client);
        } else if ((character == '[' || character == '<') && !client.quote_options.empty()) {
            client.quote_index = (client.quote_index + client.quote_options.size() - 1) %
                client.quote_options.size();
            client.quote_content_page = 0;
            show_quote(client);
        } else if ((character == ']' || character == '>') && !client.quote_options.empty()) {
            client.quote_index = (client.quote_index + 1) % client.quote_options.size();
            client.quote_content_page = 0;
            show_quote(client);
        }
        return;
    }

    if (client.viewing_quote_queue) {
        const char quote_command = static_cast<char>(
            std::toupper(static_cast<unsigned char>(character)));
        const std::size_t page_count = client.quote_submissions.page_count;
        if (quote_command == 'Q') {
            show_welcome(client);
        } else if (quote_command == 'N' && client.quote_submission_page + 1 < page_count) {
            ++client.quote_submission_page;
            client.quote_submission_selection_index = 0;
            client.selected_quote_submission_id.reset();
            show_quote_queue(client);
        } else if (quote_command == 'P' && client.quote_submission_page > 0) {
            --client.quote_submission_page;
            client.quote_submission_selection_index = 9;
            client.selected_quote_submission_id.reset();
            show_quote_queue(client);
        } else if ((character >= '1' && character <= '9') || character == '0') {
            const std::size_t row = character == '0'
                ? 9
                : static_cast<std::size_t>(character - '1');
            if (row < client.quote_submissions.entries.size()) {
                client.quote_submission_selection_index = row;
                client.selected_quote_submission_id = client.quote_submissions.entries[row].id;
                show_quote_queue(client);
            } else {
                (void)write_channel(client, "\a");
            }
        } else if ((quote_command == 'A' || quote_command == 'D') &&
            client.selected_quote_submission_id.has_value()) {
            try {
                if (quote_command == 'A') {
                    client.community->approve_quote_submission(*client.selected_quote_submission_id);
                    record_sysop_action(client, "approved quote submission",
                        "submission " + std::to_string(*client.selected_quote_submission_id));
                    std::clog << "SysOp " << client.handle << " approved a caller quote.\n";
                } else {
                    client.community->delete_quote_submission(*client.selected_quote_submission_id);
                    record_sysop_action(client, "rejected quote submission",
                        "submission " + std::to_string(*client.selected_quote_submission_id));
                    std::clog << "SysOp " << client.handle << " rejected a caller quote.\n";
                }
                client.selected_quote_submission_id.reset();
                show_quote_queue(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not process quote submission: " << error.what() << '\n';
                (void)write_channel(client, "\r\nCould not process that quote.\r\n");
                show_quote_queue(client);
            }
        }
        return;
    }

    if (client.viewing_polls) {
        if (client.adding_poll_choice) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                const std::string choice = std::move(client.poll_input);
                client.poll_input.clear();
                client.adding_poll_choice = false;
                if (!choice.empty() && client.selected_poll_id.has_value()) {
                    try {
                        client.community->add_poll_choice(
                            *client.selected_poll_id, client.handle, choice);
                        std::clog << "User " << client.handle << " added a choice to poll "
                                  << *client.selected_poll_id << ".\n";
                    } catch (const std::exception& error) {
                        std::cerr << "Could not add poll choice: " << error.what() << '\n';
                        show_polls(client);
                        (void)write_channel(client, "\r\nCould not add that choice.\r\n");
                        return;
                    }
                }
                show_polls(client);
            } else if (character == 27) {
                client.poll_input.clear();
                client.adding_poll_choice = false;
                show_polls(client);
            } else if (character == '\b' || character == 127) {
                if (!client.poll_input.empty()) {
                    client.poll_input.pop_back();
                    (void)write_channel(client, "\b \b");
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= 32 && byte != 127 && client.poll_input.size() < 65) {
                    client.poll_input.push_back(character);
                    (void)write_channel(client, std::string_view(&character, 1));
                }
            }
            return;
        }
        if (client.creating_poll) {
            if (client.poll_question_entered && client.poll_subtitle_entered &&
                (!client.poll_choice_policy_entered || !client.poll_vote_policy_entered)) {
                const char answer = static_cast<char>(
                    std::toupper(static_cast<unsigned char>(character)));
                if (answer == 'Y' || answer == 'N') {
                    if (!client.poll_choice_policy_entered) {
                        client.allow_poll_new_choices = answer == 'Y';
                        client.poll_choice_policy_entered = true;
                    } else {
                        client.allow_poll_vote_changes = answer == 'Y';
                        client.poll_vote_policy_entered = true;
                    }
                    show_polls(client);
                } else {
                    (void)write_channel(client, "\a");
                }
                return;
            }
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                std::string line = std::move(client.poll_input);
                client.poll_input.clear();
                if (!client.poll_question_entered) {
                    if (line.empty()) {
                        client.creating_poll = false;
                        show_polls(client);
                        return;
                    }
                    client.poll_question = std::move(line);
                    client.poll_question_entered = true;
                } else if (!client.poll_subtitle_entered) {
                    client.poll_subtitle = std::move(line);
                    client.poll_subtitle_entered = true;
                } else if (line.empty()) {
                    if (client.poll_options.size() < 2) {
                        show_polls(client);
                        (void)write_channel(client, "\r\nA poll needs at least two choices.\r\n");
                        return;
                    }
                    try {
                        client.community->create_poll(client.handle, client.poll_question,
                            client.poll_subtitle, client.allow_poll_new_choices,
                            client.allow_poll_vote_changes, client.poll_options);
                        record_sysop_action(client, "created poll", client.poll_question);
                        std::clog << "SysOp " << client.handle << " created poll: "
                                  << client.poll_question << "\n";
                        client.creating_poll = false;
                        client.poll_question_entered = false;
                        client.poll_subtitle_entered = false;
                        client.poll_choice_policy_entered = false;
                        client.allow_poll_new_choices = false;
                        client.poll_vote_policy_entered = false;
                        client.allow_poll_vote_changes = false;
                        client.poll_question.clear();
                        client.poll_subtitle.clear();
                        client.poll_options.clear();
                        client.poll_page = 0;
                        show_polls(client);
                    } catch (const std::exception& error) {
                        std::cerr << "Could not create poll: " << error.what() << '\n';
                        show_polls(client);
                        (void)write_channel(client, "\r\nCould not create that poll: " +
                            std::string(error.what()) + "\r\n");
                    }
                    return;
                } else if (client.poll_options.size() < 25) {
                    client.poll_options.push_back(std::move(line));
                    if (client.poll_options.size() == 25) {
                        try {
                            client.community->create_poll(client.handle, client.poll_question,
                                client.poll_subtitle, client.allow_poll_new_choices,
                                client.allow_poll_vote_changes, client.poll_options);
                            record_sysop_action(client, "created poll", client.poll_question);
                            std::clog << "SysOp " << client.handle << " created poll: "
                                      << client.poll_question << "\n";
                            client.creating_poll = false;
                            client.poll_question_entered = false;
                            client.poll_subtitle_entered = false;
                            client.poll_choice_policy_entered = false;
                            client.allow_poll_new_choices = false;
                            client.poll_vote_policy_entered = false;
                            client.allow_poll_vote_changes = false;
                            client.poll_question.clear();
                            client.poll_subtitle.clear();
                            client.poll_options.clear();
                            client.poll_page = 0;
                        } catch (const std::exception& error) {
                            std::cerr << "Could not create poll: " << error.what() << '\n';
                            (void)write_channel(client, "\r\nCould not create that poll: " +
                                std::string(error.what()) + "\r\n");
                        }
                    }
                }
                show_polls(client);
            } else if (character == 27) {
                client.creating_poll = false;
                client.poll_question_entered = false;
                client.poll_subtitle_entered = false;
                client.poll_choice_policy_entered = false;
                client.allow_poll_new_choices = false;
                client.poll_vote_policy_entered = false;
                client.allow_poll_vote_changes = false;
                client.poll_question.clear();
                client.poll_subtitle.clear();
                client.poll_input.clear();
                client.poll_options.clear();
                show_polls(client);
            } else if (character == '\b' || character == 127) {
                if (!client.poll_input.empty()) {
                    client.poll_input.pop_back();
                    (void)write_channel(client, "\b \b");
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                const std::size_t limit = !client.poll_question_entered || !client.poll_subtitle_entered
                    ? 60
                    : 65;
                if (byte >= 32 && byte != 127 && client.poll_input.size() < limit) {
                    client.poll_input.push_back(character);
                    (void)write_channel(client, std::string_view(&character, 1));
                }
            }
            return;
        }
        const char poll_command = static_cast<char>(
            std::toupper(static_cast<unsigned char>(character)));
        if (client.reading_poll) {
            if (poll_command == 'Q') {
                client.reading_poll = false;
                client.selected_poll_id.reset();
                client.showing_poll_results = false;
                client.changing_poll_vote = false;
                client.poll_choice_page = 0;
                show_polls(client);
            } else if (poll_command == 'R') {
                client.showing_poll_results = !client.showing_poll_results;
                show_polls(client);
            } else if (poll_command == 'C' && client.active_poll.caller_vote.has_value() &&
                client.active_poll.allow_vote_changes) {
                client.changing_poll_vote = true;
                show_polls(client);
            } else if (poll_command == 'L' && client.is_sysop && client.showing_poll_results) {
                std::string roster = "\r\nVOTERS BY CHOICE\r\n";
                for (const PollOption& option : client.active_poll.options) {
                    roster += "\r\n" + option.text + ": ";
                    const std::vector<std::string> voters = client.community->poll_voters(
                        client.active_poll.id, option.id);
                    const std::size_t shown = std::min<std::size_t>(voters.size(), 40);
                    if (shown == 0) {
                        roster += "(none)";
                    }
                    for (std::size_t index = 0; index < shown; ++index) {
                        if (index != 0) {
                            roster += ", ";
                        }
                        roster += voters[index];
                    }
                    if (voters.size() > shown) {
                        roster += " ... +" + std::to_string(voters.size() - shown) + " more";
                    }
                }
                roster += "\r\n\r\nPress R to redraw the poll or Q for topics.\r\n";
                (void)write_channel(client, roster);
            } else if (poll_command == 'N' &&
                (client.poll_choice_page + 1) * 10 < client.active_poll.options.size()) {
                ++client.poll_choice_page;
                show_polls(client);
            } else if (poll_command == 'P' && client.poll_choice_page > 0) {
                --client.poll_choice_page;
                show_polls(client);
            } else if (poll_command == 'A' && client.active_poll.allow_new_choices &&
                client.active_poll.options.size() < 25) {
                client.adding_poll_choice = true;
                client.poll_input.clear();
                show_polls(client);
            } else if ((!client.active_poll.caller_vote.has_value() || client.changing_poll_vote) &&
                ((character >= '1' && character <= '9') || character == '0')) {
                const std::size_t row = character == '0'
                    ? 9
                    : static_cast<std::size_t>(character - '1');
                const std::size_t option_index = client.poll_choice_page * 10 + row;
                if (option_index < client.active_poll.options.size()) {
                    client.poll_choice_selection_index = option_index;
                    const PollOption& option = client.active_poll.options[option_index];
                    try {
                        client.community->vote(client.active_poll.id, option.id, client.handle);
                        client.showing_poll_results = true;
                        client.changing_poll_vote = false;
                        std::clog << "User " << client.handle << " voted in poll "
                                  << client.active_poll.id << ".\n";
                        show_polls(client);
                    } catch (const std::exception& error) {
                        std::cerr << "Could not record poll vote: " << error.what() << '\n';
                        (void)write_channel(client, "\r\nCould not record that vote.\r\n");
                        show_polls(client);
                    }
                } else {
                    (void)write_channel(client, "\a");
                }
            }
        } else if (poll_command == 'Q') {
            show_welcome(client);
        } else if (poll_command == 'N' && (client.poll_page + 1) * 10 < client.poll_list.size()) {
            ++client.poll_page;
            show_polls(client);
        } else if (poll_command == 'P' && client.poll_page > 0) {
            --client.poll_page;
            show_polls(client);
        } else if (poll_command == 'A' && client.is_sysop) {
            client.creating_poll = true;
            client.poll_question_entered = false;
            client.poll_subtitle_entered = false;
            client.poll_choice_policy_entered = false;
            client.allow_poll_new_choices = false;
            client.poll_vote_policy_entered = false;
            client.allow_poll_vote_changes = false;
            client.poll_question.clear();
            client.poll_subtitle.clear();
            client.poll_input.clear();
            client.poll_options.clear();
            show_polls(client);
        } else if ((character >= '1' && character <= '9') || character == '0') {
            const std::size_t row = character == '0'
                ? 9
                : static_cast<std::size_t>(character - '1');
            const std::size_t index = client.poll_page * 10 + row;
            if (index < client.poll_list.size()) {
                client.poll_selection_index = index;
                client.selected_poll_id = client.poll_list[index].id;
                client.reading_poll = true;
                client.poll_choice_page = 0;
                client.poll_choice_selection_index = 0;
                client.showing_poll_results = false;
                client.changing_poll_vote = false;
                show_polls(client);
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.viewing_bulletins) {
        const char bulletin_command = static_cast<char>(
            std::toupper(static_cast<unsigned char>(character)));
        if (client.reading_bulletin) {
            const std::size_t count = client.bulletin_catalog == nullptr
                ? 0
                : std::min<std::size_t>(client.bulletin_catalog->size(), 26);
            if (bulletin_command == 'Q') {
                client.reading_bulletin = false;
                show_bulletins(client);
            } else if (bulletin_command == 'N' && count > 0) {
                client.bulletin_index = (client.bulletin_index + 1) % count;
                show_bulletins(client);
            } else if (bulletin_command == 'P' && count > 0) {
                client.bulletin_index = (client.bulletin_index + count - 1) % count;
                show_bulletins(client);
            }
        } else if (bulletin_command == 'Q') {
            show_welcome(client);
        } else if (bulletin_command == '?') {
            show_bulletins(client);
        } else if (bulletin_command >= 'A' && bulletin_command <= 'Z') {
            const std::size_t index = static_cast<std::size_t>(bulletin_command - 'A');
            if (client.bulletin_catalog != nullptr && index < client.bulletin_catalog->size() && index < 26) {
                client.bulletin_index = index;
                client.reading_bulletin = true;
                show_bulletins(client);
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.viewing_one_liners) {
        if (client.adding_one_liner || client.editing_one_liner) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                const std::string text = std::move(client.one_liner_input);
                client.one_liner_input.clear();
                const bool editing = client.editing_one_liner;
                const std::optional<std::int64_t> edit_id = client.editing_one_liner_id;
                client.adding_one_liner = false;
                client.editing_one_liner = false;
                client.editing_one_liner_id.reset();
                if (text.empty()) {
                    show_one_liners(client);
                } else if (editing && edit_id.has_value() && client.is_sysop) {
                    const auto original = std::find_if(client.one_liner_page.entries.begin(),
                        client.one_liner_page.entries.end(), [&](const OneLiner& entry) {
                            return entry.id == *edit_id;
                        });
                    try {
                        const std::string old_text = original == client.one_liner_page.entries.end()
                            ? std::string("(entry unavailable)")
                            : original->text;
                        client.community->update_one_liner(*edit_id, text);
                        record_sysop_action(client, "edited one-liner", "entry " + std::to_string(*edit_id));
                        std::clog << "SysOp " << client.handle << " edited one-liner " << *edit_id
                                  << " from \"" << old_text << "\" to \"" << text << "\".\n";
                        show_one_liners(client);
                    } catch (const std::exception& error) {
                        std::cerr << "Could not edit one-liner: " << error.what() << '\n';
                        show_one_liners(client);
                        (void)write_channel(client, "\r\nCould not edit that one-liner.\r\n");
                    }
                } else {
                    client.pending_one_liner_text = text;
                    client.one_liner_anonymous = false;
                    if (client.messages != nullptr &&
                        client.messages->can_post_public_anonymously(client.handle)) {
                        client.prompting_one_liner_anonymous = true;
                    } else {
                        client.confirming_one_liner_post = true;
                    }
                    show_one_liners(client);
                }
            } else if (character == 27) {
                client.one_liner_input.clear();
                client.adding_one_liner = false;
                client.editing_one_liner = false;
                client.editing_one_liner_id.reset();
                show_one_liners(client);
            } else if (character == '\b' || character == 127) {
                if (!client.one_liner_input.empty()) {
                    client.one_liner_input.pop_back();
                    (void)write_channel(client, "\b \b");
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= 32 && byte != 127 && client.one_liner_input.size() < 200) {
                    client.one_liner_input.push_back(character);
                    (void)write_channel(client, std::string_view(&character, 1));
                }
            }
        } else if (client.confirming_one_liner_delete) {
            const char answer = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
            if (answer == 'Y' && client.selected_one_liner_id.has_value() && client.is_sysop) {
                const std::int64_t id = *client.selected_one_liner_id;
                const auto selected = std::find_if(client.one_liner_page.entries.begin(),
                    client.one_liner_page.entries.end(), [&](const OneLiner& entry) {
                        return entry.id == id;
                    });
                const std::string summary = selected == client.one_liner_page.entries.end()
                    ? std::string("(entry unavailable)")
                    : selected->text;
                try {
                    client.community->delete_one_liner(id);
                    record_sysop_action(client, "deleted one-liner", "entry " + std::to_string(id));
                    std::clog << "SysOp " << client.handle << " deleted one-liner " << id
                              << " \"" << summary << "\".\n";
                    client.selected_one_liner_id.reset();
                    client.confirming_one_liner_delete = false;
                    show_one_liners(client);
                } catch (const std::exception& error) {
                    std::cerr << "Could not delete one-liner: " << error.what() << '\n';
                    client.confirming_one_liner_delete = false;
                    show_one_liners(client);
                    (void)write_channel(client, "\r\nCould not delete that one-liner.\r\n");
                }
            } else if (answer == 'N' || answer == 27) {
                client.confirming_one_liner_delete = false;
                show_one_liners(client);
            }
        } else if (client.prompting_one_liner_anonymous) {
            const char answer = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
            if (answer == 'Y') {
                client.one_liner_anonymous = true;
                client.prompting_one_liner_anonymous = false;
                client.confirming_one_liner_post = true;
                show_one_liners(client);
            } else if (answer == 'N') {
                client.one_liner_anonymous = false;
                client.prompting_one_liner_anonymous = false;
                client.confirming_one_liner_post = true;
                show_one_liners(client);
            } else if (answer == 27) {
                client.one_liner_anonymous = false;
                client.prompting_one_liner_anonymous = false;
                client.pending_one_liner_text.clear();
                show_one_liners(client);
            } else {
                (void)write_channel(client, "\r\nAnswer Y or N.\r\nPost anonymously? Y/N ");
            }
        } else if (client.confirming_one_liner_post) {
            const char answer = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
            if (answer == 'Y') {
                try {
                    if (client.messages == nullptr ||
                        !client.messages->can_submit_one_liner(client.handle)) {
                        throw std::invalid_argument("account does not pass AddOneLiner ACS");
                    }
                    const bool anonymous = client.one_liner_anonymous && client.messages != nullptr &&
                        client.messages->can_post_public_anonymously(client.handle);
                    client.community->add_one_liner(
                        client.handle, client.pending_one_liner_text, anonymous);
                    std::clog << "User " << client.handle << " posted a"
                              << (anonymous ? "n anonymous" : "")
                              << " one-liner.\n";
                    client.pending_one_liner_text.clear();
                    client.one_liner_anonymous = false;
                    client.confirming_one_liner_post = false;
                    client.one_liner_page.page = 0;
                    show_one_liners(client);
                } catch (const std::exception& error) {
                    std::cerr << "Could not save one-liner: " << error.what() << '\n';
                    client.pending_one_liner_text.clear();
                    client.one_liner_anonymous = false;
                    client.confirming_one_liner_post = false;
                    show_one_liners(client);
                    (void)write_channel(client, "\r\nCould not save that one-liner.\r\n");
                }
            } else if (answer == 'N' || answer == 27) {
                client.pending_one_liner_text.clear();
                client.one_liner_anonymous = false;
                client.confirming_one_liner_post = false;
                show_one_liners(client);
            }
        } else {
            const char command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
            if (command == 'Q') {
                show_welcome(client);
            } else if (command == 'A') {
                if (client.messages != nullptr && client.messages->can_submit_one_liner(client.handle)) {
                    client.adding_one_liner = true;
                    client.one_liner_input.clear();
                    client.one_liner_anonymous = false;
                    show_one_liners(client);
                } else {
                    (void)write_channel(client, "\r\nYour account does not pass the one-liner ACS.\r\n");
                    show_one_liners(client);
                }
            } else if (command == 'R') {
                try {
                    const std::optional<OneLiner> entry = client.community->random_one_liner();
                    if (entry.has_value()) {
                        std::string author = entry->anonymous ? "Anonymous" : entry->author;
                        if (entry->anonymous && client.messages != nullptr &&
                            client.messages->can_read_public_anonymously(client.handle)) {
                            author += " (" + entry->author + ")";
                        }
                        (void)write_channel(client, "\r\nRandom OneLiner: " + author + ": " +
                            entry->text + "\r\n");
                    } else {
                        (void)write_channel(client, "\r\nNo one-liners have been posted yet.\r\n");
                    }
                } catch (const std::exception& error) {
                    std::cerr << "Could not choose a random one-liner: " << error.what() << '\n';
                    (void)write_channel(client, "\r\nCould not read a random one-liner.\r\n");
                }
            } else if (client.is_sysop && ((character >= '1' && character <= '9') || character == '0')) {
                const std::size_t row = character == '0'
                    ? 9
                    : static_cast<std::size_t>(character - '1');
                if (row < client.one_liner_page.entries.size()) {
                    client.one_liner_selection_index = row;
                    client.selected_one_liner_id = client.one_liner_page.entries[row].id;
                    show_one_liners(client);
                } else {
                    (void)write_channel(client, "\a");
                }
            } else if (client.is_sysop && command == 'E' && client.selected_one_liner_id.has_value()) {
                const auto selected = std::find_if(client.one_liner_page.entries.begin(),
                    client.one_liner_page.entries.end(), [&](const OneLiner& entry) {
                        return entry.id == *client.selected_one_liner_id;
                    });
                if (selected != client.one_liner_page.entries.end()) {
                    client.editing_one_liner = true;
                    client.editing_one_liner_id = selected->id;
                    client.one_liner_input = selected->text;
                    show_one_liners(client);
                }
            } else if (client.is_sysop && command == 'D' && client.selected_one_liner_id.has_value()) {
                client.confirming_one_liner_delete = true;
                show_one_liners(client);
            } else if (command == 'N' && client.one_liner_page.page + 1 < client.one_liner_page.page_count) {
                ++client.one_liner_page.page;
                client.selected_one_liner_id.reset();
                client.one_liner_selection_index = 0;
                show_one_liners(client);
            } else if (command == 'P' && client.one_liner_page.page > 0) {
                --client.one_liner_page.page;
                client.selected_one_liner_id.reset();
                client.one_liner_selection_index = 0;
                show_one_liners(client);
            }
        }
        return;
    }

    if (client.viewing_uploads) {
        const char upload_command = static_cast<char>(
            std::toupper(static_cast<unsigned char>(character)));
        if (client.selecting_upload_area) {
            const std::size_t page_count = std::max<std::size_t>(
                1, (client.upload_publish_areas.size() + 9) / 10);
            if (upload_command == 'Q') {
                show_upload_detail(client);
            } else if (upload_command == 'N' && client.upload_publish_area_page + 1 < page_count) {
                ++client.upload_publish_area_page;
                client.upload_publish_area_selection_index = client.upload_publish_area_page * 10;
                show_upload_publish_areas(client);
            } else if (upload_command == 'P' && client.upload_publish_area_page > 0) {
                --client.upload_publish_area_page;
                client.upload_publish_area_selection_index = client.upload_publish_area_page * 10;
                show_upload_publish_areas(client);
            } else if ((character >= '1' && character <= '9') || character == '0') {
                const std::size_t row = character == '0'
                    ? 9
                    : static_cast<std::size_t>(character - '1');
                const std::size_t index = client.upload_publish_area_page * 10 + row;
                if (index < client.upload_publish_areas.size()) {
                    client.upload_publish_area_selection_index = index;
                    publish_selected_upload(client, client.upload_publish_areas[index].id);
                } else {
                    (void)write_channel(client, "\a");
                }
            }
        } else if (client.viewing_upload_detail) {
            if (client.confirming_upload_delete) {
                if (upload_command == 'D') {
                    delete_selected_upload(client);
                } else if (upload_command == 'Q') {
                    show_upload_review(client);
                } else {
                    client.confirming_upload_delete = false;
                    show_upload_detail(client);
                }
            } else if (upload_command == 'Q') {
                show_upload_review(client);
            } else if (upload_command == 'P') {
                client.upload_publish_area_page = 0;
                show_upload_publish_areas(client);
            } else if (upload_command == 'D') {
                client.confirming_upload_delete = true;
                show_upload_detail(client);
            }
        } else {
            const std::size_t page_count = std::max<std::size_t>(
                1, (client.incoming_files.size() + 9) / 10);
            if (upload_command == 'Q') {
                show_welcome(client);
            } else if (upload_command == 'N' && client.incoming_files_page + 1 < page_count) {
                ++client.incoming_files_page;
                client.incoming_file_selection_index = client.incoming_files_page * 10;
                show_upload_review(client);
            } else if (upload_command == 'P' && client.incoming_files_page > 0) {
                --client.incoming_files_page;
                client.incoming_file_selection_index = client.incoming_files_page * 10;
                show_upload_review(client);
            } else if (upload_command == 'R') {
                show_upload_review(client);
            } else if ((character >= '1' && character <= '9') || character == '0') {
                const std::size_t row = character == '0'
                    ? 9
                    : static_cast<std::size_t>(character - '1');
                const std::size_t index = client.incoming_files_page * 10 + row;
                if (index < client.incoming_files.size()) {
                    client.incoming_file_selection_index = index;
                    client.selected_upload = client.incoming_files[index];
                    client.confirming_upload_delete = false;
                    show_upload_detail(client);
                } else {
                    (void)write_channel(client, "\a");
                }
            }
        }
        return;
    }

    if (client.viewing_download_queue) {
        const char command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        if (client.confirming_download_queue_clear) {
            client.confirming_download_queue_clear = false;
            if (command == 'Y' && client.files != nullptr) {
                try {
                    client.files->clear_download_queue(client.handle);
                    client.download_queue_page = 0;
                } catch (const std::exception& error) {
                    std::cerr << "Could not clear download queue for " << client.handle
                        << ": " << error.what() << '\n';
                    (void)write_channel(client, "\a");
                }
            }
            show_download_queue(client);
        } else if (command == 'Q') {
            return_from_file_browser(client);
        } else if (command == 'C') {
            client.confirming_download_queue_clear = true;
            show_download_queue(client);
        } else if (command == 'R') {
            show_download_queue(client);
        } else if (command == 'N' && client.download_queue_page + 1 <
                std::max<std::size_t>(1, (client.download_queue.size() + 9) / 10)) {
            ++client.download_queue_page;
            client.download_queue_selection_index = client.download_queue_page * 10;
            show_download_queue(client);
        } else if (command == 'P' && client.download_queue_page > 0) {
            --client.download_queue_page;
            client.download_queue_selection_index = client.download_queue_page * 10;
            show_download_queue(client);
        } else if ((character >= '1' && character <= '9') || character == '0') {
            const std::size_t row = character == '0'
                ? 9
                : static_cast<std::size_t>(character - '1');
            const std::size_t index = client.download_queue_page * 10 + row;
            if (index < client.download_queue.size() && client.files != nullptr) {
                client.download_queue_selection_index = index;
                try {
                    client.files->remove_queued_download(client.handle, client.download_queue[index].id);
                    show_download_queue(client);
                } catch (const std::exception& error) {
                    std::cerr << "Could not remove queued download for " << client.handle
                        << ": " << error.what() << '\n';
                    (void)write_channel(client, "\a");
                }
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.editing_file_description) {
        if (character == '\r' || character == '\n') {
            client.ignore_line_feed = character == '\r';
            try {
                if (!client.selected_public_file.has_value() || client.files == nullptr) {
                    throw std::invalid_argument("file description editor lost its selected file");
                }
                client.files->set_description(client.file_area_id,
                    client.selected_public_file->name, client.file_description_input);
                client.selected_public_file->description = client.file_description_input;
                client.editing_file_description = false;
                client.file_description_input.clear();
                show_public_file_detail(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not update file description for " << client.handle
                          << ": " << error.what() << '\n';
                (void)write_channel(client, "\a");
                redraw_file_description_editor(client);
            }
        } else if (character == 27) {
            client.editing_file_description = false;
            client.file_description_input.clear();
            show_public_file_detail(client);
        } else if (character == '\b' || character == 127) {
            if (!client.file_description_input.empty()) {
                client.file_description_input.pop_back();
                redraw_file_description_editor(client);
            }
        } else {
            const unsigned char byte = static_cast<unsigned char>(character);
            if (byte >= 32 && byte != 127 && byte != 27 && client.file_description_input.size() < 160) {
                client.file_description_input.push_back(character);
                redraw_file_description_editor(client);
            }
        }
        return;
    }

    if (client.editing_file_extended_description) {
        if (character == '\r' || character == '\n') {
            client.ignore_line_feed = character == '\r';
            if (client.file_extended_description_input.empty()) {
                try {
                    if (!client.selected_public_file.has_value() || client.files == nullptr) {
                        throw std::invalid_argument("extended-description editor lost its selected file");
                    }
                    std::string description;
                    for (std::size_t index = 0;
                         index < client.file_extended_description_draft.size(); ++index) {
                        if (index > 0) {
                            description.push_back('\n');
                        }
                        description += client.file_extended_description_draft[index];
                    }
                    client.files->set_extended_description(client.file_area_id,
                        client.selected_public_file->name, description);
                    client.selected_public_file->extended_description = std::move(description);
                    client.editing_file_extended_description = false;
                    client.file_extended_description_draft.clear();
                    client.file_extended_description_input.clear();
                    client.extended_file_description_page = 0;
                    show_public_file_detail(client);
                } catch (const std::exception& error) {
                    std::cerr << "Could not update extended file description for "
                              << client.handle << ": " << error.what() << '\n';
                    (void)write_channel(client, "\a");
                    redraw_file_description_editor(client);
                }
            } else if (client.file_extended_description_draft.size() >= 99) {
                (void)write_channel(client, "\a");
                redraw_file_description_editor(client);
            } else {
                client.file_extended_description_draft.push_back(
                    std::move(client.file_extended_description_input));
                client.file_extended_description_input.clear();
                redraw_file_description_editor(client);
            }
        } else if (character == 27) {
            client.editing_file_extended_description = false;
            client.file_extended_description_draft.clear();
            client.file_extended_description_input.clear();
            show_public_file_detail(client);
        } else if (character == '\b' || character == 127) {
            if (!client.file_extended_description_input.empty()) {
                client.file_extended_description_input.pop_back();
                redraw_file_description_editor(client);
            }
        } else {
            const unsigned char byte = static_cast<unsigned char>(character);
            if (byte >= 32 && byte != 127 && byte != 27) {
                if (client.file_extended_description_input.size() < 50) {
                    client.file_extended_description_input.push_back(character);
                    redraw_file_description_editor(client);
                } else {
                    (void)write_channel(client, "\a");
                }
            }
        }
        return;
    }

    if (client.viewing_extended_file_description) {
        const char command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        if (command == 'Q' || command == 'B') {
            show_public_file_detail(client);
        } else if (command == 'E' && client.is_sysop) {
            client.file_extended_description_draft.clear();
            client.file_extended_description_input.clear();
            client.editing_file_extended_description = true;
            redraw_file_description_editor(client);
        } else if (client.selected_public_file.has_value()) {
            const std::size_t line_count = static_cast<std::size_t>(
                std::count(client.selected_public_file->extended_description.begin(),
                    client.selected_public_file->extended_description.end(), '\n')) + 1;
            const std::size_t page_size = static_cast<std::size_t>(std::max(1, client.rows - 11));
            const std::size_t page_count = std::max<std::size_t>(1,
                (line_count + page_size - 1) / page_size);
            if (command == 'N' && client.extended_file_description_page + 1 < page_count) {
                ++client.extended_file_description_page;
                show_extended_file_description(client);
            } else if (command == 'P' && client.extended_file_description_page > 0) {
                --client.extended_file_description_page;
                show_extended_file_description(client);
            }
        }
        return;
    }

    if (client.viewing_file_detail) {
        const char command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        if (client.confirming_public_file_delete) {
            if (command == 'Y' && client.is_sysop && client.files != nullptr &&
                client.selected_public_file.has_value()) {
                try {
                    const std::string filename = client.selected_public_file->name;
                    client.files->delete_public_file(client.handle, client.file_area_id, filename);
                    record_sysop_action(client, "deleted public file",
                        filename + " in area " + std::to_string(client.file_area_id));
                    client.confirming_public_file_delete = false;
                    client.selected_public_file.reset();
                    return_from_file_browser(client);
                } catch (const std::exception& error) {
                    std::cerr << "Could not delete public file for " << client.handle
                        << ": " << error.what() << '\n';
                    (void)write_channel(client, "\a");
                    client.confirming_public_file_delete = false;
                    return_from_file_browser(client);
                }
            } else if (command == 'N' || command == 'Q') {
                client.confirming_public_file_delete = false;
                show_public_file_detail(client);
            }
        } else if (client.confirming_public_file_credit_withdrawal) {
            if (command == 'Y' && client.is_sysop && client.files != nullptr &&
                client.selected_public_file.has_value()) {
                try {
                    const std::string filename = client.selected_public_file->name;
                    client.files->withdraw_file_owner_credit(client.handle, client.file_area_id, filename);
                    record_sysop_action(client, "withdrew file-owner credit",
                        filename + " in area " + std::to_string(client.file_area_id));
                    client.confirming_public_file_credit_withdrawal = false;
                    (void)write_channel(client, "\r\nWithdrew the recorded uploader point credit.\r\n");
                    show_public_file_detail(client);
                } catch (const std::exception& error) {
                    client.confirming_public_file_credit_withdrawal = false;
                    (void)write_channel(client, "\r\nCould not withdraw uploader credit: " +
                        std::string(error.what()) + "\r\n");
                    show_public_file_detail(client);
                }
            } else if (command == 'N' || command == 'Q') {
                client.confirming_public_file_credit_withdrawal = false;
                show_public_file_detail(client);
            }
        } else if (command == 'D' && client.is_sysop && client.selected_public_file.has_value()) {
            client.confirming_public_file_delete = true;
            show_public_file_detail(client);
        } else if (command == 'W' && client.is_sysop && client.selected_public_file.has_value()) {
            client.confirming_public_file_credit_withdrawal = true;
            show_public_file_detail(client);
        } else if (command == 'P' && client.is_sysop && client.files != nullptr &&
            client.selected_public_file.has_value() && !client.selected_public_file->validated) {
            client.entering_file_point_validation = true;
            client.entering_file_owner_point_adjustment = false;
            client.validation_file_points = 0;
            client.validation_file_points_input.clear();
            client.owner_point_adjustment_input.clear();
            show_public_file_detail(client);
        } else if (command == 'M' && client.is_sysop && client.selected_public_file.has_value() &&
            client.files != nullptr) {
            client.entering_file_move_area = true;
            client.file_move_area_input.clear();
            show_public_file_detail(client);
        } else if (command == 'Y' && client.is_sysop && client.selected_public_file.has_value() &&
            client.files != nullptr) {
            try {
                const bool request_only = !client.selected_public_file->request_only;
                client.files->set_file_request_only(client.handle, client.file_area_id,
                    client.selected_public_file->name, request_only);
                client.selected_public_file->request_only = request_only;
                record_sysop_action(client, request_only ? "marked public file request-only"
                    : "made public file downloadable", client.selected_public_file->name +
                    " in area " + std::to_string(client.file_area_id));
                show_public_file_detail(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not change request status for " << client.handle << ": "
                          << error.what() << '\n';
                (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                show_public_file_detail(client);
            }
        } else if (command == 'R' && !client.is_sysop && client.selected_public_file.has_value() &&
            client.selected_public_file->request_only && client.accounts != nullptr &&
            client.messages != nullptr) {
            try {
                const std::vector<AccountSummary> accounts = client.accounts->list_accounts();
                const auto sysop = std::find_if(accounts.begin(), accounts.end(), [&client](const auto& account) {
                    return account.is_sysop && account.enabled && account.approved &&
                        ::strcasecmp(account.handle.c_str(), client.handle.c_str()) != 0;
                });
                if (sysop == accounts.end()) {
                    throw std::invalid_argument("no active SysOp account is available for file requests");
                }
                std::string subject = "File request: " + client.selected_public_file->name;
                if (subject.size() > 80) {
                    subject.resize(80);
                }
                std::string body;
                const auto append_field = [&body](std::string_view label, std::string_view value) {
                    std::size_t offset = 0;
                    bool first = true;
                    do {
                        const std::string_view prefix = first ? label : std::string_view("  ");
                        const std::size_t amount = std::min<std::size_t>(78 - prefix.size(),
                            value.size() - offset);
                        if (!body.empty()) {
                            body.push_back('\n');
                        }
                        body.append(prefix);
                        body.append(value.substr(offset, amount));
                        offset += amount;
                        first = false;
                    } while (offset < value.size());
                };
                append_field("Caller: ", client.handle);
                append_field("File: ", client.selected_public_file->name);
                const std::string area = client.file_area_name + " (#" +
                    std::to_string(client.file_area_id) + ")";
                append_field("Area: ", area);
                client.messages->send_private(client.handle, sysop->handle, subject, body);
                (void)write_channel(client, "\r\nFile request sent to " + sysop->handle + ".\r\n");
            } catch (const std::exception& error) {
                (void)write_channel(client, "\r\nCould not send file request: " +
                    std::string(error.what()) + "\r\n");
            }
        } else if (command == '1' && client.is_sysop && client.selected_public_file.has_value() &&
            client.files != nullptr) {
            client.entering_file_rename = true;
            client.file_rename_input.clear();
            show_public_file_detail(client);
        } else if (command == '6' && client.is_sysop && client.selected_public_file.has_value() &&
            client.files != nullptr) {
            client.entering_file_download_count = true;
            client.file_download_count_input.clear();
            show_public_file_detail(client);
        } else if (command == '7' && client.is_sysop && client.selected_public_file.has_value() &&
            client.files != nullptr) {
            client.entering_file_points = true;
            client.file_points_input.clear();
            show_public_file_detail(client);
        } else if (command == '4' && client.is_sysop && client.selected_public_file.has_value() &&
            client.files != nullptr) {
            client.entering_file_owner = true;
            client.file_owner_input.clear();
            show_public_file_detail(client);
        } else if (command == '5' && client.is_sysop && client.selected_public_file.has_value() &&
            client.files != nullptr) {
            client.entering_file_date = true;
            client.file_date_input.clear();
            show_public_file_detail(client);
        } else if (command == '2' && client.is_sysop && client.selected_public_file.has_value() &&
            client.files != nullptr) {
            try {
                const std::string filename = client.selected_public_file->name;
                client.selected_public_file->size = client.files->refresh_file_size(
                    client.handle, client.file_area_id, filename);
                record_sysop_action(client, "refreshed public-file size",
                    filename + " in area " + std::to_string(client.file_area_id));
                show_public_file_detail(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not refresh file size for " << client.handle << ": "
                          << error.what() << '\n';
                (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                show_public_file_detail(client);
            }
        } else if (command == 'Q') {
            return_from_file_browser(client);
        } else if (command == 'B') {
            show_download_queue(client);
        } else if (command == 'V' && client.selected_public_file.has_value() &&
            !client.selected_public_file->extended_description.empty()) {
            client.extended_file_description_page = 0;
            show_extended_file_description(client);
        } else if ((command == 'E' || command == 'X') && client.is_sysop &&
            client.selected_public_file.has_value()) {
            client.file_extended_description_draft.clear();
            client.file_extended_description_input.clear();
            client.editing_file_extended_description = true;
            redraw_file_description_editor(client);
        } else if (command == '3' && client.is_sysop && client.selected_public_file.has_value()) {
            client.file_description_input = client.selected_public_file->description;
            client.editing_file_description = true;
            redraw_file_description_editor(client);
        } else if (command == 'A' && client.is_sysop && client.files != nullptr &&
            client.selected_public_file.has_value()) {
            try {
                const bool validated = !client.selected_public_file->validated;
                client.files->set_file_validated(client.handle, client.file_area_id,
                    client.selected_public_file->name, validated);
                client.selected_public_file->validated = validated;
                const std::string detail = client.selected_public_file->name +
                    (validated ? " in area " : " marked unvalidated in area ") +
                    std::to_string(client.file_area_id);
                record_sysop_action(client, validated ? "validated public file" : "unvalidated public file", detail);
                show_public_file_detail(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not update file validation for " << client.handle
                    << ": " << error.what() << '\n';
                (void)write_channel(client, "\a");
                show_public_file_detail(client);
            }
        } else if (command == 'T' && client.files != nullptr && client.selected_public_file.has_value()) {
            try {
                const auto queue = client.files->download_queue(client.handle);
                const auto queued = std::find_if(queue.begin(), queue.end(), [&client](const auto& item) {
                    return item.area_id == client.file_area_id &&
                        ::strcasecmp(item.filename.c_str(), client.selected_public_file->name.c_str()) == 0;
                });
                if (queued == queue.end()) {
                    const DownloadQueueAddResult result = client.files->tag_download(
                        client.handle, client.file_area_id, client.selected_public_file->name);
                    if (result == DownloadQueueAddResult::Full) {
                        (void)write_channel(client, "\a");
                    }
                } else {
                    client.files->remove_queued_download(client.handle, queued->id);
                }
                show_public_file_detail(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not update download queue for " << client.handle
                    << ": " << error.what() << '\n';
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.viewing_archive_art) {
        const char command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        if (command == 'Q' || command == 'B') {
            show_archive_listing(client);
        }
        return;
    }

    if (client.viewing_archive_text) {
        const char command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        const std::size_t page_size = static_cast<std::size_t>(std::max(1, client.rows - 10));
        const std::size_t page_count = std::max<std::size_t>(1,
            (client.archive_text_lines.size() + page_size - 1) / page_size);
        if (command == 'Q' || command == 'B') {
            show_archive_listing(client);
        } else if (command == 'N' && client.archive_text_page + 1 < page_count) {
            ++client.archive_text_page;
            show_archive_text(client);
        } else if (command == 'P' && client.archive_text_page > 0) {
            --client.archive_text_page;
            show_archive_text(client);
        }
        return;
    }

    if (client.viewing_archive_entry_detail) {
        const char command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        if (command == 'Q' || command == 'B') {
            show_archive_listing(client);
        }
        return;
    }

    if (client.viewing_archive) {
        const char command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        ArchiveFrame& frame = client.archive_stack.back();
        const std::size_t page_count = std::max<std::size_t>(
            1, (frame.visible_entries.size() + 9) / 10);
        if (command == 'Q') {
            return_from_file_browser(client);
        } else if (command == 'B') {
            if (!frame.prefix.empty()) {
                const std::size_t without_trailing = frame.prefix.size() - 1;
                const std::size_t slash = frame.prefix.rfind('/', without_trailing == 0
                    ? 0
                    : without_trailing - 1);
                frame.prefix = slash == std::string::npos ? std::string{} : frame.prefix.substr(0, slash + 1);
                frame.page = 0;
                show_archive_listing(client);
            } else if (client.archive_stack.size() > 1) {
                client.archive_stack.pop_back();
                show_archive_listing(client);
            } else {
                return_from_file_browser(client);
            }
        } else if (command == 'N' && frame.page + 1 < page_count) {
            ++frame.page;
            frame.selection_index = frame.page * 10;
            show_archive_listing(client);
        } else if (command == 'P' && frame.page > 0) {
            --frame.page;
            frame.selection_index = frame.page * 10;
            show_archive_listing(client);
        } else if ((character >= '1' && character <= '9') || character == '0') {
            const std::size_t row = character == '0'
                ? 9
                : static_cast<std::size_t>(character - '1');
            frame.selection_index = frame.page * 10 + row;
            open_archive_entry(client, row);
        }
        return;
    }

    if (client.viewing_file_validation) {
        const char command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        if (client.confirming_bulk_file_validation) {
            if (command == 'Y') {
                try {
                    const std::uint64_t validated = client.files->validate_pending_files(client.handle);
                    record_sysop_action(client, "validated all pending public files",
                        std::to_string(validated) + " files");
                    client.confirming_bulk_file_validation = false;
                    client.file_validation_page_index = 0;
                    show_file_validation_queue(client);
                } catch (const std::exception& error) {
                    (void)write_channel(client, "\r\nCould not validate pending files: " +
                        std::string(error.what()) + "\r\n");
                    client.confirming_bulk_file_validation = false;
                    show_file_validation_queue(client);
                }
            } else if (command == 'N' || command == 'Q') {
                client.confirming_bulk_file_validation = false;
                show_file_validation_queue(client);
            }
        } else if (command == 'Q') {
            client.return_to_file_validation = false;
            client.viewing_file_validation = false;
            client.file_area_page = 0;
            show_file_areas(client);
        } else if (command == 'A' && client.file_validation_page.total > 0) {
            client.confirming_bulk_file_validation = true;
            show_file_validation_queue(client);
        } else if (command == 'R') {
            show_file_validation_queue(client);
        } else if (command == 'N' && client.file_validation_page_index + 1 <
                client.file_validation_page.page_count) {
            ++client.file_validation_page_index;
            client.file_validation_selection_index = 0;
            show_file_validation_queue(client);
        } else if (command == 'P' && client.file_validation_page_index > 0) {
            --client.file_validation_page_index;
            client.file_validation_selection_index = 9;
            show_file_validation_queue(client);
        } else if ((character >= '1' && character <= '9') || character == '0') {
            const std::size_t row = character == '0'
                ? 9
                : static_cast<std::size_t>(character - '1');
            if (row < client.file_validation_page.files.size()) {
                client.file_validation_selection_index = row;
                const NewFileEntry& entry = client.file_validation_page.files[row];
                client.file_area_id = entry.area_id;
                client.file_area_name = entry.area_name;
                client.selected_public_file = entry.file;
                client.confirming_public_file_delete = false;
                client.confirming_public_file_credit_withdrawal = false;
                client.entering_file_point_validation = false;
                client.entering_file_owner_point_adjustment = false;
                client.validation_file_points = 0;
                client.validation_file_points_input.clear();
                client.owner_point_adjustment_input.clear();
                show_public_file_detail(client);
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.viewing_new_files) {
        const char scan_command = static_cast<char>(
            std::toupper(static_cast<unsigned char>(character)));
        if (scan_command == 'Q') {
            client.return_to_new_files = false;
            client.viewing_new_files = false;
            client.choosing_file_scan_area = false;
            client.file_area_page = 0;
            show_file_areas(client);
        } else if (scan_command == 'R') {
            show_new_file_scan(client);
        } else if (scan_command == 'N' && client.new_file_page_index + 1 <
                client.new_file_page.page_count) {
            ++client.new_file_page_index;
            client.new_file_selection_index = 0;
            show_new_file_scan(client);
        } else if (scan_command == 'P' && client.new_file_page_index > 0) {
            --client.new_file_page_index;
            client.new_file_selection_index = 9;
            show_new_file_scan(client);
        } else if ((character >= '1' && character <= '9') || character == '0') {
            const std::size_t row = character == '0'
                ? 9
                : static_cast<std::size_t>(character - '1');
            if (row < client.new_file_page.files.size()) {
                client.new_file_selection_index = row;
                const NewFileEntry& entry = client.new_file_page.files[row];
                client.file_area_id = entry.area_id;
                client.file_area_name = entry.area_name;
                client.return_to_new_files = true;
                open_selected_public_file(client, entry.file);
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.viewing_files) {
        if (client.viewing_file_list) {
            if (client.searching_files) {
                const auto redraw_search_prompt = [&client] {
                    const std::string prompt = "\x1b[" + std::to_string(client.rows - 1) +
                        ";3H\x1b[2K\x1b[97mSearch> " + client.file_search_input +
                        "\x1b[0m\x1b[?25h";
                    (void)write_channel(client, prompt);
                };
                if (character == '\r' || character == '\n') {
                    client.ignore_line_feed = character == '\r';
                    client.file_search = std::move(client.file_search_input);
                    client.file_search_input.clear();
                    client.file_list_page = 0;
                    client.searching_files = false;
                    show_file_listing(client);
                } else if (character == 27) {
                    client.file_search_input.clear();
                    client.searching_files = false;
                    show_file_listing(client);
                } else if (character == '\b' || character == 127) {
                    if (!client.file_search_input.empty()) {
                        client.file_search_input.pop_back();
                        redraw_search_prompt();
                    }
                } else {
                    const unsigned char byte = static_cast<unsigned char>(character);
                    if (byte >= 32 && byte != 127 && client.file_search_input.size() < 64) {
                        client.file_search_input.push_back(character);
                        redraw_search_prompt();
                    }
                }
                return;
            }
            const char file_command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
            if (file_command == 'Q') {
                show_file_areas(client);
            } else if (file_command == 'N' && client.file_list_page + 1 < client.file_page.page_count) {
                ++client.file_list_page;
                client.file_list_selection_index = 0;
                show_file_listing(client);
            } else if (file_command == 'P' && client.file_list_page > 0) {
                --client.file_list_page;
                client.file_list_selection_index = 0;
                show_file_listing(client);
            } else if (character == '/') {
                client.searching_files = true;
                client.file_search_input = client.file_search;
                show_file_listing(client);
            } else if (file_command == 'R') {
                client.file_search.clear();
                client.file_list_page = 0;
                show_file_listing(client);
            } else if (file_command == 'B') {
                client.download_queue_page = 0;
                show_download_queue(client);
            } else if ((character >= '1' && character <= '9') || character == '0') {
                const std::size_t row = character == '0'
                    ? 9
                    : static_cast<std::size_t>(character - '1');
                if (row < client.file_page.files.size()) {
                    client.file_list_selection_index = row;
                    open_selected_public_file(client, client.file_page.files[row]);
                } else {
                    (void)write_channel(client, "\a");
                }
            }
        } else {
            const char file_command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
            const std::size_t page_count = std::max<std::size_t>(
                1, (client.file_areas.size() + 9) / 10);
            if (file_command == 'Q') {
                client.choosing_file_scan_area = false;
                show_welcome(client);
            } else if (character == 27 && client.choosing_file_scan_area) {
                client.choosing_file_scan_area = false;
                show_file_areas(client);
            } else if (file_command == 'S' && !client.choosing_file_scan_area) {
                client.choosing_file_scan_area = false;
                client.new_file_page_index = 0;
                show_new_file_scan(client);
            } else if (file_command == 'T' && !client.choosing_file_scan_area) {
                client.choosing_file_scan_area = true;
                show_file_areas(client);
            } else if (file_command == 'D' && !client.choosing_file_scan_area) {
                client.entering_file_scan_date = true;
                client.file_scan_date_input.clear();
                (void)write_channel(client,
                    "\r\nEnter oldest date for new files (MM/DD/YYYY), or Esc to cancel: ");
            } else if (file_command == 'V' && !client.choosing_file_scan_area && client.is_sysop) {
                client.file_validation_page_index = 0;
                show_file_validation_queue(client);
            } else if (client.choosing_file_scan_area &&
                (file_command == 'F' || file_command == 'U') && client.files != nullptr) {
                try {
                    client.files->set_new_file_scan_all(client.handle, file_command == 'F');
                    client.choosing_file_scan_area = false;
                    show_file_areas(client);
                } catch (const std::exception& error) {
                    std::cerr << "Could not update all new-file scan areas for "
                              << client.handle << ": " << error.what() << '\n';
                    (void)write_channel(client, "\a");
                    client.choosing_file_scan_area = false;
                    show_file_areas(client);
                }
            } else if (file_command == 'N' && client.file_area_page + 1 < page_count) {
                ++client.file_area_page;
                show_file_areas(client);
            } else if (file_command == 'P' && client.file_area_page > 0) {
                --client.file_area_page;
                show_file_areas(client);
            } else if ((character >= '1' && character <= '9') || character == '0') {
                const std::size_t row = character == '0'
                    ? 9
                    : static_cast<std::size_t>(character - '1');
                const std::size_t index = client.file_area_page * 10 + row;
                if (client.choosing_file_scan_area) {
                    if (index < client.file_areas.size() && client.files != nullptr) {
                        try {
                            (void)client.files->toggle_new_file_scan(
                                client.handle, client.file_areas[index].id);
                            client.choosing_file_scan_area = false;
                            show_file_areas(client);
                        } catch (const std::exception& error) {
                            std::cerr << "Could not change new-file scan area for "
                                      << client.handle << ": " << error.what() << '\n';
                            (void)write_channel(client, "\a");
                            client.choosing_file_scan_area = false;
                            show_file_areas(client);
                        }
                    } else {
                        (void)write_channel(client, "\a");
                    }
                } else {
                    select_file_area(client, index);
                }
            }
        }
        return;
    }

    if (client.viewing_profile) {
        if (client.editing_profile) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                save_profile_edit(client);
                return;
            }
            if (character == 27) {
                if (client.profile_completion_active) {
                    client.profile_input.clear();
                    save_profile_edit(client);
                    return;
                }
                if (client.changing_password) {
                    client.password_change_current.clear();
                    client.password_change_new.clear();
                    client.changing_password = false;
                    client.profile_input.clear();
                    client.editing_profile = false;
                    client.profile_field.reset();
                    show_profile(client);
                    return;
                }
                client.profile_input.clear();
                client.editing_profile = false;
                client.profile_field.reset();
                show_profile(client);
                return;
            }
            if (character == '\b' || character == 127) {
                if (!client.profile_input.empty()) {
                    client.profile_input.pop_back();
                    (void)write_channel(client, "\b \b");
                }
                return;
            }
            const unsigned char byte = static_cast<unsigned char>(character);
            std::size_t limit{};
            switch (*client.profile_field) {
            case ClientContext::ProfileField::RealName: limit = 48; break;
            case ClientContext::ProfileField::Location:
            case ClientContext::ProfileField::Signature: limit = 80; break;
            case ClientContext::ProfileField::BirthDate: limit = 10; break;
            case ClientContext::ProfileField::Sex: limit = 1; break;
            case ClientContext::ProfileField::Country: limit = 16; break;
            case ClientContext::ProfileField::Street: limit = 30; break;
            case ClientContext::ProfileField::CityState: limit = 30; break;
            case ClientContext::ProfileField::PostalCode: limit = 10; break;
            case ClientContext::ProfileField::Phone: limit = 12; break;
            case ClientContext::ProfileField::UserAnswer1:
            case ClientContext::ProfileField::UserAnswer2:
            case ClientContext::ProfileField::UserAnswer3: limit = 35; break;
            case ClientContext::ProfileField::ForgotPasswordAnswer: limit = 40; break;
            case ClientContext::ProfileField::CurrentPassword:
            case ClientContext::ProfileField::NewPassword:
            case ClientContext::ProfileField::ConfirmPassword: limit = 128; break;
            }
            if (byte >= 32 && byte != 127 && client.profile_input.size() < limit) {
                const char accepted = *client.profile_field == ClientContext::ProfileField::Sex
                    ? static_cast<char>(std::toupper(byte)) : character;
                client.profile_input.push_back(accepted);
                if (*client.profile_field == ClientContext::ProfileField::ForgotPasswordAnswer) {
                    (void)write_channel(client, "*");
                } else {
                    (void)write_channel(client, std::string_view(&accepted, 1));
                }
            }
            return;
        }
        const char profile_command = static_cast<char>(
            std::toupper(static_cast<unsigned char>(character)));
        if (profile_command == 'Q') {
            show_welcome(client);
        } else if (!client.viewing_profile_contacts && profile_command == 'N') {
            client.viewing_profile_contacts = true;
            client.profile_selection_index = 0;
            show_profile(client);
        } else if (client.viewing_profile_contacts && profile_command == 'M') {
            client.viewing_profile_contacts = false;
            client.profile_selection_index = 0;
            show_profile(client);
        } else if (client.viewing_profile_contacts && profile_command == 'A') {
            start_profile_edit(client, ClientContext::ProfileField::Street);
        } else if (client.viewing_profile_contacts && profile_command == 'C') {
            start_profile_edit(client, ClientContext::ProfileField::Country);
        } else if (client.viewing_profile_contacts && profile_command == 'L') {
            start_profile_edit(client, ClientContext::ProfileField::CityState);
        } else if (client.viewing_profile_contacts && profile_command == 'Z') {
            start_profile_edit(client, ClientContext::ProfileField::PostalCode);
        } else if (client.viewing_profile_contacts && profile_command == 'P') {
            start_profile_edit(client, ClientContext::ProfileField::Phone);
        } else if (client.viewing_profile_contacts && profile_command == '1') {
            start_profile_edit(client, ClientContext::ProfileField::UserAnswer1);
        } else if (client.viewing_profile_contacts && profile_command == '2') {
            start_profile_edit(client, ClientContext::ProfileField::UserAnswer2);
        } else if (client.viewing_profile_contacts && profile_command == '3') {
            start_profile_edit(client, ClientContext::ProfileField::UserAnswer3);
        } else if (client.viewing_profile_contacts && profile_command == 'R') {
            start_profile_edit(client, ClientContext::ProfileField::ForgotPasswordAnswer);
        } else if (!client.viewing_profile_contacts && profile_command == 'R') {
            start_profile_edit(client, ClientContext::ProfileField::RealName);
        } else if (!client.viewing_profile_contacts && profile_command == 'L') {
            start_profile_edit(client, ClientContext::ProfileField::Location);
        } else if (!client.viewing_profile_contacts && profile_command == 'S') {
            start_profile_edit(client, ClientContext::ProfileField::Signature);
        } else if (!client.viewing_profile_contacts && profile_command == 'B') {
            start_profile_edit(client, ClientContext::ProfileField::BirthDate);
        } else if (!client.viewing_profile_contacts && profile_command == 'G') {
            start_profile_edit(client, ClientContext::ProfileField::Sex);
        } else if (!client.viewing_profile_contacts && profile_command == 'W') {
            start_password_change(client);
        } else if (!client.viewing_profile_contacts &&
            (profile_command == 'C' || profile_command == 'X' ||
            profile_command == 'P' || profile_command == 'H' || profile_command == 'E' ||
            profile_command == 'M')) {
            AccountProfile updated = client.profile;
            switch (profile_command) {
            case 'C': updated.ansi_color = !updated.ansi_color; break;
            case 'X': updated.clear_screen = !updated.clear_screen; break;
            case 'P': updated.pause_screens = !updated.pause_screens; break;
            case 'H': updated.hotkeys = !updated.hotkeys; break;
            case 'E': updated.expert_mode = !updated.expert_mode; break;
            case 'M': updated.mailbox_closed = !updated.mailbox_closed; break;
            default: break;
            }
            try {
                client.accounts->update_profile(updated);
                client.profile = std::move(updated);
                show_profile(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not update terminal preferences: " << error.what() << '\n';
                (void)write_channel(client, "\r\nPreference update failed.\r\n");
                show_profile(client);
            }
        }
        return;
    }

    if (client.viewing_sysop_areas) {
        if (client.area_admin_confirming_message_deletion) {
            const char deletion_command = static_cast<char>(
                std::toupper(static_cast<unsigned char>(character)));
            if (deletion_command == 'Y') {
                const long long area_id = client.area_admin_delete_id;
                try {
                    const RemovedBoardArea removed = client.messages->remove_area(area_id);
                    const std::string detail = std::to_string(area_id) + " " + removed.name +
                        " (" + std::to_string(removed.message_count) + " posts removed)";
                    record_sysop_action(client, "deleted message area", detail);
                    client.area_admin_notice = "Deleted message area " + std::to_string(area_id) +
                        " and " + std::to_string(removed.message_count) + " posts.";
                    std::clog << "SysOp " << client.handle << " deleted message area " << area_id
                              << " (" << removed.name << ", " << removed.message_count << " posts).\n";
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                client.area_admin_confirming_message_deletion = false;
                client.area_admin_delete_id = 0;
                client.area_admin_delete_name.clear();
                show_sysop_area_admin(client);
            } else if (deletion_command == 'N' || deletion_command == 'Q' || character == 27) {
                client.area_admin_confirming_message_deletion = false;
                client.area_admin_delete_id = 0;
                client.area_admin_delete_name.clear();
                client.area_admin_notice = "Message-area deletion cancelled.";
                show_sysop_area_admin(client);
            }
            return;
        }

        if (client.area_admin_confirming_file_deletion) {
            const char deletion_command = static_cast<char>(
                std::toupper(static_cast<unsigned char>(character)));
            if (deletion_command == 'R' || deletion_command == 'D') {
                const int area_id = static_cast<int>(client.area_admin_delete_id);
                const std::string area_name = client.area_admin_delete_name;
                const bool delete_storage = deletion_command == 'D';
                try {
                    const RemovedFileArea removed = client.files->remove_area(area_id, delete_storage);
                    std::string detail = std::to_string(area_id) + " " + removed.name;
                    if (removed.storage_cleanup_pending) {
                        detail += " (storage cleanup pending at " + removed.storage_path + ")";
                    } else if (delete_storage) {
                        detail += " (storage deleted)";
                    } else {
                        detail += " (storage retained at " + removed.storage_path + ")";
                    }
                    record_sysop_action(client, "deleted file area", detail);
                    if (removed.storage_cleanup_pending) {
                        client.area_admin_notice = "Removed area listing; storage cleanup is pending at " +
                            removed.storage_path;
                    } else if (delete_storage) {
                        client.area_admin_notice = "Removed file area " + std::to_string(area_id) +
                            " and its storage.";
                    } else {
                        client.area_admin_notice = "Removed area listing; files remain at " +
                            removed.storage_path;
                    }
                    std::clog << "SysOp " << client.handle << " deleted file area " << area_id
                              << " (" << area_name << ", "
                              << (delete_storage ? "storage removal requested" : "storage retained") << ").\n";
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                client.area_admin_confirming_file_deletion = false;
                client.area_admin_delete_id = 0;
                client.area_admin_delete_name.clear();
                show_sysop_area_admin(client);
            } else if (deletion_command == 'N' || deletion_command == 'Q' || character == 27) {
                client.area_admin_confirming_file_deletion = false;
                client.area_admin_delete_id = 0;
                client.area_admin_delete_name.clear();
                client.area_admin_notice = "File-area deletion cancelled.";
                show_sysop_area_admin(client);
            }
            return;
        }

        if (client.area_admin_deleting_file) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    std::size_t parsed = 0;
                    const long parsed_id = std::stol(client.area_admin_input, &parsed);
                    if (parsed != client.area_admin_input.size() || parsed_id < 1 || parsed_id > INT_MAX) {
                        throw std::invalid_argument("file area ID must be a positive number");
                    }
                    const int area_id = static_cast<int>(parsed_id);
                    const auto selected = std::find_if(client.file_areas.begin(), client.file_areas.end(),
                        [area_id](const FileAreaSummary& area) { return area.id == area_id; });
                    if (selected == client.file_areas.end()) {
                        throw std::invalid_argument("file area ID does not exist");
                    }
                    client.area_admin_delete_id = area_id;
                    client.area_admin_delete_name = selected->name;
                    client.area_admin_deleting_file = false;
                    client.area_admin_confirming_file_deletion = true;
                    client.area_admin_input.clear();
                    client.area_admin_notice.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.area_admin_deleting_file = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "File-area deletion cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= '0' && byte <= '9' && client.area_admin_input.size() < 10) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.area_admin_deleting_message) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    std::size_t parsed = 0;
                    const long long parsed_id = std::stoll(client.area_admin_input, &parsed);
                    if (parsed != client.area_admin_input.size() || parsed_id < 1) {
                        throw std::invalid_argument("message area ID must be a positive number");
                    }
                    const auto selected = std::find_if(client.board_areas.begin(), client.board_areas.end(),
                        [parsed_id](const BoardArea& area) { return area.id == parsed_id; });
                    if (selected == client.board_areas.end()) {
                        throw std::invalid_argument("message area ID does not exist");
                    }
                    client.area_admin_delete_id = parsed_id;
                    client.area_admin_delete_name = selected->name;
                    client.area_admin_deleting_message = false;
                    client.area_admin_confirming_message_deletion = true;
                    client.area_admin_input.clear();
                    client.area_admin_notice.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.area_admin_deleting_message = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Message-area deletion cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= '0' && byte <= '9' && client.area_admin_input.size() < 19) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.admin_policy_edit != ClientContext::AdminPolicyEdit::None) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    std::vector<std::string_view> fields;
                    std::size_t start = 0;
                    for (;;) {
                        const std::size_t separator = client.area_admin_input.find(';', start);
                        const std::size_t end = separator == std::string::npos
                            ? client.area_admin_input.size() : separator;
                        fields.emplace_back(client.area_admin_input.data() + start, end - start);
                        if (separator == std::string::npos) {
                            break;
                        }
                        start = separator + 1;
                    }
                    const auto parse_number = [](std::string_view value, std::string_view label,
                                                  std::uint32_t maximum) {
                        std::uint32_t result{};
                        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
                        if (value.empty() || parsed.ec != std::errc{} ||
                            parsed.ptr != value.data() + value.size() || result > maximum) {
                            throw std::invalid_argument(std::string(label) + " is outside its valid range.");
                        }
                        return result;
                    };
                    const auto enabled_value = [](std::string_view value) {
                        if (value == "on") return true;
                        if (value == "off") return false;
                        throw std::invalid_argument("Use on or off for the policy state.");
                    };
                    const auto acs_value = [](std::string_view value) {
                        return value == "-" ? std::string{} : std::string(value);
                    };
                    switch (client.admin_policy_edit) {
                    case ClientContext::AdminPolicyEdit::Ratios: {
                        if (fields.size() != 4) {
                            throw std::invalid_argument("Use on|off;DLRatio;DLKRatio;NoDLRatio ACS.");
                        }
                        const bool enabled = enabled_value(fields[0]);
                        const std::uint32_t count_ratio = parse_number(fields[1], "DLRatio", INT_MAX);
                        const std::uint32_t kib_ratio = parse_number(fields[2], "DLKRatio", INT_MAX);
                        const std::string no_ratio_acs = acs_value(fields[3]);
                        client.files->set_download_ratios(enabled, count_ratio, kib_ratio, no_ratio_acs);
                        record_sysop_action(client, "updated global file ratios",
                            std::string(enabled ? "ULDLRatio=on" : "ULDLRatio=off") +
                                " DLRatio=" + std::to_string(count_ratio) +
                                " DLKRatio=" + std::to_string(kib_ratio) +
                                " NoDLRatio=" + (no_ratio_acs.empty() ? "*" : no_ratio_acs));
                        client.area_admin_notice = "Updated global file ratios and ULDLRatio state.";
                        break;
                    }
                    case ClientContext::AdminPolicyEdit::LevelRatios: {
                        if (fields.size() == 3 && fields[2] == "global") {
                            const std::uint32_t min_level = parse_number(fields[0], "SL_MIN", 255);
                            const std::uint32_t max_level = parse_number(fields[1], "SL_MAX", 255);
                            if (min_level > max_level) {
                                throw std::invalid_argument("SL_MIN must not exceed SL_MAX.");
                            }
                            client.files->clear_download_level_ratios(
                                static_cast<int>(min_level), static_cast<int>(max_level));
                            record_sysop_action(client, "cleared security-level file-ratio overrides",
                                "SL=" + std::to_string(min_level) + "-" + std::to_string(max_level));
                            client.area_admin_notice = "Cleared ratio overrides; selected levels inherit global values.";
                            break;
                        }
                        if (fields.size() != 4) {
                            throw std::invalid_argument("Use SL_MIN;SL_MAX;DLRatio;DLKRatio, or SL_MIN;SL_MAX;global.");
                        }
                        const std::uint32_t min_level = parse_number(fields[0], "SL_MIN", 255);
                        const std::uint32_t max_level = parse_number(fields[1], "SL_MAX", 255);
                        const std::uint32_t count_ratio = parse_number(fields[2], "DLRatio", INT_MAX);
                        const std::uint32_t kib_ratio = parse_number(fields[3], "DLKRatio", INT_MAX);
                        if (min_level > max_level) {
                            throw std::invalid_argument("SL_MIN must not exceed SL_MAX.");
                        }
                        client.files->set_download_level_ratios(static_cast<int>(min_level),
                            static_cast<int>(max_level), count_ratio, kib_ratio);
                        record_sysop_action(client, "updated security-level file ratios",
                            "SL=" + std::to_string(min_level) + "-" + std::to_string(max_level) +
                                " DLRatio=" + std::to_string(count_ratio) +
                                " DLKRatio=" + std::to_string(kib_ratio));
                        client.area_admin_notice = "Updated file ratios for the selected security levels.";
                        break;
                    }
                    case ClientContext::AdminPolicyEdit::DailyLimits: {
                        if (fields.size() != 5) {
                            throw std::invalid_argument("Use on|off;SL_MIN;SL_MAX;FILES;KIB.");
                        }
                        const bool enabled = enabled_value(fields[0]);
                        const std::uint32_t min_level = parse_number(fields[1], "SL_MIN", 255);
                        const std::uint32_t max_level = parse_number(fields[2], "SL_MAX", 255);
                        const std::uint32_t max_files = parse_number(fields[3], "daily file limit", INT_MAX);
                        const std::uint32_t max_kib = parse_number(fields[4], "daily KiB limit", INT_MAX);
                        if (min_level > max_level) {
                            throw std::invalid_argument("SL_MIN must not exceed SL_MAX.");
                        }
                        client.files->set_download_daily_limits(enabled, static_cast<int>(min_level),
                            static_cast<int>(max_level), max_files, max_kib);
                        record_sysop_action(client, "updated daily file-download limits",
                            std::string(enabled ? "DailyLimits=on" : "DailyLimits=off") +
                                " SL=" + std::to_string(min_level) + "-" + std::to_string(max_level) +
                                " Files=" + std::to_string(max_files) + " KiB=" + std::to_string(max_kib));
                        client.area_admin_notice = "Updated per-level daily file-download limits.";
                        break;
                    }
                    case ClientContext::AdminPolicyEdit::Points: {
                        if (fields.size() != 5) {
                            throw std::invalid_argument(
                                "Use on|off;BASE_KIB;UPLOAD_COMP;REWARD_RATIO;NOFILECREDITS ACS.");
                        }
                        const bool enabled = enabled_value(fields[0]);
                        const std::uint32_t base_size = parse_number(fields[1], "BASE_KIB", 32767);
                        const std::uint32_t upload_compensation = parse_number(fields[2], "UPLOAD_COMP", 32767);
                        const std::uint32_t reward_ratio = parse_number(fields[3], "REWARD_RATIO", 32767);
                        const std::string no_file_credits_acs = fields[4] == "-"
                            ? "%" : std::string(fields[4]);
                        client.files->set_file_point_rules(enabled, base_size, upload_compensation,
                            reward_ratio, no_file_credits_acs);
                        record_sysop_action(client, "updated file-point rules",
                            std::string(enabled ? "FileCreditRatio=on" : "FileCreditRatio=off") +
                                " BaseKiB=" + std::to_string(base_size) +
                                " UploadComp=" + std::to_string(upload_compensation) +
                                " RewardRatio=" + std::to_string(reward_ratio) +
                                " NoFileCredits=" + no_file_credits_acs);
                        client.area_admin_notice = "Updated global file-point charging and credit rules.";
                        break;
                    }
                    case ClientContext::AdminPolicyEdit::UploadValidation: {
                        if (fields.size() != 2) {
                            throw std::invalid_argument("Use AUTO_VALIDATE_ACS;ValidateAll on|off.");
                        }
                        const std::string auto_validate_acs = acs_value(fields[0]);
                        const bool validate_all = enabled_value(fields[1]);
                        client.files->set_upload_validation_rules(auto_validate_acs, validate_all);
                        record_sysop_action(client, "updated file upload validation rules",
                            "ULValReq=" + (auto_validate_acs.empty() ? "*" : auto_validate_acs) +
                                " ValidateAllFiles=" + (validate_all ? "on" : "off"));
                        client.area_admin_notice = "Updated upload auto-validation and validate-all rules.";
                        break;
                    }
                    case ClientContext::AdminPolicyEdit::UnvalidatedAccess: {
                        if (fields.size() != 2) {
                            throw std::invalid_argument("Use SEEUNVAL_ACS;DLUNVAL_ACS.");
                        }
                        const std::string see_acs = acs_value(fields[0]);
                        const std::string download_acs = acs_value(fields[1]);
                        client.files->set_unvalidated_access(see_acs, download_acs);
                        record_sysop_action(client, "updated unvalidated-file access rules",
                            "SeeUnVal=" + (see_acs.empty() ? "*" : see_acs) +
                                " DLUnVal=" + (download_acs.empty() ? "*" : download_acs));
                        client.area_admin_notice = "Updated unvalidated-file visibility and download ACS.";
                        break;
                    }
                    case ClientContext::AdminPolicyEdit::AreaNoRatio: {
                        if (fields.size() != 2) {
                            throw std::invalid_argument("Use AREA_ID;on|off.");
                        }
                        const std::uint32_t area_id = parse_number(fields[0], "AREA_ID", INT_MAX);
                        if (area_id < 1) {
                            throw std::invalid_argument("AREA_ID must be positive.");
                        }
                        const bool exempt = enabled_value(fields[1]);
                        client.files->set_area_no_ratio(static_cast<int>(area_id), exempt);
                        record_sysop_action(client, exempt ? "exempted file area from ratios"
                                                           : "enabled file-area ratios",
                            "AREA=" + std::to_string(area_id));
                        client.area_admin_notice = exempt
                            ? "Excluded the file area from ratio and daily-limit checks."
                            : "Enabled ratio and daily-limit checks for the file area.";
                        break;
                    }
                    case ClientContext::AdminPolicyEdit::PostRatio: {
                        if (fields.size() != 3) {
                            throw std::invalid_argument("Use SL_MIN;SL_MAX;PERCENT (0-100).");
                        }
                        const std::uint32_t minimum_level = parse_number(fields[0], "SL_MIN", 255);
                        const std::uint32_t maximum_level = parse_number(fields[1], "SL_MAX", 255);
                        const std::uint32_t percent = parse_number(fields[2], "PERCENT", 100);
                        if (minimum_level > maximum_level) {
                            throw std::invalid_argument("SL_MIN must not exceed SL_MAX.");
                        }
                        client.messages->set_post_ratio_range(
                            static_cast<int>(minimum_level), static_cast<int>(maximum_level),
                            static_cast<int>(percent));
                        record_sysop_action(client, "updated post-call ratios",
                            "SL=" + std::to_string(minimum_level) + "-" +
                                std::to_string(maximum_level) + " Percent=" + std::to_string(percent));
                        client.area_admin_notice = "Updated post-call ratios for the selected security levels.";
                        break;
                    }
                    case ClientContext::AdminPolicyEdit::SubmissionAcs: {
                        if (fields.size() != 2) {
                            throw std::invalid_argument("Use ADDQUOTE;ADDONELINER ACS, with - for open access.");
                        }
                        const std::string quote_acs = acs_value(fields[0]);
                        const std::string one_liner_acs = acs_value(fields[1]);
                        client.messages->set_submission_acs(quote_acs, one_liner_acs);
                        record_sysop_action(client, "updated quote and one-liner ACS",
                            "AddQuote=" + (quote_acs.empty() ? "*" : quote_acs) +
                                " AddOneLiner=" + (one_liner_acs.empty() ? "*" : one_liner_acs));
                        client.area_admin_notice = "Updated quote and one-liner submission access rules.";
                        break;
                    }
                    case ClientContext::AdminPolicyEdit::InvisibleAcs: {
                        if (fields.size() != 1) {
                            throw std::invalid_argument("Enter one invisibility ACS expression, or - for open access.");
                        }
                        const std::string invisible_acs = acs_value(fields[0]);
                        client.messages->set_invisibility_acs(invisible_acs);
                        record_sysop_action(client, "updated invisible-mode ACS",
                            invisible_acs.empty() ? "Invisible=*" : "Invisible=" + invisible_acs);
                        client.area_admin_notice = "Updated the ACS required to toggle invisible mode.";
                        break;
                    }
                    case ClientContext::AdminPolicyEdit::ValidationEligibility: {
                        if (fields.size() != 2) {
                            throw std::invalid_argument("Use on|off;NewSL (0-255).");
                        }
                        const bool active = enabled_value(fields[0]);
                        const std::uint32_t new_level = parse_number(fields[1], "NewSL", 255);
                        client.messages->set_validation_eligibility(active, static_cast<int>(new_level));
                        record_sysop_action(client, "updated account validation eligibility",
                            std::string("ValidationKey=") + (active ? "on" : "off") +
                                " NewSL=" + std::to_string(new_level));
                        client.area_admin_notice = "Updated the validation key and new-user security level.";
                        break;
                    }
                    case ClientContext::AdminPolicyEdit::None:
                        break;
                    }
                    client.admin_policy_edit = ClientContext::AdminPolicyEdit::None;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.admin_policy_edit = ClientContext::AdminPolicyEdit::None;
                client.area_admin_input.clear();
                client.area_admin_notice = "File policy edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= 32 && byte < 127 && client.area_admin_input.size() < 128) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.editing_global_anonymous_acs) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t first = client.area_admin_input.find(';');
                    const std::size_t second = first == std::string::npos
                        ? std::string::npos : client.area_admin_input.find(';', first + 1);
                    const std::size_t third = second == std::string::npos
                        ? std::string::npos : client.area_admin_input.find(';', second + 1);
                    if (first == std::string::npos || second == std::string::npos ||
                        third == std::string::npos ||
                        client.area_admin_input.find(';', third + 1) != std::string::npos) {
                        throw std::invalid_argument(
                            "Use PUBPOST;PUBREAD;PRIVPOST;PRIVREAD, with - for an open rule.");
                    }
                    const auto expression = [](std::string value) {
                        return value == "-" ? std::string{} : value;
                    };
                    const std::string public_post = expression(client.area_admin_input.substr(0, first));
                    const std::string public_read = expression(client.area_admin_input.substr(first + 1, second - first - 1));
                    const std::string private_post = expression(client.area_admin_input.substr(second + 1, third - second - 1));
                    const std::string private_read = expression(client.area_admin_input.substr(third + 1));
                    client.messages->set_anonymous_acs(public_post, public_read, private_post, private_read);
                    record_sysop_action(client, "updated anonymous-message ACS",
                        "AnonPubPost=" + (public_post.empty() ? "*" : public_post) +
                            " AnonPubRead=" + (public_read.empty() ? "*" : public_read) +
                            " AnonPrivPost=" + (private_post.empty() ? "*" : private_post) +
                            " AnonPrivRead=" + (private_read.empty() ? "*" : private_read));
                    client.area_admin_notice = "Updated global public/private anonymous ACS rules.";
                    client.editing_global_anonymous_acs = false;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_global_anonymous_acs = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Anonymous ACS edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= 32 && byte < 127 && client.area_admin_input.size() < 84) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.editing_global_post_acs) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t separator = client.area_admin_input.find(';');
                    if (separator == std::string::npos ||
                        client.area_admin_input.find(';', separator + 1) != std::string::npos) {
                        throw std::invalid_argument("Use PUBPOST;PRIVPOST, with - for an open rule.");
                    }
                    const auto expression = [](std::string value) {
                        return value == "-" ? std::string{} : value;
                    };
                    const std::string public_post = expression(client.area_admin_input.substr(0, separator));
                    const std::string private_post = expression(client.area_admin_input.substr(separator + 1));
                    client.messages->set_normal_post_acs(public_post, private_post);
                    record_sysop_action(client, "updated normal-post ACS",
                        "NormPubPost=" + (public_post.empty() ? "*" : public_post) +
                            " NormPrivPost=" + (private_post.empty() ? "*" : private_post));
                    client.area_admin_notice = "Updated global public/private posting ACS rules.";
                    client.editing_global_post_acs = false;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_global_post_acs = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Global posting ACS edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= 32 && byte < 127 && client.area_admin_input.size() < 42) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.editing_global_post_limits) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t separator = client.area_admin_input.find(';');
                    if (separator == std::string::npos ||
                        client.area_admin_input.find(';', separator + 1) != std::string::npos) {
                        throw std::invalid_argument("Use MAXPUB;MAXPRIV, with each limit from 0 to 255.");
                    }
                    const auto parse_limit = [&](std::size_t begin, std::size_t end) {
                        const std::string_view value(client.area_admin_input.data() + begin, end - begin);
                        int result{};
                        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
                        if (value.empty() || parsed.ec != std::errc{} ||
                            parsed.ptr != value.data() + value.size() || result < 0 || result > 255) {
                            throw std::invalid_argument("Each message limit must be from 0 to 255 per call.");
                        }
                        return result;
                    };
                    const int public_limit = parse_limit(0, separator);
                    const int private_limit = parse_limit(separator + 1, client.area_admin_input.size());
                    client.messages->set_post_limits(public_limit, private_limit);
                    record_sysop_action(client, "updated message post limits",
                        "MaxPubPost=" + std::to_string(public_limit) +
                            " MaxPrivPost=" + std::to_string(private_limit));
                    client.area_admin_notice = "Updated public/private message limits per call.";
                    client.editing_global_post_limits = false;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_global_post_limits = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Message post-limit edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (((byte >= '0' && byte <= '9') || byte == ';') && client.area_admin_input.size() < 7) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.editing_global_mail_limits) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t separator = client.area_admin_input.find(';');
                    if (separator == std::string::npos ||
                        client.area_admin_input.find(';', separator + 1) != std::string::npos) {
                        throw std::invalid_argument("Use MAXWAIT;CSWAIT, with each limit from 0 to 255.");
                    }
                    const auto parse_limit = [&](std::size_t begin, std::size_t end) {
                        const std::string_view value(client.area_admin_input.data() + begin, end - begin);
                        int result{};
                        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
                        if (value.empty() || parsed.ec != std::errc{} ||
                            parsed.ptr != value.data() + value.size() || result < 0 || result > 255) {
                            throw std::invalid_argument("Each private-mail waiting limit must be from 0 to 255.");
                        }
                        return result;
                    };
                    const int normal_limit = parse_limit(0, separator);
                    const int sysop_limit = parse_limit(separator + 1, client.area_admin_input.size());
                    client.messages->set_private_mail_waiting_limits(normal_limit, sysop_limit);
                    record_sysop_action(client, "updated private-mail waiting limits",
                        "MaxWaiting=" + std::to_string(normal_limit) +
                            " CSMaxWaiting=" + std::to_string(sysop_limit));
                    client.area_admin_notice = "Updated normal/SysOp private-mail waiting limits.";
                    client.editing_global_mail_limits = false;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_global_mail_limits = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Private-mail waiting-limit edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (((byte >= '0' && byte <= '9') || byte == ';') && client.area_admin_input.size() < 7) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.editing_global_credit_costs) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t separator = client.area_admin_input.find(';');
                    if (separator == std::string::npos ||
                        client.area_admin_input.find(';', separator + 1) != std::string::npos) {
                        throw std::invalid_argument("Use PUBLIC;PRIVATE, with signed costs from -32767 to 32767.");
                    }
                    const auto parse_cost = [&](std::size_t begin, std::size_t end) {
                        const std::string_view value(client.area_admin_input.data() + begin, end - begin);
                        int result{};
                        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
                        if (value.empty() || parsed.ec != std::errc{} ||
                            parsed.ptr != value.data() + value.size() || result < -32767 || result > 32767) {
                            throw std::invalid_argument("Each message credit cost must be from -32767 to 32767.");
                        }
                        return result;
                    };
                    const int public_cost = parse_cost(0, separator);
                    const int private_cost = parse_cost(separator + 1, client.area_admin_input.size());
                    client.messages->set_credit_costs(public_cost, private_cost);
                    record_sysop_action(client, "updated message credit costs",
                        "CreditPost=" + std::to_string(public_cost) +
                            " CreditEmail=" + std::to_string(private_cost));
                    client.area_admin_notice = "Updated public/private message credit costs.";
                    client.editing_global_credit_costs = false;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_global_credit_costs = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Message credit-cost edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (((byte >= '0' && byte <= '9') || byte == '-' || byte == ';') &&
                    client.area_admin_input.size() < 13) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.editing_message_area_password) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t separator = client.area_admin_input.find(';');
                    if (separator == std::string::npos) {
                        throw std::invalid_argument("Use AREA_ID;PASSWORD, or AREA_ID;- to remove the password.");
                    }
                    const std::string_view id_text(client.area_admin_input.data(), separator);
                    long long area_id{};
                    const auto parsed = std::from_chars(
                        id_text.data(), id_text.data() + id_text.size(), area_id);
                    if (id_text.empty() || parsed.ec != std::errc{} ||
                        parsed.ptr != id_text.data() + id_text.size() || area_id < 1) {
                        throw std::invalid_argument("Message-area ID must be a positive number.");
                    }
                    const auto selected = std::find_if(client.board_areas.begin(), client.board_areas.end(),
                        [area_id](const BoardArea& area) { return area.id == area_id; });
                    if (selected == client.board_areas.end()) {
                        throw std::invalid_argument("Message area ID does not exist.");
                    }
                    std::string password = client.area_admin_input.substr(separator + 1);
                    const bool clearing = password == "-" || password.empty();
                    if (clearing) {
                        password.clear();
                    }
                    client.messages->set_area_password(area_id, password);
                    record_sysop_action(client,
                        clearing ? "cleared message-area password" : "set message-area password",
                        std::to_string(area_id) + " " + selected->name);
                    client.area_admin_notice = clearing
                        ? "Removed the shared password from " + selected->name + "."
                        : "Set the shared password for " + selected->name + ".";
                    client.editing_message_area_password = false;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_message_area_password = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Message-area password edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= 32 && byte < 127 && client.area_admin_input.size() < 40) {
                    const std::size_t separator = client.area_admin_input.find(';');
                    if (separator == std::string::npos || client.area_admin_input.size() - separator - 1 < 20) {
                        client.area_admin_input.push_back(character);
                        show_sysop_area_admin(client);
                    }
                }
            }
            return;
        }

        if (client.editing_message_taglines) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t separator = client.area_admin_input.find(';');
                    if (separator == std::string::npos ||
                        client.area_admin_input.find(';', separator + 1) != std::string::npos) {
                        throw std::invalid_argument("Use AREA_ID;on or AREA_ID;off.");
                    }
                    const std::string_view id_text(client.area_admin_input.data(), separator);
                    long long area_id{};
                    const auto parsed = std::from_chars(
                        id_text.data(), id_text.data() + id_text.size(), area_id);
                    if (id_text.empty() || parsed.ec != std::errc{} ||
                        parsed.ptr != id_text.data() + id_text.size() || area_id < 1) {
                        throw std::invalid_argument("Message-area ID must be a positive number.");
                    }
                    std::string state = client.area_admin_input.substr(separator + 1);
                    std::transform(state.begin(), state.end(), state.begin(), [](unsigned char value) {
                        return static_cast<char>(std::tolower(value));
                    });
                    if (state != "on" && state != "off") {
                        throw std::invalid_argument("Tagline setting must be on or off.");
                    }
                    const auto selected = std::find_if(client.board_areas.begin(), client.board_areas.end(),
                        [area_id](const BoardArea& area) { return area.id == area_id; });
                    if (selected == client.board_areas.end()) {
                        throw std::invalid_argument("Message area ID does not exist.");
                    }
                    const std::string area_name = selected->name;
                    client.messages->set_area_taglines_enabled(area_id, state == "on");
                    record_sysop_action(client, "updated message-area tagline setting",
                        std::to_string(area_id) + " " + area_name + " " + state);
                    client.area_admin_notice = "Message taglines " + state + " for " + area_name + ".";
                    client.editing_message_taglines = false;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_message_taglines = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Message tagline edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (((byte >= '0' && byte <= '9') || byte == ';' ||
                        (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z')) &&
                    client.area_admin_input.size() < 24) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.editing_message_filter) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t separator = client.area_admin_input.find(';');
                    if (separator == std::string::npos ||
                        client.area_admin_input.find(';', separator + 1) != std::string::npos) {
                        throw std::invalid_argument("Use AREA_ID;on or AREA_ID;off.");
                    }
                    const std::string_view id_text(client.area_admin_input.data(), separator);
                    long long area_id{};
                    const auto parsed = std::from_chars(
                        id_text.data(), id_text.data() + id_text.size(), area_id);
                    if (id_text.empty() || parsed.ec != std::errc{} ||
                        parsed.ptr != id_text.data() + id_text.size() || area_id < 1) {
                        throw std::invalid_argument("Message-area ID must be a positive number.");
                    }
                    std::string state = client.area_admin_input.substr(separator + 1);
                    std::transform(state.begin(), state.end(), state.begin(), [](unsigned char value) {
                        return static_cast<char>(std::tolower(value));
                    });
                    if (state != "on" && state != "off") {
                        throw std::invalid_argument("Message filter setting must be on or off.");
                    }
                    const auto selected = std::find_if(client.board_areas.begin(), client.board_areas.end(),
                        [area_id](const BoardArea& area) { return area.id == area_id; });
                    if (selected == client.board_areas.end()) {
                        throw std::invalid_argument("Message area ID does not exist.");
                    }
                    const std::string area_name = selected->name;
                    client.messages->set_area_public_text_filter(area_id, state == "on");
                    record_sysop_action(client, "updated message-area public-text filter",
                        std::to_string(area_id) + " " + area_name + " " + state);
                    client.area_admin_notice = "Public-message filtering " + state + " for " + area_name + ".";
                    client.editing_message_filter = false;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_message_filter = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Message filter edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (((byte >= '0' && byte <= '9') || byte == ';' ||
                        (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z')) &&
                    client.area_admin_input.size() < 24) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.editing_message_unhidden) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t separator = client.area_admin_input.find(';');
                    if (separator == std::string::npos ||
                        client.area_admin_input.find(';', separator + 1) != std::string::npos) {
                        throw std::invalid_argument("Use AREA_ID;on or AREA_ID;off.");
                    }
                    const std::string_view id_text(client.area_admin_input.data(), separator);
                    long long area_id{};
                    const auto parsed = std::from_chars(
                        id_text.data(), id_text.data() + id_text.size(), area_id);
                    if (id_text.empty() || parsed.ec != std::errc{} ||
                        parsed.ptr != id_text.data() + id_text.size() || area_id < 1) {
                        throw std::invalid_argument("Message-area ID must be a positive number.");
                    }
                    std::string state = client.area_admin_input.substr(separator + 1);
                    std::transform(state.begin(), state.end(), state.begin(), [](unsigned char value) {
                        return static_cast<char>(std::tolower(value));
                    });
                    if (state != "on" && state != "off") {
                        throw std::invalid_argument("Visibility state must be on or off.");
                    }
                    const auto selected = std::find_if(client.board_areas.begin(), client.board_areas.end(),
                        [area_id](const BoardArea& area) { return area.id == area_id; });
                    if (selected == client.board_areas.end()) {
                        throw std::invalid_argument("Message area ID does not exist.");
                    }
                    const std::string area_name = selected->name;
                    client.messages->set_area_unhidden(area_id, state == "on");
                    record_sysop_action(client, "updated message-area visibility",
                        std::to_string(area_id) + " " + area_name + " " + state);
                    client.area_admin_notice = "Visibility without access " + state + " for " + area_name + ".";
                    client.editing_message_unhidden = false;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_message_unhidden = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Message-area visibility edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (((byte >= '0' && byte <= '9') || byte == ';' ||
                        (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z')) &&
                    client.area_admin_input.size() < 24) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.editing_message_tearline) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t separator = client.area_admin_input.find(';');
                    if (separator == std::string::npos ||
                        client.area_admin_input.find(';', separator + 1) != std::string::npos) {
                        throw std::invalid_argument("Use AREA_ID;on or AREA_ID;off.");
                    }
                    const std::string_view id_text(client.area_admin_input.data(), separator);
                    long long area_id{};
                    const auto parsed = std::from_chars(
                        id_text.data(), id_text.data() + id_text.size(), area_id);
                    if (id_text.empty() || parsed.ec != std::errc{} ||
                        parsed.ptr != id_text.data() + id_text.size() || area_id < 1) {
                        throw std::invalid_argument("Message-area ID must be a positive number.");
                    }
                    std::string state = client.area_admin_input.substr(separator + 1);
                    std::transform(state.begin(), state.end(), state.begin(), [](unsigned char value) {
                        return static_cast<char>(std::tolower(value));
                    });
                    if (state != "on" && state != "off") {
                        throw std::invalid_argument("Tearline setting must be on or off.");
                    }
                    const auto selected = std::find_if(client.board_areas.begin(), client.board_areas.end(),
                        [area_id](const BoardArea& area) { return area.id == area_id; });
                    if (selected == client.board_areas.end()) {
                        throw std::invalid_argument("Message area ID does not exist.");
                    }
                    const std::string area_name = selected->name;
                    client.messages->set_area_tearline_enabled(area_id, state == "on");
                    record_sysop_action(client, "updated message-area tearline setting",
                        std::to_string(area_id) + " " + area_name + " " + state);
                    client.area_admin_notice = "Message tearlines " + state + " for " + area_name + ".";
                    client.editing_message_tearline = false;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_message_tearline = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Message tearline edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (((byte >= '0' && byte <= '9') || byte == ';' ||
                        (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z')) &&
                    client.area_admin_input.size() < 24) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.editing_message_origin) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t first_separator = client.area_admin_input.find(';');
                    const std::size_t second_separator = first_separator == std::string::npos
                        ? std::string::npos : client.area_admin_input.find(';', first_separator + 1);
                    if (first_separator == std::string::npos || second_separator == std::string::npos ||
                        client.area_admin_input.find(';', second_separator + 1) != std::string::npos) {
                        throw std::invalid_argument("Use AREA_ID;ORIGIN;ZONE:NET/NODE.POINT.");
                    }
                    const std::string_view id_text(client.area_admin_input.data(), first_separator);
                    long long area_id{};
                    const auto parsed = std::from_chars(
                        id_text.data(), id_text.data() + id_text.size(), area_id);
                    if (id_text.empty() || parsed.ec != std::errc{} ||
                        parsed.ptr != id_text.data() + id_text.size() || area_id < 1) {
                        throw std::invalid_argument("Message-area ID must be a positive number.");
                    }
                    std::string_view origin(client.area_admin_input.data() + first_separator + 1,
                        second_separator - first_separator - 1);
                    std::string_view address(client.area_admin_input.data() + second_separator + 1,
                        client.area_admin_input.size() - second_separator - 1);
                    if (origin == "-") origin = {};
                    if (address == "-") address = {};
                    const auto selected = std::find_if(client.board_areas.begin(), client.board_areas.end(),
                        [area_id](const BoardArea& area) { return area.id == area_id; });
                    if (selected == client.board_areas.end()) {
                        throw std::invalid_argument("Message area ID does not exist.");
                    }
                    const std::string area_name = selected->name;
                    client.messages->set_area_origin(area_id, origin, address);
                    record_sysop_action(client, "updated message-area origin",
                        std::to_string(area_id) + " " + area_name);
                    client.area_admin_notice = "Updated tearline origin for " + area_name + ".";
                    client.editing_message_origin = false;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_message_origin = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Message origin edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= 32 && byte != 127 && client.area_admin_input.size() < 104) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.editing_message_force_read) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t separator = client.area_admin_input.find(';');
                    if (separator == std::string::npos ||
                        client.area_admin_input.find(';', separator + 1) != std::string::npos) {
                        throw std::invalid_argument("Use AREA_ID;on or AREA_ID;off.");
                    }
                    const std::string_view id_text(client.area_admin_input.data(), separator);
                    long long area_id{};
                    const auto parsed = std::from_chars(
                        id_text.data(), id_text.data() + id_text.size(), area_id);
                    if (id_text.empty() || parsed.ec != std::errc{} ||
                        parsed.ptr != id_text.data() + id_text.size() || area_id < 1) {
                        throw std::invalid_argument("Message-area ID must be a positive number.");
                    }
                    std::string state = client.area_admin_input.substr(separator + 1);
                    std::transform(state.begin(), state.end(), state.begin(), [](unsigned char value) {
                        return static_cast<char>(std::tolower(value));
                    });
                    if (state != "on" && state != "off") {
                        throw std::invalid_argument("Forced-scan state must be on or off.");
                    }
                    const auto selected = std::find_if(client.board_areas.begin(), client.board_areas.end(),
                        [area_id](const BoardArea& area) { return area.id == area_id; });
                    if (selected == client.board_areas.end()) {
                        throw std::invalid_argument("Message area ID does not exist.");
                    }
                    const std::string area_name = selected->name;
                    client.messages->set_area_force_read(area_id, state == "on");
                    record_sysop_action(client, "updated forced message-area scan",
                        std::to_string(area_id) + " " + area_name + " " + state);
                    client.area_admin_notice = "Forced new scans " + state + " for " + area_name + ".";
                    client.editing_message_force_read = false;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_message_force_read = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Forced-scan edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (((byte >= '0' && byte <= '9') || byte == ';' ||
                        (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z')) &&
                    client.area_admin_input.size() < 24) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.editing_message_real_names) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t separator = client.area_admin_input.find(';');
                    if (separator == std::string::npos ||
                        client.area_admin_input.find(';', separator + 1) != std::string::npos) {
                        throw std::invalid_argument("Use AREA_ID;on or AREA_ID;off.");
                    }
                    const std::string_view id_text(client.area_admin_input.data(), separator);
                    long long area_id{};
                    const auto parsed = std::from_chars(
                        id_text.data(), id_text.data() + id_text.size(), area_id);
                    if (id_text.empty() || parsed.ec != std::errc{} ||
                        parsed.ptr != id_text.data() + id_text.size() || area_id < 1) {
                        throw std::invalid_argument("Message-area ID must be a positive number.");
                    }
                    std::string state = client.area_admin_input.substr(separator + 1);
                    std::transform(state.begin(), state.end(), state.begin(), [](unsigned char value) {
                        return static_cast<char>(std::tolower(value));
                    });
                    if (state != "on" && state != "off") {
                        throw std::invalid_argument("Real-name search state must be on or off.");
                    }
                    const auto selected = std::find_if(client.board_areas.begin(), client.board_areas.end(),
                        [area_id](const BoardArea& area) { return area.id == area_id; });
                    if (selected == client.board_areas.end()) {
                        throw std::invalid_argument("Message area ID does not exist.");
                    }
                    const std::string area_name = selected->name;
                    client.messages->set_area_real_name_search(area_id, state == "on");
                    record_sysop_action(client, "updated message-area real-name search",
                        std::to_string(area_id) + " " + area_name + " " + state);
                    client.area_admin_notice = "Real-name searches " + state + " for " + area_name + ".";
                    client.editing_message_real_names = false;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_message_real_names = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Real-name search edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (((byte >= '0' && byte <= '9') || byte == ';' ||
                        (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z')) &&
                    client.area_admin_input.size() < 24) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.editing_message_quote_templates) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t first_separator = client.area_admin_input.find(';');
                    const std::size_t second_separator = first_separator == std::string::npos
                        ? std::string::npos
                        : client.area_admin_input.find(';', first_separator + 1);
                    if (first_separator == std::string::npos || second_separator == std::string::npos) {
                        throw std::invalid_argument("Use AREA_ID;S|E;TEXT.");
                    }
                    const std::string_view id_text(client.area_admin_input.data(), first_separator);
                    long long area_id{};
                    const auto parsed = std::from_chars(
                        id_text.data(), id_text.data() + id_text.size(), area_id);
                    if (id_text.empty() || parsed.ec != std::errc{} ||
                        parsed.ptr != id_text.data() + id_text.size() || area_id < 1) {
                        throw std::invalid_argument("Message-area ID must be a positive number.");
                    }
                    std::string_view which(client.area_admin_input.data() + first_separator + 1,
                        second_separator - first_separator - 1);
                    if (which.size() != 1) {
                        throw std::invalid_argument("Choose S for the start or E for the end template.");
                    }
                    const char target = static_cast<char>(std::toupper(
                        static_cast<unsigned char>(which.front())));
                    if (target != 'S' && target != 'E') {
                        throw std::invalid_argument("Choose S for the start or E for the end template.");
                    }
                    const auto selected = std::find_if(client.board_areas.begin(), client.board_areas.end(),
                        [area_id](const BoardArea& area) { return area.id == area_id; });
                    if (selected == client.board_areas.end()) {
                        throw std::invalid_argument("Message area ID does not exist.");
                    }
                    const std::string text = client.area_admin_input.substr(second_separator + 1);
                    const std::string start = target == 'S' ? text : selected->quote_start;
                    const std::string end = target == 'E' ? text : selected->quote_end;
                    client.messages->set_area_quote_templates(area_id, start, end);
                    record_sysop_action(client, "updated message-area quote template",
                        std::to_string(area_id) + " " + selected->name + " " + target + "=" + text);
                    client.area_admin_notice = "Updated " + std::string(target == 'S' ? "start" : "end") +
                        " quote template for " + selected->name + ".";
                    client.editing_message_quote_templates = false;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_message_quote_templates = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Quote-template edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= 32 && byte < 127 && client.area_admin_input.size() < 128) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.editing_private_quote_templates) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t separator = client.area_admin_input.find(';');
                    if (separator == std::string::npos) {
                        throw std::invalid_argument("Use S;TEXT for the opening line or E;TEXT for the closing line.");
                    }
                    const char target = static_cast<char>(std::toupper(
                        static_cast<unsigned char>(client.area_admin_input.front())));
                    if (separator != 1 || (target != 'S' && target != 'E')) {
                        throw std::invalid_argument("Choose S for the start or E for the end template.");
                    }
                    MessageQuoteTemplates templates = client.messages->private_quote_templates();
                    const std::string text = client.area_admin_input.substr(separator + 1);
                    if (target == 'S') {
                        templates.start = text;
                    } else {
                        templates.end = text;
                    }
                    client.messages->set_private_quote_templates(templates.start, templates.end);
                    record_sysop_action(client, "updated private-mail quote template",
                        std::string(1, target) + "=" + text);
                    client.area_admin_notice = "Updated private-mail " +
                        std::string(target == 'S' ? "opening" : "closing") + " quote template.";
                    client.editing_private_quote_templates = false;
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_private_quote_templates = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Private quote-template edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= 32 && byte < 127 && client.area_admin_input.size() < 82) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.editing_file_area_access || client.editing_message_area_access) {
            const bool editing_message_access = client.editing_message_area_access;
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t first_separator = client.area_admin_input.find(';');
                    const std::size_t second_separator = first_separator == std::string::npos
                        ? std::string::npos
                        : client.area_admin_input.find(';', first_separator + 1);
                    const std::size_t third_separator = second_separator == std::string::npos
                        ? std::string::npos
                        : client.area_admin_input.find(';', second_separator + 1);
                    const std::size_t fourth_separator = third_separator == std::string::npos
                        ? std::string::npos
                        : client.area_admin_input.find(';', third_separator + 1);
                    const std::size_t fifth_separator = fourth_separator == std::string::npos
                        ? std::string::npos
                        : client.area_admin_input.find(';', fourth_separator + 1);
                    if (first_separator == std::string::npos || second_separator == std::string::npos ||
                        (editing_message_access && (third_separator == std::string::npos ||
                            fourth_separator == std::string::npos)) ||
                        (editing_message_access && fifth_separator != std::string::npos &&
                            client.area_admin_input.find(';', fifth_separator + 1) != std::string::npos) ||
                        (!editing_message_access && fourth_separator != std::string::npos)) {
                        throw std::invalid_argument(editing_message_access
                            ? "Use ID;access;post;MCI;SysOp[;anonymous mode], e.g. 2;S50;D20;F@;S255;Y"
                            : "Use ID;access ACS;download ACS[;upload ACS], e.g. 2;S50;D20;S20");
                    }
                    const std::string_view id_text(client.area_admin_input.data(), first_separator);
                    long long area_id{};
                    const auto parsed_id = std::from_chars(
                        id_text.data(), id_text.data() + id_text.size(), area_id);
                    if (id_text.empty() || parsed_id.ec != std::errc{} ||
                        parsed_id.ptr != id_text.data() + id_text.size() || area_id < 1 ||
                        (!editing_message_access && area_id > INT_MAX)) {
                        throw std::invalid_argument(editing_message_access
                            ? "Message-area ID must be a positive number"
                            : "File-area ID must be a positive number");
                    }
                    const auto expression = [&](std::size_t begin, std::size_t end) {
                        std::string value = client.area_admin_input.substr(begin, end - begin);
                        return value == "-" ? std::string{} : value;
                    };
                    const std::string access = expression(first_separator + 1, second_separator);
                    const std::string second_acs = editing_message_access
                        ? expression(second_separator + 1, third_separator)
                        : expression(second_separator + 1, third_separator == std::string::npos
                            ? client.area_admin_input.size() : third_separator);
                    if (editing_message_access) {
                        const std::string mci_acs = expression(third_separator + 1, fourth_separator);
                        const std::string sysop_acs = expression(fourth_separator + 1,
                            fifth_separator == std::string::npos ? client.area_admin_input.size() : fifth_separator);
                        std::optional<AnonymousMode> anonymous_mode;
                        std::string anonymous_mode_text;
                        if (fifth_separator != std::string::npos) {
                            anonymous_mode_text = client.area_admin_input.substr(fifth_separator + 1);
                            if (!anonymous_mode_text.empty() && anonymous_mode_text != "-") {
                                if (anonymous_mode_text.size() != 1) {
                                    throw std::invalid_argument("anonymous mode must be N, Y, F, D, or A");
                                }
                                switch (std::toupper(static_cast<unsigned char>(anonymous_mode_text.front()))) {
                                case 'N': anonymous_mode = AnonymousMode::Disabled; break;
                                case 'Y': anonymous_mode = AnonymousMode::Optional; break;
                                case 'F': anonymous_mode = AnonymousMode::Forced; break;
                                case 'D': anonymous_mode = AnonymousMode::DearAbby; break;
                                case 'A': anonymous_mode = AnonymousMode::AnyName; break;
                                default: throw std::invalid_argument("anonymous mode must be N, Y, F, D, or A");
                                }
                            }
                        }
                        const auto selected = std::find_if(client.board_areas.begin(), client.board_areas.end(),
                            [area_id](const BoardArea& area) { return area.id == area_id; });
                        if (selected == client.board_areas.end()) {
                            throw std::invalid_argument("Message area ID does not exist");
                        }
                        client.messages->set_area_access(area_id, access, second_acs, mci_acs, sysop_acs);
                        if (anonymous_mode.has_value()) {
                            client.messages->set_area_anonymous_mode(area_id, *anonymous_mode);
                        }
                        record_sysop_action(client, "updated message-area ACS",
                            std::to_string(area_id) + " " + selected->name + " ACS=" +
                                (access.empty() ? "*" : access) + " PostACS=" +
                                (second_acs.empty() ? "*" : second_acs) + " MCIACS=" +
                                (mci_acs.empty() ? "*" : mci_acs) + " SysOpACS=" +
                                (sysop_acs.empty() ? "*" : sysop_acs) +
                                (anonymous_mode.has_value() ? " Anonymous=" + anonymous_mode_text : std::string{}));
                        client.area_admin_notice = "Updated access rules for message area " +
                            std::to_string(area_id) + ".";
                        client.editing_message_area_access = false;
                    } else {
                        const int file_area_id = static_cast<int>(area_id);
                        const auto selected = std::find_if(client.file_areas.begin(), client.file_areas.end(),
                            [file_area_id](const FileAreaSummary& area) { return area.id == file_area_id; });
                        if (selected == client.file_areas.end()) {
                            throw std::invalid_argument("File area ID does not exist");
                        }
                        const std::string upload_acs = third_separator == std::string::npos
                            ? std::string{}
                            : expression(third_separator + 1, client.area_admin_input.size());
                        client.files->set_area_access(file_area_id, access, second_acs, upload_acs);
                        record_sysop_action(client, "updated file-area ACS",
                            std::to_string(file_area_id) + " " + selected->name + " ACS=" +
                                (access.empty() ? "*" : access) + " DLACS=" +
                                (second_acs.empty() ? "*" : second_acs) + " ULACS=" +
                                (upload_acs.empty() ? "*" : upload_acs));
                        client.area_admin_notice = "Updated access rules for file area " +
                            std::to_string(file_area_id) + ".";
                        client.editing_file_area_access = false;
                    }
                    client.area_admin_input.clear();
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.editing_file_area_access = false;
                client.editing_message_area_access = false;
                client.area_admin_input.clear();
                client.area_admin_notice = editing_message_access
                    ? "Message-area access edit cancelled."
                    : "File-area access edit cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= 32 && byte < 127 && client.area_admin_input.size() < 128) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        if (client.area_admin_kind.has_value() || client.area_admin_renaming_file ||
            client.area_admin_renaming_message) {
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::string name = client.area_admin_input;
                    if (client.area_admin_renaming_file || client.area_admin_renaming_message) {
                        const std::size_t separator = name.find('=');
                        if (separator == std::string::npos || separator == 0 || separator + 1 >= name.size()) {
                            throw std::invalid_argument("use ID=New area name, for example 2=Utilities");
                        }
                        std::size_t parsed = 0;
                        const long long parsed_id = std::stoll(name.substr(0, separator), &parsed);
                        if (parsed != separator || parsed_id < 1 ||
                            (client.area_admin_renaming_file && parsed_id > INT_MAX)) {
                            throw std::invalid_argument("area ID must be a positive number");
                        }
                        const std::string new_name = name.substr(separator + 1);
                        if (client.area_admin_renaming_file) {
                            const int area_id = static_cast<int>(parsed_id);
                            const auto selected = std::find_if(client.file_areas.begin(), client.file_areas.end(),
                                [area_id](const FileAreaSummary& area) { return area.id == area_id; });
                            if (selected == client.file_areas.end()) {
                                throw std::invalid_argument("file area ID does not exist");
                            }
                            const std::string old_name = selected->name;
                            client.files->rename_area(area_id, new_name);
                            record_sysop_action(client, "renamed file area",
                                std::to_string(area_id) + " " + old_name + " -> " + new_name);
                            client.area_admin_notice = "Renamed file area " + std::to_string(area_id) + ".";
                            std::clog << "SysOp " << client.handle << " renamed file area " << area_id
                                      << " from " << old_name << " to " << new_name << ".\n";
                        } else {
                            const auto selected = std::find_if(client.board_areas.begin(), client.board_areas.end(),
                                [parsed_id](const BoardArea& area) { return area.id == parsed_id; });
                            if (selected == client.board_areas.end()) {
                                throw std::invalid_argument("message area ID does not exist");
                            }
                            const std::string old_name = selected->name;
                            client.messages->rename_area(parsed_id, new_name);
                            record_sysop_action(client, "renamed message area",
                                std::to_string(parsed_id) + " " + old_name + " -> " + new_name);
                            client.area_admin_notice = "Renamed message area " + std::to_string(parsed_id) + ".";
                            std::clog << "SysOp " << client.handle << " renamed message area " << parsed_id
                                      << " from " << old_name << " to " << new_name << ".\n";
                        }
                    } else if (*client.area_admin_kind == ClientContext::AreaAdminKind::File) {
                        client.files->create_area(name);
                        record_sysop_action(client, "created file area", name);
                        client.area_admin_notice = "Created file area: " + name;
                        std::clog << "SysOp " << client.handle << " created file area " << name << ".\n";
                    } else {
                        client.messages->create_area(name);
                        record_sysop_action(client, "created message area", name);
                        client.area_admin_notice = "Created message area: " + name;
                        std::clog << "SysOp " << client.handle << " created message area " << name << ".\n";
                    }
                } catch (const std::exception& error) {
                    client.area_admin_notice = error.what();
                }
                client.area_admin_kind.reset();
                client.area_admin_renaming_file = false;
                client.area_admin_renaming_message = false;
                client.area_admin_input.clear();
                show_sysop_area_admin(client);
            } else if (character == 27) {
                client.area_admin_kind.reset();
                client.area_admin_renaming_file = false;
                client.area_admin_renaming_message = false;
                client.area_admin_input.clear();
                client.area_admin_notice = "Area operation cancelled.";
                show_sysop_area_admin(client);
            } else if (character == '\b' || character == 127) {
                if (!client.area_admin_input.empty()) {
                    client.area_admin_input.pop_back();
                    show_sysop_area_admin(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                const std::size_t input_limit =
                    client.area_admin_renaming_file || client.area_admin_renaming_message ? 80 : 48;
                if (byte >= 32 && byte != 127 && client.area_admin_input.size() < input_limit) {
                    client.area_admin_input.push_back(character);
                    show_sysop_area_admin(client);
                }
            }
            return;
        }

        const char area_command = static_cast<char>(
            std::toupper(static_cast<unsigned char>(character)));
        const auto begin_file_policy_edit = [&client](ClientContext::AdminPolicyEdit mode,
                                                       std::string_view notice) {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_message_force_read = false;
            client.editing_message_area_password = false;
            client.editing_message_taglines = false;
            client.editing_message_filter = false;
            client.editing_message_unhidden = false;
            client.editing_message_tearline = false;
            client.editing_message_origin = false;
            client.editing_message_real_names = false;
            client.editing_message_quote_templates = false;
            client.editing_private_quote_templates = false;
            client.editing_global_anonymous_acs = false;
            client.editing_global_post_acs = false;
            client.editing_global_post_limits = false;
            client.editing_global_credit_costs = false;
            client.editing_global_mail_limits = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.admin_policy_edit = mode;
            client.area_admin_input.clear();
            client.area_admin_notice = notice;
        };
        if (area_command == 'Q') {
            client.area_admin_notice.clear();
            show_sysop_accounts(client);
        } else if (area_command == 'R') {
            begin_file_policy_edit(ClientContext::AdminPolicyEdit::Ratios,
                "Set on|off;DLRatio;DLKRatio;NoDLRatio ACS. Use - for open ACS.");
            show_sysop_area_admin(client);
        } else if (area_command == '1') {
            begin_file_policy_edit(ClientContext::AdminPolicyEdit::LevelRatios,
                "Set SL_MIN;SL_MAX;DLRatio;DLKRatio, or SL_MIN;SL_MAX;global to inherit.");
            show_sysop_area_admin(client);
        } else if (area_command == '2') {
            begin_file_policy_edit(ClientContext::AdminPolicyEdit::DailyLimits,
                "Set DailyLimits;SL_MIN;SL_MAX;DLOneDay;DLKOneDay for the inclusive range.");
            show_sysop_area_admin(client);
        } else if (area_command == '3') {
            begin_file_policy_edit(ClientContext::AdminPolicyEdit::Points,
                "Set on|off;BASE_KIB;UPLOAD_COMP;REWARD_RATIO;NOFILECREDITS ACS; use - for no exemption.");
            show_sysop_area_admin(client);
        } else if (area_command == '4') {
            begin_file_policy_edit(ClientContext::AdminPolicyEdit::UploadValidation,
                "Set AUTO_VALIDATE_ACS;ValidateAllFiles on|off. Use - for open ACS.");
            show_sysop_area_admin(client);
        } else if (area_command == '5') {
            begin_file_policy_edit(ClientContext::AdminPolicyEdit::UnvalidatedAccess,
                "Set SeeUnVal ACS;DLUnVal ACS. Use - for open ACS.");
            show_sysop_area_admin(client);
        } else if (area_command == '6') {
            begin_file_policy_edit(ClientContext::AdminPolicyEdit::AreaNoRatio,
                "Set AREA_ID;on to exempt or AREA_ID;off to enforce file ratios.");
            show_sysop_area_admin(client);
        } else if (area_command == '7') {
            begin_file_policy_edit(ClientContext::AdminPolicyEdit::PostRatio,
                "Set minimum public posts per 100 logins for an inclusive security-level range.");
            show_sysop_area_admin(client);
        } else if (area_command == '8') {
            begin_file_policy_edit(ClientContext::AdminPolicyEdit::SubmissionAcs,
                "Set AddQuote and AddOneLiner rules; enter - for unrestricted access.");
            const auto settings = client.messages->submission_acs();
            client.area_admin_notice = "Current AddQuote;AddOneLiner ACS: " +
                (settings.first.empty() ? "-" : settings.first) + ";" +
                (settings.second.empty() ? "-" : settings.second);
            show_sysop_area_admin(client);
        } else if (area_command == '9') {
            begin_file_policy_edit(ClientContext::AdminPolicyEdit::InvisibleAcs,
                "Set the ACS callers must pass before toggling invisible mode.");
            const std::string settings = client.messages->invisibility_acs();
            client.area_admin_notice = "Current invisible-mode ACS: " +
                (settings.empty() ? "-" : settings);
            show_sysop_area_admin(client);
        } else if (area_command == '0') {
            begin_file_policy_edit(ClientContext::AdminPolicyEdit::ValidationEligibility,
                "Set whether the ! validation key is active and the NewSL threshold for ACS V.");
            const auto settings = client.messages->validation_eligibility();
            client.area_admin_notice = std::string("Current validation key: ") +
                (settings.first ? "on" : "off") + "; NewSL=" + std::to_string(settings.second);
            show_sysop_area_admin(client);
        } else if (area_command == 'C') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_message_area_access = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.editing_file_area_access = !client.file_areas.empty();
            client.area_admin_input.clear();
            client.area_admin_notice = client.file_areas.empty()
                ? "There are no file areas to configure."
                : "Enter ID;access ACS;download ACS[;upload ACS]. Blank or - means unrestricted.";
            show_sysop_area_admin(client);
        } else if (area_command == 'B') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.editing_message_area_access = !client.board_areas.empty();
            client.area_admin_input.clear();
            client.area_admin_notice = client.board_areas.empty()
                ? "There are no message areas to configure."
                : "Enter ID;access;post;MCI;SysOp[;N/Y/F/D/A]. Blank/- ACS passes for all callers.";
            show_sysop_area_admin(client);
        } else if (area_command == 'H') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_message_force_read = !client.board_areas.empty();
            client.editing_message_real_names = false;
            client.editing_message_quote_templates = false;
            client.editing_private_quote_templates = false;
            client.editing_global_anonymous_acs = false;
            client.editing_global_post_acs = false;
            client.editing_global_post_limits = false;
            client.editing_global_credit_costs = false;
            client.editing_global_mail_limits = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            client.area_admin_notice = client.board_areas.empty()
                ? "There are no message areas to configure."
                : "Enter AREA_ID;on or AREA_ID;off to set forced new scans.";
            show_sysop_area_admin(client);
        } else if (area_command == 'J') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_message_force_read = false;
            client.editing_message_real_names = false;
            client.editing_message_quote_templates = !client.board_areas.empty();
            client.editing_private_quote_templates = false;
            client.editing_global_anonymous_acs = false;
            client.editing_global_post_acs = false;
            client.editing_global_post_limits = false;
            client.editing_global_credit_costs = false;
            client.editing_global_mail_limits = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            client.area_admin_notice = client.board_areas.empty()
                ? "There are no message areas to configure."
                : "S=opening, E=closing; @F from, @T to, @D date, @S subject, @B area.";
            show_sysop_area_admin(client);
        } else if (area_command == 'I') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_message_force_read = false;
            client.editing_message_real_names = !client.board_areas.empty();
            client.editing_message_quote_templates = false;
            client.editing_private_quote_templates = false;
            client.editing_global_anonymous_acs = false;
            client.editing_global_post_acs = false;
            client.editing_global_post_limits = false;
            client.editing_global_credit_costs = false;
            client.editing_global_mail_limits = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            client.area_admin_notice = client.board_areas.empty()
                ? "There are no message areas to configure."
                : "Turn real-name searches on or off for one message area.";
            show_sysop_area_admin(client);
        } else if (area_command == 'O') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_message_force_read = false;
            client.editing_message_area_password = !client.board_areas.empty();
            client.editing_message_real_names = false;
            client.editing_message_quote_templates = false;
            client.editing_private_quote_templates = false;
            client.editing_global_anonymous_acs = false;
            client.editing_global_post_acs = false;
            client.editing_global_post_limits = false;
            client.editing_global_credit_costs = false;
            client.editing_global_mail_limits = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            client.area_admin_notice = client.board_areas.empty()
                ? "There are no message areas to configure."
                : "Set a shared password with AREA_ID;PASSWORD. Use - to clear; input is hidden.";
            show_sysop_area_admin(client);
        } else if (area_command == 'Y') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_message_force_read = false;
            client.editing_message_area_password = false;
            client.editing_message_taglines = !client.board_areas.empty();
            client.editing_message_filter = false;
            client.editing_message_real_names = false;
            client.editing_message_quote_templates = false;
            client.editing_private_quote_templates = false;
            client.editing_global_anonymous_acs = false;
            client.editing_global_post_acs = false;
            client.editing_global_post_limits = false;
            client.editing_global_credit_costs = false;
            client.editing_global_mail_limits = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            client.area_admin_notice = client.board_areas.empty()
                ? "There are no message areas to configure."
                : "Enter AREA_ID;on or AREA_ID;off to enable or disable the tagline prompt.";
            show_sysop_area_admin(client);
        } else if (area_command == 'T') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_message_force_read = false;
            client.editing_message_area_password = false;
            client.editing_message_taglines = false;
            client.editing_message_filter = !client.board_areas.empty();
            client.editing_message_real_names = false;
            client.editing_message_quote_templates = false;
            client.editing_private_quote_templates = false;
            client.editing_global_anonymous_acs = false;
            client.editing_global_post_acs = false;
            client.editing_global_post_limits = false;
            client.editing_global_credit_costs = false;
            client.editing_global_mail_limits = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            client.area_admin_notice = client.board_areas.empty()
                ? "There are no message areas to configure."
                : "Enter AREA_ID;on or AREA_ID;off to filter public message text.";
            show_sysop_area_admin(client);
        } else if (area_command == 'V') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_message_force_read = false;
            client.editing_message_area_password = false;
            client.editing_message_taglines = false;
            client.editing_message_filter = false;
            client.editing_message_unhidden = false;
            client.editing_message_tearline = !client.board_areas.empty();
            client.editing_message_real_names = false;
            client.editing_message_quote_templates = false;
            client.editing_private_quote_templates = false;
            client.editing_global_anonymous_acs = false;
            client.editing_global_post_acs = false;
            client.editing_global_post_limits = false;
            client.editing_global_credit_costs = false;
            client.editing_global_mail_limits = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            client.area_admin_notice = client.board_areas.empty()
                ? "There are no message areas to configure."
                : "Enter AREA_ID;on or AREA_ID;off to append Renegade tearline and origin text.";
            show_sysop_area_admin(client);
        } else if (area_command == 'Z') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_message_force_read = false;
            client.editing_message_area_password = false;
            client.editing_message_taglines = false;
            client.editing_message_filter = false;
            client.editing_message_unhidden = false;
            client.editing_message_tearline = false;
            client.editing_message_origin = !client.board_areas.empty();
            client.editing_message_real_names = false;
            client.editing_message_quote_templates = false;
            client.editing_private_quote_templates = false;
            client.editing_global_anonymous_acs = false;
            client.editing_global_post_acs = false;
            client.editing_global_post_limits = false;
            client.editing_global_credit_costs = false;
            client.editing_global_mail_limits = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            client.area_admin_notice = client.board_areas.empty()
                ? "There are no message areas to configure."
                : "Enter AREA_ID;ORIGIN;ZONE:NET/NODE.POINT; use - to clear a value.";
            show_sysop_area_admin(client);
        } else if (area_command == 'U') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_message_force_read = false;
            client.editing_message_area_password = false;
            client.editing_message_taglines = false;
            client.editing_message_filter = false;
            client.editing_message_unhidden = !client.board_areas.empty();
            client.editing_message_real_names = false;
            client.editing_message_quote_templates = false;
            client.editing_private_quote_templates = false;
            client.editing_global_anonymous_acs = false;
            client.editing_global_post_acs = false;
            client.editing_global_post_limits = false;
            client.editing_global_credit_costs = false;
            client.editing_global_mail_limits = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            client.area_admin_notice = client.board_areas.empty()
                ? "There are no message areas to configure."
                : "Enter AREA_ID;on or AREA_ID;off to list an area when ACS fails.";
            show_sysop_area_admin(client);
        } else if (area_command == 'P') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_message_force_read = false;
            client.editing_message_real_names = false;
            client.editing_message_quote_templates = false;
            client.editing_private_quote_templates = true;
            client.editing_global_anonymous_acs = false;
            client.editing_global_post_acs = false;
            client.editing_global_post_limits = false;
            client.editing_global_credit_costs = false;
            client.editing_global_mail_limits = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            client.area_admin_notice = "S=opening, E=closing; @F from, @T to, @D date, @S subject, @B Email.";
            show_sysop_area_admin(client);
        } else if (area_command == 'A') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_global_anonymous_acs = true;
            client.editing_global_post_acs = false;
            client.editing_global_post_limits = false;
            client.editing_global_credit_costs = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            const auto settings = client.messages->anonymous_acs();
            client.area_admin_notice = "Current PUBPOST;PUBREAD;PRIVPOST;PRIVREAD ACS: " +
                (settings.public_post.empty() ? "-" : settings.public_post) + ";" +
                (settings.public_read.empty() ? "-" : settings.public_read) + ";" +
                (settings.private_post.empty() ? "-" : settings.private_post) + ";" +
                (settings.private_read.empty() ? "-" : settings.private_read);
            show_sysop_area_admin(client);
        } else if (area_command == 'G') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_global_anonymous_acs = false;
            client.editing_global_post_acs = true;
            client.editing_global_post_limits = false;
            client.editing_global_credit_costs = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            const auto settings = client.messages->normal_post_acs();
            client.area_admin_notice = "Current NormPubPost;NormPrivPost ACS: " +
                (settings.first.empty() ? "-" : settings.first) + ";" +
                (settings.second.empty() ? "-" : settings.second);
            show_sysop_area_admin(client);
        } else if (area_command == 'L') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_global_anonymous_acs = false;
            client.editing_global_post_acs = false;
            client.editing_global_post_limits = true;
            client.editing_global_credit_costs = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            const MessagePostLimits limits = client.messages->post_limits();
            client.area_admin_notice = "Current MaxPubPost;MaxPrivPost per call: " +
                std::to_string(limits.public_per_call) + ";" + std::to_string(limits.private_per_call);
            show_sysop_area_admin(client);
        } else if (area_command == 'K') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_global_anonymous_acs = false;
            client.editing_global_post_acs = false;
            client.editing_global_post_limits = false;
            client.editing_global_credit_costs = true;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            const MessageCreditCosts costs = client.messages->credit_costs();
            client.area_admin_notice = "Current CreditPost;CreditEmail: " +
                std::to_string(costs.public_post) + ";" + std::to_string(costs.private_mail);
            show_sysop_area_admin(client);
        } else if (area_command == 'W') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.editing_file_area_access = false;
            client.editing_message_area_access = false;
            client.editing_global_anonymous_acs = false;
            client.editing_global_post_acs = false;
            client.editing_global_post_limits = false;
            client.editing_global_credit_costs = false;
            client.editing_global_mail_limits = true;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            const PrivateMailWaitingLimits limits = client.messages->private_mail_waiting_limits();
            client.area_admin_notice = "Current MaxWaiting;CSMaxWaiting: " +
                std::to_string(limits.normal_users) + ";" + std::to_string(limits.sysops);
            show_sysop_area_admin(client);
        } else if (area_command == 'M' || area_command == 'F') {
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_kind = area_command == 'F'
                ? ClientContext::AreaAdminKind::File
                : ClientContext::AreaAdminKind::Message;
            client.area_admin_input.clear();
            client.area_admin_notice.clear();
            show_sysop_area_admin(client);
        } else if (area_command == 'E') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = !client.file_areas.empty();
            client.area_admin_renaming_message = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            client.area_admin_notice = client.file_areas.empty()
                ? "There are no file areas to rename."
                : "Enter the displayed file-area ID, an equals sign, and the new name.";
            show_sysop_area_admin(client);
        } else if (area_command == 'N') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = !client.board_areas.empty();
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_input.clear();
            client.area_admin_notice = client.board_areas.empty()
                ? "There are no message areas to rename."
                : "Enter the displayed message-area ID, an equals sign, and the new name.";
            show_sysop_area_admin(client);
        } else if (area_command == 'D') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.area_admin_deleting_file = !client.file_areas.empty();
            client.area_admin_deleting_message = false;
            client.area_admin_confirming_message_deletion = false;
            client.area_admin_delete_id = 0;
            client.area_admin_delete_name.clear();
            client.area_admin_input.clear();
            client.area_admin_notice = client.file_areas.empty()
                ? "There are no file areas to delete."
                : "Enter a file-area ID; deletion requires a second confirmation.";
            show_sysop_area_admin(client);
        } else if (area_command == 'X') {
            client.area_admin_kind.reset();
            client.area_admin_renaming_file = false;
            client.area_admin_renaming_message = false;
            client.area_admin_deleting_file = false;
            client.area_admin_confirming_file_deletion = false;
            client.area_admin_deleting_message = !client.board_areas.empty();
            client.area_admin_delete_id = 0;
            client.area_admin_delete_name.clear();
            client.area_admin_input.clear();
            client.area_admin_notice = client.board_areas.empty()
                ? "There are no message areas to delete."
                : "Deleting a message area permanently removes all of its posts.";
            show_sysop_area_admin(client);
        }
        return;
    }

    if (client.viewing_sysop) {
        const char admin_command = static_cast<char>(
            std::toupper(static_cast<unsigned char>(character)));
        if (client.editing_sysop_profile) {
            if (!client.sysop_selected_index.has_value() ||
                *client.sysop_selected_index >= client.sysop_accounts.size()) {
                client.editing_sysop_profile = false;
                client.editing_sysop_profile_field = '\0';
                client.sysop_account_input.clear();
                show_sysop_accounts(client);
                return;
            }
            if (client.editing_sysop_profile_field != '\0') {
                const char field = client.editing_sysop_profile_field;
                if (character == '\r' || character == '\n') {
                    client.ignore_line_feed = character == '\r';
                    try {
                        const std::string handle =
                            client.sysop_accounts[*client.sysop_selected_index].handle;
                        if (field == 'W') {
                            if (client.sysop_account_input.size() < 12 ||
                                client.sysop_account_input.size() > 128) {
                                throw std::invalid_argument("Password must be 12-128 characters.");
                            }
                            const AccountProfile account_profile = client.accounts->profile(handle);
                            if (client.sysop_account_input == handle ||
                                client.sysop_account_input == account_profile.real_name) {
                                throw std::invalid_argument("Password cannot be the handle or real name.");
                            }
                            if (client.accounts->verify_password(handle, client.sysop_account_input)) {
                                throw std::invalid_argument("New password must differ from the current password.");
                            }
                            client.sysop_password_new = client.sysop_account_input;
                            client.editing_sysop_profile_field = 'w';
                            client.sysop_account_input.clear();
                            show_sysop_account_review(client);
                            return;
                        }
                        if (field == 'w') {
                            if (client.sysop_account_input != client.sysop_password_new) {
                                client.sysop_password_new.clear();
                                client.sysop_account_input.clear();
                                client.editing_sysop_profile_field = 'W';
                                (void)write_channel(client, "\r\nPasswords do not match; enter the new password again.\r\n");
                                show_sysop_account_review(client);
                                return;
                            }
                            client.accounts->set_password(handle, client.sysop_password_new);
                            record_sysop_action(client, "reset account password", handle);
                            client.sysop_password_new.clear();
                            client.editing_sysop_profile_field = '\0';
                            client.sysop_account_input.clear();
                            show_sysop_account_review(client);
                            (void)write_channel(client, "\r\nAccount password reset.\r\n");
                            return;
                        }
                        if (field == 'F') {
                            client.accounts->set_forgot_password_answer(
                                handle, client.sysop_account_input);
                        } else {
                            AccountProfile updated = client.accounts->profile(handle);
                            switch (field) {
                            case 'R': updated.real_name = client.sysop_account_input; break;
                            case 'C': updated.country = client.sysop_account_input; break;
                            case 'A': updated.street = client.sysop_account_input; break;
                            case 'L':
                                updated.city_state = client.sysop_account_input;
                                updated.location = client.sysop_account_input;
                                break;
                            case 'Z': updated.postal_code = client.sysop_account_input; break;
                            case 'P': updated.phone = client.sysop_account_input; break;
                            case 'D': updated.birth_date = client.sysop_account_input; break;
                            case 'G': updated.sex = client.sysop_account_input.empty()
                                ? '\0' : client.sysop_account_input.front(); break;
                            case 'S': updated.signature = client.sysop_account_input; break;
                            case '1': updated.user_answers[0] = client.sysop_account_input; break;
                            case '2': updated.user_answers[1] = client.sysop_account_input; break;
                            case '3': updated.user_answers[2] = client.sysop_account_input; break;
                            default: throw std::invalid_argument("unknown profile field");
                            }
                            client.accounts->update_profile(updated);
                        }
                        static constexpr std::array<std::pair<char, std::string_view>, 13> field_names{{
                            {'R', "real name"}, {'C', "country"}, {'A', "street address"},
                            {'L', "city and state"}, {'Z', "postal code"}, {'P', "phone"},
                            {'D', "birth date"}, {'G', "gender"}, {'S', "signature"},
                            {'1', "SysOp answer 1"}, {'2', "SysOp answer 2"},
                            {'3', "SysOp answer 3"}, {'F', "recovery answer"},
                        }};
                        const auto field_name = std::find_if(field_names.begin(), field_names.end(),
                            [field](const auto& item) { return item.first == field; });
                        record_sysop_action(client, "updated account profile",
                            handle + " " + std::string(field_name->second));
                        client.sysop_accounts = client.accounts->list_accounts();
                        const auto selected = std::find_if(client.sysop_accounts.begin(),
                            client.sysop_accounts.end(), [&handle](const AccountSummary& account) {
                                return account.handle == handle;
                            });
                        if (selected == client.sysop_accounts.end()) {
                            throw std::runtime_error("updated account disappeared from the account list");
                        }
                        client.sysop_selected_index = static_cast<std::size_t>(
                            std::distance(client.sysop_accounts.begin(), selected));
                        client.editing_sysop_profile_field = '\0';
                        client.sysop_account_input.clear();
                        show_sysop_account_review(client);
                    } catch (const std::exception& error) {
                        (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                        if (field == 'w') {
                            client.sysop_password_new.clear();
                            client.editing_sysop_profile_field = 'W';
                        }
                        client.sysop_account_input.clear();
                        show_sysop_account_review(client);
                    }
                } else if (character == 27) {
                    if (field == 'W' || field == 'w') {
                        client.sysop_password_new.clear();
                    }
                    client.editing_sysop_profile_field = '\0';
                    client.sysop_account_input.clear();
                    show_sysop_account_review(client);
                } else if (character == '\b' || character == 127) {
                    if (!client.sysop_account_input.empty()) {
                        client.sysop_account_input.pop_back();
                        show_sysop_account_review(client);
                    }
                } else {
                    const std::size_t maximum = field == 'W' || field == 'w' ? 128 :
                        field == 'R' ? 48 : field == 'C' ? 16 :
                        field == 'A' || field == 'L' ? 30 : field == 'Z' ? 10 :
                        field == 'P' ? 12 : field == 'D' ? 10 : field == 'G' ? 1 :
                        field == 'S' ? 80 : field == 'F' ? 40 : 35;
                    const unsigned char byte = static_cast<unsigned char>(character);
                    if (byte >= 32 && byte < 127 && client.sysop_account_input.size() < maximum) {
                        client.sysop_account_input.push_back(field == 'G'
                            ? static_cast<char>(std::toupper(byte)) : character);
                        show_sysop_account_review(client);
                    }
                }
                return;
            }
            if (admin_command == 'Q' || character == 27) {
                client.editing_sysop_profile = false;
                show_sysop_account_review(client);
            } else if (admin_command == 'R' || admin_command == 'C' || admin_command == 'A' ||
                admin_command == 'L' || admin_command == 'Z' || admin_command == 'P' ||
                admin_command == 'D' || admin_command == 'G' || admin_command == 'S' ||
                admin_command == 'F' || admin_command == 'W' ||
                (character >= '1' && character <= '3')) {
                client.editing_sysop_profile_field = admin_command;
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else {
                (void)write_channel(client, "\a");
            }
            return;
        }
        if (client.editing_sysop_short_message) {
            if (!client.sysop_selected_index.has_value() ||
                *client.sysop_selected_index >= client.sysop_accounts.size()) {
                client.editing_sysop_short_message = false;
                client.sysop_account_input.clear();
                show_sysop_accounts(client);
                return;
            }
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    if (client.sysop_account_input.empty()) {
                        throw std::invalid_argument("Enter a message from 1 to 80 characters.");
                    }
                    if (client.community == nullptr) {
                        throw std::runtime_error("short-message storage is unavailable");
                    }
                    const std::string handle =
                        client.sysop_accounts[*client.sysop_selected_index].handle;
                    client.community->send_short_message(handle, client.sysop_account_input, true);
                    record_sysop_action(client, "queued short message", handle);
                    std::clog << "SysOp " << client.handle << " queued a short message for "
                              << handle << ".\n";
                    client.editing_sysop_short_message = false;
                    client.sysop_account_input.clear();
                    show_sysop_account_review(client);
                    (void)write_channel(client, "\r\nShort message queued for " + handle + ".\r\n");
                } catch (const std::exception& error) {
                    (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                    client.sysop_account_input.clear();
                    show_sysop_account_review(client);
                }
            } else if (character == 27) {
                client.editing_sysop_short_message = false;
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (character == '\b' || character == 127) {
                if (!client.sysop_account_input.empty()) {
                    client.sysop_account_input.pop_back();
                    show_sysop_account_review(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= 32 && byte < 127 && client.sysop_account_input.size() < 80) {
                    client.sysop_account_input.push_back(character);
                    show_sysop_account_review(client);
                }
            }
            return;
        }
        if (client.viewing_validation_admin) {
            if (client.validation_admin_operation != '\0') {
                if (character == '\r' || character == '\n') {
                    client.ignore_line_feed = character == '\r';
                    try {
                        if (client.validation_admin_operation == 'S') {
                            const ValidationLevel level = parse_validation_admin_record(
                                client.validation_admin_input);
                            client.accounts->set_validation_level(level);
                            record_sysop_action(client, "saved validation level",
                                std::string(1, level.key) + " " + level.description);
                            client.validation_admin_notice = "Saved validation level " +
                                std::string(1, level.key) + ".";
                        } else if (client.validation_admin_operation == 'D') {
                            if (client.validation_admin_input.size() != 1) {
                                throw std::invalid_argument("Enter one validation key to delete.");
                            }
                            const char key = client.validation_admin_input.front();
                            client.accounts->delete_validation_level(key);
                            record_sysop_action(client, "deleted validation level", std::string(1, key));
                            client.validation_admin_notice = "Deleted validation level " +
                                std::string(1, key) + ".";
                        } else {
                            if (client.validation_admin_input.size() != 1) {
                                throw std::invalid_argument("Enter one validation key to edit.");
                            }
                            const char key = client.validation_admin_input.front();
                            const auto level = std::find_if(client.validation_levels.begin(),
                                client.validation_levels.end(),
                                [key](const ValidationLevel& item) { return item.key == key; });
                            if (level == client.validation_levels.end()) {
                                throw std::invalid_argument("validation level does not exist");
                            }
                            client.validation_admin_selection_index = static_cast<std::size_t>(
                                std::distance(client.validation_levels.begin(), level));
                            client.validation_admin_page = client.validation_admin_selection_index / 10;
                            client.validation_admin_input = format_validation_admin_record(*level);
                            client.validation_admin_operation = 'S';
                            client.validation_admin_notice = "Edit the record fields, then press Enter to save.";
                            show_validation_level_admin(client);
                            return;
                        }
                        client.validation_admin_operation = '\0';
                        client.validation_admin_input.clear();
                    } catch (const std::exception& error) {
                        client.validation_admin_notice = error.what();
                    }
                    show_validation_level_admin(client);
                } else if (character == 27) {
                    client.validation_admin_operation = '\0';
                    client.validation_admin_input.clear();
                    client.validation_admin_notice = "Validation-level edit cancelled.";
                    show_validation_level_admin(client);
                } else if (character == '\b' || character == 127) {
                    if (!client.validation_admin_input.empty()) {
                        client.validation_admin_input.pop_back();
                        show_validation_level_admin(client);
                    }
                } else {
                    const unsigned char byte = static_cast<unsigned char>(character);
                    if (byte >= 32 && byte < 127 && client.validation_admin_input.size() < 400) {
                        client.validation_admin_input.push_back(character);
                        show_validation_level_admin(client);
                    }
                }
            } else if (admin_command == 'Q') {
                client.validation_admin_notice.clear();
                show_sysop_accounts(client);
            } else if (admin_command == 'N' &&
                client.validation_admin_page + 1 < (client.validation_levels.size() + 9) / 10) {
                ++client.validation_admin_page;
                client.validation_admin_selection_index = client.validation_admin_page * 10;
                show_validation_level_admin(client);
            } else if (admin_command == 'P' && client.validation_admin_page > 0) {
                --client.validation_admin_page;
                client.validation_admin_selection_index = client.validation_admin_page * 10;
                show_validation_level_admin(client);
            } else if (admin_command == 'R') {
                show_validation_level_admin(client);
            } else if (admin_command == 'S') {
                client.validation_admin_operation = 'S';
                client.validation_admin_input.clear();
                client.validation_admin_notice =
                    "Enter a source validation record; use hyphens for blank fields.";
                show_validation_level_admin(client);
            } else if (admin_command == 'D') {
                client.validation_admin_operation = 'D';
                client.validation_admin_input.clear();
                client.validation_admin_notice = "Referenced expire-to levels cannot be deleted.";
                show_validation_level_admin(client);
            } else if (admin_command == 'E') {
                client.validation_admin_operation = 'E';
                client.validation_admin_input.clear();
                client.validation_admin_notice = "Edit a level by its one-character key.";
                show_validation_level_admin(client);
            } else {
                (void)write_channel(client, "\a");
            }
        } else if (client.viewing_signup_question_admin) {
            if (client.editing_custom_user_question == -1) {
                if (character == '\r' || character == '\n') {
                    client.ignore_line_feed = character == '\r';
                    client.editing_custom_user_question = static_cast<int>(
                        std::min<std::size_t>(client.signup_question_prompt_selection_index, 2) + 1);
                    client.custom_user_question_input.clear();
                    show_signup_question_admin(client);
                } else if (character == '1' || character == '2' || character == '3') {
                    client.signup_question_prompt_selection_index = static_cast<std::size_t>(character - '1');
                    client.editing_custom_user_question = character - '0';
                    client.custom_user_question_input.clear();
                    show_signup_question_admin(client);
                } else if (character == 27 || admin_command == 'Q') {
                    client.editing_custom_user_question = 0;
                    client.custom_user_question_input.clear();
                    show_signup_question_admin(client);
                } else {
                    (void)write_channel(client, "\a");
                }
            } else if (client.editing_custom_user_question >= 1 &&
                client.editing_custom_user_question <= 3) {
                if (character == '\r' || character == '\n') {
                    client.ignore_line_feed = character == '\r';
                    try {
                        client.accounts->set_custom_user_question(
                            client.editing_custom_user_question, client.custom_user_question_input);
                        record_sysop_action(client, "changed custom signup question prompt",
                            "question " + std::to_string(client.editing_custom_user_question));
                        client.editing_custom_user_question = 0;
                        client.custom_user_question_input.clear();
                        show_signup_question_admin(client);
                    } catch (const std::exception& error) {
                        (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                        client.custom_user_question_input.clear();
                        show_signup_question_admin(client);
                    }
                } else if (character == 27) {
                    client.editing_custom_user_question = -1;
                    client.custom_user_question_input.clear();
                    show_signup_question_admin(client);
                } else if (character == '\b' || character == 127) {
                    if (!client.custom_user_question_input.empty()) {
                        client.custom_user_question_input.pop_back();
                        show_signup_question_admin(client);
                    }
                } else {
                    const unsigned char byte = static_cast<unsigned char>(character);
                    if (byte >= 32 && byte < 127 && client.custom_user_question_input.size() < 70) {
                        client.custom_user_question_input.push_back(character);
                        show_signup_question_admin(client);
                    }
                }
            } else if (admin_command == 'Q') {
                show_sysop_accounts(client);
            } else if (admin_command == 'N' && !client.signup_preferences_page) {
                client.signup_preferences_page = true;
                client.signup_question_selection_index = 0;
                show_signup_question_admin(client);
            } else if (admin_command == 'P' && client.signup_preferences_page) {
                client.signup_preferences_page = false;
                client.signup_question_selection_index = 0;
                show_signup_question_admin(client);
            } else if (admin_command == 'P' && !client.signup_preferences_page) {
                client.editing_custom_user_question = -1;
                client.signup_question_prompt_selection_index = 0;
                client.custom_user_question_input.clear();
                show_signup_question_admin(client);
            } else {
                int source_id = 0;
                if (client.signup_preferences_page) {
                    switch (admin_command) {
                    case 'O': source_id = 16; break;
                    case 'S': source_id = 19; break;
                    case 'T': source_id = 20; break;
                    case 'U': source_id = 21; break;
                    case 'V': source_id = 22; break;
                    case 'Y': source_id = 25; break;
                    default: break;
                    }
                } else {
                    switch (admin_command) {
                    case 'B': source_id = 2; break;
                    case 'C': source_id = 3; break;
                    case 'D': source_id = 4; break;
                    case 'E': source_id = 5; break;
                    case 'F': source_id = 6; break;
                    case 'G': source_id = 7; break;
                    case 'H': source_id = 8; break;
                    case 'I': source_id = 9; break;
                    case 'J': source_id = 10; break;
                    case 'K': source_id = 11; break;
                    case 'L': source_id = 12; break;
                    case 'M': source_id = 14; break;
                    default: break;
                    }
                }
                if (source_id == 0) {
                    (void)write_channel(client, "\a");
                } else {
                    try {
                        const auto enabled = client.accounts->signup_question_states();
                        const bool new_state = !enabled[static_cast<std::size_t>(source_id)];
                        client.accounts->set_signup_question_enabled(source_id, new_state);
                        record_sysop_action(client, "changed signup question",
                            std::to_string(source_id) + (new_state ? " on" : " off"));
                        show_signup_question_admin(client);
                    } catch (const std::exception& error) {
                        std::cerr << "Could not change signup question: " << error.what() << '\n';
                        (void)write_channel(client, "\r\nCould not change that signup question.\r\n");
                        show_signup_question_admin(client);
                    }
                }
            }
            return;
        }
        if (client.viewing_sysop_audit) {
            const std::size_t pages = client.sysop_audit.page_count;
            if (admin_command == 'Q') {
                show_sysop_accounts(client);
            } else if (admin_command == 'R') {
                show_sysop_audit(client);
            } else if (admin_command == 'N' && client.sysop_audit_page > 0) {
                --client.sysop_audit_page;
                show_sysop_audit(client);
            } else if (admin_command == 'P' && client.sysop_audit_page + 1 < pages) {
                ++client.sysop_audit_page;
                show_sysop_audit(client);
            }
            return;
        }
        if (client.editing_sysop_validation_level) {
            if (!client.sysop_selected_index.has_value() ||
                *client.sysop_selected_index >= client.sysop_accounts.size()) {
                client.editing_sysop_validation_level = false;
                client.confirming_sysop_validation = false;
                client.pending_sysop_validation.reset();
                client.sysop_account_input.clear();
                show_sysop_accounts(client);
                return;
            }
            if (client.confirming_sysop_validation) {
                const char confirmation = static_cast<char>(
                    std::toupper(static_cast<unsigned char>(character)));
                if (confirmation == 'Y' && client.pending_sysop_validation.has_value()) {
                    try {
                        const std::string handle = client.sysop_accounts[*client.sysop_selected_index].handle;
                        const ValidationLevel level = *client.pending_sysop_validation;
                        client.accounts->apply_validation_level(handle, level.key);
                        if (!level.user_message.empty() && client.community != nullptr) {
                            try {
                                client.community->send_short_message(handle, level.user_message, true);
                            } catch (const std::exception& error) {
                                std::cerr << "Could not queue validation message for " << handle << ": "
                                          << error.what() << '\n';
                            }
                        }
                        record_sysop_action(client, "validated account",
                            handle + " key=" + std::string(1, level.key));
                        client.sysop_accounts = client.accounts->list_accounts();
                        const auto selected = std::find_if(client.sysop_accounts.begin(), client.sysop_accounts.end(),
                            [&handle](const AccountSummary& account) { return account.handle == handle; });
                        if (selected == client.sysop_accounts.end()) {
                            throw std::runtime_error("updated account disappeared from the account list");
                        }
                        client.sysop_selected_index = static_cast<std::size_t>(
                            std::distance(client.sysop_accounts.begin(), selected));
                        client.editing_sysop_validation_level = false;
                        client.confirming_sysop_validation = false;
                        client.pending_sysop_validation.reset();
                        client.sysop_account_input.clear();
                        show_sysop_account_review(client);
                        (void)write_channel(client, "\r\nValidation applied to " + handle + ".\r\n");
                    } catch (const std::exception& error) {
                        (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                        client.editing_sysop_validation_level = false;
                        client.confirming_sysop_validation = false;
                        client.pending_sysop_validation.reset();
                        client.sysop_account_input.clear();
                        show_sysop_account_review(client);
                    }
                } else if (confirmation == 'N' || character == 27) {
                    client.editing_sysop_validation_level = false;
                    client.confirming_sysop_validation = false;
                    client.pending_sysop_validation.reset();
                    client.sysop_account_input.clear();
                    show_sysop_account_review(client);
                } else {
                    (void)write_channel(client, "\a");
                }
                return;
            }
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    if (client.sysop_account_input.size() != 1) {
                        throw std::invalid_argument("Enter one validation key.");
                    }
                    const std::string handle = client.sysop_accounts[*client.sysop_selected_index].handle;
                    const char key = client.sysop_account_input.front();
                    const auto validation_levels = client.accounts->validation_levels();
                    const auto level = std::find_if(validation_levels.begin(), validation_levels.end(),
                        [key](const ValidationLevel& item) { return item.key == key; });
                    if (level == validation_levels.end()) {
                        throw std::invalid_argument("validation level does not exist");
                    }
                    const AccountSummary& account = client.sysop_accounts[*client.sysop_selected_index];
                    const std::string new_ar = validation_preview_flags(
                        account.acs_ar_flags, level->ar_flags, level->soft_ar_flags);
                    const std::string new_ac = validation_preview_flags(
                        account.acs_ac_flags, level->ac_flags, level->soft_ac_flags);
                    if (account.subscription_key == key && account.security_level == level->security_level &&
                        account.download_security_level == level->download_security_level &&
                        account.acs_ar_flags == new_ar && account.acs_ac_flags == new_ac) {
                        throw std::invalid_argument("This account is already validated at that level.");
                    }
                    const std::int64_t new_credits = account.credits + level->credits;
                    const std::int64_t new_file_points = account.file_points + level->file_points;
                    if (new_credits < std::numeric_limits<std::int32_t>::min() ||
                        new_credits > std::numeric_limits<std::int32_t>::max() || new_file_points < 0 ||
                        new_file_points > std::numeric_limits<std::int32_t>::max()) {
                        throw std::invalid_argument("Validation awards exceed the account balance range.");
                    }
                    client.pending_sysop_validation = *level;
                    client.confirming_sysop_validation = true;
                    client.sysop_account_input.assign(1, key);
                    show_sysop_account_review(client);
                } catch (const std::exception& error) {
                    (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                    client.editing_sysop_validation_level = false;
                    client.confirming_sysop_validation = false;
                    client.pending_sysop_validation.reset();
                    client.sysop_account_input.clear();
                    show_sysop_account_review(client);
                }
            } else if (character == 27) {
                client.editing_sysop_validation_level = false;
                client.confirming_sysop_validation = false;
                client.pending_sysop_validation.reset();
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (character == '\b' || character == 127) {
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (static_cast<unsigned char>(character) >= 32 &&
                static_cast<unsigned char>(character) < 127) {
                client.sysop_account_input.assign(1, character);
                show_sysop_account_review(client);
            }
            return;
        }
        if (client.editing_sysop_birth_date || client.editing_sysop_sex ||
            client.editing_sysop_expiration_date) {
            const bool editing_birth_date = client.editing_sysop_birth_date;
            const bool editing_expiration_date = client.editing_sysop_expiration_date;
            if (!client.sysop_selected_index.has_value() ||
                *client.sysop_selected_index >= client.sysop_accounts.size()) {
                client.editing_sysop_birth_date = false;
                client.editing_sysop_sex = false;
                client.editing_sysop_expiration_date = false;
                client.sysop_account_input.clear();
                show_sysop_accounts(client);
                return;
            }
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::string handle = client.sysop_accounts[*client.sysop_selected_index].handle;
                    AccountProfile updated = client.accounts->profile(handle);
                    if (editing_birth_date) {
                        updated.birth_date = client.sysop_account_input;
                    } else if (editing_expiration_date) {
                        updated.expiration_date = client.sysop_account_input;
                    } else {
                        updated.sex = client.sysop_account_input.empty()
                            ? '\0' : client.sysop_account_input.front();
                    }
                    client.accounts->update_profile(updated);
                    record_sysop_action(client,
                        editing_birth_date ? "updated account birth date" :
                            (editing_expiration_date ? "updated account expiration" : "updated account gender"),
                        handle);
                    client.sysop_accounts = client.accounts->list_accounts();
                    const auto selected = std::find_if(client.sysop_accounts.begin(), client.sysop_accounts.end(),
                        [&handle](const AccountSummary& account) { return account.handle == handle; });
                    if (selected == client.sysop_accounts.end()) {
                        throw std::runtime_error("updated account disappeared from the account list");
                    }
                    client.sysop_selected_index = static_cast<std::size_t>(
                        std::distance(client.sysop_accounts.begin(), selected));
                    client.editing_sysop_birth_date = false;
                    client.editing_sysop_sex = false;
                    client.editing_sysop_expiration_date = false;
                    client.sysop_account_input.clear();
                    show_sysop_account_review(client);
                } catch (const std::exception& error) {
                    (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                    show_sysop_account_review(client);
                }
            } else if (character == 27) {
                client.editing_sysop_birth_date = false;
                client.editing_sysop_sex = false;
                client.editing_sysop_expiration_date = false;
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (character == '\b' || character == 127) {
                if (!client.sysop_account_input.empty()) {
                    client.sysop_account_input.pop_back();
                    show_sysop_account_review(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                const std::size_t limit = editing_birth_date || editing_expiration_date ? 10 : 1;
                if (byte >= 32 && byte < 127 && client.sysop_account_input.size() < limit) {
                    const char accepted = editing_birth_date || editing_expiration_date
                        ? character : static_cast<char>(std::toupper(byte));
                    client.sysop_account_input.push_back(accepted);
                    show_sysop_account_review(client);
                }
            }
            return;
        }
        if (client.editing_sysop_credits || client.editing_sysop_file_points) {
            const bool editing_file_points = client.editing_sysop_file_points;
            if (!client.sysop_selected_index.has_value() ||
                *client.sysop_selected_index >= client.sysop_accounts.size()) {
                client.editing_sysop_credits = false;
                client.editing_sysop_file_points = false;
                client.sysop_account_input.clear();
                show_sysop_accounts(client);
                return;
            }
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::string_view input(client.sysop_account_input);
                    std::int64_t balance{};
                    const auto parsed = std::from_chars(input.data(), input.data() + input.size(), balance);
                    if (input.empty() || parsed.ec != std::errc{} || parsed.ptr != input.data() + input.size()) {
                        throw std::invalid_argument(editing_file_points
                            ? "Enter a whole-number file-point balance."
                            : "Enter a signed whole-number credit balance.");
                    }
                    const std::string handle = client.sysop_accounts[*client.sysop_selected_index].handle;
                    if (editing_file_points) {
                        client.accounts->set_file_points(handle, balance);
                    } else {
                        client.accounts->set_credits(handle, balance);
                    }
                    record_sysop_action(client,
                        editing_file_points ? "updated account file points" : "updated account credits",
                        handle + " balance=" + std::to_string(balance));
                    client.sysop_accounts = client.accounts->list_accounts();
                    const auto selected = std::find_if(client.sysop_accounts.begin(), client.sysop_accounts.end(),
                        [&handle](const AccountSummary& account) { return account.handle == handle; });
                    if (selected == client.sysop_accounts.end()) {
                        throw std::runtime_error("updated account disappeared from the account list");
                    }
                    client.sysop_selected_index = static_cast<std::size_t>(
                        std::distance(client.sysop_accounts.begin(), selected));
                    client.editing_sysop_credits = false;
                    client.editing_sysop_file_points = false;
                    client.sysop_account_input.clear();
                    show_sysop_account_review(client);
                } catch (const std::exception& error) {
                    (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                    show_sysop_account_review(client);
                }
            } else if (character == 27) {
                client.editing_sysop_credits = false;
                client.editing_sysop_file_points = false;
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (character == '\b' || character == 127) {
                if (!client.sysop_account_input.empty()) {
                    client.sysop_account_input.pop_back();
                    show_sysop_account_review(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                const bool sign_allowed = !editing_file_points && byte == '-' && client.sysop_account_input.empty();
                if (((byte >= '0' && byte <= '9') || sign_allowed) &&
                    client.sysop_account_input.size() < (editing_file_points ? 10U : 11U)) {
                    client.sysop_account_input.push_back(character);
                    show_sysop_account_review(client);
                }
            }
            return;
        }
        if (client.editing_sysop_acs_flags) {
            if (!client.sysop_selected_index.has_value() ||
                *client.sysop_selected_index >= client.sysop_accounts.size()) {
                client.editing_sysop_acs_flags = false;
                client.sysop_account_input.clear();
                show_sysop_accounts(client);
                return;
            }
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t separator = client.sysop_account_input.find('/');
                    if (separator == std::string::npos ||
                        client.sysop_account_input.find('/', separator + 1) != std::string::npos) {
                        throw std::invalid_argument("Enter ACS flags as AR/AC, for example AB/EP");
                    }
                    std::string ar_flags = client.sysop_account_input.substr(0, separator);
                    std::string ac_flags = client.sysop_account_input.substr(separator + 1);
                    if (ar_flags == "-") ar_flags.clear();
                    if (ac_flags == "-") ac_flags.clear();
                    const std::string handle = client.sysop_accounts[*client.sysop_selected_index].handle;
                    client.accounts->set_acs_flags(handle, ar_flags, ac_flags);
                    record_sysop_action(client, "updated account ACS flags",
                        handle + " AR=" + (ar_flags.empty() ? "-" : ar_flags) +
                            " AC=" + (ac_flags.empty() ? "-" : ac_flags));
                    client.sysop_accounts = client.accounts->list_accounts();
                    const auto selected = std::find_if(client.sysop_accounts.begin(), client.sysop_accounts.end(),
                        [&handle](const AccountSummary& account) { return account.handle == handle; });
                    if (selected == client.sysop_accounts.end()) {
                        throw std::runtime_error("updated account disappeared from the account list");
                    }
                    client.sysop_selected_index = static_cast<std::size_t>(
                        std::distance(client.sysop_accounts.begin(), selected));
                    client.editing_sysop_acs_flags = false;
                    client.sysop_account_input.clear();
                    show_sysop_account_review(client);
                } catch (const std::exception& error) {
                    (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                    show_sysop_account_review(client);
                }
            } else if (character == 27) {
                client.editing_sysop_acs_flags = false;
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (character == '\b' || character == 127) {
                if (!client.sysop_account_input.empty()) {
                    client.sysop_account_input.pop_back();
                    show_sysop_account_review(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if (byte >= 32 && byte < 127 && client.sysop_account_input.size() < 44) {
                    client.sysop_account_input.push_back(character);
                    show_sysop_account_review(client);
                }
            }
            return;
        }
        if (client.editing_sysop_security_levels) {
            if (!client.sysop_selected_index.has_value() ||
                *client.sysop_selected_index >= client.sysop_accounts.size()) {
                client.editing_sysop_security_levels = false;
                client.sysop_account_input.clear();
                show_sysop_accounts(client);
                return;
            }
            if (character == '\r' || character == '\n') {
                client.ignore_line_feed = character == '\r';
                try {
                    const std::size_t separator = client.sysop_account_input.find(',');
                    if (separator == std::string::npos ||
                        client.sysop_account_input.find(',', separator + 1) != std::string::npos) {
                        throw std::invalid_argument("Enter security levels as SL,DSL, for example 50,20");
                    }
                    const auto parse_level = [&](std::string_view value) {
                        int level{};
                        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), level);
                        if (value.empty() || parsed.ec != std::errc{} ||
                            parsed.ptr != value.data() + value.size() || level < 0 || level > 255) {
                            throw std::invalid_argument("Security levels must be numbers from 0 to 255");
                        }
                        return level;
                    };
                    const std::string_view input(client.sysop_account_input);
                    const int security_level = parse_level(input.substr(0, separator));
                    const int download_security_level = parse_level(input.substr(separator + 1));
                    const std::string handle = client.sysop_accounts[*client.sysop_selected_index].handle;
                    client.accounts->set_security_levels(handle, security_level, download_security_level);
                    record_sysop_action(client, "updated account security levels",
                        handle + " SL=" + std::to_string(security_level) +
                            " DSL=" + std::to_string(download_security_level));
                    client.sysop_accounts = client.accounts->list_accounts();
                    const auto selected = std::find_if(client.sysop_accounts.begin(), client.sysop_accounts.end(),
                        [&handle](const AccountSummary& account) { return account.handle == handle; });
                    if (selected == client.sysop_accounts.end()) {
                        throw std::runtime_error("updated account disappeared from the account list");
                    }
                    client.sysop_selected_index = static_cast<std::size_t>(
                        std::distance(client.sysop_accounts.begin(), selected));
                    client.editing_sysop_security_levels = false;
                    client.sysop_account_input.clear();
                    show_sysop_account_review(client);
                } catch (const std::exception& error) {
                    (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                    show_sysop_account_review(client);
                }
            } else if (character == 27) {
                client.editing_sysop_security_levels = false;
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (character == '\b' || character == 127) {
                if (!client.sysop_account_input.empty()) {
                    client.sysop_account_input.pop_back();
                    show_sysop_account_review(client);
                }
            } else {
                const unsigned char byte = static_cast<unsigned char>(character);
                if ((byte >= '0' && byte <= '9') || byte == ',') {
                    if (client.sysop_account_input.size() < 7) {
                        client.sysop_account_input.push_back(character);
                        show_sysop_account_review(client);
                    }
                }
            }
            return;
        }
        if (client.viewing_sysop_account_detail) {
            if (admin_command == 'Q' || admin_command == 'B') {
                client.viewing_sysop_account_detail = false;
                show_sysop_accounts(client);
            } else if (admin_command == 'S' && client.sysop_selected_index.has_value() &&
                *client.sysop_selected_index < client.sysop_accounts.size()) {
                client.editing_sysop_security_levels = true;
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (admin_command == 'F' && client.sysop_selected_index.has_value() &&
                *client.sysop_selected_index < client.sysop_accounts.size()) {
                client.editing_sysop_acs_flags = true;
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (admin_command == 'C' && client.sysop_selected_index.has_value() &&
                *client.sysop_selected_index < client.sysop_accounts.size()) {
                client.editing_sysop_credits = true;
                client.editing_sysop_file_points = false;
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (admin_command == 'P' && client.sysop_selected_index.has_value() &&
                *client.sysop_selected_index < client.sysop_accounts.size()) {
                client.editing_sysop_credits = false;
                client.editing_sysop_file_points = true;
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (admin_command == 'D' && client.sysop_selected_index.has_value() &&
                *client.sysop_selected_index < client.sysop_accounts.size()) {
                client.editing_sysop_birth_date = true;
                client.editing_sysop_sex = false;
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (admin_command == 'G' && client.sysop_selected_index.has_value() &&
                *client.sysop_selected_index < client.sysop_accounts.size()) {
                client.editing_sysop_birth_date = false;
                client.editing_sysop_sex = true;
                client.editing_sysop_expiration_date = false;
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (admin_command == 'X' && client.sysop_selected_index.has_value() &&
                *client.sysop_selected_index < client.sysop_accounts.size()) {
                client.editing_sysop_birth_date = false;
                client.editing_sysop_sex = false;
                client.editing_sysop_expiration_date = true;
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (admin_command == 'V' && client.sysop_selected_index.has_value() &&
                *client.sysop_selected_index < client.sysop_accounts.size()) {
                client.editing_sysop_validation_level = true;
                client.confirming_sysop_validation = false;
                client.pending_sysop_validation.reset();
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (admin_command == 'E' && client.sysop_selected_index.has_value() &&
                *client.sysop_selected_index < client.sysop_accounts.size()) {
                client.editing_sysop_profile = true;
                client.editing_sysop_profile_field = '\0';
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (admin_command == 'I' && client.sysop_selected_index.has_value() &&
                *client.sysop_selected_index < client.sysop_accounts.size()) {
                client.editing_sysop_short_message = true;
                client.sysop_account_input.clear();
                show_sysop_account_review(client);
            } else if (admin_command == 'M' && client.sysop_selected_index.has_value() &&
                *client.sysop_selected_index < client.sysop_accounts.size()) {
                try {
                    const AccountSummary account = client.sysop_accounts[*client.sysop_selected_index];
                    const bool close_mailbox = !account.mailbox_closed;
                    client.accounts->set_mailbox_closed(account.handle, close_mailbox);
                    record_sysop_action(client,
                        close_mailbox ? "closed private mailbox" : "opened private mailbox",
                        account.handle);
                    client.sysop_accounts = client.accounts->list_accounts();
                    const auto selected = std::find_if(client.sysop_accounts.begin(), client.sysop_accounts.end(),
                        [&account](const AccountSummary& item) { return item.handle == account.handle; });
                    if (selected == client.sysop_accounts.end()) {
                        throw std::runtime_error("updated account disappeared from the account list");
                    }
                    client.sysop_selected_index = static_cast<std::size_t>(
                        std::distance(client.sysop_accounts.begin(), selected));
                    show_sysop_account_review(client);
                } catch (const std::exception& error) {
                    (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                    show_sysop_account_review(client);
                }
            }
            return;
        }
        const std::size_t page_count = std::max<std::size_t>(
            1, (client.sysop_accounts.size() + 9) / 10);
        if (admin_command == 'Q') {
            show_welcome(client);
        } else if (admin_command == 'A') {
            client.area_admin_notice.clear();
            show_sysop_area_admin(client);
        } else if (admin_command == 'L') {
            client.sysop_audit_page = 0;
            show_sysop_audit(client);
        } else if (admin_command == 'W') {
            client.signup_preferences_page = false;
            show_signup_question_admin(client);
        } else if (admin_command == 'Y') {
            client.validation_admin_page = 0;
            client.validation_admin_selection_index = 0;
            client.validation_admin_operation = '\0';
            client.validation_admin_input.clear();
            client.validation_admin_notice.clear();
            show_validation_level_admin(client);
        } else if (admin_command == 'N' && client.sysop_page + 1 < page_count) {
            ++client.sysop_page;
            client.sysop_selected_index.reset();
            show_sysop_accounts(client);
        } else if (admin_command == 'P' && client.sysop_page > 0) {
            --client.sysop_page;
            client.sysop_selected_index.reset();
            show_sysop_accounts(client);
        } else if ((character >= '1' && character <= '9') || character == '0') {
            const std::size_t row = character == '0'
                ? 9
                : static_cast<std::size_t>(character - '1');
            const std::size_t index = client.sysop_page * 10 + row;
            if (index < client.sysop_accounts.size()) {
                client.sysop_selected_index = index;
                show_sysop_accounts(client);
            } else {
                (void)write_channel(client, "\a");
            }
        } else if (admin_command == 'R') {
            show_sysop_accounts(client);
        } else if (admin_command == 'V' && client.sysop_selected_index.has_value() &&
            *client.sysop_selected_index < client.sysop_accounts.size()) {
            show_sysop_account_review(client);
        } else if ((admin_command == 'E' || admin_command == 'D' || admin_command == 'T') &&
            client.sysop_selected_index.has_value() &&
            *client.sysop_selected_index < client.sysop_accounts.size()) {
            const std::string handle = client.sysop_accounts[*client.sysop_selected_index].handle;
            const bool was_approved = client.sysop_accounts[*client.sysop_selected_index].approved;
            try {
                std::string action;
                if (admin_command == 'E') {
                    client.accounts->set_enabled(handle, true);
                    action = client.sysop_accounts[*client.sysop_selected_index].approved
                        ? "enable"
                        : "approve";
                    if (!was_approved && client.community != nullptr) {
                        try {
                            client.community->send_short_message(
                                handle, "Your Renegade BBS account has been approved. Welcome!");
                        } catch (const std::exception& error) {
                            std::cerr << "Could not queue account approval notice: " << error.what() << '\n';
                        }
                    }
                } else if (admin_command == 'D') {
                    client.accounts->set_enabled(handle, false);
                    action = "disable";
                } else if (handle == client.handle) {
                    (void)write_channel(client, "\r\nYou cannot change your own SysOp access here.\r\n");
                } else {
                    client.accounts->set_sysop(handle,
                        !client.sysop_accounts[*client.sysop_selected_index].is_sysop);
                    action = client.sysop_accounts[*client.sysop_selected_index].is_sysop
                        ? "revoke SysOp from"
                        : "grant SysOp to";
                }
                if (!action.empty()) {
                    record_sysop_action(client, action, handle);
                    std::clog << "SysOp " << client.handle << ' ' << action << " account "
                              << handle << ".\n";
                }
                show_sysop_accounts(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not update account access: " << error.what() << '\n';
                (void)write_channel(client, "\r\nAccount update failed.\r\n");
                show_sysop_accounts(client);
            }
        }
        return;
    }

    if (client.entering_message_area_password) {
        if (character == '\r' || character == '\n') {
            client.ignore_line_feed = character == '\r';
            const auto area_id = client.pending_message_area_id;
            const auto parent_id = client.pending_parent_message_id;
            const std::string password = std::move(client.message_line);
            client.message_line.clear();
            client.entering_message_area_password = false;
            client.pending_message_area_id.reset();
            if (area_id.has_value() && client.messages->verify_area_password(
                    client.handle, *area_id, password)) {
                client.unlocked_message_areas.insert(*area_id);
                if (parent_id.has_value()) {
                    client.pending_parent_message_id.reset();
                    open_parent_message(client, *parent_id);
                    return;
                }
                const auto selected = std::find_if(client.board_areas.begin(), client.board_areas.end(),
                    [area_id](const BoardArea& area) { return area.id == *area_id; });
                if (selected != client.board_areas.end()) {
                    const std::size_t index = static_cast<std::size_t>(
                        std::distance(client.board_areas.begin(), selected));
                    select_message_area(client, index);
                    return;
                }
            }
            client.pending_parent_message_id.reset();
            (void)write_channel(client, "\r\nIncorrect password.\r\n");
            if (parent_id.has_value()) {
                show_selected_message(client);
            } else {
                show_message_areas(client);
            }
        } else if (character == 27) {
            const bool return_to_reader = client.pending_parent_message_id.has_value();
            client.message_line.clear();
            client.entering_message_area_password = false;
            client.pending_message_area_id.reset();
            client.pending_parent_message_id.reset();
            if (return_to_reader) {
                show_selected_message(client);
            } else {
                show_message_areas(client);
            }
        } else if (character == '\b' || character == 127) {
            if (!client.message_line.empty()) {
                client.message_line.pop_back();
                (void)write_channel(client, "\b \b");
            }
        } else {
            const unsigned char byte = static_cast<unsigned char>(character);
            if (byte >= 32 && byte < 127 && client.message_line.size() < 20) {
                client.message_line.push_back(character);
                (void)write_channel(client, "*");
            }
        }
        return;
    }

    if (client.entering_message_search_query) {
        if (character == '\r' || character == '\n') {
            client.ignore_line_feed = character == '\r';
            client.message_search_query = client.message_line;
            client.message_line.clear();
            client.entering_message_search_query = false;
            client.choosing_message_search_field = true;
            show_message_search_prompt(client, false);
        } else if (character == 27) {
            cancel_message_search(client);
        } else if (character == '\b' || character == 127) {
            if (!client.message_line.empty()) {
                client.message_line.pop_back();
                (void)write_channel(client, "\b \b");
            }
        } else {
            const unsigned char byte = static_cast<unsigned char>(character);
            if (byte >= 32 && byte != 127 && client.message_line.size() < 40) {
                client.message_line.push_back(character);
                (void)write_channel(client, std::string_view(&character, 1));
            }
        }
        return;
    }

    if (client.choosing_message_search_field) {
        const char search_command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        switch (search_command) {
        case 'F': client.message_search_selection_index = 0; break;
        case 'T': client.message_search_selection_index = 1; break;
        case 'S': client.message_search_selection_index = 2; break;
        case 'A': client.message_search_selection_index = 3; break;
        case 'Y': client.message_search_selection_index = 4; break;
        case 'U': client.message_search_selection_index = 5; break;
        case 'N': client.message_search_selection_index = 6; break;
        case 'G': client.message_search_selection_index = 7; break;
        default: break;
        }
        if (character == '\r' || character == '\n') {
            static constexpr std::array<char, 8> search_keys{'F', 'T', 'S', 'A', 'Y', 'U', 'N', 'G'};
            client.ignore_line_feed = character == '\r';
            handle_input(client, search_keys[client.message_search_selection_index]);
            return;
        }
        if (search_command == 'Q' || character == 27) {
            cancel_message_search(client);
        } else if (search_command == 'N') {
            client.message_search_new_only = !client.message_search_new_only;
            show_message_search_prompt(client, false);
        } else if (search_command == 'G') {
            client.message_search_all_areas = !client.message_search_all_areas;
            show_message_search_prompt(client, false);
        } else {
            std::optional<MessageSearchField> field;
            switch (search_command) {
            case 'F': field = MessageSearchField::From; break;
            case 'T': field = MessageSearchField::To; break;
            case 'S': field = MessageSearchField::Subject; break;
            case 'A': field = MessageSearchField::AllText; break;
            case 'Y': field = MessageSearchField::ToMe; break;
            case 'U': field = MessageSearchField::Yours; break;
            default: break;
            }
            if (!field.has_value()) {
                (void)write_channel(client, "\a");
            } else if (client.message_search_query.empty() &&
                *field != MessageSearchField::ToMe && *field != MessageSearchField::Yours) {
                (void)write_channel(client, "\a\r\nEnter search text for this field first.");
                show_message_search_prompt(client, false);
            } else {
                client.message_search_field = *field;
                client.searching_messages = true;
                client.choosing_message_search_field = false;
                client.message_list_page = 0;
                show_message_board(client);
            }
        }
        return;
    }

    if (client.confirming_message_extract) {
        handle_message_extract_input(client, character);
        return;
    }

    if (client.writing_message) {
        if (character == '\r' || character == '\n') {
            client.ignore_line_feed = character == '\r';
            submit_message_line(client);
            return;
        }
        if (character == 27) {
            cancel_message_post(client);
            return;
        }
        if (character == '\b' || character == 127) {
            if (!client.message_line.empty()) {
                client.message_line.pop_back();
                (void)write_channel(client, "\b \b");
            }
            return;
        }
        const unsigned char byte = static_cast<unsigned char>(character);
        if (byte < 32 || byte == 127) {
            return;
        }
        const bool legacy_message_body = client.writing_message_body &&
            !client.message_is_auto && !client.message_is_quote;
        const std::size_t line_limit = client.entering_message_goto
            ? 20
            : (client.entering_private_recipient ? 32
            : (client.entering_private_goto ? 20
                : (client.entering_private_anonymous || client.entering_auto_anonymous ? 1
                : (client.entering_message_recipient || client.entering_message_anonymous ? 36
                    : (client.writing_message_body
                        ? (legacy_message_body ? kMessageLineCharacterLimit * 4 : 200)
                        : 80)))));
        if (client.message_line.size() < line_limit) {
            client.message_line.push_back(character);
            (void)write_channel(client, std::string_view(&character, 1));
        }
        return;
    }

    if (client.viewing_new_scan) {
        const char scan_command = static_cast<char>(
            std::toupper(static_cast<unsigned char>(character)));
        const std::size_t page_count = client.new_scan_page.page_count;
        if (scan_command == 'Q') {
            show_message_areas(client);
        } else if (scan_command == 'R') {
            show_unread_messages(client);
        } else if (scan_command == 'N' && client.new_scan_page_index + 1 < page_count) {
            ++client.new_scan_page_index;
            client.new_scan_selection_index = 0;
            show_unread_messages(client);
        } else if (scan_command == 'P' && client.new_scan_page_index > 0) {
            --client.new_scan_page_index;
            client.new_scan_selection_index = 0;
            show_unread_messages(client);
        } else if ((character >= '1' && character <= '9') || character == '0') {
            const std::size_t row = character == '0'
                ? 9
                : static_cast<std::size_t>(character - '1');
            if (row < client.new_scan_page.messages.size()) {
                client.new_scan_selection_index = row;
                const UnreadBoardMessage& entry = client.new_scan_page.messages[row];
                client.current_area = entry.area_name;
                remember_message_area(client, client.current_area);
                client.reader_message = entry.message;
                client.message_page = 0;
                client.reader_backstack.clear();
                client.reading_from_new_scan = true;
                client.viewing_new_scan = false;
                client.viewing_messages = true;
                show_selected_message(client);
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.viewing_message_scan_settings) {
        const char scan_command = static_cast<char>(
            std::toupper(static_cast<unsigned char>(character)));
        const std::size_t page_count = std::max<std::size_t>(
            1, (client.board_areas.size() + 9) / 10);
        if (scan_command == 'Q') {
            show_message_areas(client);
        } else if (scan_command == 'F' || scan_command == 'U') {
            try {
                client.messages->set_all_area_new_scans(client.handle, scan_command == 'F');
                show_message_scan_settings(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not update message scan settings: " << error.what() << '\n';
                (void)write_channel(client, "\r\nCould not update scan flags.\r\n");
                show_message_scan_settings(client);
            }
        } else if (scan_command == 'N' && client.area_page + 1 < page_count) {
            ++client.area_page;
            client.message_area_selection_index = client.area_page * 10;
            show_message_scan_settings(client);
        } else if (scan_command == 'P' && client.area_page > 0) {
            --client.area_page;
            client.message_area_selection_index = client.area_page * 10;
            show_message_scan_settings(client);
        } else if ((character >= '1' && character <= '9') || character == '0') {
            const std::size_t slot = character == '0'
                ? 9
                : static_cast<std::size_t>(character - '1');
            const std::size_t index = client.area_page * 10 + slot;
            if (index < client.board_areas.size()) {
                if (client.board_areas[index].force_read) {
                    (void)write_channel(client, "\a");
                    return;
                }
                try {
                    (void)client.messages->toggle_area_new_scan(
                        client.handle, client.board_areas[index].name);
                    show_message_scan_settings(client);
                } catch (const std::exception& error) {
                    std::cerr << "Could not toggle message scan flag: " << error.what() << '\n';
                    (void)write_channel(client, "\r\nCould not change that scan flag.\r\n");
                    show_message_scan_settings(client);
                }
            } else {
                (void)write_channel(client, "\a");
            }
        }
        return;
    }

    if (client.viewing_areas) {
        const char area_command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        const std::size_t page_count = std::max<std::size_t>(1, (client.board_areas.size() + 9) / 10);
        if (area_command == 'Q') {
            show_welcome(client);
        } else if (area_command == 'S') {
            client.new_scan_page_index = 0;
            show_unread_messages(client);
        } else if (area_command == 'T') {
            client.area_page = 0;
            show_message_scan_settings(client);
        } else if (area_command == 'D') {
            client.entering_message_scan_date = true;
            client.message_scan_date_input.clear();
            (void)write_channel(client,
                "\r\nEnter oldest date for new messages (MM/DD/YYYY), or Esc to cancel: ");
        } else if (area_command == 'N' && client.area_page + 1 < page_count) {
            ++client.area_page;
            show_message_areas(client);
        } else if (area_command == 'P' && client.area_page > 0) {
            --client.area_page;
            show_message_areas(client);
        } else if (character >= '1' && character <= '9') {
            select_message_area(client, client.area_page * 10 + static_cast<std::size_t>(character - '1'));
        } else if (character == '0') {
            select_message_area(client, client.area_page * 10 + 9);
        }
        return;
    }

    if (client.viewing_private_mail) {
        if (client.selecting_message_move_area) {
            handle_message_move_input(client, character);
            return;
        }
        const char mail_command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        if (client.reading_private_message) {
            if (mail_command == 'B' || mail_command == 'Q') {
                if (mail_command == 'Q') {
                    show_welcome(client);
                } else {
                    show_private_mailbox(client);
                }
            } else if (mail_command == 'N' &&
                client.private_message_page + 1 < client.private_message_page_count) {
                ++client.private_message_page;
                show_selected_private_message(client);
            } else if (mail_command == 'P' && client.private_message_page > 0) {
                --client.private_message_page;
                show_selected_private_message(client);
            } else if (mail_command == 'D' && client.private_message.has_value()) {
                try {
                    const bool deleted = client.messages->toggle_private_deleted(
                        client.handle, client.private_message->id);
                    client.private_message->deleted = deleted;
                    if (client.is_sysop) {
                        record_sysop_action(client,
                            deleted ? "deleted private message" : "restored private message",
                            "#" + std::to_string(client.private_message->id) + " " +
                                client.private_message->sender_handle + " -> " + client.private_message->recipient);
                    }
                    std::clog << (client.is_sysop ? "SysOp " : "Caller ") << client.handle
                              << (deleted ? " deleted private message #" : " restored private message #")
                              << client.private_message->id << ".\n";
                    (void)write_channel(client, deleted
                        ? "\r\nPrivate message deleted.\r\n"
                        : "\r\nPrivate message restored.\r\n");
                    show_selected_private_message(client);
                } catch (const std::exception& error) {
                    (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                    show_selected_private_message(client);
                }
            } else if (mail_command == 'E' && client.private_mailbox == PrivateMailbox::Outbox &&
                client.private_message.has_value()) {
                start_private_message_edit(client);
            } else if (mail_command == 'M') {
                begin_private_message_move(client);
            } else if (mail_command == 'X') {
                begin_message_extract(client, true);
            } else if (mail_command == 'R' && client.private_mailbox == PrivateMailbox::Inbox &&
                client.private_message.has_value()) {
                if (private_reply_allowed(client, *client.private_message)) {
                    start_private_message(client, &*client.private_message);
                } else {
                    (void)write_channel(client, "\r\nYou cannot reply to this anonymous message.\r\n");
                    show_selected_private_message(client);
                }
            } else if (mail_command == 'F' && client.private_message.has_value()) {
                start_private_message(client, &*client.private_message, true);
            } else if (mail_command == 'G') {
                client.writing_message = true;
                client.writing_message_body = false;
                client.message_is_private = true;
                client.reading_private_message = false;
                client.entering_private_recipient = false;
                client.entering_private_anonymous = false;
                client.entering_private_goto = true;
                client.forwarding_private_message = false;
                client.forwarding_private_message_id.reset();
                client.message_line.clear();
                client.message_subject.clear();
                client.message_subject_default.clear();
                redraw_message_editor(client);
            }
            return;
        }

        if (mail_command == 'Q') {
            show_welcome(client);
        } else if (mail_command == 'I' && client.private_mailbox != PrivateMailbox::Inbox) {
            client.private_mailbox = PrivateMailbox::Inbox;
            client.private_mail_list_page = 0;
            client.private_message_index = 0;
            show_private_mailbox(client);
        } else if (mail_command == 'O' && client.private_mailbox != PrivateMailbox::Outbox) {
            client.private_mailbox = PrivateMailbox::Outbox;
            client.private_mail_list_page = 0;
            client.private_message_index = 0;
            show_private_mailbox(client);
        } else if (mail_command == 'C') {
            start_private_message(client);
        } else if (mail_command == 'N' &&
            client.private_mail_list_page + 1 < client.private_mail_list_page_count) {
            ++client.private_mail_list_page;
            client.private_message_index = 0;
            show_private_mailbox(client);
        } else if (mail_command == 'P' && client.private_mail_list_page > 0) {
            --client.private_mail_list_page;
            client.private_message_index = 0;
            show_private_mailbox(client);
        } else if (mail_command == 'R') {
            select_private_message(client, 0);
        } else if (character >= '1' && character <= '9') {
            select_private_message(client, static_cast<std::size_t>(character - '1'));
        } else if (character == '0') {
            select_private_message(client, 9);
        }
        return;
    }

    if (client.viewing_messages) {
        const char board_command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        if (client.selecting_message_move_area) {
            handle_message_move_input(client, character);
            return;
        }
        if (client.confirming_message_validation) {
            client.confirming_message_validation = false;
            if (board_command == 'Y') {
                try {
                    const std::size_t validated = client.messages->validate_all_messages(
                        client.handle, client.current_area);
                    if (validated > 0) {
                        record_sysop_action(client, "validated all public messages",
                            client.current_area + " (" + std::to_string(validated) + " posts)");
                    }
                    std::clog << "Area moderator " << client.handle << " validated " << validated
                              << " pending posts in " << client.current_area << ".\n";
                    (void)write_channel(client, "\r\n" + std::to_string(validated) +
                        " messages validated.\r\n");
                } catch (const std::exception& error) {
                    (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                }
            } else {
                (void)write_channel(client, "\r\nValidation cancelled.\r\n");
            }
            show_message_board(client);
            return;
        }
        if (client.reading_message) {
            if (board_command == 'B') {
                if (!client.reader_backstack.empty()) {
                    ClientContext::ReaderFrame previous = std::move(client.reader_backstack.back());
                    client.reader_backstack.pop_back();
                    client.reader_message = std::move(previous.message);
                    client.message_page = previous.page;
                    client.current_area = std::move(previous.area);
                    show_selected_message(client);
                } else if (client.reading_from_new_scan) {
                    show_unread_messages(client);
                } else {
                    show_message_board(client);
                }
            } else if (board_command == 'Q') {
                client.searching_messages = false;
                client.message_search_all_areas = false;
                client.message_search_new_only = false;
                client.message_search_query.clear();
                show_message_areas(client);
            } else if (board_command == 'N' && client.message_page + 1 < client.message_page_count) {
                ++client.message_page;
                show_selected_message(client);
            } else if (board_command == 'P' && client.message_page > 0) {
                --client.message_page;
                show_selected_message(client);
            } else if (board_command == 'D' && client.reader_message.has_value()) {
                try {
                    const bool moderator = client.messages->can_moderate_area(
                        client.handle, client.current_area);
                    const std::string subject = client.reader_message->subject;
                    const bool deleted = client.messages->toggle_message_deleted(
                        client.handle, client.current_area, client.reader_message->id);
                    client.reader_message->deleted = deleted;
                    if (moderator) {
                        record_sysop_action(client,
                            deleted ? "deleted public message" : "restored public message",
                            "#" + std::to_string(client.reader_message->id) + " " + subject);
                    }
                    std::clog << (moderator ? "Area moderator " : "Caller ") << client.handle
                              << (deleted ? " deleted public message #" : " restored public message #")
                              << client.reader_message->id << " in " << client.current_area << ".\n";
                    (void)write_channel(client, deleted
                        ? "\r\nPublic message deleted.\r\n"
                        : "\r\nPublic message restored.\r\n");
                    show_selected_message(client);
                } catch (const std::exception& error) {
                    (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                    show_selected_message(client);
                }
            } else if (board_command == 'V' && client.reader_message.has_value()) {
                try {
                    const std::string subject = client.reader_message->subject;
                    const bool unvalidated = client.messages->toggle_message_validation(
                        client.handle, client.current_area, client.reader_message->id);
                    client.reader_message->unvalidated = unvalidated;
                    record_sysop_action(client,
                        unvalidated ? "marked public message unvalidated" : "validated public message",
                        "#" + std::to_string(client.reader_message->id) + " " + subject);
                    std::clog << "Area moderator " << client.handle
                              << (unvalidated ? " marked public message #" : " validated public message #")
                              << client.reader_message->id << " in " << client.current_area << ".\n";
                    (void)write_channel(client, unvalidated
                        ? "\r\nMessage marked unvalidated.\r\n"
                        : "\r\nMessage validated.\r\n");
                    show_selected_message(client);
                } catch (const std::exception& error) {
                    (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                    show_selected_message(client);
                }
            } else if (board_command == 'K' && client.reader_message.has_value()) {
                try {
                    const std::string subject = client.reader_message->subject;
                    const bool permanent = client.messages->toggle_message_permanent(
                        client.handle, client.current_area, client.reader_message->id);
                    client.reader_message->permanent = permanent;
                    record_sysop_action(client,
                        permanent ? "marked public message permanent" : "removed permanent status from public message",
                        "#" + std::to_string(client.reader_message->id) + " " + subject);
                    std::clog << "Area moderator " << client.handle
                              << (permanent ? " marked public message #" : " removed permanent status from message #")
                              << client.reader_message->id << " in " << client.current_area << ".\n";
                    (void)write_channel(client, permanent
                        ? "\r\nMessage marked permanent.\r\n"
                        : "\r\nPermanent status removed.\r\n");
                    show_selected_message(client);
                } catch (const std::exception& error) {
                    (void)write_channel(client, "\r\n" + std::string(error.what()) + "\r\n");
                    show_selected_message(client);
                }
            } else if (board_command == 'M') {
                begin_message_move(client);
            } else if (board_command == 'X') {
                begin_message_extract(client, false);
            } else if (board_command == 'E' && client.reader_message.has_value()) {
                const bool moderator = client.messages->can_moderate_area(
                    client.handle, client.current_area);
                if (moderator || ::strcasecmp(
                        client.reader_message->owner_handle.c_str(), client.handle.c_str()) == 0) {
                    start_message_edit(client);
                } else {
                    (void)write_channel(client, "\a");
                }
            } else if (board_command == 'R') {
                if (client.reader_message.has_value()) {
                    start_message_post(client, client.reader_message->id, client.reader_message->subject,
                        client.reader_message->recipient, &*client.reader_message);
                } else {
                    (void)write_channel(client, "\a");
                }
            } else if (board_command == 'F') {
                start_public_message_forward(client);
            } else if (board_command == 'G') {
                client.writing_message = true;
                client.writing_message_body = false;
                client.message_is_private = false;
                client.entering_private_recipient = false;
                client.entering_message_recipient = false;
                client.entering_message_anonymous = false;
                client.entering_message_goto = true;
                client.message_is_auto = false;
                client.message_is_quote = false;
                client.editing_public_message = false;
                client.message_line.clear();
                client.message_subject.clear();
                client.message_subject_default.clear();
                client.viewing_messages = false;
                client.reading_message = false;
                redraw_message_editor(client);
            } else if (board_command == 'O') {
                if (!client.reader_message.has_value() || !client.reader_message->reply_to.has_value()) {
                    (void)write_channel(client, "\a");
                    return;
                }
                open_parent_message(client, *client.reader_message->reply_to);
            }
            return;
        }
        if (board_command == 'W') {
            start_message_post(client);
        } else if (board_command == 'V') {
            if (client.messages->can_moderate_area(client.handle, client.current_area)) {
                client.confirming_message_validation = true;
                (void)write_channel(client,
                    "\r\nValidate every pending message in this area? Press Y to confirm, any other key to cancel: ");
            } else {
                (void)write_channel(client, "\a");
            }
        } else if (board_command == 'Q') {
            if (client.searching_messages) {
                cancel_message_search(client);
            } else {
                show_message_areas(client);
            }
        } else if (board_command == 'X') {
            begin_message_search(client);
        } else if (board_command == 'S') {
            if (client.searching_messages) {
                client.message_search_new_only = !client.message_search_new_only;
            } else {
                client.unread_only_messages = !client.unread_only_messages;
            }
            client.message_list_page = 0;
            show_message_board(client);
        } else if (board_command == 'N' && client.message_list_page + 1 < client.message_list_page_count) {
            ++client.message_list_page;
            client.message_list_selection_index = 0;
            show_message_board(client);
        } else if (board_command == 'P' && client.message_list_page > 0) {
            --client.message_list_page;
            client.message_list_selection_index = 0;
            show_message_board(client);
        } else if (board_command == 'R') {
            select_board_message(client, 0);
        } else if (character >= '1' && character <= '9') {
            select_board_message(client, static_cast<std::size_t>(character - '1'));
        } else if (character == '0') {
            select_board_message(client, 9);
        }
        return;
    }

    if (client.viewing_art) {
        if (character == '\r' || character == '\n' || character == 27 ||
            static_cast<unsigned char>(character) < 32 || character == 127) {
            return;
        }
        const char gallery_command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        if (gallery_command == 'Q') {
            show_welcome(client);
        } else if (gallery_command == 'P') {
            if (client.art_index == 0 && client.art_catalog != nullptr && !client.art_catalog->empty()) {
                client.art_index = client.art_catalog->size() - 1;
            } else if (client.art_index > 0) {
                --client.art_index;
            }
            show_artwork(client);
        } else if (gallery_command == 'N' || character == ' ') {
            ++client.art_index;
            show_artwork(client);
        }
        return;
    }

    if (client.waiting_for_return) {
        if (client.viewing_entrance) {
            client.viewing_entrance = false;
            client.waiting_for_return = false;
            show_initial_screen(client);
            return;
        }
        if (client.viewing_once_only) {
            client.viewing_once_only = false;
            client.waiting_for_return = false;
            show_initial_screen(client);
            return;
        }
        if (client.showing_nodes &&
            static_cast<char>(std::toupper(static_cast<unsigned char>(character))) == 'A' &&
            client.is_sysop && client.community != nullptr && client.caller_session_id.has_value()) {
            try {
                const bool available = !client.sysop_available;
                client.community->update_caller_session_availability(
                    *client.caller_session_id, available);
                client.sysop_available = available;
                (void)write_channel(client, std::string("\r\nSysOp availability for this node is now ") +
                    (client.sysop_available ? "on.\r\n" : "off.\r\n"));
                show_nodes(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not update SysOp availability: " << error.what() << '\n';
                show_welcome(client);
            }
            return;
        }
        if (client.showing_nodes &&
            static_cast<char>(std::toupper(static_cast<unsigned char>(character))) == 'I' &&
            client.messages != nullptr && client.community != nullptr &&
            client.caller_session_id.has_value() &&
            client.messages->can_toggle_invisibility(client.handle)) {
            try {
                const bool invisible = !client.invisible;
                client.community->update_caller_session_invisible(*client.caller_session_id, invisible);
                client.registry->set_invisible(client, invisible);
                (void)write_channel(client, std::string("\r\nInvisible mode is now ") +
                    (invisible ? "on.\r\n" : "off.\r\n"));
                show_nodes(client);
            } catch (const std::exception& error) {
                std::cerr << "Could not update caller invisibility: " << error.what() << '\n';
                show_welcome(client);
            }
            return;
        }
        show_welcome(client);
        return;
    }

    if (client.in_chat.load()) {
        if (character == '\r' || character == '\n') {
            client.ignore_line_feed = character == '\r';
            submit_chat_line(client);
            return;
        }
        if (character == '\b' || character == 127) {
            if (!client.chat_input.empty()) {
                client.chat_input.pop_back();
                (void)write_channel(client, "\b \b");
            }
            return;
        }
        if (character == 27 || static_cast<unsigned char>(character) < 32) {
            return;
        }
        if (client.chat_input.size() < 250) {
            client.chat_input.push_back(character);
            (void)write_channel(client, std::string_view(&character, 1));
        }
        return;
    }

    if (character == 27 || character == '\r' || character == '\n') {
        return;
    }
    const char command = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
    if (client.welcome_menu_active) {
        const std::string_view menu_keys = welcome_menu_keys(client.is_sysop);
        if (menu_keys.find(command) != std::string_view::npos) {
            client.welcome_menu_active = false;
        }
    }
    switch (command) {
    case 'N':
        show_nodes(client);
        break;
    case 'H':
        show_help(client);
        break;
    case 'C':
        enter_chat(client);
        break;
    case 'A':
        client.art_index = 0;
        show_artwork(client);
        break;
    case 'R':
        show_quote(client, true);
        break;
    case 'B':
        client.bulletin_index = 0;
        client.reading_bulletin = false;
        show_bulletins(client);
        break;
    case 'D':
        client.bbs_listing_page_index = 0;
        client.selected_bbs_listing_id.reset();
        client.bbs_detail_page = 0;
        show_bbs_directory(client);
        break;
    case 'L':
        client.caller_page = 0;
        show_callers(client);
        break;
    case 'T':
        client.statistics_page = 0;
        show_statistics(client);
        break;
    case 'G':
        client.auto_message_page = 0;
        show_auto_message(client);
        break;
    case 'V':
        client.poll_page = 0;
        client.reading_poll = false;
        client.selected_poll_id.reset();
        show_polls(client);
        break;
    case 'O':
        client.one_liner_page.page = 0;
        show_one_liners(client);
        break;
    case 'M':
        client.area_page = 0;
        show_message_areas(client);
        break;
    case 'F':
        client.file_area_page = 0;
        show_file_areas(client);
        break;
    case 'I':
        if (client.is_sysop) {
            client.incoming_files_page = 0;
            show_upload_review(client);
        } else {
            (void)write_channel(client, "\a");
        }
        break;
    case 'J':
        if (client.is_sysop) {
            client.quote_submission_page = 0;
            client.selected_quote_submission_id.reset();
            show_quote_queue(client);
        } else {
            (void)write_channel(client, "\a");
        }
        break;
    case 'P':
        enter_private_mail(client);
        break;
    case 'U':
        show_profile(client);
        break;
    case 'K':
        show_time_bank(client);
        break;
    case 'S':
        if (client.is_sysop) {
            client.sysop_page = 0;
            client.sysop_selected_index.reset();
            show_sysop_accounts(client);
        } else {
            (void)write_channel(client, "\a");
        }
        break;
    case 'Q':
        client.close_requested = true;
        break;
    default:
        (void)write_channel(client, "\a");
        break;
    }
}

void drain_outgoing(ClientContext& client) {
    std::deque<std::string> pending;
    {
        std::lock_guard lock(client.outgoing_mutex);
        pending.swap(client.outgoing);
    }
    for (const std::string& message : pending) {
        std::string output = "\r\n" + message + "\r\n";
        if (client.in_chat.load()) {
            output += "Chat> " + client.chat_input;
        } else {
            output += "Command > ";
        }
        if (!write_channel(client, output)) {
            client.close_requested = true;
            return;
        }
    }
}

void drain_sftp_output(ClientContext& client) {
    while (!client.sftp_output.empty()) {
        std::string response = std::move(client.sftp_output.front());
        client.sftp_output.pop_front();
        client.sftp_output_bytes -= response.size();
        if (!write_binary_channel(client, response)) {
            client.close_requested = true;
            return;
        }
    }
}

void process_terminal_byte(ClientContext& client, char character) {
    if (client.pending_terminal_escape.empty()) {
        if (character == '\x1b') {
            client.pending_terminal_escape.assign(1, character);
            client.terminal_escape_started = std::chrono::steady_clock::now();
        } else {
            handle_input(client, character);
        }
        return;
    }

    if (client.pending_terminal_escape.size() == 1) {
        if (character == '[' || character == 'O') {
            client.pending_terminal_escape.push_back(character);
            return;
        }
        client.pending_terminal_escape.clear();
        handle_input(client, '\x1b');
        if (!client.close_requested) {
            process_terminal_byte(client, character);
        }
        return;
    }

    client.pending_terminal_escape.push_back(character);
    if (client.pending_terminal_escape.size() > 32) {
        client.pending_terminal_escape.clear();
        return;
    }
    const unsigned char byte = static_cast<unsigned char>(character);
    if (byte < 0x40 || byte > 0x7e) {
        return;
    }

    const char final = character;
    const bool is_arrow = final == 'A' || final == 'B' || final == 'C' || final == 'D';
    client.pending_terminal_escape.clear();
    if (!is_arrow) {
        return;
    }
    switch (final) {
    case 'A': handle_input(client, kTerminalArrowUp); break;
    case 'B': handle_input(client, kTerminalArrowDown); break;
    case 'C': handle_input(client, kTerminalArrowRight); break;
    case 'D': handle_input(client, kTerminalArrowLeft); break;
    default: break;
    }
}

void process_incoming(ClientContext& client) {
    std::string bytes;
    bytes.swap(client.incoming);
    for (const char character : bytes) {
        process_terminal_byte(client, character);
        if (client.close_requested) {
            break;
        }
    }
    if (!client.close_requested && !client.pending_terminal_escape.empty() &&
        std::chrono::steady_clock::now() - client.terminal_escape_started >=
            std::chrono::milliseconds(250)) {
        const bool lone_escape = client.pending_terminal_escape.size() == 1;
        client.pending_terminal_escape.clear();
        if (lone_escape) {
            handle_input(client, '\x1b');
        }
    }
}

void handle_client(
    ssh_session session,
    AccountStore& accounts,
    FileStore& files,
    SessionRegistry& registry,
    LoginRateLimiter& login_rate_limiter,
    std::string_view entrance_art,
    std::string_view new_caller_art,
    std::string_view welcome_art,
    std::string_view sysop_art,
    std::string_view profile_art,
    std::string_view once_only_art,
    std::string_view once_only_art_modified,
    std::string_view birthday_art,
    std::string_view birthday_late_art,
    const std::vector<AnsiArtwork>& art_catalog,
    const std::vector<AnsiArtwork>& bulletin_catalog,
    const std::vector<AnsiArtwork>& quote_catalog,
    const std::vector<AnsiArtwork>& tagline_catalog,
    MessageStore& messages,
    CommunityStore& community,
    const SupplementalScreenArt& supplemental_art,
    std::string_view nodes_art,
    std::string_view callers_art,
    std::string_view stats_art,
    std::string_view help_art,
    std::string_view bbs_art,
    std::string_view file_areas_art,
    std::string_view chat_art,
    std::string_view bulletin_art,
    std::string_view areas_art,
    std::string_view board_art,
    std::string_view mailbox_art,
    std::string_view reader_art,
    std::string_view editor_art,
    unsigned int idle_timeout_seconds,
    unsigned int birthday_check_frequency,
    bool allow_signup,
    unsigned int session_time_limit_minutes,
    unsigned int time_bank_max_minutes,
    unsigned int time_bank_deposit_daily_limit,
    unsigned int time_bank_withdrawal_daily_limit) {
    struct SessionGuard {
        ssh_session value{};
        ~SessionGuard() {
            if (value != nullptr) {
                if (ssh_is_connected(value)) {
                    ssh_disconnect(value);
                }
                ssh_free(value);
            }
        }
    } session_guard{session};

    ClientContext client;
    client.accounts = &accounts;
    client.files = &files;
    client.registry = &registry;
    client.login_rate_limiter = &login_rate_limiter;
    client.peer_address = get_peer_address(session);
    client.entrance_art = entrance_art;
    client.new_caller_art = new_caller_art;
    client.welcome_art = welcome_art;
    client.sysop_art = sysop_art;
    client.profile_art = profile_art;
    client.once_only_art = once_only_art;
    client.once_only_art_modified = once_only_art_modified;
    client.birthday_art = birthday_art;
    client.birthday_late_art = birthday_late_art;
    client.nodes_art = nodes_art;
    client.callers_art = callers_art;
    client.stats_art = stats_art;
    client.help_art = help_art;
    client.bbs_art = bbs_art;
    client.file_areas_art = file_areas_art;
    client.chat_art = chat_art;
    client.bulletin_art = bulletin_art;
    client.areas_art = areas_art;
    client.board_art = board_art;
    client.mailbox_art = mailbox_art;
    client.reader_art = reader_art;
    client.editor_art = editor_art;
    client.supplemental_art = &supplemental_art;
    client.idle_timeout_seconds = idle_timeout_seconds;
    client.birthday_check_frequency = birthday_check_frequency;
    client.allow_signup = allow_signup;
    client.session_time_limit_minutes = session_time_limit_minutes;
    client.time_bank_max_minutes = static_cast<int>(time_bank_max_minutes);
    client.time_bank_deposit_daily_limit = static_cast<int>(time_bank_deposit_daily_limit);
    client.time_bank_withdrawal_daily_limit = static_cast<int>(time_bank_withdrawal_daily_limit);
    client.art_catalog = &art_catalog;
    client.bulletin_catalog = &bulletin_catalog;
    client.quote_catalog = &quote_catalog;
    client.tagline_catalog = &tagline_catalog;
    client.messages = &messages;
    client.community = &community;
    struct RegistryGuard {
        SessionRegistry& registry;
        ClientContext& client;
        ~RegistryGuard() {
            if (client.community != nullptr && client.caller_session_id.has_value()) {
                try {
                    client.community->record_caller_logout(*client.caller_session_id);
                } catch (const std::exception& error) {
                    std::cerr << "Could not record BBS caller logout: " << error.what() << '\n';
                } catch (...) {
                }
            }
            if (client.in_chat.load()) {
                try {
                    registry.broadcast(client, "Node " + std::to_string(client.node_number) +
                        " - " + client.handle + " disconnected from chat.");
                } catch (...) {
                }
            }
            registry.leave(client);
        }
    } registry_guard{registry, client};

    ssh_server_callbacks_struct server_callbacks{};
    server_callbacks.userdata = &client;
    server_callbacks.auth_password_function = authenticate_password;
    server_callbacks.auth_none_function = deny_passwordless_auth;
    server_callbacks.channel_open_request_session_function = open_session_channel;
    ssh_callbacks_init(&server_callbacks);

    if (ssh_set_server_callbacks(session, &server_callbacks) != SSH_OK) {
        std::cerr << "Could not configure SSH callbacks.\n";
        return;
    }
    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);

    const int session_fd = ssh_get_fd(session);
    if (session_fd >= 0) {
        const timeval handshake_timeout{15, 0};
        (void)::setsockopt(session_fd, SOL_SOCKET, SO_RCVTIMEO, &handshake_timeout, sizeof(handshake_timeout));
    }

    if (ssh_handle_key_exchange(session) != SSH_OK) {
        return;
    }
    if (session_fd >= 0) {
        const timeval no_timeout{};
        (void)::setsockopt(session_fd, SOL_SOCKET, SO_RCVTIMEO, &no_timeout, sizeof(no_timeout));
    }
    ssh_set_blocking(session, 0);

    struct EventGuard {
        ssh_event value{};
        ~EventGuard() {
            if (value != nullptr) {
                ssh_event_free(value);
            }
        }
    } event_guard{ssh_event_new()};
    if (event_guard.value == nullptr || ssh_event_add_session(event_guard.value, session) != SSH_OK) {
        std::cerr << "Could not create SSH session event loop.\n";
        return;
    }

    while (stop_requested == 0 && !client.channel_closed && !client.close_requested && ssh_is_connected(session)) {
        const int result = ssh_event_dopoll(event_guard.value, 100);
        if (result == SSH_ERROR) {
            break;
        }
        if (client.resize_pending && client.shell_requested && client.drawn &&
            !client.waiting_for_display_pause) {
            client.resize_pending = false;
            redraw_active_screen(client);
        }
        const auto now = std::chrono::steady_clock::now();
        const bool session_requested = client.shell_requested || client.sftp_requested;
        if ((!client.authenticated && now - client.connected_at > std::chrono::seconds(30)) ||
            (client.authenticated && !session_requested &&
                now - client.authenticated_at > std::chrono::seconds(30))) {
            break;
        }
        if (client.authenticated && session_requested && client.session_deadline.has_value() &&
            now >= *client.session_deadline) {
            if (client.shell_requested && write_channel(client, "\r\nYour allowed online time has expired. Please reconnect later.\r\n")) {
                flush_before_disconnect(client, event_guard.value, std::chrono::milliseconds(300));
            }
            break;
        }
        if (client.authenticated && session_requested && client.idle_timeout_seconds > 0 &&
            now - client.last_activity_at > std::chrono::seconds(client.idle_timeout_seconds)) {
            if (client.shell_requested && write_channel(client, "\r\nIdle timeout reached. Please reconnect to continue.\r\n")) {
                flush_before_disconnect(client, event_guard.value, std::chrono::milliseconds(300));
            }
            break;
        }
        if (client.shell_requested && !client.drawn) {
            show_initial_screen(client);
        }
        if (client.shell_requested && client.drawn) {
            process_incoming(client);
            drain_outgoing(client);
            if (!flush_channel_output(client)) {
                client.close_requested = true;
            }
        } else if (client.sftp_requested) {
            drain_sftp_output(client);
            if (!flush_channel_output(client)) {
                client.close_requested = true;
            }
        }
    }

    if (stop_requested != 0 && client.shell_requested && client.authenticated && client.channel != nullptr &&
        ssh_channel_is_open(client.channel) && ssh_is_connected(session)) {
        if (write_channel(client, "\r\nThe BBS is shutting down. Please reconnect shortly.\r\n")) {
            flush_before_disconnect(client, event_guard.value, std::chrono::milliseconds(300));
        }
    }

    ssh_event_remove_session(event_guard.value, session);
    if (client.channel != nullptr) {
        if (ssh_channel_is_open(client.channel)) {
            (void)ssh_channel_send_eof(client.channel);
            (void)ssh_channel_close(client.channel);
        }
        ssh_channel_free(client.channel);
        client.channel = nullptr;
    }
}

} // namespace

int run_server(const ServerConfig& config) {
    if (config.max_nodes < 1 || config.max_nodes > 32) {
        std::cerr << "Node count must be between 1 and 32.\n";
        return 2;
    }
    if (config.max_connections != 0 &&
        (config.max_connections < config.max_nodes || config.max_connections > 64)) {
        std::cerr << "Connection count must be at least the node count and no greater than 64.\n";
        return 2;
    }
    if (config.idle_timeout_seconds > 86400) {
        std::cerr << "Idle timeout must be between 0 and 86400 seconds.\n";
        return 2;
    }
    if (config.session_time_limit_minutes > 32767 || config.time_bank_max_minutes > 32767 ||
        config.time_bank_deposit_daily_limit > 32767 || config.time_bank_withdrawal_daily_limit > 32767) {
        std::cerr << "Session and time bank limits must be between 0 and 32767 minutes.\n";
        return 2;
    }
    if (config.auth_failures_per_address < 1 || config.auth_failures_per_address > 100) {
        std::cerr << "Per-address authentication failure limit must be between 1 and 100.\n";
        return 2;
    }
    if (config.auth_failure_window_seconds < 30 || config.auth_failure_window_seconds > 86400) {
        std::cerr << "Per-address authentication failure window must be between 30 and 86400 seconds.\n";
        return 2;
    }
    const int connection_limit = config.max_connections == 0
        ? std::min(config.max_nodes + 2, 64)
        : config.max_connections;

    AccountStore accounts(config.database_path);
    FileStore files(config.database_path, config.file_directory);
    MessageStore messages(config.database_path);
    CommunityStore community(config.database_path);
    try {
        accounts.initialize();
        files.initialize();
        files.recover_download_point_reservations();
        messages.initialize();
        community.initialize();
    } catch (const std::exception& error) {
        std::cerr << "Could not initialize BBS database: " << error.what() << '\n';
        return 1;
    }

    struct stat host_key_info {};
    if (::stat(config.host_key_path.c_str(), &host_key_info) != 0 || !S_ISREG(host_key_info.st_mode)) {
        std::cerr << "SSH host key is missing or is not a regular file: " << config.host_key_path << '\n'
                  << "Generate one with: ssh-keygen -t ed25519 -N '' -f " << config.host_key_path << '\n';
        return 1;
    }
    if ((host_key_info.st_mode & 0077) != 0) {
        std::cerr << "SSH host key permissions are too open; restrict it to its owner (chmod 600).\n";
        return 1;
    }

    const std::string welcome_art = load_ansi_art(config.welcome_art_path);
    if (welcome_art.empty()) {
        std::cerr << "Welcome ANSI art could not be loaded from " << config.welcome_art_path
                  << "; using the built-in screen.\n";
    } else {
        std::cout << "Loaded welcome ANSI art from " << config.welcome_art_path << ".\n";
    }
    const std::vector<AnsiArtwork> art_catalog = load_ansi_art_catalog(config.art_directory);
    std::cout << "Loaded " << art_catalog.size() << " ANSI/ASCII artwork files from "
              << config.art_directory << ".\n";
    const std::vector<AnsiArtwork> bulletin_catalog = load_ansi_art_catalog(config.bulletin_directory);
    std::cout << "Loaded " << std::min<std::size_t>(bulletin_catalog.size(), 26)
              << " bulletin files from " << config.bulletin_directory << ".\n";
    const std::vector<AnsiArtwork> quote_catalog = load_quote_catalog(config.quote_directory);
    std::cout << "Loaded " << quote_catalog.size() << " quotes from " << config.quote_directory << ".\n";
    const std::vector<AnsiArtwork> tagline_catalog = load_quote_catalog(config.tagline_directory);
    std::cout << "Loaded " << tagline_catalog.size() << " taglines from " << config.tagline_directory << ".\n";
    const auto load_screen_art = [](const std::string& path, std::string_view role) {
        if (path.empty()) {
            return std::string{};
        }
        std::string art = load_ansi_art(path);
        if (art.empty()) {
            std::cerr << role << " ANSI art could not be loaded from " << path << ".\n";
        } else {
            std::cout << "Loaded " << role << " ANSI art from " << path << ".\n";
        }
        return art;
    };
    const std::string sysop_art = load_screen_art(config.sysop_art_path, "SysOp control");
    const std::string profile_art = load_screen_art(config.profile_art_path, "User profile");
    const std::string entrance_art = load_screen_art(config.entrance_art_path, "Login entrance");
    const std::string new_caller_art = load_screen_art(
        config.new_caller_art_path, "New caller application");
    const std::string once_only_art = load_screen_art(config.once_only_art_path, "One-time login notice");
    std::string once_only_art_modified;
    if (!once_only_art.empty()) {
        std::error_code time_error;
        const std::filesystem::file_time_type file_modified =
            std::filesystem::last_write_time(config.once_only_art_path, time_error);
        if (!time_error) {
            const auto system_modified = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                file_modified - std::filesystem::file_time_type::clock::now() +
                    std::chrono::system_clock::now());
            const std::time_t modified_time = std::chrono::system_clock::to_time_t(system_modified);
            std::tm utc_modified{};
            std::array<char, 32> timestamp{};
            if (::gmtime_r(&modified_time, &utc_modified) != nullptr &&
                std::strftime(timestamp.data(), timestamp.size(), "%Y-%m-%d %H:%M:%S", &utc_modified) != 0) {
                once_only_art_modified = timestamp.data();
            }
        }
        if (once_only_art_modified.empty()) {
            std::cerr << "Could not read modification time for one-time login notice art.\n";
        }
    }
    const std::string birthday_art = load_screen_art(config.birthday_art_path, "Birthday greeting");
    const std::string birthday_late_art = load_screen_art(
        config.birthday_late_art_path, "Late birthday greeting");
    const std::string nodes_art = load_screen_art(config.nodes_art_path, "Node activity");
    const std::string callers_art = load_screen_art(config.callers_art_path, "Caller history");
    const std::string stats_art = load_screen_art(config.stats_art_path, "Statistics");
    const std::string help_art = load_screen_art(config.help_art_path, "Help");
    const std::string bbs_art = load_screen_art(config.bbs_art_path, "BBS directory");
    const std::string file_areas_art = load_screen_art(config.file_areas_art_path, "File areas");
    const std::string chat_art = load_screen_art(config.chat_art_path, "Chat");
    const std::string bulletin_art = load_screen_art(config.bulletin_art_path, "Bulletins");
    const SupplementalScreenArt supplemental_art{
        load_screen_art(config.time_bank_art_path, "Time bank"),
        load_screen_art(config.polls_art_path, "Voting"),
        load_screen_art(config.auto_message_art_path, "Auto-message"),
        load_screen_art(config.quotes_art_path, "Quotes"),
        load_screen_art(config.one_liners_art_path, "One-liners"),
        load_screen_art(config.uploads_art_path, "Upload review"),
        load_screen_art(config.quote_review_art_path, "Quote review"),
        load_screen_art(config.new_files_art_path, "New-file scan"),
        load_screen_art(config.file_validation_art_path, "File validation"),
        load_screen_art(config.download_queue_art_path, "Download queue"),
        load_screen_art(config.archive_art_path, "Archive viewer"),
        load_screen_art(config.message_move_art_path, "Message move"),
        load_screen_art(config.sysop_accounts_art_path, "SysOp accounts"),
        load_screen_art(config.sysop_account_art_path, "SysOp account review"),
        load_screen_art(config.sysop_areas_art_path, "SysOp area setup"),
        load_screen_art(config.sysop_audit_art_path, "SysOp audit"),
        load_screen_art(config.signup_questions_art_path, "Signup questions"),
        load_screen_art(config.validation_levels_art_path, "Validation levels"),
        load_screen_art(config.message_search_art_path, "Message search"),
        load_screen_art(config.message_scan_art_path, "Message scan settings"),
        load_screen_art(config.unread_messages_art_path, "Unread message scan"),
        load_screen_art(config.private_reader_art_path, "Private message reader")};
    const std::string message_art = load_screen_art(config.message_art_path, "Shared message");
    std::string areas_art = load_screen_art(config.areas_art_path, "Message areas");
    std::string board_art = load_screen_art(config.board_art_path, "Message post list");
    std::string mailbox_art = load_screen_art(config.mailbox_art_path, "Private mailbox");
    std::string reader_art = load_screen_art(config.reader_art_path, "Message reader");
    std::string editor_art = load_screen_art(config.editor_art_path, "Message editor");
    if (areas_art.empty()) {
        areas_art = !message_art.empty() ? message_art : load_screen_art(
            "assets/ansi/renegade/AREAS.ANS", "Default message areas");
    }
    if (board_art.empty()) {
        board_art = !message_art.empty() ? message_art : load_screen_art(
            "assets/ansi/renegade/MESSAGE-BOARD.ANS", "Default message board");
    }
    if (mailbox_art.empty()) {
        mailbox_art = !message_art.empty() ? message_art : board_art;
    }
    if (reader_art.empty()) {
        reader_art = !config.board_art_path.empty() && !board_art.empty() ? board_art :
            load_screen_art("assets/ansi/renegade/MESSAGE-READER.ANS", "Default message reader");
    }
    if (editor_art.empty()) {
        editor_art = load_screen_art(
            "assets/ansi/renegade/MESSAGE-WRITER.ANS", "Default message composer");
    }

    ssh_bind server = ssh_bind_new();
    if (server == nullptr) {
        std::cerr << "Could not allocate SSH listener.\n";
        return 1;
    }

    unsigned int port = config.port;
    if (ssh_bind_options_set(server, SSH_BIND_OPTIONS_BINDADDR, config.bind_address.c_str()) != SSH_OK ||
        ssh_bind_options_set(server, SSH_BIND_OPTIONS_BINDPORT, &port) != SSH_OK ||
        ssh_bind_options_set(server, SSH_BIND_OPTIONS_HOSTKEY, config.host_key_path.c_str()) != SSH_OK) {
        std::cerr << "Could not configure SSH listener: " << ssh_get_error(server) << '\n';
        ssh_bind_free(server);
        return 1;
    }
    if (ssh_bind_listen(server) != SSH_OK) {
        std::cerr << "Could not listen for SSH connections: " << ssh_get_error(server) << '\n';
        ssh_bind_free(server);
        return 1;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);

    SessionRegistry registry(config.max_nodes);
    LoginRateLimiter login_rate_limiter(
        config.auth_failures_per_address,
        std::chrono::seconds(config.auth_failure_window_seconds));
    struct Worker {
        std::thread thread;
        std::shared_ptr<std::atomic_bool> finished;
    };
    std::vector<Worker> workers;
    workers.reserve(static_cast<std::size_t>(connection_limit) * 2U);
    std::atomic_int active_connections{};
    const unsigned int idle_timeout_seconds = config.idle_timeout_seconds;
    const unsigned int birthday_check_frequency = config.birthday_check_frequency;
    const bool allow_signup = config.allow_signup;
    const unsigned int session_time_limit_minutes = config.session_time_limit_minutes;
    const unsigned int time_bank_max_minutes = config.time_bank_max_minutes;
    const unsigned int time_bank_deposit_daily_limit = config.time_bank_deposit_daily_limit;
    const unsigned int time_bank_withdrawal_daily_limit = config.time_bank_withdrawal_daily_limit;
    std::cout << "Renegade C++ listening on " << config.bind_address << ':' << config.port
              << " with " << config.max_nodes << " nodes and a " << connection_limit
              << " connection limit.\n";

    const auto reap_workers = [&workers] {
        auto worker = workers.begin();
        while (worker != workers.end()) {
            if (worker->finished != nullptr && worker->finished->load(std::memory_order_acquire)) {
                if (worker->thread.joinable()) {
                    worker->thread.join();
                }
                worker = workers.erase(worker);
            } else {
                ++worker;
            }
        }
    };

    pollfd listener{};
    listener.fd = static_cast<int>(ssh_bind_get_fd(server));
    listener.events = POLLIN;
    bool runtime_failure = false;
    while (stop_requested == 0) {
        reap_workers();
        const int ready = ::poll(&listener, 1, 250);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "Listener poll failed.\n";
            runtime_failure = true;
            stop_requested = 1;
            break;
        }
        if (ready == 0) {
            continue;
        }
        if ((listener.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            std::cerr << "SSH listener stopped unexpectedly.\n";
            runtime_failure = true;
            stop_requested = 1;
            break;
        }
        if ((listener.revents & POLLIN) == 0) {
            continue;
        }

        ssh_session session = ssh_new();
        if (session == nullptr) {
            std::cerr << "Could not allocate incoming SSH session.\n";
            continue;
        }
        if (ssh_bind_accept(server, session) != SSH_OK) {
            ssh_free(session);
            if (stop_requested == 0) {
                std::cerr << "Could not accept SSH connection: " << ssh_get_error(server) << '\n';
            }
            continue;
        }
        const int previous_connections = active_connections.fetch_add(1);
        if (previous_connections >= connection_limit) {
            active_connections.fetch_sub(1);
            (void)ssh_disconnect(session);
            ssh_free(session);
            continue;
        }
        try {
            workers.emplace_back();
            Worker& worker = workers.back();
            worker.finished = std::make_shared<std::atomic_bool>(false);
            const std::shared_ptr<std::atomic_bool> finished = worker.finished;
            worker.thread = std::thread([session, &accounts, &files, &registry, &active_connections,
                                         &login_rate_limiter,
                                         &entrance_art, &new_caller_art, &welcome_art,
                                         &once_only_art, &once_only_art_modified,
                                         &sysop_art, &profile_art,
                                         &birthday_art, &birthday_late_art,
                                         &art_catalog, &bulletin_catalog, &quote_catalog,
                                         &tagline_catalog,
                                         &messages, &community,
                                         &supplemental_art,
                                         &nodes_art, &help_art,
                                         &callers_art,
                                         &stats_art,
                                         &bbs_art,
                                         &file_areas_art,
                                         &chat_art, &bulletin_art,
                                         &areas_art, &board_art, &reader_art,
                                         &mailbox_art,
                                         &editor_art,
                                         idle_timeout_seconds, birthday_check_frequency, allow_signup,
                                         session_time_limit_minutes, time_bank_max_minutes,
                                         time_bank_deposit_daily_limit, time_bank_withdrawal_daily_limit,
                                         finished] {
                struct CompletionGuard {
                    std::shared_ptr<std::atomic_bool> finished;
                    ~CompletionGuard() { finished->store(true, std::memory_order_release); }
                } completion_guard{finished};
                struct ConnectionCountGuard {
                    std::atomic_int& count;
                    ~ConnectionCountGuard() { count.fetch_sub(1); }
                } guard{active_connections};
                try {
                    handle_client(
                        session, accounts, files, registry, login_rate_limiter,
                        entrance_art, new_caller_art, welcome_art, sysop_art, profile_art,
                        once_only_art, once_only_art_modified,
                        birthday_art, birthday_late_art,
                        art_catalog, bulletin_catalog, quote_catalog, tagline_catalog,
                        messages, community, supplemental_art,
                        nodes_art, callers_art, stats_art, help_art, bbs_art, file_areas_art,
                        chat_art, bulletin_art, areas_art, board_art,
                        mailbox_art, reader_art,
                        editor_art,
                        idle_timeout_seconds, birthday_check_frequency, allow_signup,
                        session_time_limit_minutes,
                        time_bank_max_minutes, time_bank_deposit_daily_limit,
                        time_bank_withdrawal_daily_limit);
                } catch (const std::exception& error) {
                    std::cerr << "SSH session ended with an internal error: " << error.what() << '\n';
                } catch (...) {
                    std::cerr << "SSH session ended with an unknown internal error.\n";
                }
            });
        } catch (const std::exception& error) {
            if (!workers.empty() && !workers.back().thread.joinable()) {
                workers.pop_back();
            }
            active_connections.fetch_sub(1);
            (void)ssh_disconnect(session);
            ssh_free(session);
            std::cerr << "Could not start SSH worker thread: " << error.what() << '\n';
            runtime_failure = true;
            stop_requested = 1;
            break;
        } catch (...) {
            if (!workers.empty() && !workers.back().thread.joinable()) {
                workers.pop_back();
            }
            active_connections.fetch_sub(1);
            (void)ssh_disconnect(session);
            ssh_free(session);
            std::cerr << "Could not start SSH worker thread.\n";
            runtime_failure = true;
            stop_requested = 1;
            break;
        }
    }

    for (Worker& worker : workers) {
        if (worker.thread.joinable()) {
            worker.thread.join();
        }
    }
    ssh_bind_free(server);
    return runtime_failure ? 1 : 0;
}

} // namespace renegade
