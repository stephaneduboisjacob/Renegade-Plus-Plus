#pragma once

#include <string>
#include <string_view>
#include <optional>
#include <vector>

#include "account_store.hpp"
#include "archive_store.hpp"
#include "community_store.hpp"
#include "file_store.hpp"
#include "message_store.hpp"

namespace renegade {

struct NodeInfo {
    int number{};
    std::string handle;
    bool in_chat{};
    bool invisible{};
};

struct AnsiArtwork {
    std::string name;
    std::string contents;
};

struct RenderedMessagePage {
    std::string screen;
    std::size_t page_count{};
};

struct RenderedAreaPage {
    std::string screen;
    std::size_t page_count{};
};

struct RenderedAutoMessagePage {
    std::string screen;
    std::size_t page_count{1};
};

struct RenderedQuotePage {
    std::string screen;
    std::size_t page{};
    std::size_t page_count{1};
};

[[nodiscard]] std::string account_admin_screen(
    const std::vector<AccountSummary>& accounts,
    std::size_t page,
    std::optional<std::size_t> selected_index,
    int columns,
    int rows,
    std::string_view screen_art = {});
[[nodiscard]] std::string signup_question_admin_screen(
    const std::array<bool, 27>& enabled,
    std::string_view recovery_question,
    const std::array<std::string, 3>& user_questions,
    int editing_user_question,
    std::string_view user_question_input,
    bool preferences_page,
    int columns,
    int rows,
    std::string_view screen_art = {},
    std::size_t selected_index = 0,
    std::size_t selected_prompt_index = 0);
[[nodiscard]] std::string validation_level_admin_screen(
    const std::vector<ValidationLevel>& levels,
    std::size_t page,
    std::size_t selected_index,
    char edit_operation,
    std::string_view input,
    std::string_view notice,
    int columns,
    int rows,
    std::string_view screen_art = {});
[[nodiscard]] std::string account_review_screen(
    const AccountSummary& account,
    bool editing_security_levels,
    bool editing_acs_flags,
    bool editing_credits,
    bool editing_file_points,
    bool editing_birth_date,
    bool editing_sex,
    bool editing_expiration_date,
    bool editing_validation_level,
    bool confirming_validation_level,
    bool editing_profile,
    char profile_field,
    bool editing_short_message,
    std::string_view security_level_input,
    int columns,
    int rows,
    std::string_view screen_art = {},
    std::size_t selected_action = 0);
[[nodiscard]] std::string validation_preview_screen(
    const AccountSummary& account,
    const ValidationLevel& level,
    std::string_view new_ar_flags,
    std::string_view new_ac_flags,
    std::int64_t new_credits,
    std::int64_t new_file_points,
    int columns,
    int rows,
    std::string_view screen_art = {});
[[nodiscard]] std::string sysop_audit_screen(
    const SysopAuditPage& page,
    int columns,
    int rows,
    std::string_view screen_art = {});

[[nodiscard]] std::string sysop_area_admin_screen(
    const std::vector<BoardArea>& message_areas,
    const std::vector<FileAreaSummary>& file_areas,
    bool entering_name,
    bool is_file_area,
    bool renaming_file_area,
    bool renaming_message_area,
    bool deleting_file_area,
    bool editing_file_area_access,
    bool editing_message_area_access,
    bool editing_message_force_read,
    bool editing_message_area_password,
    bool editing_message_taglines,
    bool editing_message_filter,
    bool editing_message_unhidden,
    bool editing_message_tearline,
    bool editing_message_origin,
    bool editing_message_real_names,
    bool editing_message_quote_templates,
    bool editing_private_quote_templates,
    bool editing_global_anonymous_acs,
    bool editing_global_post_acs,
    bool editing_global_post_limits,
    bool editing_global_credit_costs,
    bool editing_global_mail_limits,
    std::string_view file_policy_prompt,
    bool confirming_file_area_deletion,
    bool deleting_message_area,
    bool confirming_message_area_deletion,
    long long deletion_area_id,
    std::string_view deletion_area_name,
    std::string_view input,
    std::string_view notice,
    int columns,
    int rows,
    std::string_view screen_art = {},
    std::size_t selected_action = 0);

[[nodiscard]] std::string profile_screen(
    const AccountProfile& profile,
    bool contact_page,
    int columns,
    int rows,
    std::string_view screen_art = {},
    std::size_t selected_action = 0);
[[nodiscard]] std::string time_bank_screen(
    const TimeBankStatus& status,
    std::optional<int> remaining_minutes,
    int bank_limit,
    int deposit_daily_limit,
    int withdrawal_daily_limit,
    bool entering_amount,
    bool depositing,
    std::string_view input,
    int columns,
    int rows,
    std::string_view screen_art = {},
    std::size_t selected_action = 0);

[[nodiscard]] std::vector<AnsiArtwork> load_ansi_art_catalog(std::string_view directory);
[[nodiscard]] std::vector<AnsiArtwork> load_quote_catalog(std::string_view directory);
[[nodiscard]] RenderedQuotePage quote_screen(
    const AnsiArtwork& quote,
    std::size_t index,
    std::size_t total,
    std::size_t page,
    int columns,
    int rows,
    std::string_view screen_art = {});
[[nodiscard]] std::string quote_review_screen(
    const QuoteSubmissionPage& page,
    std::optional<std::int64_t> selected_id,
    int columns,
    int rows,
    std::string_view screen_art = {});
[[nodiscard]] std::string bbs_directory_screen(
    const BbsListingPage& page,
    std::optional<std::int64_t> selected_id,
    int columns,
    int rows,
    std::string_view screen_art = {});
[[nodiscard]] std::string bbs_listing_detail_screen(
    const BbsListing& listing,
    std::size_t detail_page,
    bool can_manage,
    int columns,
    int rows,
    std::string_view screen_art = {});
[[nodiscard]] std::string short_messages_screen(
    const std::vector<ShortMessage>& messages,
    std::size_t page,
    int columns,
    int rows,
    std::string_view screen_art = {});

[[nodiscard]] std::string welcome_screen(
    std::string_view handle,
    int node_number,
    int columns,
    int rows,
    std::string_view welcome_art = {},
    bool is_sysop = false,
    std::string_view tagline = {},
    bool hotkeys = true,
    bool expert_mode = false,
    std::size_t selected_index = 0);
[[nodiscard]] std::string_view welcome_menu_keys(bool is_sysop);
[[nodiscard]] std::string entrance_screen(
    std::string_view handle,
    int node_number,
    int columns,
    int rows,
    std::string_view entrance_art = {});

[[nodiscard]] std::string load_ansi_art(std::string_view path);
[[nodiscard]] std::string sanitize_terminal_art(std::string_view source);
[[nodiscard]] std::string sanitize_terminal_text(std::string_view source);
[[nodiscard]] std::string artwork_screen(
    const AnsiArtwork& artwork,
    std::size_t index,
    std::size_t total,
    int columns,
    int rows);
[[nodiscard]] std::string bulletin_list_screen(
    const std::vector<AnsiArtwork>& bulletins,
    int columns,
    int rows,
    std::string_view bulletin_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string bulletin_article_screen(
    const AnsiArtwork& bulletin,
    std::size_t index,
    std::size_t total,
    int columns,
    int rows);
[[nodiscard]] std::string polls_screen(
    const std::vector<Poll>& polls,
    std::size_t page,
    int columns,
    int rows,
    bool sysop,
    std::string_view screen_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string poll_detail_screen(
    const Poll& poll,
    std::size_t choice_page,
    bool show_results,
    bool sysop,
    bool changing_vote,
    int columns,
    int rows,
    std::string_view screen_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string callers_screen(
    const CallerSessionPage& page,
    int columns,
    int rows,
    std::string_view callers_art = {});
[[nodiscard]] std::string statistics_screen(
    const CommunityStatistics& statistics,
    std::size_t page,
    int columns,
    int rows,
    std::string_view stats_art = {});
[[nodiscard]] RenderedAutoMessagePage auto_message_screen(
    const std::optional<AutoMessage>& message,
    bool may_read_anonymous,
    bool sysop,
    std::size_t page,
    int columns,
    int rows,
    std::string_view message_art = {});

[[nodiscard]] std::string nodes_screen(
    const std::vector<NodeInfo>& nodes,
    int node_number,
    int columns,
    int rows,
    bool may_toggle_invisible = false,
    bool invisible = false,
    bool may_toggle_availability = false,
    bool sysop_available = false,
    std::string_view nodes_art = {});

[[nodiscard]] std::string help_screen(int columns, int rows, std::string_view help_art = {});
[[nodiscard]] std::string file_areas_screen(
    const std::vector<FileAreaSummary>& areas,
    std::size_t page,
    bool choosing_scan_area,
    bool sysop,
    int columns,
    int rows,
    std::string_view file_areas_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string file_validation_screen(
    const FileValidationPage& page,
    bool confirm_bulk_validation,
    int columns,
    int rows,
    std::string_view file_areas_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string new_file_scan_screen(
    const NewFilePage& page,
    std::string_view since,
    int columns,
    int rows,
    std::string_view file_areas_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string file_listing_screen(
    const FilePage& page,
    int area_id,
    std::string_view area_name,
    std::string_view search,
    int columns,
    int rows,
    std::string_view file_areas_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string file_detail_screen(
    const FileEntry& file,
    std::string_view area_name,
    bool tagged,
    bool sysop,
    bool confirm_delete,
    bool confirm_credit_withdrawal,
    int columns,
    int rows,
    std::string_view file_areas_art = {});
[[nodiscard]] std::string extended_file_description_screen(
    const FileEntry& file,
    std::string_view area_name,
    std::size_t page,
    bool sysop,
    int columns,
    int rows,
    std::string_view file_areas_art = {});
[[nodiscard]] std::string file_description_edit_screen(
    const FileEntry& file,
    std::string_view input,
    int columns,
    int rows,
    std::string_view file_areas_art = {});
[[nodiscard]] std::string extended_file_description_edit_screen(
    const FileEntry& file,
    const std::vector<std::string>& draft_lines,
    std::string_view input,
    int columns,
    int rows,
    std::string_view file_areas_art = {});
[[nodiscard]] std::string download_queue_screen(
    const std::vector<DownloadQueueEntry>& files,
    std::size_t page,
    bool confirming_clear,
    int columns,
    int rows,
    std::string_view file_areas_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string archive_listing_screen(
    const ArchiveListing& archive,
    std::string_view archive_name,
    std::size_t page,
    int columns,
    int rows,
    std::string_view file_areas_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string archive_entry_detail_screen(
    const ArchiveEntry& entry,
    std::string_view parent_archive,
    int columns,
    int rows,
    std::string_view file_areas_art = {});
[[nodiscard]] std::string archive_text_screen(
    std::string_view name,
    const std::vector<std::string>& lines,
    std::size_t page,
    int columns,
    int rows,
    std::string_view file_areas_art = {});
[[nodiscard]] std::string upload_review_screen(
    const std::vector<IncomingFile>& uploads,
    std::size_t page,
    int columns,
    int rows,
    std::string_view file_areas_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string upload_detail_screen(
    const IncomingFile& upload,
    bool confirm_delete,
    int columns,
    int rows,
    std::string_view file_areas_art = {});
[[nodiscard]] std::string upload_publish_area_screen(
    const IncomingFile& upload,
    const std::vector<FileAreaSummary>& areas,
    std::size_t page,
    int columns,
    int rows,
    std::string_view file_areas_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string one_liners_screen(
    const OneLinerPage& page,
    bool sysop,
    bool may_read_anonymous,
    std::optional<std::int64_t> selected_id,
    int columns,
    int rows,
    std::string_view screen_art = {});
[[nodiscard]] RenderedAreaPage message_areas_screen(
    const std::vector<BoardArea>& areas,
    std::size_t page,
    std::string_view current_area,
    int columns,
    int rows,
    std::string_view message_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string message_scan_settings_screen(
    const std::vector<BoardArea>& areas,
    std::size_t page,
    int columns,
    int rows,
    std::string_view message_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string message_board_screen(
    const std::vector<BoardMessage>& messages,
    const std::vector<std::string>& message_areas,
    std::string_view area_name,
    std::size_t page,
    std::size_t page_count,
    std::size_t total,
    std::size_t unread_total,
    bool unread_only,
    bool search_results,
    bool can_validate_all,
    int columns,
    int rows,
    std::string_view message_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string message_search_screen(
    std::string_view area_name,
    std::string_view query,
    bool entering_query,
    bool new_only,
    bool all_areas,
    int columns,
    int rows,
    std::string_view message_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string message_move_screen(
    const std::vector<BoardArea>& targets,
    std::string_view source_area,
    long long message_id,
    std::size_t page,
    std::size_t page_count,
    bool confirming,
    bool private_target_available,
    std::string_view target_area,
    int columns,
    int rows,
    std::string_view message_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string unread_messages_screen(
    const UnreadBoardPage& page,
    int columns,
    int rows,
    std::string_view message_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] std::string private_mailbox_screen(
    const std::vector<PrivateMessage>& messages,
    PrivateMailbox mailbox,
    std::size_t page,
    std::size_t page_count,
    std::size_t total,
    std::size_t unread_total,
    int columns,
    int rows,
    std::string_view mailbox_art = {},
    std::size_t selected_index = 0);
[[nodiscard]] RenderedMessagePage message_reader_screen(
    const BoardMessage& message,
    bool can_toggle_deleted,
    bool can_validate,
    bool can_edit,
    std::size_t page,
    int columns,
    int rows,
    std::string_view reader_art = {});
[[nodiscard]] RenderedMessagePage private_message_reader_screen(
    const PrivateMessage& message,
    bool allow_reply,
    bool allow_forward,
    bool allow_edit,
    bool allow_move,
    bool allow_extract,
    std::size_t page,
    int columns,
    int rows,
    std::string_view reader_art = {});
[[nodiscard]] std::string chat_screen(
    std::string_view handle,
    int node_number,
    int columns = 80,
    int rows = 25,
    std::string_view chat_art = {},
    std::string_view chat_input = {});

} // namespace renegade
