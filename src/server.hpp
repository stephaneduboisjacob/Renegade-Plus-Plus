#pragma once

#include <string>

namespace renegade {

struct ServerConfig {
    std::string bind_address{"127.0.0.1"};
    unsigned int port{2222};
    std::string host_key_path{"var/ssh_host_ed25519_key"};
    std::string database_path{"data/renegade.sqlite3"};
    std::string file_directory{"files"};
    std::string entrance_art_path{"assets/ansi/renegade/ENTRANCE.ANS"};
    std::string new_caller_art_path{"assets/ansi/renegade/NEW-CALLER.ANS"};
    std::string welcome_art_path{"assets/ansi/imported/Roy_EarlyANSI/MAINMENU.ANS"};
    std::string sysop_art_path{"assets/ansi/renegade/SYSOP.ANS"};
    std::string profile_art_path{"assets/ansi/renegade/USER-PROFILE.ANS"};
    std::string time_bank_art_path{"assets/ansi/renegade/TIME-BANK.ANS"};
    std::string once_only_art_path;
    std::string birthday_art_path{"assets/ansi/renegade/BIRTHDAY.ANS"};
    std::string birthday_late_art_path{"assets/ansi/renegade/BIRTHDAY-LATE.ANS"};
    std::string nodes_art_path{"assets/ansi/renegade/NODES.ANS"};
    std::string callers_art_path{"assets/ansi/renegade/CALLER-LOG.ANS"};
    std::string stats_art_path{"assets/ansi/renegade/STATISTICS.ANS"};
    std::string help_art_path{"assets/ansi/renegade/HELP.ANS"};
    std::string bbs_art_path{"assets/ansi/renegade/BBS-DIRECTORY.ANS"};
    std::string file_areas_art_path{"assets/ansi/imported/Roy_EarlyANSI/FILEDIR.ANS"};
    std::string chat_art_path{"assets/ansi/imported/Roy_EarlyANSI/CHATMENU.ANS"};
    std::string bulletin_art_path{"assets/ansi/renegade/BULLETINS.ANS"};
    std::string polls_art_path{"assets/ansi/renegade/VOTING.ANS"};
    std::string auto_message_art_path{"assets/ansi/renegade/AUTO-MESSAGE.ANS"};
    std::string quotes_art_path{"assets/ansi/renegade/QUOTES.ANS"};
    std::string one_liners_art_path{"assets/ansi/renegade/ONE-LINERS.ANS"};
    std::string uploads_art_path{"assets/ansi/renegade/UPLOADS.ANS"};
    std::string quote_review_art_path{"assets/ansi/renegade/QUOTE-REVIEW.ANS"};
    std::string new_files_art_path{"assets/ansi/renegade/NEW-FILES.ANS"};
    std::string file_validation_art_path{"assets/ansi/renegade/FILE-VALIDATION.ANS"};
    std::string download_queue_art_path{"assets/ansi/renegade/DOWNLOAD-QUEUE.ANS"};
    std::string archive_art_path{"assets/ansi/renegade/ARCHIVE-VIEWER.ANS"};
    std::string message_move_art_path{"assets/ansi/renegade/MESSAGE-MOVE.ANS"};
    std::string message_search_art_path{"assets/ansi/renegade/MESSAGE-SEARCH.ANS"};
    std::string message_scan_art_path{"assets/ansi/renegade/MESSAGE-SCAN.ANS"};
    std::string unread_messages_art_path{"assets/ansi/renegade/NEW-MESSAGES.ANS"};
    std::string private_reader_art_path{"assets/ansi/renegade/PRIVATE-READER.ANS"};
    std::string sysop_accounts_art_path{"assets/ansi/renegade/ACCOUNT-ADMIN.ANS"};
    std::string sysop_account_art_path{"assets/ansi/renegade/ACCOUNT-REVIEW.ANS"};
    std::string sysop_areas_art_path{"assets/ansi/renegade/AREA-ADMIN.ANS"};
    std::string sysop_audit_art_path{"assets/ansi/renegade/SYSOP-AUDIT.ANS"};
    std::string signup_questions_art_path{"assets/ansi/renegade/SIGNUP-QUESTIONS.ANS"};
    std::string validation_levels_art_path{"assets/ansi/renegade/VALIDATION-LEVELS.ANS"};
    std::string message_art_path{"assets/ansi/imported/Roy_EarlyANSI/MMSMENU.ANS"};
    std::string areas_art_path;
    std::string board_art_path;
    std::string mailbox_art_path{"assets/ansi/renegade/MAILBOX.ANS"};
    std::string reader_art_path;
    std::string editor_art_path;
    std::string art_directory{"assets/ansi"};
    std::string bulletin_directory{"bulletins"};
    std::string quote_directory{"quotes"};
    std::string tagline_directory{"taglines"};
    int max_nodes{4};
    int max_connections{};
    bool allow_signup{};
    unsigned int idle_timeout_seconds{1800};
    unsigned int birthday_check_frequency{};
    unsigned int session_time_limit_minutes{};
    unsigned int time_bank_max_minutes{};
    unsigned int time_bank_deposit_daily_limit{};
    unsigned int time_bank_withdrawal_daily_limit{};
    unsigned int auth_failures_per_address{10};
    unsigned int auth_failure_window_seconds{300};
};

int run_server(const ServerConfig& config);

} // namespace renegade
