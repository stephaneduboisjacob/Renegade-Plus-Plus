#include "message_store.hpp"

#include "account_store.hpp"
#include "legacy_acs.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <charconv>
#include <exception>
#include <filesystem>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>

namespace renegade {
namespace {

class Database final {
public:
    explicit Database(const std::string& path, int flags) {
        const int result = sqlite3_open_v2(path.c_str(), &handle_, flags, nullptr);
        if (result != SQLITE_OK) {
            const std::string message = handle_ != nullptr
                ? sqlite3_errmsg(handle_)
                : "could not allocate SQLite handle";
            if (handle_ != nullptr) {
                sqlite3_close(handle_);
                handle_ = nullptr;
            }
            throw std::runtime_error("opening message database: " + message);
        }
        sqlite3_busy_timeout(handle_, 5000);
        (void)sqlite3_exec(handle_, "PRAGMA foreign_keys = ON", nullptr, nullptr, nullptr);
    }

    ~Database() {
        if (handle_ != nullptr) {
            sqlite3_close(handle_);
        }
    }

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    [[nodiscard]] sqlite3* get() const noexcept { return handle_; }

private:
    sqlite3* handle_{};
};

class Statement final {
public:
    Statement(sqlite3* database, const char* sql) {
        if (sqlite3_prepare_v2(database, sql, -1, &statement_, nullptr) != SQLITE_OK) {
            throw std::runtime_error("preparing message query: " + std::string(sqlite3_errmsg(database)));
        }
    }

    ~Statement() { sqlite3_finalize(statement_); }
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    [[nodiscard]] sqlite3_stmt* get() const noexcept { return statement_; }

private:
    sqlite3_stmt* statement_{};
};

void check_sqlite(sqlite3* database, int result, std::string_view operation) {
    if (result != SQLITE_OK && result != SQLITE_DONE && result != SQLITE_ROW) {
        throw std::runtime_error(std::string(operation) + ": " + sqlite3_errmsg(database));
    }
}

void execute_sql(sqlite3* database, const char* sql, std::string_view operation) {
    char* error = nullptr;
    const int result = sqlite3_exec(database, sql, nullptr, nullptr, &error);
    if (result != SQLITE_OK) {
        const std::string message = error != nullptr ? error : sqlite3_errmsg(database);
        sqlite3_free(error);
        throw std::runtime_error(std::string(operation) + ": " + message);
    }
}

void bind_text(sqlite3* database, sqlite3_stmt* statement, int index, std::string_view value) {
    const int result = sqlite3_bind_text(
        statement, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
    check_sqlite(database, result, "binding message data");
}

std::string column_text(sqlite3_stmt* statement, int column);

std::string message_setting(sqlite3* database, std::string_view key, std::string_view fallback) {
    Statement table(database,
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'message_store_meta'");
    if (sqlite3_step(table.get()) != SQLITE_ROW) {
        return std::string(fallback);
    }
    Statement statement(database, "SELECT value FROM message_store_meta WHERE key = ?1");
    bind_text(database, statement.get(), 1, key);
    const int result = sqlite3_step(statement.get());
    check_sqlite(database, result, "reading message-system setting");
    return result == SQLITE_ROW ? column_text(statement.get(), 0) : std::string(fallback);
}

int message_count_limit(sqlite3* database, std::string_view key) {
    const std::string value = message_setting(database, key, "255");
    int parsed{};
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (value.empty() || result.ec != std::errc{} || result.ptr != value.data() + value.size() ||
        parsed < 0 || parsed > 255) {
        return 0;
    }
    return parsed;
}

int message_credit_cost(sqlite3* database, std::string_view key) {
    const std::string value = message_setting(database, key, "0");
    int parsed{};
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (value.empty() || result.ec != std::errc{} || result.ptr != value.data() + value.size() ||
        parsed < -32767 || parsed > 32767) {
        return 0;
    }
    return parsed;
}

std::int64_t account_credit_balance(sqlite3* database, std::string_view handle) {
    Statement statement(database, "SELECT credits FROM accounts WHERE handle = ?1 COLLATE NOCASE");
    bind_text(database, statement.get(), 1, handle);
    const int result = sqlite3_step(statement.get());
    check_sqlite(database, result, "reading account credit balance");
    if (result == SQLITE_DONE) {
        throw std::invalid_argument("BBS account does not exist");
    }
    return sqlite3_column_int64(statement.get(), 0);
}

void set_account_credit_balance(sqlite3* database, std::string_view handle, std::int64_t balance) {
    if (balance < std::numeric_limits<std::int32_t>::min() ||
        balance > std::numeric_limits<std::int32_t>::max()) {
        throw std::invalid_argument("message credit adjustment would exceed the account balance range");
    }
    Statement statement(database, "UPDATE accounts SET credits = ?1 WHERE handle = ?2 COLLATE NOCASE");
    check_sqlite(database, sqlite3_bind_int64(statement.get(), 1, balance), "binding account credit balance");
    bind_text(database, statement.get(), 2, handle);
    check_sqlite(database, sqlite3_step(statement.get()), "saving account credit balance");
    if (sqlite3_changes(database) == 0) {
        throw std::invalid_argument("BBS account does not exist");
    }
}

void ensure_private_recipient_accepts_mail(
    sqlite3* database, std::string_view recipient, bool sender_is_sysop) {
    Statement account(database,
        "SELECT mailbox_closed, is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
    bind_text(database, account.get(), 1, recipient);
    const int account_result = sqlite3_step(account.get());
    check_sqlite(database, account_result, "checking private-mail recipient mailbox");
    if (account_result != SQLITE_ROW) {
        throw std::invalid_argument("private-mail recipient account does not exist");
    }
    const bool recipient_is_sysop = sqlite3_column_int(account.get(), 1) != 0;
    if (!sender_is_sysop && sqlite3_column_int(account.get(), 0) != 0) {
        throw std::invalid_argument("the recipient's private mailbox is closed");
    }
    if (sender_is_sysop) {
        return;
    }
    const int waiting_limit = message_count_limit(database,
        recipient_is_sysop ? "max_sysop_mail_waiting" : "max_mail_waiting");

    Statement waiting(database,
        "SELECT COUNT(*) FROM private_messages AS messages "
        "LEFT JOIN private_message_reads AS read_marks ON read_marks.message_id = messages.id "
        "AND read_marks.user_handle = messages.recipient_handle "
        "WHERE messages.recipient_handle = ?1 COLLATE NOCASE AND messages.deleted = 0 "
        "AND read_marks.message_id IS NULL");
    bind_text(database, waiting.get(), 1, recipient);
    const int waiting_result = sqlite3_step(waiting.get());
    check_sqlite(database, waiting_result, "counting unread private mail for recipient");
    if (sqlite3_column_int64(waiting.get(), 0) >= waiting_limit) {
        throw std::invalid_argument("the recipient's private mailbox is full");
    }
}

std::string column_text(sqlite3_stmt* statement, int column) {
    const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(statement, column));
    const int bytes = sqlite3_column_bytes(statement, column);
    return value == nullptr || bytes <= 0 ? std::string{} : std::string(value, static_cast<std::size_t>(bytes));
}

BoardMessage read_message(sqlite3_stmt* statement) {
    BoardMessage message{
        sqlite3_column_int64(statement, 0),
        column_text(statement, 1),
        column_text(statement, 2),
        column_text(statement, 3),
        column_text(statement, 4),
        sqlite3_column_type(statement, 5) == SQLITE_NULL
            ? std::nullopt
            : std::optional<long long>(static_cast<long long>(sqlite3_column_int64(statement, 5))),
        false,
        false,
        false,
        false,
        false,
        {},
        {},
        {},
        0,
    };
    message.owner_handle = message.author;
    if (sqlite3_column_count(statement) > 6) {
        message.allow_mci = sqlite3_column_int(statement, 6) != 0;
    }
    if (sqlite3_column_count(statement) > 7) {
        message.deleted = sqlite3_column_int(statement, 7) != 0;
    }
    if (sqlite3_column_count(statement) > 8) {
        message.unread = sqlite3_column_int(statement, 8) != 0;
    }
    if (sqlite3_column_count(statement) > 9) {
        message.unvalidated = sqlite3_column_int(statement, 9) != 0;
    }
    if (sqlite3_column_count(statement) > 10) {
        message.permanent = sqlite3_column_int(statement, 10) != 0;
    }
    if (sqlite3_column_count(statement) > 11) {
        message.recipient = column_text(statement, 11);
    }
    if (sqlite3_column_count(statement) > 12) {
        message.anonymous_type = sqlite3_column_int(statement, 12);
    }
    if (sqlite3_column_count(statement) > 13) {
        message.posted_as = column_text(statement, 13);
    }
    switch (message.anonymous_type) {
    case 1:
    case 2:
        message.author = "Anonymous";
        break;
    case 3:
        message.author = "Abby";
        break;
    case 4:
        message.author = "Problemed Person";
        break;
    case 5:
        message.author = message.posted_as;
        break;
    default:
        break;
    }
    return message;
}

void reveal_anonymous_author(BoardMessage& message, bool may_see_identity) {
    if (message.anonymous_type == 0) {
        return;
    }
    if (may_see_identity && !message.owner_handle.empty()) {
        message.author += " (" + message.owner_handle + ")";
    }
}

PrivateMessage read_private_message(sqlite3_stmt* statement) {
    PrivateMessage message{
        sqlite3_column_int64(statement, 0),
        column_text(statement, 1),
        column_text(statement, 2),
        column_text(statement, 3),
        column_text(statement, 4),
        column_text(statement, 5),
        sqlite3_column_type(statement, 6) == SQLITE_NULL
            ? std::nullopt
            : std::optional<long long>(static_cast<long long>(sqlite3_column_int64(statement, 6))),
        false,
        false,
        {},
        0,
        {},
        false,
    };
    if (sqlite3_column_count(statement) > 7) {
        message.unread = sqlite3_column_int(statement, 7) != 0;
    }
    if (sqlite3_column_count(statement) > 8) {
        message.deleted = sqlite3_column_int(statement, 8) != 0;
    }
    message.sender_handle = message.sender;
    if (sqlite3_column_count(statement) > 9) {
        message.anonymous_type = sqlite3_column_int(statement, 9);
    }
    if (sqlite3_column_count(statement) > 10) {
        message.posted_as = column_text(statement, 10);
    }
    return message;
}

bool has_private_message_column(sqlite3* database, std::string_view name);

void apply_private_sender_visibility(
    PrivateMessage& message, bool may_see_anonymous_details) {
    message.anonymous_details_visible = message.anonymous_type == 0 || may_see_anonymous_details;
    switch (message.anonymous_type) {
    case 1:
    case 2:
        message.sender = "Anonymous";
        break;
    case 3:
        message.sender = "Abby";
        break;
    case 4:
        message.sender = "Problemed Person";
        break;
    case 5:
        message.sender = message.posted_as.empty() ? "Anonymous" : message.posted_as;
        break;
    default:
        message.sender = message.sender_handle;
        break;
    }
}

void migrate_private_anonymous_metadata(sqlite3* database) {
    bool has_legacy_anonymous_limit = false;
    {
        Statement statement(database,
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'private_messages'");
        const int result = sqlite3_step(statement.get());
        check_sqlite(database, result, "checking private-message identity constraint");
        has_legacy_anonymous_limit = result == SQLITE_ROW &&
            column_text(statement.get(), 0).find("BETWEEN 0 AND 2") != std::string::npos;
    }
    const bool has_posted_as = has_private_message_column(database, "posted_as");
    if (!has_legacy_anonymous_limit && has_posted_as) {
        return;
    }

    execute_sql(database, "PRAGMA foreign_keys = OFF",
        "disabling foreign keys for private-message identity migration");
    execute_sql(database, "BEGIN IMMEDIATE", "starting private-message identity migration");
    try {
        execute_sql(database,
            "CREATE TABLE private_messages_identity ("
            "id INTEGER PRIMARY KEY,"
            "sender_handle TEXT NOT NULL COLLATE NOCASE REFERENCES accounts(handle),"
            "recipient_handle TEXT NOT NULL COLLATE NOCASE REFERENCES accounts(handle),"
            "subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 80),"
            "body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 157000),"
            "reply_to INTEGER REFERENCES private_messages_identity(id),"
            "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),"
            "anonymous_type INTEGER NOT NULL DEFAULT 0 CHECK(anonymous_type BETWEEN 0 AND 5),"
            "posted_as TEXT NOT NULL DEFAULT '' CHECK(length(posted_as) <= 36)"
            ")",
            "creating private-message identity table");
        const std::string posted_as = has_posted_as ? "posted_as" : "''";
        const std::string copy_sql =
            "INSERT INTO private_messages_identity(id, sender_handle, recipient_handle, subject, body, "
            "reply_to, created_at, deleted, anonymous_type, posted_as) "
            "SELECT id, sender_handle, recipient_handle, subject, body, reply_to, created_at, deleted, "
            "anonymous_type, " + posted_as + " FROM private_messages";
        execute_sql(database, copy_sql.c_str(), "copying private messages to identity table");
        execute_sql(database, "DROP TABLE private_messages",
            "replacing private-message identity table");
        execute_sql(database, "ALTER TABLE private_messages_identity RENAME TO private_messages",
            "installing private-message identity table");
        execute_sql(database,
            "CREATE INDEX IF NOT EXISTS private_messages_recipient_order "
            "ON private_messages(recipient_handle, id DESC)",
            "rebuilding private-message recipient index");
        execute_sql(database,
            "CREATE INDEX IF NOT EXISTS private_messages_sender_order "
            "ON private_messages(sender_handle, id DESC)",
            "rebuilding private-message sender index");
        execute_sql(database, "COMMIT", "committing private-message identity migration");
    } catch (...) {
        (void)sqlite3_exec(database, "ROLLBACK", nullptr, nullptr, nullptr);
        (void)sqlite3_exec(database, "PRAGMA foreign_keys = ON", nullptr, nullptr, nullptr);
        throw;
    }
    execute_sql(database, "PRAGMA foreign_keys = ON",
        "reenabling foreign keys after private-message identity migration");
}

bool has_reply_column(sqlite3* database) {
    Statement statement(database, "PRAGMA table_info(messages)");
    for (;;) {
        const int result = sqlite3_step(statement.get());
        if (result == SQLITE_DONE) {
            return false;
        }
        check_sqlite(database, result, "checking message schema");
        if (column_text(statement.get(), 1) == "reply_to") {
            return true;
        }
    }
}

bool has_area_column(sqlite3* database, std::string_view name) {
    Statement statement(database, "PRAGMA table_info(message_areas)");
    for (;;) {
        const int result = sqlite3_step(statement.get());
        if (result == SQLITE_DONE) {
            return false;
        }
        check_sqlite(database, result, "checking message-area schema");
        if (column_text(statement.get(), 1) == name) {
            return true;
        }
    }
}

bool has_message_column(sqlite3* database, std::string_view name) {
    Statement statement(database, "PRAGMA table_info(messages)");
    for (;;) {
        const int result = sqlite3_step(statement.get());
        if (result == SQLITE_DONE) {
            return false;
        }
        check_sqlite(database, result, "checking message schema");
        if (column_text(statement.get(), 1) == name) {
            return true;
        }
    }
}

bool has_private_message_column(sqlite3* database, std::string_view name) {
    Statement statement(database, "PRAGMA table_info(private_messages)");
    for (;;) {
        const int result = sqlite3_step(statement.get());
        if (result == SQLITE_DONE) {
            return false;
        }
        check_sqlite(database, result, "checking private-message schema");
        if (column_text(statement.get(), 1) == name) {
            return true;
        }
    }
}

bool table_has_old_body_limit(sqlite3* database, std::string_view table_name) {
    Statement statement(database,
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1");
    bind_text(database, statement.get(), 1, table_name);
    const int result = sqlite3_step(statement.get());
    check_sqlite(database, result, "checking message body storage limit");
    return result == SQLITE_ROW && column_text(statement.get(), 0).find("4000") != std::string::npos;
}

void migrate_message_body_limits(sqlite3* database) {
    const bool rebuild_public = table_has_old_body_limit(database, "messages");
    const bool rebuild_private = table_has_old_body_limit(database, "private_messages");
    if (!rebuild_public && !rebuild_private) {
        return;
    }

    execute_sql(database, "PRAGMA foreign_keys = OFF", "disabling foreign keys for message migration");
    execute_sql(database, "BEGIN IMMEDIATE", "starting message body-limit migration");
    try {
        if (rebuild_public) {
            execute_sql(database,
                "CREATE TABLE messages_wide ("
                "id INTEGER PRIMARY KEY,"
                "area_id INTEGER NOT NULL REFERENCES message_areas(id),"
                "author_handle TEXT NOT NULL,"
                "subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 80),"
                "body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 157000),"
                "reply_to INTEGER REFERENCES messages_wide(id),"
                "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "allow_mci INTEGER NOT NULL DEFAULT 0 CHECK(allow_mci IN (0,1)),"
                "deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),"
                "unvalidated INTEGER NOT NULL DEFAULT 0 CHECK(unvalidated IN (0,1)),"
                "permanent INTEGER NOT NULL DEFAULT 0 CHECK(permanent IN (0,1)),"
                "recipient TEXT NOT NULL DEFAULT 'All' CHECK(length(recipient) BETWEEN 1 AND 36),"
                "anonymous_type INTEGER NOT NULL DEFAULT 0 CHECK(anonymous_type BETWEEN 0 AND 5),"
                "posted_as TEXT NOT NULL DEFAULT '' CHECK(length(posted_as) <= 36)"
                ")",
                "creating expanded public-message table");
            execute_sql(database,
                "INSERT INTO messages_wide(id, area_id, author_handle, subject, body, reply_to, created_at, "
                "allow_mci, deleted, unvalidated, permanent, recipient, anonymous_type, posted_as) "
                "SELECT id, area_id, author_handle, subject, body, reply_to, created_at, allow_mci, deleted, "
                "unvalidated, permanent, recipient, anonymous_type, posted_as FROM messages",
                "copying public messages to expanded table");
            execute_sql(database, "DROP TABLE messages", "replacing old public-message table");
            execute_sql(database, "ALTER TABLE messages_wide RENAME TO messages",
                "installing expanded public-message table");
            execute_sql(database,
                "CREATE INDEX IF NOT EXISTS messages_author_order_nocase "
                "ON messages(author_handle COLLATE NOCASE, id DESC)",
                "rebuilding public-message author index");
            execute_sql(database,
                "CREATE INDEX IF NOT EXISTS messages_area_order ON messages(area_id, id DESC)",
                "rebuilding public-message area index");
        }
        if (rebuild_private) {
            execute_sql(database,
                "CREATE TABLE private_messages_wide ("
                "id INTEGER PRIMARY KEY,"
                "sender_handle TEXT NOT NULL COLLATE NOCASE REFERENCES accounts(handle),"
                "recipient_handle TEXT NOT NULL COLLATE NOCASE REFERENCES accounts(handle),"
                "subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 80),"
                "body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 157000),"
                "reply_to INTEGER REFERENCES private_messages_wide(id),"
                "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),"
                "anonymous_type INTEGER NOT NULL DEFAULT 0 CHECK(anonymous_type BETWEEN 0 AND 5),"
                "posted_as TEXT NOT NULL DEFAULT '' CHECK(length(posted_as) <= 36)"
                ")",
                "creating expanded private-message table");
            const std::string posted_as = has_private_message_column(database, "posted_as")
                ? "posted_as" : "''";
            const std::string copy_sql =
                "INSERT INTO private_messages_wide(id, sender_handle, recipient_handle, subject, body, reply_to, "
                "created_at, deleted, anonymous_type, posted_as) "
                "SELECT id, sender_handle, recipient_handle, subject, body, reply_to, created_at, deleted, "
                "anonymous_type, " + posted_as + " FROM private_messages";
            execute_sql(database, copy_sql.c_str(), "copying private messages to expanded table");
            execute_sql(database, "DROP TABLE private_messages", "replacing old private-message table");
            execute_sql(database, "ALTER TABLE private_messages_wide RENAME TO private_messages",
                "installing expanded private-message table");
            execute_sql(database,
                "CREATE INDEX IF NOT EXISTS private_messages_recipient_order "
                "ON private_messages(recipient_handle, id DESC)",
                "rebuilding private-message recipient index");
            execute_sql(database,
                "CREATE INDEX IF NOT EXISTS private_messages_sender_order "
                "ON private_messages(sender_handle, id DESC)",
                "rebuilding private-message sender index");
        }
        execute_sql(database, "COMMIT", "committing message body-limit migration");
    } catch (...) {
        (void)sqlite3_exec(database, "ROLLBACK", nullptr, nullptr, nullptr);
        (void)sqlite3_exec(database, "PRAGMA foreign_keys = ON", nullptr, nullptr, nullptr);
        throw;
    }
    execute_sql(database, "PRAGMA foreign_keys = ON", "reenabling foreign keys after message migration");
}

bool caller_session_column_exists(sqlite3* database, std::string_view name) {
    Statement columns(database, "PRAGMA table_info(caller_sessions)");
    for (;;) {
        const int result = sqlite3_step(columns.get());
        if (result == SQLITE_DONE) {
            return false;
        }
        check_sqlite(database, result, "checking caller-session time-limit schema");
        const auto* column = reinterpret_cast<const char*>(sqlite3_column_text(columns.get(), 1));
        if (column != nullptr && std::string_view(column) == name) {
            return true;
        }
    }
}

AccessLevels account_access_levels(sqlite3* database, std::string_view handle) {
    Statement statement(database,
        "SELECT security_level, download_security_level, is_sysop, acs_ar_flags, acs_ac_flags, credits, rowid, birth_date, sex, expert_mode, expiration_date "
        "FROM accounts WHERE handle = ?1 COLLATE NOCASE");
    bind_text(database, statement.get(), 1, handle);
    const int result = sqlite3_step(statement.get());
    check_sqlite(database, result, "reading account access levels");
    if (result == SQLITE_DONE) {
        throw std::invalid_argument("BBS account does not exist");
    }
    AccessLevels levels{sqlite3_column_int(statement.get(), 0), sqlite3_column_int(statement.get(), 1),
        sqlite3_column_int(statement.get(), 2) != 0, column_text(statement.get(), 3),
        column_text(statement.get(), 4), sqlite3_column_int64(statement.get(), 5),
        sqlite3_column_int64(statement.get(), 6), 0, 0, 0, {}, '\0', true, true, 0, 32767, {}};
    levels.birth_date = column_text(statement.get(), 7);
    const std::string sex = column_text(statement.get(), 8);
    levels.sex = sex.empty() ? '\0' : sex.front();
    levels.novice_help = sqlite3_column_int(statement.get(), 9) == 0;
    levels.expiration_date = column_text(statement.get(), 10);
    levels.validation_key_active = message_setting(database, "validation_key_active", "0") == "1";
    const std::string validation_level = message_setting(database, "validation_new_security_level", "10");
    int parsed_validation_level{};
    const auto validation_level_parse = std::from_chars(
        validation_level.data(), validation_level.data() + validation_level.size(), parsed_validation_level);
    if (!validation_level.empty() && validation_level_parse.ec == std::errc{} &&
        validation_level_parse.ptr == validation_level.data() + validation_level.size() &&
        parsed_validation_level >= 0 && parsed_validation_level <= 255) {
        levels.validation_new_security_level = parsed_validation_level;
    }
    const auto count_for_handle = [database, handle](const char* table_name, const char* sql,
                                          std::string_view operation) -> std::uint64_t {
        Statement available(database,
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1");
        bind_text(database, available.get(), 1, table_name);
        if (sqlite3_step(available.get()) != SQLITE_ROW) {
            return 0;
        }
        Statement count(database, sql);
        bind_text(database, count.get(), 1, handle);
        const int count_result = sqlite3_step(count.get());
        check_sqlite(database, count_result, operation);
        return count_result == SQLITE_ROW
            ? static_cast<std::uint64_t>(std::max<sqlite3_int64>(0, sqlite3_column_int64(count.get(), 0)))
            : 0;
    };
    levels.public_posts = count_for_handle("messages",
        "SELECT COUNT(*) FROM messages WHERE author_handle = ?1 COLLATE NOCASE",
        "counting public posts for ACS");
    levels.total_calls = count_for_handle("account_activity",
        "SELECT total_calls FROM account_activity WHERE handle = ?1 COLLATE NOCASE",
        "counting caller sessions for ACS");
    const std::string post_ratio = message_setting(database,
        "post_ratio_" + std::to_string(levels.security_level), "0");
    int parsed_post_ratio{};
    const auto ratio_parse = std::from_chars(
        post_ratio.data(), post_ratio.data() + post_ratio.size(), parsed_post_ratio);
    if (!post_ratio.empty() && ratio_parse.ec == std::errc{} &&
        ratio_parse.ptr == post_ratio.data() + post_ratio.size() &&
        parsed_post_ratio > 0 && parsed_post_ratio <= 100) {
        levels.post_ratio_percent = parsed_post_ratio;
    }
    Statement polls_table(database,
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'polls'");
    const int polls_table_result = sqlite3_step(polls_table.get());
    check_sqlite(database, polls_table_result, "checking poll access data availability");
    if (polls_table_result == SQLITE_ROW) {
        Statement unvoted(database,
            "SELECT COUNT(*) FROM polls AS p LEFT JOIN poll_votes AS v "
            "ON v.poll_id = p.id AND v.caller = ?1 COLLATE NOCASE WHERE v.id IS NULL");
        bind_text(database, unvoted.get(), 1, handle);
        const int unvoted_result = sqlite3_step(unvoted.get());
        check_sqlite(database, unvoted_result, "checking caller poll votes");
        levels.voted_in_all_polls = unvoted_result == SQLITE_ROW &&
            sqlite3_column_int64(unvoted.get(), 0) == 0;
    }
    Statement session_table(database,
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'caller_sessions'");
    const int table_result = sqlite3_step(session_table.get());
    check_sqlite(database, table_result, "checking caller-session history availability");
    if (table_result == SQLITE_ROW) {
        const bool has_expiry = caller_session_column_exists(database, "expires_at");
        const bool has_invisible = caller_session_column_exists(database, "invisible");
        std::string session_query =
            "SELECT node, CAST((julianday('now') - julianday(connected_at)) * 1440 AS INTEGER), ";
        session_query += has_expiry
            ? "CASE WHEN expires_at = '' THEN 32767 ELSE MAX(0, CAST((julianday(expires_at) - julianday('now')) * 1440 AS INTEGER)) END, "
            : "32767, ";
        session_query += has_invisible ? "invisible " : "0 ";
        session_query +=
            "FROM caller_sessions WHERE handle = ?1 COLLATE NOCASE AND disconnected_at = '' "
            "ORDER BY connected_at DESC LIMIT 1";
        Statement session(database, session_query.c_str());
        bind_text(database, session.get(), 1, handle);
        const int session_result = sqlite3_step(session.get());
        check_sqlite(database, session_result, "reading active caller-session duration");
        if (session_result == SQLITE_ROW) {
            levels.node_number = sqlite3_column_int(session.get(), 0);
            levels.online_minutes = std::max<sqlite3_int64>(0, sqlite3_column_int64(session.get(), 1));
            levels.remaining_minutes = sqlite3_column_int(session.get(), 2);
            levels.invisible = sqlite3_column_int(session.get(), 3) != 0;
        }
        if (caller_session_column_exists(database, "sysop_available")) {
            Statement availability(database,
                "SELECT EXISTS(SELECT 1 FROM caller_sessions AS s "
                "JOIN accounts AS a ON a.handle = s.handle COLLATE NOCASE "
                "WHERE s.disconnected_at = '' AND s.sysop_available = 1 AND a.is_sysop = 1)");
            const int availability_result = sqlite3_step(availability.get());
            check_sqlite(database, availability_result, "checking SysOp availability");
            levels.sysop_available = availability_result == SQLITE_ROW &&
                sqlite3_column_int(availability.get(), 0) != 0;
        }
    }
    return levels;
}

std::int64_t find_message_area_id(sqlite3* database, std::string_view area) {
    Statement statement(database, "SELECT id FROM message_areas WHERE name = ?1 COLLATE NOCASE");
    bind_text(database, statement.get(), 1, area);
    const int result = sqlite3_step(statement.get());
    check_sqlite(database, result, "finding message-area number for ACS");
    return result == SQLITE_ROW ? sqlite3_column_int64(statement.get(), 0) : 0;
}

bool area_access_allowed(
    sqlite3* database, std::string_view viewer, std::string_view area, bool posting) {
    const AccessLevels levels = account_access_levels(database, viewer);
    Statement statement(database,
        "SELECT id, access_acs, post_acs FROM message_areas WHERE name = ?1 COLLATE NOCASE");
    bind_text(database, statement.get(), 1, area);
    const int result = sqlite3_step(statement.get());
    check_sqlite(database, result, "reading message-area access rules");
    if (result == SQLITE_DONE) {
        return false;
    }
    AccessLevels area_levels = levels;
    area_levels.message_area_number = sqlite3_column_int64(statement.get(), 0);
    return evaluate_legacy_acs(column_text(statement.get(), 1), area_levels) &&
        (!posting || evaluate_legacy_acs(column_text(statement.get(), 2), area_levels));
}

bool area_mci_allowed(sqlite3* database, std::string_view viewer, std::string_view area) {
    const AccessLevels levels = account_access_levels(database, viewer);
    Statement statement(database,
        "SELECT id, mci_acs FROM message_areas WHERE name = ?1 COLLATE NOCASE");
    bind_text(database, statement.get(), 1, area);
    const int result = sqlite3_step(statement.get());
    check_sqlite(database, result, "reading message-area MCI access rules");
    if (result != SQLITE_ROW) {
        return false;
    }
    AccessLevels area_levels = levels;
    area_levels.message_area_number = sqlite3_column_int64(statement.get(), 0);
    return evaluate_legacy_acs(column_text(statement.get(), 1), area_levels);
}

bool area_moderator_allowed(sqlite3* database, std::string_view viewer, std::string_view area) {
    const AccessLevels levels = account_access_levels(database, viewer);
    if (levels.is_sysop) {
        return true;
    }
    Statement statement(database,
        "SELECT id, sysop_acs FROM message_areas WHERE name = ?1 COLLATE NOCASE");
    bind_text(database, statement.get(), 1, area);
    const int result = sqlite3_step(statement.get());
    check_sqlite(database, result, "reading message-area SysOpACS");
    if (result != SQLITE_ROW) {
        return false;
    }
    AccessLevels area_levels = levels;
    area_levels.message_area_number = sqlite3_column_int64(statement.get(), 0);
    return evaluate_legacy_acs(column_text(statement.get(), 1), area_levels);
}

void bind_visible_area_ids(
    sqlite3* database, sqlite3_stmt* statement, const std::vector<long long>& ids, int first_index) {
    for (std::size_t index = 0; index < ids.size(); ++index) {
        const int result = sqlite3_bind_int64(statement, first_index + static_cast<int>(index),
            static_cast<sqlite3_int64>(ids[index]));
        check_sqlite(database, result, "binding accessible message areas");
    }
}

std::string area_id_placeholders(std::size_t count, int first_index) {
    std::string result;
    for (std::size_t index = 0; index < count; ++index) {
        if (index != 0) {
            result += ',';
        }
        result += '?' + std::to_string(first_index + static_cast<int>(index));
    }
    return result;
}

void make_database_private(const std::string& path) {
    struct stat info {};
    if (::stat(path.c_str(), &info) == 0 && (info.st_mode & 0077) != 0) {
        if (::chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
            throw std::runtime_error("could not restrict message database file permissions");
        }
    }
}

bool has_unsafe_text(std::string_view value, bool allow_newline) {
    for (const unsigned char character : value) {
        if (character == 0 || character == 0x1b || character == 0x7f ||
            (character < 0x20 && character != '\t' && !(allow_newline && (character == '\r' || character == '\n')))) {
            return true;
        }
    }
    return false;
}

bool valid_message_body_text(
    std::string_view body,
    std::size_t max_line_count = kMessageLineCountLimit) noexcept {
    if (body.empty() || body.size() > kMessageBodyByteLimit || has_unsafe_text(body, true)) {
        return false;
    }
    std::size_t lines = 1;
    std::size_t line_characters = 0;
    for (std::size_t index = 0; index < body.size(); ++index) {
        const unsigned char byte = static_cast<unsigned char>(body[index]);
        if (byte == '\r' || byte == '\n') {
            if (line_characters > kMessageLineCharacterLimit) {
                return false;
            }
            line_characters = 0;
            if (++lines > max_line_count) {
                return false;
            }
            if (byte == '\r' && index + 1 < body.size() && body[index + 1] == '\n') {
                ++index;
            }
        } else if ((byte & 0xc0U) != 0x80U) {
            if (++line_characters > kMessageLineCharacterLimit) {
                return false;
            }
        }
    }
    return line_characters <= kMessageLineCharacterLimit;
}

bool valid_area_name(std::string_view name) {
    if (name.empty() || name.size() > 40 || name.front() == ' ' || name.back() == ' ') {
        return false;
    }
    for (const unsigned char character : name) {
        if (character < 0x20 || character == 0x7f || character == 0x1b) {
            return false;
        }
    }
    return true;
}

std::string filter_legacy_public_message(std::string_view body) {
    std::string filtered;
    filtered.reserve(body.size());
    for (std::size_t index = 0; index < body.size();) {
        const unsigned char character = static_cast<unsigned char>(body[index]);
        if (character == '^' && index + 1 < body.size()) {
            const unsigned char next = static_cast<unsigned char>(body[index + 1]);
            if ((next >= '0' && next <= '9') || next == 19) {
                index += 2;
                continue;
            }
        }
        if (character == '|' && index + 2 < body.size() &&
            body[index + 1] >= '0' && body[index + 1] <= '9' &&
            body[index + 2] >= '0' && body[index + 2] <= '9') {
            index += 3;
            continue;
        }
        if (character == '\r' || character == '\n') {
            filtered.push_back(static_cast<char>(character));
        } else if (character < 0x20 || character >= 0x7f) {
            filtered.push_back('*');
        } else {
            filtered.push_back(static_cast<char>(character));
        }
        ++index;
    }
    return filtered;
}

} // namespace

std::size_t utf8_codepoint_count(std::string_view text) noexcept {
    std::size_t count = 0;
    for (const unsigned char byte : text) {
        if ((byte & 0xc0U) != 0x80U) {
            ++count;
        }
    }
    return count;
}

bool valid_message_body(std::string_view body) noexcept {
    return valid_message_body_text(body);
}

MessageStore::MessageStore(std::string database_path)
    : database_path_(std::move(database_path)) {}

void MessageStore::initialize() const {
    std::call_once(initialization_, [this] {
        const std::filesystem::path path(database_path_);
        if (path.has_parent_path()) {
            std::filesystem::create_directories(path.parent_path());
        }

        Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
        constexpr const char* schema =
            "CREATE TABLE IF NOT EXISTS message_areas ("
            "id INTEGER PRIMARY KEY,"
            "name TEXT NOT NULL UNIQUE COLLATE NOCASE,"
            "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "access_acs TEXT NOT NULL DEFAULT '',"
            "post_acs TEXT NOT NULL DEFAULT '',"
            "mci_acs TEXT NOT NULL DEFAULT '',"
            "sysop_acs TEXT NOT NULL DEFAULT 'S255',"
            "anonymous_mode INTEGER NOT NULL DEFAULT 0 CHECK(anonymous_mode BETWEEN 0 AND 4),"
            "force_read INTEGER NOT NULL DEFAULT 0 CHECK(force_read IN (0,1)),"
            "use_real_names INTEGER NOT NULL DEFAULT 0 CHECK(use_real_names IN (0,1)),"
            "quote_start TEXT NOT NULL DEFAULT '^0Quoting message from ^1@F ^0to ^1@T^0',"
            "quote_end TEXT NOT NULL DEFAULT '^0on ^1@D ^0...',"
            "password_hash TEXT NOT NULL DEFAULT '',"
            "add_tagline INTEGER NOT NULL DEFAULT 0 CHECK(add_tagline IN (0,1)),"
            "filter_public_text INTEGER NOT NULL DEFAULT 0 CHECK(filter_public_text IN (0,1)),"
            "unhidden INTEGER NOT NULL DEFAULT 0 CHECK(unhidden IN (0,1)),"
            "add_tearline INTEGER NOT NULL DEFAULT 0 CHECK(add_tearline IN (0,1)),"
            "origin_line TEXT NOT NULL DEFAULT '' CHECK(length(origin_line) <= 50),"
            "origin_address TEXT NOT NULL DEFAULT '' CHECK(length(origin_address) <= 24)"
            ");"
            "CREATE TABLE IF NOT EXISTS message_area_scan_preferences ("
            "user_handle TEXT NOT NULL COLLATE NOCASE REFERENCES accounts(handle) ON DELETE CASCADE,"
            "area_id INTEGER NOT NULL REFERENCES message_areas(id) ON DELETE CASCADE,"
            "enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),"
            "PRIMARY KEY(user_handle, area_id)"
            ");"
            "CREATE TABLE IF NOT EXISTS message_last_areas ("
            "user_handle TEXT PRIMARY KEY COLLATE NOCASE REFERENCES accounts(handle) ON DELETE CASCADE,"
            "area_id INTEGER REFERENCES message_areas(id) ON DELETE SET NULL"
            ");"
            "CREATE TABLE IF NOT EXISTS messages ("
            "id INTEGER PRIMARY KEY,"
            "area_id INTEGER NOT NULL REFERENCES message_areas(id),"
            "author_handle TEXT NOT NULL,"
            "subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 80),"
            "body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 157000),"
            "reply_to INTEGER REFERENCES messages(id),"
            "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "allow_mci INTEGER NOT NULL DEFAULT 0 CHECK(allow_mci IN (0,1)),"
            "deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),"
            "unvalidated INTEGER NOT NULL DEFAULT 0 CHECK(unvalidated IN (0,1)),"
            "permanent INTEGER NOT NULL DEFAULT 0 CHECK(permanent IN (0,1)),"
            "recipient TEXT NOT NULL DEFAULT 'All' CHECK(length(recipient) BETWEEN 1 AND 36),"
            "anonymous_type INTEGER NOT NULL DEFAULT 0 CHECK(anonymous_type BETWEEN 0 AND 5),"
            "posted_as TEXT NOT NULL DEFAULT '' CHECK(length(posted_as) <= 36)"
            ");"
            "CREATE TABLE IF NOT EXISTS message_reads ("
            "user_handle TEXT NOT NULL COLLATE NOCASE,"
            "message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,"
            "read_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "PRIMARY KEY(user_handle, message_id)"
            ");"
            "CREATE INDEX IF NOT EXISTS messages_author_order_nocase "
            "ON messages(author_handle COLLATE NOCASE, id DESC);"
            "CREATE TABLE IF NOT EXISTS private_messages ("
            "id INTEGER PRIMARY KEY,"
            "sender_handle TEXT NOT NULL COLLATE NOCASE REFERENCES accounts(handle),"
            "recipient_handle TEXT NOT NULL COLLATE NOCASE REFERENCES accounts(handle),"
            "subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 80),"
            "body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 157000),"
            "reply_to INTEGER REFERENCES private_messages(id),"
            "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),"
            "anonymous_type INTEGER NOT NULL DEFAULT 0 CHECK(anonymous_type BETWEEN 0 AND 5),"
            "posted_as TEXT NOT NULL DEFAULT '' CHECK(length(posted_as) <= 36)"
            ");"
            "CREATE TABLE IF NOT EXISTS private_message_reads ("
            "user_handle TEXT NOT NULL COLLATE NOCASE REFERENCES accounts(handle),"
            "message_id INTEGER NOT NULL REFERENCES private_messages(id) ON DELETE CASCADE,"
            "read_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "PRIMARY KEY(user_handle, message_id)"
            ");"
            "CREATE INDEX IF NOT EXISTS messages_area_order ON messages(area_id, id DESC);"
            "CREATE INDEX IF NOT EXISTS private_messages_recipient_order ON private_messages(recipient_handle, id DESC);"
            "CREATE INDEX IF NOT EXISTS private_messages_sender_order ON private_messages(sender_handle, id DESC);"
            "CREATE TABLE IF NOT EXISTS message_store_meta ("
            "key TEXT PRIMARY KEY,"
            "value TEXT NOT NULL"
            ");";
        char* error = nullptr;
        const int result = sqlite3_exec(database.get(), schema, nullptr, nullptr, &error);
        if (result != SQLITE_OK) {
            const std::string message = error != nullptr ? error : sqlite3_errmsg(database.get());
            sqlite3_free(error);
            throw std::runtime_error("initializing message store: " + message);
        }
        if (!has_area_column(database.get(), "access_acs")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN access_acs TEXT NOT NULL DEFAULT ''",
                "adding message-area ACS");
        }
        if (!has_area_column(database.get(), "post_acs")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN post_acs TEXT NOT NULL DEFAULT ''",
                "adding message-area PostACS");
        }
        if (!has_area_column(database.get(), "mci_acs")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN mci_acs TEXT NOT NULL DEFAULT ''",
                "adding message-area MCIACS");
        }
        if (!has_area_column(database.get(), "sysop_acs")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN sysop_acs TEXT NOT NULL DEFAULT 'S255'",
                "adding message-area SysOpACS");
        }
        if (!has_area_column(database.get(), "anonymous_mode")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN anonymous_mode INTEGER NOT NULL DEFAULT 0",
                "adding message-area anonymous-posting mode");
        }
        if (!has_area_column(database.get(), "force_read")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN force_read INTEGER NOT NULL DEFAULT 0",
                "adding forced message-area scans");
        }
        if (!has_area_column(database.get(), "use_real_names")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN use_real_names INTEGER NOT NULL DEFAULT 0",
                "adding real-name message search setting");
        }
        if (!has_area_column(database.get(), "quote_start")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN quote_start TEXT NOT NULL DEFAULT '^0Quoting message from ^1@F ^0to ^1@T^0'",
                "adding message-area quote opening template");
        }
        if (!has_area_column(database.get(), "quote_end")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN quote_end TEXT NOT NULL DEFAULT '^0on ^1@D ^0...'",
                "adding message-area quote ending template");
        }
        if (!has_area_column(database.get(), "password_hash")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''",
                "adding message-area password hash");
        }
        if (!has_area_column(database.get(), "add_tagline")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN add_tagline INTEGER NOT NULL DEFAULT 0",
                "adding message-area tagline setting");
        }
        if (!has_area_column(database.get(), "filter_public_text")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN filter_public_text INTEGER NOT NULL DEFAULT 0",
                "adding message-area public-text filter setting");
        }
        if (!has_area_column(database.get(), "unhidden")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN unhidden INTEGER NOT NULL DEFAULT 0",
                "adding message-area visibility setting");
        }
        if (!has_area_column(database.get(), "add_tearline")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN add_tearline INTEGER NOT NULL DEFAULT 0",
                "adding message-area tearline setting");
        }
        if (!has_area_column(database.get(), "origin_line")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN origin_line TEXT NOT NULL DEFAULT ''",
                "adding message-area origin line");
        }
        if (!has_area_column(database.get(), "origin_address")) {
            execute_sql(database.get(),
                "ALTER TABLE message_areas ADD COLUMN origin_address TEXT NOT NULL DEFAULT ''",
                "adding message-area origin address");
        }
        if (!has_message_column(database.get(), "allow_mci")) {
            execute_sql(database.get(),
                "ALTER TABLE messages ADD COLUMN allow_mci INTEGER NOT NULL DEFAULT 0",
                "adding message MCI permission");
        }
        if (!has_message_column(database.get(), "deleted")) {
            execute_sql(database.get(),
                "ALTER TABLE messages ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0",
                "adding message deletion status");
        }
        if (!has_message_column(database.get(), "unvalidated")) {
            execute_sql(database.get(),
                "ALTER TABLE messages ADD COLUMN unvalidated INTEGER NOT NULL DEFAULT 0",
                "adding message validation status");
        }
        if (!has_message_column(database.get(), "permanent")) {
            execute_sql(database.get(),
                "ALTER TABLE messages ADD COLUMN permanent INTEGER NOT NULL DEFAULT 0",
                "adding permanent-message status");
        }
        if (!has_message_column(database.get(), "recipient")) {
            execute_sql(database.get(),
                "ALTER TABLE messages ADD COLUMN recipient TEXT NOT NULL DEFAULT 'All'",
                "adding public-message recipient");
        }
        if (!has_message_column(database.get(), "anonymous_type")) {
            execute_sql(database.get(),
                "ALTER TABLE messages ADD COLUMN anonymous_type INTEGER NOT NULL DEFAULT 0",
                "adding public-message anonymous identity");
        }
        if (!has_message_column(database.get(), "posted_as")) {
            execute_sql(database.get(),
                "ALTER TABLE messages ADD COLUMN posted_as TEXT NOT NULL DEFAULT ''",
                "adding public-message display name");
        }
        if (!has_private_message_column(database.get(), "deleted")) {
            execute_sql(database.get(),
                "ALTER TABLE private_messages ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0",
                "adding private-message deletion status");
        }
        if (!has_private_message_column(database.get(), "anonymous_type")) {
            execute_sql(database.get(),
                "ALTER TABLE private_messages ADD COLUMN anonymous_type INTEGER NOT NULL DEFAULT 0",
                "adding private-message anonymous identity");
        }
        migrate_private_anonymous_metadata(database.get());
        execute_sql(database.get(),
            "INSERT OR IGNORE INTO message_store_meta(key, value) VALUES"
            "('anonymous_post_acs', 'S255'), ('anonymous_read_acs', 'S255'), "
            "('anonymous_private_post_acs', 'S255'), ('anonymous_private_read_acs', 'S255'), "
            "('normal_public_post_acs', ''), ('normal_private_post_acs', ''), "
            "('max_public_posts_per_call', '255'), ('max_private_posts_per_call', '255'), "
            "('max_mail_waiting', '255'), ('max_sysop_mail_waiting', '255'), "
            "('credit_public_post', '0'), ('credit_private_mail', '0'), "
            "('invisible_acs', 'S255'), ('validation_key_active', '0'), "
            "('validation_new_security_level', '10')",
            "creating default anonymous-message ACS settings");
        if (!has_reply_column(database.get())) {
            char* migration_error = nullptr;
            const int migration = sqlite3_exec(
                database.get(),
                "ALTER TABLE messages ADD COLUMN reply_to INTEGER REFERENCES messages(id)",
                nullptr,
                nullptr,
                &migration_error);
            if (migration != SQLITE_OK && !has_reply_column(database.get())) {
                const std::string message = migration_error != nullptr
                    ? migration_error
                    : sqlite3_errmsg(database.get());
                sqlite3_free(migration_error);
                throw std::runtime_error("adding message reply support: " + message);
            }
            sqlite3_free(migration_error);
        }
        migrate_message_body_limits(database.get());
        execute_sql(database.get(), "BEGIN IMMEDIATE", "starting message-area initialization");
        try {
            bool initial_areas_seeded = false;
            {
                Statement marker(database.get(),
                    "SELECT 1 FROM message_store_meta WHERE key = 'initial_areas_seeded'");
                const int step = sqlite3_step(marker.get());
                check_sqlite(database.get(), step, "checking initial message-area setup");
                initial_areas_seeded = step == SQLITE_ROW;
            }
            if (!initial_areas_seeded) {
                bool has_areas = false;
                {
                    Statement query(database.get(), "SELECT 1 FROM message_areas LIMIT 1");
                    const int step = sqlite3_step(query.get());
                    check_sqlite(database.get(), step, "checking message-area table");
                    has_areas = step == SQLITE_ROW;
                }
                if (!has_areas) {
                    execute_sql(database.get(),
                        "INSERT INTO message_areas(name) VALUES('General')",
                        "creating default message area");
                }
                execute_sql(database.get(),
                    "INSERT INTO message_store_meta(key, value) VALUES('initial_areas_seeded', '1')",
                    "saving initial message-area setup");
            }
            execute_sql(database.get(), "COMMIT", "saving message-area initialization");
        } catch (...) {
            (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
            throw;
        }
        make_database_private(database_path_);
    });
}

std::string MessageStore::initial_area(std::string_view viewer) const {
    if (!valid_handle(viewer)) {
        throw std::invalid_argument("invalid viewer handle");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels levels = account_access_levels(database.get(), viewer);
    {
        Statement saved(database.get(),
            "SELECT areas.id, areas.name, areas.access_acs FROM message_last_areas AS remembered "
            "JOIN message_areas AS areas ON areas.id = remembered.area_id "
            "WHERE remembered.user_handle = ?1 COLLATE NOCASE");
        bind_text(database.get(), saved.get(), 1, viewer);
        const int result = sqlite3_step(saved.get());
        check_sqlite(database.get(), result, "reading the last message area");
        AccessLevels saved_area_levels = levels;
        if (result == SQLITE_ROW) {
            saved_area_levels.message_area_number = sqlite3_column_int64(saved.get(), 0);
        }
        if (result == SQLITE_ROW && evaluate_legacy_acs(column_text(saved.get(), 2), saved_area_levels)) {
            return column_text(saved.get(), 1);
        }
    }
    Statement first(database.get(), "SELECT id, name, access_acs FROM message_areas ORDER BY id");
    for (;;) {
        const int result = sqlite3_step(first.get());
        if (result == SQLITE_DONE) {
            break;
        }
        check_sqlite(database.get(), result, "finding the first accessible message area");
        AccessLevels first_area_levels = levels;
        first_area_levels.message_area_number = sqlite3_column_int64(first.get(), 0);
        if (evaluate_legacy_acs(column_text(first.get(), 2), first_area_levels)) {
            return column_text(first.get(), 1);
        }
    }
    return "General";
}

void MessageStore::set_last_area(std::string_view viewer, std::string_view area) const {
    if (!valid_handle(viewer) || !valid_area_name(area)) {
        throw std::invalid_argument("invalid last message-area preference");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels levels = account_access_levels(database.get(), viewer);
    Statement lookup(database.get(), "SELECT id, access_acs FROM message_areas WHERE name = ?1 COLLATE NOCASE");
    bind_text(database.get(), lookup.get(), 1, area);
    const int found = sqlite3_step(lookup.get());
    check_sqlite(database.get(), found, "checking the selected message area");
    AccessLevels area_levels = levels;
    if (found == SQLITE_ROW) {
        area_levels.message_area_number = sqlite3_column_int64(lookup.get(), 0);
    }
    if (found != SQLITE_ROW || !evaluate_legacy_acs(column_text(lookup.get(), 1), area_levels)) {
        throw std::invalid_argument("selected message area is not accessible");
    }
    const sqlite3_int64 area_id = sqlite3_column_int64(lookup.get(), 0);
    Statement save(database.get(),
        "INSERT INTO message_last_areas(user_handle, area_id) VALUES(?1, ?2) "
        "ON CONFLICT(user_handle) DO UPDATE SET area_id = excluded.area_id");
    bind_text(database.get(), save.get(), 1, viewer);
    check_sqlite(database.get(), sqlite3_bind_int64(save.get(), 2, area_id),
        "binding last message-area preference");
    check_sqlite(database.get(), sqlite3_step(save.get()), "saving the last message area");
}

std::vector<BoardArea> MessageStore::areas(
    std::string_view viewer, bool include_restricted, bool include_unhidden) const {
    if (!valid_handle(viewer)) {
        throw std::invalid_argument("invalid viewer handle");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels levels = account_access_levels(database.get(), viewer);
    Statement statement(database.get(),
        "SELECT areas.id, areas.name, "
        "COUNT(CASE WHEN messages.deleted = 0 AND messages.unvalidated = 0 THEN messages.id END) - "
        "COUNT(CASE WHEN messages.deleted = 0 AND messages.unvalidated = 0 "
        "THEN read_marks.message_id END), "
        "COUNT(messages.id) - COUNT(read_marks.message_id), "
        "areas.access_acs, areas.post_acs, areas.mci_acs, areas.sysop_acs, areas.anonymous_mode, "
        "CASE WHEN areas.force_read = 1 THEN 1 ELSE COALESCE(scan_preferences.enabled, 1) END, "
        "areas.force_read, areas.use_real_names, areas.quote_start, areas.quote_end, "
        "CASE WHEN areas.password_hash <> '' THEN 1 ELSE 0 END, areas.add_tagline, "
        "areas.filter_public_text, areas.unhidden, areas.add_tearline, areas.origin_line, areas.origin_address "
        "FROM message_areas AS areas "
        "LEFT JOIN messages ON messages.area_id = areas.id "
        "LEFT JOIN message_reads AS read_marks ON read_marks.message_id = messages.id "
        "AND read_marks.user_handle = ?1 COLLATE NOCASE "
        "LEFT JOIN message_area_scan_preferences AS scan_preferences ON scan_preferences.area_id = areas.id "
        "AND scan_preferences.user_handle = ?1 COLLATE NOCASE "
        "GROUP BY areas.id, areas.name, scan_preferences.enabled ORDER BY areas.name COLLATE NOCASE");
    bind_text(database.get(), statement.get(), 1, viewer);
    std::vector<BoardArea> result;
    for (;;) {
        const int step = sqlite3_step(statement.get());
        if (step == SQLITE_DONE) {
            break;
        }
        check_sqlite(database.get(), step, "reading message areas");
        const std::string access = column_text(statement.get(), 4);
        const std::string post = column_text(statement.get(), 5);
        const std::string mci = column_text(statement.get(), 6);
        const std::string sysop = column_text(statement.get(), 7);
        const int anonymous_mode = sqlite3_column_int(statement.get(), 8);
        const bool new_scan_enabled = sqlite3_column_int(statement.get(), 9) != 0;
        const bool force_read = sqlite3_column_int(statement.get(), 10) != 0;
        const bool use_real_names = sqlite3_column_int(statement.get(), 11) != 0;
        const std::string quote_start = column_text(statement.get(), 12);
        const std::string quote_end = column_text(statement.get(), 13);
        const bool password_protected = sqlite3_column_int(statement.get(), 14) != 0;
        const bool add_tagline = sqlite3_column_int(statement.get(), 15) != 0;
        const bool filter_public_text = sqlite3_column_int(statement.get(), 16) != 0;
        AccessLevels area_levels = levels;
        area_levels.message_area_number = sqlite3_column_int64(statement.get(), 0);
        const bool access_allowed = evaluate_legacy_acs(access, area_levels);
        const bool unhidden = sqlite3_column_int(statement.get(), 17) != 0;
        const bool add_tearline = sqlite3_column_int(statement.get(), 18) != 0;
        const std::string origin_line = column_text(statement.get(), 19);
        const std::string origin_address = column_text(statement.get(), 20);
        if (!include_restricted && !access_allowed && !(include_unhidden && unhidden)) {
            continue;
        }
        const bool moderator = levels.is_sysop || evaluate_legacy_acs(sysop, area_levels);
        const sqlite3_int64 unread = access_allowed
            ? sqlite3_column_int64(statement.get(), moderator ? 3 : 2) : 0;
        result.push_back({sqlite3_column_int64(statement.get(), 0), column_text(statement.get(), 1),
            unread <= 0 || (password_protected && !include_restricted)
                ? 0 : static_cast<std::size_t>(unread), access, post, mci, sysop,
            anonymous_mode >= 0 && anonymous_mode <= 4
                ? static_cast<AnonymousMode>(anonymous_mode) : AnonymousMode::Disabled,
            new_scan_enabled, force_read, use_real_names, password_protected, add_tagline,
            filter_public_text, access_allowed, unhidden, add_tearline, origin_line, origin_address,
            quote_start, quote_end});
    }
    return result;
}

void MessageStore::set_message_scan_date(
    std::string_view viewer, std::string_view mmddyyyy) const {
    if (!valid_handle(viewer) || mmddyyyy.size() != 10 ||
        mmddyyyy[2] != '/' || mmddyyyy[5] != '/') {
        throw std::invalid_argument("enter the oldest scan date as MM/DD/YYYY");
    }
    const auto parse_component = [mmddyyyy](std::size_t start, std::size_t length) {
        int value{};
        const char* begin = mmddyyyy.data() + start;
        const auto parsed = std::from_chars(begin, begin + length, value);
        if (parsed.ec != std::errc{} || parsed.ptr != begin + length) {
            throw std::invalid_argument("enter the oldest scan date as MM/DD/YYYY");
        }
        return value;
    };
    const int month = parse_component(0, 2);
    const int day = parse_component(3, 2);
    const int year = parse_component(6, 4);
    if (year < 1 || year > 9999) {
        throw std::invalid_argument("scan date must be a valid calendar date no later than today");
    }
    using namespace std::chrono;
    const year_month_day selected{std::chrono::year{year}, std::chrono::month{static_cast<unsigned>(month)},
        std::chrono::day{static_cast<unsigned>(day)}};
    if (!selected.ok() || sys_days{selected} > floor<days>(system_clock::now())) {
        throw std::invalid_argument("scan date must be a valid calendar date no later than today");
    }
    const auto two_digits = [](unsigned value) {
        return value < 10 ? "0" + std::to_string(value) : std::to_string(value);
    };
    std::string year_text = std::to_string(year);
    year_text.insert(0, 4 - year_text.size(), '0');
    const std::string cutoff = year_text + "-" + two_digits(static_cast<unsigned>(month)) +
        "-" + two_digits(static_cast<unsigned>(day)) + " 00:00:00";

    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting message scan-date update");
    try {
        Statement account(database.get(), "SELECT 1 FROM accounts WHERE handle = ?1 COLLATE NOCASE");
        bind_text(database.get(), account.get(), 1, viewer);
        const int account_result = sqlite3_step(account.get());
        check_sqlite(database.get(), account_result, "checking message scan-date account");
        if (account_result != SQLITE_ROW) {
            throw std::invalid_argument("BBS account does not exist");
        }
        Statement clear_newer(database.get(),
            "DELETE FROM message_reads WHERE user_handle = ?1 COLLATE NOCASE AND message_id IN "
            "(SELECT id FROM messages WHERE created_at >= ?2)");
        bind_text(database.get(), clear_newer.get(), 1, viewer);
        bind_text(database.get(), clear_newer.get(), 2, cutoff);
        check_sqlite(database.get(), sqlite3_step(clear_newer.get()),
            "resetting reads after the message scan date");

        Statement mark_older(database.get(),
            "INSERT OR IGNORE INTO message_reads(user_handle, message_id) "
            "SELECT ?1, id FROM messages WHERE created_at < ?2");
        bind_text(database.get(), mark_older.get(), 1, viewer);
        bind_text(database.get(), mark_older.get(), 2, cutoff);
        check_sqlite(database.get(), sqlite3_step(mark_older.get()),
            "marking messages before the scan date as read");
        execute_sql(database.get(), "COMMIT", "saving message scan date");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

bool MessageStore::toggle_area_new_scan(std::string_view viewer, std::string_view area) const {
    if (!valid_handle(viewer) || !valid_area_name(area)) {
        throw std::invalid_argument("invalid message-area scan preference request");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting message-area scan preference change");
    bool enabled{};
    try {
        if (!area_access_allowed(database.get(), viewer, area, false)) {
            throw std::invalid_argument("message area is not available to this account");
        }
        Statement current(database.get(),
            "SELECT COALESCE(preferences.enabled, 1), areas.force_read FROM message_areas AS areas "
            "LEFT JOIN message_area_scan_preferences AS preferences ON preferences.area_id = areas.id "
            "AND preferences.user_handle = ?1 COLLATE NOCASE WHERE areas.name = ?2 COLLATE NOCASE");
        bind_text(database.get(), current.get(), 1, viewer);
        bind_text(database.get(), current.get(), 2, area);
        const int result = sqlite3_step(current.get());
        check_sqlite(database.get(), result, "reading message-area scan preference");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("message area does not exist");
        }
        if (sqlite3_column_int(current.get(), 1) != 0) {
            enabled = true;
            execute_sql(database.get(), "COMMIT", "keeping forced message-area scan enabled");
            make_database_private(database_path_);
            return enabled;
        }
        enabled = sqlite3_column_int(current.get(), 0) == 0;
        Statement update(database.get(),
            "INSERT INTO message_area_scan_preferences(user_handle, area_id, enabled) "
            "SELECT ?1, areas.id, ?3 FROM message_areas AS areas WHERE areas.name = ?2 COLLATE NOCASE "
            "ON CONFLICT(user_handle, area_id) DO UPDATE SET enabled = excluded.enabled");
        bind_text(database.get(), update.get(), 1, viewer);
        bind_text(database.get(), update.get(), 2, area);
        check_sqlite(database.get(), sqlite3_bind_int(update.get(), 3, enabled ? 1 : 0),
            "binding message-area scan preference");
        check_sqlite(database.get(), sqlite3_step(update.get()), "saving message-area scan preference");
        execute_sql(database.get(), "COMMIT", "saving message-area scan preference");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
    return enabled;
}

void MessageStore::set_all_area_new_scans(std::string_view viewer, bool enabled) const {
    if (!valid_handle(viewer)) {
        throw std::invalid_argument("invalid message-area scan preference account");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting all message-area scan preference change");
    try {
        const AccessLevels levels = account_access_levels(database.get(), viewer);
        Statement select(database.get(), "SELECT id, access_acs, force_read FROM message_areas ORDER BY id");
        std::vector<std::pair<long long, bool>> accessible_areas;
        for (;;) {
            const int result = sqlite3_step(select.get());
            if (result == SQLITE_DONE) {
                break;
            }
            check_sqlite(database.get(), result, "reading message-area scan access");
            AccessLevels area_levels = levels;
            area_levels.message_area_number = sqlite3_column_int64(select.get(), 0);
            if (evaluate_legacy_acs(column_text(select.get(), 1), area_levels)) {
                accessible_areas.emplace_back(sqlite3_column_int64(select.get(), 0),
                    sqlite3_column_int(select.get(), 2) != 0);
            }
        }
        for (const auto& [area_id, force_read] : accessible_areas) {
            Statement update(database.get(),
                "INSERT INTO message_area_scan_preferences(user_handle, area_id, enabled) "
                "VALUES(?1, ?2, ?3) ON CONFLICT(user_handle, area_id) "
                "DO UPDATE SET enabled = excluded.enabled");
            bind_text(database.get(), update.get(), 1, viewer);
            check_sqlite(database.get(), sqlite3_bind_int64(
                update.get(), 2, static_cast<sqlite3_int64>(area_id)), "binding message-area ID");
            check_sqlite(database.get(), sqlite3_bind_int(update.get(), 3,
                (enabled || force_read) ? 1 : 0),
                "binding message-area scan preference");
            check_sqlite(database.get(), sqlite3_step(update.get()),
                "saving all message-area scan preferences");
        }
        execute_sql(database.get(), "COMMIT", "saving all message-area scan preferences");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

void MessageStore::set_area_anonymous_mode(long long area_id, AnonymousMode mode) const {
    const int value = static_cast<int>(mode);
    if (area_id < 1 || value < 0 || value > 4) {
        throw std::invalid_argument("message-area anonymous mode must be N, Y, F, D, or A");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(database.get(), "UPDATE message_areas SET anonymous_mode = ?1 WHERE id = ?2");
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 1, value), "binding anonymous-posting mode");
    check_sqlite(database.get(), sqlite3_bind_int64(
        statement.get(), 2, static_cast<sqlite3_int64>(area_id)), "binding message-area ID");
    check_sqlite(database.get(), sqlite3_step(statement.get()), "updating message-area anonymous mode");
    if (sqlite3_changes(database.get()) == 0) {
        Statement exists(database.get(), "SELECT 1 FROM message_areas WHERE id = ?1");
        check_sqlite(database.get(), sqlite3_bind_int64(
            exists.get(), 1, static_cast<sqlite3_int64>(area_id)), "binding message-area ID");
        const int result = sqlite3_step(exists.get());
        check_sqlite(database.get(), result, "checking message area for anonymous-mode update");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("message area does not exist");
        }
    }
    make_database_private(database_path_);
}

AnonymousMode MessageStore::area_anonymous_mode(
    std::string_view viewer, std::string_view area) const {
    if (!valid_handle(viewer) || !valid_area_name(area)) {
        throw std::invalid_argument("invalid viewer or message area");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels levels = account_access_levels(database.get(), viewer);
    if (levels.ac_flags.find('*') != std::string::npos) {
        return AnonymousMode::Disabled;
    }
    Statement statement(database.get(),
        "SELECT anonymous_mode, id FROM message_areas WHERE name = ?1 COLLATE NOCASE");
    bind_text(database.get(), statement.get(), 1, area);
    const int result = sqlite3_step(statement.get());
    check_sqlite(database.get(), result, "reading message-area anonymous mode");
    if (result == SQLITE_DONE) {
        throw std::invalid_argument("message area does not exist");
    }
    const int value = sqlite3_column_int(statement.get(), 0);
    AccessLevels area_levels = levels;
    area_levels.message_area_number = sqlite3_column_int64(statement.get(), 1);
    const AnonymousMode configured = value >= 0 && value <= 4
        ? static_cast<AnonymousMode>(value) : AnonymousMode::Disabled;
    if (configured == AnonymousMode::Disabled && evaluate_legacy_acs(
            message_setting(database.get(), "anonymous_post_acs", "S255"), area_levels)) {
        return AnonymousMode::Optional;
    }
    return configured;
}

void MessageStore::set_anonymous_acs(
    std::string_view public_post, std::string_view public_read,
    std::string_view private_post, std::string_view private_read) const {
    if (!valid_legacy_acs(public_post) || !valid_legacy_acs(public_read) ||
        !valid_legacy_acs(private_post) || !valid_legacy_acs(private_read)) {
        throw std::invalid_argument("anonymous message ACS rules must use supported Renegade syntax and be at most 20 characters");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting anonymous-message ACS update");
    try {
        const auto save = [&](std::string_view key, std::string_view value) {
            Statement statement(database.get(),
                "INSERT INTO message_store_meta(key, value) VALUES(?1, ?2) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
            bind_text(database.get(), statement.get(), 1, key);
            bind_text(database.get(), statement.get(), 2, value);
            check_sqlite(database.get(), sqlite3_step(statement.get()), "saving anonymous-message ACS");
        };
        save("anonymous_post_acs", public_post);
        save("anonymous_read_acs", public_read);
        save("anonymous_private_post_acs", private_post);
        save("anonymous_private_read_acs", private_read);
        execute_sql(database.get(), "COMMIT", "saving anonymous-message ACS settings");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

void MessageStore::set_normal_post_acs(
    std::string_view public_post, std::string_view private_post) const {
    if (!valid_legacy_acs(public_post) || !valid_legacy_acs(private_post)) {
        throw std::invalid_argument("normal public/private posting ACS must use supported Renegade syntax and be at most 20 characters");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting normal-post ACS update");
    try {
        const auto save = [&](std::string_view key, std::string_view value) {
            Statement statement(database.get(),
                "INSERT INTO message_store_meta(key, value) VALUES(?1, ?2) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
            bind_text(database.get(), statement.get(), 1, key);
            bind_text(database.get(), statement.get(), 2, value);
            check_sqlite(database.get(), sqlite3_step(statement.get()), "saving normal-post ACS");
        };
        save("normal_public_post_acs", public_post);
        save("normal_private_post_acs", private_post);
        execute_sql(database.get(), "COMMIT", "saving normal-post ACS rules");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

std::pair<std::string, std::string> MessageStore::normal_post_acs() const {
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    return {
        message_setting(database.get(), "normal_public_post_acs", ""),
        message_setting(database.get(), "normal_private_post_acs", ""),
    };
}

void MessageStore::set_submission_acs(std::string_view quote, std::string_view one_liner) const {
    if (!valid_legacy_acs(quote) || !valid_legacy_acs(one_liner)) {
        throw std::invalid_argument(
            "quote and one-liner ACS must use supported Renegade syntax and be at most 20 characters");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting quote and one-liner ACS update");
    try {
        const auto save = [&](std::string_view key, std::string_view value) {
            Statement setting(database.get(),
                "INSERT INTO message_store_meta(key, value) VALUES(?1, ?2) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
            bind_text(database.get(), setting.get(), 1, key);
            bind_text(database.get(), setting.get(), 2, value);
            check_sqlite(database.get(), sqlite3_step(setting.get()), "saving quote and one-liner ACS");
        };
        save("add_quote_acs", quote);
        save("add_one_liner_acs", one_liner);
        execute_sql(database.get(), "COMMIT", "saving quote and one-liner ACS");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

std::pair<std::string, std::string> MessageStore::submission_acs() const {
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    return {
        message_setting(database.get(), "add_quote_acs", ""),
        message_setting(database.get(), "add_one_liner_acs", ""),
    };
}

bool MessageStore::can_submit_quote(std::string_view caller) const {
    if (!valid_handle(caller)) {
        return false;
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels levels = account_access_levels(database.get(), caller);
    return evaluate_legacy_acs(message_setting(database.get(), "add_quote_acs", ""), levels);
}

bool MessageStore::can_submit_one_liner(std::string_view caller) const {
    if (!valid_handle(caller)) {
        return false;
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels levels = account_access_levels(database.get(), caller);
    return evaluate_legacy_acs(message_setting(database.get(), "add_one_liner_acs", ""), levels);
}

bool MessageStore::passes_access_rule(
    std::string_view caller, std::string_view expression, int node_number,
    int remaining_minutes, int online_minutes, bool invisible) const {
    if (!valid_handle(caller) || !valid_legacy_acs(expression) || node_number < 0 || node_number > 32 ||
        remaining_minutes < 0 || remaining_minutes > 32767 || online_minutes < 0 ||
        online_minutes > 32767) {
        return false;
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    AccessLevels levels = account_access_levels(database.get(), caller);
    levels.node_number = node_number;
    levels.remaining_minutes = remaining_minutes;
    levels.online_minutes = online_minutes;
    levels.invisible = invisible;
    return evaluate_legacy_acs(expression, levels);
}

void MessageStore::set_invisibility_acs(std::string_view expression) const {
    if (!valid_legacy_acs(expression)) {
        throw std::invalid_argument("invisibility ACS must use supported Renegade syntax and be at most 20 characters");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement setting(database.get(),
        "INSERT INTO message_store_meta(key, value) VALUES('invisible_acs', ?1) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
    bind_text(database.get(), setting.get(), 1, expression);
    check_sqlite(database.get(), sqlite3_step(setting.get()), "saving invisibility ACS");
    make_database_private(database_path_);
}

std::string MessageStore::invisibility_acs() const {
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    return message_setting(database.get(), "invisible_acs", "S255");
}

bool MessageStore::can_toggle_invisibility(std::string_view caller) const {
    if (!valid_handle(caller)) {
        return false;
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels levels = account_access_levels(database.get(), caller);
    return evaluate_legacy_acs(message_setting(database.get(), "invisible_acs", "S255"), levels);
}

void MessageStore::set_validation_eligibility(bool key_active, int new_security_level) const {
    if (new_security_level < 0 || new_security_level > 255) {
        throw std::invalid_argument("new-user security level must be between 0 and 255");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting validation eligibility update");
    try {
        const auto save = [&](std::string_view key, std::string_view value) {
            Statement setting(database.get(),
                "INSERT INTO message_store_meta(key, value) VALUES(?1, ?2) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
            bind_text(database.get(), setting.get(), 1, key);
            bind_text(database.get(), setting.get(), 2, value);
            check_sqlite(database.get(), sqlite3_step(setting.get()), "saving validation eligibility");
        };
        save("validation_key_active", key_active ? "1" : "0");
        save("validation_new_security_level", std::to_string(new_security_level));
        execute_sql(database.get(), "COMMIT", "saving validation eligibility");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

std::pair<bool, int> MessageStore::validation_eligibility() const {
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    const std::string active = message_setting(database.get(), "validation_key_active", "0");
    const std::string level = message_setting(database.get(), "validation_new_security_level", "10");
    int parsed_level{};
    const auto parsed = std::from_chars(level.data(), level.data() + level.size(), parsed_level);
    if (level.empty() || parsed.ec != std::errc{} || parsed.ptr != level.data() + level.size() ||
        parsed_level < 0 || parsed_level > 255) {
        parsed_level = 10;
    }
    return {active == "1", parsed_level};
}

void MessageStore::set_post_limits(int public_per_call, int private_per_call) const {
    if (public_per_call < 0 || public_per_call > 255 ||
        private_per_call < 0 || private_per_call > 255) {
        throw std::invalid_argument("public/private post limits must be between 0 and 255 per call");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting message-post limit update");
    try {
        const auto save = [&](std::string_view key, int value) {
            Statement statement(database.get(),
                "INSERT INTO message_store_meta(key, value) VALUES(?1, ?2) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
            bind_text(database.get(), statement.get(), 1, key);
            bind_text(database.get(), statement.get(), 2, std::to_string(value));
            check_sqlite(database.get(), sqlite3_step(statement.get()), "saving message-post limit");
        };
        save("max_public_posts_per_call", public_per_call);
        save("max_private_posts_per_call", private_per_call);
        execute_sql(database.get(), "COMMIT", "saving message-post limits");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

MessagePostLimits MessageStore::post_limits() const {
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    return {
        message_count_limit(database.get(), "max_public_posts_per_call"),
        message_count_limit(database.get(), "max_private_posts_per_call"),
    };
}

void MessageStore::set_post_ratio_range(
    int minimum_security_level, int maximum_security_level, int percent) const {
    if (minimum_security_level < 0 || maximum_security_level > 255 ||
        minimum_security_level > maximum_security_level || percent < 0 || percent > 100) {
        throw std::invalid_argument("post-call ratios require SL 0-255 and a percentage from 0 to 100");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting post-call ratio update");
    try {
        for (int level = minimum_security_level; level <= maximum_security_level; ++level) {
            Statement setting(database.get(),
                "INSERT INTO message_store_meta(key, value) VALUES(?1, ?2) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
            bind_text(database.get(), setting.get(), 1, "post_ratio_" + std::to_string(level));
            bind_text(database.get(), setting.get(), 2, std::to_string(percent));
            check_sqlite(database.get(), sqlite3_step(setting.get()), "saving post-call ratio");
        }
        execute_sql(database.get(), "COMMIT", "saving post-call ratios");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

void MessageStore::set_private_mail_waiting_limits(int normal_users, int sysops) const {
    if (normal_users < 0 || normal_users > 255 || sysops < 0 || sysops > 255) {
        throw std::invalid_argument("private-mail waiting limits must be between 0 and 255");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting private-mail waiting-limit update");
    try {
        const auto save = [&](std::string_view key, int value) {
            Statement statement(database.get(),
                "INSERT INTO message_store_meta(key, value) VALUES(?1, ?2) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
            bind_text(database.get(), statement.get(), 1, key);
            bind_text(database.get(), statement.get(), 2, std::to_string(value));
            check_sqlite(database.get(), sqlite3_step(statement.get()), "saving private-mail waiting limit");
        };
        save("max_mail_waiting", normal_users);
        save("max_sysop_mail_waiting", sysops);
        execute_sql(database.get(), "COMMIT", "saving private-mail waiting limits");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

PrivateMailWaitingLimits MessageStore::private_mail_waiting_limits() const {
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    return {
        message_count_limit(database.get(), "max_mail_waiting"),
        message_count_limit(database.get(), "max_sysop_mail_waiting"),
    };
}

void MessageStore::set_credit_costs(int public_post, int private_mail) const {
    if (public_post < -32767 || public_post > 32767 ||
        private_mail < -32767 || private_mail > 32767) {
        throw std::invalid_argument("public/private message credit costs must be between -32767 and 32767");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting message credit-cost update");
    try {
        const auto save = [&](std::string_view key, int value) {
            Statement statement(database.get(),
                "INSERT INTO message_store_meta(key, value) VALUES(?1, ?2) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
            bind_text(database.get(), statement.get(), 1, key);
            bind_text(database.get(), statement.get(), 2, std::to_string(value));
            check_sqlite(database.get(), sqlite3_step(statement.get()), "saving message credit cost");
        };
        save("credit_public_post", public_post);
        save("credit_private_mail", private_mail);
        execute_sql(database.get(), "COMMIT", "saving message credit costs");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

MessageCreditCosts MessageStore::credit_costs() const {
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    return {
        message_credit_cost(database.get(), "credit_public_post"),
        message_credit_cost(database.get(), "credit_private_mail"),
    };
}

AnonymousAcsSettings MessageStore::anonymous_acs() const {
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    return {
        message_setting(database.get(), "anonymous_post_acs", "S255"),
        message_setting(database.get(), "anonymous_read_acs", "S255"),
        message_setting(database.get(), "anonymous_private_post_acs", "S255"),
        message_setting(database.get(), "anonymous_private_read_acs", "S255"),
    };
}

bool MessageStore::can_post_public_anonymously(std::string_view viewer) const {
    if (!valid_handle(viewer)) {
        return false;
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels levels = account_access_levels(database.get(), viewer);
    return evaluate_legacy_acs(message_setting(database.get(), "anonymous_post_acs", "S255"), levels);
}

bool MessageStore::can_post_public(
    std::string_view viewer, std::string_view area, int posts_this_call) const {
    if (!valid_handle(viewer) || !valid_area_name(area) || posts_this_call < 0) {
        return false;
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    AccessLevels levels = account_access_levels(database.get(), viewer);
    Statement area_context(database.get(),
        "SELECT id FROM message_areas WHERE name = ?1 COLLATE NOCASE");
    bind_text(database.get(), area_context.get(), 1, area);
    const int area_result = sqlite3_step(area_context.get());
    check_sqlite(database.get(), area_result, "finding the selected public message area");
    if (area_result != SQLITE_ROW) {
        return false;
    }
    levels.message_area_number = sqlite3_column_int64(area_context.get(), 0);
    if (levels.ac_flags.find('P') != std::string::npos ||
        !evaluate_legacy_acs(message_setting(database.get(), "normal_public_post_acs", ""), levels)) {
        return false;
    }
    const int credit_cost = message_credit_cost(database.get(), "credit_public_post");
    if (levels.ac_flags.find('3') == std::string::npos &&
        account_credit_balance(database.get(), viewer) < credit_cost) {
        return false;
    }
    if (!levels.is_sysop && posts_this_call >=
        message_count_limit(database.get(), "max_public_posts_per_call")) {
        return false;
    }
    return area_access_allowed(database.get(), viewer, area, true);
}

bool MessageStore::can_send_private(std::string_view sender, int sent_this_call) const {
    if (!valid_handle(sender) || sent_this_call < 0) {
        return false;
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels levels = account_access_levels(database.get(), sender);
    if (levels.is_sysop) {
        return true;
    }
    if (levels.ac_flags.find('E') != std::string::npos ||
        !evaluate_legacy_acs(message_setting(database.get(), "normal_private_post_acs", ""), levels) ||
        sent_this_call >= message_count_limit(database.get(), "max_private_posts_per_call")) {
        return false;
    }
    const int credit_cost = message_credit_cost(database.get(), "credit_private_mail");
    return credit_cost <= 0 || levels.ac_flags.find('3') != std::string::npos ||
        account_credit_balance(database.get(), sender) >= credit_cost;
}

bool MessageStore::can_read_public_anonymously(std::string_view viewer) const {
    if (!valid_handle(viewer)) {
        return false;
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels levels = account_access_levels(database.get(), viewer);
    return evaluate_legacy_acs(message_setting(database.get(), "anonymous_read_acs", "S255"), levels);
}

bool MessageStore::can_post_private_anonymously(std::string_view sender) const {
    if (!valid_handle(sender)) {
        return false;
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels levels = account_access_levels(database.get(), sender);
    return evaluate_legacy_acs(
        message_setting(database.get(), "anonymous_private_post_acs", "S255"), levels);
}

bool MessageStore::can_read_private_anonymously(std::string_view viewer) const {
    if (!valid_handle(viewer)) {
        return false;
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels levels = account_access_levels(database.get(), viewer);
    return evaluate_legacy_acs(
        message_setting(database.get(), "anonymous_private_read_acs", "S255"), levels);
}

void MessageStore::set_area_access(
    long long area_id,
    std::string_view access_acs,
    std::string_view post_acs,
    std::string_view mci_acs,
    std::string_view sysop_acs) const {
    if (area_id < 1 || !valid_legacy_acs(access_acs) || !valid_legacy_acs(post_acs) ||
        !valid_legacy_acs(mci_acs) || !valid_legacy_acs(sysop_acs)) {
        throw std::invalid_argument(
            "message-area ACS, PostACS, MCIACS, and SysOpACS must use supported Renegade syntax and be at most 20 characters");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(database.get(),
        "UPDATE message_areas SET access_acs = ?1, post_acs = ?2, mci_acs = ?3, "
        "sysop_acs = ?4 WHERE id = ?5");
    bind_text(database.get(), statement.get(), 1, access_acs);
    bind_text(database.get(), statement.get(), 2, post_acs);
    bind_text(database.get(), statement.get(), 3, mci_acs);
    bind_text(database.get(), statement.get(), 4, sysop_acs);
    check_sqlite(database.get(), sqlite3_bind_int64(
        statement.get(), 5, static_cast<sqlite3_int64>(area_id)), "binding message-area ID");
    check_sqlite(database.get(), sqlite3_step(statement.get()), "updating message-area access rules");
    if (sqlite3_changes(database.get()) == 0) {
        Statement exists(database.get(), "SELECT 1 FROM message_areas WHERE id = ?1");
        check_sqlite(database.get(), sqlite3_bind_int64(
            exists.get(), 1, static_cast<sqlite3_int64>(area_id)), "binding message-area ID");
        const int result = sqlite3_step(exists.get());
        check_sqlite(database.get(), result, "checking message area for access update");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("message area does not exist");
        }
    }
    make_database_private(database_path_);
}

void MessageStore::set_area_force_read(long long area_id, bool enabled) const {
    if (area_id < 1) {
        throw std::invalid_argument("message-area ID must be positive");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(database.get(), "UPDATE message_areas SET force_read = ?1 WHERE id = ?2");
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 1, enabled ? 1 : 0),
        "binding forced message-area scan setting");
    check_sqlite(database.get(), sqlite3_bind_int64(statement.get(), 2, area_id),
        "binding message-area ID");
    check_sqlite(database.get(), sqlite3_step(statement.get()), "updating forced message-area scan setting");
    if (sqlite3_changes(database.get()) == 0) {
        Statement exists(database.get(), "SELECT 1 FROM message_areas WHERE id = ?1");
        check_sqlite(database.get(), sqlite3_bind_int64(exists.get(), 1, area_id),
            "binding message-area ID");
        const int result = sqlite3_step(exists.get());
        check_sqlite(database.get(), result, "checking message area for forced-scan update");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("message area does not exist");
        }
    }
    make_database_private(database_path_);
}

void MessageStore::set_area_password(long long area_id, std::string_view password) const {
    if (area_id < 1 || password.size() > 20 ||
        std::any_of(password.begin(), password.end(), [](unsigned char value) {
            return value < 32 || value == 127;
        })) {
        throw std::invalid_argument("message-area passwords must be printable and at most 20 bytes");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    const std::string encoded_hash = password.empty() ? std::string{} : hash_password(password);
    Statement update(database.get(), "UPDATE message_areas SET password_hash = ?1 WHERE id = ?2");
    bind_text(database.get(), update.get(), 1, encoded_hash);
    check_sqlite(database.get(), sqlite3_bind_int64(update.get(), 2, area_id),
        "binding message-area password area");
    check_sqlite(database.get(), sqlite3_step(update.get()), "updating message-area password");
    if (sqlite3_changes(database.get()) == 0) {
        Statement exists(database.get(), "SELECT 1 FROM message_areas WHERE id = ?1");
        check_sqlite(database.get(), sqlite3_bind_int64(exists.get(), 1, area_id),
            "binding message-area existence check");
        if (sqlite3_step(exists.get()) != SQLITE_ROW) {
            throw std::invalid_argument("message area does not exist");
        }
    }
}

bool MessageStore::verify_area_password(
    std::string_view viewer, long long area_id, std::string_view password) const {
    if (!valid_handle(viewer) || area_id < 1 || password.size() > 20) {
        return false;
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    AccessLevels levels = account_access_levels(database.get(), viewer);
    levels.message_area_number = area_id;
    Statement query(database.get(),
        "SELECT password_hash, access_acs FROM message_areas WHERE id = ?1");
    check_sqlite(database.get(), sqlite3_bind_int64(query.get(), 1, area_id),
        "binding message-area password lookup");
    const int result = sqlite3_step(query.get());
    check_sqlite(database.get(), result, "reading message-area password");
    if (result != SQLITE_ROW || !evaluate_legacy_acs(column_text(query.get(), 1), levels)) {
        return false;
    }
    const std::string encoded_hash = column_text(query.get(), 0);
    return encoded_hash.empty() || verify_password_hash(encoded_hash, password);
}

void MessageStore::set_area_real_name_search(long long area_id, bool enabled) const {
    if (area_id < 1) {
        throw std::invalid_argument("message-area ID must be positive");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(database.get(),
        "UPDATE message_areas SET use_real_names = ?1 WHERE id = ?2");
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 1, enabled ? 1 : 0),
        "binding real-name search setting");
    check_sqlite(database.get(), sqlite3_bind_int64(statement.get(), 2, area_id),
        "binding message-area ID");
    check_sqlite(database.get(), sqlite3_step(statement.get()), "updating real-name search setting");
    if (sqlite3_changes(database.get()) == 0) {
        Statement exists(database.get(), "SELECT 1 FROM message_areas WHERE id = ?1");
        check_sqlite(database.get(), sqlite3_bind_int64(exists.get(), 1, area_id),
            "binding message-area ID");
        const int result = sqlite3_step(exists.get());
        check_sqlite(database.get(), result, "checking message area for real-name search update");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("message area does not exist");
        }
    }
    make_database_private(database_path_);
}

void MessageStore::set_area_taglines_enabled(long long area_id, bool enabled) const {
    if (area_id < 1) {
        throw std::invalid_argument("message-area ID must be positive");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(database.get(), "UPDATE message_areas SET add_tagline = ?1 WHERE id = ?2");
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 1, enabled ? 1 : 0),
        "binding message-area tagline setting");
    check_sqlite(database.get(), sqlite3_bind_int64(statement.get(), 2, area_id),
        "binding message-area ID");
    check_sqlite(database.get(), sqlite3_step(statement.get()), "updating message-area tagline setting");
    if (sqlite3_changes(database.get()) == 0) {
        Statement exists(database.get(), "SELECT 1 FROM message_areas WHERE id = ?1");
        check_sqlite(database.get(), sqlite3_bind_int64(exists.get(), 1, area_id),
            "binding message-area ID");
        const int result = sqlite3_step(exists.get());
        check_sqlite(database.get(), result, "checking message area for tagline update");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("message area does not exist");
        }
    }
    make_database_private(database_path_);
}

void MessageStore::set_area_public_text_filter(long long area_id, bool enabled) const {
    if (area_id < 1) {
        throw std::invalid_argument("message-area ID must be positive");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(database.get(),
        "UPDATE message_areas SET filter_public_text = ?1 WHERE id = ?2");
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 1, enabled ? 1 : 0),
        "binding message-area public-text filter setting");
    check_sqlite(database.get(), sqlite3_bind_int64(statement.get(), 2, area_id),
        "binding message-area ID");
    check_sqlite(database.get(), sqlite3_step(statement.get()),
        "updating message-area public-text filter setting");
    if (sqlite3_changes(database.get()) == 0) {
        Statement exists(database.get(), "SELECT 1 FROM message_areas WHERE id = ?1");
        check_sqlite(database.get(), sqlite3_bind_int64(exists.get(), 1, area_id),
            "binding message-area ID");
        const int result = sqlite3_step(exists.get());
        check_sqlite(database.get(), result, "checking message area for text-filter update");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("message area does not exist");
        }
    }
    make_database_private(database_path_);
}

void MessageStore::set_area_unhidden(long long area_id, bool enabled) const {
    if (area_id < 1) {
        throw std::invalid_argument("message-area ID must be positive");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(database.get(), "UPDATE message_areas SET unhidden = ?1 WHERE id = ?2");
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 1, enabled ? 1 : 0),
        "binding message-area visibility setting");
    check_sqlite(database.get(), sqlite3_bind_int64(statement.get(), 2, area_id),
        "binding message-area ID");
    check_sqlite(database.get(), sqlite3_step(statement.get()),
        "updating message-area visibility setting");
    if (sqlite3_changes(database.get()) == 0) {
        Statement exists(database.get(), "SELECT 1 FROM message_areas WHERE id = ?1");
        check_sqlite(database.get(), sqlite3_bind_int64(exists.get(), 1, area_id),
            "binding message-area ID");
        const int result = sqlite3_step(exists.get());
        check_sqlite(database.get(), result, "checking message area for visibility update");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("message area does not exist");
        }
    }
    make_database_private(database_path_);
}

void MessageStore::set_area_tearline_enabled(long long area_id, bool enabled) const {
    if (area_id < 1) {
        throw std::invalid_argument("message-area ID must be positive");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(database.get(), "UPDATE message_areas SET add_tearline = ?1 WHERE id = ?2");
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 1, enabled ? 1 : 0),
        "binding message-area tearline setting");
    check_sqlite(database.get(), sqlite3_bind_int64(statement.get(), 2, area_id),
        "binding message-area ID");
    check_sqlite(database.get(), sqlite3_step(statement.get()), "updating message-area tearline setting");
    if (sqlite3_changes(database.get()) == 0) {
        Statement exists(database.get(), "SELECT 1 FROM message_areas WHERE id = ?1");
        check_sqlite(database.get(), sqlite3_bind_int64(exists.get(), 1, area_id),
            "binding message-area ID");
        const int result = sqlite3_step(exists.get());
        check_sqlite(database.get(), result, "checking message area for tearline update");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("message area does not exist");
        }
    }
    make_database_private(database_path_);
}

void MessageStore::set_area_origin(
    long long area_id, std::string_view origin_line, std::string_view origin_address) const {
    const auto valid_origin_address = [](std::string_view address) {
        if (address.empty()) {
            return true;
        }
        const std::size_t colon = address.find(':');
        const std::size_t slash = address.find('/');
        const std::size_t dot = address.find('.');
        if (colon == std::string_view::npos || slash == std::string_view::npos ||
            colon == 0 || slash <= colon + 1 || slash + 1 >= address.size() ||
            (dot != std::string_view::npos && (dot <= slash + 1 || dot + 1 >= address.size())) ||
            address.find(':', colon + 1) != std::string_view::npos ||
            address.find('/', slash + 1) != std::string_view::npos ||
            (dot != std::string_view::npos && address.find('.', dot + 1) != std::string_view::npos)) {
            return false;
        }
        for (const unsigned char byte : address) {
            if (!(byte >= '0' && byte <= '9') && byte != ':' && byte != '/' && byte != '.') {
                return false;
            }
        }
        return true;
    };
    const std::string address_suffix = origin_address.empty()
        ? std::string{} : " (" + std::string(origin_address) + ")";
    if (area_id < 1 || origin_line.size() > 50 || origin_address.size() > 24 ||
        has_unsafe_text(origin_line, false) || !valid_origin_address(origin_address) ||
        11 + utf8_codepoint_count(origin_line) + address_suffix.size() > 78) {
        throw std::invalid_argument(
            "origin text must be printable and at most 50 bytes; address must use zone:net/node.point format, "
            "and the complete origin line must fit 78 characters");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(database.get(),
        "UPDATE message_areas SET origin_line = ?1, origin_address = ?2 WHERE id = ?3");
    bind_text(database.get(), statement.get(), 1, origin_line);
    bind_text(database.get(), statement.get(), 2, origin_address);
    check_sqlite(database.get(), sqlite3_bind_int64(statement.get(), 3, area_id),
        "binding message-area ID");
    check_sqlite(database.get(), sqlite3_step(statement.get()), "updating message-area origin");
    if (sqlite3_changes(database.get()) == 0) {
        Statement exists(database.get(), "SELECT 1 FROM message_areas WHERE id = ?1");
        check_sqlite(database.get(), sqlite3_bind_int64(exists.get(), 1, area_id),
            "binding message-area ID");
        const int result = sqlite3_step(exists.get());
        check_sqlite(database.get(), result, "checking message area for origin update");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("message area does not exist");
        }
    }
    make_database_private(database_path_);
}

void MessageStore::set_area_quote_templates(
    long long area_id,
    std::string_view quote_start,
    std::string_view quote_end) const {
    const auto valid_template = [](std::string_view value) {
        return value.size() <= 80 && std::none_of(value.begin(), value.end(), [](unsigned char byte) {
            return byte < 0x20 || byte == 0x7f;
        });
    };
    if (area_id < 1 || !valid_template(quote_start) || !valid_template(quote_end)) {
        throw std::invalid_argument("quote templates must be at most 80 printable bytes each");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(database.get(),
        "UPDATE message_areas SET quote_start = ?1, quote_end = ?2 WHERE id = ?3");
    bind_text(database.get(), statement.get(), 1, quote_start);
    bind_text(database.get(), statement.get(), 2, quote_end);
    check_sqlite(database.get(), sqlite3_bind_int64(statement.get(), 3, area_id),
        "binding message-area ID");
    check_sqlite(database.get(), sqlite3_step(statement.get()), "updating message-area quote templates");
    if (sqlite3_changes(database.get()) == 0) {
        Statement exists(database.get(), "SELECT 1 FROM message_areas WHERE id = ?1");
        check_sqlite(database.get(), sqlite3_bind_int64(exists.get(), 1, area_id),
            "binding message-area ID");
        const int result = sqlite3_step(exists.get());
        check_sqlite(database.get(), result, "checking message area for quote-template update");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("message area does not exist");
        }
    }
    make_database_private(database_path_);
}

MessageQuoteTemplates MessageStore::area_quote_templates(
    std::string_view viewer, std::string_view area) const {
    if (!valid_handle(viewer) || !valid_area_name(area)) {
        throw std::invalid_argument("invalid viewer or message area");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    if (!area_access_allowed(database.get(), viewer, area, false)) {
        throw std::invalid_argument("message area is not available to this account");
    }
    Statement statement(database.get(),
        "SELECT quote_start, quote_end FROM message_areas WHERE name = ?1 COLLATE NOCASE");
    bind_text(database.get(), statement.get(), 1, area);
    const int result = sqlite3_step(statement.get());
    check_sqlite(database.get(), result, "reading message-area quote templates");
    if (result != SQLITE_ROW) {
        throw std::invalid_argument("message area does not exist");
    }
    return {column_text(statement.get(), 0), column_text(statement.get(), 1)};
}

void MessageStore::set_private_quote_templates(
    std::string_view quote_start, std::string_view quote_end) const {
    const auto valid_template = [](std::string_view value) {
        return value.size() <= 80 && std::none_of(value.begin(), value.end(), [](unsigned char byte) {
            return byte < 0x20 || byte == 0x7f;
        });
    };
    if (!valid_template(quote_start) || !valid_template(quote_end)) {
        throw std::invalid_argument("private quote templates must be at most 80 printable bytes each");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting private quote-template update");
    try {
        for (const auto& [key, value] : std::array<std::pair<std::string_view, std::string_view>, 2>{{
                {"private_quote_start", quote_start}, {"private_quote_end", quote_end}}}) {
            Statement statement(database.get(),
                "INSERT INTO message_store_meta(key, value) VALUES(?1, ?2) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
            bind_text(database.get(), statement.get(), 1, key);
            bind_text(database.get(), statement.get(), 2, value);
            check_sqlite(database.get(), sqlite3_step(statement.get()),
                "saving private quote template");
        }
        execute_sql(database.get(), "COMMIT", "saving private quote templates");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

MessageQuoteTemplates MessageStore::private_quote_templates() const {
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    return {
        message_setting(database.get(), "private_quote_start", "^0Quoting message from ^1@F ^0to ^1@T^0"),
        message_setting(database.get(), "private_quote_end", "^0on ^1@D ^0...")};
}

std::string MessageStore::area_real_name_label(
    std::string_view viewer, std::string_view area, std::string_view handle) const {
    if (!valid_handle(viewer) || !valid_area_name(area) || !valid_handle(handle)) {
        throw std::invalid_argument("invalid real-name display request");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    if (!area_access_allowed(database.get(), viewer, area, false)) {
        throw std::invalid_argument("message area is not available to this account");
    }
    Statement statement(database.get(),
        "SELECT CASE WHEN areas.use_real_names = 1 AND accounts.real_name <> '' "
        "THEN accounts.real_name ELSE ?3 END FROM message_areas AS areas "
        "LEFT JOIN accounts ON accounts.handle = ?2 COLLATE NOCASE "
        "WHERE areas.name = ?1 COLLATE NOCASE");
    bind_text(database.get(), statement.get(), 1, area);
    bind_text(database.get(), statement.get(), 2, handle);
    bind_text(database.get(), statement.get(), 3, handle);
    const int result = sqlite3_step(statement.get());
    check_sqlite(database.get(), result, "reading message-area display name");
    if (result != SQLITE_ROW) {
        throw std::invalid_argument("message area does not exist");
    }
    return column_text(statement.get(), 0);
}

bool MessageStore::can_use_area_mci(std::string_view viewer, std::string_view area) const {
    if (!valid_handle(viewer) || !valid_area_name(area)) {
        return false;
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    return area_mci_allowed(database.get(), viewer, area);
}

bool MessageStore::can_moderate_area(std::string_view viewer, std::string_view area) const {
    if (!valid_handle(viewer) || !valid_area_name(area)) {
        return false;
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    return area_moderator_allowed(database.get(), viewer, area);
}

bool MessageStore::toggle_message_deleted(
    std::string_view actor, std::string_view area, long long message_id) const {
    if (!valid_handle(actor) || !valid_area_name(area) || message_id < 1) {
        throw std::invalid_argument("invalid public-message deletion request");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_sqlite(database.get(), sqlite3_exec(database.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr),
        "starting public-message status change");
    if (!area_access_allowed(database.get(), actor, area, false)) {
        throw std::invalid_argument("message area is not available to this account");
    }
    std::string author;
    bool was_deleted{};
    bool permanent{};
    {
        Statement query(database.get(),
            "SELECT messages.author_handle, messages.deleted, messages.permanent FROM messages "
            "JOIN message_areas ON message_areas.id = messages.area_id "
            "WHERE message_areas.name = ?1 COLLATE NOCASE AND messages.id = ?2");
        bind_text(database.get(), query.get(), 1, area);
        check_sqlite(database.get(), sqlite3_bind_int64(
            query.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding public message ID");
        const int result = sqlite3_step(query.get());
        check_sqlite(database.get(), result, "reading public-message status");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("public message does not exist");
        }
        author = column_text(query.get(), 0);
        was_deleted = sqlite3_column_int(query.get(), 1) != 0;
        permanent = sqlite3_column_int(query.get(), 2) != 0;
    }
    if (permanent) {
        throw std::invalid_argument("permanent public messages cannot be deleted or restored");
    }
    const bool moderator = area_moderator_allowed(database.get(), actor, area);
    if (!moderator && sqlite3_stricmp(author.c_str(), std::string(actor).c_str()) != 0) {
        throw std::invalid_argument("only the message author or an area SysOp may change this status");
    }
    Statement update(database.get(), "UPDATE messages SET deleted = ?1 WHERE id = ?2");
    check_sqlite(database.get(), sqlite3_bind_int(update.get(), 1, was_deleted ? 0 : 1),
        "binding public-message deleted status");
    check_sqlite(database.get(), sqlite3_bind_int64(
        update.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding public message ID");
    check_sqlite(database.get(), sqlite3_step(update.get()), "updating public-message status");
    check_sqlite(database.get(), sqlite3_exec(database.get(), "COMMIT", nullptr, nullptr, nullptr),
        "saving public-message status");
    make_database_private(database_path_);
    return !was_deleted;
}

bool MessageStore::toggle_message_validation(
    std::string_view actor, std::string_view area, long long message_id) const {
    if (!valid_handle(actor) || !valid_area_name(area) || message_id < 1) {
        throw std::invalid_argument("invalid public-message validation request");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_sqlite(database.get(), sqlite3_exec(database.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr),
        "starting public-message validation change");
    if (!area_moderator_allowed(database.get(), actor, area)) {
        throw std::invalid_argument("only an area SysOp may change message validation status");
    }
    bool was_unvalidated{};
    {
        Statement query(database.get(),
            "SELECT messages.unvalidated FROM messages "
            "JOIN message_areas ON message_areas.id = messages.area_id "
            "WHERE message_areas.name = ?1 COLLATE NOCASE AND messages.id = ?2");
        bind_text(database.get(), query.get(), 1, area);
        check_sqlite(database.get(), sqlite3_bind_int64(
            query.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding public message ID");
        const int result = sqlite3_step(query.get());
        check_sqlite(database.get(), result, "reading public-message validation status");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("public message does not exist");
        }
        was_unvalidated = sqlite3_column_int(query.get(), 0) != 0;
    }
    Statement update(database.get(), "UPDATE messages SET unvalidated = ?1 WHERE id = ?2");
    check_sqlite(database.get(), sqlite3_bind_int(update.get(), 1, was_unvalidated ? 0 : 1),
        "binding public-message validation status");
    check_sqlite(database.get(), sqlite3_bind_int64(
        update.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding public message ID");
    check_sqlite(database.get(), sqlite3_step(update.get()), "updating public-message validation status");
    check_sqlite(database.get(), sqlite3_exec(database.get(), "COMMIT", nullptr, nullptr, nullptr),
        "saving public-message validation status");
    make_database_private(database_path_);
    return !was_unvalidated;
}

bool MessageStore::toggle_message_permanent(
    std::string_view actor, std::string_view area, long long message_id) const {
    if (!valid_handle(actor) || !valid_area_name(area) || message_id < 1) {
        throw std::invalid_argument("invalid permanent-message status request");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_sqlite(database.get(), sqlite3_exec(database.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr),
        "starting permanent-message status change");
    if (!area_moderator_allowed(database.get(), actor, area)) {
        throw std::invalid_argument("only an area SysOp may change permanent-message status");
    }
    bool was_permanent{};
    {
        Statement query(database.get(),
            "SELECT messages.permanent FROM messages "
            "JOIN message_areas ON message_areas.id = messages.area_id "
            "WHERE message_areas.name = ?1 COLLATE NOCASE AND messages.id = ?2");
        bind_text(database.get(), query.get(), 1, area);
        check_sqlite(database.get(), sqlite3_bind_int64(
            query.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding public message ID");
        const int result = sqlite3_step(query.get());
        check_sqlite(database.get(), result, "reading permanent-message status");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("public message does not exist");
        }
        was_permanent = sqlite3_column_int(query.get(), 0) != 0;
    }
    Statement update(database.get(), "UPDATE messages SET permanent = ?1 WHERE id = ?2");
    check_sqlite(database.get(), sqlite3_bind_int(update.get(), 1, was_permanent ? 0 : 1),
        "binding permanent-message status");
    check_sqlite(database.get(), sqlite3_bind_int64(
        update.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding public message ID");
    check_sqlite(database.get(), sqlite3_step(update.get()), "updating permanent-message status");
    check_sqlite(database.get(), sqlite3_exec(database.get(), "COMMIT", nullptr, nullptr, nullptr),
        "saving permanent-message status");
    make_database_private(database_path_);
    return !was_permanent;
}

std::size_t MessageStore::validate_all_messages(std::string_view actor, std::string_view area) const {
    if (!valid_handle(actor) || !valid_area_name(area)) {
        throw std::invalid_argument("invalid public-message validation request");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    if (!area_moderator_allowed(database.get(), actor, area)) {
        throw std::invalid_argument("only an area SysOp may validate messages");
    }
    Statement update(database.get(),
        "UPDATE messages SET unvalidated = 0 WHERE unvalidated = 1 AND area_id = "
        "(SELECT id FROM message_areas WHERE name = ?1 COLLATE NOCASE)");
    bind_text(database.get(), update.get(), 1, area);
    check_sqlite(database.get(), sqlite3_step(update.get()), "validating all pending messages");
    const std::size_t validated = static_cast<std::size_t>(std::max(0, sqlite3_changes(database.get())));
    make_database_private(database_path_);
    return validated;
}

void MessageStore::edit_message_body(
    std::string_view actor, std::string_view area, long long message_id, std::string_view body) const {
    if (!valid_handle(actor) || !valid_area_name(area) || message_id < 1) {
        throw std::invalid_argument("invalid public-message edit request");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_sqlite(database.get(), sqlite3_exec(database.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr),
        "starting public-message edit");
    if (!area_access_allowed(database.get(), actor, area, false)) {
        throw std::invalid_argument("message area is not available to this account");
    }
    std::string author;
    {
        Statement query(database.get(),
            "SELECT messages.author_handle FROM messages "
            "JOIN message_areas ON message_areas.id = messages.area_id "
            "WHERE message_areas.name = ?1 COLLATE NOCASE AND messages.id = ?2");
        bind_text(database.get(), query.get(), 1, area);
        check_sqlite(database.get(), sqlite3_bind_int64(
            query.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding public message ID");
        const int result = sqlite3_step(query.get());
        check_sqlite(database.get(), result, "reading public-message author");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("public message does not exist");
        }
        author = column_text(query.get(), 0);
    }
    const bool moderator = area_moderator_allowed(database.get(), actor, area);
    if (!moderator && sqlite3_stricmp(author.c_str(), std::string(actor).c_str()) != 0) {
        throw std::invalid_argument("only the message author or an area SysOp may edit this message");
    }
    Statement update(database.get(), "UPDATE messages SET body = ?1 WHERE id = ?2");
    bind_text(database.get(), update.get(), 1, body);
    check_sqlite(database.get(), sqlite3_bind_int64(
        update.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding public message ID");
    check_sqlite(database.get(), sqlite3_step(update.get()), "updating public-message text");
    check_sqlite(database.get(), sqlite3_exec(database.get(), "COMMIT", nullptr, nullptr, nullptr),
        "saving public-message edit");
    make_database_private(database_path_);
}

void MessageStore::edit_private_message_body(
    std::string_view actor, long long message_id, std::string_view body) const {
    if (!valid_handle(actor) || message_id < 1) {
        throw std::invalid_argument("invalid private-message edit request");
    }
    if (!valid_message_body(body)) {
        throw std::invalid_argument("message body must be 1-500 lines of up to 78 characters without terminal control codes");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting private-message edit");
    try {
        Statement update(database.get(),
            "UPDATE private_messages SET body = ?1 WHERE id = ?2 "
            "AND sender_handle = ?3 COLLATE NOCASE");
        bind_text(database.get(), update.get(), 1, body);
        check_sqlite(database.get(), sqlite3_bind_int64(
            update.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding private-message ID");
        bind_text(database.get(), update.get(), 3, actor);
        check_sqlite(database.get(), sqlite3_step(update.get()), "updating private-message text");
        if (sqlite3_changes(database.get()) == 0) {
            throw std::invalid_argument("only the sender may edit this private message");
        }
        execute_sql(database.get(), "COMMIT", "saving private-message edit");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

long long MessageStore::move_message(
    std::string_view actor,
    std::string_view source_area,
    std::string_view target_area,
    long long message_id) const {
    if (!valid_handle(actor) || !valid_area_name(source_area) || !valid_area_name(target_area) ||
        message_id < 1) {
        throw std::invalid_argument("invalid public-message move request");
    }
    if (sqlite3_stricmp(std::string(source_area).c_str(), std::string(target_area).c_str()) == 0) {
        throw std::invalid_argument("a message cannot be moved to its current area");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting public-message move");
    long long destination_message_id{};
    try {
        if (!area_moderator_allowed(database.get(), actor, source_area)) {
            throw std::invalid_argument("only a message-area SysOp may move this message");
        }
        if (!area_access_allowed(database.get(), actor, target_area, true)) {
            throw std::invalid_argument("you do not have read and posting access to the destination area");
        }
        Statement insert(database.get(),
            "INSERT INTO messages(area_id, author_handle, subject, body, reply_to, created_at, allow_mci, "
            "deleted, unvalidated, permanent, recipient, anonymous_type, posted_as) "
            "SELECT target.id, source.author_handle, source.subject, source.body, source.reply_to, "
            "source.created_at, source.allow_mci, 0, source.unvalidated, source.permanent, source.recipient, "
            "source.anonymous_type, source.posted_as FROM messages AS source "
            "JOIN message_areas AS source_area ON source_area.id = source.area_id "
            "JOIN message_areas AS target ON target.name = ?1 COLLATE NOCASE "
            "WHERE source_area.name = ?2 COLLATE NOCASE AND source.id = ?3");
        bind_text(database.get(), insert.get(), 1, target_area);
        bind_text(database.get(), insert.get(), 2, source_area);
        check_sqlite(database.get(), sqlite3_bind_int64(
            insert.get(), 3, static_cast<sqlite3_int64>(message_id)), "binding public message ID");
        check_sqlite(database.get(), sqlite3_step(insert.get()), "copying public message to destination area");
        if (sqlite3_changes(database.get()) == 0) {
            throw std::invalid_argument("source message or destination area does not exist");
        }
        destination_message_id = static_cast<long long>(sqlite3_last_insert_rowid(database.get()));
        Statement delete_source(database.get(),
            "UPDATE messages SET deleted = 1 WHERE id = ?1 AND area_id = "
            "(SELECT id FROM message_areas WHERE name = ?2 COLLATE NOCASE)");
        check_sqlite(database.get(), sqlite3_bind_int64(
            delete_source.get(), 1, static_cast<sqlite3_int64>(message_id)), "binding source message ID");
        bind_text(database.get(), delete_source.get(), 2, source_area);
        check_sqlite(database.get(), sqlite3_step(delete_source.get()), "hiding source message after move");
        if (sqlite3_changes(database.get()) == 0) {
            throw std::invalid_argument("source message no longer exists in the selected area");
        }
        execute_sql(database.get(), "COMMIT", "saving public-message move");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
    return destination_message_id;
}

long long MessageStore::move_private_message_to_area(
    std::string_view actor, std::string_view target_area, long long message_id) const {
    if (!valid_handle(actor) || !valid_area_name(target_area) || message_id < 1) {
        throw std::invalid_argument("invalid private-message move request");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting private-message move");
    long long destination_message_id{};
    try {
        if (!account_access_levels(database.get(), actor).is_sysop) {
            throw std::invalid_argument("only a SysOp may move private mail into a public area");
        }
        if (!area_access_allowed(database.get(), actor, target_area, true)) {
            throw std::invalid_argument("you do not have read and posting access to the destination area");
        }
        Statement insert(database.get(),
            "INSERT INTO messages(area_id, author_handle, subject, body, reply_to, created_at, allow_mci, "
            "deleted, unvalidated, permanent, recipient, anonymous_type, posted_as) "
            "SELECT target.id, source.sender_handle, source.subject, source.body, NULL, source.created_at, "
            "0, 0, 0, 0, source.recipient_handle, source.anonymous_type, source.posted_as "
            "FROM private_messages AS source JOIN message_areas AS target "
            "ON target.name = ?1 COLLATE NOCASE WHERE source.id = ?2 AND source.deleted = 0 "
            "AND (source.sender_handle = ?3 COLLATE NOCASE OR source.recipient_handle = ?3 COLLATE NOCASE)");
        bind_text(database.get(), insert.get(), 1, target_area);
        check_sqlite(database.get(), sqlite3_bind_int64(
            insert.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding private message ID");
        bind_text(database.get(), insert.get(), 3, actor);
        check_sqlite(database.get(), sqlite3_step(insert.get()), "copying private message to public area");
        if (sqlite3_changes(database.get()) == 0) {
            throw std::invalid_argument("active private message or destination area does not exist");
        }
        destination_message_id = static_cast<long long>(sqlite3_last_insert_rowid(database.get()));
        Statement hide_source(database.get(),
            "UPDATE private_messages SET deleted = 1 WHERE id = ?1 AND deleted = 0 "
            "AND (sender_handle = ?2 COLLATE NOCASE OR recipient_handle = ?2 COLLATE NOCASE)");
        check_sqlite(database.get(), sqlite3_bind_int64(
            hide_source.get(), 1, static_cast<sqlite3_int64>(message_id)), "binding source private message ID");
        bind_text(database.get(), hide_source.get(), 2, actor);
        check_sqlite(database.get(), sqlite3_step(hide_source.get()), "hiding private message after move");
        if (sqlite3_changes(database.get()) == 0) {
            throw std::invalid_argument("source private message is no longer available");
        }
        execute_sql(database.get(), "COMMIT", "saving private-message move");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
    return destination_message_id;
}

long long MessageStore::move_public_message_to_private(
    std::string_view actor, std::string_view source_area, long long message_id) const {
    if (!valid_handle(actor) || !valid_area_name(source_area) || message_id < 1) {
        throw std::invalid_argument("invalid public-to-private message move request");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting public-to-private message move");
    long long destination_message_id{};
    try {
        const AccessLevels actor_levels = account_access_levels(database.get(), actor);
        if (!area_moderator_allowed(database.get(), actor, source_area)) {
            throw std::invalid_argument("only a message-area SysOp may move this message");
        }
        std::string recipient_handle;
        {
            Statement recipient(database.get(),
                "SELECT messages.recipient FROM messages "
                "JOIN message_areas ON message_areas.id = messages.area_id "
                "WHERE message_areas.name = ?1 COLLATE NOCASE AND messages.id = ?2");
            bind_text(database.get(), recipient.get(), 1, source_area);
            check_sqlite(database.get(), sqlite3_bind_int64(
                recipient.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding public message ID");
            const int result = sqlite3_step(recipient.get());
            check_sqlite(database.get(), result, "checking public message private-mail recipient");
            if (result == SQLITE_DONE) {
                throw std::invalid_argument("source public message does not exist in the selected area");
            }
            recipient_handle = column_text(recipient.get(), 0);
        }
        ensure_private_recipient_accepts_mail(database.get(), recipient_handle, actor_levels.is_sysop);
        Statement insert(database.get(),
            "INSERT INTO private_messages(sender_handle, recipient_handle, subject, body, reply_to, "
            "created_at, deleted, anonymous_type, posted_as) "
            "SELECT source.author_handle, recipient.handle, source.subject, source.body, NULL, "
            "source.created_at, 0, source.anonymous_type, source.posted_as "
            "FROM messages AS source "
            "JOIN message_areas AS source_area ON source_area.id = source.area_id "
            "JOIN accounts AS recipient ON recipient.handle = source.recipient COLLATE NOCASE "
            "WHERE source_area.name = ?1 COLLATE NOCASE AND source.id = ?2");
        bind_text(database.get(), insert.get(), 1, source_area);
        check_sqlite(database.get(), sqlite3_bind_int64(
            insert.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding public message ID");
        check_sqlite(database.get(), sqlite3_step(insert.get()), "copying public message into private mail");
        if (sqlite3_changes(database.get()) == 0) {
            throw std::invalid_argument(
                "the public message's To field must match an existing account to move it into private mail");
        }
        destination_message_id = static_cast<long long>(sqlite3_last_insert_rowid(database.get()));
        Statement hide_source(database.get(),
            "UPDATE messages SET deleted = 1 WHERE id = ?1 AND area_id = "
            "(SELECT id FROM message_areas WHERE name = ?2 COLLATE NOCASE)");
        check_sqlite(database.get(), sqlite3_bind_int64(
            hide_source.get(), 1, static_cast<sqlite3_int64>(message_id)), "binding source public message ID");
        bind_text(database.get(), hide_source.get(), 2, source_area);
        check_sqlite(database.get(), sqlite3_step(hide_source.get()), "hiding public message after move");
        if (sqlite3_changes(database.get()) == 0) {
            throw std::invalid_argument("source public message no longer exists in the selected area");
        }
        execute_sql(database.get(), "COMMIT", "saving public-to-private message move");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
    return destination_message_id;
}

MessageUserUsage MessageStore::user_usage(std::string_view handle) const {
    if (!valid_handle(handle)) {
        throw std::invalid_argument("invalid account handle for message usage lookup");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    const auto count = [&database, handle](const char* sql, std::string_view operation) {
        Statement query(database.get(), sql);
        bind_text(database.get(), query.get(), 1, handle);
        const int result = sqlite3_step(query.get());
        check_sqlite(database.get(), result, operation);
        if (result != SQLITE_ROW) {
            return std::uint64_t{};
        }
        return static_cast<std::uint64_t>(std::max<sqlite3_int64>(0,
            sqlite3_column_int64(query.get(), 0)));
    };
    return {
        count("SELECT COUNT(*) FROM messages WHERE author_handle = ?1 COLLATE NOCASE AND deleted = 0",
            "counting account public posts"),
        count("SELECT COUNT(*) FROM private_messages WHERE sender_handle = ?1 COLLATE NOCASE",
            "counting account private mail"),
    };
}

BoardMessagePage MessageStore::board_page(
    std::string_view area,
    std::string_view viewer,
    std::size_t page,
    std::size_t page_size,
    bool unread_only) const {
    if (!valid_area_name(area)) {
        throw std::invalid_argument("invalid message area name");
    }
    if (!valid_handle(viewer)) {
        throw std::invalid_argument("invalid viewer handle");
    }
    initialize();
    page_size = std::clamp<std::size_t>(page_size, 1, 50);
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    if (!area_access_allowed(database.get(), viewer, area, false)) {
        throw std::invalid_argument("message area is not available to this account");
    }
    check_sqlite(database.get(), sqlite3_exec(database.get(), "BEGIN", nullptr, nullptr, nullptr),
        "starting message board snapshot");
    Statement count_statement(database.get(),
        "SELECT COUNT(messages.id), COUNT(messages.id) - COUNT(read_marks.message_id) "
        "FROM messages JOIN message_areas ON message_areas.id = messages.area_id "
        "LEFT JOIN message_reads AS read_marks ON read_marks.message_id = messages.id "
        "AND read_marks.user_handle = ?2 COLLATE NOCASE "
        "WHERE message_areas.name = ?1 COLLATE NOCASE "
        "AND ((messages.deleted = 0 AND messages.unvalidated = 0) OR ?4 = 1) "
        "AND (?3 = 0 OR read_marks.message_id IS NULL)");
    bind_text(database.get(), count_statement.get(), 1, area);
    bind_text(database.get(), count_statement.get(), 2, viewer);
    const bool moderator = area_moderator_allowed(database.get(), viewer, area);
    AccessLevels levels = account_access_levels(database.get(), viewer);
    levels.message_area_number = find_message_area_id(database.get(), area);
    const bool may_read_anonymous = evaluate_legacy_acs(
        message_setting(database.get(), "anonymous_read_acs", "S255"), levels);
    const bool sysop = levels.is_sysop;
    check_sqlite(database.get(), sqlite3_bind_int(count_statement.get(), 3, unread_only ? 1 : 0),
        "binding unread message filter");
    check_sqlite(database.get(), sqlite3_bind_int(count_statement.get(), 4, moderator ? 1 : 0),
        "binding message moderator visibility");
    const int count_result = sqlite3_step(count_statement.get());
    check_sqlite(database.get(), count_result, "counting message posts");
    const sqlite3_int64 total_count = sqlite3_column_int64(count_statement.get(), 0);
    const std::size_t total = total_count <= 0 ? 0 : static_cast<std::size_t>(total_count);
    const sqlite3_int64 unread_count = sqlite3_column_int64(count_statement.get(), 1);
    const std::size_t unread_total = unread_count <= 0 ? 0 : static_cast<std::size_t>(unread_count);
    const std::size_t page_count = total / page_size + (total % page_size == 0 ? 0 : 1);
    const std::size_t last_page = page_count == 0 ? 0 : page_count - 1;
    page = std::min(page, last_page);
    const std::size_t offset = page * page_size;

    Statement statement(database.get(),
        "SELECT messages.id, messages.author_handle, messages.subject, messages.body, messages.created_at, "
        "messages.reply_to, messages.allow_mci, messages.deleted, "
        "CASE WHEN read_marks.message_id IS NULL THEN 1 ELSE 0 END "
        ", messages.unvalidated, messages.permanent, messages.recipient, "
        "messages.anonymous_type, messages.posted_as "
        "FROM messages JOIN message_areas ON message_areas.id = messages.area_id "
        "LEFT JOIN message_reads AS read_marks ON read_marks.message_id = messages.id "
        "AND read_marks.user_handle = ?2 COLLATE NOCASE "
        "WHERE message_areas.name = ?1 COLLATE NOCASE "
        "AND ((messages.deleted = 0 AND messages.unvalidated = 0) OR ?4 = 1) "
        "AND (?3 = 0 OR read_marks.message_id IS NULL) "
        "ORDER BY messages.id DESC LIMIT ?5 OFFSET ?6");
    bind_text(database.get(), statement.get(), 1, area);
    bind_text(database.get(), statement.get(), 2, viewer);
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 3, unread_only ? 1 : 0),
        "binding unread message filter");
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 4, moderator ? 1 : 0),
        "binding message moderator visibility");
    check_sqlite(database.get(), sqlite3_bind_int64(statement.get(), 5, static_cast<sqlite3_int64>(page_size)),
        "setting message list limit");
    check_sqlite(database.get(), sqlite3_bind_int64(statement.get(), 6, static_cast<sqlite3_int64>(offset)),
        "setting message list offset");

    std::vector<BoardMessage> messages;
    for (;;) {
        const int result = sqlite3_step(statement.get());
        if (result == SQLITE_DONE) {
            break;
        }
        check_sqlite(database.get(), result, "reading message board");
        BoardMessage message = read_message(statement.get());
        reveal_anonymous_author(message,
            message.anonymous_type == 2 ? sysop : (moderator || may_read_anonymous));
        messages.push_back(std::move(message));
    }
    return {std::move(messages), page, std::max<std::size_t>(1, page_count), total, unread_total};
}

BoardMessagePage MessageStore::search_page(
    std::string_view area,
    std::string_view viewer,
    std::string_view query,
    MessageSearchField field,
    bool unread_only,
    std::size_t page,
    std::size_t page_size) const {
    const int field_value = static_cast<int>(field);
    if (!valid_area_name(area) || !valid_handle(viewer) || query.size() > 40 ||
        field_value < static_cast<int>(MessageSearchField::From) ||
        field_value > static_cast<int>(MessageSearchField::Yours)) {
        throw std::invalid_argument("invalid public-message search request");
    }
    if (field != MessageSearchField::ToMe && field != MessageSearchField::Yours && query.empty()) {
        throw std::invalid_argument("enter a search phrase before choosing a message field");
    }
    std::string escaped_query;
    escaped_query.reserve(query.size() * 2 + 2);
    escaped_query.push_back('%');
    for (const char character : query) {
        if (character == '%' || character == '_' || character == '\\') {
            escaped_query.push_back('\\');
        }
        escaped_query.push_back(character);
    }
    escaped_query.push_back('%');

    initialize();
    page_size = std::clamp<std::size_t>(page_size, 1, 50);
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    if (!area_access_allowed(database.get(), viewer, area, false)) {
        throw std::invalid_argument("message area is not available to this account");
    }
    check_sqlite(database.get(), sqlite3_exec(database.get(), "BEGIN", nullptr, nullptr, nullptr),
        "starting message-search snapshot");
    const bool moderator = area_moderator_allowed(database.get(), viewer, area);
    AccessLevels levels = account_access_levels(database.get(), viewer);
    levels.message_area_number = find_message_area_id(database.get(), area);
    const bool may_read_anonymous = evaluate_legacy_acs(
        message_setting(database.get(), "anonymous_read_acs", "S255"), levels);
    const bool sysop = levels.is_sysop;
    Statement area_settings(database.get(),
        "SELECT use_real_names FROM message_areas WHERE name = ?1 COLLATE NOCASE");
    bind_text(database.get(), area_settings.get(), 1, area);
    const int area_settings_result = sqlite3_step(area_settings.get());
    check_sqlite(database.get(), area_settings_result, "reading message-search area settings");
    if (area_settings_result != SQLITE_ROW) {
        throw std::invalid_argument("message area does not exist");
    }
    const bool use_real_names = sqlite3_column_int(area_settings.get(), 0) != 0;
    const std::string visible_author =
        "(CASE WHEN ?9 = 1 AND author_account.real_name <> '' "
        "THEN author_account.real_name ELSE messages.author_handle END)";
    const std::string author_search =
        "(CASE WHEN messages.anonymous_type = 0 THEN " + visible_author + " "
        "WHEN messages.anonymous_type = 2 AND ?7 = 1 THEN " + visible_author + " "
        "WHEN messages.anonymous_type <> 2 AND (?7 = 1 OR ?8 = 1) THEN " + visible_author + " "
        "WHEN messages.anonymous_type IN (1,2) THEN 'Anonymous' "
        "WHEN messages.anonymous_type = 3 THEN 'Abby' "
        "WHEN messages.anonymous_type = 4 THEN 'Problemed Person' "
        "WHEN messages.anonymous_type = 5 AND messages.posted_as <> '' THEN messages.posted_as "
        "ELSE 'Anonymous' END)";
    const std::string recipient_search =
        "(CASE WHEN ?9 = 1 AND recipient_account.real_name <> '' "
        "THEN recipient_account.real_name ELSE messages.recipient END)";
    const std::string filter =
        "((?3 = 1 AND lower(" + author_search + ") LIKE lower(?4) ESCAPE '\\') "
        "OR (?3 = 2 AND lower(" + recipient_search + ") LIKE lower(?4) ESCAPE '\\') "
        "OR (?3 = 3 AND lower(messages.subject) LIKE lower(?4) ESCAPE '\\') "
        "OR (?3 = 4 AND (lower(" + author_search + ") LIKE lower(?4) ESCAPE '\\' "
        "OR lower(" + recipient_search + ") LIKE lower(?4) ESCAPE '\\' "
        "OR lower(messages.subject) LIKE lower(?4) ESCAPE '\\' "
        "OR lower(messages.body) LIKE lower(?4) ESCAPE '\\')) "
        "OR (?3 = 5 AND messages.recipient = ?2 COLLATE NOCASE) "
        "OR (?3 = 6 AND messages.author_handle = ?2 COLLATE NOCASE))";
    const char* count_sql =
        "SELECT COUNT(messages.id), COUNT(messages.id) - COUNT(read_marks.message_id) "
        "FROM messages JOIN message_areas ON message_areas.id = messages.area_id "
        "LEFT JOIN accounts AS author_account ON author_account.handle = messages.author_handle COLLATE NOCASE "
        "LEFT JOIN accounts AS recipient_account ON recipient_account.handle = messages.recipient COLLATE NOCASE "
        "LEFT JOIN message_reads AS read_marks ON read_marks.message_id = messages.id "
        "AND read_marks.user_handle = ?2 COLLATE NOCASE "
        "WHERE message_areas.name = ?1 COLLATE NOCASE "
        "AND ((messages.deleted = 0 AND messages.unvalidated = 0) OR ?6 = 1) "
        "AND (?5 = 0 OR read_marks.message_id IS NULL) AND ";
    const std::string count_query = std::string(count_sql) + filter;
    Statement count_statement(database.get(), count_query.c_str());
    bind_text(database.get(), count_statement.get(), 1, area);
    bind_text(database.get(), count_statement.get(), 2, viewer);
    check_sqlite(database.get(), sqlite3_bind_int(count_statement.get(), 3, field_value),
        "binding message-search field");
    bind_text(database.get(), count_statement.get(), 4, escaped_query);
    check_sqlite(database.get(), sqlite3_bind_int(count_statement.get(), 5, unread_only ? 1 : 0),
        "binding new-message search filter");
    check_sqlite(database.get(), sqlite3_bind_int(count_statement.get(), 6, moderator ? 1 : 0),
        "binding message moderator visibility");
    check_sqlite(database.get(), sqlite3_bind_int(count_statement.get(), 7, sysop ? 1 : 0),
        "binding message-search identity access");
    check_sqlite(database.get(), sqlite3_bind_int(count_statement.get(), 8,
        (moderator || may_read_anonymous) ? 1 : 0),
        "binding anonymous message-search access");
    check_sqlite(database.get(), sqlite3_bind_int(count_statement.get(), 9, use_real_names ? 1 : 0),
        "binding real-name search setting");
    int count_result = sqlite3_step(count_statement.get());
    check_sqlite(database.get(), count_result, "counting message-search results");
    const sqlite3_int64 total_count = sqlite3_column_int64(count_statement.get(), 0);
    const std::size_t total = total_count <= 0 ? 0 : static_cast<std::size_t>(total_count);
    const sqlite3_int64 unread_count = sqlite3_column_int64(count_statement.get(), 1);
    const std::size_t unread_total = unread_count <= 0 ? 0 : static_cast<std::size_t>(unread_count);
    const std::size_t page_count = total / page_size + (total % page_size == 0 ? 0 : 1);
    page = std::min(page, page_count == 0 ? 0 : page_count - 1);
    const std::size_t offset = page * page_size;

    const char* message_sql =
        "SELECT messages.id, messages.author_handle, messages.subject, messages.body, messages.created_at, "
        "messages.reply_to, messages.allow_mci, messages.deleted, "
        "CASE WHEN read_marks.message_id IS NULL THEN 1 ELSE 0 END, "
        "messages.unvalidated, messages.permanent, messages.recipient, "
        "messages.anonymous_type, messages.posted_as "
        "FROM messages JOIN message_areas ON message_areas.id = messages.area_id "
        "LEFT JOIN accounts AS author_account ON author_account.handle = messages.author_handle COLLATE NOCASE "
        "LEFT JOIN accounts AS recipient_account ON recipient_account.handle = messages.recipient COLLATE NOCASE "
        "LEFT JOIN message_reads AS read_marks ON read_marks.message_id = messages.id "
        "AND read_marks.user_handle = ?2 COLLATE NOCASE "
        "WHERE message_areas.name = ?1 COLLATE NOCASE "
        "AND ((messages.deleted = 0 AND messages.unvalidated = 0) OR ?6 = 1) "
        "AND (?5 = 0 OR read_marks.message_id IS NULL) AND ";
    const std::string search_query = std::string(message_sql) + filter +
        " ORDER BY messages.id DESC LIMIT ?10 OFFSET ?11";
    Statement statement(database.get(), search_query.c_str());
    bind_text(database.get(), statement.get(), 1, area);
    bind_text(database.get(), statement.get(), 2, viewer);
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 3, field_value),
        "binding message-search field");
    bind_text(database.get(), statement.get(), 4, escaped_query);
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 5, unread_only ? 1 : 0),
        "binding new-message search filter");
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 6, moderator ? 1 : 0),
        "binding message moderator visibility");
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 7, sysop ? 1 : 0),
        "binding message-search identity access");
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 8,
        (moderator || may_read_anonymous) ? 1 : 0),
        "binding anonymous message-search access");
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 9, use_real_names ? 1 : 0),
        "binding real-name search setting");
    check_sqlite(database.get(), sqlite3_bind_int64(
        statement.get(), 10, static_cast<sqlite3_int64>(page_size)), "setting search-result limit");
    check_sqlite(database.get(), sqlite3_bind_int64(
        statement.get(), 11, static_cast<sqlite3_int64>(offset)), "setting search-result offset");

    std::vector<BoardMessage> messages;
    for (;;) {
        const int result = sqlite3_step(statement.get());
        if (result == SQLITE_DONE) {
            break;
        }
        check_sqlite(database.get(), result, "reading message-search results");
        BoardMessage message = read_message(statement.get());
        reveal_anonymous_author(message,
            message.anonymous_type == 2 ? sysop : (moderator || may_read_anonymous));
        messages.push_back(std::move(message));
    }
    return {std::move(messages), page, std::max<std::size_t>(1, page_count), total, unread_total};
}

UnreadBoardPage MessageStore::unread_messages(
    std::string_view viewer,
    std::size_t page,
    std::size_t page_size,
    const std::vector<long long>& unlocked_area_ids) const {
    if (!valid_handle(viewer)) {
        throw std::invalid_argument("invalid viewer handle");
    }
    initialize();
    page_size = std::clamp<std::size_t>(page_size, 1, 50);
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    check_sqlite(database.get(), sqlite3_exec(database.get(), "BEGIN", nullptr, nullptr, nullptr),
        "starting unread-message scan");
    const AccessLevels levels = account_access_levels(database.get(), viewer);
    const std::set<long long> unlocked(unlocked_area_ids.begin(), unlocked_area_ids.end());
    const std::string anonymous_read_acs =
        message_setting(database.get(), "anonymous_read_acs", "S255");
    std::vector<long long> visible_area_ids;
    std::vector<long long> moderated_area_ids;
    std::vector<long long> anonymous_visible_area_ids;
    {
        Statement areas_query(database.get(),
            "SELECT areas.id, areas.access_acs, areas.sysop_acs, "
            "COALESCE(areas.password_hash, ''), "
            "COALESCE(scan_preferences.enabled, 1), areas.force_read FROM message_areas AS areas "
            "LEFT JOIN message_area_scan_preferences AS scan_preferences ON scan_preferences.area_id = areas.id "
            "AND scan_preferences.user_handle = ?1 COLLATE NOCASE ORDER BY areas.id");
        bind_text(database.get(), areas_query.get(), 1, viewer);
        for (;;) {
            const int step = sqlite3_step(areas_query.get());
            if (step == SQLITE_DONE) {
                break;
            }
            check_sqlite(database.get(), step, "reading message-area access rules for unread scan");
            const long long area_id = sqlite3_column_int64(areas_query.get(), 0);
            AccessLevels area_levels = levels;
            area_levels.message_area_number = area_id;
            if (evaluate_legacy_acs(anonymous_read_acs, area_levels)) {
                anonymous_visible_area_ids.push_back(area_id);
            }
            if (evaluate_legacy_acs(column_text(areas_query.get(), 1), area_levels) &&
                (column_text(areas_query.get(), 3).empty() || unlocked.contains(area_id)) &&
                (sqlite3_column_int(areas_query.get(), 4) != 0 ||
                    sqlite3_column_int(areas_query.get(), 5) != 0)) {
                visible_area_ids.push_back(area_id);
                if (levels.is_sysop || evaluate_legacy_acs(column_text(areas_query.get(), 2), area_levels)) {
                    moderated_area_ids.push_back(area_id);
                }
            }
        }
    }
    if (visible_area_ids.empty()) {
        return {{}, 0, 1, 0};
    }
    const std::string placeholders = area_id_placeholders(visible_area_ids.size(), 2);
    const int moderator_first_index = 2 + static_cast<int>(visible_area_ids.size());
    const std::string moderator_placeholders = area_id_placeholders(
        moderated_area_ids.size(), moderator_first_index);
    const std::string visibility_filter = moderated_area_ids.empty()
        ? " AND messages.deleted = 0 AND messages.unvalidated = 0"
        : " AND ((messages.deleted = 0 AND messages.unvalidated = 0) OR messages.area_id IN (" +
            moderator_placeholders + "))";
    const std::string count_sql =
        "SELECT COUNT(messages.id) FROM messages "
        "LEFT JOIN message_reads AS read_marks ON read_marks.message_id = messages.id "
        "AND read_marks.user_handle = ?1 COLLATE NOCASE "
        "WHERE read_marks.message_id IS NULL AND messages.area_id IN (" + placeholders + ")" + visibility_filter;
    Statement count(database.get(), count_sql.c_str());
    bind_text(database.get(), count.get(), 1, viewer);
    bind_visible_area_ids(database.get(), count.get(), visible_area_ids, 2);
    if (!moderated_area_ids.empty()) {
        bind_visible_area_ids(database.get(), count.get(), moderated_area_ids, moderator_first_index);
    }
    const int count_result = sqlite3_step(count.get());
    check_sqlite(database.get(), count_result, "counting unread messages");
    const sqlite3_int64 total_count = sqlite3_column_int64(count.get(), 0);
    const std::size_t total = total_count <= 0 ? 0 : static_cast<std::size_t>(total_count);
    const std::size_t page_count = total / page_size + (total % page_size == 0 ? 0 : 1);
    page = std::min(page, page_count == 0 ? 0 : page_count - 1);

    const int limit_index = 2 + static_cast<int>(visible_area_ids.size()) +
        static_cast<int>(moderated_area_ids.size());
    const int offset_index = limit_index + 1;
    const std::string query_sql =
        "SELECT messages.id, messages.author_handle, messages.subject, messages.body, "
        "messages.created_at, messages.reply_to, messages.allow_mci, messages.deleted, 1, "
        "messages.unvalidated, messages.permanent, messages.recipient, messages.anonymous_type, "
        "messages.posted_as, message_areas.name, messages.area_id "
        "FROM messages JOIN message_areas ON message_areas.id = messages.area_id "
        "LEFT JOIN message_reads AS read_marks ON read_marks.message_id = messages.id "
        "AND read_marks.user_handle = ?1 COLLATE NOCASE "
        "WHERE read_marks.message_id IS NULL AND messages.area_id IN (" + placeholders + ")" + visibility_filter + " "
        "ORDER BY messages.id DESC LIMIT ?" + std::to_string(limit_index) +
        " OFFSET ?" + std::to_string(offset_index);
    Statement query(database.get(), query_sql.c_str());
    bind_text(database.get(), query.get(), 1, viewer);
    bind_visible_area_ids(database.get(), query.get(), visible_area_ids, 2);
    if (!moderated_area_ids.empty()) {
        bind_visible_area_ids(database.get(), query.get(), moderated_area_ids, moderator_first_index);
    }
    check_sqlite(database.get(), sqlite3_bind_int64(
        query.get(), limit_index, static_cast<sqlite3_int64>(page_size)), "setting unread scan limit");
    check_sqlite(database.get(), sqlite3_bind_int64(
        query.get(), offset_index, static_cast<sqlite3_int64>(page * page_size)), "setting unread scan offset");

    UnreadBoardPage result;
    result.page = page;
    result.page_count = std::max<std::size_t>(1, page_count);
    result.total = total;
    for (;;) {
        const int step = sqlite3_step(query.get());
        if (step == SQLITE_DONE) {
            break;
        }
        check_sqlite(database.get(), step, "reading unread-message scan");
        BoardMessage message = read_message(query.get());
        const long long area_id = sqlite3_column_int64(query.get(), 15);
        const bool area_moderator = std::find(moderated_area_ids.begin(), moderated_area_ids.end(), area_id) !=
            moderated_area_ids.end();
        const bool may_read_anonymous = std::find(
            anonymous_visible_area_ids.begin(), anonymous_visible_area_ids.end(), area_id) !=
            anonymous_visible_area_ids.end();
        reveal_anonymous_author(message,
            message.anonymous_type == 2 ? levels.is_sysop : (area_moderator || may_read_anonymous));
        result.messages.push_back({std::move(message), column_text(query.get(), 14)});
    }
    return result;
}

std::optional<BoardMessage> MessageStore::find(
    std::string_view viewer, std::string_view area, long long message_id) const {
    if (!valid_handle(viewer) || !valid_area_name(area) || message_id < 1) {
        return std::nullopt;
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    if (!area_access_allowed(database.get(), viewer, area, false)) {
        return std::nullopt;
    }
    const bool moderator = area_moderator_allowed(database.get(), viewer, area);
    AccessLevels levels = account_access_levels(database.get(), viewer);
    levels.message_area_number = find_message_area_id(database.get(), area);
    const bool may_read_anonymous = evaluate_legacy_acs(
        message_setting(database.get(), "anonymous_read_acs", "S255"), levels);
    const bool sysop = levels.is_sysop;
    Statement statement(database.get(),
        "SELECT messages.id, messages.author_handle, messages.subject, messages.body, "
        "messages.created_at, messages.reply_to, messages.allow_mci, messages.deleted, 0, "
        "messages.unvalidated, messages.permanent, messages.recipient, messages.anonymous_type, "
        "messages.posted_as "
        "FROM messages JOIN message_areas ON message_areas.id = messages.area_id "
        "WHERE message_areas.name = ?1 COLLATE NOCASE AND messages.id = ?2 "
        "AND ((messages.deleted = 0 AND messages.unvalidated = 0) OR ?3 = 1)");
    bind_text(database.get(), statement.get(), 1, area);
    check_sqlite(database.get(), sqlite3_bind_int64(
        statement.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding message ID");
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 3, moderator ? 1 : 0),
        "binding message moderator visibility");
    const int result = sqlite3_step(statement.get());
    if (result == SQLITE_DONE) {
        return std::nullopt;
    }
    check_sqlite(database.get(), result, "reading message by ID");
    BoardMessage message = read_message(statement.get());
    reveal_anonymous_author(message,
        message.anonymous_type == 2 ? sysop : (moderator || may_read_anonymous));
    return message;
}

std::optional<LocatedBoardMessage> MessageStore::find_with_area(
    std::string_view viewer, long long message_id) const {
    if (!valid_handle(viewer) || message_id < 1) {
        return std::nullopt;
    }
    initialize();
    std::string area_name;
    {
        Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
        Statement statement(database.get(),
            "SELECT message_areas.name FROM messages "
            "JOIN message_areas ON message_areas.id = messages.area_id WHERE messages.id = ?1");
        check_sqlite(database.get(), sqlite3_bind_int64(
            statement.get(), 1, static_cast<sqlite3_int64>(message_id)), "binding parent message ID");
        const int result = sqlite3_step(statement.get());
        if (result == SQLITE_DONE) {
            return std::nullopt;
        }
        check_sqlite(database.get(), result, "locating parent message area");
        area_name = column_text(statement.get(), 0);
    }
    const auto message = find(viewer, area_name, message_id);
    if (!message.has_value()) {
        return std::nullopt;
    }
    return LocatedBoardMessage{*message, std::move(area_name)};
}

void MessageStore::mark_read(std::string_view viewer, std::string_view area, long long message_id) const {
    if (!valid_handle(viewer)) {
        throw std::invalid_argument("invalid viewer handle");
    }
    if (!valid_area_name(area) || message_id < 1) {
        throw std::invalid_argument("invalid message read marker");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    if (!area_access_allowed(database.get(), viewer, area, false)) {
        throw std::invalid_argument("message area is not available to this account");
    }
    const bool moderator = area_moderator_allowed(database.get(), viewer, area);
    Statement statement(database.get(),
        "INSERT OR IGNORE INTO message_reads(user_handle, message_id) "
        "SELECT ?1, messages.id FROM messages "
        "JOIN message_areas ON message_areas.id = messages.area_id "
        "WHERE message_areas.name = ?2 COLLATE NOCASE AND messages.id = ?3 "
        "AND ((messages.deleted = 0 AND messages.unvalidated = 0) OR ?4 = 1)");
    bind_text(database.get(), statement.get(), 1, viewer);
    bind_text(database.get(), statement.get(), 2, area);
    check_sqlite(database.get(), sqlite3_bind_int64(
        statement.get(), 3, static_cast<sqlite3_int64>(message_id)), "binding read marker message ID");
    check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 4, moderator ? 1 : 0),
        "binding message moderator visibility");
    check_sqlite(database.get(), sqlite3_step(statement.get()), "marking message read");
}

void MessageStore::create_area(std::string_view name) const {
    if (!valid_area_name(name)) {
        throw std::invalid_argument("area name must be 1-40 printable characters without surrounding spaces");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(database.get(), "INSERT INTO message_areas(name) VALUES(?1)");
    bind_text(database.get(), statement.get(), 1, name);
    check_sqlite(database.get(), sqlite3_step(statement.get()), "creating message area");
}

void MessageStore::rename_area(long long area_id, std::string_view name) const {
    if (area_id < 1 || !valid_area_name(name)) {
        throw std::invalid_argument("message area ID and name are invalid");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(database.get(), "UPDATE message_areas SET name = ?1 WHERE id = ?2");
    bind_text(database.get(), statement.get(), 1, name);
    check_sqlite(database.get(), sqlite3_bind_int64(
        statement.get(), 2, static_cast<sqlite3_int64>(area_id)), "binding message-area ID");
    check_sqlite(database.get(), sqlite3_step(statement.get()), "renaming message area");
    if (sqlite3_changes(database.get()) == 0) {
        throw std::invalid_argument("message area does not exist");
    }
}

RemovedBoardArea MessageStore::remove_area(long long area_id) const {
    if (area_id < 1) {
        throw std::invalid_argument("message area ID must be a positive number");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting message-area deletion");
    std::string area_name;
    std::size_t message_count = 0;
    try {
        {
            Statement query(database.get(),
                "SELECT name, (SELECT COUNT(*) FROM messages WHERE area_id = message_areas.id) "
                "FROM message_areas WHERE id = ?1");
            check_sqlite(database.get(), sqlite3_bind_int64(
                query.get(), 1, static_cast<sqlite3_int64>(area_id)), "binding message-area ID");
            const int step = sqlite3_step(query.get());
            check_sqlite(database.get(), step, "looking up message area for deletion");
            if (step == SQLITE_DONE) {
                throw std::invalid_argument("message area does not exist");
            }
            area_name = column_text(query.get(), 0);
            message_count = static_cast<std::size_t>(sqlite3_column_int64(query.get(), 1));
        }

        {
            Statement detach_replies(database.get(),
                "UPDATE messages SET reply_to = NULL WHERE reply_to IN "
                "(SELECT id FROM messages WHERE area_id = ?1)");
            check_sqlite(database.get(), sqlite3_bind_int64(
                detach_replies.get(), 1, static_cast<sqlite3_int64>(area_id)), "binding message-area ID");
            check_sqlite(database.get(), sqlite3_step(detach_replies.get()), "detaching replies to removed posts");
        }
        {
            Statement remove_messages(database.get(), "DELETE FROM messages WHERE area_id = ?1");
            check_sqlite(database.get(), sqlite3_bind_int64(
                remove_messages.get(), 1, static_cast<sqlite3_int64>(area_id)), "binding message-area ID");
            check_sqlite(database.get(), sqlite3_step(remove_messages.get()), "deleting message-area posts");
        }
        {
            Statement remove_area(database.get(), "DELETE FROM message_areas WHERE id = ?1");
            check_sqlite(database.get(), sqlite3_bind_int64(
                remove_area.get(), 1, static_cast<sqlite3_int64>(area_id)), "binding message-area ID");
            check_sqlite(database.get(), sqlite3_step(remove_area.get()), "deleting message-area listing");
            if (sqlite3_changes(database.get()) == 0) {
                throw std::invalid_argument("message area does not exist");
            }
        }
        execute_sql(database.get(), "COMMIT", "saving message-area deletion");
    } catch (...) {
        const std::exception_ptr failure = std::current_exception();
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        std::rethrow_exception(failure);
    }
    return {area_id, std::move(area_name), message_count};
}

void MessageStore::post(
    std::string_view author,
    std::string_view area,
    std::string_view subject,
    std::string_view body,
    std::optional<long long> reply_to,
    bool allow_mci,
    std::string_view recipient,
    int anonymous_type,
    std::string_view posted_as,
    int posts_this_call) const {
    if (!valid_handle(author)) {
        throw std::invalid_argument("invalid author handle");
    }
    if (!valid_area_name(area)) {
        throw std::invalid_argument("invalid message area name");
    }
    if (subject.empty() || subject.size() > 80 || has_unsafe_text(subject, false)) {
        throw std::invalid_argument("subject must be 1-80 characters without control codes");
    }
    if (!valid_message_body(body)) {
        throw std::invalid_argument("message body must be 1-500 lines of up to 78 characters without terminal control codes");
    }
    const std::string recipient_name = recipient.empty() ? "All" : std::string(recipient);
    if (recipient_name.size() > 36 || has_unsafe_text(recipient_name, false)) {
        throw std::invalid_argument("message recipient must be 1-36 characters without control codes");
    }
    if (anonymous_type < 0 || anonymous_type > 5) {
        throw std::invalid_argument("invalid anonymous message identity");
    }
    const std::string display_name(posted_as);
    if (display_name.size() > 36 || has_unsafe_text(display_name, false)) {
        throw std::invalid_argument("anonymous display name must be at most 36 characters without control codes");
    }

    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting public-message post");
    try {
        if (!area_access_allowed(database.get(), author, area, true)) {
            throw std::invalid_argument("account cannot post in this message area");
        }
        AccessLevels levels = account_access_levels(database.get(), author);
        if (levels.ac_flags.find('P') != std::string::npos) {
            throw std::invalid_argument("account cannot make normal public posts");
        }
        if (posts_this_call < 0 || (!levels.is_sysop && posts_this_call >=
            message_count_limit(database.get(), "max_public_posts_per_call"))) {
            throw std::invalid_argument("account has reached the public-message limit for this call");
        }
        const bool no_credit_check = levels.ac_flags.find('3') != std::string::npos;
        const int credit_cost = message_credit_cost(database.get(), "credit_public_post");
        const std::int64_t current_balance = account_credit_balance(database.get(), author);
        if (!no_credit_check && current_balance < credit_cost) {
            throw std::invalid_argument("there are not enough account credits to post a public message");
        }
        Statement mode_query(database.get(),
            "SELECT anonymous_mode, filter_public_text, add_tearline, origin_line, origin_address "
            ", id "
            "FROM message_areas "
            "WHERE name = ?1 COLLATE NOCASE");
        bind_text(database.get(), mode_query.get(), 1, area);
        const int mode_result = sqlite3_step(mode_query.get());
        check_sqlite(database.get(), mode_result, "reading message-area anonymous mode for posting");
        if (mode_result == SQLITE_DONE) {
            throw std::invalid_argument("message area does not exist");
        }
        levels.message_area_number = sqlite3_column_int64(mode_query.get(), 5);
        if (!evaluate_legacy_acs(
                message_setting(database.get(), "normal_public_post_acs", ""), levels)) {
            throw std::invalid_argument("account cannot make normal public posts");
        }
        std::string stored_body = sqlite3_column_int(mode_query.get(), 1) != 0
            ? filter_legacy_public_message(body) : std::string(body);
        if (!valid_message_body(stored_body)) {
            throw std::invalid_argument(
                "message body must be 1-500 lines of up to 78 characters without terminal control codes");
        }
        if (sqlite3_column_int(mode_query.get(), 2) != 0) {
            const std::string origin_line = column_text(mode_query.get(), 3);
            const std::string origin_address = column_text(mode_query.get(), 4);
            std::string footer = "\n\n--- Renegade v1.40\n * Origin: " + origin_line;
            if (!origin_address.empty()) {
                footer += " (" + origin_address + ")";
            }
            if (utf8_codepoint_count(footer.substr(footer.rfind('\n') + 1)) >
                kMessageLineCharacterLimit || stored_body.size() + footer.size() > kMessageBodyByteLimit) {
                throw std::invalid_argument("configured message tearline exceeds the message limits");
            }
            stored_body += footer;
        }
        AnonymousMode anonymous_mode = levels.ac_flags.find('*') != std::string::npos
            ? AnonymousMode::Disabled
            : static_cast<AnonymousMode>(sqlite3_column_int(mode_query.get(), 0));
        if (anonymous_mode == AnonymousMode::Disabled && levels.ac_flags.find('*') == std::string::npos &&
            evaluate_legacy_acs(message_setting(database.get(), "anonymous_post_acs", "S255"), levels)) {
            anonymous_mode = AnonymousMode::Optional;
        }
        bool identity_allowed = false;
        switch (anonymous_mode) {
        case AnonymousMode::Disabled:
            identity_allowed = anonymous_type == 0;
            break;
        case AnonymousMode::Optional:
        case AnonymousMode::Forced:
            identity_allowed = anonymous_type == 0 || anonymous_type == 1 ||
                (anonymous_type == 2 && levels.is_sysop);
            break;
        case AnonymousMode::DearAbby:
            identity_allowed = anonymous_type == 0 || anonymous_type == 3 || anonymous_type == 4;
            break;
        case AnonymousMode::AnyName:
            identity_allowed = anonymous_type == 0 || anonymous_type == 5;
            break;
        }
        if (anonymous_mode == AnonymousMode::Forced && anonymous_type == 0) {
            identity_allowed = false;
        }
        if (!identity_allowed) {
            throw std::invalid_argument("anonymous identity is not allowed by this area or account settings");
        }
        if (anonymous_type == 5 && display_name.empty()) {
            throw std::invalid_argument("enter the name to display on this message");
        }
        if (anonymous_type != 5 && !display_name.empty()) {
            throw std::invalid_argument("a display name is only valid for an any-name anonymous post");
        }
        const bool store_mci = allow_mci && area_mci_allowed(database.get(), author, area);
        Statement statement(database.get(),
            "INSERT INTO messages(area_id, author_handle, subject, body, reply_to, allow_mci, unvalidated, "
            "recipient, anonymous_type, posted_as) "
            "SELECT area.id, ?1, ?3, ?4, ?5, ?6, "
            "CASE WHEN instr(account.acs_ac_flags, 'V') > 0 THEN 1 ELSE 0 END, ?7, ?8, ?9 "
            "FROM message_areas AS area JOIN accounts AS account ON account.handle = ?1 COLLATE NOCASE "
            "WHERE area.name = ?2 COLLATE NOCASE "
            "AND (?5 IS NULL OR EXISTS (SELECT 1 FROM messages AS parent "
            "WHERE parent.id = ?5 AND parent.area_id = area.id))");
        bind_text(database.get(), statement.get(), 1, author);
        bind_text(database.get(), statement.get(), 2, area);
        bind_text(database.get(), statement.get(), 3, subject);
        bind_text(database.get(), statement.get(), 4, stored_body);
        if (reply_to.has_value()) {
            check_sqlite(database.get(), sqlite3_bind_int64(
                statement.get(), 5, static_cast<sqlite3_int64>(*reply_to)), "binding reply target");
        } else {
            check_sqlite(database.get(), sqlite3_bind_null(statement.get(), 5), "binding reply target");
        }
        check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 6, store_mci ? 1 : 0),
            "binding message MCI permission");
        bind_text(database.get(), statement.get(), 7, recipient_name);
        check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 8, anonymous_type),
            "binding message anonymous identity");
        bind_text(database.get(), statement.get(), 9, display_name);
        check_sqlite(database.get(), sqlite3_step(statement.get()), "posting message");
        if (sqlite3_changes(database.get()) == 0) {
            throw std::invalid_argument("message area or reply target does not exist");
        }
        if (!no_credit_check) {
            set_account_credit_balance(database.get(), author, current_balance - credit_cost);
        }
        execute_sql(database.get(), "COMMIT", "saving public-message post and credits");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

PrivateMessagePage MessageStore::private_mail_page(
    std::string_view viewer,
    PrivateMailbox mailbox,
    std::size_t page,
    std::size_t page_size) const {
    if (!valid_handle(viewer)) {
        throw std::invalid_argument("invalid private-mail viewer handle");
    }
    initialize();
    page_size = std::clamp<std::size_t>(page_size, 1, 50);
    const bool inbox = mailbox == PrivateMailbox::Inbox;
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels viewer_levels = account_access_levels(database.get(), viewer);
    const bool may_read_anonymous = evaluate_legacy_acs(
        message_setting(database.get(), "anonymous_private_read_acs", "S255"), viewer_levels);

    Statement count_statement(database.get(), inbox
        ? "SELECT COUNT(messages.id), COALESCE(SUM(CASE WHEN read_marks.message_id IS NULL "
          "THEN 1 ELSE 0 END), 0) FROM private_messages AS messages "
          "LEFT JOIN private_message_reads AS read_marks ON read_marks.message_id = messages.id "
          "AND read_marks.user_handle = ?1 COLLATE NOCASE "
          "WHERE messages.recipient_handle = ?1 COLLATE NOCASE AND messages.deleted = 0"
        : "SELECT COUNT(messages.id), 0 FROM private_messages AS messages "
          "WHERE messages.sender_handle = ?1 COLLATE NOCASE");
    bind_text(database.get(), count_statement.get(), 1, viewer);
    check_sqlite(database.get(), sqlite3_step(count_statement.get()), "counting private messages");
    const sqlite3_int64 total_count = sqlite3_column_int64(count_statement.get(), 0);
    const std::size_t total = total_count <= 0 ? 0 : static_cast<std::size_t>(total_count);
    const sqlite3_int64 unread_count = sqlite3_column_int64(count_statement.get(), 1);
    const std::size_t unread_total = unread_count <= 0 ? 0 : static_cast<std::size_t>(unread_count);
    const std::size_t page_count = total / page_size + (total % page_size == 0 ? 0 : 1);
    page = std::min(page, page_count == 0 ? 0 : page_count - 1);
    const std::size_t offset = page * page_size;

    Statement statement(database.get(), inbox
        ? "SELECT messages.id, messages.sender_handle, messages.recipient_handle, messages.subject, "
          "messages.body, messages.created_at, messages.reply_to, "
          "CASE WHEN read_marks.message_id IS NULL THEN 1 ELSE 0 END, messages.deleted, "
          "messages.anonymous_type, messages.posted_as "
          "FROM private_messages AS messages "
          "LEFT JOIN private_message_reads AS read_marks ON read_marks.message_id = messages.id "
          "AND read_marks.user_handle = ?1 COLLATE NOCASE "
          "WHERE messages.recipient_handle = ?1 COLLATE NOCASE AND messages.deleted = 0 "
          "ORDER BY messages.id DESC LIMIT ?2 OFFSET ?3"
        : "SELECT messages.id, messages.sender_handle, messages.recipient_handle, messages.subject, "
          "messages.body, messages.created_at, messages.reply_to, 0, messages.deleted, "
          "messages.anonymous_type, messages.posted_as "
          "FROM private_messages AS messages "
          "WHERE messages.sender_handle = ?1 COLLATE NOCASE "
          "ORDER BY messages.id DESC LIMIT ?2 OFFSET ?3");
    bind_text(database.get(), statement.get(), 1, viewer);
    check_sqlite(database.get(), sqlite3_bind_int64(
        statement.get(), 2, static_cast<sqlite3_int64>(page_size)), "setting private-mail page size");
    check_sqlite(database.get(), sqlite3_bind_int64(
        statement.get(), 3, static_cast<sqlite3_int64>(offset)), "setting private-mail page offset");

    std::vector<PrivateMessage> messages;
    for (;;) {
        const int result = sqlite3_step(statement.get());
        if (result == SQLITE_DONE) {
            break;
        }
        check_sqlite(database.get(), result, "reading private mailbox");
        PrivateMessage message = read_private_message(statement.get());
        apply_private_sender_visibility(message, message.anonymous_type == 2
            ? viewer_levels.is_sysop
            : may_read_anonymous);
        messages.push_back(std::move(message));
    }
    return {std::move(messages), page, std::max<std::size_t>(1, page_count), total, unread_total};
}

std::optional<PrivateMessage> MessageStore::find_private(
    std::string_view viewer,
    long long message_id) const {
    if (!valid_handle(viewer) || message_id < 1) {
        return std::nullopt;
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels viewer_levels = account_access_levels(database.get(), viewer);
    const bool may_read_anonymous = evaluate_legacy_acs(
        message_setting(database.get(), "anonymous_private_read_acs", "S255"), viewer_levels);
    Statement statement(database.get(),
        "SELECT messages.id, messages.sender_handle, messages.recipient_handle, messages.subject, "
        "messages.body, messages.created_at, messages.reply_to, "
        "CASE WHEN messages.recipient_handle = ?1 COLLATE NOCASE "
        "AND read_marks.message_id IS NULL THEN 1 ELSE 0 END, messages.deleted, "
        "messages.anonymous_type, messages.posted_as "
        "FROM private_messages AS messages "
        "LEFT JOIN private_message_reads AS read_marks ON read_marks.message_id = messages.id "
        "AND read_marks.user_handle = ?1 COLLATE NOCASE "
        "WHERE messages.id = ?2 AND (messages.sender_handle = ?1 COLLATE NOCASE "
        "OR messages.recipient_handle = ?1 COLLATE NOCASE)");
    bind_text(database.get(), statement.get(), 1, viewer);
    check_sqlite(database.get(), sqlite3_bind_int64(
        statement.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding private message ID");
    const int result = sqlite3_step(statement.get());
    if (result == SQLITE_DONE) {
        return std::nullopt;
    }
    check_sqlite(database.get(), result, "reading private message");
    PrivateMessage message = read_private_message(statement.get());
    apply_private_sender_visibility(message, message.anonymous_type == 2
        ? viewer_levels.is_sysop
        : may_read_anonymous);
    return message;
}

void MessageStore::mark_private_read(std::string_view viewer, long long message_id) const {
    if (!valid_handle(viewer)) {
        throw std::invalid_argument("invalid private-mail viewer handle");
    }
    if (message_id < 1) {
        throw std::invalid_argument("invalid private message read marker");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(database.get(),
        "INSERT OR IGNORE INTO private_message_reads(user_handle, message_id) "
        "SELECT messages.recipient_handle, messages.id FROM private_messages AS messages "
        "WHERE messages.recipient_handle = ?1 COLLATE NOCASE AND messages.id = ?2 AND messages.deleted = 0");
    bind_text(database.get(), statement.get(), 1, viewer);
    check_sqlite(database.get(), sqlite3_bind_int64(
        statement.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding private message ID");
    check_sqlite(database.get(), sqlite3_step(statement.get()), "marking private message read");
}

bool MessageStore::toggle_private_deleted(std::string_view actor, long long message_id) const {
    if (!valid_handle(actor) || message_id < 1) {
        throw std::invalid_argument("invalid private-message deletion request");
    }
    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_sqlite(database.get(), sqlite3_exec(database.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr),
        "starting private-message status change");
    bool was_deleted{};
    {
        Statement query(database.get(),
            "SELECT sender_handle, recipient_handle, deleted FROM private_messages WHERE id = ?1");
        check_sqlite(database.get(), sqlite3_bind_int64(
            query.get(), 1, static_cast<sqlite3_int64>(message_id)), "binding private-message ID");
        const int result = sqlite3_step(query.get());
        check_sqlite(database.get(), result, "reading private-message status");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("private message does not exist");
        }
        const std::string sender = column_text(query.get(), 0);
        const std::string recipient = column_text(query.get(), 1);
        if (sqlite3_stricmp(sender.c_str(), std::string(actor).c_str()) != 0 &&
            sqlite3_stricmp(recipient.c_str(), std::string(actor).c_str()) != 0) {
            throw std::invalid_argument("only the sender or recipient may change this private message");
        }
        was_deleted = sqlite3_column_int(query.get(), 2) != 0;
    }
    Statement update(database.get(), "UPDATE private_messages SET deleted = ?1 WHERE id = ?2");
    check_sqlite(database.get(), sqlite3_bind_int(update.get(), 1, was_deleted ? 0 : 1),
        "binding private-message deleted status");
    check_sqlite(database.get(), sqlite3_bind_int64(
        update.get(), 2, static_cast<sqlite3_int64>(message_id)), "binding private-message ID");
    check_sqlite(database.get(), sqlite3_step(update.get()), "updating private-message status");
    check_sqlite(database.get(), sqlite3_exec(database.get(), "COMMIT", nullptr, nullptr, nullptr),
        "saving private-message status");
    make_database_private(database_path_);
    return !was_deleted;
}

void MessageStore::send_private(
    std::string_view sender,
    std::string_view recipient,
    std::string_view subject,
    std::string_view body,
    std::optional<long long> reply_to,
    bool anonymous,
    int sent_this_call) const {
    if (!valid_handle(sender) || !valid_handle(recipient)) {
        throw std::invalid_argument("invalid private-message account handle");
    }
    const std::string sender_name(sender);
    const std::string recipient_name(recipient);
    if (sqlite3_stricmp(sender_name.c_str(), recipient_name.c_str()) == 0) {
        throw std::invalid_argument("private messages must be addressed to another account");
    }
    if (subject.empty() || subject.size() > 80 || has_unsafe_text(subject, false)) {
        throw std::invalid_argument("private-message subject must be 1-80 characters without control codes");
    }
    if (!valid_message_body(body)) {
        throw std::invalid_argument("private-message body must be 1-500 lines of up to 78 characters without terminal control codes");
    }
    if (reply_to.has_value() && *reply_to < 1) {
        throw std::invalid_argument("invalid private-message reply target");
    }

    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting private-message post");
    try {
        const AccessLevels sender_levels = account_access_levels(database.get(), sender);
        if (!sender_levels.is_sysop && (sender_levels.ac_flags.find('E') != std::string::npos ||
            !evaluate_legacy_acs(message_setting(database.get(), "normal_private_post_acs", ""), sender_levels))) {
            throw std::invalid_argument("account cannot send private mail");
        }
        if (sent_this_call < 0 || (!sender_levels.is_sysop && sent_this_call >=
            message_count_limit(database.get(), "max_private_posts_per_call"))) {
            throw std::invalid_argument("account has reached the private-message limit for this call");
        }
        const int credit_cost = message_credit_cost(database.get(), "credit_private_mail");
        const bool no_credit_check = sender_levels.ac_flags.find('3') != std::string::npos;
        const std::int64_t current_balance = account_credit_balance(database.get(), sender);
        if (credit_cost > 0 && !sender_levels.is_sysop && !no_credit_check &&
            current_balance < credit_cost) {
            throw std::invalid_argument("there are not enough account credits to send private mail");
        }
        const bool anonymous_allowed = evaluate_legacy_acs(
            message_setting(database.get(), "anonymous_private_post_acs", "S255"), sender_levels);
        if (anonymous && !anonymous_allowed) {
            throw std::invalid_argument("account cannot send anonymous private mail");
        }
        ensure_private_recipient_accepts_mail(database.get(), recipient, sender_levels.is_sysop);
        const int anonymous_type = anonymous ? (sender_levels.is_sysop ? 2 : 1) : 0;
        Statement statement(database.get(),
            "INSERT INTO private_messages(sender_handle, recipient_handle, subject, body, reply_to, anonymous_type) "
            "SELECT sender.handle, recipient.handle, ?3, ?4, ?5, ?6 "
            "FROM accounts AS sender CROSS JOIN accounts AS recipient "
            "WHERE sender.handle = ?1 COLLATE NOCASE AND recipient.handle = ?2 COLLATE NOCASE "
            "AND (?5 IS NULL OR EXISTS (SELECT 1 FROM private_messages AS parent "
            "WHERE parent.id = ?5 AND (parent.sender_handle = ?1 COLLATE NOCASE "
            "OR parent.recipient_handle = ?1 COLLATE NOCASE)))");
        bind_text(database.get(), statement.get(), 1, sender);
        bind_text(database.get(), statement.get(), 2, recipient);
        bind_text(database.get(), statement.get(), 3, subject);
        bind_text(database.get(), statement.get(), 4, body);
        if (reply_to.has_value()) {
            check_sqlite(database.get(), sqlite3_bind_int64(
                statement.get(), 5, static_cast<sqlite3_int64>(*reply_to)), "binding private-message reply target");
        } else {
            check_sqlite(database.get(), sqlite3_bind_null(statement.get(), 5), "binding private-message reply target");
        }
        check_sqlite(database.get(), sqlite3_bind_int(statement.get(), 6, anonymous_type),
            "binding private-message anonymous identity");
        check_sqlite(database.get(), sqlite3_step(statement.get()), "sending private message");
        if (sqlite3_changes(database.get()) == 0) {
            throw std::invalid_argument("sender, recipient, or private-message reply target does not exist or is not accessible");
        }
        set_account_credit_balance(database.get(), sender, current_balance - credit_cost);
        execute_sql(database.get(), "COMMIT", "saving private message and credits");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

void MessageStore::forward_private(
    std::string_view actor,
    std::string_view recipient,
    long long original_message_id,
    std::string_view forwarding_header) const {
    if (!valid_handle(actor) || !valid_handle(recipient) || original_message_id < 1 ||
        forwarding_header.empty() || forwarding_header.size() > 512 ||
        has_unsafe_text(forwarding_header, true)) {
        throw std::invalid_argument("invalid private-message forward request");
    }
    const std::string actor_name(actor);
    const std::string recipient_name(recipient);
    if (sqlite3_stricmp(actor_name.c_str(), recipient_name.c_str()) == 0) {
        throw std::invalid_argument("private messages cannot be forwarded to yourself");
    }

    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting private-message forward");
    try {
        const AccessLevels actor_levels = account_access_levels(database.get(), actor);
        std::string canonical_recipient;
        {
            Statement target(database.get(), "SELECT handle FROM accounts WHERE handle = ?1 COLLATE NOCASE");
            bind_text(database.get(), target.get(), 1, recipient);
            const int result = sqlite3_step(target.get());
            check_sqlite(database.get(), result, "looking up private-message forward recipient");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("forward recipient account does not exist");
            }
            canonical_recipient = column_text(target.get(), 0);
        }
        ensure_private_recipient_accepts_mail(database.get(), canonical_recipient, actor_levels.is_sysop);

        std::string original_sender;
        std::string original_subject;
        std::string forwarded_body;
        std::optional<long long> original_reply_to;
        int original_anonymous_type{};
        std::string original_posted_as;
        {
            Statement original(database.get(),
                "SELECT sender_handle, subject, body, reply_to, anonymous_type, posted_as "
                "FROM private_messages WHERE id = ?1 AND deleted = 0 "
                "AND (sender_handle = ?2 COLLATE NOCASE OR recipient_handle = ?2 COLLATE NOCASE)");
            check_sqlite(database.get(), sqlite3_bind_int64(
                original.get(), 1, static_cast<sqlite3_int64>(original_message_id)),
                "binding original private-message ID");
            bind_text(database.get(), original.get(), 2, actor);
            const int result = sqlite3_step(original.get());
            check_sqlite(database.get(), result, "reading original private message for forwarding");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("original private message is unavailable for forwarding");
            }
            original_sender = column_text(original.get(), 0);
            original_subject = column_text(original.get(), 1);
            forwarded_body = std::string(forwarding_header) + column_text(original.get(), 2);
            if (sqlite3_column_type(original.get(), 3) != SQLITE_NULL) {
                original_reply_to = static_cast<long long>(sqlite3_column_int64(original.get(), 3));
            }
            original_anonymous_type = sqlite3_column_int(original.get(), 4);
            original_posted_as = column_text(original.get(), 5);
        }
        if (!valid_message_body_text(forwarded_body, kMessageLineCountLimit + 3)) {
            throw std::invalid_argument("forwarded message exceeds the 78-character or 503-line limit");
        }

        Statement insert(database.get(),
            "INSERT INTO private_messages(sender_handle, recipient_handle, subject, body, reply_to, "
            "anonymous_type, posted_as) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)");
        bind_text(database.get(), insert.get(), 1, original_sender);
        bind_text(database.get(), insert.get(), 2, canonical_recipient);
        bind_text(database.get(), insert.get(), 3, original_subject);
        bind_text(database.get(), insert.get(), 4, forwarded_body);
        if (original_reply_to.has_value()) {
            check_sqlite(database.get(), sqlite3_bind_int64(
                insert.get(), 5, static_cast<sqlite3_int64>(*original_reply_to)),
                "binding forwarded private-message reply target");
        } else {
            check_sqlite(database.get(), sqlite3_bind_null(insert.get(), 5),
                "binding forwarded private-message reply target");
        }
        check_sqlite(database.get(), sqlite3_bind_int(insert.get(), 6, original_anonymous_type),
            "binding forwarded private-message identity");
        bind_text(database.get(), insert.get(), 7, original_posted_as);
        check_sqlite(database.get(), sqlite3_step(insert.get()), "saving forwarded private message");
        execute_sql(database.get(), "COMMIT", "saving forwarded private message");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

void MessageStore::forward_public_private(
    std::string_view actor,
    std::string_view recipient,
    std::string_view area,
    long long original_message_id,
    std::string_view forwarding_header) const {
    if (!valid_handle(actor) || !valid_handle(recipient) || !valid_area_name(area) ||
        original_message_id < 1 || forwarding_header.empty() || forwarding_header.size() > 512 ||
        has_unsafe_text(forwarding_header, true)) {
        throw std::invalid_argument("invalid public-message forward request");
    }
    const std::string actor_name(actor);
    const std::string recipient_name(recipient);
    if (sqlite3_stricmp(actor_name.c_str(), recipient_name.c_str()) == 0) {
        throw std::invalid_argument("messages cannot be forwarded to yourself");
    }

    initialize();
    Database database(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting public-message forward");
    try {
        if (!area_access_allowed(database.get(), actor, area, false)) {
            throw std::invalid_argument("message area is not available to this account");
        }
        const bool moderator = area_moderator_allowed(database.get(), actor, area);
        std::string canonical_recipient;
        {
            Statement target(database.get(), "SELECT handle FROM accounts WHERE handle = ?1 COLLATE NOCASE");
            bind_text(database.get(), target.get(), 1, recipient);
            const int result = sqlite3_step(target.get());
            check_sqlite(database.get(), result, "looking up private-message forward recipient");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("forward recipient account does not exist");
            }
            canonical_recipient = column_text(target.get(), 0);
        }
        const AccessLevels actor_levels = account_access_levels(database.get(), actor);
        ensure_private_recipient_accepts_mail(database.get(), canonical_recipient, actor_levels.is_sysop);

        std::string original_sender;
        std::string original_subject;
        std::string forwarded_body;
        std::string original_posted_as;
        int original_anonymous_type{};
        {
            Statement original(database.get(),
                "SELECT messages.author_handle, messages.subject, messages.body, "
                "messages.anonymous_type, messages.posted_as, messages.deleted, messages.unvalidated "
                "FROM messages JOIN message_areas ON message_areas.id = messages.area_id "
                "WHERE message_areas.name = ?1 COLLATE NOCASE AND messages.id = ?2");
            bind_text(database.get(), original.get(), 1, area);
            check_sqlite(database.get(), sqlite3_bind_int64(
                original.get(), 2, static_cast<sqlite3_int64>(original_message_id)),
                "binding original public-message ID");
            const int result = sqlite3_step(original.get());
            check_sqlite(database.get(), result, "reading original public message for forwarding");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("original public message is unavailable for forwarding");
            }
            if (!moderator && (sqlite3_column_int(original.get(), 5) != 0 ||
                sqlite3_column_int(original.get(), 6) != 0)) {
                throw std::invalid_argument("original public message is unavailable for forwarding");
            }
            original_sender = column_text(original.get(), 0);
            original_subject = column_text(original.get(), 1);
            forwarded_body = std::string(forwarding_header) + column_text(original.get(), 2);
            original_anonymous_type = sqlite3_column_int(original.get(), 3);
            original_posted_as = column_text(original.get(), 4);
        }
        if (!valid_message_body_text(forwarded_body, kMessageLineCountLimit + 3)) {
            throw std::invalid_argument("forwarded message exceeds the 78-character or 503-line limit");
        }

        Statement insert(database.get(),
            "INSERT INTO private_messages(sender_handle, recipient_handle, subject, body, reply_to, "
            "anonymous_type, posted_as) VALUES(?1, ?2, ?3, ?4, NULL, ?5, ?6)");
        bind_text(database.get(), insert.get(), 1, original_sender);
        bind_text(database.get(), insert.get(), 2, canonical_recipient);
        bind_text(database.get(), insert.get(), 3, original_subject);
        bind_text(database.get(), insert.get(), 4, forwarded_body);
        check_sqlite(database.get(), sqlite3_bind_int(insert.get(), 5, original_anonymous_type),
            "binding forwarded public-message identity");
        bind_text(database.get(), insert.get(), 6, original_posted_as);
        check_sqlite(database.get(), sqlite3_step(insert.get()), "saving forwarded public message");
        execute_sql(database.get(), "COMMIT", "saving forwarded public message");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

} // namespace renegade
