#include "community_store.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <utility>

namespace renegade {
namespace {

class Database final {
public:
    explicit Database(const std::string& path) {
        if (sqlite3_open_v2(path.c_str(), &handle_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
            const std::string error = handle_ != nullptr ? sqlite3_errmsg(handle_) : "allocation failed";
            if (handle_ != nullptr) {
                sqlite3_close(handle_);
                handle_ = nullptr;
            }
            throw std::runtime_error("opening community database: " + error);
        }
        sqlite3_busy_timeout(handle_, 5000);
    }
    ~Database() { if (handle_ != nullptr) sqlite3_close(handle_); }
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    [[nodiscard]] sqlite3* get() const noexcept { return handle_; }
private:
    sqlite3* handle_{};
};

class Statement final {
public:
    Statement(sqlite3* db, const char* sql) : db_(db) {
        if (sqlite3_prepare_v2(db, sql, -1, &statement_, nullptr) != SQLITE_OK) {
            throw std::runtime_error("preparing community query: " + std::string(sqlite3_errmsg(db)));
        }
    }
    ~Statement() { sqlite3_finalize(statement_); }
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    [[nodiscard]] sqlite3_stmt* get() const noexcept { return statement_; }
    void bind_text(int index, std::string_view value) {
        const int result = sqlite3_bind_text(statement_, index, value.data(),
            static_cast<int>(value.size()), SQLITE_TRANSIENT);
        if (result != SQLITE_OK) {
            throw std::runtime_error("binding community text: " + std::string(sqlite3_errmsg(db_)));
        }
    }
    void bind_int64(int index, sqlite3_int64 value) {
        const int result = sqlite3_bind_int64(statement_, index, value);
        if (result != SQLITE_OK) {
            throw std::runtime_error("binding community number: " + std::string(sqlite3_errmsg(db_)));
        }
    }
    void check(int result, std::string_view operation) const {
        if (result != SQLITE_OK && result != SQLITE_DONE && result != SQLITE_ROW) {
            throw std::runtime_error(std::string(operation) + ": " + sqlite3_errmsg(db_));
        }
    }
private:
    sqlite3* db_{};
    sqlite3_stmt* statement_{};
};

void validate_one_liner(std::string_view author, std::string_view text) {
    if (author.empty() || author.size() > 32 || text.empty() || text.size() > 200) {
        throw std::invalid_argument("one-liners require a handle and 1-200 printable characters");
    }
    for (const unsigned char value : author) {
        if (!std::isalnum(value) && value != '.' && value != '_' && value != '-') {
            throw std::invalid_argument("invalid one-liner author handle");
        }
    }
    for (const unsigned char value : text) {
        if (value < 0x20 || value == 0x7f || value == 0x1b) {
            throw std::invalid_argument("one-liners must be single-line printable text");
        }
    }
}

std::string column_text(sqlite3_stmt* statement, int index) {
    const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(statement, index));
    return value == nullptr ? std::string{} : std::string(value);
}

void execute_sql(sqlite3* database, const char* sql, std::string_view operation) {
    char* error = nullptr;
    if (sqlite3_exec(database, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string detail = error != nullptr ? error : sqlite3_errmsg(database);
        sqlite3_free(error);
        throw std::runtime_error(std::string(operation) + ": " + detail);
    }
}

void validate_bbs_listing(std::string_view owner, const BbsListing& listing) {
    if (owner.empty() || owner.size() > 32 || listing.bbs_name.empty()) {
        throw std::invalid_argument("a BBS listing needs an owner and a BBS name");
    }
    for (const unsigned char value : owner) {
        if (!std::isalnum(value) && value != '.' && value != '_' && value != '-') {
            throw std::invalid_argument("invalid BBS listing owner handle");
        }
    }
    struct FieldLimit {
        const char* name;
        std::string BbsListing::*value;
        std::size_t maximum;
    };
    static constexpr FieldLimit fields[]{
        {"BBS name", &BbsListing::bbs_name, 30},
        {"SysOp name", &BbsListing::sysop_name, 30},
        {"Telnet address", &BbsListing::telnet_url, 60},
        {"Web site", &BbsListing::website_url, 60},
        {"Phone number", &BbsListing::phone_number, 20},
        {"Software", &BbsListing::software, 8},
        {"Speed", &BbsListing::speed, 8},
        {"Description", &BbsListing::description, 60},
        {"Description 2", &BbsListing::description2, 60},
        {"XA", &BbsListing::xa, 8},
        {"XB", &BbsListing::xb, 30},
        {"XC", &BbsListing::xc, 30},
        {"XD", &BbsListing::xd, 40},
        {"XE", &BbsListing::xe, 60},
        {"XF", &BbsListing::xf, 60},
    };
    for (const FieldLimit& field : fields) {
        const std::string& value = listing.*(field.value);
        if (value.size() > field.maximum) {
            throw std::invalid_argument(std::string(field.name) + " exceeds " +
                std::to_string(field.maximum) + " bytes");
        }
        for (const unsigned char byte : value) {
            if (byte < 0x20 || byte == 0x7f || byte == 0x1b) {
                throw std::invalid_argument(std::string(field.name) + " must be printable single-line text");
            }
        }
    }
}

BbsListing read_bbs_listing(sqlite3_stmt* statement) {
    BbsListing result;
    result.id = sqlite3_column_int64(statement, 0);
    result.owner = column_text(statement, 1);
    result.bbs_name = column_text(statement, 2);
    result.sysop_name = column_text(statement, 3);
    result.telnet_url = column_text(statement, 4);
    result.website_url = column_text(statement, 5);
    result.phone_number = column_text(statement, 6);
    result.software = column_text(statement, 7);
    result.speed = column_text(statement, 8);
    result.description = column_text(statement, 9);
    result.description2 = column_text(statement, 10);
    result.xa = column_text(statement, 11);
    result.xb = column_text(statement, 12);
    result.xc = column_text(statement, 13);
    result.xd = column_text(statement, 14);
    result.xe = column_text(statement, 15);
    result.xf = column_text(statement, 16);
    result.date_added = column_text(statement, 17);
    result.date_edited = column_text(statement, 18);
    return result;
}

void bind_bbs_listing(Statement& statement, int first_index, const BbsListing& listing) {
    const std::string* const fields[]{
        &listing.bbs_name, &listing.sysop_name, &listing.telnet_url, &listing.website_url,
        &listing.phone_number, &listing.software, &listing.speed, &listing.description,
        &listing.description2, &listing.xa, &listing.xb, &listing.xc, &listing.xd,
        &listing.xe, &listing.xf,
    };
    for (std::size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); ++index) {
        statement.bind_text(first_index + static_cast<int>(index), *fields[index]);
    }
}

Poll load_poll(sqlite3* database, std::int64_t id, std::string_view caller) {
    Statement topic(database,
        "SELECT id, question, subtitle, created_by, created_at, allow_new_choices, allow_vote_changes "
        "FROM polls WHERE id = ?1");
    topic.bind_int64(1, id);
    const int topic_step = sqlite3_step(topic.get());
    if (topic_step == SQLITE_DONE) {
        throw std::invalid_argument("poll does not exist");
    }
    topic.check(topic_step, "reading poll");
    Poll result;
    result.id = sqlite3_column_int64(topic.get(), 0);
    result.question = column_text(topic.get(), 1);
    result.subtitle = column_text(topic.get(), 2);
    result.created_by = column_text(topic.get(), 3);
    result.created_at = column_text(topic.get(), 4);
    result.allow_new_choices = sqlite3_column_int(topic.get(), 5) != 0;
    result.allow_vote_changes = sqlite3_column_int(topic.get(), 6) != 0;

    Statement caller_vote(database,
        "SELECT option_id FROM poll_votes WHERE poll_id = ?1 AND caller = ?2 COLLATE NOCASE");
    caller_vote.bind_int64(1, id);
    caller_vote.bind_text(2, caller);
    const int vote_step = sqlite3_step(caller_vote.get());
    if (vote_step == SQLITE_ROW) {
        result.caller_vote = sqlite3_column_int64(caller_vote.get(), 0);
    } else {
        caller_vote.check(vote_step, "reading caller poll vote");
    }

    Statement options(database,
        "SELECT o.id, o.text, COUNT(v.id) FROM poll_options AS o "
        "LEFT JOIN poll_votes AS v ON v.option_id = o.id "
        "WHERE o.poll_id = ?1 GROUP BY o.id ORDER BY o.position");
    options.bind_int64(1, id);
    for (;;) {
        const int step = sqlite3_step(options.get());
        if (step == SQLITE_DONE) {
            break;
        }
        options.check(step, "reading poll choices");
        const std::uint64_t count = static_cast<std::uint64_t>(sqlite3_column_int64(options.get(), 2));
        result.options.push_back({sqlite3_column_int64(options.get(), 0),
            column_text(options.get(), 1), count});
        result.total_votes += count;
    }
    return result;
}

} // namespace

CommunityStore::CommunityStore(std::string database_path) : database_path_(std::move(database_path)) {}

void CommunityStore::initialize() const {
    std::call_once(initialize_once_, [this] { initialize_schema(); });
}

void CommunityStore::initialize_schema() const {
    const std::filesystem::path path(database_path_);
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path());
    }
    Database database(database_path_);
    const char* sql = "CREATE TABLE IF NOT EXISTS one_liners ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "author TEXT NOT NULL,"
        "text TEXT NOT NULL CHECK(length(text) BETWEEN 1 AND 200),"
        "anonymous INTEGER NOT NULL DEFAULT 0 CHECK(anonymous IN (0,1)),"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "edited_at TEXT NOT NULL DEFAULT '')";
    char* error = nullptr;
    if (sqlite3_exec(database.get(), sql, nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string detail = error != nullptr ? error : sqlite3_errmsg(database.get());
        sqlite3_free(error);
        throw std::runtime_error("creating one-liner table: " + detail);
    }
    bool has_edited_at = false;
    {
        Statement columns(database.get(), "PRAGMA table_info(one_liners)");
        for (;;) {
            const int step = sqlite3_step(columns.get());
            if (step == SQLITE_DONE) {
                break;
            }
            columns.check(step, "checking one-liner schema");
            if (column_text(columns.get(), 1) == "edited_at") {
                has_edited_at = true;
                break;
            }
        }
    }
    if (!has_edited_at) {
        char* alter_error = nullptr;
        if (sqlite3_exec(database.get(),
                "ALTER TABLE one_liners ADD COLUMN edited_at TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, &alter_error) != SQLITE_OK) {
            const std::string detail = alter_error != nullptr ? alter_error : sqlite3_errmsg(database.get());
            sqlite3_free(alter_error);
            throw std::runtime_error("migrating one-liner schema: " + detail);
        }
    }
    const char* community_sql =
        "CREATE TABLE IF NOT EXISTS polls ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "created_by TEXT NOT NULL,"
        "question TEXT NOT NULL CHECK(length(question) BETWEEN 1 AND 60),"
        "subtitle TEXT NOT NULL DEFAULT '',"
        "allow_new_choices INTEGER NOT NULL DEFAULT 0 CHECK(allow_new_choices IN (0,1)),"
        "allow_vote_changes INTEGER NOT NULL DEFAULT 0 CHECK(allow_vote_changes IN (0,1)),"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
        "CREATE TABLE IF NOT EXISTS poll_options ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "poll_id INTEGER NOT NULL REFERENCES polls(id) ON DELETE CASCADE,"
        "position INTEGER NOT NULL CHECK(position BETWEEN 1 AND 25),"
        "text TEXT NOT NULL CHECK(length(text) BETWEEN 1 AND 65),"
        "UNIQUE(poll_id, position));"
        "CREATE TABLE IF NOT EXISTS poll_votes ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "poll_id INTEGER NOT NULL REFERENCES polls(id) ON DELETE CASCADE,"
        "option_id INTEGER NOT NULL REFERENCES poll_options(id) ON DELETE CASCADE,"
        "caller TEXT NOT NULL COLLATE NOCASE,"
        "voted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(poll_id, caller));"
        "CREATE TABLE IF NOT EXISTS caller_sessions ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "handle TEXT NOT NULL,"
        "node INTEGER NOT NULL CHECK(node BETWEEN 1 AND 32),"
        "connected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "disconnected_at TEXT NOT NULL DEFAULT '',"
        "expires_at TEXT NOT NULL DEFAULT '',"
        "invisible INTEGER NOT NULL DEFAULT 0 CHECK(invisible IN (0, 1)),"
        "sysop_available INTEGER NOT NULL DEFAULT 0 CHECK(sysop_available IN (0, 1)));"
        "CREATE TABLE IF NOT EXISTS account_activity ("
        "handle TEXT PRIMARY KEY COLLATE NOCASE,"
        "total_calls INTEGER NOT NULL DEFAULT 0 CHECK(total_calls >= 0),"
        "calls_today INTEGER NOT NULL DEFAULT 0 CHECK(calls_today >= 0),"
        "total_online_seconds INTEGER NOT NULL DEFAULT 0 CHECK(total_online_seconds >= 0),"
        "online_seconds_today INTEGER NOT NULL DEFAULT 0 CHECK(online_seconds_today >= 0),"
        "activity_day TEXT NOT NULL DEFAULT '',"
        "previous_on TEXT NOT NULL DEFAULT '',"
        "last_on TEXT NOT NULL DEFAULT '');"
        "CREATE TABLE IF NOT EXISTS auto_message ("
        "id INTEGER PRIMARY KEY CHECK(id = 1),"
        "author TEXT NOT NULL,"
        "text TEXT NOT NULL CHECK(length(text) BETWEEN 1 AND 4000),"
        "anonymous INTEGER NOT NULL DEFAULT 0 CHECK(anonymous IN (0,1)),"
        "anonymous_type INTEGER NOT NULL DEFAULT 0 CHECK(anonymous_type BETWEEN 0 AND 2),"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
        "CREATE TABLE IF NOT EXISTS quotes ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "author TEXT NOT NULL,"
        "text TEXT NOT NULL CHECK(length(text) BETWEEN 1 AND 4000),"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
        "CREATE TABLE IF NOT EXISTS quote_submissions ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "author TEXT NOT NULL,"
        "text TEXT NOT NULL CHECK(length(text) BETWEEN 1 AND 4000),"
        "submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
        "CREATE TABLE IF NOT EXISTS bbs_listings ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "owner TEXT NOT NULL COLLATE NOCASE,"
        "bbs_name TEXT NOT NULL CHECK(length(bbs_name) BETWEEN 1 AND 30),"
        "sysop_name TEXT NOT NULL DEFAULT '',"
        "telnet_url TEXT NOT NULL DEFAULT '',"
        "website_url TEXT NOT NULL DEFAULT '',"
        "phone_number TEXT NOT NULL DEFAULT '',"
        "software TEXT NOT NULL DEFAULT '',"
        "speed TEXT NOT NULL DEFAULT '',"
        "description TEXT NOT NULL DEFAULT '',"
        "description2 TEXT NOT NULL DEFAULT '',"
        "xa TEXT NOT NULL DEFAULT '',"
        "xb TEXT NOT NULL DEFAULT '',"
        "xc TEXT NOT NULL DEFAULT '',"
        "xd TEXT NOT NULL DEFAULT '',"
        "xe TEXT NOT NULL DEFAULT '',"
        "xf TEXT NOT NULL DEFAULT '',"
        "date_added TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "date_edited TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
        "CREATE TABLE IF NOT EXISTS short_messages ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "recipient TEXT NOT NULL COLLATE NOCASE,"
        "text TEXT NOT NULL CHECK(length(text) BETWEEN 1 AND 80),"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "delivered_at TEXT NOT NULL DEFAULT '');"
        "CREATE INDEX IF NOT EXISTS short_messages_pending "
        "ON short_messages(recipient COLLATE NOCASE, delivered_at, id);"
        "CREATE TABLE IF NOT EXISTS scheduled_events ("
        "slot INTEGER PRIMARY KEY CHECK(slot BETWEEN 1 AND 10),"
        "description TEXT NOT NULL CHECK(length(description) BETWEEN 1 AND 30),"
        "type TEXT NOT NULL CHECK(type IN ('logon','chat','permission','external'))," 
        "active INTEGER NOT NULL DEFAULT 0 CHECK(active IN (0,1)),"
        "monthly INTEGER NOT NULL DEFAULT 0 CHECK(monthly IN (0,1)),"
        "day_mask INTEGER NOT NULL DEFAULT 127 CHECK(day_mask BETWEEN 0 AND 127),"
        "day_of_month INTEGER NOT NULL DEFAULT 0 CHECK(day_of_month BETWEEN 0 AND 31),"
        "start_minute INTEGER NOT NULL DEFAULT 0 CHECK(start_minute BETWEEN 0 AND 1439),"
        "finish_minute INTEGER NOT NULL DEFAULT 0 CHECK(finish_minute BETWEEN 0 AND 1439),"
        "pre_warning_minutes INTEGER NOT NULL DEFAULT 0 CHECK(pre_warning_minutes BETWEEN 0 AND 255),"
        "node INTEGER NOT NULL DEFAULT 0 CHECK(node BETWEEN 0 AND 32),"
        "access_acs TEXT NOT NULL DEFAULT '' CHECK(length(access_acs) <= 20),"
        "max_time_minutes INTEGER NOT NULL DEFAULT 60 CHECK(max_time_minutes BETWEEN 0 AND 65535),"
        "set_ar_flag TEXT NOT NULL DEFAULT '' CHECK(length(set_ar_flag) <= 1),"
        "clear_ar_flag TEXT NOT NULL DEFAULT '' CHECK(length(clear_ar_flag) <= 1),"
        "low_baud INTEGER NOT NULL DEFAULT 0 CHECK(low_baud BETWEEN 0 AND 2147483647),"
        "high_baud INTEGER NOT NULL DEFAULT 115200 CHECK(high_baud BETWEEN 0 AND 2147483647),"
        "soft INTEGER NOT NULL DEFAULT 0 CHECK(soft IN (0,1)),"
        "run_if_missed INTEGER NOT NULL DEFAULT 0 CHECK(run_if_missed IN (0,1)),"
        "last_run_date TEXT NOT NULL DEFAULT '');"
        "CREATE TABLE IF NOT EXISTS sysop_audit ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 32),"
        "action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 64),"
        "subject TEXT NOT NULL DEFAULT '' CHECK(length(subject) <= 256),"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
        "CREATE INDEX IF NOT EXISTS sysop_audit_recent ON sysop_audit(id DESC);"
        "CREATE TABLE IF NOT EXISTS file_user_activity ("
        "handle TEXT PRIMARY KEY COLLATE NOCASE,"
        "uploads INTEGER NOT NULL DEFAULT 0 CHECK(uploads >= 0),"
        "uploaded_bytes INTEGER NOT NULL DEFAULT 0 CHECK(uploaded_bytes >= 0),"
        "downloads INTEGER NOT NULL DEFAULT 0 CHECK(downloads >= 0),"
        "downloaded_bytes INTEGER NOT NULL DEFAULT 0 CHECK(downloaded_bytes >= 0));";
    error = nullptr;
    if (sqlite3_exec(database.get(), community_sql, nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string detail = error != nullptr ? error : sqlite3_errmsg(database.get());
        sqlite3_free(error);
        throw std::runtime_error("creating community tables: " + detail);
    }
    bool has_session_expiry = false;
    bool has_session_invisible = false;
    bool has_session_availability = false;
    {
        Statement session_columns(database.get(), "PRAGMA table_info(caller_sessions)");
        for (;;) {
            const int step = sqlite3_step(session_columns.get());
            if (step == SQLITE_DONE) {
                break;
            }
            session_columns.check(step, "checking caller-session schema");
            const std::string column = column_text(session_columns.get(), 1);
            has_session_expiry = has_session_expiry || column == "expires_at";
            has_session_invisible = has_session_invisible || column == "invisible";
            has_session_availability = has_session_availability || column == "sysop_available";
        }
    }
    if (!has_session_expiry) {
        char* alter_error = nullptr;
        if (sqlite3_exec(database.get(),
                "ALTER TABLE caller_sessions ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, &alter_error) != SQLITE_OK) {
            const std::string detail = alter_error != nullptr ? alter_error : sqlite3_errmsg(database.get());
            sqlite3_free(alter_error);
            throw std::runtime_error("migrating caller-session time limits: " + detail);
        }
    }
    if (!has_session_invisible) {
        char* alter_error = nullptr;
        if (sqlite3_exec(database.get(),
                "ALTER TABLE caller_sessions ADD COLUMN invisible INTEGER NOT NULL DEFAULT 0 CHECK(invisible IN (0, 1))",
                nullptr, nullptr, &alter_error) != SQLITE_OK) {
            const std::string detail = alter_error != nullptr ? alter_error : sqlite3_errmsg(database.get());
            sqlite3_free(alter_error);
            throw std::runtime_error("migrating caller-session invisibility: " + detail);
        }
    }
    if (!has_session_availability) {
        char* alter_error = nullptr;
        if (sqlite3_exec(database.get(),
                "ALTER TABLE caller_sessions ADD COLUMN sysop_available INTEGER NOT NULL DEFAULT 0 CHECK(sysop_available IN (0, 1))",
                nullptr, nullptr, &alter_error) != SQLITE_OK) {
            const std::string detail = alter_error != nullptr ? alter_error : sqlite3_errmsg(database.get());
            sqlite3_free(alter_error);
            throw std::runtime_error("migrating SysOp availability: " + detail);
        }
    }
    bool has_auto_message_type = false;
    {
        Statement auto_columns(database.get(), "PRAGMA table_info(auto_message)");
        for (;;) {
            const int step = sqlite3_step(auto_columns.get());
            if (step == SQLITE_DONE) {
                break;
            }
            auto_columns.check(step, "checking auto-message schema");
            if (column_text(auto_columns.get(), 1) == "anonymous_type") {
                has_auto_message_type = true;
                break;
            }
        }
    }
    if (!has_auto_message_type) {
        char* alter_error = nullptr;
        if (sqlite3_exec(database.get(),
                "ALTER TABLE auto_message ADD COLUMN anonymous_type INTEGER NOT NULL DEFAULT 0",
                nullptr, nullptr, &alter_error) != SQLITE_OK) {
            const std::string detail = alter_error != nullptr ? alter_error : sqlite3_errmsg(database.get());
            sqlite3_free(alter_error);
            throw std::runtime_error("migrating auto-message anonymous identity: " + detail);
        }
    }
    if (sqlite3_exec(database.get(),
            "UPDATE auto_message SET anonymous_type = CASE WHEN anonymous = 1 THEN 1 ELSE 0 END "
            "WHERE anonymous_type = 0",
            nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string detail = error != nullptr ? error : sqlite3_errmsg(database.get());
        sqlite3_free(error);
        throw std::runtime_error("migrating existing auto-message identity: " + detail);
    }
    bool has_previous_on = false;
    {
        Statement activity_columns(database.get(), "PRAGMA table_info(account_activity)");
        for (;;) {
            const int step = sqlite3_step(activity_columns.get());
            if (step == SQLITE_DONE) {
                break;
            }
            activity_columns.check(step, "checking account activity schema");
            if (column_text(activity_columns.get(), 1) == "previous_on") {
                has_previous_on = true;
                break;
            }
        }
    }
    if (!has_previous_on) {
        char* alter_error = nullptr;
        if (sqlite3_exec(database.get(),
                "ALTER TABLE account_activity ADD COLUMN previous_on TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, &alter_error) != SQLITE_OK) {
            const std::string detail = alter_error != nullptr ? alter_error : sqlite3_errmsg(database.get());
            sqlite3_free(alter_error);
            throw std::runtime_error("migrating account activity schema: " + detail);
        }
    }
    bool has_choice_policy = false;
    {
        Statement poll_columns(database.get(), "PRAGMA table_info(polls)");
        for (;;) {
            const int step = sqlite3_step(poll_columns.get());
            if (step == SQLITE_DONE) {
                break;
            }
            poll_columns.check(step, "checking poll schema");
            if (column_text(poll_columns.get(), 1) == "allow_new_choices") {
                has_choice_policy = true;
                break;
            }
        }
    }
    if (!has_choice_policy) {
        char* alter_error = nullptr;
        if (sqlite3_exec(database.get(),
                "ALTER TABLE polls ADD COLUMN allow_new_choices INTEGER NOT NULL DEFAULT 0 CHECK(allow_new_choices IN (0,1))",
                nullptr, nullptr, &alter_error) != SQLITE_OK) {
            const std::string detail = alter_error != nullptr ? alter_error : sqlite3_errmsg(database.get());
            sqlite3_free(alter_error);
            throw std::runtime_error("migrating poll schema: " + detail);
        }
    }
    bool has_vote_policy = false;
    {
        Statement vote_policy_columns(database.get(), "PRAGMA table_info(polls)");
        for (;;) {
            const int step = sqlite3_step(vote_policy_columns.get());
            if (step == SQLITE_DONE) {
                break;
            }
            vote_policy_columns.check(step, "checking poll vote policy");
            if (column_text(vote_policy_columns.get(), 1) == "allow_vote_changes") {
                has_vote_policy = true;
                break;
            }
        }
    }
    if (!has_vote_policy) {
        char* alter_error = nullptr;
        if (sqlite3_exec(database.get(),
                "ALTER TABLE polls ADD COLUMN allow_vote_changes INTEGER NOT NULL DEFAULT 0 CHECK(allow_vote_changes IN (0,1))",
                nullptr, nullptr, &alter_error) != SQLITE_OK) {
            const std::string detail = alter_error != nullptr ? alter_error : sqlite3_errmsg(database.get());
            sqlite3_free(alter_error);
            throw std::runtime_error("migrating poll vote policy: " + detail);
        }
    }
}

OneLinerPage CommunityStore::one_liners(std::size_t page, std::size_t page_size) const {
    if (page_size == 0 || page_size > 100) {
        throw std::invalid_argument("one-liner page size must be between 1 and 100");
    }
    initialize();
    Database database(database_path_);
    Statement count(database.get(), "SELECT COUNT(*) FROM one_liners");
    count.check(sqlite3_step(count.get()), "counting one-liners");
    OneLinerPage result;
    result.total = static_cast<std::uint64_t>(sqlite3_column_int64(count.get(), 0));
    result.page_count = std::max<std::size_t>(1,
        static_cast<std::size_t>((result.total + page_size - 1) / page_size));
    result.page = std::min(page, result.page_count - 1);
    Statement query(database.get(),
        "SELECT id, author, text, anonymous, created_at, edited_at FROM one_liners "
        "ORDER BY id DESC LIMIT ?1 OFFSET ?2");
    query.bind_int64(1, static_cast<sqlite3_int64>(page_size));
    query.bind_int64(2, static_cast<sqlite3_int64>(result.page * page_size));
    for (;;) {
        const int step = sqlite3_step(query.get());
        if (step == SQLITE_DONE) {
            break;
        }
        query.check(step, "reading one-liners");
        result.entries.push_back({sqlite3_column_int64(query.get(), 0), column_text(query.get(), 1),
            column_text(query.get(), 2), sqlite3_column_int(query.get(), 3) != 0,
            column_text(query.get(), 4), column_text(query.get(), 5)});
    }
    return result;
}

void CommunityStore::add_one_liner(std::string_view author, std::string_view text, bool anonymous) const {
    validate_one_liner(author, text);
    initialize();
    Database database(database_path_);
    Statement insert(database.get(),
        "INSERT INTO one_liners(author, text, anonymous) VALUES(?1, ?2, ?3)");
    insert.bind_text(1, author);
    insert.bind_text(2, text);
    insert.bind_int64(3, anonymous ? 1 : 0);
    insert.check(sqlite3_step(insert.get()), "saving one-liner");
}

void CommunityStore::update_one_liner(std::int64_t id, std::string_view text) const {
    if (text.empty() || text.size() > 200) {
        throw std::invalid_argument("one-liners must contain 1-200 printable characters");
    }
    for (const unsigned char value : text) {
        if (value < 0x20 || value == 0x7f || value == 0x1b) {
            throw std::invalid_argument("one-liners must be single-line printable text");
        }
    }
    initialize();
    Database database(database_path_);
    Statement update(database.get(),
        "UPDATE one_liners SET text = ?1, edited_at = CURRENT_TIMESTAMP WHERE id = ?2");
    update.bind_text(1, text);
    update.bind_int64(2, id);
    update.check(sqlite3_step(update.get()), "updating one-liner");
    if (sqlite3_changes(database.get()) != 1) {
        throw std::runtime_error("the selected one-liner no longer exists");
    }
}

void CommunityStore::delete_one_liner(std::int64_t id) const {
    initialize();
    Database database(database_path_);
    Statement remove(database.get(), "DELETE FROM one_liners WHERE id = ?1");
    remove.bind_int64(1, id);
    remove.check(sqlite3_step(remove.get()), "deleting one-liner");
    if (sqlite3_changes(database.get()) != 1) {
        throw std::runtime_error("the selected one-liner no longer exists");
    }
}

std::optional<OneLiner> CommunityStore::random_one_liner() const {
    initialize();
    Database database(database_path_);
    Statement query(database.get(),
        "SELECT id, author, text, anonymous, created_at, edited_at FROM one_liners "
        "ORDER BY RANDOM() LIMIT 1");
    const int step = sqlite3_step(query.get());
    if (step == SQLITE_DONE) {
        return std::nullopt;
    }
    query.check(step, "choosing a random one-liner");
    return OneLiner{sqlite3_column_int64(query.get(), 0), column_text(query.get(), 1),
        column_text(query.get(), 2), sqlite3_column_int(query.get(), 3) != 0,
        column_text(query.get(), 4), column_text(query.get(), 5)};
}

Poll CommunityStore::poll(std::int64_t id, std::string_view caller) const {
    if (id < 1 || caller.empty() || caller.size() > 32) {
        throw std::invalid_argument("invalid poll lookup");
    }
    initialize();
    Database database(database_path_);
    return load_poll(database.get(), id, caller);
}

std::vector<Poll> CommunityStore::polls(std::string_view caller) const {
    if (caller.empty() || caller.size() > 32) {
        throw std::invalid_argument("invalid poll caller handle");
    }
    initialize();
    Database database(database_path_);
    std::vector<std::int64_t> ids;
    {
        Statement query(database.get(), "SELECT id FROM polls ORDER BY id DESC LIMIT 25");
        for (;;) {
            const int step = sqlite3_step(query.get());
            if (step == SQLITE_DONE) {
                break;
            }
            query.check(step, "listing polls");
            ids.push_back(sqlite3_column_int64(query.get(), 0));
        }
    }
    std::vector<Poll> result;
    result.reserve(ids.size());
    for (const std::int64_t id : ids) {
        result.push_back(load_poll(database.get(), id, caller));
    }
    return result;
}

void CommunityStore::create_poll(
    std::string_view author,
    std::string_view question,
    std::string_view subtitle,
    bool allow_new_choices,
    bool allow_vote_changes,
    const std::vector<std::string>& options) const {
    if (author.empty() || author.size() > 32 || options.size() < 2 || options.size() > 25 ||
        question.empty() || question.size() > 60 || subtitle.size() > 60) {
        throw std::invalid_argument("polls need a handle, a 1-60 character question, and 2-25 choices");
    }
    for (const unsigned char value : author) {
        if (!std::isalnum(value) && value != '.' && value != '_' && value != '-') {
            throw std::invalid_argument("invalid poll author handle");
        }
    }
    const auto validate_text = [](std::string_view value, std::size_t limit, std::string_view field) {
        if (value.empty() || value.size() > limit) {
            throw std::invalid_argument(std::string(field) + " must fit its legacy Renegade field");
        }
        for (const unsigned char byte : value) {
            if (byte < 0x20 || byte == 0x7f || byte == 0x1b) {
                throw std::invalid_argument(std::string(field) + " must be printable single-line text");
            }
        }
    };
    validate_text(question, 60, "poll question");
    if (!subtitle.empty()) {
        validate_text(subtitle, 60, "poll subtitle");
    }
    for (const std::string& option : options) {
        validate_text(option, 65, "poll choice");
    }

    initialize();
    Database database(database_path_);
    char* error = nullptr;
    if (sqlite3_exec(database.get(), "BEGIN IMMEDIATE", nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string detail = error != nullptr ? error : sqlite3_errmsg(database.get());
        sqlite3_free(error);
        throw std::runtime_error("starting poll creation: " + detail);
    }
    try {
        int poll_count = 0;
        {
            Statement count(database.get(), "SELECT COUNT(*) FROM polls");
            count.check(sqlite3_step(count.get()), "counting polls");
            poll_count = sqlite3_column_int(count.get(), 0);
        }
        if (poll_count >= 25) {
            throw std::runtime_error("the Renegade voting system supports up to 25 topics");
        }
        Statement insert_poll(database.get(),
            "INSERT INTO polls(created_by, question, subtitle, allow_new_choices, allow_vote_changes) "
            "VALUES(?1, ?2, ?3, ?4, ?5)");
        insert_poll.bind_text(1, author);
        insert_poll.bind_text(2, question);
        insert_poll.bind_text(3, subtitle);
        insert_poll.bind_int64(4, allow_new_choices ? 1 : 0);
        insert_poll.bind_int64(5, allow_vote_changes ? 1 : 0);
        insert_poll.check(sqlite3_step(insert_poll.get()), "saving poll");
        const std::int64_t poll_id = sqlite3_last_insert_rowid(database.get());
        Statement insert_option(database.get(),
            "INSERT INTO poll_options(poll_id, position, text) VALUES(?1, ?2, ?3)");
        for (std::size_t index = 0; index < options.size(); ++index) {
            sqlite3_reset(insert_option.get());
            sqlite3_clear_bindings(insert_option.get());
            insert_option.bind_int64(1, poll_id);
            insert_option.bind_int64(2, static_cast<sqlite3_int64>(index + 1));
            insert_option.bind_text(3, options[index]);
            insert_option.check(sqlite3_step(insert_option.get()), "saving poll choice");
        }
        if (sqlite3_exec(database.get(), "COMMIT", nullptr, nullptr, &error) != SQLITE_OK) {
            const std::string detail = error != nullptr ? error : sqlite3_errmsg(database.get());
            sqlite3_free(error);
            error = nullptr;
            throw std::runtime_error("committing poll: " + detail);
        }
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void CommunityStore::add_poll_choice(
    std::int64_t poll_id,
    std::string_view caller,
    std::string_view choice) const {
    if (poll_id < 1 || caller.empty() || caller.size() > 32 || choice.empty() || choice.size() > 65) {
        throw std::invalid_argument("poll choices must contain 1-65 printable characters");
    }
    for (const unsigned char byte : choice) {
        if (byte < 0x20 || byte == 0x7f || byte == 0x1b) {
            throw std::invalid_argument("poll choices must be printable single-line text");
        }
    }
    initialize();
    Database database(database_path_);
    char* error = nullptr;
    if (sqlite3_exec(database.get(), "BEGIN IMMEDIATE", nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string detail = error != nullptr ? error : sqlite3_errmsg(database.get());
        sqlite3_free(error);
        throw std::runtime_error("starting poll choice addition: " + detail);
    }
    try {
        bool allowed = false;
        int choice_count = 0;
        {
            Statement policy(database.get(),
                "SELECT allow_new_choices, (SELECT COUNT(*) FROM poll_options WHERE poll_id = ?1) "
                "FROM polls WHERE id = ?1");
            policy.bind_int64(1, poll_id);
            const int step = sqlite3_step(policy.get());
            if (step == SQLITE_DONE) {
                throw std::invalid_argument("poll does not exist");
            }
            policy.check(step, "checking poll choice policy");
            allowed = sqlite3_column_int(policy.get(), 0) != 0;
            choice_count = sqlite3_column_int(policy.get(), 1);
        }
        if (!allowed) {
            throw std::invalid_argument("this poll does not allow caller-added choices");
        }
        if (choice_count >= 25) {
            throw std::invalid_argument("this poll already has the maximum of 25 choices");
        }
        Statement insert(database.get(),
            "INSERT INTO poll_options(poll_id, position, text) VALUES(?1, ?2, ?3)");
        insert.bind_int64(1, poll_id);
        insert.bind_int64(2, choice_count + 1);
        insert.bind_text(3, choice);
        insert.check(sqlite3_step(insert.get()), "adding poll choice");
        if (sqlite3_exec(database.get(), "COMMIT", nullptr, nullptr, &error) != SQLITE_OK) {
            const std::string detail = error != nullptr ? error : sqlite3_errmsg(database.get());
            sqlite3_free(error);
            error = nullptr;
            throw std::runtime_error("committing poll choice: " + detail);
        }
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void CommunityStore::vote(std::int64_t poll_id, std::int64_t option_id, std::string_view caller) const {
    if (poll_id < 1 || option_id < 1 || caller.empty() || caller.size() > 32) {
        throw std::invalid_argument("invalid poll vote");
    }
    initialize();
    Database database(database_path_);
    char* error = nullptr;
    if (sqlite3_exec(database.get(), "BEGIN IMMEDIATE", nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string detail = error != nullptr ? error : sqlite3_errmsg(database.get());
        sqlite3_free(error);
        throw std::runtime_error("starting poll vote: " + detail);
    }
    try {
        {
            Statement option(database.get(),
                "SELECT 1 FROM poll_options WHERE id = ?1 AND poll_id = ?2");
            option.bind_int64(1, option_id);
            option.bind_int64(2, poll_id);
            const int option_step = sqlite3_step(option.get());
            if (option_step == SQLITE_DONE) {
                throw std::invalid_argument("that choice does not belong to this poll");
            }
            option.check(option_step, "checking poll choice");
        }
        bool can_change = false;
        {
            Statement policy(database.get(),
                "SELECT allow_vote_changes FROM polls WHERE id = ?1");
            policy.bind_int64(1, poll_id);
            const int step = sqlite3_step(policy.get());
            if (step == SQLITE_DONE) {
                throw std::invalid_argument("poll does not exist");
            }
            policy.check(step, "checking vote-change policy");
            can_change = sqlite3_column_int(policy.get(), 0) != 0;
        }
        bool already_voted = false;
        {
            Statement previous(database.get(),
                "SELECT 1 FROM poll_votes WHERE poll_id = ?1 AND caller = ?2 COLLATE NOCASE");
            previous.bind_int64(1, poll_id);
            previous.bind_text(2, caller);
            const int step = sqlite3_step(previous.get());
            already_voted = step == SQLITE_ROW;
            if (!already_voted) {
                previous.check(step, "checking prior poll vote");
            }
        }
        if (already_voted && !can_change) {
            throw std::invalid_argument("a vote has already been recorded for this topic");
        }
        if (already_voted) {
            Statement update(database.get(),
                "UPDATE poll_votes SET option_id = ?1, voted_at = CURRENT_TIMESTAMP "
                "WHERE poll_id = ?2 AND caller = ?3 COLLATE NOCASE");
            update.bind_int64(1, option_id);
            update.bind_int64(2, poll_id);
            update.bind_text(3, caller);
            update.check(sqlite3_step(update.get()), "changing poll vote");
        } else {
            Statement insert(database.get(),
                "INSERT INTO poll_votes(poll_id, option_id, caller) VALUES(?1, ?2, ?3)");
            insert.bind_int64(1, poll_id);
            insert.bind_int64(2, option_id);
            insert.bind_text(3, caller);
            insert.check(sqlite3_step(insert.get()), "recording poll vote");
        }
        if (sqlite3_exec(database.get(), "COMMIT", nullptr, nullptr, &error) != SQLITE_OK) {
            const std::string detail = error != nullptr ? error : sqlite3_errmsg(database.get());
            sqlite3_free(error);
            error = nullptr;
            throw std::runtime_error("committing poll vote: " + detail);
        }
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

std::vector<std::string> CommunityStore::poll_voters(
    std::int64_t poll_id,
    std::int64_t option_id) const {
    if (poll_id < 1 || option_id < 1) {
        throw std::invalid_argument("invalid poll voter lookup");
    }
    initialize();
    Database database(database_path_);
    Statement query(database.get(),
        "SELECT caller FROM poll_votes WHERE poll_id = ?1 AND option_id = ?2 "
        "ORDER BY caller COLLATE NOCASE LIMIT 1000");
    query.bind_int64(1, poll_id);
    query.bind_int64(2, option_id);
    std::vector<std::string> result;
    for (;;) {
        const int step = sqlite3_step(query.get());
        if (step == SQLITE_DONE) {
            break;
        }
        query.check(step, "listing poll voters");
        result.push_back(column_text(query.get(), 0));
    }
    return result;
}

std::int64_t CommunityStore::record_caller_login(
    std::string_view handle, int node, std::optional<int> remaining_seconds) const {
    if (handle.empty() || handle.size() > 32 || node < 1 || node > 32 ||
        (remaining_seconds.has_value() && (*remaining_seconds < 0 || *remaining_seconds > 32767 * 60))) {
        throw std::invalid_argument("invalid caller session");
    }
    for (const unsigned char value : handle) {
        if (!std::isalnum(value) && value != '.' && value != '_' && value != '-') {
            throw std::invalid_argument("invalid caller handle");
        }
    }
    initialize();
    Database database(database_path_);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting caller login accounting");
    std::int64_t id{};
    try {
        Statement insert(database.get(),
            "INSERT INTO caller_sessions(handle, node, expires_at, sysop_available) "
            "VALUES(?1, ?2, CASE WHEN ?3 < 0 THEN '' "
            "ELSE datetime('now', '+' || ?3 || ' seconds') END, "
            "CASE WHEN EXISTS(SELECT 1 FROM accounts WHERE handle = ?1 COLLATE NOCASE AND is_sysop = 1) "
            "THEN 1 ELSE 0 END)");
        insert.bind_text(1, handle);
        insert.bind_int64(2, node);
        insert.bind_int64(3, remaining_seconds.value_or(-1));
        insert.check(sqlite3_step(insert.get()), "recording caller login");
        id = sqlite3_last_insert_rowid(database.get());

        Statement activity(database.get(),
            "INSERT INTO account_activity(handle, total_calls, calls_today, activity_day, previous_on, last_on) "
            "VALUES(?1, 1, 1, date('now'), '', CURRENT_TIMESTAMP) "
            "ON CONFLICT(handle) DO UPDATE SET "
            "total_calls = CASE WHEN total_calls < 9223372036854775807 THEN total_calls + 1 ELSE total_calls END, "
            "calls_today = CASE WHEN activity_day = date('now') THEN calls_today + 1 ELSE 1 END, "
            "online_seconds_today = CASE WHEN activity_day = date('now') THEN online_seconds_today ELSE 0 END, "
            "activity_day = date('now'), previous_on = last_on, last_on = CURRENT_TIMESTAMP");
        activity.bind_text(1, handle);
        activity.check(sqlite3_step(activity.get()), "recording account login totals");
        execute_sql(database.get(), "COMMIT", "saving caller login accounting");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    char* error = nullptr;
    if (sqlite3_exec(database.get(),
            "DELETE FROM caller_sessions WHERE id NOT IN "
            "(SELECT id FROM caller_sessions ORDER BY id DESC LIMIT 10000)",
            nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string detail = error != nullptr ? error : sqlite3_errmsg(database.get());
        sqlite3_free(error);
        std::cerr << "Could not prune caller history: " << detail << '\n';
    }
    return id;
}

void CommunityStore::update_caller_session_time(
    std::int64_t session_id, std::optional<int> remaining_seconds) const {
    if (session_id < 1 ||
        (remaining_seconds.has_value() && (*remaining_seconds < 0 || *remaining_seconds > 32767 * 60))) {
        throw std::invalid_argument("invalid caller-session time limit");
    }
    initialize();
    Database database(database_path_);
    Statement update(database.get(),
        "UPDATE caller_sessions SET expires_at = CASE WHEN ?1 < 0 THEN '' "
        "ELSE datetime('now', '+' || ?1 || ' seconds') END WHERE id = ?2 AND disconnected_at = ''");
    update.bind_int64(1, remaining_seconds.value_or(-1));
    update.bind_int64(2, session_id);
    update.check(sqlite3_step(update.get()), "updating caller-session time limit");
}

void CommunityStore::update_caller_session_invisible(std::int64_t session_id, bool invisible) const {
    if (session_id < 1) {
        throw std::invalid_argument("invalid caller session");
    }
    initialize();
    Database database(database_path_);
    Statement update(database.get(),
        "UPDATE caller_sessions SET invisible = ?1 WHERE id = ?2 AND disconnected_at = ''");
    update.bind_int64(1, invisible ? 1 : 0);
    update.bind_int64(2, session_id);
    update.check(sqlite3_step(update.get()), "updating caller invisibility");
    if (sqlite3_changes(database.get()) != 1) {
        throw std::runtime_error("caller session is no longer active");
    }
}

void CommunityStore::update_caller_session_availability(std::int64_t session_id, bool available) const {
    if (session_id < 1) {
        throw std::invalid_argument("invalid caller session");
    }
    initialize();
    Database database(database_path_);
    Statement update(database.get(),
        "UPDATE caller_sessions SET sysop_available = ?1 WHERE id = ?2 AND disconnected_at = ''");
    update.bind_int64(1, available ? 1 : 0);
    update.bind_int64(2, session_id);
    update.check(sqlite3_step(update.get()), "updating SysOp availability");
    if (sqlite3_changes(database.get()) != 1) {
        throw std::runtime_error("caller session is no longer active");
    }
}

void CommunityStore::record_caller_logout(std::int64_t session_id) const {
    if (session_id < 1) {
        return;
    }
    initialize();
    Database database(database_path_);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting caller logout accounting");
    try {
        Statement update(database.get(),
            "UPDATE caller_sessions SET disconnected_at = CURRENT_TIMESTAMP "
            "WHERE id = ?1 AND disconnected_at = ''");
        update.bind_int64(1, session_id);
        update.check(sqlite3_step(update.get()), "recording caller logout");
        if (sqlite3_changes(database.get()) != 0) {
            Statement activity(database.get(),
                "UPDATE account_activity SET "
                "total_online_seconds = CASE "
                "WHEN total_online_seconds <= 9223372036854775807 - MAX(0, CAST((julianday(s.disconnected_at) - "
                "julianday(s.connected_at)) * 86400 AS INTEGER)) THEN total_online_seconds + "
                "MAX(0, CAST((julianday(s.disconnected_at) - julianday(s.connected_at)) * 86400 AS INTEGER)) "
                "ELSE 9223372036854775807 END, "
                "online_seconds_today = CASE WHEN activity_day = date('now') THEN "
                "CASE WHEN online_seconds_today <= 9223372036854775807 - "
                "MAX(0, CAST((julianday(s.disconnected_at) - julianday(s.connected_at)) * 86400 AS INTEGER)) "
                "THEN online_seconds_today + MAX(0, CAST((julianday(s.disconnected_at) - "
                "julianday(s.connected_at)) * 86400 AS INTEGER)) ELSE 9223372036854775807 END "
                "ELSE online_seconds_today END "
                "FROM caller_sessions AS s WHERE s.id = ?1 AND account_activity.handle = s.handle COLLATE NOCASE");
            activity.bind_int64(1, session_id);
            activity.check(sqlite3_step(activity.get()), "recording account online time");
        }
        execute_sql(database.get(), "COMMIT", "saving caller logout accounting");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

CallerSessionPage CommunityStore::today_callers(std::size_t page, std::size_t page_size) const {
    if (page_size == 0 || page_size > 100) {
        throw std::invalid_argument("caller history page size must be between 1 and 100");
    }
    initialize();
    Database database(database_path_);
    Statement count(database.get(),
        "SELECT COUNT(*) FROM caller_sessions WHERE date(connected_at) = date('now')");
    count.check(sqlite3_step(count.get()), "counting today's callers");
    CallerSessionPage result;
    result.total = static_cast<std::uint64_t>(sqlite3_column_int64(count.get(), 0));
    result.page_count = std::max<std::size_t>(1,
        static_cast<std::size_t>((result.total + page_size - 1) / page_size));
    result.page = std::min(page, result.page_count - 1);
    Statement query(database.get(),
        "SELECT id, handle, node, connected_at, disconnected_at FROM caller_sessions "
        "WHERE date(connected_at) = date('now') ORDER BY id DESC LIMIT ?1 OFFSET ?2");
    query.bind_int64(1, static_cast<sqlite3_int64>(page_size));
    query.bind_int64(2, static_cast<sqlite3_int64>(result.page * page_size));
    for (;;) {
        const int step = sqlite3_step(query.get());
        if (step == SQLITE_DONE) {
            break;
        }
        query.check(step, "reading today's caller history");
        result.entries.push_back({sqlite3_column_int64(query.get(), 0), column_text(query.get(), 1),
            sqlite3_column_int(query.get(), 2), column_text(query.get(), 3),
            column_text(query.get(), 4)});
    }
    return result;
}

AccountUsage CommunityStore::account_usage(std::string_view handle) const {
    if (handle.empty() || handle.size() > 32) {
        throw std::invalid_argument("invalid account handle for usage lookup");
    }
    initialize();
    Database database(database_path_);
    Statement query(database.get(),
        "SELECT total_calls, CASE WHEN activity_day = date('now') THEN calls_today ELSE 0 END, "
        "total_online_seconds, CASE WHEN activity_day = date('now') THEN online_seconds_today ELSE 0 END, "
        "last_on, previous_on FROM account_activity WHERE handle = ?1 COLLATE NOCASE");
    query.bind_text(1, handle);
    const int step = sqlite3_step(query.get());
    query.check(step, "reading caller account usage");
    if (step == SQLITE_DONE) {
        return {};
    }
    const auto nonnegative = [&query](int column) {
        return static_cast<std::uint64_t>(std::max<sqlite3_int64>(0,
            sqlite3_column_int64(query.get(), column)));
    };
    return {
        nonnegative(0),
        nonnegative(1),
        nonnegative(2),
        nonnegative(3),
        column_text(query.get(), 4),
        column_text(query.get(), 5),
    };
}

std::optional<AutoMessage> CommunityStore::auto_message() const {
    initialize();
    Database database(database_path_);
    Statement query(database.get(),
        "SELECT author, text, anonymous, created_at, anonymous_type FROM auto_message WHERE id = 1");
    const int step = sqlite3_step(query.get());
    if (step == SQLITE_DONE) {
        return std::nullopt;
    }
    query.check(step, "reading auto-message");
    return AutoMessage{column_text(query.get(), 0), column_text(query.get(), 1),
        sqlite3_column_int(query.get(), 2) != 0, column_text(query.get(), 3),
        sqlite3_column_int(query.get(), 4)};
}

void CommunityStore::set_auto_message(
    std::string_view author,
    std::string_view text,
    bool anonymous,
    bool sysop_anonymous) const {
    if (author.empty() || author.size() > 32 || text.empty() || text.size() > 4000) {
        throw std::invalid_argument("auto-messages need a handle and 1-4000 characters");
    }
    for (const unsigned char value : author) {
        if (!std::isalnum(value) && value != '.' && value != '_' && value != '-') {
            throw std::invalid_argument("invalid auto-message author handle");
        }
    }
    for (const unsigned char value : text) {
        if (value == '\r' || value == '\t' || value == 0x7f || value == 0x1b ||
            (value < 0x20 && value != '\n')) {
            throw std::invalid_argument("auto-messages must contain printable lines");
        }
    }
    initialize();
    Database database(database_path_);
    const int anonymous_type = anonymous ? (sysop_anonymous ? 2 : 1) : 0;
    Statement update(database.get(),
        "INSERT INTO auto_message(id, author, text, anonymous, anonymous_type) VALUES(1, ?1, ?2, ?3, ?4) "
        "ON CONFLICT(id) DO UPDATE SET author = excluded.author, text = excluded.text, "
        "anonymous = excluded.anonymous, anonymous_type = excluded.anonymous_type, "
        "created_at = CURRENT_TIMESTAMP");
    update.bind_text(1, author);
    update.bind_text(2, text);
    update.bind_int64(3, anonymous ? 1 : 0);
    update.bind_int64(4, anonymous_type);
    update.check(sqlite3_step(update.get()), "saving auto-message");
}

CommunityStatistics CommunityStore::statistics() const {
    initialize();
    Database database(database_path_);
    const auto count = [&database](const char* sql) -> std::uint64_t {
        Statement query(database.get(), sql);
        const int step = sqlite3_step(query.get());
        query.check(step, "reading community statistics");
        if (step != SQLITE_ROW) {
            return 0;
        }
        const sqlite3_int64 value = sqlite3_column_int64(query.get(), 0);
        return value > 0 ? static_cast<std::uint64_t>(value) : 0;
    };

    CommunityStatistics result;
    result.accounts = count("SELECT COUNT(*) FROM accounts");
    result.public_messages = count("SELECT COUNT(*) FROM messages WHERE deleted = 0");
    result.private_messages = count("SELECT COUNT(*) FROM private_messages");
    result.public_files = count("SELECT COUNT(*) FROM file_entries");
    result.downloads = count("SELECT COALESCE(SUM(download_count), 0) FROM file_entries");
    result.callers_today = count(
        "SELECT COALESCE(SUM(calls_today), 0) FROM account_activity WHERE activity_day = date('now')");
    result.one_liners = count("SELECT COUNT(*) FROM one_liners");
    result.polls = count("SELECT COUNT(*) FROM polls");

    const auto read_user_leaders = [&database](const char* sql,
        std::vector<StatisticLeader>& output, std::string_view operation) {
        Statement leaders(database.get(), sql);
        for (;;) {
            const int step = sqlite3_step(leaders.get());
            if (step == SQLITE_DONE) {
                break;
            }
            leaders.check(step, operation);
            const sqlite3_int64 value = sqlite3_column_int64(leaders.get(), 1);
            output.push_back({column_text(leaders.get(), 0),
                static_cast<std::uint64_t>(std::max<sqlite3_int64>(0, value))});
        }
    };

    {
        Statement leaders(database.get(),
            "SELECT m.author_handle, COUNT(*) FROM messages AS m "
            "JOIN accounts AS a ON a.handle = m.author_handle COLLATE NOCASE "
            "WHERE a.enabled = 1 AND a.approved = 1 AND m.deleted = 0 "
            "GROUP BY m.author_handle ORDER BY COUNT(*) DESC, m.author_handle COLLATE NOCASE LIMIT 5");
        for (;;) {
            const int step = sqlite3_step(leaders.get());
            if (step == SQLITE_DONE) {
                break;
            }
            leaders.check(step, "reading top message posters");
            result.top_public_posters.push_back({column_text(leaders.get(), 0),
                static_cast<std::uint64_t>(sqlite3_column_int64(leaders.get(), 1))});
        }
    }
    read_user_leaders(
        "SELECT s.handle, (s.total_online_seconds + COALESCE((SELECT SUM(MAX(0, CAST((julianday(CURRENT_TIMESTAMP) "
        "- julianday(c.connected_at)) * 86400 AS INTEGER))) FROM caller_sessions AS c "
        "WHERE c.handle = s.handle COLLATE NOCASE AND c.disconnected_at = ''), 0)) / 60 "
        "FROM account_activity AS s JOIN accounts AS a ON a.handle = s.handle COLLATE NOCASE "
        "WHERE a.enabled = 1 AND a.approved = 1 AND s.total_online_seconds > 0 "
        "ORDER BY 2 DESC, s.handle COLLATE NOCASE LIMIT 5",
        result.top_online_minutes, "reading top caller time");
    read_user_leaders(
        "SELECT f.handle, f.uploads FROM file_user_activity AS f "
        "JOIN accounts AS a ON a.handle = f.handle COLLATE NOCASE "
        "WHERE a.enabled = 1 AND a.approved = 1 AND f.uploads > 0 "
        "ORDER BY f.uploads DESC, f.handle COLLATE NOCASE LIMIT 5",
        result.top_uploaders, "reading top uploaders");
    read_user_leaders(
        "SELECT f.handle, f.downloads FROM file_user_activity AS f "
        "JOIN accounts AS a ON a.handle = f.handle COLLATE NOCASE "
        "WHERE a.enabled = 1 AND a.approved = 1 AND f.downloads > 0 "
        "ORDER BY f.downloads DESC, f.handle COLLATE NOCASE LIMIT 5",
        result.top_downloaders, "reading top downloaders");
    read_user_leaders(
        "SELECT f.handle, f.uploaded_bytes / 1024 FROM file_user_activity AS f "
        "JOIN accounts AS a ON a.handle = f.handle COLLATE NOCASE "
        "WHERE a.enabled = 1 AND a.approved = 1 AND f.uploaded_bytes > 0 "
        "ORDER BY f.uploaded_bytes DESC, f.handle COLLATE NOCASE LIMIT 5",
        result.top_uploaded_kib, "reading highest upload volume");
    read_user_leaders(
        "SELECT f.handle, f.downloaded_bytes / 1024 FROM file_user_activity AS f "
        "JOIN accounts AS a ON a.handle = f.handle COLLATE NOCASE "
        "WHERE a.enabled = 1 AND a.approved = 1 AND f.downloaded_bytes > 0 "
        "ORDER BY f.downloaded_bytes DESC, f.handle COLLATE NOCASE LIMIT 5",
        result.top_downloaded_kib, "reading highest download volume");
    {
        Statement leaders(database.get(),
            "SELECT s.handle, s.total_calls FROM account_activity AS s "
            "JOIN accounts AS a ON a.handle = s.handle COLLATE NOCASE "
            "WHERE a.enabled = 1 AND a.approved = 1 AND s.total_calls > 0 "
            "ORDER BY s.total_calls DESC, s.handle COLLATE NOCASE LIMIT 5");
        for (;;) {
            const int step = sqlite3_step(leaders.get());
            if (step == SQLITE_DONE) {
                break;
            }
            leaders.check(step, "reading most frequent callers");
            result.top_callers.push_back({column_text(leaders.get(), 0),
                static_cast<std::uint64_t>(sqlite3_column_int64(leaders.get(), 1))});
        }
    }
    {
        Statement leaders(database.get(),
            "SELECT p.sender_handle, COUNT(*) FROM private_messages AS p "
            "JOIN accounts AS a ON a.handle = p.sender_handle COLLATE NOCASE "
            "WHERE a.enabled = 1 AND a.approved = 1 "
            "GROUP BY p.sender_handle ORDER BY COUNT(*) DESC, p.sender_handle COLLATE NOCASE LIMIT 5");
        for (;;) {
            const int step = sqlite3_step(leaders.get());
            if (step == SQLITE_DONE) {
                break;
            }
            leaders.check(step, "reading private-mail senders");
            result.top_private_mail_senders.push_back({column_text(leaders.get(), 0),
                static_cast<std::uint64_t>(sqlite3_column_int64(leaders.get(), 1))});
        }
    }
    {
        Statement leaders(database.get(),
            "SELECT a.name, f.filename, SUM(f.download_count) AS downloads "
            "FROM file_entries AS f JOIN file_areas AS a ON a.id = f.area_id "
            "GROUP BY a.id, f.filename HAVING downloads > 0 "
            "ORDER BY downloads DESC, a.name COLLATE NOCASE, f.filename COLLATE NOCASE LIMIT 5");
        for (;;) {
            const int step = sqlite3_step(leaders.get());
            if (step == SQLITE_DONE) {
                break;
            }
            leaders.check(step, "reading most-downloaded files");
            result.top_downloads.push_back({column_text(leaders.get(), 0),
                column_text(leaders.get(), 1),
                static_cast<std::uint64_t>(sqlite3_column_int64(leaders.get(), 2))});
        }
    }
    return result;
}

std::vector<CommunityQuote> CommunityStore::approved_quotes() const {
    initialize();
    Database database(database_path_);
    Statement query(database.get(),
        "SELECT id, author, text, created_at FROM quotes ORDER BY id DESC LIMIT 4096");
    std::vector<CommunityQuote> result;
    std::size_t total_text_bytes = 0;
    for (;;) {
        const int step = sqlite3_step(query.get());
        if (step == SQLITE_DONE) {
            break;
        }
        query.check(step, "reading approved quotes");
        const std::string text = column_text(query.get(), 2);
        if (total_text_bytes + text.size() > 4U * 1024U * 1024U) {
            break;
        }
        total_text_bytes += text.size();
        result.push_back({sqlite3_column_int64(query.get(), 0),
            column_text(query.get(), 1), text, column_text(query.get(), 3)});
    }
    return result;
}

QuoteSubmissionPage CommunityStore::quote_submissions(std::size_t page, std::size_t page_size) const {
    if (page_size == 0 || page_size > 100) {
        throw std::invalid_argument("quote-submission page size must be between 1 and 100");
    }
    initialize();
    Database database(database_path_);
    Statement count(database.get(), "SELECT COUNT(*) FROM quote_submissions");
    count.check(sqlite3_step(count.get()), "counting quote submissions");
    QuoteSubmissionPage result;
    result.total = static_cast<std::uint64_t>(sqlite3_column_int64(count.get(), 0));
    result.page_count = std::max<std::size_t>(1,
        static_cast<std::size_t>((result.total + page_size - 1) / page_size));
    result.page = std::min(page, result.page_count - 1);
    Statement query(database.get(),
        "SELECT id, author, text, submitted_at FROM quote_submissions "
        "ORDER BY id DESC LIMIT ?1 OFFSET ?2");
    query.bind_int64(1, static_cast<sqlite3_int64>(page_size));
    query.bind_int64(2, static_cast<sqlite3_int64>(result.page * page_size));
    for (;;) {
        const int step = sqlite3_step(query.get());
        if (step == SQLITE_DONE) {
            break;
        }
        query.check(step, "reading quote submissions");
        result.entries.push_back({sqlite3_column_int64(query.get(), 0),
            column_text(query.get(), 1), column_text(query.get(), 2), column_text(query.get(), 3)});
    }
    return result;
}

void CommunityStore::submit_quote(std::string_view author, std::string_view text) const {
    if (author.empty() || author.size() > 32 || text.empty() || text.size() > 4000) {
        throw std::invalid_argument("quotes need an account handle and 1-4000 characters");
    }
    for (const unsigned char value : author) {
        if (!std::isalnum(value) && value != '.' && value != '_' && value != '-') {
            throw std::invalid_argument("invalid quote author handle");
        }
    }
    for (const unsigned char value : text) {
        if (value == '\r' || value == '\t' || value == 0x7f || value == 0x1b ||
            (value < 0x20 && value != '\n')) {
            throw std::invalid_argument("quote text must contain printable lines");
        }
    }
    initialize();
    Database database(database_path_);
    if (sqlite3_exec(database.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK) {
        throw std::runtime_error("starting quote submission: " + std::string(sqlite3_errmsg(database.get())));
    }
    try {
        {
            Statement count(database.get(), "SELECT COUNT(*) FROM quote_submissions");
            count.check(sqlite3_step(count.get()), "counting pending quote submissions");
            if (sqlite3_column_int64(count.get(), 0) >= 1000) {
                throw std::runtime_error("the SysOp quote-review queue is full");
            }
        }
        {
            Statement insert(database.get(),
                "INSERT INTO quote_submissions(author, text) VALUES(?1, ?2)");
            insert.bind_text(1, author);
            insert.bind_text(2, text);
            insert.check(sqlite3_step(insert.get()), "submitting quote for review");
        }
        if (sqlite3_exec(database.get(), "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error("saving quote submission: " + std::string(sqlite3_errmsg(database.get())));
        }
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void CommunityStore::approve_quote_submission(std::int64_t id) const {
    if (id < 1) {
        throw std::invalid_argument("invalid quote submission id");
    }
    initialize();
    Database database(database_path_);
    if (sqlite3_exec(database.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK) {
        throw std::runtime_error("starting quote approval: " + std::string(sqlite3_errmsg(database.get())));
    }
    try {
        {
            Statement quote_limits(database.get(),
                "SELECT COUNT(*), COALESCE(SUM(length(text)), 0) FROM quotes");
            quote_limits.check(sqlite3_step(quote_limits.get()), "checking approved quote capacity");
            if (sqlite3_column_int64(quote_limits.get(), 0) >= 4096 ||
                sqlite3_column_int64(quote_limits.get(), 1) >= 4 * 1024 * 1024) {
                throw std::runtime_error("the approved quote catalog has reached its storage limit");
            }
        }
        {
            Statement copy(database.get(),
                "INSERT INTO quotes(author, text) "
                "SELECT author, text FROM quote_submissions WHERE id = ?1");
            copy.bind_int64(1, id);
            copy.check(sqlite3_step(copy.get()), "approving quote submission");
            if (sqlite3_changes(database.get()) != 1) {
                throw std::runtime_error("the selected quote submission no longer exists");
            }
            Statement remove(database.get(), "DELETE FROM quote_submissions WHERE id = ?1");
            remove.bind_int64(1, id);
            remove.check(sqlite3_step(remove.get()), "removing approved quote submission");
            if (sqlite3_changes(database.get()) != 1) {
                throw std::runtime_error("the selected quote submission could not be removed");
            }
        }
        if (sqlite3_exec(database.get(), "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error("saving quote approval: " + std::string(sqlite3_errmsg(database.get())));
        }
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void CommunityStore::delete_quote_submission(std::int64_t id) const {
    if (id < 1) {
        throw std::invalid_argument("invalid quote submission id");
    }
    initialize();
    Database database(database_path_);
    Statement remove(database.get(), "DELETE FROM quote_submissions WHERE id = ?1");
    remove.bind_int64(1, id);
    remove.check(sqlite3_step(remove.get()), "deleting quote submission");
    if (sqlite3_changes(database.get()) != 1) {
        throw std::runtime_error("the selected quote submission no longer exists");
    }
}

BbsListingPage CommunityStore::bbs_listings(std::size_t page, std::size_t page_size) const {
    if (page_size == 0 || page_size > 100) {
        throw std::invalid_argument("BBS directory page size must be between 1 and 100");
    }
    initialize();
    Database database(database_path_);
    Statement count(database.get(), "SELECT COUNT(*) FROM bbs_listings");
    count.check(sqlite3_step(count.get()), "counting BBS directory entries");
    BbsListingPage result;
    result.total = static_cast<std::uint64_t>(sqlite3_column_int64(count.get(), 0));
    result.page_count = std::max<std::size_t>(1,
        static_cast<std::size_t>((result.total + page_size - 1) / page_size));
    result.page = std::min(page, result.page_count - 1);
    Statement query(database.get(),
        "SELECT id, owner, bbs_name, sysop_name, telnet_url, website_url, phone_number, software, speed, "
        "description, description2, xa, xb, xc, xd, xe, xf, date_added, date_edited "
        "FROM bbs_listings ORDER BY bbs_name COLLATE NOCASE, id LIMIT ?1 OFFSET ?2");
    query.bind_int64(1, static_cast<sqlite3_int64>(page_size));
    query.bind_int64(2, static_cast<sqlite3_int64>(result.page * page_size));
    for (;;) {
        const int step = sqlite3_step(query.get());
        if (step == SQLITE_DONE) {
            break;
        }
        query.check(step, "reading BBS directory");
        result.entries.push_back(read_bbs_listing(query.get()));
    }
    return result;
}

std::size_t CommunityStore::bbs_listing_page_for(std::int64_t id, std::size_t page_size) const {
    if (id < 1 || page_size == 0 || page_size > 100) {
        throw std::invalid_argument("invalid BBS directory page lookup");
    }
    initialize();
    Database database(database_path_);
    Statement query(database.get(),
        "SELECT COUNT(*) FROM bbs_listings AS earlier WHERE "
        "earlier.bbs_name COLLATE NOCASE < (SELECT bbs_name FROM bbs_listings WHERE id = ?1) OR "
        "(earlier.bbs_name COLLATE NOCASE = (SELECT bbs_name FROM bbs_listings WHERE id = ?1) "
        "AND earlier.id < ?1)");
    query.bind_int64(1, id);
    const int step = sqlite3_step(query.get());
    query.check(step, "locating BBS directory entry");
    const sqlite3_int64 position = sqlite3_column_int64(query.get(), 0);
    return static_cast<std::size_t>(std::max<sqlite3_int64>(0, position)) / page_size;
}

std::int64_t CommunityStore::add_bbs_listing(std::string_view owner, const BbsListing& listing) const {
    validate_bbs_listing(owner, listing);
    initialize();
    Database database(database_path_);
    {
        Statement count(database.get(), "SELECT COUNT(*) FROM bbs_listings");
        count.check(sqlite3_step(count.get()), "checking BBS directory capacity");
        if (sqlite3_column_int64(count.get(), 0) >= 10000) {
            throw std::runtime_error("the BBS directory has reached its 10,000-entry limit");
        }
    }
    Statement insert(database.get(),
        "INSERT INTO bbs_listings(owner, bbs_name, sysop_name, telnet_url, website_url, phone_number, "
        "software, speed, description, description2, xa, xb, xc, xd, xe, xf, date_added, date_edited) "
        "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, "
        "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)");
    insert.bind_text(1, owner);
    bind_bbs_listing(insert, 2, listing);
    insert.check(sqlite3_step(insert.get()), "adding BBS directory entry");
    return static_cast<std::int64_t>(sqlite3_last_insert_rowid(database.get()));
}

void CommunityStore::update_bbs_listing(
    std::int64_t id,
    std::string_view caller,
    bool sysop,
    const BbsListing& listing) const {
    if (id < 1 || caller.empty()) {
        throw std::invalid_argument("invalid BBS directory update request");
    }
    validate_bbs_listing(caller, listing);
    initialize();
    Database database(database_path_);
    Statement update(database.get(),
        "UPDATE bbs_listings SET bbs_name = ?1, sysop_name = ?2, telnet_url = ?3, website_url = ?4, "
        "phone_number = ?5, software = ?6, speed = ?7, description = ?8, description2 = ?9, "
        "xa = ?10, xb = ?11, xc = ?12, xd = ?13, xe = ?14, xf = ?15, "
        "date_edited = CURRENT_TIMESTAMP WHERE id = ?16 AND (owner = ?17 COLLATE NOCASE OR ?18 = 1)");
    bind_bbs_listing(update, 1, listing);
    update.bind_int64(16, id);
    update.bind_text(17, caller);
    update.bind_int64(18, sysop ? 1 : 0);
    update.check(sqlite3_step(update.get()), "updating BBS directory entry");
    if (sqlite3_changes(database.get()) != 1) {
        throw std::runtime_error("the listing no longer exists or belongs to another caller");
    }
}

void CommunityStore::delete_bbs_listing(std::int64_t id, std::string_view caller, bool sysop) const {
    if (id < 1 || caller.empty()) {
        throw std::invalid_argument("invalid BBS directory delete request");
    }
    initialize();
    Database database(database_path_);
    Statement remove(database.get(),
        "DELETE FROM bbs_listings WHERE id = ?1 AND (owner = ?2 COLLATE NOCASE OR ?3 = 1)");
    remove.bind_int64(1, id);
    remove.bind_text(2, caller);
    remove.bind_int64(3, sysop ? 1 : 0);
    remove.check(sqlite3_step(remove.get()), "deleting BBS directory entry");
    if (sqlite3_changes(database.get()) != 1) {
        throw std::runtime_error("the listing no longer exists or belongs to another caller");
    }
}

void CommunityStore::send_short_message(
    std::string_view recipient, std::string_view text, bool allow_pending_account) const {
    if (recipient.empty() || recipient.size() > 32 || text.empty() || text.size() > 80) {
        throw std::invalid_argument("short messages need a handle and 1-80 printable characters");
    }
    for (const unsigned char value : recipient) {
        if (!std::isalnum(value) && value != '.' && value != '_' && value != '-') {
            throw std::invalid_argument("invalid short-message recipient");
        }
    }
    for (const unsigned char value : text) {
        if (value < 0x20 || value == 0x7f || value == 0x1b) {
            throw std::invalid_argument("short messages must be single-line printable text");
        }
    }
    initialize();
    Database database(database_path_);
    {
        Statement account(database.get(),
            "SELECT 1 FROM accounts WHERE handle = ?1 COLLATE NOCASE "
            "AND (?2 = 1 OR (enabled = 1 AND approved = 1))");
        account.bind_text(1, recipient);
        account.bind_int64(2, allow_pending_account ? 1 : 0);
        const int step = sqlite3_step(account.get());
        account.check(step, "checking short-message recipient");
        if (step != SQLITE_ROW) {
            throw std::invalid_argument("short-message recipient is not an active BBS account");
        }
    }
    if (sqlite3_exec(database.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK) {
        throw std::runtime_error("starting short-message queue update: " +
            std::string(sqlite3_errmsg(database.get())));
    }
    try {
        char* prune_error = nullptr;
        if (sqlite3_exec(database.get(),
                "DELETE FROM short_messages WHERE delivered_at <> '' AND created_at < datetime('now', '-90 days')",
                nullptr, nullptr, &prune_error) != SQLITE_OK) {
            const std::string detail = prune_error != nullptr ? prune_error : sqlite3_errmsg(database.get());
            sqlite3_free(prune_error);
            throw std::runtime_error("pruning delivered short messages: " + detail);
        }
        {
            Statement count(database.get(),
                "SELECT COUNT(*), SUM(CASE WHEN recipient = ?1 COLLATE NOCASE THEN 1 ELSE 0 END) "
                "FROM short_messages WHERE delivered_at = ''");
            count.bind_text(1, recipient);
            count.check(sqlite3_step(count.get()), "checking short-message capacity");
            if (sqlite3_column_int64(count.get(), 0) >= 100000) {
                throw std::runtime_error("the short-message system queue is full");
            }
            if (sqlite3_column_int64(count.get(), 1) >= 256) {
                throw std::runtime_error("the caller's short-message queue is full");
            }
        }
        {
            Statement insert(database.get(), "INSERT INTO short_messages(recipient, text) VALUES(?1, ?2)");
            insert.bind_text(1, recipient);
            insert.bind_text(2, text);
            insert.check(sqlite3_step(insert.get()), "sending short message");
        }
        if (sqlite3_exec(database.get(), "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error("saving short message: " + std::string(sqlite3_errmsg(database.get())));
        }
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

std::vector<ShortMessage> CommunityStore::claim_short_messages(std::string_view recipient) const {
    if (recipient.empty() || recipient.size() > 32) {
        throw std::invalid_argument("invalid short-message account handle");
    }
    initialize();
    Database database(database_path_);
    if (sqlite3_exec(database.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK) {
        throw std::runtime_error("starting short-message delivery: " +
            std::string(sqlite3_errmsg(database.get())));
    }
    try {
        std::vector<ShortMessage> result;
        {
            Statement query(database.get(),
                "SELECT id, text, created_at FROM short_messages "
                "WHERE recipient = ?1 COLLATE NOCASE AND delivered_at = '' ORDER BY id LIMIT 50");
            query.bind_text(1, recipient);
            for (;;) {
                const int step = sqlite3_step(query.get());
                if (step == SQLITE_DONE) {
                    break;
                }
                query.check(step, "reading pending short messages");
                result.push_back({sqlite3_column_int64(query.get(), 0), column_text(query.get(), 1),
                    column_text(query.get(), 2)});
            }
        }
        for (const ShortMessage& message : result) {
            Statement mark(database.get(),
                "UPDATE short_messages SET delivered_at = CURRENT_TIMESTAMP "
                "WHERE id = ?1 AND recipient = ?2 COLLATE NOCASE AND delivered_at = ''");
            mark.bind_int64(1, message.id);
            mark.bind_text(2, recipient);
            mark.check(sqlite3_step(mark.get()), "marking short message delivered");
        }
        if (sqlite3_exec(database.get(), "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error("finishing short-message delivery: " +
                std::string(sqlite3_errmsg(database.get())));
        }
        return result;
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

std::vector<ScheduledEvent> CommunityStore::scheduled_events() const {
    initialize();
    Database database(database_path_);
    Statement query(database.get(),
        "SELECT slot, description, type, active, monthly, day_mask, day_of_month, start_minute, "
        "finish_minute, pre_warning_minutes, node, access_acs, max_time_minutes, set_ar_flag, "
        "clear_ar_flag, low_baud, high_baud, soft, run_if_missed, last_run_date "
        "FROM scheduled_events ORDER BY slot");
    std::vector<ScheduledEvent> result;
    for (;;) {
        const int step = sqlite3_step(query.get());
        if (step == SQLITE_DONE) {
            break;
        }
        query.check(step, "listing scheduled events");
        ScheduledEvent event;
        event.slot = sqlite3_column_int(query.get(), 0);
        event.description = column_text(query.get(), 1);
        event.type = column_text(query.get(), 2);
        event.active = sqlite3_column_int(query.get(), 3) != 0;
        event.monthly = sqlite3_column_int(query.get(), 4) != 0;
        event.day_mask = sqlite3_column_int(query.get(), 5);
        event.day_of_month = sqlite3_column_int(query.get(), 6);
        event.start_minute = sqlite3_column_int(query.get(), 7);
        event.finish_minute = sqlite3_column_int(query.get(), 8);
        event.pre_warning_minutes = sqlite3_column_int(query.get(), 9);
        event.node = sqlite3_column_int(query.get(), 10);
        event.access_acs = column_text(query.get(), 11);
        event.max_time_minutes = sqlite3_column_int(query.get(), 12);
        const std::string set_flag = column_text(query.get(), 13);
        const std::string clear_flag = column_text(query.get(), 14);
        event.set_ar_flag = set_flag.empty() ? '\0' : set_flag.front();
        event.clear_ar_flag = clear_flag.empty() ? '\0' : clear_flag.front();
        event.low_baud = sqlite3_column_int(query.get(), 15);
        event.high_baud = sqlite3_column_int(query.get(), 16);
        event.soft = sqlite3_column_int(query.get(), 17) != 0;
        event.run_if_missed = sqlite3_column_int(query.get(), 18) != 0;
        event.last_run_date = column_text(query.get(), 19);
        result.push_back(std::move(event));
    }
    return result;
}

void CommunityStore::set_scheduled_event(const ScheduledEvent& event) const {
    if (event.slot < 1 || event.slot > 10 || event.description.empty() ||
        event.description.size() > 30 ||
        (event.type != "logon" && event.type != "chat" && event.type != "permission" &&
            event.type != "external") || event.day_mask < 0 || event.day_mask > 127 ||
        event.day_of_month < 0 || event.day_of_month > 31 ||
        event.start_minute < 0 || event.start_minute > 1439 ||
        event.finish_minute < 0 || event.finish_minute > 1439 ||
        event.pre_warning_minutes < 0 || event.pre_warning_minutes > 255 ||
        event.node < 0 || event.node > 32 || event.access_acs.size() > 20 ||
        event.max_time_minutes < 0 || event.max_time_minutes > 65535 ||
        event.low_baud < 0 || event.high_baud < event.low_baud ||
        (event.set_ar_flag != '\0' && (event.set_ar_flag < 'A' || event.set_ar_flag > 'Z')) ||
        (event.clear_ar_flag != '\0' && (event.clear_ar_flag < 'A' || event.clear_ar_flag > 'Z')) ||
        (event.monthly ? (event.day_of_month < 1 || event.day_of_month > 31) : event.day_mask == 0)) {
        throw std::invalid_argument("invalid scheduled event fields");
    }
    initialize();
    Database database(database_path_);
    Statement save(database.get(),
        "INSERT INTO scheduled_events (slot, description, type, active, monthly, day_mask, day_of_month, "
        "start_minute, finish_minute, pre_warning_minutes, node, access_acs, max_time_minutes, "
        "set_ar_flag, clear_ar_flag, low_baud, high_baud, soft, run_if_missed) "
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19) "
        "ON CONFLICT(slot) DO UPDATE SET description=excluded.description, type=excluded.type, "
        "active=excluded.active, monthly=excluded.monthly, day_mask=excluded.day_mask, "
        "day_of_month=excluded.day_of_month, start_minute=excluded.start_minute, "
        "finish_minute=excluded.finish_minute, pre_warning_minutes=excluded.pre_warning_minutes, "
        "node=excluded.node, access_acs=excluded.access_acs, max_time_minutes=excluded.max_time_minutes, "
        "set_ar_flag=excluded.set_ar_flag, clear_ar_flag=excluded.clear_ar_flag, "
        "low_baud=excluded.low_baud, high_baud=excluded.high_baud, soft=excluded.soft, "
        "run_if_missed=excluded.run_if_missed");
    save.bind_int64(1, event.slot);
    save.bind_text(2, event.description);
    save.bind_text(3, event.type);
    save.bind_int64(4, event.active ? 1 : 0);
    save.bind_int64(5, event.monthly ? 1 : 0);
    save.bind_int64(6, event.day_mask);
    save.bind_int64(7, event.day_of_month);
    save.bind_int64(8, event.start_minute);
    save.bind_int64(9, event.finish_minute);
    save.bind_int64(10, event.pre_warning_minutes);
    save.bind_int64(11, event.node);
    save.bind_text(12, event.access_acs);
    save.bind_int64(13, event.max_time_minutes);
    save.bind_text(14, event.set_ar_flag == '\0' ? std::string_view{} : std::string_view(&event.set_ar_flag, 1));
    save.bind_text(15, event.clear_ar_flag == '\0' ? std::string_view{} : std::string_view(&event.clear_ar_flag, 1));
    save.bind_int64(16, event.low_baud);
    save.bind_int64(17, event.high_baud);
    save.bind_int64(18, event.soft ? 1 : 0);
    save.bind_int64(19, event.run_if_missed ? 1 : 0);
    save.check(sqlite3_step(save.get()), "saving scheduled event");
}

void CommunityStore::delete_scheduled_event(int slot) const {
    if (slot < 1 || slot > 10) {
        throw std::invalid_argument("event slot must be between 1 and 10");
    }
    initialize();
    Database database(database_path_);
    Statement remove(database.get(), "DELETE FROM scheduled_events WHERE slot = ?1");
    remove.bind_int64(1, slot);
    remove.check(sqlite3_step(remove.get()), "deleting scheduled event");
}

void CommunityStore::record_sysop_action(
    std::string_view actor, std::string_view action, std::string_view subject) const {
    if (actor.empty() || actor.size() > 32 || action.empty() || action.size() > 64 || subject.size() > 256) {
        throw std::invalid_argument("SysOp audit fields are outside their allowed lengths");
    }
    for (const unsigned char value : actor) {
        if (!std::isalnum(value) && value != '.' && value != '_' && value != '-') {
            throw std::invalid_argument("invalid SysOp audit actor");
        }
    }
    for (const std::string_view value : {action, subject}) {
        for (const unsigned char byte : value) {
            if (byte < 0x20 || byte == 0x7f || byte == 0x1b) {
                throw std::invalid_argument("SysOp audit text must be single-line printable text");
            }
        }
    }
    initialize();
    Database database(database_path_);
    execute_sql(database.get(), "BEGIN IMMEDIATE", "starting SysOp audit write");
    try {
        {
            Statement insert(database.get(),
                "INSERT INTO sysop_audit(actor, action, subject) VALUES(?1, ?2, ?3)");
            insert.bind_text(1, actor);
            insert.bind_text(2, action);
            insert.bind_text(3, subject);
            insert.check(sqlite3_step(insert.get()), "recording SysOp action");
        }
        execute_sql(database.get(),
            "DELETE FROM sysop_audit WHERE id NOT IN "
            "(SELECT id FROM sysop_audit ORDER BY id DESC LIMIT 20000)",
            "pruning SysOp audit history");
        execute_sql(database.get(), "COMMIT", "saving SysOp audit action");
    } catch (...) {
        (void)sqlite3_exec(database.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

SysopAuditPage CommunityStore::sysop_audit(std::size_t page, std::size_t page_size) const {
    if (page_size == 0 || page_size > 100) {
        throw std::invalid_argument("SysOp audit page size must be between 1 and 100");
    }
    initialize();
    Database database(database_path_);
    SysopAuditPage result;
    {
        Statement count(database.get(), "SELECT COUNT(*) FROM sysop_audit");
        count.check(sqlite3_step(count.get()), "counting SysOp audit entries");
        result.total = static_cast<std::uint64_t>(sqlite3_column_int64(count.get(), 0));
    }
    result.page_count = result.total == 0 ? 1 : static_cast<std::size_t>(
        (result.total + page_size - 1) / page_size);
    result.page = std::min(page, result.page_count - 1);
    Statement query(database.get(),
        "SELECT id, actor, action, subject, created_at FROM sysop_audit "
        "ORDER BY id DESC LIMIT ?1 OFFSET ?2");
    query.bind_int64(1, static_cast<sqlite3_int64>(page_size));
    query.bind_int64(2, static_cast<sqlite3_int64>(result.page * page_size));
    for (;;) {
        const int step = sqlite3_step(query.get());
        if (step == SQLITE_DONE) {
            break;
        }
        query.check(step, "reading SysOp audit history");
        result.entries.push_back({
            sqlite3_column_int64(query.get(), 0),
            column_text(query.get(), 1),
            column_text(query.get(), 2),
            column_text(query.get(), 3),
            column_text(query.get(), 4),
        });
    }
    return result;
}

} // namespace renegade
