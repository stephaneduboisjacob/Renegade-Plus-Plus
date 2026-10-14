#include "file_store.hpp"
#include "archive_store.hpp"
#include "legacy_acs.hpp"

#include <sqlite3.h>

#include <linux/fs.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <chrono>
#include <climits>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <strings.h>
#include <system_error>
#include <sys/file.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace renegade {
namespace {

class Database final {
public:
    Database(const std::string& path, int flags) {
        const int result = sqlite3_open_v2(path.c_str(), &handle_, flags, nullptr);
        if (result != SQLITE_OK) {
            const std::string message = handle_ != nullptr
                ? sqlite3_errmsg(handle_)
                : "could not allocate SQLite handle";
            if (handle_ != nullptr) {
                sqlite3_close(handle_);
                handle_ = nullptr;
            }
            throw std::runtime_error("opening file-area database: " + message);
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
    Statement(sqlite3* db, const char* sql) : db_(db) {
        if (sqlite3_prepare_v2(db, sql, -1, &statement_, nullptr) != SQLITE_OK) {
            throw std::runtime_error("preparing file-area query: " + std::string(sqlite3_errmsg(db)));
        }
    }

    ~Statement() { sqlite3_finalize(statement_); }
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    [[nodiscard]] sqlite3_stmt* get() const noexcept { return statement_; }
    void bind_text(int index, std::string_view value) {
        check(sqlite3_bind_text(statement_, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT),
            "binding file-area data");
    }
    void bind_int(int index, int value) {
        check(sqlite3_bind_int(statement_, index, value), "binding file-area data");
    }
    void bind_int64(int index, sqlite3_int64 value) {
        check(sqlite3_bind_int64(statement_, index, value), "binding file-area data");
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

void check_exec(sqlite3* db, const char* sql, std::string_view operation) {
    char* error = nullptr;
    const int result = sqlite3_exec(db, sql, nullptr, nullptr, &error);
    if (result != SQLITE_OK) {
        const std::string detail = error != nullptr ? error : sqlite3_errmsg(db);
        sqlite3_free(error);
        throw std::runtime_error(std::string(operation) + ": " + detail);
    }
}

bool file_column_exists(sqlite3* db, std::string_view name) {
    Statement columns(db, "PRAGMA table_info(file_entries)");
    for (;;) {
        const int result = sqlite3_step(columns.get());
        if (result == SQLITE_DONE) {
            return false;
        }
        columns.check(result, "checking file-entry schema");
        const auto* column = reinterpret_cast<const char*>(sqlite3_column_text(columns.get(), 1));
        if (column != nullptr && name == column) {
            return true;
        }
    }
}

bool activity_column_exists(sqlite3* db, std::string_view name) {
    Statement columns(db, "PRAGMA table_info(file_user_activity)");
    for (;;) {
        const int result = sqlite3_step(columns.get());
        if (result == SQLITE_DONE) {
            return false;
        }
        columns.check(result, "checking file activity schema");
        const auto* column = reinterpret_cast<const char*>(sqlite3_column_text(columns.get(), 1));
        if (column != nullptr && name == column) {
            return true;
        }
    }
}

bool area_column_exists(sqlite3* db, std::string_view name) {
    Statement columns(db, "PRAGMA table_info(file_areas)");
    for (;;) {
        const int result = sqlite3_step(columns.get());
        if (result == SQLITE_DONE) {
            return false;
        }
        columns.check(result, "checking file-area schema");
        const auto* column = reinterpret_cast<const char*>(sqlite3_column_text(columns.get(), 1));
        if (column != nullptr && name == column) {
            return true;
        }
    }
}

bool caller_session_column_exists(sqlite3* db, std::string_view name) {
    Statement columns(db, "PRAGMA table_info(caller_sessions)");
    for (;;) {
        const int result = sqlite3_step(columns.get());
        if (result == SQLITE_DONE) {
            return false;
        }
        columns.check(result, "checking caller-session time-limit schema");
        const auto* column = reinterpret_cast<const char*>(sqlite3_column_text(columns.get(), 1));
        if (column != nullptr && std::string_view(column) == name) {
            return true;
        }
    }
}

AccessLevels account_access_levels(sqlite3* db, std::string_view handle) {
    Statement query(db,
        "SELECT security_level, download_security_level, is_sysop, acs_ar_flags, acs_ac_flags, credits, rowid, birth_date, sex, expert_mode, expiration_date FROM accounts "
        "WHERE handle = ?1 COLLATE NOCASE");
    query.bind_text(1, handle);
    const int result = sqlite3_step(query.get());
    query.check(result, "reading account security levels");
    if (result == SQLITE_DONE) {
        throw std::invalid_argument("BBS account does not exist");
    }
    const auto text = [&query](int column) {
        const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(query.get(), column));
        return value == nullptr ? std::string{} : std::string(value);
    };
    AccessLevels levels{sqlite3_column_int(query.get(), 0), sqlite3_column_int(query.get(), 1),
        sqlite3_column_int(query.get(), 2) != 0, text(3), text(4), sqlite3_column_int64(query.get(), 5),
        sqlite3_column_int64(query.get(), 6), 0, 0, 0, {}, '\0', true, true, 0, 32767, {}};
    levels.birth_date = text(7);
    const std::string sex = text(8);
    levels.sex = sex.empty() ? '\0' : sex.front();
    levels.novice_help = sqlite3_column_int(query.get(), 9) == 0;
    levels.expiration_date = text(10);
    const auto count_for_handle = [db, handle](const char* table_name, const char* sql,
                                    std::string_view operation) -> std::uint64_t {
        Statement available(db,
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1");
        available.bind_text(1, table_name);
        if (sqlite3_step(available.get()) != SQLITE_ROW) {
            return 0;
        }
        Statement count(db, sql);
        count.bind_text(1, handle);
        const int count_result = sqlite3_step(count.get());
        count.check(count_result, operation);
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
    int configured_post_ratio{};
    {
        Statement metadata_table(db,
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'message_store_meta'");
        if (sqlite3_step(metadata_table.get()) == SQLITE_ROW) {
            Statement ratio(db, "SELECT value FROM message_store_meta WHERE key = ?1");
            ratio.bind_text(1, "post_ratio_" + std::to_string(levels.security_level));
            const int ratio_result = sqlite3_step(ratio.get());
            ratio.check(ratio_result, "reading post-call ratio for ACS");
            if (ratio_result == SQLITE_ROW) {
                const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(ratio.get(), 0));
                if (value != nullptr) {
                    const std::string_view ratio_text(value);
                    const auto parsed = std::from_chars(
                        ratio_text.data(), ratio_text.data() + ratio_text.size(), configured_post_ratio);
                    if (parsed.ec != std::errc{} || parsed.ptr != ratio_text.data() + ratio_text.size() ||
                        configured_post_ratio < 0 || configured_post_ratio > 100) {
                        configured_post_ratio = 0;
                    }
                }
            }
        }
    }
    levels.post_ratio_percent = configured_post_ratio;
    {
        Statement metadata_table(db,
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'message_store_meta'");
        if (sqlite3_step(metadata_table.get()) == SQLITE_ROW) {
            Statement validation(db,
                "SELECT key, value FROM message_store_meta "
                "WHERE key IN ('validation_key_active', 'validation_new_security_level')");
            for (;;) {
                const int validation_result = sqlite3_step(validation.get());
                if (validation_result == SQLITE_DONE) {
                    break;
                }
                validation.check(validation_result, "reading validation ACS settings");
                const auto* key_value = reinterpret_cast<const char*>(sqlite3_column_text(validation.get(), 0));
                const auto* setting_value = reinterpret_cast<const char*>(sqlite3_column_text(validation.get(), 1));
                if (key_value == nullptr || setting_value == nullptr) {
                    continue;
                }
                const std::string_view key(key_value);
                const std::string_view value(setting_value);
                if (key == "validation_key_active") {
                    levels.validation_key_active = value == "1";
                } else if (key == "validation_new_security_level") {
                    int new_level{};
                    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), new_level);
                    if (parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size() &&
                        new_level >= 0 && new_level <= 255) {
                        levels.validation_new_security_level = new_level;
                    }
                }
            }
        }
    }
    Statement polls_table(db, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'polls'");
    const int polls_table_result = sqlite3_step(polls_table.get());
    polls_table.check(polls_table_result, "checking poll access data availability");
    if (polls_table_result == SQLITE_ROW) {
        Statement unvoted(db,
            "SELECT COUNT(*) FROM polls AS p LEFT JOIN poll_votes AS v "
            "ON v.poll_id = p.id AND v.caller = ?1 COLLATE NOCASE WHERE v.id IS NULL");
        unvoted.bind_text(1, handle);
        const int unvoted_result = sqlite3_step(unvoted.get());
        unvoted.check(unvoted_result, "checking caller poll votes");
        levels.voted_in_all_polls = unvoted_result == SQLITE_ROW &&
            sqlite3_column_int64(unvoted.get(), 0) == 0;
    }
    Statement session_table(db, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'caller_sessions'");
    const int table_result = sqlite3_step(session_table.get());
    session_table.check(table_result, "checking caller-session history availability");
    if (table_result == SQLITE_ROW) {
        const bool has_expiry = caller_session_column_exists(db, "expires_at");
        const bool has_invisible = caller_session_column_exists(db, "invisible");
        std::string session_query =
            "SELECT node, CAST((julianday('now') - julianday(connected_at)) * 1440 AS INTEGER), ";
        session_query += has_expiry
            ? "CASE WHEN expires_at = '' THEN 32767 ELSE MAX(0, CAST((julianday(expires_at) - julianday('now')) * 1440 AS INTEGER)) END, "
            : "32767, ";
        session_query += has_invisible ? "invisible " : "0 ";
        session_query +=
            "FROM caller_sessions WHERE handle = ?1 COLLATE NOCASE AND disconnected_at = '' "
            "ORDER BY connected_at DESC LIMIT 1";
        Statement session(db, session_query.c_str());
        session.bind_text(1, handle);
        const int session_result = sqlite3_step(session.get());
        session.check(session_result, "reading active caller-session duration");
        if (session_result == SQLITE_ROW) {
            levels.node_number = sqlite3_column_int(session.get(), 0);
            levels.online_minutes = std::max<sqlite3_int64>(0, sqlite3_column_int64(session.get(), 1));
            levels.remaining_minutes = sqlite3_column_int(session.get(), 2);
            levels.invisible = sqlite3_column_int(session.get(), 3) != 0;
        }
        if (caller_session_column_exists(db, "sysop_available")) {
            Statement availability(db,
                "SELECT EXISTS(SELECT 1 FROM caller_sessions AS s "
                "JOIN accounts AS a ON a.handle = s.handle COLLATE NOCASE "
                "WHERE s.disconnected_at = '' AND s.sysop_available = 1 AND a.is_sysop = 1)");
            const int availability_result = sqlite3_step(availability.get());
            availability.check(availability_result, "checking SysOp availability");
            levels.sysop_available = availability_result == SQLITE_ROW &&
                sqlite3_column_int(availability.get(), 0) != 0;
        }
    }
    return levels;
}

std::string file_store_setting(sqlite3* db, std::string_view key, std::string_view fallback) {
    Statement query(db, "SELECT value FROM file_store_meta WHERE key = ?1");
    query.bind_text(1, key);
    const int result = sqlite3_step(query.get());
    query.check(result, "reading file-store setting");
    if (result == SQLITE_DONE) {
        return std::string(fallback);
    }
    const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(query.get(), 0));
    return value == nullptr ? std::string(fallback) : std::string(value);
}

std::uint64_t file_store_unsigned_setting(sqlite3* db, std::string_view key) {
    const std::string value = file_store_setting(db, key, "0");
    std::uint64_t parsed_value{};
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), parsed_value);
    if (value.empty() || parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
        throw std::runtime_error("stored file-ratio setting is invalid: " + std::string(key));
    }
    return parsed_value;
}

std::uint64_t saturating_add(std::uint64_t left, std::uint64_t right) {
    return right > UINT64_MAX - left ? UINT64_MAX : left + right;
}

bool exceeds_ratio(std::uint64_t numerator, std::uint64_t denominator, std::uint64_t limit) {
    if (limit == 0) {
        return false;
    }
    const long double ratio = denominator > 0
        ? static_cast<long double>(numerator) / static_cast<long double>(denominator)
        : static_cast<long double>(numerator);
    return ratio > static_cast<long double>(limit);
}

std::uint64_t calculate_file_point_cost(sqlite3* db, std::uint64_t size_bytes) {
    if (file_store_setting(db, "file_points_enabled", "0") != "1") {
        return 0;
    }
    const std::uint64_t base_size_kib = file_store_unsigned_setting(db, "file_points_base_size_kib");
    if (base_size_kib == 0) {
        return 0;
    }
    return std::min<std::uint64_t>(32767U, (size_bytes / 1024U) / base_size_kib);
}

void credit_validated_file_uploader(
    sqlite3* db,
    int area_id,
    std::string_view filename,
    std::optional<std::uint64_t> explicit_reward = std::nullopt) {
    if (file_store_setting(db, "file_points_enabled", "0") != "1") {
        return;
    }
    const std::uint64_t multiplier = file_store_unsigned_setting(
        db, "file_points_upload_compensation");
    const std::uint64_t base_size_kib = file_store_unsigned_setting(
        db, "file_points_base_size_kib");
    std::string owner;
    std::uint64_t size_bytes = 0;
    bool validated = false;
    bool already_credited = false;
    {
        Statement file(db,
            "SELECT owner_handle, size, validated, uploader_credited FROM file_entries "
            "WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE");
        file.bind_int(1, area_id);
        file.bind_text(2, filename);
        const int result = sqlite3_step(file.get());
        file.check(result, "reading file for uploader credit");
        if (result != SQLITE_ROW) {
            throw std::invalid_argument("file is not indexed in this area");
        }
        const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(file.get(), 0));
        owner = value == nullptr ? std::string{} : std::string(value);
        size_bytes = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
            0, sqlite3_column_int64(file.get(), 1)));
        validated = sqlite3_column_int(file.get(), 2) != 0;
        already_credited = sqlite3_column_int(file.get(), 3) != 0;
    }
    if (!validated || already_credited || owner.empty()) {
        return;
    }
    const std::uint64_t reward = explicit_reward.has_value()
        ? std::min<std::uint64_t>(INT_MAX, *explicit_reward)
        : std::max<std::uint64_t>(1, std::min<std::uint64_t>(INT_MAX,
            (base_size_kib == 0 ? 0 : (size_bytes / 1024U) / base_size_kib) * multiplier));
    std::uint64_t credited_amount = 0;
    {
        Statement account(db, "SELECT file_points FROM accounts WHERE handle = ?1 COLLATE NOCASE");
        account.bind_text(1, owner);
        const int result = sqlite3_step(account.get());
        account.check(result, "reading file uploader point balance");
        if (result != SQLITE_ROW) {
            return;
        }
        const std::uint64_t balance = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
            0, sqlite3_column_int64(account.get(), 0)));
        credited_amount = std::min<std::uint64_t>(reward, 2147483647U - balance);
    }
    {
        Statement account(db,
            "UPDATE accounts SET file_points = file_points + ?1 WHERE handle = ?2 COLLATE NOCASE");
        account.bind_int64(1, static_cast<sqlite3_int64>(credited_amount));
        account.bind_text(2, owner);
        account.check(sqlite3_step(account.get()), "crediting file uploader points");
    }
    Statement mark(db,
        "UPDATE file_entries SET uploader_credited = 1, uploader_credit_amount = ?1 WHERE area_id = ?2 "
        "AND filename = ?3 COLLATE NOCASE AND uploader_credited = 0");
    mark.bind_int64(1, static_cast<sqlite3_int64>(credited_amount));
    mark.bind_int(2, area_id);
    mark.bind_text(3, filename);
    mark.check(sqlite3_step(mark.get()), "recording uploader point credit");
}

void revoke_validated_file_uploader(sqlite3* db, int area_id, std::string_view filename) {
    std::string owner;
    std::uint64_t credited_amount = 0;
    {
        Statement file(db,
            "SELECT owner_handle, uploader_credit_amount FROM file_entries "
            "WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE AND uploader_credited = 1");
        file.bind_int(1, area_id);
        file.bind_text(2, filename);
        const int result = sqlite3_step(file.get());
        file.check(result, "reading uploader credit for validation reversal");
        if (result != SQLITE_ROW) {
            return;
        }
        const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(file.get(), 0));
        owner = value == nullptr ? std::string{} : std::string(value);
        credited_amount = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
            0, sqlite3_column_int64(file.get(), 1)));
    }
    if (!owner.empty() && credited_amount > 0) {
        Statement account(db,
            "UPDATE accounts SET file_points = MAX(0, file_points - ?1) WHERE handle = ?2 COLLATE NOCASE");
        account.bind_int64(1, static_cast<sqlite3_int64>(credited_amount));
        account.bind_text(2, owner);
        account.check(sqlite3_step(account.get()), "reversing uploader file-point credit");
    }
    Statement clear(db,
        "UPDATE file_entries SET uploader_credited = 0, uploader_credit_amount = 0 "
        "WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE");
    clear.bind_int(1, area_id);
    clear.bind_text(2, filename);
    clear.check(sqlite3_step(clear.get()), "clearing uploader file-point credit state");
}

bool valid_area_name(std::string_view name) {
    if (name.empty() || name.size() > 48 || name.front() == ' ' || name.back() == ' ') {
        return false;
    }
    for (const unsigned char value : name) {
        if (value < 0x20 || value == 0x7f || value == 0x1b) {
            return false;
        }
    }
    return true;
}

bool valid_file_name(std::string_view name) {
    if (name.empty() || name == "." || name == ".." || name.size() > 255) {
        return false;
    }
    for (const unsigned char value : name) {
        if (value < 0x20 || value == 0x7f || value == '/' || value == '\\' || value == 0x1b) {
            return false;
        }
    }
    return true;
}

struct EmbeddedDescription {
    std::string summary;
    std::string extended;
};

std::optional<EmbeddedDescription> embedded_archive_description(
    int descriptor,
    std::string_view filename,
    off_t size) {
    if (!ArchiveStore::supports_filename(filename) || size <= 0 ||
        static_cast<std::uint64_t>(size) > ArchiveStore::max_archive_bytes) {
        return std::nullopt;
    }
    try {
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            const ssize_t amount = ::pread(descriptor, bytes.data() + offset, bytes.size() - offset,
                static_cast<off_t>(offset));
            if (amount < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::nullopt;
            }
            if (amount == 0) {
                return std::nullopt;
            }
            offset += static_cast<std::size_t>(amount);
        }
        const ArchiveListing archive = ArchiveStore::list(bytes);
        for (const std::string_view requested : {"FILE_ID.DIZ", "DESC.SDI"}) {
            for (const ArchiveEntry& entry : archive.entries) {
                if (entry.directory || entry.encrypted) {
                    continue;
                }
                const std::size_t slash = entry.name.find_last_of('/');
                const std::string_view basename = slash == std::string::npos
                    ? std::string_view(entry.name)
                    : std::string_view(entry.name).substr(slash + 1);
                const bool matches = basename.size() == requested.size() && std::equal(
                    basename.begin(), basename.end(), requested.begin(),
                    [](unsigned char left, unsigned char right) {
                        return std::toupper(left) == std::toupper(right);
                    });
                if (!matches) {
                    continue;
                }
                const std::vector<std::uint8_t> description_bytes = ArchiveStore::read_entry(
                    bytes, entry.index, 64U * 1024U);
                EmbeddedDescription description;
                std::vector<std::string> lines;
                std::string line;
                const auto save_line = [&] {
                    while (!line.empty() && line.back() == ' ') {
                        line.pop_back();
                    }
                    lines.push_back(line.empty() ? " " : line);
                    line.clear();
                };
                for (std::size_t description_offset = 0;
                     description_offset < description_bytes.size() && lines.size() < 100;
                     ++description_offset) {
                    const std::uint8_t byte = description_bytes[description_offset];
                    if (byte == '\r' || byte == '\n') {
                        save_line();
                        if (byte == '\r' && description_offset + 1 < description_bytes.size() &&
                            description_bytes[description_offset + 1] == '\n') {
                            ++description_offset;
                        }
                    } else if (line.size() < 50) {
                        if (byte >= 0x20 && byte < 0x7f) {
                            line.push_back(static_cast<char>(byte));
                        } else if (byte >= 0x80) {
                            line.push_back('?');
                        }
                    }
                }
                if (lines.size() < 100 && !line.empty()) {
                    save_line();
                }
                if (!lines.empty()) {
                    description.summary = std::move(lines.front());
                    if (description.summary == " ") {
                        description.summary.clear();
                    }
                    for (std::size_t index = 1; index < lines.size(); ++index) {
                        if (index > 1) {
                            description.extended.push_back('\n');
                        }
                        description.extended += lines[index];
                    }
                    while (!description.extended.empty()) {
                        const std::size_t last_line = description.extended.find_last_of('\n');
                        const std::string_view tail = last_line == std::string::npos
                            ? std::string_view(description.extended)
                            : std::string_view(description.extended).substr(last_line + 1);
                        if (tail != " ") {
                            break;
                        }
                        if (last_line == std::string::npos) {
                            description.extended.clear();
                        } else {
                            description.extended.erase(last_line);
                        }
                    }
                    if (!description.summary.empty() || !description.extended.empty()) {
                        return description;
                    }
                }
                break;
            }
        }
    } catch (const std::exception&) {
        return std::nullopt;
    }
    return std::nullopt;
}

bool valid_account_handle(std::string_view handle) {
    if (handle.empty() || handle.size() > 32) {
        return false;
    }
    for (const unsigned char value : handle) {
        if (!std::isalnum(value) && value != '.' && value != '_' && value != '-') {
            return false;
        }
    }
    return true;
}

class FileDescriptor final {
public:
    explicit FileDescriptor(int value = -1) noexcept : value_(value) {}
    ~FileDescriptor() { reset(); }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept : value_(other.release()) {}
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }
    [[nodiscard]] int get() const noexcept { return value_; }
    [[nodiscard]] int release() noexcept {
        const int value = value_;
        value_ = -1;
        return value;
    }
    void reset(int value = -1) noexcept {
        if (value_ >= 0) {
            (void)::close(value_);
        }
        value_ = value;
    }
private:
    int value_{};
};

void copy_upload(int source, int destination, off_t size) {
    std::array<char, 64U * 1024U> buffer{};
    off_t offset = 0;
    while (offset < size) {
        const std::size_t requested = static_cast<std::size_t>(
            std::min<off_t>(static_cast<off_t>(buffer.size()), size - offset));
        const ssize_t read_count = ::pread(source, buffer.data(), requested, offset);
        if (read_count < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::system_error(errno, std::generic_category(), "reading upload for publication");
        }
        if (read_count == 0) {
            throw std::system_error(EIO, std::generic_category(), "upload changed during publication");
        }
        std::size_t written = 0;
        while (written < static_cast<std::size_t>(read_count)) {
            const ssize_t write_count = ::write(destination, buffer.data() + written,
                static_cast<std::size_t>(read_count) - written);
            if (write_count < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::system_error(errno, std::generic_category(), "writing published file");
            }
            if (write_count == 0) {
                throw std::system_error(EIO, std::generic_category(), "published file write made no progress");
            }
            written += static_cast<std::size_t>(write_count);
        }
        offset += read_count;
    }
}

void make_private_directory(const std::filesystem::path& path) {
    std::error_code error;
    std::filesystem::create_directories(path, error);
    if (error) {
        throw std::system_error(error, "creating file-area storage");
    }
    if (::chmod(path.c_str(), S_IRWXU) != 0) {
        throw std::system_error(errno, std::generic_category(), "restricting file-area storage permissions");
    }
}

std::string timestamp(std::filesystem::file_time_type file_time) {
    const auto system_time = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        file_time - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
    const std::time_t value = std::chrono::system_clock::to_time_t(system_time);
    std::tm broken_down{};
    if (::gmtime_r(&value, &broken_down) == nullptr) {
        return {};
    }
    std::array<char, 32> formatted{};
    if (std::strftime(formatted.data(), formatted.size(), "%Y-%m-%d %H:%M", &broken_down) == 0) {
        return {};
    }
    return formatted.data();
}

void synchronize_area(sqlite3* db, const std::filesystem::path& root, int area_id) {
    const std::filesystem::path area_path = root / "areas" / std::to_string(area_id);
    make_private_directory(area_path);

    std::set<std::string> visible_files;
    std::error_code iterator_error;
    for (std::filesystem::directory_iterator iterator(
             area_path, std::filesystem::directory_options::skip_permission_denied, iterator_error), end;
         iterator != end;
         iterator.increment(iterator_error)) {
        if (iterator_error) {
            iterator_error.clear();
            continue;
        }
        const std::filesystem::directory_entry entry = *iterator;
        std::error_code status_error;
        if (entry.is_symlink(status_error) || status_error || !entry.is_regular_file(status_error) || status_error) {
            continue;
        }
        const std::string filename = entry.path().filename().string();
        if (!valid_file_name(filename)) {
            continue;
        }
        const std::uintmax_t size = entry.file_size(status_error);
        if (status_error || size > static_cast<std::uintmax_t>(INT64_MAX)) {
            continue;
        }
        const std::string modified = timestamp(entry.last_write_time(status_error));
        if (status_error) {
            continue;
        }
        Statement insert(db,
            "INSERT INTO file_entries(area_id, filename, size, modified_at) VALUES(?1, ?2, ?3, ?4) "
            "ON CONFLICT(area_id, filename) DO UPDATE SET size = excluded.size, modified_at = excluded.modified_at");
        insert.bind_int(1, area_id);
        insert.bind_text(2, filename);
        insert.bind_int64(3, static_cast<sqlite3_int64>(size));
        insert.bind_text(4, modified);
        insert.check(sqlite3_step(insert.get()), "indexing file-area entry");
        visible_files.insert(filename);
    }

    Statement existing(db, "SELECT filename, request_only FROM file_entries WHERE area_id = ?1");
    existing.bind_int(1, area_id);
    std::vector<std::string> stale;
    for (;;) {
        const int result = sqlite3_step(existing.get());
        if (result == SQLITE_DONE) {
            break;
        }
        existing.check(result, "reading file-area index");
        const auto* filename = reinterpret_cast<const char*>(sqlite3_column_text(existing.get(), 0));
        if (filename != nullptr && !visible_files.contains(filename) &&
            sqlite3_column_int(existing.get(), 1) == 0) {
            stale.emplace_back(filename);
        }
    }
    for (const std::string& filename : stale) {
        Statement remove(db, "DELETE FROM file_entries WHERE area_id = ?1 AND filename = ?2");
        remove.bind_int(1, area_id);
        remove.bind_text(2, filename);
        remove.check(sqlite3_step(remove.get()), "removing stale file-area entry");
    }
}

} // namespace

FileStore::FileStore(std::string database_path, std::string root_path)
    : database_path_(std::move(database_path)), root_path_(std::move(root_path)) {}

void FileStore::initialize() const {
    const std::filesystem::path database_path(database_path_);
    if (database_path.has_parent_path()) {
        std::filesystem::create_directories(database_path.parent_path());
    }
    const std::filesystem::path root(root_path_);
    make_private_directory(root / "areas");
    make_private_directory(root / "incoming");

    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "CREATE TABLE IF NOT EXISTS file_areas ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "name TEXT NOT NULL UNIQUE COLLATE NOCASE,"
        "access_acs TEXT NOT NULL DEFAULT '',"
        "download_acs TEXT NOT NULL DEFAULT '',"
        "upload_acs TEXT NOT NULL DEFAULT '',"
        "no_ratio INTEGER NOT NULL DEFAULT 0 CHECK(no_ratio IN (0, 1)),"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")", "creating file-area table");
    check_exec(db.get(), "CREATE TABLE IF NOT EXISTS file_entries ("
        "area_id INTEGER NOT NULL REFERENCES file_areas(id) ON DELETE CASCADE,"
        "filename TEXT NOT NULL COLLATE NOCASE,"
        "size INTEGER NOT NULL CHECK(size >= 0),"
        "modified_at TEXT NOT NULL DEFAULT '',"
        "description TEXT NOT NULL DEFAULT '',"
        "extended_description TEXT NOT NULL DEFAULT '',"
        "download_count INTEGER NOT NULL DEFAULT 0 CHECK(download_count >= 0),"
        "file_points INTEGER NOT NULL DEFAULT 0 CHECK(file_points BETWEEN 0 AND 32767),"
        "uploader_credit_amount INTEGER NOT NULL DEFAULT 0 CHECK(uploader_credit_amount BETWEEN 0 AND 2147483647),"
        "PRIMARY KEY(area_id, filename)"
        ")", "creating file-entry table");
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file-area schema update");
    try {
        if (!file_column_exists(db.get(), "extended_description")) {
            check_exec(db.get(),
                "ALTER TABLE file_entries ADD COLUMN extended_description TEXT NOT NULL DEFAULT ''",
                "adding file extended descriptions");
        }
        if (!file_column_exists(db.get(), "owner_handle")) {
            check_exec(db.get(),
                "ALTER TABLE file_entries ADD COLUMN owner_handle TEXT NOT NULL DEFAULT ''",
                "adding file owners");
        }
        if (!file_column_exists(db.get(), "validated")) {
            check_exec(db.get(),
                "ALTER TABLE file_entries ADD COLUMN validated INTEGER NOT NULL DEFAULT 1 CHECK(validated IN (0, 1))",
                "adding file validation state");
        }
        if (!file_column_exists(db.get(), "request_only")) {
            check_exec(db.get(),
                "ALTER TABLE file_entries ADD COLUMN request_only INTEGER NOT NULL DEFAULT 0 CHECK(request_only IN (0, 1))",
                "adding request-only file state");
        }
        if (!file_column_exists(db.get(), "file_points")) {
            check_exec(db.get(),
                "ALTER TABLE file_entries ADD COLUMN file_points INTEGER NOT NULL DEFAULT 0 "
                "CHECK(file_points BETWEEN 0 AND 32767)",
                "adding per-file point cost");
        }
        if (!file_column_exists(db.get(), "uploader_credited")) {
            check_exec(db.get(),
                "ALTER TABLE file_entries ADD COLUMN uploader_credited INTEGER NOT NULL DEFAULT 0 "
                "CHECK(uploader_credited IN (0, 1))",
                "adding uploader point-credit state");
        }
        if (!file_column_exists(db.get(), "uploader_credit_amount")) {
            check_exec(db.get(),
                "ALTER TABLE file_entries ADD COLUMN uploader_credit_amount INTEGER NOT NULL DEFAULT 0 "
                "CHECK(uploader_credit_amount BETWEEN 0 AND 2147483647)",
                "adding credited uploader point amount");
        }
        check_exec(db.get(), "COMMIT", "saving file-area schema update");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    check_exec(db.get(), "CREATE TABLE IF NOT EXISTS file_user_activity ("
        "handle TEXT PRIMARY KEY COLLATE NOCASE,"
        "uploads INTEGER NOT NULL DEFAULT 0 CHECK(uploads >= 0),"
        "uploaded_bytes INTEGER NOT NULL DEFAULT 0 CHECK(uploaded_bytes >= 0),"
        "downloads INTEGER NOT NULL DEFAULT 0 CHECK(downloads >= 0),"
        "downloaded_bytes INTEGER NOT NULL DEFAULT 0 CHECK(downloaded_bytes >= 0),"
        "uploaded_kib INTEGER NOT NULL DEFAULT 0 CHECK(uploaded_kib >= 0),"
        "downloaded_kib INTEGER NOT NULL DEFAULT 0 CHECK(downloaded_kib >= 0),"
        "downloads_today INTEGER NOT NULL DEFAULT 0 CHECK(downloads_today >= 0),"
        "downloaded_kib_today INTEGER NOT NULL DEFAULT 0 CHECK(downloaded_kib_today >= 0),"
        "download_activity_day TEXT NOT NULL DEFAULT ''"
        ")", "creating per-account file activity table");
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting daily file-activity migration");
    try {
        if (!activity_column_exists(db.get(), "uploaded_kib")) {
            check_exec(db.get(),
                "ALTER TABLE file_user_activity ADD COLUMN uploaded_kib INTEGER NOT NULL DEFAULT 0 "
                "CHECK(uploaded_kib >= 0)", "adding cumulative uploaded KiB");
            check_exec(db.get(),
                "UPDATE file_user_activity SET uploaded_kib = uploaded_bytes / 1024",
                "initializing cumulative uploaded KiB");
        }
        if (!activity_column_exists(db.get(), "downloaded_kib")) {
            check_exec(db.get(),
                "ALTER TABLE file_user_activity ADD COLUMN downloaded_kib INTEGER NOT NULL DEFAULT 0 "
                "CHECK(downloaded_kib >= 0)", "adding cumulative downloaded KiB");
            check_exec(db.get(),
                "UPDATE file_user_activity SET downloaded_kib = downloaded_bytes / 1024",
                "initializing cumulative downloaded KiB");
        }
        if (!activity_column_exists(db.get(), "downloads_today")) {
            check_exec(db.get(),
                "ALTER TABLE file_user_activity ADD COLUMN downloads_today INTEGER NOT NULL DEFAULT 0 "
                "CHECK(downloads_today >= 0)", "adding daily download count");
        }
        if (!activity_column_exists(db.get(), "downloaded_kib_today")) {
            check_exec(db.get(),
                "ALTER TABLE file_user_activity ADD COLUMN downloaded_kib_today INTEGER NOT NULL DEFAULT 0 "
                "CHECK(downloaded_kib_today >= 0)", "adding daily downloaded KiB");
        }
        if (!activity_column_exists(db.get(), "download_activity_day")) {
            check_exec(db.get(),
                "ALTER TABLE file_user_activity ADD COLUMN download_activity_day TEXT NOT NULL DEFAULT ''",
                "adding daily download date");
        }
        check_exec(db.get(), "COMMIT", "saving daily file-activity migration");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    check_exec(db.get(), "CREATE TABLE IF NOT EXISTS file_download_queue ("
        "queue_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "handle TEXT NOT NULL COLLATE NOCASE,"
        "area_id INTEGER NOT NULL REFERENCES file_areas(id) ON DELETE CASCADE,"
        "filename TEXT NOT NULL COLLATE NOCASE,"
        "queued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(handle, area_id, filename)"
        ")", "creating per-account download queue");
    check_exec(db.get(), "CREATE TABLE IF NOT EXISTS file_point_reservations ("
        "reservation_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "handle TEXT NOT NULL COLLATE NOCASE,"
        "points INTEGER NOT NULL CHECK(points > 0),"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")", "creating file-point download reservations");
    check_exec(db.get(), "CREATE TABLE IF NOT EXISTS file_daily_download_limits ("
        "security_level INTEGER PRIMARY KEY CHECK(security_level BETWEEN 0 AND 255),"
        "max_files INTEGER NOT NULL CHECK(max_files BETWEEN 0 AND 2147483647),"
        "max_kib INTEGER NOT NULL CHECK(max_kib BETWEEN 0 AND 2147483647)"
        ")", "creating per-security-level daily download limits");
    check_exec(db.get(), "CREATE TABLE IF NOT EXISTS file_download_level_ratios ("
        "security_level INTEGER PRIMARY KEY CHECK(security_level BETWEEN 0 AND 255),"
        "max_downloads_per_upload INTEGER NOT NULL CHECK(max_downloads_per_upload BETWEEN 0 AND 2147483647),"
        "max_kib_per_uploaded_kib INTEGER NOT NULL CHECK(max_kib_per_uploaded_kib BETWEEN 0 AND 2147483647)"
        ")", "creating per-security-level download ratios");
    check_exec(db.get(), "CREATE TABLE IF NOT EXISTS file_daily_download_reservations ("
        "reservation_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "handle TEXT NOT NULL COLLATE NOCASE,"
        "file_kib INTEGER NOT NULL CHECK(file_kib >= 0),"
        "reserved_day TEXT NOT NULL"
        ")", "creating active daily download reservations");
    check_exec(db.get(), "CREATE TABLE IF NOT EXISTS file_area_scan_exclusions ("
        "handle TEXT NOT NULL COLLATE NOCASE,"
        "area_id INTEGER NOT NULL REFERENCES file_areas(id) ON DELETE CASCADE,"
        "PRIMARY KEY(handle, area_id)"
        ")", "creating per-account new-file scan preferences");
    check_exec(db.get(), "CREATE TABLE IF NOT EXISTS file_user_scan_dates ("
        "handle TEXT PRIMARY KEY COLLATE NOCASE REFERENCES accounts(handle) ON DELETE CASCADE,"
        "since_date TEXT NOT NULL"
        ")", "creating per-account new-file scan dates");
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file-area access schema update");
    try {
        if (!area_column_exists(db.get(), "access_acs")) {
            check_exec(db.get(),
                "ALTER TABLE file_areas ADD COLUMN access_acs TEXT NOT NULL DEFAULT ''",
                "adding file-area access ACS");
        }
        if (!area_column_exists(db.get(), "download_acs")) {
            check_exec(db.get(),
                "ALTER TABLE file_areas ADD COLUMN download_acs TEXT NOT NULL DEFAULT ''",
                "adding file-area download ACS");
        }
        if (!area_column_exists(db.get(), "upload_acs")) {
            check_exec(db.get(),
                "ALTER TABLE file_areas ADD COLUMN upload_acs TEXT NOT NULL DEFAULT ''",
                "adding file-area upload ACS");
        }
        if (!area_column_exists(db.get(), "no_ratio")) {
            check_exec(db.get(),
                "ALTER TABLE file_areas ADD COLUMN no_ratio INTEGER NOT NULL DEFAULT 0 CHECK(no_ratio IN (0, 1))",
                "adding the file-area ratio exemption");
        }
        check_exec(db.get(), "COMMIT", "saving file-area access schema");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    check_exec(db.get(), "CREATE TABLE IF NOT EXISTS file_store_meta ("
        "key TEXT PRIMARY KEY,"
        "value TEXT NOT NULL"
        ")", "creating file-store metadata table");

    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file-area initialization");
    try {
        Statement default_see_unvalidated(db.get(),
            "INSERT OR IGNORE INTO file_store_meta(key, value) VALUES('see_unvalidated_acs', 'S255')");
        default_see_unvalidated.check(sqlite3_step(default_see_unvalidated.get()),
            "setting default unvalidated-file visibility ACS");
        Statement default_download_unvalidated(db.get(),
            "INSERT OR IGNORE INTO file_store_meta(key, value) VALUES('download_unvalidated_acs', 'S255')");
        default_download_unvalidated.check(sqlite3_step(default_download_unvalidated.get()),
            "setting default unvalidated-file download ACS");
        Statement default_count_ratio(db.get(),
            "INSERT OR IGNORE INTO file_store_meta(key, value) VALUES('download_count_ratio', '0')");
        default_count_ratio.check(sqlite3_step(default_count_ratio.get()),
            "setting default file-count ratio");
        Statement default_kib_ratio(db.get(),
            "INSERT OR IGNORE INTO file_store_meta(key, value) VALUES('download_kib_ratio', '0')");
        default_kib_ratio.check(sqlite3_step(default_kib_ratio.get()),
            "setting default file-size ratio");
        Statement default_ratio_state(db.get(),
            "INSERT OR IGNORE INTO file_store_meta(key, value) "
            "SELECT 'download_ratios_enabled', CASE WHEN "
            "CAST((SELECT value FROM file_store_meta WHERE key = 'download_count_ratio') AS INTEGER) > 0 OR "
            "CAST((SELECT value FROM file_store_meta WHERE key = 'download_kib_ratio') AS INTEGER) > 0 "
            "THEN '1' ELSE '0' END");
        default_ratio_state.check(sqlite3_step(default_ratio_state.get()),
            "setting default file-ratio state");
        Statement default_no_ratio_acs(db.get(),
            "INSERT OR IGNORE INTO file_store_meta(key, value) VALUES('no_download_ratio_acs', 'S255')");
        default_no_ratio_acs.check(sqlite3_step(default_no_ratio_acs.get()),
            "setting default ratio exemption ACS");
        Statement default_upload_validation_acs(db.get(),
            "INSERT OR IGNORE INTO file_store_meta(key, value) VALUES('upload_auto_validate_acs', 'S255')");
        default_upload_validation_acs.check(sqlite3_step(default_upload_validation_acs.get()),
            "setting default upload auto-validation ACS");
        Statement default_validate_all_files(db.get(),
            "INSERT OR IGNORE INTO file_store_meta(key, value) VALUES('validate_all_files', '0')");
        default_validate_all_files.check(sqlite3_step(default_validate_all_files.get()),
            "setting default validate-all-files policy");
        const auto default_point_setting = [&db](std::string_view key, std::string_view value) {
            Statement setting(db.get(),
                "INSERT OR IGNORE INTO file_store_meta(key, value) VALUES(?1, ?2)");
            setting.bind_text(1, key);
            setting.bind_text(2, value);
            setting.check(sqlite3_step(setting.get()), "setting default file-point policy");
        };
        default_point_setting("file_points_enabled", "0");
        default_point_setting("file_points_base_size_kib", "0");
        default_point_setting("file_points_upload_compensation", "1");
        default_point_setting("file_points_reward_ratio", "0");
        default_point_setting("no_file_credits_acs", "%");
        default_point_setting("daily_file_limits_enabled", "0");
        bool initial_areas_seeded = false;
        {
            Statement marker(db.get(), "SELECT 1 FROM file_store_meta WHERE key = 'initial_areas_seeded'");
            const int result = sqlite3_step(marker.get());
            marker.check(result, "checking initial file-area setup");
            initial_areas_seeded = result == SQLITE_ROW;
        }
        if (!initial_areas_seeded) {
            bool has_areas = false;
            {
                Statement count(db.get(), "SELECT 1 FROM file_areas LIMIT 1");
                const int result = sqlite3_step(count.get());
                count.check(result, "checking file-area table");
                has_areas = result == SQLITE_ROW;
            }
            if (!has_areas) {
                Statement insert(db.get(), "INSERT INTO file_areas(name) VALUES('General')");
                insert.check(sqlite3_step(insert.get()), "creating default file area");
            }
            Statement marker(db.get(),
                "INSERT INTO file_store_meta(key, value) VALUES('initial_areas_seeded', '1')");
            marker.check(sqlite3_step(marker.get()), "saving initial file-area setup");
        }
        check_exec(db.get(), "COMMIT", "saving file-area initialization");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::create_area(std::string_view name) const {
    if (!valid_area_name(name)) {
        throw std::invalid_argument("file area name must be 1-48 printable characters without surrounding spaces");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement insert(db.get(), "INSERT INTO file_areas(name) VALUES(?1)");
    insert.bind_text(1, name);
    insert.check(sqlite3_step(insert.get()), "creating file area");
    const int area_id = static_cast<int>(sqlite3_last_insert_rowid(db.get()));
    make_private_directory(std::filesystem::path(root_path_) / "areas" / std::to_string(area_id));
}

void FileStore::rename_area(int area_id, std::string_view name) const {
    if (area_id < 1 || !valid_area_name(name)) {
        throw std::invalid_argument("file area ID and name are invalid");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement update(db.get(), "UPDATE file_areas SET name = ?1 WHERE id = ?2");
    update.bind_text(1, name);
    update.bind_int(2, area_id);
    update.check(sqlite3_step(update.get()), "renaming file area");
    if (sqlite3_changes(db.get()) == 0) {
        throw std::invalid_argument("file area does not exist");
    }
}

void FileStore::set_area_access(
    int area_id,
    std::string_view access_acs,
    std::string_view download_acs,
    std::string_view upload_acs) const {
    if (area_id < 1 || !valid_legacy_acs(access_acs) || !valid_legacy_acs(download_acs) ||
        !valid_legacy_acs(upload_acs)) {
        throw std::invalid_argument(
            "file-area ACS, DLACS, and ULACS must use supported Renegade syntax and be at most 20 characters");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement update(db.get(),
        "UPDATE file_areas SET access_acs = ?1, download_acs = ?2, upload_acs = ?3 WHERE id = ?4");
    update.bind_text(1, access_acs);
    update.bind_text(2, download_acs);
    update.bind_text(3, upload_acs);
    update.bind_int(4, area_id);
    update.check(sqlite3_step(update.get()), "updating file-area access rules");
    if (sqlite3_changes(db.get()) == 0) {
        Statement exists(db.get(), "SELECT 1 FROM file_areas WHERE id = ?1");
        exists.bind_int(1, area_id);
        const int result = sqlite3_step(exists.get());
        exists.check(result, "checking file area for access update");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("file area does not exist");
        }
    }
}

void FileStore::set_unvalidated_access(
    std::string_view see_acs,
    std::string_view download_acs) const {
    if (!valid_legacy_acs(see_acs) || !valid_legacy_acs(download_acs)) {
        throw std::invalid_argument(
            "SeeUnVal and DLUnVal must use supported Renegade syntax and be at most 20 characters");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting unvalidated-file ACS update");
    try {
        Statement see(db.get(),
            "INSERT INTO file_store_meta(key, value) VALUES('see_unvalidated_acs', ?1) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
        see.bind_text(1, see_acs);
        see.check(sqlite3_step(see.get()), "saving SeeUnVal ACS");
        Statement download(db.get(),
            "INSERT INTO file_store_meta(key, value) VALUES('download_unvalidated_acs', ?1) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
        download.bind_text(1, download_acs);
        download.check(sqlite3_step(download.get()), "saving DLUnVal ACS");
        check_exec(db.get(), "COMMIT", "saving unvalidated-file ACS rules");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::set_upload_validation_rules(
    std::string_view auto_validate_acs,
    bool validate_all_files) const {
    if (!valid_legacy_acs(auto_validate_acs)) {
        throw std::invalid_argument("upload auto-validation ACS must use supported Renegade syntax");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting upload validation policy update");
    try {
        Statement acs(db.get(),
            "INSERT INTO file_store_meta(key, value) VALUES('upload_auto_validate_acs', ?1) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
        acs.bind_text(1, auto_validate_acs);
        acs.check(sqlite3_step(acs.get()), "saving upload auto-validation ACS");
        Statement all(db.get(),
            "INSERT INTO file_store_meta(key, value) VALUES('validate_all_files', ?1) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
        all.bind_text(1, validate_all_files ? "1" : "0");
        all.check(sqlite3_step(all.get()), "saving validate-all-files policy");
        check_exec(db.get(), "COMMIT", "saving upload validation policy");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::set_area_no_ratio(int area_id, bool no_ratio) const {
    if (area_id < 1) {
        throw std::invalid_argument("file-area ID must be positive");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement update(db.get(), "UPDATE file_areas SET no_ratio = ?1 WHERE id = ?2");
    update.bind_int(1, no_ratio ? 1 : 0);
    update.bind_int(2, area_id);
    update.check(sqlite3_step(update.get()), "updating file-area ratio exemption");
    if (sqlite3_changes(db.get()) == 0) {
        throw std::invalid_argument("file area does not exist");
    }
}

void FileStore::set_download_ratios(
    std::uint64_t download_count_ratio,
    std::uint64_t download_kib_ratio,
    std::string_view no_ratio_acs) const {
    set_download_ratios(true, download_count_ratio, download_kib_ratio, no_ratio_acs);
}

void FileStore::set_download_ratios(
    bool enabled,
    std::uint64_t download_count_ratio,
    std::uint64_t download_kib_ratio,
    std::string_view no_ratio_acs) const {
    constexpr std::uint64_t maximum_ratio = 2147483647U;
    if (download_count_ratio > maximum_ratio || download_kib_ratio > maximum_ratio ||
        !valid_legacy_acs(no_ratio_acs)) {
        throw std::invalid_argument(
            "file ratios must be 0-2147483647 and the no-ratio ACS must use supported syntax");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file-ratio configuration update");
    try {
        const auto save = [&db](std::string_view key, std::string_view value) {
            Statement update(db.get(),
                "INSERT INTO file_store_meta(key, value) VALUES(?1, ?2) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
            update.bind_text(1, key);
            update.bind_text(2, value);
            update.check(sqlite3_step(update.get()), "saving file-ratio configuration");
        };
        const std::string count_text = std::to_string(download_count_ratio);
        const std::string kib_text = std::to_string(download_kib_ratio);
        save("download_count_ratio", count_text);
        save("download_kib_ratio", kib_text);
        save("no_download_ratio_acs", no_ratio_acs);
        save("download_ratios_enabled", enabled ? "1" : "0");
        check_exec(db.get(), "COMMIT", "saving file-ratio configuration");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::set_download_level_ratios(
    int security_level_min,
    int security_level_max,
    std::uint64_t download_count_ratio,
    std::uint64_t download_kib_ratio) const {
    constexpr std::uint64_t maximum = 2147483647U;
    if (security_level_min < 0 || security_level_max > 255 ||
        security_level_min > security_level_max || download_count_ratio > maximum ||
        download_kib_ratio > maximum) {
        throw std::invalid_argument(
            "ratio rules require a security range from 0 to 255 and limits from 0 to 2147483647");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting per-level download-ratio update");
    try {
        for (int level = security_level_min; level <= security_level_max; ++level) {
            Statement rule(db.get(),
                "INSERT INTO file_download_level_ratios(security_level, max_downloads_per_upload, "
                "max_kib_per_uploaded_kib) VALUES(?1, ?2, ?3) ON CONFLICT(security_level) DO UPDATE SET "
                "max_downloads_per_upload = excluded.max_downloads_per_upload, "
                "max_kib_per_uploaded_kib = excluded.max_kib_per_uploaded_kib");
            rule.bind_int(1, level);
            rule.bind_int64(2, static_cast<sqlite3_int64>(download_count_ratio));
            rule.bind_int64(3, static_cast<sqlite3_int64>(download_kib_ratio));
            rule.check(sqlite3_step(rule.get()), "saving per-level download ratios");
        }
        check_exec(db.get(), "COMMIT", "saving per-level download ratios");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::clear_download_level_ratios(int security_level_min, int security_level_max) const {
    if (security_level_min < 0 || security_level_max > 255 || security_level_min > security_level_max) {
        throw std::invalid_argument("ratio override range must be between security levels 0 and 255");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting per-level ratio reset");
    try {
        Statement clear(db.get(),
            "DELETE FROM file_download_level_ratios WHERE security_level BETWEEN ?1 AND ?2");
        clear.bind_int(1, security_level_min);
        clear.bind_int(2, security_level_max);
        clear.check(sqlite3_step(clear.get()), "clearing per-level download-ratio overrides");
        check_exec(db.get(), "COMMIT", "saving per-level ratio reset");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::set_download_daily_limits(
    bool enabled,
    int security_level_min,
    int security_level_max,
    std::uint64_t max_files,
    std::uint64_t max_kib) const {
    constexpr std::uint64_t maximum = 2147483647U;
    if (security_level_min < 0 || security_level_max > 255 ||
        security_level_min > security_level_max || max_files > maximum || max_kib > maximum) {
        throw std::invalid_argument(
            "daily limits require a security range from 0 to 255 and file/KiB caps from 0 to 2147483647");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting daily download-limit update");
    try {
        Statement state(db.get(),
            "INSERT INTO file_store_meta(key, value) VALUES('daily_file_limits_enabled', ?1) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
        state.bind_text(1, enabled ? "1" : "0");
        state.check(sqlite3_step(state.get()), "saving daily download-limit state");
        for (int level = security_level_min; level <= security_level_max; ++level) {
            Statement rule(db.get(),
                "INSERT INTO file_daily_download_limits(security_level, max_files, max_kib) "
                "VALUES(?1, ?2, ?3) ON CONFLICT(security_level) DO UPDATE SET "
                "max_files = excluded.max_files, max_kib = excluded.max_kib");
            rule.bind_int(1, level);
            rule.bind_int64(2, static_cast<sqlite3_int64>(max_files));
            rule.bind_int64(3, static_cast<sqlite3_int64>(max_kib));
            rule.check(sqlite3_step(rule.get()), "saving per-level daily download limits");
        }
        check_exec(db.get(), "COMMIT", "saving daily download limits");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::set_file_point_rules(
    bool enabled,
    std::uint32_t base_size_kib,
    std::uint32_t upload_compensation,
    std::uint32_t reward_ratio,
    std::string_view no_file_credits_acs) const {
    constexpr std::uint32_t maximum = 32767;
    if (base_size_kib > maximum || upload_compensation > maximum || reward_ratio > maximum ||
        !valid_legacy_acs(no_file_credits_acs)) {
        throw std::invalid_argument(
            "file-point values must be 0-32767 and NoFileCredits ACS must use supported syntax");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file-point policy update");
    try {
        const auto save = [&db](std::string_view key, std::string_view value) {
            Statement update(db.get(),
                "INSERT INTO file_store_meta(key, value) VALUES(?1, ?2) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
            update.bind_text(1, key);
            update.bind_text(2, value);
            update.check(sqlite3_step(update.get()), "saving file-point policy");
        };
        save("file_points_enabled", enabled ? "1" : "0");
        save("file_points_base_size_kib", std::to_string(base_size_kib));
        save("file_points_upload_compensation", std::to_string(upload_compensation));
        save("file_points_reward_ratio", std::to_string(reward_ratio));
        save("no_file_credits_acs", no_file_credits_acs);
        check_exec(db.get(), "COMMIT", "saving file-point policy");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

RemovedFileArea FileStore::remove_area(int area_id, bool delete_storage) const {
    if (area_id < 1) {
        throw std::invalid_argument("file area ID must be a positive number");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    const std::filesystem::path areas_path = std::filesystem::path(root_path_) / "areas";
    std::filesystem::path area_path = areas_path / std::to_string(area_id);
    std::filesystem::path trash_path;

    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file-area deletion");
    bool moved_to_trash = false;
    std::string area_name;
    try {
        {
            Statement query(db.get(), "SELECT name FROM file_areas WHERE id = ?1");
            query.bind_int(1, area_id);
            const int result = sqlite3_step(query.get());
            query.check(result, "looking up file area for deletion");
            if (result == SQLITE_DONE) {
                throw std::invalid_argument("file area does not exist");
            }
            const auto* name = reinterpret_cast<const char*>(sqlite3_column_text(query.get(), 0));
            if (name == nullptr) {
                throw std::runtime_error("file area has no name");
            }
            area_name = name;
        }

        if (delete_storage) {
            std::error_code parent_error;
            const std::filesystem::file_status parent_status =
                std::filesystem::symlink_status(areas_path, parent_error);
            if (parent_error) {
                throw std::system_error(parent_error, "checking file-area storage root");
            }
            if (std::filesystem::is_symlink(parent_status) || !std::filesystem::is_directory(parent_status)) {
                throw std::runtime_error("file-area storage root must be a real directory");
            }

            std::error_code area_error;
            const std::filesystem::file_status area_status =
                std::filesystem::symlink_status(area_path, area_error);
            if (area_error && area_error != std::errc::no_such_file_or_directory) {
                throw std::system_error(area_error, "checking file-area storage");
            }
            const bool has_storage = !area_error && area_status.type() != std::filesystem::file_type::not_found;
            if (has_storage) {
                const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
                for (unsigned int attempt = 0; attempt < 100; ++attempt) {
                    trash_path = areas_path / (".removed-area-" + std::to_string(area_id) + "-" +
                        std::to_string(nonce) + "-" + std::to_string(attempt));
                    std::error_code candidate_error;
                    const auto candidate_status = std::filesystem::symlink_status(trash_path, candidate_error);
                    if (candidate_error == std::errc::no_such_file_or_directory ||
                        (!candidate_error && candidate_status.type() == std::filesystem::file_type::not_found)) {
                        break;
                    }
                    trash_path.clear();
                }
                if (trash_path.empty()) {
                    throw std::runtime_error("could not choose a temporary path for file-area deletion");
                }
                std::error_code rename_error;
                std::filesystem::rename(area_path, trash_path, rename_error);
                if (rename_error) {
                    throw std::system_error(rename_error, "staging file-area storage for deletion");
                }
                moved_to_trash = true;
            }
        }

        {
            Statement remove(db.get(), "DELETE FROM file_areas WHERE id = ?1");
            remove.bind_int(1, area_id);
            remove.check(sqlite3_step(remove.get()), "deleting file-area listing");
            if (sqlite3_changes(db.get()) == 0) {
                throw std::invalid_argument("file area does not exist");
            }
        }
        check_exec(db.get(), "COMMIT", "saving file-area deletion");
    } catch (...) {
        const std::exception_ptr failure = std::current_exception();
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        if (moved_to_trash) {
            std::error_code restore_error;
            std::filesystem::rename(trash_path, area_path, restore_error);
            if (restore_error) {
                throw std::runtime_error("file-area deletion failed and storage could not be restored; "
                    "recover it from " + trash_path.string() + ": " + restore_error.message());
            }
        }
        std::rethrow_exception(failure);
    }

    if (!delete_storage) {
        return {area_name, area_path.string(), false};
    }
    if (!moved_to_trash) {
        return {area_name, {}, false};
    }
    std::error_code remove_error;
    std::filesystem::remove_all(trash_path, remove_error);
    if (remove_error) {
        return {area_name, trash_path.string(), true};
    }
    return {area_name, {}, false};
}

std::vector<FileAreaSummary> FileStore::areas(std::string_view viewer) const {
    if (!viewer.empty() && !valid_account_handle(viewer)) {
        throw std::invalid_argument("invalid account handle for file-area listing");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels levels = viewer.empty() ? AccessLevels{} : account_access_levels(db.get(), viewer);
    const std::string see_unvalidated_acs = file_store_setting(db.get(), "see_unvalidated_acs", "S255");
    Statement ids(db.get(), "SELECT id FROM file_areas ORDER BY id");
    std::vector<int> area_ids;
    for (;;) {
        const int result = sqlite3_step(ids.get());
        if (result == SQLITE_DONE) {
            break;
        }
        ids.check(result, "reading file areas");
        area_ids.push_back(sqlite3_column_int(ids.get(), 0));
    }
    for (const int area_id : area_ids) {
        synchronize_area(db.get(), root_path_, area_id);
    }

    Statement query(db.get(),
        "SELECT a.id, a.name, "
        "COUNT(f.filename), COALESCE(SUM(f.size), 0), "
        "COUNT(CASE WHEN (f.validated = 1 OR f.owner_handle = ?1 COLLATE NOCASE) "
        "THEN f.filename END), "
        "COALESCE(SUM(CASE WHEN (f.validated = 1 OR f.owner_handle = ?1 COLLATE NOCASE) "
        "THEN f.size ELSE 0 END), 0), "
        "CASE WHEN ?1 = '' OR e.area_id IS NULL THEN 1 ELSE 0 END, "
        "a.access_acs, a.download_acs, a.upload_acs, a.no_ratio "
        "FROM file_areas a LEFT JOIN file_entries f ON f.area_id = a.id "
        "LEFT JOIN file_area_scan_exclusions e ON e.area_id = a.id AND e.handle = ?1 COLLATE NOCASE "
        "GROUP BY a.id, a.name ORDER BY a.id");
    query.bind_text(1, viewer);
    std::vector<FileAreaSummary> result;
    for (;;) {
        const int step = sqlite3_step(query.get());
        if (step == SQLITE_DONE) {
            break;
        }
        query.check(step, "listing file areas");
        const auto* name = reinterpret_cast<const char*>(sqlite3_column_text(query.get(), 1));
        if (name == nullptr) {
            continue;
        }
        const auto text_column = [&query](int column) {
            const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(query.get(), column));
            return value == nullptr ? std::string{} : std::string(value);
        };
        const std::string access_acs = text_column(7);
        const std::string download_acs = text_column(8);
        const std::string upload_acs = text_column(9);
        AccessLevels area_levels = levels;
        area_levels.file_area_number = sqlite3_column_int64(query.get(), 0);
        if (!viewer.empty() && !evaluate_legacy_acs(access_acs, area_levels)) {
            continue;
        }
        const bool see_unvalidated = viewer.empty() || evaluate_legacy_acs(
            see_unvalidated_acs, area_levels);
        const int file_count_column = see_unvalidated ? 2 : 4;
        const int file_bytes_column = see_unvalidated ? 3 : 5;
        result.push_back({sqlite3_column_int(query.get(), 0), name,
            static_cast<std::uint64_t>(sqlite3_column_int64(query.get(), file_count_column)),
            static_cast<std::uint64_t>(sqlite3_column_int64(query.get(), file_bytes_column)),
            sqlite3_column_int(query.get(), 6) != 0, access_acs, download_acs, upload_acs,
            sqlite3_column_int(query.get(), 10) != 0});
    }
    return result;
}

bool FileStore::toggle_new_file_scan(std::string_view handle, int area_id) const {
    if (!valid_account_handle(handle) || area_id < 1) {
        throw std::invalid_argument("invalid account or file-area ID for new-file scan preference");
    }
    const auto visible_areas = areas(handle);
    if (std::none_of(visible_areas.begin(), visible_areas.end(), [area_id](const FileAreaSummary& area) {
            return area.id == area_id;
        })) {
        throw std::invalid_argument("file area is not available to this account");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting new-file scan preference update");
    try {
        {
            Statement exists(db.get(), "SELECT 1 FROM file_areas WHERE id = ?1");
            exists.bind_int(1, area_id);
            const int result = sqlite3_step(exists.get());
            exists.check(result, "checking file area for scan preference");
            if (result == SQLITE_DONE) {
                throw std::invalid_argument("file area does not exist");
            }
        }
        Statement remove(db.get(),
            "DELETE FROM file_area_scan_exclusions WHERE handle = ?1 COLLATE NOCASE AND area_id = ?2");
        remove.bind_text(1, handle);
        remove.bind_int(2, area_id);
        remove.check(sqlite3_step(remove.get()), "enabling file area in new-file scan");
        const bool enabled = sqlite3_changes(db.get()) != 0;
        if (!enabled) {
            Statement insert(db.get(),
                "INSERT INTO file_area_scan_exclusions(handle, area_id) VALUES(?1, ?2)");
            insert.bind_text(1, handle);
            insert.bind_int(2, area_id);
            insert.check(sqlite3_step(insert.get()), "disabling file area in new-file scan");
        }
        check_exec(db.get(), "COMMIT", "finishing new-file scan preference update");
        return !enabled;
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::set_new_file_scan_all(std::string_view handle, bool enabled) const {
    if (!valid_account_handle(handle)) {
        throw std::invalid_argument("invalid account handle for new-file scan preferences");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting all-area scan preference update");
    try {
        Statement clear(db.get(),
            "DELETE FROM file_area_scan_exclusions WHERE handle = ?1 COLLATE NOCASE");
        clear.bind_text(1, handle);
        clear.check(sqlite3_step(clear.get()), "resetting new-file scan preferences");
        if (!enabled) {
            Statement disable(db.get(),
                "INSERT INTO file_area_scan_exclusions(handle, area_id) "
                "SELECT ?1, id FROM file_areas");
            disable.bind_text(1, handle);
            disable.check(sqlite3_step(disable.get()), "disabling all file areas in new-file scan");
        }
        check_exec(db.get(), "COMMIT", "finishing all-area scan preference update");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

NewFilePage FileStore::new_files_since(
    std::string_view handle,
    std::string_view since,
    std::size_t page,
    std::size_t page_size) const {
    if (!valid_account_handle(handle)) {
        throw std::invalid_argument("invalid account handle for new-file scan");
    }
    if (page_size < 1 || page_size > 100) {
        throw std::invalid_argument("new-file scan page size must be between 1 and 100");
    }
    const auto visible_areas = areas(handle);
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    const AccessLevels account_levels = account_access_levels(db.get(), handle);
    const std::string see_unvalidated_acs = file_store_setting(db.get(), "see_unvalidated_acs", "S255");
    std::vector<int> see_unvalidated_area_ids;
    for (const FileAreaSummary& area : visible_areas) {
        AccessLevels area_levels = account_levels;
        area_levels.file_area_number = area.id;
        if (evaluate_legacy_acs(see_unvalidated_acs, area_levels)) {
            see_unvalidated_area_ids.push_back(area.id);
        }
    }
    std::string effective_since(since);
    Statement configured_date(db.get(),
        "SELECT since_date FROM file_user_scan_dates WHERE handle = ?1 COLLATE NOCASE");
    configured_date.bind_text(1, handle);
    const int date_result = sqlite3_step(configured_date.get());
    configured_date.check(date_result, "reading per-account new-file scan date");
    if (date_result == SQLITE_ROW) {
        const auto* configured = reinterpret_cast<const char*>(sqlite3_column_text(configured_date.get(), 0));
        if (configured != nullptr) {
            effective_since = configured;
        }
    }
    if (visible_areas.empty()) {
        NewFilePage empty;
        empty.page = 0;
        empty.page_count = 1;
        empty.since_date = effective_since;
        return empty;
    }
    std::string area_filter = " AND f.area_id IN (";
    for (std::size_t index = 0; index < visible_areas.size(); ++index) {
        if (index != 0) {
            area_filter.push_back(',');
        }
        area_filter += std::to_string(visible_areas[index].id);
    }
    area_filter.push_back(')');
    std::string pending_visibility =
        "(f.validated = 1 OR f.owner_handle = ?1 COLLATE NOCASE";
    if (!see_unvalidated_area_ids.empty()) {
        pending_visibility += " OR f.area_id IN (";
        for (std::size_t index = 0; index < see_unvalidated_area_ids.size(); ++index) {
            if (index != 0) {
                pending_visibility.push_back(',');
            }
            pending_visibility += std::to_string(see_unvalidated_area_ids[index]);
        }
        pending_visibility.push_back(')');
    }
    pending_visibility.push_back(')');
    const std::string count_sql =
        "SELECT COUNT(*) FROM file_entries f "
        "JOIN file_areas a ON a.id = f.area_id "
        "LEFT JOIN file_area_scan_exclusions e ON e.area_id = a.id AND e.handle = ?1 COLLATE NOCASE "
        "WHERE e.area_id IS NULL AND substr(f.modified_at, 1, 10) >= substr(?2, 1, 10) "
        "AND " + pending_visibility + area_filter;
    Statement count(db.get(), count_sql.c_str());
    count.bind_text(1, handle);
    count.bind_text(2, effective_since);
    count.check(sqlite3_step(count.get()), "counting new files");
    const sqlite3_int64 total_value = std::max<sqlite3_int64>(0, sqlite3_column_int64(count.get(), 0));
    const auto total = static_cast<std::uint64_t>(total_value);
    const std::size_t page_count = total == 0 ? 1 : static_cast<std::size_t>(
        1 + (total - 1) / page_size);
    page = std::min(page, page_count - 1);
    const std::size_t offset = page * page_size;
    const std::string query_sql =
        "SELECT a.id, a.name, f.filename, f.description, f.extended_description, f.owner_handle, "
        "f.size, f.modified_at, f.download_count, f.file_points, f.validated, f.request_only "
        "FROM file_entries f "
        "JOIN file_areas a ON a.id = f.area_id "
        "LEFT JOIN file_area_scan_exclusions e ON e.area_id = a.id AND e.handle = ?1 COLLATE NOCASE "
        "WHERE e.area_id IS NULL AND substr(f.modified_at, 1, 10) >= substr(?2, 1, 10) "
        "AND " + pending_visibility + " " + area_filter +
        " ORDER BY f.modified_at DESC, a.id, f.filename COLLATE NOCASE LIMIT ?3 OFFSET ?4";
    Statement query(db.get(), query_sql.c_str());
    query.bind_text(1, handle);
    query.bind_text(2, effective_since);
    query.bind_int64(3, static_cast<sqlite3_int64>(page_size));
    query.bind_int64(4, static_cast<sqlite3_int64>(offset));
    NewFilePage result;
    result.page = page;
    result.page_count = page_count;
    result.total = total;
    result.since_date = effective_since;
    for (;;) {
        const int step = sqlite3_step(query.get());
        if (step == SQLITE_DONE) {
            break;
        }
        query.check(step, "listing new files");
        const auto column = [&query](int index) {
            const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(query.get(), index));
            return value == nullptr ? std::string{} : std::string(value);
        };
        result.files.push_back({sqlite3_column_int(query.get(), 0), column(1),
            {column(2), column(3), column(4), column(5),
                static_cast<std::uint64_t>(std::max<sqlite3_int64>(0,
                    sqlite3_column_int64(query.get(), 6))),
                column(7),
                static_cast<std::uint64_t>(std::max<sqlite3_int64>(0,
                    sqlite3_column_int64(query.get(), 8))),
                static_cast<std::uint64_t>(std::max<sqlite3_int64>(0,
                    sqlite3_column_int64(query.get(), 9))),
                sqlite3_column_int(query.get(), 10) != 0,
                sqlite3_column_int(query.get(), 11) != 0}});
    }
    return result;
}

FileValidationPage FileStore::unvalidated_files(
    std::string_view sysop,
    std::size_t page,
    std::size_t page_size) const {
    if (!valid_account_handle(sysop) || page_size < 1 || page_size > 100) {
        throw std::invalid_argument("invalid SysOp or page size for file validation queue");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement moderator(db.get(), "SELECT is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
    moderator.bind_text(1, sysop);
    const int moderator_result = sqlite3_step(moderator.get());
    moderator.check(moderator_result, "checking file validation queue access");
    if (moderator_result != SQLITE_ROW || sqlite3_column_int(moderator.get(), 0) == 0) {
        throw std::invalid_argument("only a SysOp can open the file validation queue");
    }
    std::vector<int> area_ids;
    Statement areas_query(db.get(), "SELECT id FROM file_areas ORDER BY id");
    for (;;) {
        const int step = sqlite3_step(areas_query.get());
        if (step == SQLITE_DONE) {
            break;
        }
        areas_query.check(step, "reading file areas for validation queue");
        area_ids.push_back(sqlite3_column_int(areas_query.get(), 0));
    }
    for (const int area_id : area_ids) {
        synchronize_area(db.get(), root_path_, area_id);
    }
    Statement count(db.get(), "SELECT COUNT(*) FROM file_entries WHERE validated = 0");
    count.check(sqlite3_step(count.get()), "counting unvalidated files");
    const auto total = static_cast<std::uint64_t>(
        std::max<sqlite3_int64>(0, sqlite3_column_int64(count.get(), 0)));
    const std::size_t page_count = total == 0 ? 1 : static_cast<std::size_t>(
        1 + (total - 1) / page_size);
    page = std::min(page, page_count - 1);
    Statement query(db.get(),
        "SELECT a.id, a.name, f.filename, f.description, f.extended_description, f.owner_handle, "
        "f.size, f.modified_at, f.download_count, f.file_points, f.validated, f.request_only "
        "FROM file_entries f JOIN file_areas a ON a.id = f.area_id WHERE f.validated = 0 "
        "ORDER BY f.modified_at DESC, a.id, f.filename COLLATE NOCASE LIMIT ?1 OFFSET ?2");
    query.bind_int64(1, static_cast<sqlite3_int64>(page_size));
    query.bind_int64(2, static_cast<sqlite3_int64>(page * page_size));
    FileValidationPage result;
    result.page = page;
    result.page_count = page_count;
    result.total = total;
    for (;;) {
        const int step = sqlite3_step(query.get());
        if (step == SQLITE_DONE) {
            break;
        }
        query.check(step, "listing unvalidated files");
        const auto column = [&query](int index) {
            const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(query.get(), index));
            return value == nullptr ? std::string{} : std::string(value);
        };
        result.files.push_back({sqlite3_column_int(query.get(), 0), column(1),
            {column(2), column(3), column(4), column(5),
                static_cast<std::uint64_t>(std::max<sqlite3_int64>(0,
                    sqlite3_column_int64(query.get(), 6))),
                column(7),
                static_cast<std::uint64_t>(std::max<sqlite3_int64>(0,
                    sqlite3_column_int64(query.get(), 8))),
                static_cast<std::uint64_t>(std::max<sqlite3_int64>(0,
                    sqlite3_column_int64(query.get(), 9))),
                sqlite3_column_int(query.get(), 10) != 0,
                sqlite3_column_int(query.get(), 11) != 0}});
    }
    return result;
}

std::uint64_t FileStore::validate_pending_files(std::string_view sysop) const {
    if (!valid_account_handle(sysop)) {
        throw std::invalid_argument("invalid SysOp account for bulk file validation");
    }
    (void)unvalidated_files(sysop, 0, 1);
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting bulk file validation");
    try {
        Statement moderator(db.get(), "SELECT is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
        moderator.bind_text(1, sysop);
        const int moderator_result = sqlite3_step(moderator.get());
        moderator.check(moderator_result, "checking bulk file-validation permission");
        if (moderator_result != SQLITE_ROW || sqlite3_column_int(moderator.get(), 0) == 0) {
            throw std::invalid_argument("only a SysOp can validate all pending files");
        }
        std::vector<std::pair<int, std::string>> pending;
        {
            Statement query(db.get(),
                "SELECT area_id, filename FROM file_entries WHERE validated = 0 ORDER BY area_id, filename COLLATE NOCASE");
            for (;;) {
                const int result = sqlite3_step(query.get());
                if (result == SQLITE_DONE) {
                    break;
                }
                query.check(result, "reading pending files for bulk validation");
                const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(query.get(), 1));
                pending.emplace_back(sqlite3_column_int(query.get(), 0),
                    value == nullptr ? std::string{} : std::string(value));
            }
        }
        for (const auto& [area_id, filename] : pending) {
            Statement update(db.get(),
                "UPDATE file_entries SET validated = 1 WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE "
                "AND validated = 0");
            update.bind_int(1, area_id);
            update.bind_text(2, filename);
            update.check(sqlite3_step(update.get()), "validating pending public file");
            if (sqlite3_changes(db.get()) > 0) {
                credit_validated_file_uploader(db.get(), area_id, filename);
            }
        }
        check_exec(db.get(), "COMMIT", "saving bulk file validation");
        return static_cast<std::uint64_t>(pending.size());
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::set_new_file_scan_date(
    std::string_view handle, std::string_view mmddyyyy) const {
    if (!valid_account_handle(handle) || mmddyyyy.size() != 10 ||
        mmddyyyy[2] != '/' || mmddyyyy[5] != '/') {
        throw std::invalid_argument("enter the oldest new-file date as MM/DD/YYYY");
    }
    const auto parse_component = [mmddyyyy](std::size_t start, std::size_t length) {
        int value{};
        const char* begin = mmddyyyy.data() + start;
        const auto parsed = std::from_chars(begin, begin + length, value);
        if (parsed.ec != std::errc{} || parsed.ptr != begin + length) {
            throw std::invalid_argument("enter the oldest new-file date as MM/DD/YYYY");
        }
        return value;
    };
    const int month = parse_component(0, 2);
    const int day = parse_component(3, 2);
    const int year = parse_component(6, 4);
    using namespace std::chrono;
    const year_month_day selected{std::chrono::year{year}, std::chrono::month{static_cast<unsigned>(month)},
        std::chrono::day{static_cast<unsigned>(day)}};
    if (year < 1 || year > 9999 || !selected.ok() ||
        sys_days{selected} > floor<days>(system_clock::now())) {
        throw std::invalid_argument("new-file scan date must be a valid date no later than today");
    }
    std::string year_text = std::to_string(year);
    year_text.insert(0, 4 - year_text.size(), '0');
    const auto two_digits = [](unsigned value) {
        return value < 10 ? "0" + std::to_string(value) : std::to_string(value);
    };
    const std::string iso_date = year_text + "-" + two_digits(static_cast<unsigned>(month)) +
        "-" + two_digits(static_cast<unsigned>(day));

    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement account(db.get(), "SELECT 1 FROM accounts WHERE handle = ?1 COLLATE NOCASE");
    account.bind_text(1, handle);
    const int account_result = sqlite3_step(account.get());
    account.check(account_result, "checking account for new-file scan date");
    if (account_result != SQLITE_ROW) {
        throw std::invalid_argument("BBS account does not exist");
    }
    Statement update(db.get(),
        "INSERT INTO file_user_scan_dates(handle, since_date) VALUES(?1, ?2) "
        "ON CONFLICT(handle) DO UPDATE SET since_date = excluded.since_date");
    update.bind_text(1, handle);
    update.bind_text(2, iso_date);
    update.check(sqlite3_step(update.get()), "saving per-account new-file scan date");
}

bool FileStore::can_download(std::string_view handle, int area_id) const {
    if (!valid_account_handle(handle) || area_id < 1) {
        return false;
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    Statement query(db.get(),
        "SELECT a.access_acs, a.download_acs, u.security_level, u.download_security_level, u.is_sysop, "
        "u.acs_ar_flags, u.acs_ac_flags, u.credits, u.id "
        "FROM file_areas a CROSS JOIN accounts u "
        "WHERE a.id = ?1 AND u.handle = ?2 COLLATE NOCASE");
    query.bind_int(1, area_id);
    query.bind_text(2, handle);
    const int result = sqlite3_step(query.get());
    query.check(result, "checking file-area download access");
    if (result == SQLITE_DONE) {
        return false;
    }
    const auto text = [&query](int column) {
        const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(query.get(), column));
        return value == nullptr ? std::string{} : std::string(value);
    };
    const std::string access_acs = text(0);
    const std::string download_acs = text(1);
    AccessLevels levels{sqlite3_column_int(query.get(), 2), sqlite3_column_int(query.get(), 3),
        sqlite3_column_int(query.get(), 4) != 0, text(5), text(6),
        sqlite3_column_int64(query.get(), 7), sqlite3_column_int64(query.get(), 8), 0, 0, 0, {}, '\0', true, true, 0, 32767, {}};
    AccessLevels caller_levels = account_access_levels(db.get(), handle);
    levels.online_minutes = caller_levels.online_minutes;
    levels.birth_date = caller_levels.birth_date;
    levels.sex = caller_levels.sex;
    levels.voted_in_all_polls = caller_levels.voted_in_all_polls;
    levels.novice_help = caller_levels.novice_help;
    levels.node_number = caller_levels.node_number;
    levels.remaining_minutes = caller_levels.remaining_minutes;
    levels.expiration_date = caller_levels.expiration_date;
    levels.file_area_number = area_id;
    return evaluate_legacy_acs(access_acs, levels) && evaluate_legacy_acs(download_acs, levels);
}

bool FileStore::can_upload(std::string_view handle, int area_id) const {
    if (!valid_account_handle(handle) || area_id < 1) {
        return false;
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    Statement query(db.get(),
        "SELECT a.access_acs, a.upload_acs, u.security_level, u.download_security_level, u.is_sysop, "
        "u.acs_ar_flags, u.acs_ac_flags, u.credits, u.id "
        "FROM file_areas a CROSS JOIN accounts u "
        "WHERE a.id = ?1 AND u.handle = ?2 COLLATE NOCASE");
    query.bind_int(1, area_id);
    query.bind_text(2, handle);
    const int result = sqlite3_step(query.get());
    query.check(result, "checking file-area upload access");
    if (result == SQLITE_DONE) {
        return false;
    }
    const auto text = [&query](int column) {
        const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(query.get(), column));
        return value == nullptr ? std::string{} : std::string(value);
    };
    AccessLevels levels{sqlite3_column_int(query.get(), 2), sqlite3_column_int(query.get(), 3),
        sqlite3_column_int(query.get(), 4) != 0, text(5), text(6),
        sqlite3_column_int64(query.get(), 7), sqlite3_column_int64(query.get(), 8), 0, 0, 0, {}, '\0', true, true, 0, 32767, {}};
    AccessLevels caller_levels = account_access_levels(db.get(), handle);
    levels.online_minutes = caller_levels.online_minutes;
    levels.birth_date = caller_levels.birth_date;
    levels.sex = caller_levels.sex;
    levels.voted_in_all_polls = caller_levels.voted_in_all_polls;
    levels.novice_help = caller_levels.novice_help;
    levels.node_number = caller_levels.node_number;
    levels.remaining_minutes = caller_levels.remaining_minutes;
    levels.expiration_date = caller_levels.expiration_date;
    levels.file_area_number = area_id;
    return evaluate_legacy_acs(text(0), levels) && evaluate_legacy_acs(text(1), levels);
}

bool FileStore::can_download_file(
    std::string_view handle,
    int area_id,
    std::string_view filename) const {
    if (!valid_account_handle(handle) || area_id < 1 || !valid_file_name(filename)) {
        return false;
    }
    if (!can_download(handle, area_id)) {
        return false;
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    AccessLevels levels = account_access_levels(db.get(), handle);
    levels.file_area_number = area_id;
    const bool may_download_unvalidated = evaluate_legacy_acs(
        file_store_setting(db.get(), "download_unvalidated_acs", "S255"), levels);
    Statement query(db.get(),
        "SELECT f.validated, f.request_only FROM file_entries f "
        "WHERE f.area_id = ?1 AND f.filename = ?2 COLLATE NOCASE");
    query.bind_int(1, area_id);
    query.bind_text(2, filename);
    const int result = sqlite3_step(query.get());
    query.check(result, "checking per-file download access");
    if (result != SQLITE_ROW) {
        return false;
    }
    return sqlite3_column_int(query.get(), 1) == 0 &&
        (sqlite3_column_int(query.get(), 0) != 0 || may_download_unvalidated);
}

bool FileStore::can_transfer_file(
    std::string_view handle,
    int area_id,
    std::string_view filename) const {
    if (!can_download_file(handle, area_id, filename)) {
        return false;
    }
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    if (file_store_setting(db.get(), "download_ratios_enabled", "0") != "1") {
        return true;
    }
    AccessLevels levels = account_access_levels(db.get(), handle);
    levels.file_area_number = area_id;
    if (levels.ac_flags.find('1') != std::string::npos || evaluate_legacy_acs(
            file_store_setting(db.get(), "no_download_ratio_acs", "S255"), levels)) {
        return true;
    }
    std::uint64_t count_ratio_limit = file_store_unsigned_setting(db.get(), "download_count_ratio");
    std::uint64_t kib_ratio_limit = file_store_unsigned_setting(db.get(), "download_kib_ratio");
    {
        Statement level_ratio(db.get(),
            "SELECT max_downloads_per_upload, max_kib_per_uploaded_kib "
            "FROM file_download_level_ratios WHERE security_level = ?1");
        level_ratio.bind_int(1, levels.security_level);
        const int result = sqlite3_step(level_ratio.get());
        level_ratio.check(result, "reading per-level download ratios");
        if (result == SQLITE_ROW) {
            count_ratio_limit = static_cast<std::uint64_t>(sqlite3_column_int64(level_ratio.get(), 0));
            kib_ratio_limit = static_cast<std::uint64_t>(sqlite3_column_int64(level_ratio.get(), 1));
        }
    }
    if (count_ratio_limit == 0 && kib_ratio_limit == 0) {
        return true;
    }
    std::uint64_t uploaded_files = 0;
    std::uint64_t uploaded_kib = 0;
    std::uint64_t downloaded_files = 0;
    std::uint64_t downloaded_kib = 0;
    {
        Statement activity(db.get(),
            "SELECT uploads, uploaded_kib, downloads, downloaded_kib "
            "FROM file_user_activity WHERE handle = ?1 COLLATE NOCASE");
        activity.bind_text(1, handle);
        const int result = sqlite3_step(activity.get());
        activity.check(result, "reading file-ratio activity");
        if (result == SQLITE_ROW) {
            uploaded_files = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                0, sqlite3_column_int64(activity.get(), 0)));
            uploaded_kib = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                0, sqlite3_column_int64(activity.get(), 1)));
            downloaded_files = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                0, sqlite3_column_int64(activity.get(), 2)));
            downloaded_kib = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                0, sqlite3_column_int64(activity.get(), 3)));
        }
    }
    std::uint64_t requested_size = 0;
    bool area_exempt = false;
    {
        Statement file(db.get(),
            "SELECT f.size, a.no_ratio FROM file_entries f JOIN file_areas a ON a.id = f.area_id "
            "WHERE f.area_id = ?1 AND f.filename = ?2 COLLATE NOCASE");
        file.bind_int(1, area_id);
        file.bind_text(2, filename);
        const int result = sqlite3_step(file.get());
        file.check(result, "reading file for ratio check");
        if (result != SQLITE_ROW) {
            return false;
        }
        requested_size = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
            0, sqlite3_column_int64(file.get(), 0)));
        area_exempt = sqlite3_column_int(file.get(), 1) != 0;
    }
    if (area_exempt) {
        return true;
    }
    std::uint64_t reserved_files = 0;
    std::uint64_t reserved_kib = 0;
    {
        Statement reservations(db.get(),
            "SELECT COUNT(*), COALESCE(SUM(file_kib), 0) FROM file_daily_download_reservations "
            "WHERE handle = ?1 COLLATE NOCASE");
        reservations.bind_text(1, handle);
        const int result = sqlite3_step(reservations.get());
        reservations.check(result, "reading active downloads for ratio check");
        reserved_files = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
            0, sqlite3_column_int64(reservations.get(), 0)));
        reserved_kib = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
            0, sqlite3_column_int64(reservations.get(), 1)));
    }
    const std::uint64_t count_numerator = saturating_add(
        saturating_add(downloaded_files, reserved_files), 1);
    if (exceeds_ratio(count_numerator, uploaded_files, count_ratio_limit)) {
        return false;
    }
    const std::uint64_t kib_numerator = saturating_add(
        saturating_add(downloaded_kib, reserved_kib), requested_size / 1024U);
    if (exceeds_ratio(kib_numerator, uploaded_kib, kib_ratio_limit)) {
        return false;
    }
    return true;
}

void FileStore::set_file_validated(
    std::string_view actor,
    int area_id,
    std::string_view filename,
    bool validated) const {
    if (!valid_account_handle(actor) || area_id < 1 || !valid_file_name(filename)) {
        throw std::invalid_argument("invalid account, area or filename for file validation");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file-validation update");
    try {
        Statement moderator(db.get(), "SELECT is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
        moderator.bind_text(1, actor);
        const int moderator_result = sqlite3_step(moderator.get());
        moderator.check(moderator_result, "checking file-validation permission");
        if (moderator_result != SQLITE_ROW || sqlite3_column_int(moderator.get(), 0) == 0) {
            throw std::invalid_argument("only a SysOp can validate public files");
        }
        Statement update(db.get(),
            "UPDATE file_entries SET validated = ?1 WHERE area_id = ?2 AND filename = ?3 COLLATE NOCASE");
        update.bind_int(1, validated ? 1 : 0);
        update.bind_int(2, area_id);
        update.bind_text(3, filename);
        update.check(sqlite3_step(update.get()), "updating file validation state");
        if (sqlite3_changes(db.get()) == 0) {
            throw std::invalid_argument("file is not indexed in this file area");
        }
        if (validated) {
            credit_validated_file_uploader(db.get(), area_id, filename);
        } else {
            revoke_validated_file_uploader(db.get(), area_id, filename);
        }
        check_exec(db.get(), "COMMIT", "saving file-validation update");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::validate_file_with_points(
    std::string_view actor,
    int area_id,
    std::string_view filename,
    std::uint64_t file_points,
    std::int64_t owner_balance_adjustment) const {
    if (!valid_account_handle(actor) || area_id < 1 || !valid_file_name(filename) ||
        file_points > 999U || owner_balance_adjustment < -2147483647LL ||
        owner_balance_adjustment > 999LL) {
        throw std::invalid_argument("invalid account, file, point cost, or owner balance adjustment");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting point-entry file validation");
    try {
        Statement moderator(db.get(), "SELECT is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
        moderator.bind_text(1, actor);
        const int moderator_result = sqlite3_step(moderator.get());
        moderator.check(moderator_result, "checking point-entry validation permission");
        if (moderator_result != SQLITE_ROW || sqlite3_column_int(moderator.get(), 0) == 0) {
            throw std::invalid_argument("only a SysOp can validate public files");
        }

        std::string owner_handle;
        {
            Statement file(db.get(),
                "SELECT owner_handle, validated FROM file_entries "
                "WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE");
            file.bind_int(1, area_id);
            file.bind_text(2, filename);
            const int result = sqlite3_step(file.get());
            file.check(result, "reading file for point-entry validation");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("file is not indexed in this file area");
            }
            if (sqlite3_column_int(file.get(), 1) != 0) {
                throw std::invalid_argument("file is already validated");
            }
            const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(file.get(), 0));
            owner_handle = value == nullptr ? std::string{} : std::string(value);
        }
        if (owner_balance_adjustment != 0 && owner_handle.empty()) {
            throw std::invalid_argument("file has no uploader account for the balance adjustment");
        }
        revoke_validated_file_uploader(db.get(), area_id, filename);
        {
            Statement update(db.get(),
                "UPDATE file_entries SET file_points = ?1, validated = 1 "
                "WHERE area_id = ?2 AND filename = ?3 COLLATE NOCASE");
            update.bind_int64(1, static_cast<sqlite3_int64>(file_points));
            update.bind_int(2, area_id);
            update.bind_text(3, filename);
            update.check(sqlite3_step(update.get()), "saving point-entry file validation");
        }
        credit_validated_file_uploader(db.get(), area_id, filename,
            file_points > 0 ? std::optional<std::uint64_t>(file_points) : std::nullopt);
        if (owner_balance_adjustment != 0) {
            sqlite3_int64 balance = 0;
            {
                Statement account(db.get(),
                    "SELECT file_points FROM accounts WHERE handle = ?1 COLLATE NOCASE");
                account.bind_text(1, owner_handle);
                const int result = sqlite3_step(account.get());
                account.check(result, "reading uploader balance adjustment target");
                if (result != SQLITE_ROW) {
                    throw std::invalid_argument("file uploader account does not exist");
                }
                balance = std::max<sqlite3_int64>(0, sqlite3_column_int64(account.get(), 0));
            }
            if (owner_balance_adjustment < -balance) {
                throw std::invalid_argument("owner balance adjustment cannot reduce the balance below zero");
            }
            Statement adjust(db.get(),
                "UPDATE accounts SET file_points = MAX(0, MIN(2147483647, file_points + ?1)) "
                "WHERE handle = ?2 COLLATE NOCASE");
            adjust.bind_int64(1, owner_balance_adjustment);
            adjust.bind_text(2, owner_handle);
            adjust.check(sqlite3_step(adjust.get()), "adjusting uploader balance after validation");
        }
        check_exec(db.get(), "COMMIT", "saving point-entry validation");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::set_file_request_only(
    std::string_view actor,
    int area_id,
    std::string_view filename,
    bool request_only) const {
    if (!valid_account_handle(actor) || area_id < 1 || !valid_file_name(filename)) {
        throw std::invalid_argument("invalid account, area or filename for request-file update");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting request-file update");
    try {
        bool is_sysop = false;
        {
            Statement moderator(db.get(), "SELECT is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
            moderator.bind_text(1, actor);
            const int result = sqlite3_step(moderator.get());
            moderator.check(result, "checking request-file permission");
            is_sysop = result == SQLITE_ROW && sqlite3_column_int(moderator.get(), 0) != 0;
        }
        if (!is_sysop) {
            throw std::invalid_argument("only a SysOp can change request-file status");
        }
        synchronize_area(db.get(), root_path_, area_id);
        FileDescriptor root(::open(root_path_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (root.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file root");
        }
        FileDescriptor areas_root(::openat(root.get(), "areas",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (areas_root.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file areas");
        }
        const std::string area_name = std::to_string(area_id);
        FileDescriptor area(::openat(areas_root.get(), area_name.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (area.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file area");
        }
        const std::string file_name(filename);
        FileDescriptor file(::openat(area.get(), file_name.c_str(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        if (file.get() < 0 && (!request_only || errno != ENOENT)) {
            throw std::system_error(errno, std::generic_category(), "opening file to update request status");
        }
        if (file.get() >= 0) {
            if (::flock(file.get(), LOCK_EX | LOCK_NB) != 0) {
                throw std::system_error(errno, std::generic_category(), "file is in an active SFTP transfer");
            }
            struct stat info {};
            if (::fstat(file.get(), &info) != 0) {
                throw std::system_error(errno, std::generic_category(), "checking file request status");
            }
            if (!S_ISREG(info.st_mode)) {
                throw std::invalid_argument("public file is not a regular file");
            }
        }
        Statement update(db.get(),
            "UPDATE file_entries SET request_only = ?1 WHERE area_id = ?2 AND filename = ?3 COLLATE NOCASE");
        update.bind_int(1, request_only ? 1 : 0);
        update.bind_int(2, area_id);
        update.bind_text(3, filename);
        update.check(sqlite3_step(update.get()), "updating request-file status");
        if (sqlite3_changes(db.get()) == 0) {
            throw std::invalid_argument("file is not indexed in this area");
        }
        check_exec(db.get(), "COMMIT", "saving request-file status");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::set_file_owner(
    std::string_view actor,
    int area_id,
    std::string_view filename,
    std::string_view owner_handle) const {
    if (!valid_account_handle(actor) || !valid_account_handle(owner_handle) || area_id < 1 ||
        !valid_file_name(filename)) {
        throw std::invalid_argument("invalid account, area or filename for file-owner update");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file-owner update");
    try {
        bool is_sysop = false;
        {
            Statement moderator(db.get(), "SELECT is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
            moderator.bind_text(1, actor);
            const int result = sqlite3_step(moderator.get());
            moderator.check(result, "checking file-owner update permission");
            is_sysop = result == SQLITE_ROW && sqlite3_column_int(moderator.get(), 0) != 0;
        }
        if (!is_sysop) {
            throw std::invalid_argument("only a SysOp can change a file owner");
        }
        std::string current_owner;
        {
            Statement current(db.get(),
                "SELECT owner_handle FROM file_entries WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE");
            current.bind_int(1, area_id);
            current.bind_text(2, filename);
            const int result = sqlite3_step(current.get());
            current.check(result, "reading current file owner");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("file is not indexed in this file area");
            }
            const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(current.get(), 0));
            current_owner = value == nullptr ? std::string{} : std::string(value);
        }
        const std::string replacement_owner(owner_handle);
        if (!current_owner.empty() && ::strcasecmp(current_owner.c_str(), replacement_owner.c_str()) == 0) {
            check_exec(db.get(), "COMMIT", "finishing file-owner update");
            return;
        }
        {
            Statement owner(db.get(), "SELECT 1 FROM accounts WHERE handle = ?1 COLLATE NOCASE");
            owner.bind_text(1, owner_handle);
            const int result = sqlite3_step(owner.get());
            owner.check(result, "checking replacement file owner");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("file owner account does not exist");
            }
        }
        revoke_validated_file_uploader(db.get(), area_id, filename);
        Statement update(db.get(),
            "UPDATE file_entries SET owner_handle = ?1 WHERE area_id = ?2 AND filename = ?3 COLLATE NOCASE");
        update.bind_text(1, owner_handle);
        update.bind_int(2, area_id);
        update.bind_text(3, filename);
        update.check(sqlite3_step(update.get()), "updating file owner");
        if (sqlite3_changes(db.get()) == 0) {
            throw std::invalid_argument("file is not indexed in this area");
        }
        credit_validated_file_uploader(db.get(), area_id, filename);
        check_exec(db.get(), "COMMIT", "saving file-owner update");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::withdraw_file_owner_credit(
    std::string_view actor, int area_id, std::string_view filename) const {
    if (!valid_account_handle(actor) || area_id < 1 || !valid_file_name(filename)) {
        throw std::invalid_argument("invalid account, area, or filename for uploader-credit withdrawal");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting uploader-credit withdrawal");
    try {
        Statement moderator(db.get(), "SELECT is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
        moderator.bind_text(1, actor);
        const int moderator_result = sqlite3_step(moderator.get());
        moderator.check(moderator_result, "checking uploader-credit withdrawal permission");
        if (moderator_result != SQLITE_ROW || sqlite3_column_int(moderator.get(), 0) == 0) {
            throw std::invalid_argument("only a SysOp can withdraw uploader credit");
        }
        Statement file(db.get(),
            "SELECT uploader_credited FROM file_entries WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE");
        file.bind_int(1, area_id);
        file.bind_text(2, filename);
        const int file_result = sqlite3_step(file.get());
        file.check(file_result, "checking uploader-credit withdrawal state");
        if (file_result != SQLITE_ROW) {
            throw std::invalid_argument("file is not indexed in this file area");
        }
        if (sqlite3_column_int(file.get(), 0) == 0) {
            throw std::invalid_argument("the uploader has no credited points for this file");
        }
        revoke_validated_file_uploader(db.get(), area_id, filename);
        check_exec(db.get(), "COMMIT", "saving uploader-credit withdrawal");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::set_file_points(
    std::string_view actor,
    int area_id,
    std::string_view filename,
    std::uint64_t points) const {
    if (!valid_account_handle(actor) || area_id < 1 || !valid_file_name(filename) ||
        points > 32767U) {
        throw std::invalid_argument("file points must be between 0 and 32767");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file-point edit");
    try {
        {
            Statement moderator(db.get(), "SELECT is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
            moderator.bind_text(1, actor);
            const int result = sqlite3_step(moderator.get());
            moderator.check(result, "checking file-point edit permission");
            if (result != SQLITE_ROW || sqlite3_column_int(moderator.get(), 0) == 0) {
                throw std::invalid_argument("only a SysOp can change file points");
            }
        }
        Statement update(db.get(),
            "UPDATE file_entries SET file_points = ?1 WHERE area_id = ?2 AND filename = ?3 COLLATE NOCASE");
        update.bind_int64(1, static_cast<sqlite3_int64>(points));
        update.bind_int(2, area_id);
        update.bind_text(3, filename);
        update.check(sqlite3_step(update.get()), "updating file points");
        if (sqlite3_changes(db.get()) == 0) {
            throw std::invalid_argument("file is not indexed in this area");
        }
        check_exec(db.get(), "COMMIT", "saving file-point edit");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::set_file_date(
    std::string_view actor,
    int area_id,
    std::string_view filename,
    std::string_view mmddyyyy) const {
    if (!valid_account_handle(actor) || area_id < 1 || !valid_file_name(filename) ||
        mmddyyyy.size() != 10 || mmddyyyy[2] != '-' || mmddyyyy[5] != '-') {
        throw std::invalid_argument("enter the file date as MM-DD-YYYY");
    }
    const auto parse_component = [mmddyyyy](std::size_t start, std::size_t length) {
        int value{};
        const char* begin = mmddyyyy.data() + start;
        const auto parsed = std::from_chars(begin, begin + length, value);
        if (parsed.ec != std::errc{} || parsed.ptr != begin + length) {
            throw std::invalid_argument("enter the file date as MM-DD-YYYY");
        }
        return value;
    };
    const int month = parse_component(0, 2);
    const int day = parse_component(3, 2);
    const int year = parse_component(6, 4);
    using namespace std::chrono;
    const year_month_day selected{std::chrono::year{year},
        std::chrono::month{static_cast<unsigned>(month)}, std::chrono::day{static_cast<unsigned>(day)}};
    const sys_days selected_day{selected};
    if (year < 1 || year > 9999 || !selected.ok() || selected_day > floor<days>(system_clock::now())) {
        throw std::invalid_argument("file date must be valid and no later than today");
    }
    const auto two_digits = [](unsigned value) {
        return value < 10 ? "0" + std::to_string(value) : std::to_string(value);
    };
    std::string year_text = std::to_string(year);
    year_text.insert(0, 4 - year_text.size(), '0');
    const std::string iso_date = year_text + "-" +
        two_digits(static_cast<unsigned>(month)) + "-" + two_digits(static_cast<unsigned>(day));

    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file-date update");
    FileDescriptor file;
    struct timespec original_times[2]{};
    bool changed_file_time = false;
    try {
        bool is_sysop = false;
        {
            Statement moderator(db.get(), "SELECT is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
            moderator.bind_text(1, actor);
            const int result = sqlite3_step(moderator.get());
            moderator.check(result, "checking file-date update permission");
            is_sysop = result == SQLITE_ROW && sqlite3_column_int(moderator.get(), 0) != 0;
        }
        if (!is_sysop) {
            throw std::invalid_argument("only a SysOp can change a file date");
        }
        synchronize_area(db.get(), root_path_, area_id);
        bool request_only = false;
        {
            Statement indexed(db.get(),
                "SELECT request_only FROM file_entries WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE");
            indexed.bind_int(1, area_id);
            indexed.bind_text(2, filename);
            const int result = sqlite3_step(indexed.get());
            indexed.check(result, "checking file before date update");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("file is not indexed in this area");
            }
            request_only = sqlite3_column_int(indexed.get(), 0) != 0;
        }
        FileDescriptor root(::open(root_path_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (root.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file root");
        }
        FileDescriptor areas_root(::openat(root.get(), "areas",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (areas_root.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file areas");
        }
        const std::string area_name = std::to_string(area_id);
        FileDescriptor area(::openat(areas_root.get(), area_name.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (area.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file area");
        }
        const std::string file_name(filename);
        file.reset(::openat(area.get(), file_name.c_str(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        if (file.get() < 0 && (!request_only || errno != ENOENT)) {
            throw std::system_error(errno, std::generic_category(), "opening file for date update");
        }
        if (file.get() >= 0) {
            if (::flock(file.get(), LOCK_EX | LOCK_NB) != 0) {
                throw std::system_error(errno, std::generic_category(), "file is in an active SFTP transfer");
            }
            struct stat info {};
            if (::fstat(file.get(), &info) != 0 || !S_ISREG(info.st_mode)) {
                throw std::system_error(errno == 0 ? EINVAL : errno, std::generic_category(),
                    "checking file before date update");
            }
            original_times[0] = info.st_atim;
            original_times[1] = info.st_mtim;
            const auto seconds = duration_cast<std::chrono::seconds>(selected_day.time_since_epoch()).count();
            struct timespec selected_times[2]{{0, UTIME_OMIT}, {static_cast<time_t>(seconds), 0}};
            if (::futimens(file.get(), selected_times) != 0) {
                throw std::system_error(errno, std::generic_category(), "updating file modification date");
            }
            changed_file_time = true;
        }
        Statement update(db.get(),
            "UPDATE file_entries SET modified_at = ?1 WHERE area_id = ?2 AND filename = ?3 COLLATE NOCASE");
        update.bind_text(1, iso_date + " 00:00");
        update.bind_int(2, area_id);
        update.bind_text(3, filename);
        update.check(sqlite3_step(update.get()), "saving file upload date");
        if (sqlite3_changes(db.get()) == 0) {
            throw std::runtime_error("file index changed during date update");
        }
        check_exec(db.get(), "COMMIT", "saving file-date update");
        changed_file_time = false;
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        if (changed_file_time && file.get() >= 0 && ::futimens(file.get(), original_times) != 0) {
            std::cerr << "Could not restore file modification date after update failure: "
                      << std::generic_category().message(errno) << '\n';
        }
        throw;
    }
}

std::uint64_t FileStore::refresh_file_size(
    std::string_view actor,
    int area_id,
    std::string_view filename) const {
    if (!valid_account_handle(actor) || area_id < 1 || !valid_file_name(filename)) {
        throw std::invalid_argument("invalid account, area or filename for file-size refresh");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file-size refresh");
    try {
        bool is_sysop = false;
        {
            Statement moderator(db.get(), "SELECT is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
            moderator.bind_text(1, actor);
            const int result = sqlite3_step(moderator.get());
            moderator.check(result, "checking file-size refresh permission");
            is_sysop = result == SQLITE_ROW && sqlite3_column_int(moderator.get(), 0) != 0;
        }
        if (!is_sysop) {
            throw std::invalid_argument("only a SysOp can refresh a public file size");
        }
        synchronize_area(db.get(), root_path_, area_id);
        FileDescriptor root(::open(root_path_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (root.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file root");
        }
        FileDescriptor areas_root(::openat(root.get(), "areas",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (areas_root.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file areas");
        }
        const std::string area_name = std::to_string(area_id);
        FileDescriptor area(::openat(areas_root.get(), area_name.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (area.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file area");
        }
        const std::string file_name(filename);
        FileDescriptor file(::openat(area.get(), file_name.c_str(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        if (file.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file for size refresh");
        }
        if (::flock(file.get(), LOCK_SH | LOCK_NB) != 0) {
            throw std::system_error(errno, std::generic_category(), "file is in an active SFTP upload");
        }
        struct stat info {};
        if (::fstat(file.get(), &info) != 0) {
            throw std::system_error(errno, std::generic_category(), "checking public file size");
        }
        if (!S_ISREG(info.st_mode) || info.st_size < 0) {
            throw std::invalid_argument("public file is not a regular file");
        }
        Statement update(db.get(),
            "UPDATE file_entries SET size = ?1 WHERE area_id = ?2 AND filename = ?3 COLLATE NOCASE");
        update.bind_int64(1, static_cast<sqlite3_int64>(info.st_size));
        update.bind_int(2, area_id);
        update.bind_text(3, filename);
        update.check(sqlite3_step(update.get()), "updating public file size");
        if (sqlite3_changes(db.get()) == 0) {
            throw std::invalid_argument("file is not indexed in this area");
        }
        check_exec(db.get(), "COMMIT", "saving file-size refresh");
        return static_cast<std::uint64_t>(info.st_size);
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::delete_public_file(
    std::string_view actor,
    int area_id,
    std::string_view filename) const {
    if (!valid_account_handle(actor) || area_id < 1 || !valid_file_name(filename)) {
        throw std::invalid_argument("invalid account, area or filename for public file deletion");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    bool is_sysop = false;
    {
        Statement moderator(db.get(), "SELECT is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
        moderator.bind_text(1, actor);
        const int moderator_result = sqlite3_step(moderator.get());
        moderator.check(moderator_result, "checking public-file deletion permission");
        is_sysop = moderator_result == SQLITE_ROW && sqlite3_column_int(moderator.get(), 0) != 0;
    }
    if (!is_sysop) {
        throw std::invalid_argument("only a SysOp can delete public files");
    }
    {
        Statement indexed(db.get(),
            "SELECT 1 FROM file_entries WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE");
        indexed.bind_int(1, area_id);
        indexed.bind_text(2, filename);
        const int indexed_result = sqlite3_step(indexed.get());
        indexed.check(indexed_result, "checking public file before deletion");
        if (indexed_result != SQLITE_ROW) {
            throw std::invalid_argument("file is not indexed in that file area");
        }
    }

    FileDescriptor root(::open(root_path_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (root.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening public file root");
    }
    FileDescriptor areas_root(::openat(root.get(), "areas",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (areas_root.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening public file areas");
    }
    const std::string area_name = std::to_string(area_id);
    FileDescriptor area(::openat(areas_root.get(), area_name.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (area.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening public file area");
    }
    const std::string file_name(filename);
    FileDescriptor file(::openat(area.get(), file_name.c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening public file for deletion");
    }
    if (::flock(file.get(), LOCK_EX | LOCK_NB) != 0) {
        throw std::system_error(errno, std::generic_category(), "public file is in an active upload");
    }
    struct stat info {};
    if (::fstat(file.get(), &info) != 0) {
        throw std::system_error(errno, std::generic_category(), "checking public file before deletion");
    }
    if (!S_ISREG(info.st_mode)) {
        throw std::invalid_argument("public file is not a regular file");
    }
    if (::unlinkat(area.get(), file_name.c_str(), 0) != 0) {
        throw std::system_error(errno, std::generic_category(), "removing public file");
    }
    Statement remove(db.get(),
        "DELETE FROM file_entries WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE");
    remove.bind_int(1, area_id);
    remove.bind_text(2, filename);
    remove.check(sqlite3_step(remove.get()), "removing public file index entry");
    if (sqlite3_changes(db.get()) == 0) {
        throw std::runtime_error("public file index changed during deletion");
    }
}

void FileStore::move_public_file(
    std::string_view actor,
    int source_area_id,
    std::string_view filename,
    int target_area_id) const {
    if (!valid_account_handle(actor) || source_area_id < 1 || target_area_id < 1 ||
        !valid_file_name(filename)) {
        throw std::invalid_argument("invalid account, area or filename for public file move");
    }
    if (source_area_id == target_area_id) {
        throw std::invalid_argument("a file cannot be moved to its current area");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting public file move");
    bool moved = false;
    FileDescriptor source_area;
    FileDescriptor target_area;
    const std::string file_name(filename);
    try {
        bool is_sysop = false;
        {
            Statement moderator(db.get(), "SELECT is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
            moderator.bind_text(1, actor);
            const int result = sqlite3_step(moderator.get());
            moderator.check(result, "checking public-file move permission");
            is_sysop = result == SQLITE_ROW && sqlite3_column_int(moderator.get(), 0) != 0;
        }
        if (!is_sysop) {
            throw std::invalid_argument("only a SysOp can move public files");
        }
        {
            Statement source(db.get(), "SELECT 1 FROM file_areas WHERE id = ?1");
            source.bind_int(1, source_area_id);
            const int result = sqlite3_step(source.get());
            source.check(result, "checking source file area");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("source file area does not exist");
            }
        }
        {
            Statement target(db.get(), "SELECT 1 FROM file_areas WHERE id = ?1");
            target.bind_int(1, target_area_id);
            const int result = sqlite3_step(target.get());
            target.check(result, "checking target file area");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("target file area does not exist");
            }
        }
        synchronize_area(db.get(), root_path_, source_area_id);
        synchronize_area(db.get(), root_path_, target_area_id);
        {
            Statement indexed(db.get(),
                "SELECT 1 FROM file_entries WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE");
            indexed.bind_int(1, source_area_id);
            indexed.bind_text(2, filename);
            const int result = sqlite3_step(indexed.get());
            indexed.check(result, "checking public file before move");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("file is not indexed in the source area");
            }
        }

        FileDescriptor root(::open(root_path_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (root.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file root");
        }
        FileDescriptor areas_root(::openat(root.get(), "areas",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (areas_root.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file areas");
        }
        const std::string source_name = std::to_string(source_area_id);
        source_area.reset(::openat(areas_root.get(), source_name.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (source_area.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening source file area");
        }
        const std::string target_name = std::to_string(target_area_id);
        target_area.reset(::openat(areas_root.get(), target_name.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (target_area.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening target file area");
        }
        FileDescriptor file(::openat(source_area.get(), file_name.c_str(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        if (file.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file for move");
        }
        if (::flock(file.get(), LOCK_EX | LOCK_NB) != 0) {
            throw std::system_error(errno, std::generic_category(), "public file is in an active SFTP transfer");
        }
        struct stat info {};
        if (::fstat(file.get(), &info) != 0) {
            throw std::system_error(errno, std::generic_category(), "checking public file before move");
        }
        if (!S_ISREG(info.st_mode)) {
            throw std::invalid_argument("public file is not a regular file");
        }
        if (::syscall(SYS_renameat2, source_area.get(), file_name.c_str(),
                target_area.get(), file_name.c_str(), RENAME_NOREPLACE) != 0) {
            throw std::system_error(errno, std::generic_category(), "moving public file");
        }
        moved = true;
        Statement update(db.get(),
            "UPDATE file_entries SET area_id = ?1 WHERE area_id = ?2 AND filename = ?3 COLLATE NOCASE");
        update.bind_int(1, target_area_id);
        update.bind_int(2, source_area_id);
        update.bind_text(3, filename);
        update.check(sqlite3_step(update.get()), "moving public file index entry");
        if (sqlite3_changes(db.get()) == 0) {
            throw std::runtime_error("public file index changed during move");
        }
        {
            Statement remove_duplicate_queue_rows(db.get(),
                "DELETE FROM file_download_queue WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE "
                "AND handle COLLATE NOCASE IN (SELECT handle FROM file_download_queue WHERE area_id = ?3 "
                "AND filename = ?2 COLLATE NOCASE)");
            remove_duplicate_queue_rows.bind_int(1, target_area_id);
            remove_duplicate_queue_rows.bind_text(2, filename);
            remove_duplicate_queue_rows.bind_int(3, source_area_id);
            remove_duplicate_queue_rows.check(sqlite3_step(remove_duplicate_queue_rows.get()),
                "merging download queue rows during file move");
        }
        {
            Statement move_queue_rows(db.get(),
                "UPDATE file_download_queue SET area_id = ?1 WHERE area_id = ?2 AND filename = ?3 COLLATE NOCASE");
            move_queue_rows.bind_int(1, target_area_id);
            move_queue_rows.bind_int(2, source_area_id);
            move_queue_rows.bind_text(3, filename);
            move_queue_rows.check(sqlite3_step(move_queue_rows.get()),
                "updating download queue rows during file move");
        }
        check_exec(db.get(), "COMMIT", "finishing public file move");
        moved = false;
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        if (moved && source_area.get() >= 0 && target_area.get() >= 0 &&
            ::syscall(SYS_renameat2, target_area.get(), file_name.c_str(),
                source_area.get(), file_name.c_str(), RENAME_NOREPLACE) != 0) {
            std::cerr << "Could not roll back public file move for " << file_name << ": "
                      << std::generic_category().message(errno) << '\n';
        }
        throw;
    }
}

void FileStore::rename_public_file(
    std::string_view actor,
    int area_id,
    std::string_view filename,
    std::string_view new_filename) const {
    if (!valid_account_handle(actor) || area_id < 1 || !valid_file_name(filename) ||
        !valid_file_name(new_filename) || ::strcasecmp(std::string(filename).c_str(),
            std::string(new_filename).c_str()) == 0) {
        throw std::invalid_argument("invalid account, area or filename for public file rename");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting public file rename");
    bool renamed = false;
    FileDescriptor area;
    const std::string old_name(filename);
    const std::string new_name(new_filename);
    try {
        bool is_sysop = false;
        {
            Statement moderator(db.get(), "SELECT is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
            moderator.bind_text(1, actor);
            const int result = sqlite3_step(moderator.get());
            moderator.check(result, "checking public-file rename permission");
            is_sysop = result == SQLITE_ROW && sqlite3_column_int(moderator.get(), 0) != 0;
        }
        if (!is_sysop) {
            throw std::invalid_argument("only a SysOp can rename public files");
        }
        synchronize_area(db.get(), root_path_, area_id);
        {
            Statement source(db.get(),
                "SELECT 1 FROM file_entries WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE");
            source.bind_int(1, area_id);
            source.bind_text(2, filename);
            const int result = sqlite3_step(source.get());
            source.check(result, "checking public file before rename");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("file is not indexed in the selected area");
            }
        }
        {
            Statement target(db.get(),
                "SELECT 1 FROM file_entries WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE");
            target.bind_int(1, area_id);
            target.bind_text(2, new_filename);
            const int result = sqlite3_step(target.get());
            target.check(result, "checking public-file rename target");
            if (result == SQLITE_ROW) {
                throw std::invalid_argument("another file already has that name in this area");
            }
        }
        FileDescriptor root(::open(root_path_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (root.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file root");
        }
        FileDescriptor areas_root(::openat(root.get(), "areas",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (areas_root.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file areas");
        }
        const std::string area_name = std::to_string(area_id);
        area.reset(::openat(areas_root.get(), area_name.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (area.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file area");
        }
        FileDescriptor file(::openat(area.get(), old_name.c_str(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        if (file.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file for rename");
        }
        if (::flock(file.get(), LOCK_EX | LOCK_NB) != 0) {
            throw std::system_error(errno, std::generic_category(), "public file is in an active SFTP transfer");
        }
        struct stat info {};
        if (::fstat(file.get(), &info) != 0) {
            throw std::system_error(errno, std::generic_category(), "checking public file before rename");
        }
        if (!S_ISREG(info.st_mode)) {
            throw std::invalid_argument("public file is not a regular file");
        }
        if (::syscall(SYS_renameat2, area.get(), old_name.c_str(),
                area.get(), new_name.c_str(), RENAME_NOREPLACE) != 0) {
            throw std::system_error(errno, std::generic_category(), "renaming public file");
        }
        renamed = true;
        Statement update(db.get(),
            "UPDATE file_entries SET filename = ?1 WHERE area_id = ?2 AND filename = ?3 COLLATE NOCASE");
        update.bind_text(1, new_filename);
        update.bind_int(2, area_id);
        update.bind_text(3, filename);
        update.check(sqlite3_step(update.get()), "renaming public file index entry");
        if (sqlite3_changes(db.get()) == 0) {
            throw std::runtime_error("public file index changed during rename");
        }
        {
            Statement remove_duplicate_queue_rows(db.get(),
                "DELETE FROM file_download_queue WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE "
                "AND handle COLLATE NOCASE IN (SELECT handle FROM file_download_queue WHERE area_id = ?1 "
                "AND filename = ?3 COLLATE NOCASE)");
            remove_duplicate_queue_rows.bind_int(1, area_id);
            remove_duplicate_queue_rows.bind_text(2, new_filename);
            remove_duplicate_queue_rows.bind_text(3, filename);
            remove_duplicate_queue_rows.check(sqlite3_step(remove_duplicate_queue_rows.get()),
                "merging download queue rows during file rename");
        }
        {
            Statement move_queue_rows(db.get(),
                "UPDATE file_download_queue SET filename = ?1 WHERE area_id = ?2 AND filename = ?3 COLLATE NOCASE");
            move_queue_rows.bind_text(1, new_filename);
            move_queue_rows.bind_int(2, area_id);
            move_queue_rows.bind_text(3, filename);
            move_queue_rows.check(sqlite3_step(move_queue_rows.get()),
                "updating download queue rows during file rename");
        }
        check_exec(db.get(), "COMMIT", "finishing public file rename");
        renamed = false;
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        if (renamed && area.get() >= 0 &&
            ::syscall(SYS_renameat2, area.get(), new_name.c_str(),
                area.get(), old_name.c_str(), RENAME_NOREPLACE) != 0) {
            std::cerr << "Could not roll back public file rename for " << old_name << ": "
                      << std::generic_category().message(errno) << '\n';
        }
        throw;
    }
}

int FileStore::open_public_file(
    std::string_view handle, int area_id, std::string_view filename) const {
    if (area_id < 1 || !valid_file_name(filename)) {
        throw std::invalid_argument("invalid public file-area path");
    }
    if (!can_download(handle, area_id)) {
        throw std::invalid_argument("account does not have access to download from this file area");
    }
    (void)files(handle, area_id, std::string_view{}, 0, 1);
    if (!can_download_file(handle, area_id, filename)) {
        throw std::invalid_argument("account does not have access to download this file");
    }
    {
        Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
        Statement indexed(db.get(),
            "SELECT 1 FROM file_entries WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE");
        indexed.bind_int(1, area_id);
        indexed.bind_text(2, filename);
        const int result = sqlite3_step(indexed.get());
        indexed.check(result, "checking public file index");
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("file is not published in this file area");
        }
    }

    FileDescriptor root(::open(root_path_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (root.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening public file root");
    }
    FileDescriptor area_root(::openat(root.get(), "areas", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (area_root.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening public file areas");
    }
    const std::string area_name = std::to_string(area_id);
    FileDescriptor area(::openat(area_root.get(), area_name.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (area.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening public file area");
    }
    const std::string file_name(filename);
    FileDescriptor file(::openat(area.get(), file_name.c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening public file");
    }
    struct stat status{};
    if (::fstat(file.get(), &status) != 0) {
        throw std::system_error(errno, std::generic_category(), "checking public file");
    }
    if (!S_ISREG(status.st_mode)) {
        throw std::invalid_argument("public file is not a regular file");
    }
    if (::flock(file.get(), LOCK_SH | LOCK_NB) != 0) {
        throw std::system_error(errno, std::generic_category(), "public file is in an active modification");
    }
    if (!can_download_file(handle, area_id, filename)) {
        throw std::invalid_argument("account does not have access to download this file");
    }
    return file.release();
}

std::vector<DownloadQueueEntry> FileStore::download_queue(std::string_view handle) const {
    if (!valid_account_handle(handle)) {
        throw std::invalid_argument("invalid account handle for download queue");
    }
    const auto visible_areas = areas(handle);
    std::set<int> visible_area_ids;
    for (const FileAreaSummary& area : visible_areas) {
        if (can_download(handle, area.id)) {
            visible_area_ids.insert(area.id);
        }
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement query(db.get(),
        "SELECT q.queue_id, q.area_id, COALESCE(a.name, ''), q.filename, COALESCE(f.size, 0), "
        "CASE WHEN f.filename IS NULL THEN 0 ELSE 1 END "
        "FROM file_download_queue q LEFT JOIN file_areas a ON a.id = q.area_id "
        "LEFT JOIN file_entries f ON f.area_id = q.area_id AND f.filename = q.filename "
        "WHERE q.handle = ?1 COLLATE NOCASE ORDER BY q.queue_id");
    query.bind_text(1, handle);
    std::vector<DownloadQueueEntry> result;
    for (;;) {
        const int step = sqlite3_step(query.get());
        if (step == SQLITE_DONE) {
            break;
        }
        query.check(step, "reading download queue");
        const auto column = [&query](int index) {
            const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(query.get(), index));
            return value == nullptr ? std::string{} : std::string(value);
        };
        const int area_id = sqlite3_column_int(query.get(), 1);
        if (!visible_area_ids.contains(area_id)) {
            continue;
        }
        const std::string filename = column(3);
        if (sqlite3_column_int(query.get(), 5) != 0 && !can_download_file(handle, area_id, filename)) {
            continue;
        }
        result.push_back({sqlite3_column_int64(query.get(), 0), area_id,
            column(2), filename,
            static_cast<std::uint64_t>(std::max<sqlite3_int64>(0, sqlite3_column_int64(query.get(), 4))),
            sqlite3_column_int(query.get(), 5) != 0});
    }
    return result;
}

DownloadQueueAddResult FileStore::tag_download(
    std::string_view handle,
    int area_id,
    std::string_view filename) const {
    if (!valid_account_handle(handle) || area_id < 1 || !valid_file_name(filename)) {
        throw std::invalid_argument("invalid account, area or filename for download queue");
    }
    if (!can_download(handle, area_id)) {
        throw std::invalid_argument("account does not have download access to this file area");
    }
    (void)files(handle, area_id, std::string_view{}, 0, 1);
    if (!can_download_file(handle, area_id, filename)) {
        throw std::invalid_argument("account does not have download access to this file");
    }
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting download queue update");
    try {
        bool is_available = false;
        {
            Statement available(db.get(),
                "SELECT 1 FROM file_entries WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE");
            available.bind_int(1, area_id);
            available.bind_text(2, filename);
            const int available_result = sqlite3_step(available.get());
            available.check(available_result, "checking queued file");
            is_available = available_result == SQLITE_ROW;
        }
        if (!is_available) {
            throw std::invalid_argument("file is no longer published in this file area");
        }
        bool already_queued = false;
        {
            Statement duplicate(db.get(),
                "SELECT 1 FROM file_download_queue WHERE handle = ?1 COLLATE NOCASE "
                "AND area_id = ?2 AND filename = ?3 COLLATE NOCASE");
            duplicate.bind_text(1, handle);
            duplicate.bind_int(2, area_id);
            duplicate.bind_text(3, filename);
            const int duplicate_result = sqlite3_step(duplicate.get());
            duplicate.check(duplicate_result, "checking duplicate queued file");
            already_queued = duplicate_result == SQLITE_ROW;
        }
        if (already_queued) {
            check_exec(db.get(), "COMMIT", "finishing download queue update");
            return DownloadQueueAddResult::AlreadyQueued;
        }
        sqlite3_int64 queue_size = 0;
        {
            Statement count(db.get(),
                "SELECT COUNT(*) FROM file_download_queue WHERE handle = ?1 COLLATE NOCASE");
            count.bind_text(1, handle);
            count.check(sqlite3_step(count.get()), "counting queued downloads");
            queue_size = sqlite3_column_int64(count.get(), 0);
        }
        if (queue_size >= 99) {
            check_exec(db.get(), "COMMIT", "finishing download queue update");
            return DownloadQueueAddResult::Full;
        }
        Statement insert(db.get(),
            "INSERT INTO file_download_queue(handle, area_id, filename) VALUES(?1, ?2, ?3)");
        insert.bind_text(1, handle);
        insert.bind_int(2, area_id);
        insert.bind_text(3, filename);
        insert.check(sqlite3_step(insert.get()), "adding queued download");
        check_exec(db.get(), "COMMIT", "finishing download queue update");
        return DownloadQueueAddResult::Added;
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::remove_queued_download(std::string_view handle, std::int64_t queue_id) const {
    if (!valid_account_handle(handle) || queue_id < 1) {
        throw std::invalid_argument("invalid account or queue position");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement remove(db.get(),
        "DELETE FROM file_download_queue WHERE handle = ?1 COLLATE NOCASE AND queue_id = ?2");
    remove.bind_text(1, handle);
    remove.bind_int64(2, static_cast<sqlite3_int64>(queue_id));
    remove.check(sqlite3_step(remove.get()), "removing queued download");
}

void FileStore::clear_download_queue(std::string_view handle) const {
    if (!valid_account_handle(handle)) {
        throw std::invalid_argument("invalid account handle for download queue");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement clear(db.get(), "DELETE FROM file_download_queue WHERE handle = ?1 COLLATE NOCASE");
    clear.bind_text(1, handle);
    clear.check(sqlite3_step(clear.get()), "clearing download queue");
}

FileUserUsage FileStore::user_usage(std::string_view handle) const {
    if (!valid_account_handle(handle)) {
        throw std::invalid_argument("invalid account handle for file usage lookup");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    Statement query(db.get(),
        "SELECT uploads, uploaded_bytes, downloads, downloaded_bytes "
        "FROM file_user_activity WHERE handle = ?1 COLLATE NOCASE");
    query.bind_text(1, handle);
    const int result = sqlite3_step(query.get());
    query.check(result, "reading account file usage");
    if (result == SQLITE_DONE) {
        return {};
    }
    const auto nonnegative = [&query](int column) {
        return static_cast<std::uint64_t>(std::max<sqlite3_int64>(0,
            sqlite3_column_int64(query.get(), column)));
    };
    return {nonnegative(0), nonnegative(1), nonnegative(2), nonnegative(3)};
}

std::vector<IncomingFile> FileStore::incoming_files() const {
    initialize();
    const std::filesystem::path root = std::filesystem::path(root_path_) / "incoming";
    std::vector<IncomingFile> result;
    std::error_code error;
    for (std::filesystem::directory_iterator owners(
             root, std::filesystem::directory_options::skip_permission_denied, error), end;
         owners != end && result.size() < 10000;
         owners.increment(error)) {
        if (error) {
            error.clear();
            continue;
        }
        const auto owner_entry = *owners;
        std::error_code status_error;
        if (owner_entry.is_symlink(status_error) || status_error ||
            !owner_entry.is_directory(status_error) || status_error) {
            status_error.clear();
            continue;
        }
        const std::string owner = owner_entry.path().filename().string();
        if (!valid_account_handle(owner)) {
            continue;
        }
        std::error_code files_error;
        for (std::filesystem::directory_iterator entries(
                 owner_entry.path(), std::filesystem::directory_options::skip_permission_denied,
                 files_error), files_end;
             entries != files_end && result.size() < 10000;
             entries.increment(files_error)) {
            if (files_error) {
                files_error.clear();
                continue;
            }
            const auto entry = *entries;
            if (entry.is_symlink(status_error) || status_error ||
                !entry.is_regular_file(status_error) || status_error) {
                status_error.clear();
                continue;
            }
            const std::string filename = entry.path().filename().string();
            if (!valid_file_name(filename) || filename == ".renegade-quota-lock") {
                continue;
            }
            const std::uintmax_t size = entry.file_size(status_error);
            if (status_error || size > static_cast<std::uintmax_t>(INT64_MAX)) {
                status_error.clear();
                continue;
            }
            const auto modified = entry.last_write_time(status_error);
            if (status_error) {
                status_error.clear();
                continue;
            }
            result.push_back({owner, filename, static_cast<std::uint64_t>(size), timestamp(modified)});
        }
    }
    std::sort(result.begin(), result.end(), [](const IncomingFile& left, const IncomingFile& right) {
        return left.handle == right.handle ? left.name < right.name : left.handle < right.handle;
    });
    return result;
}

void FileStore::publish_upload(
    std::string_view handle,
    std::string_view filename,
    int area_id) const {
    if (!valid_account_handle(handle) || !valid_file_name(filename) ||
        filename == ".renegade-quota-lock" || area_id < 1) {
        throw std::invalid_argument("invalid upload owner, filename, or file-area ID");
    }
    const auto available = areas();
    if (std::none_of(available.begin(), available.end(), [area_id](const FileAreaSummary& area) {
            return area.id == area_id;
        })) {
        throw std::invalid_argument("file area does not exist");
    }
    if (!can_upload(handle, area_id)) {
        throw std::invalid_argument("account does not have permission to upload into this file area");
    }
    const std::filesystem::path root(root_path_);
    FileDescriptor incoming_root(::open((root / "incoming").c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (incoming_root.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening upload root");
    }
    const std::string owner_name(handle);
    FileDescriptor owner(::openat(incoming_root.get(), owner_name.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (owner.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening upload owner directory");
    }
    const std::string file_name(filename);
    FileDescriptor source(::openat(owner.get(), file_name.c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (source.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening upload file");
    }
    if (::flock(source.get(), LOCK_EX | LOCK_NB) != 0) {
        throw std::system_error(errno, std::generic_category(), "upload is still open for transfer");
    }
    struct stat source_info {};
    if (::fstat(source.get(), &source_info) != 0) {
        throw std::system_error(errno, std::generic_category(), "checking upload file");
    }
    constexpr off_t maximum_upload_bytes = 100 * 1024 * 1024;
    if (!S_ISREG(source_info.st_mode) || source_info.st_size < 0 || source_info.st_size > maximum_upload_bytes) {
        throw std::system_error(EFBIG, std::generic_category(), "upload file is not regular or exceeds 100 MiB");
    }
    const std::optional<EmbeddedDescription> embedded_description = embedded_archive_description(
        source.get(), filename, source_info.st_size);

    FileDescriptor areas_root(::open((root / "areas").c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (areas_root.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening public file-area root");
    }
    const std::string area_name = std::to_string(area_id);
    FileDescriptor area(::openat(areas_root.get(), area_name.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (area.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening destination file area");
    }
    FileDescriptor destination(::openat(area.get(), file_name.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644));
    if (destination.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "creating public file-area entry");
    }
    bool remove_partial = true;
    try {
        copy_upload(source.get(), destination.get(), source_info.st_size);
        if (::fsync(destination.get()) != 0) {
            throw std::system_error(errno, std::generic_category(), "syncing published file");
        }
        struct stat source_after_copy {};
        if (::fstat(source.get(), &source_after_copy) != 0 ||
            source_after_copy.st_size != source_info.st_size ||
            source_after_copy.st_mtim.tv_sec != source_info.st_mtim.tv_sec ||
            source_after_copy.st_mtim.tv_nsec != source_info.st_mtim.tv_nsec) {
            throw std::system_error(EAGAIN, std::generic_category(), "upload changed during publication");
        }
        destination.reset();
        {
            Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
            check_exec(db.get(), "BEGIN IMMEDIATE", "starting published-file index update");
            try {
                synchronize_area(db.get(), root, area_id);
                const std::uint64_t file_points = calculate_file_point_cost(
                    db.get(), static_cast<std::uint64_t>(source_info.st_size));
                Statement owner_update(db.get(),
                    "UPDATE file_entries SET owner_handle = ?1, file_points = ?2, validated = 1, "
                    "uploader_credited = 0, uploader_credit_amount = 0 "
                    "WHERE area_id = ?3 AND filename = ?4 COLLATE NOCASE");
                owner_update.bind_text(1, handle);
                owner_update.bind_int64(2, static_cast<sqlite3_int64>(file_points));
                owner_update.bind_int(3, area_id);
                owner_update.bind_text(4, filename);
                owner_update.check(sqlite3_step(owner_update.get()), "recording published-file owner");
                if (sqlite3_changes(db.get()) == 0) {
                    throw std::runtime_error("published file was not added to its area index");
                }
                credit_validated_file_uploader(db.get(), area_id, filename);
                check_exec(db.get(), "COMMIT", "saving published-file index update");
            } catch (...) {
                (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
                throw;
            }
        }
        if (::unlinkat(owner.get(), file_name.c_str(), 0) != 0) {
            throw std::system_error(errno, std::generic_category(), "removing published upload from inbox");
        }
        remove_partial = false;
        if (embedded_description.has_value()) {
            try {
                if (!embedded_description->summary.empty()) {
                    set_description(area_id, filename, embedded_description->summary);
                }
                if (!embedded_description->extended.empty()) {
                    set_extended_description(area_id, filename, embedded_description->extended);
                }
            } catch (const std::exception& error) {
                std::cerr << "Published " << filename << " but could not import its archive description: "
                          << error.what() << '\n';
            }
        }
    } catch (...) {
        destination.reset();
        if (remove_partial) {
            (void)::unlinkat(area.get(), file_name.c_str(), 0);
        }
        throw;
    }
}

void FileStore::mark_public_upload_pending(
    std::string_view handle,
    int area_id,
    std::string_view filename) const {
    if (!valid_account_handle(handle) || area_id < 1 || !valid_file_name(filename) ||
        filename == ".renegade-quota-lock") {
        throw std::invalid_argument("invalid uploader, area or filename for public upload");
    }
    if (!can_upload(handle, area_id)) {
        throw std::invalid_argument("account does not have permission to upload into this file area");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    synchronize_area(db.get(), root_path_, area_id);
    Statement update(db.get(),
        "UPDATE file_entries SET owner_handle = ?1, validated = 0 "
        "WHERE area_id = ?2 AND filename = ?3 COLLATE NOCASE AND owner_handle = ''");
    update.bind_text(1, handle);
    update.bind_int(2, area_id);
    update.bind_text(3, filename);
    update.check(sqlite3_step(update.get()), "marking direct upload unvalidated");
    if (sqlite3_changes(db.get()) == 0) {
        throw std::runtime_error("direct upload was not added to its file-area index");
    }
}

void FileStore::complete_public_upload(
    std::string_view handle,
    int area_id,
    std::string_view filename) const {
    if (!valid_account_handle(handle) || area_id < 1 || !valid_file_name(filename) ||
        filename == ".renegade-quota-lock") {
        throw std::invalid_argument("invalid uploader, area or filename for completed public upload");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting completed public upload update");
    try {
        synchronize_area(db.get(), root_path_, area_id);
        AccessLevels uploader_levels = account_access_levels(db.get(), handle);
        uploader_levels.file_area_number = area_id;
        const bool validate_all = file_store_setting(db.get(), "validate_all_files", "0") == "1";
        const bool auto_validate = validate_all || evaluate_legacy_acs(
            file_store_setting(db.get(), "upload_auto_validate_acs", "S255"), uploader_levels);
        std::uint64_t size = 0;
        {
            Statement file(db.get(),
                "SELECT size FROM file_entries WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE "
                "AND owner_handle = ?3 COLLATE NOCASE");
            file.bind_int(1, area_id);
            file.bind_text(2, filename);
            file.bind_text(3, handle);
            const int result = sqlite3_step(file.get());
            file.check(result, "reading completed public upload size");
            if (result != SQLITE_ROW) {
                throw std::runtime_error("completed upload is missing from its file-area index");
            }
            size = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                0, sqlite3_column_int64(file.get(), 0)));
        }
        const std::uint64_t file_points = calculate_file_point_cost(db.get(), size);
        Statement update(db.get(),
            "UPDATE file_entries SET owner_handle = ?1, validated = ?2, file_points = ?3, "
            "uploader_credited = 0, uploader_credit_amount = 0 WHERE area_id = ?4 AND filename = ?5 COLLATE NOCASE "
            "AND owner_handle = ?1 COLLATE NOCASE");
        update.bind_text(1, handle);
        update.bind_int(2, auto_validate ? 1 : 0);
        update.bind_int64(3, static_cast<sqlite3_int64>(file_points));
        update.bind_int(4, area_id);
        update.bind_text(5, filename);
        update.check(sqlite3_step(update.get()), "saving completed public upload state");
        if (sqlite3_changes(db.get()) == 0) {
            throw std::runtime_error("completed upload is missing from its file-area index");
        }
        if (auto_validate) {
            credit_validated_file_uploader(db.get(), area_id, filename);
        }
        check_exec(db.get(), "COMMIT", "saving completed public upload state");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }

    std::optional<EmbeddedDescription> embedded_description;
    {
        FileDescriptor root(::open(root_path_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (root.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file root");
        }
        FileDescriptor areas_root(::openat(root.get(), "areas",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (areas_root.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening public file areas");
        }
        const std::string area_name = std::to_string(area_id);
        FileDescriptor area(::openat(areas_root.get(), area_name.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (area.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening uploaded file area");
        }
        const std::string file_name(filename);
        FileDescriptor file(::openat(area.get(), file_name.c_str(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        if (file.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "opening completed public upload");
        }
        struct stat info {};
        if (::fstat(file.get(), &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0) {
            throw std::system_error(errno == 0 ? EIO : errno, std::generic_category(),
                "checking completed public upload");
        }
        embedded_description = embedded_archive_description(file.get(), filename, info.st_size);
    }
    if (embedded_description.has_value()) {
        try {
            if (!embedded_description->summary.empty()) {
                set_description(area_id, filename, embedded_description->summary);
            }
            if (!embedded_description->extended.empty()) {
                set_extended_description(area_id, filename, embedded_description->extended);
            }
        } catch (const std::exception& error) {
            std::cerr << "Completed public upload " << filename
                      << " but could not import its archive description: " << error.what() << '\n';
        }
    }
}

void FileStore::delete_upload(std::string_view handle, std::string_view filename) const {
    if (!valid_account_handle(handle) || !valid_file_name(filename) ||
        filename == ".renegade-quota-lock") {
        throw std::invalid_argument("invalid upload owner or filename");
    }
    initialize();
    const std::filesystem::path root(root_path_);
    FileDescriptor incoming_root(::open((root / "incoming").c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (incoming_root.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening upload root");
    }
    const std::string owner_name(handle);
    FileDescriptor owner(::openat(incoming_root.get(), owner_name.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (owner.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening upload owner directory");
    }
    const std::string file_name(filename);
    FileDescriptor source(::openat(owner.get(), file_name.c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (source.get() < 0) {
        throw std::system_error(errno, std::generic_category(), "opening upload file");
    }
    if (::flock(source.get(), LOCK_EX | LOCK_NB) != 0) {
        throw std::system_error(errno, std::generic_category(), "upload is still open for transfer");
    }
    struct stat opened_info {};
    struct stat path_info {};
    if (::fstat(source.get(), &opened_info) != 0 || !S_ISREG(opened_info.st_mode) ||
        ::fstatat(owner.get(), file_name.c_str(), &path_info, AT_SYMLINK_NOFOLLOW) != 0 ||
        path_info.st_dev != opened_info.st_dev || path_info.st_ino != opened_info.st_ino) {
        throw std::system_error(EAGAIN, std::generic_category(), "upload changed during removal");
    }
    if (::unlinkat(owner.get(), file_name.c_str(), 0) != 0) {
        throw std::system_error(errno, std::generic_category(), "removing upload file");
    }
}

void FileStore::set_description(
    int area_id,
    std::string_view filename,
    std::string_view description) const {
    if (area_id < 1 || !valid_file_name(filename) || description.size() > 160) {
        throw std::invalid_argument("invalid file area, filename, or description length");
    }
    for (const unsigned char value : description) {
        if (value < 0x20 || value == 0x7f || value == 0x1b) {
            throw std::invalid_argument("file descriptions must be single-line printable text");
        }
    }
    (void)files({}, area_id, {}, 0);
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement update(db.get(),
        "UPDATE file_entries SET description = ?1 WHERE area_id = ?2 AND filename = ?3 COLLATE NOCASE");
    update.bind_text(1, description);
    update.bind_int(2, area_id);
    update.bind_text(3, filename);
    update.check(sqlite3_step(update.get()), "updating file description");
    if (sqlite3_changes(db.get()) == 0) {
        throw std::invalid_argument("file does not exist in that area");
    }
}

void FileStore::set_extended_description(
    int area_id,
    std::string_view filename,
    std::string_view description) const {
    if (area_id < 1 || !valid_file_name(filename) || description.size() > 5048) {
        throw std::invalid_argument("invalid file area, filename, or extended description length");
    }
    std::size_t line_start = 0;
    std::size_t line_count = 0;
    while (line_start <= description.size()) {
        const std::size_t newline = description.find('\n', line_start);
        const std::size_t line_end = newline == std::string_view::npos ? description.size() : newline;
        if (line_end - line_start > 50) {
            throw std::invalid_argument("extended description lines may contain at most 50 bytes");
        }
        for (const unsigned char value : description.substr(line_start, line_end - line_start)) {
            if (value < 0x20 || value == 0x7f || value == 0x1b) {
                throw std::invalid_argument("extended descriptions must contain printable text only");
            }
        }
        ++line_count;
        if (line_count > 99 || newline == std::string_view::npos) {
            break;
        }
        line_start = newline + 1;
    }
    (void)files({}, area_id, {}, 0);
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement update(db.get(),
        "UPDATE file_entries SET extended_description = ?1 "
        "WHERE area_id = ?2 AND filename = ?3 COLLATE NOCASE");
    update.bind_text(1, description);
    update.bind_int(2, area_id);
    update.bind_text(3, filename);
    update.check(sqlite3_step(update.get()), "updating file extended description");
    if (sqlite3_changes(db.get()) == 0) {
        throw std::invalid_argument("file does not exist in that area");
    }
}

void FileStore::set_download_count(
    std::string_view actor,
    int area_id,
    std::string_view filename,
    std::uint64_t download_count) const {
    if (!valid_account_handle(actor) || area_id < 1 || !valid_file_name(filename) ||
        download_count > static_cast<std::uint64_t>(INT_MAX)) {
        throw std::invalid_argument("invalid account, area, filename or download count");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file download-count update");
    try {
        bool is_sysop = false;
        {
            Statement moderator(db.get(), "SELECT is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
            moderator.bind_text(1, actor);
            const int result = sqlite3_step(moderator.get());
            moderator.check(result, "checking file download-count permission");
            is_sysop = result == SQLITE_ROW && sqlite3_column_int(moderator.get(), 0) != 0;
        }
        if (!is_sysop) {
            throw std::invalid_argument("only a SysOp can change a file download count");
        }
        synchronize_area(db.get(), root_path_, area_id);
        Statement update(db.get(),
            "UPDATE file_entries SET download_count = ?1 WHERE area_id = ?2 AND filename = ?3 COLLATE NOCASE");
        update.bind_int64(1, static_cast<sqlite3_int64>(download_count));
        update.bind_int(2, area_id);
        update.bind_text(3, filename);
        update.check(sqlite3_step(update.get()), "updating file download count");
        if (sqlite3_changes(db.get()) == 0) {
            throw std::invalid_argument("file is not indexed in the selected area");
        }
        check_exec(db.get(), "COMMIT", "saving file download-count update");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

std::optional<std::int64_t> FileStore::reserve_download_points(
    std::string_view downloader,
    int area_id,
    std::string_view filename) const {
    if (!valid_account_handle(downloader) || area_id < 1 || !valid_file_name(filename)) {
        throw std::invalid_argument("invalid account, file area, or filename for file-point reservation");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file-point reservation");
    try {
        std::uint64_t points = 0;
        bool no_ratio = false;
        {
            Statement file(db.get(),
                "SELECT f.file_points, a.no_ratio FROM file_entries f "
                "JOIN file_areas a ON a.id = f.area_id "
                "WHERE f.area_id = ?1 AND f.filename = ?2 COLLATE NOCASE");
            file.bind_int(1, area_id);
            file.bind_text(2, filename);
            const int result = sqlite3_step(file.get());
            file.check(result, "reading file-point cost");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("file is not indexed in this area");
            }
            points = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                0, sqlite3_column_int64(file.get(), 0)));
            no_ratio = sqlite3_column_int(file.get(), 1) != 0;
        }
        AccessLevels levels = account_access_levels(db.get(), downloader);
        levels.file_area_number = area_id;
        const bool no_file_credits = evaluate_legacy_acs(
            file_store_setting(db.get(), "no_file_credits_acs", "%"), levels);
        if (points == 0 || no_ratio || levels.ac_flags.find('3') != std::string::npos ||
            no_file_credits || file_store_setting(db.get(), "file_points_enabled", "0") != "1") {
            check_exec(db.get(), "COMMIT", "finishing file-point check");
            return std::nullopt;
        }
        std::int64_t balance = 0;
        {
            Statement account(db.get(),
                "SELECT file_points FROM accounts WHERE handle = ?1 COLLATE NOCASE");
            account.bind_text(1, downloader);
            const int result = sqlite3_step(account.get());
            account.check(result, "reading account file-point balance");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("BBS account does not exist");
            }
            balance = sqlite3_column_int64(account.get(), 0);
        }
        if (points > static_cast<std::uint64_t>(std::max<std::int64_t>(0, balance))) {
            throw std::invalid_argument("not enough file points to download this file");
        }
        {
            Statement debit(db.get(),
                "UPDATE accounts SET file_points = file_points - ?1 "
                "WHERE handle = ?2 COLLATE NOCASE AND file_points >= ?1");
            debit.bind_int64(1, static_cast<sqlite3_int64>(points));
            debit.bind_text(2, downloader);
            debit.check(sqlite3_step(debit.get()), "reserving account file points");
            if (sqlite3_changes(db.get()) == 0) {
                throw std::invalid_argument("not enough file points to download this file");
            }
        }
        {
            Statement reservation(db.get(),
                "INSERT INTO file_point_reservations(handle, points) VALUES(?1, ?2)");
            reservation.bind_text(1, downloader);
            reservation.bind_int64(2, static_cast<sqlite3_int64>(points));
            reservation.check(sqlite3_step(reservation.get()), "saving file-point reservation");
        }
        const std::int64_t reservation_id = sqlite3_last_insert_rowid(db.get());
        check_exec(db.get(), "COMMIT", "saving file-point reservation");
        return reservation_id;
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::cancel_download_points(std::int64_t reservation_id) const {
    if (reservation_id <= 0) {
        return;
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file-point reservation refund");
    try {
        std::string handle;
        std::uint64_t points = 0;
        {
            Statement reservation(db.get(),
                "SELECT handle, points FROM file_point_reservations WHERE reservation_id = ?1");
            reservation.bind_int64(1, reservation_id);
            const int result = sqlite3_step(reservation.get());
            reservation.check(result, "reading file-point reservation");
            if (result == SQLITE_DONE) {
                check_exec(db.get(), "COMMIT", "finishing file-point reservation refund");
                return;
            }
            const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(reservation.get(), 0));
            handle = value == nullptr ? std::string{} : std::string(value);
            points = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                0, sqlite3_column_int64(reservation.get(), 1)));
        }
        Statement refund(db.get(),
            "UPDATE accounts SET file_points = MIN(2147483647, file_points + ?1) "
            "WHERE handle = ?2 COLLATE NOCASE");
        refund.bind_int64(1, static_cast<sqlite3_int64>(points));
        refund.bind_text(2, handle);
        refund.check(sqlite3_step(refund.get()), "refunding reserved file points");
        Statement remove(db.get(), "DELETE FROM file_point_reservations WHERE reservation_id = ?1");
        remove.bind_int64(1, reservation_id);
        remove.check(sqlite3_step(remove.get()), "removing file-point reservation");
        check_exec(db.get(), "COMMIT", "saving file-point reservation refund");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

std::optional<std::int64_t> FileStore::reserve_daily_download(
    std::string_view downloader,
    int area_id,
    std::string_view filename) const {
    if (!valid_account_handle(downloader) || area_id < 1 || !valid_file_name(filename)) {
        throw std::invalid_argument("invalid account, file area, or filename for daily-limit check");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting daily download-limit check");
    try {
        std::uint64_t size = 0;
        bool area_exempt = false;
        {
            Statement file(db.get(),
                "SELECT f.size, a.no_ratio FROM file_entries f JOIN file_areas a ON a.id = f.area_id "
                "WHERE f.area_id = ?1 AND f.filename = ?2 COLLATE NOCASE");
            file.bind_int(1, area_id);
            file.bind_text(2, filename);
            const int result = sqlite3_step(file.get());
            file.check(result, "reading file for daily-limit check");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("file is not indexed in this area");
            }
            size = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                0, sqlite3_column_int64(file.get(), 0)));
            area_exempt = sqlite3_column_int(file.get(), 1) != 0;
        }
        AccessLevels levels = account_access_levels(db.get(), downloader);
        levels.file_area_number = area_id;
        const bool ratio_exempt = area_exempt || levels.ac_flags.find('1') != std::string::npos ||
            evaluate_legacy_acs(file_store_setting(db.get(), "no_download_ratio_acs", "S255"), levels);
        const bool daily_active = file_store_setting(db.get(), "daily_file_limits_enabled", "0") == "1" &&
            !ratio_exempt;
        std::uint64_t count_ratio_limit = file_store_unsigned_setting(db.get(), "download_count_ratio");
        std::uint64_t kib_ratio_limit = file_store_unsigned_setting(db.get(), "download_kib_ratio");
        {
            Statement level_ratio(db.get(),
                "SELECT max_downloads_per_upload, max_kib_per_uploaded_kib "
                "FROM file_download_level_ratios WHERE security_level = ?1");
            level_ratio.bind_int(1, levels.security_level);
            const int result = sqlite3_step(level_ratio.get());
            level_ratio.check(result, "reading per-level ratio for transfer reservation");
            if (result == SQLITE_ROW) {
                count_ratio_limit = static_cast<std::uint64_t>(sqlite3_column_int64(level_ratio.get(), 0));
                kib_ratio_limit = static_cast<std::uint64_t>(sqlite3_column_int64(level_ratio.get(), 1));
            }
        }
        const bool ratio_active = file_store_setting(db.get(), "download_ratios_enabled", "0") == "1" &&
            !ratio_exempt && (count_ratio_limit > 0 || kib_ratio_limit > 0);
        if (!daily_active && !ratio_active) {
            check_exec(db.get(), "COMMIT", "finishing daily download-limit check");
            return std::nullopt;
        }
        const std::uint64_t file_kib = size / 1024U;
        if (daily_active) {
            std::uint64_t max_files = 2147483647U;
            std::uint64_t max_kib = 2147483647U;
            {
                Statement limit(db.get(),
                    "SELECT max_files, max_kib FROM file_daily_download_limits WHERE security_level = ?1");
                limit.bind_int(1, levels.security_level);
                const int result = sqlite3_step(limit.get());
                limit.check(result, "reading per-level daily download limit");
                if (result == SQLITE_ROW) {
                    max_files = static_cast<std::uint64_t>(sqlite3_column_int64(limit.get(), 0));
                    max_kib = static_cast<std::uint64_t>(sqlite3_column_int64(limit.get(), 1));
                }
            }
            std::uint64_t completed_files = 0;
            std::uint64_t completed_kib = 0;
            {
                Statement activity(db.get(),
                    "SELECT downloads_today, downloaded_kib_today FROM file_user_activity "
                    "WHERE handle = ?1 COLLATE NOCASE AND download_activity_day = date('now', 'localtime')");
                activity.bind_text(1, downloader);
                const int result = sqlite3_step(activity.get());
                activity.check(result, "reading today's download activity");
                if (result == SQLITE_ROW) {
                    completed_files = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                        0, sqlite3_column_int64(activity.get(), 0)));
                    completed_kib = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                        0, sqlite3_column_int64(activity.get(), 1)));
                }
            }
            std::uint64_t reserved_files = 0;
            std::uint64_t reserved_kib = 0;
            {
                Statement reservations(db.get(),
                    "SELECT COUNT(*), COALESCE(SUM(file_kib), 0) FROM file_daily_download_reservations "
                    "WHERE handle = ?1 COLLATE NOCASE AND reserved_day = date('now', 'localtime')");
                reservations.bind_text(1, downloader);
                const int result = sqlite3_step(reservations.get());
                reservations.check(result, "reading active daily download reservations");
                reserved_files = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                    0, sqlite3_column_int64(reservations.get(), 0)));
                reserved_kib = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                    0, sqlite3_column_int64(reservations.get(), 1)));
            }
            const std::uint64_t used_files = saturating_add(completed_files, reserved_files);
            const std::uint64_t used_kib = saturating_add(completed_kib, reserved_kib);
            if (used_files >= max_files || used_kib > max_kib || file_kib > max_kib - used_kib) {
                throw std::invalid_argument("daily download limit would be exceeded");
            }
        }
        if (ratio_active) {
            std::uint64_t uploaded_files = 0;
            std::uint64_t uploaded_kib = 0;
            std::uint64_t downloaded_files = 0;
            std::uint64_t downloaded_kib = 0;
            {
                Statement activity(db.get(),
                    "SELECT uploads, uploaded_kib, downloads, downloaded_kib "
                    "FROM file_user_activity WHERE handle = ?1 COLLATE NOCASE");
                activity.bind_text(1, downloader);
                const int result = sqlite3_step(activity.get());
                activity.check(result, "reading activity for download-ratio reservation");
                if (result == SQLITE_ROW) {
                    uploaded_files = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                        0, sqlite3_column_int64(activity.get(), 0)));
                    uploaded_kib = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                        0, sqlite3_column_int64(activity.get(), 1)));
                    downloaded_files = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                        0, sqlite3_column_int64(activity.get(), 2)));
                    downloaded_kib = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                        0, sqlite3_column_int64(activity.get(), 3)));
                }
            }
            std::uint64_t reserved_files = 0;
            std::uint64_t reserved_kib = 0;
            {
                Statement reservations(db.get(),
                    "SELECT COUNT(*), COALESCE(SUM(file_kib), 0) FROM file_daily_download_reservations "
                    "WHERE handle = ?1 COLLATE NOCASE");
                reservations.bind_text(1, downloader);
                const int result = sqlite3_step(reservations.get());
                reservations.check(result, "reading active downloads for ratio reservation");
                reserved_files = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                    0, sqlite3_column_int64(reservations.get(), 0)));
                reserved_kib = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                    0, sqlite3_column_int64(reservations.get(), 1)));
            }
            if (exceeds_ratio(saturating_add(saturating_add(downloaded_files, reserved_files), 1),
                    uploaded_files, count_ratio_limit) ||
                exceeds_ratio(saturating_add(saturating_add(downloaded_kib, reserved_kib), file_kib),
                    uploaded_kib, kib_ratio_limit)) {
                throw std::invalid_argument("download ratio would be exceeded");
            }
        }
        {
            Statement reservation(db.get(),
                "INSERT INTO file_daily_download_reservations(handle, file_kib, reserved_day) "
                "VALUES(?1, ?2, date('now', 'localtime'))");
            reservation.bind_text(1, downloader);
            reservation.bind_int64(2, static_cast<sqlite3_int64>(file_kib));
            reservation.check(sqlite3_step(reservation.get()), "reserving daily download allowance");
        }
        const std::int64_t reservation_id = sqlite3_last_insert_rowid(db.get());
        check_exec(db.get(), "COMMIT", "reserving daily download allowance");
        return reservation_id;
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::cancel_daily_download(std::int64_t reservation_id) const {
    if (reservation_id <= 0) {
        return;
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement remove(db.get(), "DELETE FROM file_daily_download_reservations WHERE reservation_id = ?1");
    remove.bind_int64(1, reservation_id);
    remove.check(sqlite3_step(remove.get()), "releasing daily download allowance");
}

void FileStore::recover_download_point_reservations() const {
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file-point reservation recovery");
    try {
        Statement refund(db.get(),
            "UPDATE accounts SET file_points = MIN(2147483647, file_points + "
            "COALESCE((SELECT SUM(points) FROM file_point_reservations r "
            "WHERE r.handle = accounts.handle COLLATE NOCASE), 0)) "
            "WHERE EXISTS (SELECT 1 FROM file_point_reservations r "
            "WHERE r.handle = accounts.handle COLLATE NOCASE)");
        refund.check(sqlite3_step(refund.get()), "refunding interrupted file-point downloads");
        Statement clear(db.get(), "DELETE FROM file_point_reservations");
        clear.check(sqlite3_step(clear.get()), "clearing interrupted file-point reservations");
        Statement clear_daily(db.get(), "DELETE FROM file_daily_download_reservations");
        clear_daily.check(sqlite3_step(clear_daily.get()), "clearing interrupted daily download reservations");
        check_exec(db.get(), "COMMIT", "saving file-point reservation recovery");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

std::optional<FilePointReward> FileStore::record_download(
    int area_id,
    std::string_view filename,
    std::string_view downloader,
    std::optional<std::int64_t> points_reservation,
    std::optional<std::int64_t> daily_reservation) const {
    if (area_id < 1 || !valid_file_name(filename) || !valid_account_handle(downloader)) {
        throw std::invalid_argument("invalid file area or filename");
    }
    (void)files({}, area_id, {}, 0);
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_exec(db.get(), "BEGIN IMMEDIATE", "starting file-download accounting");
    try {
        std::optional<FilePointReward> point_reward;
        std::uint64_t size = 0;
        std::uint64_t file_points = 0;
        std::string owner;
        {
            Statement file(db.get(),
                "SELECT size, file_points, owner_handle FROM file_entries "
                "WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE");
            file.bind_int(1, area_id);
            file.bind_text(2, filename);
            const int result = sqlite3_step(file.get());
            file.check(result, "reading downloaded file accounting");
            if (result != SQLITE_ROW) {
                throw std::invalid_argument("downloaded file no longer exists in that area");
            }
            size = static_cast<std::uint64_t>(std::max<sqlite3_int64>(0, sqlite3_column_int64(file.get(), 0)));
            file_points = static_cast<std::uint64_t>(std::max<sqlite3_int64>(
                0, sqlite3_column_int64(file.get(), 1)));
            const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(file.get(), 2));
            owner = value == nullptr ? std::string{} : std::string(value);
        }
        if (points_reservation.has_value()) {
            Statement reservation(db.get(),
                "DELETE FROM file_point_reservations WHERE reservation_id = ?1 AND handle = ?2 COLLATE NOCASE");
            reservation.bind_int64(1, *points_reservation);
            reservation.bind_text(2, downloader);
            reservation.check(sqlite3_step(reservation.get()), "settling file-point reservation");
            if (sqlite3_changes(db.get()) == 0) {
                throw std::invalid_argument("file-point download reservation is no longer active");
            }
        }
        if (daily_reservation.has_value()) {
            Statement reservation(db.get(),
                "DELETE FROM file_daily_download_reservations "
                "WHERE reservation_id = ?1 AND handle = ?2 COLLATE NOCASE");
            reservation.bind_int64(1, *daily_reservation);
            reservation.bind_text(2, downloader);
            reservation.check(sqlite3_step(reservation.get()), "settling daily download reservation");
            if (sqlite3_changes(db.get()) == 0) {
                throw std::invalid_argument("daily download reservation is no longer active");
            }
        }
        {
            Statement update(db.get(),
                "UPDATE file_entries SET download_count = CASE "
                "WHEN download_count < 9223372036854775807 THEN download_count + 1 "
                "ELSE download_count END WHERE area_id = ?1 AND filename = ?2 COLLATE NOCASE");
            update.bind_int(1, area_id);
            update.bind_text(2, filename);
            update.check(sqlite3_step(update.get()), "recording file download");
            if (sqlite3_changes(db.get()) == 0) {
                throw std::invalid_argument("downloaded file no longer exists in that area");
            }
        }
        {
            Statement activity(db.get(),
                "INSERT INTO file_user_activity(handle, downloads, downloaded_bytes, downloaded_kib, "
                "downloads_today, downloaded_kib_today, download_activity_day) "
                "VALUES(?1, 1, ?2, ?3, 1, ?3, date('now', 'localtime')) "
                "ON CONFLICT(handle) DO UPDATE SET downloads = "
                "CASE WHEN downloads < 9223372036854775807 THEN downloads + 1 ELSE downloads END, "
                "downloaded_bytes = CASE WHEN downloaded_bytes <= 9223372036854775807 - excluded.downloaded_bytes "
                "THEN downloaded_bytes + excluded.downloaded_bytes ELSE 9223372036854775807 END, "
                "downloaded_kib = CASE WHEN downloaded_kib <= 9223372036854775807 - excluded.downloaded_kib "
                "THEN downloaded_kib + excluded.downloaded_kib ELSE 9223372036854775807 END, "
                "downloads_today = CASE WHEN download_activity_day = date('now', 'localtime') "
                "THEN MIN(2147483647, downloads_today + 1) ELSE 1 END, "
                "downloaded_kib_today = CASE WHEN download_activity_day = date('now', 'localtime') "
                "THEN MIN(2147483647, downloaded_kib_today + excluded.downloaded_kib_today) "
                "ELSE excluded.downloaded_kib_today END, "
                "download_activity_day = date('now', 'localtime')");
            activity.bind_text(1, downloader);
            activity.bind_int64(2, static_cast<sqlite3_int64>(size));
            activity.bind_int64(3, static_cast<sqlite3_int64>(size / 1024U));
            activity.check(sqlite3_step(activity.get()), "recording account download activity");
        }
        const std::uint64_t reward_ratio = file_store_unsigned_setting(db.get(), "file_points_reward_ratio");
        const std::uint64_t reward_multiplier = reward_ratio / 100U;
        const std::string downloader_handle(downloader);
        if (!owner.empty() && ::strcasecmp(owner.c_str(), downloader_handle.c_str()) != 0 &&
            reward_multiplier > 0 && file_points > 0) {
            const std::uint64_t reward = std::min<std::uint64_t>(INT_MAX, file_points * reward_multiplier);
            if (reward > 0) {
                Statement credit(db.get(),
                    "UPDATE accounts SET file_points = MIN(2147483647, file_points + ?1) "
                    "WHERE handle = ?2 COLLATE NOCASE");
                credit.bind_int64(1, static_cast<sqlite3_int64>(reward));
                credit.bind_text(2, owner);
                credit.check(sqlite3_step(credit.get()), "rewarding file owner for download");
                if (sqlite3_changes(db.get()) != 0) {
                    point_reward = FilePointReward{owner, std::string(filename), reward};
                }
            }
        }
        check_exec(db.get(), "COMMIT", "saving file-download accounting");
        return point_reward;
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void FileStore::record_upload(
    std::string_view uploader,
    std::string_view filename,
    std::uint64_t size) const {
    if (!valid_account_handle(uploader) || !valid_file_name(filename) || size > 100U * 1024U * 1024U ||
        size > static_cast<std::uint64_t>(INT64_MAX)) {
        throw std::invalid_argument("invalid account, filename, or size for upload accounting");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement activity(db.get(),
        "INSERT INTO file_user_activity(handle, uploads, uploaded_bytes, uploaded_kib) VALUES(?1, 1, ?2, ?3) "
        "ON CONFLICT(handle) DO UPDATE SET uploads = "
        "CASE WHEN uploads < 9223372036854775807 THEN uploads + 1 ELSE uploads END, "
        "uploaded_bytes = CASE WHEN uploaded_bytes <= 9223372036854775807 - excluded.uploaded_bytes "
        "THEN uploaded_bytes + excluded.uploaded_bytes ELSE 9223372036854775807 END, "
        "uploaded_kib = CASE WHEN uploaded_kib <= 9223372036854775807 - excluded.uploaded_kib "
        "THEN uploaded_kib + excluded.uploaded_kib ELSE 9223372036854775807 END");
    activity.bind_text(1, uploader);
    activity.bind_int64(2, static_cast<sqlite3_int64>(size));
    activity.bind_int64(3, static_cast<sqlite3_int64>(size / 1024U));
    activity.check(sqlite3_step(activity.get()), "recording account upload activity");
}

FilePage FileStore::files(
    std::string_view viewer,
    int area_id,
    std::string_view search,
    std::size_t page,
    std::size_t page_size) const {
    if (area_id < 1) {
        throw std::invalid_argument("file area number must be positive");
    }
    if (page_size < 1 || page_size > 100) {
        throw std::invalid_argument("file listing page size must be between 1 and 100");
    }
    initialize();
    if (!viewer.empty()) {
        const auto visible_areas = areas(viewer);
        if (std::none_of(visible_areas.begin(), visible_areas.end(), [area_id](const FileAreaSummary& area) {
                return area.id == area_id;
            })) {
            throw std::invalid_argument("file area is not available to this account");
        }
    }
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement existence(db.get(), "SELECT 1 FROM file_areas WHERE id = ?1");
    existence.bind_int(1, area_id);
    const int area_result = sqlite3_step(existence.get());
    if (area_result == SQLITE_DONE) {
        throw std::invalid_argument("file area does not exist");
    }
    existence.check(area_result, "checking file area");
    synchronize_area(db.get(), root_path_, area_id);

    const std::string pattern = "%" + std::string(search) + "%";
    AccessLevels viewer_levels = viewer.empty() ? AccessLevels{} : account_access_levels(db.get(), viewer);
    viewer_levels.file_area_number = area_id;
    const bool see_unvalidated = viewer.empty() || evaluate_legacy_acs(
        file_store_setting(db.get(), "see_unvalidated_acs", "S255"), viewer_levels);
    const std::string visibility =
        "(?5 = 1 OR f.validated = 1 OR f.owner_handle = ?4 COLLATE NOCASE)";
    Statement total(db.get(),
        ("SELECT COUNT(*) FROM file_entries f WHERE f.area_id = ?1 AND "
        "(?2 = '' OR filename LIKE ?3 COLLATE NOCASE OR description LIKE ?3 COLLATE NOCASE "
        "OR extended_description LIKE ?3 COLLATE NOCASE) AND " + visibility).c_str());
    total.bind_int(1, area_id);
    total.bind_text(2, search);
    total.bind_text(3, pattern);
    total.bind_text(4, viewer);
    total.bind_int(5, see_unvalidated ? 1 : 0);
    total.check(sqlite3_step(total.get()), "counting file-area entries");
    FilePage result;
    result.total = static_cast<std::uint64_t>(sqlite3_column_int64(total.get(), 0));
    result.page_count = std::max<std::size_t>(1,
        static_cast<std::size_t>((result.total + page_size - 1) / page_size));
    result.page = std::min(page, result.page_count - 1);
    const std::size_t offset = result.page * page_size;

    Statement query(db.get(),
        ("SELECT f.filename, f.description, f.extended_description, f.owner_handle, f.size, "
        "f.modified_at, f.download_count, f.file_points, f.validated, f.request_only FROM file_entries f "
        "WHERE f.area_id = ?1 AND (?2 = '' OR f.filename LIKE ?3 COLLATE NOCASE "
        "OR f.description LIKE ?3 COLLATE NOCASE OR f.extended_description LIKE ?3 COLLATE NOCASE) AND " +
        visibility + " ORDER BY f.filename COLLATE NOCASE LIMIT ?6 OFFSET ?7").c_str());
    query.bind_int(1, area_id);
    query.bind_text(2, search);
    query.bind_text(3, pattern);
    query.bind_text(4, viewer);
    query.bind_int(5, see_unvalidated ? 1 : 0);
    query.bind_int64(6, static_cast<sqlite3_int64>(page_size));
    query.bind_int64(7, static_cast<sqlite3_int64>(offset));
    for (;;) {
        const int step = sqlite3_step(query.get());
        if (step == SQLITE_DONE) {
            break;
        }
        query.check(step, "listing file-area entries");
        const auto column = [&query](int index) {
            const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(query.get(), index));
            return value == nullptr ? std::string{} : std::string(value);
        };
        result.files.push_back({column(0), column(1), column(2), column(3),
            static_cast<std::uint64_t>(sqlite3_column_int64(query.get(), 4)), column(5),
            static_cast<std::uint64_t>(sqlite3_column_int64(query.get(), 6)),
            static_cast<std::uint64_t>(sqlite3_column_int64(query.get(), 7)),
            sqlite3_column_int(query.get(), 8) != 0,
            sqlite3_column_int(query.get(), 9) != 0});
    }
    return result;
}

const std::string& FileStore::root_path() const noexcept {
    return root_path_;
}

} // namespace renegade
