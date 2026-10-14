#include "account_store.hpp"

#include <argon2.h>
#include <sqlite3.h>

#include <array>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <sys/random.h>
#include <sys/stat.h>

namespace renegade {
namespace {

constexpr std::uint32_t kArgonTimeCost = 3;
constexpr std::uint32_t kArgonMemoryKiB = 64U * 1024U;
constexpr std::uint32_t kArgonParallelism = 1;
constexpr std::uint32_t kSaltBytes = 16;
constexpr std::uint32_t kHashBytes = 32;
constexpr std::size_t kEncodedHashBytes = 256;
constexpr char kUnknownAccountPasswordHash[] =
    "$argon2id$v=19$m=65536,t=3,p=1$Um5nZER1bW15U2FsdDIwMjY$+mjNzNvaHpvDyFO+OIPOQA61uG2LiNTzvik/884IQR0";

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
            throw std::runtime_error("opening account database: " + message);
        }
        sqlite3_busy_timeout(handle_, 5000);
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
    Statement(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &statement_, nullptr) != SQLITE_OK) {
            throw std::runtime_error("preparing account query: " + std::string(sqlite3_errmsg(db)));
        }
    }

    ~Statement() { sqlite3_finalize(statement_); }
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    [[nodiscard]] sqlite3_stmt* get() const noexcept { return statement_; }

private:
    sqlite3_stmt* statement_{};
};

void check_sqlite(sqlite3* db, int result, std::string_view operation) {
    if (result != SQLITE_OK && result != SQLITE_DONE && result != SQLITE_ROW) {
        throw std::runtime_error(std::string(operation) + ": " + sqlite3_errmsg(db));
    }
}

void bind_text(sqlite3* db, sqlite3_stmt* statement, int index, std::string_view value) {
    const int result = sqlite3_bind_text(
        statement,
        index,
        value.data(),
        static_cast<int>(value.size()),
        SQLITE_TRANSIENT);
    check_sqlite(db, result, "binding account data");
}

bool account_column_exists(sqlite3* db, std::string_view name) {
    Statement statement(db, "PRAGMA table_info(accounts)");
    for (;;) {
        const int result = sqlite3_step(statement.get());
        if (result == SQLITE_DONE) {
            return false;
        }
        if (result != SQLITE_ROW) {
            throw std::runtime_error("checking account schema: " + std::string(sqlite3_errmsg(db)));
        }
        const auto* column = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 1));
        if (column != nullptr && name == column) {
            return true;
        }
    }
}

void validate_profile_field(std::string_view value, std::size_t maximum, std::string_view name) {
    if (value.size() > maximum) {
        throw std::invalid_argument(std::string(name) + " must be no more than " +
            std::to_string(maximum) + " bytes");
    }
    for (const unsigned char character : value) {
        if (character < 0x20 || character == 0x7f || character == 0x1b) {
            throw std::invalid_argument(std::string(name) + " must not contain terminal control characters");
        }
    }
}

void validate_birth_date(std::string_view value) {
    if (value.empty()) {
        return;
    }
    if (value.size() != 10 || value[4] != '-' || value[7] != '-') {
        throw std::invalid_argument("birth date must use YYYY-MM-DD format or be blank");
    }
    int year{};
    unsigned int month{};
    unsigned int day{};
    const auto parse = [](std::string_view text, auto& result) {
        const auto converted = std::from_chars(text.data(), text.data() + text.size(), result);
        return converted.ec == std::errc{} && converted.ptr == text.data() + text.size();
    };
    if (!parse(value.substr(0, 4), year) || !parse(value.substr(5, 2), month) ||
        !parse(value.substr(8, 2), day)) {
        throw std::invalid_argument("birth date must use YYYY-MM-DD format or be blank");
    }
    const bool leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    static constexpr std::array<unsigned int, 12> month_days{
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month < 1 || month > 12 || day < 1 ||
        day > month_days[month - 1] + (month == 2 && leap_year ? 1U : 0U)) {
        throw std::invalid_argument("birth date is not a valid calendar date");
    }
    const std::time_t now = std::time(nullptr);
    std::tm local_now{};
    if (localtime_r(&now, &local_now) == nullptr) {
        throw std::runtime_error("could not read the local date for birth-date validation");
    }
    const int current_year = local_now.tm_year + 1900;
    if (year >= current_year || year < current_year - 100) {
        throw std::invalid_argument("birth date must be within the last 100 years");
    }
}

void validate_sex(char sex) {
    const char normalized = static_cast<char>(std::toupper(static_cast<unsigned char>(sex)));
    if (sex != '\0' && normalized != 'M' && normalized != 'F') {
        throw std::invalid_argument("gender must be M, F, or blank");
    }
}

void validate_expiration_date(std::string_view value) {
    if (value.empty()) {
        return;
    }
    if (value.size() != 10 || value[4] != '-' || value[7] != '-') {
        throw std::invalid_argument("expiration date must use YYYY-MM-DD format or be blank");
    }
    int year{};
    unsigned int month{};
    unsigned int day{};
    const auto parse = [](std::string_view text, auto& result) {
        const auto converted = std::from_chars(text.data(), text.data() + text.size(), result);
        return converted.ec == std::errc{} && converted.ptr == text.data() + text.size();
    };
    if (!parse(value.substr(0, 4), year) || !parse(value.substr(5, 2), month) ||
        !parse(value.substr(8, 2), day)) {
        throw std::invalid_argument("expiration date must use YYYY-MM-DD format or be blank");
    }
    const bool leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    static constexpr std::array<unsigned int, 12> month_days{
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (year < 1 || month < 1 || month > 12 || day < 1 ||
        day > month_days[month - 1] + (month == 2 && leap_year ? 1U : 0U)) {
        throw std::invalid_argument("expiration date is not a valid calendar date");
    }
}

std::string normalize_acs_flags(std::string_view value, bool account_restrictions) {
    const std::string_view allowed = account_restrictions
        ? std::string_view("LCVUA*PEKM1234")
        : std::string_view{};
    const std::size_t maximum = account_restrictions ? allowed.size() : 27;
    if (value.size() > maximum) {
        throw std::invalid_argument(account_restrictions
            ? "AC flags contain unsupported or duplicate entries"
            : "AR flags must contain characters from @ through Z");
    }
    std::string result;
    result.reserve(value.size());
    for (const unsigned char byte : value) {
        const char flag = static_cast<char>(std::toupper(byte));
        const bool valid = account_restrictions
            ? allowed.find(flag) != std::string_view::npos
            : flag >= '@' && flag <= 'Z';
        if (!valid || result.find(flag) != std::string::npos) {
            throw std::invalid_argument(account_restrictions
                ? "AC flags contain unsupported or duplicate entries"
                : "AR flags contain unsupported or duplicate entries");
        }
        result.push_back(flag);
    }
    return result;
}

std::string local_date_key() {
    const std::time_t now = std::time(nullptr);
    std::tm local{};
    if (::localtime_r(&now, &local) == nullptr) {
        throw std::runtime_error("could not determine the local date for the time bank");
    }
    std::array<char, 16> value{};
    if (std::strftime(value.data(), value.size(), "%Y-%m-%d", &local) == 0) {
        throw std::runtime_error("could not format the local date for the time bank");
    }
    return value.data();
}

std::string sqlite_text(sqlite3_stmt* statement, int column) {
    const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(statement, column));
    return value == nullptr ? std::string{} : std::string(value);
}

bool valid_validation_key(char key) noexcept {
    const unsigned char byte = static_cast<unsigned char>(key);
    return byte >= '!' && byte <= '~' && key != 'Q' && key != 'q';
}

std::string date_after_days(int days) {
    const std::time_t now = std::time(nullptr);
    std::tm local{};
    if (::localtime_r(&now, &local) == nullptr) {
        throw std::runtime_error("could not determine the local date for validation expiration");
    }
    local.tm_mday += days;
    local.tm_hour = 12;
    local.tm_min = 0;
    local.tm_sec = 0;
    if (std::mktime(&local) == static_cast<std::time_t>(-1)) {
        throw std::runtime_error("could not calculate the validation expiration date");
    }
    std::array<char, 16> value{};
    if (std::strftime(value.data(), value.size(), "%Y-%m-%d", &local) == 0) {
        throw std::runtime_error("could not format the validation expiration date");
    }
    return value.data();
}

std::string merge_validation_flags(std::string current, std::string_view added, bool soft) {
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

ValidationLevel read_validation_level(sqlite3_stmt* statement) {
    ValidationLevel level;
    const std::string key = sqlite_text(statement, 0);
    const std::string expire_to = sqlite_text(statement, 1);
    level.key = key.empty() ? '\0' : key.front();
    level.expire_to_key = expire_to.empty() ? ' ' : expire_to.front();
    level.description = sqlite_text(statement, 2);
    level.user_message = sqlite_text(statement, 3);
    level.security_level = sqlite3_column_int(statement, 4);
    level.download_security_level = sqlite3_column_int(statement, 5);
    level.start_menu = sqlite3_column_int(statement, 6);
    level.expiration_days = sqlite3_column_int(statement, 7);
    level.file_points = sqlite3_column_int(statement, 8);
    level.credits = sqlite3_column_int64(statement, 9);
    level.soft_ar_flags = sqlite3_column_int(statement, 10) != 0;
    level.soft_ac_flags = sqlite3_column_int(statement, 11) != 0;
    level.ar_flags = sqlite_text(statement, 12);
    level.ac_flags = sqlite_text(statement, 13);
    return level;
}

void apply_validation_level_in_transaction(sqlite3* db, std::string_view handle, char key) {
    Statement validation(db,
        "SELECT validation_key, expire_to_key, description, user_message, new_sl, new_dsl, new_menu, "
        "expiration_days, new_file_points, new_credits, soft_ar, soft_ac, new_ar, new_ac "
        "FROM validation_levels WHERE validation_key = ?1");
    const char key_text[] = {key, '\0'};
    bind_text(db, validation.get(), 1, std::string_view(key_text, 1));
    const int validation_result = sqlite3_step(validation.get());
    if (validation_result == SQLITE_DONE) {
        throw std::invalid_argument("validation level does not exist");
    }
    check_sqlite(db, validation_result, "reading account validation level");
    const ValidationLevel level = read_validation_level(validation.get());

    if ((level.expiration_days == 0) != (level.expire_to_key == ' ')) {
        throw std::invalid_argument("validation expiration days and expire-to level must both be set or blank");
    }
    if (level.expire_to_key != ' ') {
        Statement target(db, "SELECT 1 FROM validation_levels WHERE validation_key = ?1");
        const char target_key[] = {level.expire_to_key, '\0'};
        bind_text(db, target.get(), 1, std::string_view(target_key, 1));
        const int target_result = sqlite3_step(target.get());
        if (target_result == SQLITE_DONE) {
            throw std::invalid_argument("validation expire-to level does not exist");
        }
        check_sqlite(db, target_result, "checking validation expire-to level");
    }

    std::int64_t credits{};
    std::int64_t file_points{};
    std::string ar_flags;
    std::string ac_flags;
    {
        Statement account(db,
            "SELECT acs_ar_flags, acs_ac_flags, credits, file_points "
            "FROM accounts WHERE handle = ?1 COLLATE NOCASE");
        bind_text(db, account.get(), 1, handle);
        const int account_result = sqlite3_step(account.get());
        if (account_result == SQLITE_DONE) {
            throw std::invalid_argument("BBS account does not exist");
        }
        check_sqlite(db, account_result, "reading account before validation");
        credits = sqlite3_column_int64(account.get(), 2) + level.credits;
        file_points = sqlite3_column_int64(account.get(), 3) + level.file_points;
        ar_flags = merge_validation_flags(sqlite_text(account.get(), 0), level.ar_flags, level.soft_ar_flags);
        ac_flags = merge_validation_flags(sqlite_text(account.get(), 1), level.ac_flags, level.soft_ac_flags);
    }
    if (credits < std::numeric_limits<std::int32_t>::min() ||
        credits > std::numeric_limits<std::int32_t>::max()) {
        throw std::invalid_argument("validation would move the account credits outside the 32-bit range");
    }
    if (file_points < 0 || file_points > std::numeric_limits<std::int32_t>::max()) {
        throw std::invalid_argument("validation would move the file-point balance outside the 32-bit range");
    }
    const std::string expires = level.expiration_days == 0 ? std::string{} : date_after_days(level.expiration_days);
    const char expire_to[] = {level.expire_to_key, '\0'};
    const char subscription[] = {level.key, '\0'};

    Statement update(db,
        "UPDATE accounts SET security_level = ?1, download_security_level = ?2, user_start_menu = ?3, "
        "expiration_date = ?4, expire_to_key = ?5, subscription_key = ?6, file_points = ?7, credits = ?8, "
        "acs_ar_flags = ?9, acs_ac_flags = ?10 WHERE handle = ?11 COLLATE NOCASE");
    check_sqlite(db, sqlite3_bind_int(update.get(), 1, level.security_level), "binding validated security level");
    check_sqlite(db, sqlite3_bind_int(update.get(), 2, level.download_security_level), "binding validated download level");
    check_sqlite(db, sqlite3_bind_int(update.get(), 3, level.start_menu), "binding validated start menu");
    bind_text(db, update.get(), 4, expires);
    bind_text(db, update.get(), 5, level.expire_to_key == ' ' ? std::string_view{} : std::string_view(expire_to, 1));
    bind_text(db, update.get(), 6, std::string_view(subscription, 1));
    check_sqlite(db, sqlite3_bind_int64(update.get(), 7, file_points), "binding validated file points");
    check_sqlite(db, sqlite3_bind_int64(update.get(), 8, credits), "binding validated credits");
    bind_text(db, update.get(), 9, ar_flags);
    bind_text(db, update.get(), 10, ac_flags);
    bind_text(db, update.get(), 11, handle);
    check_sqlite(db, sqlite3_step(update.get()), "applying account validation level");
}

TimeBankStatus mutate_time_bank(
    sqlite3* db,
    std::string_view handle,
    int minutes,
    int bank_limit,
    int daily_limit,
    bool depositing) {
    if (minutes < 1 || minutes > 32767) {
        throw std::invalid_argument("time bank transfers must be between 1 and 32767 minutes");
    }
    const std::string today = local_date_key();
    check_sqlite(db, sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr),
        "starting time bank transfer");
    try {
        Statement lookup(db,
            "SELECT time_bank_minutes, time_bank_deposited_today, time_bank_withdrawn_today, time_bank_day "
            "FROM accounts WHERE handle = ?1 COLLATE NOCASE");
        bind_text(db, lookup.get(), 1, handle);
        const int lookup_result = sqlite3_step(lookup.get());
        if (lookup_result == SQLITE_DONE) {
            throw std::invalid_argument("BBS account does not exist");
        }
        check_sqlite(db, lookup_result, "reading time bank balance");
        int balance = sqlite3_column_int(lookup.get(), 0);
        int deposited = sqlite3_column_int(lookup.get(), 1);
        int withdrawn = sqlite3_column_int(lookup.get(), 2);
        const bool new_day = sqlite_text(lookup.get(), 3) != today;
        const int finished_lookup = sqlite3_step(lookup.get());
        if (finished_lookup != SQLITE_DONE) {
            check_sqlite(db, finished_lookup, "finishing time bank balance read");
        }
        if (new_day) {
            deposited = 0;
            withdrawn = 0;
        }

        if (depositing) {
            if (bank_limit > 0 && minutes > bank_limit - balance) {
                throw std::invalid_argument("time bank account limit would be exceeded");
            }
            if (daily_limit > 0 && minutes > daily_limit - deposited) {
                throw std::invalid_argument("daily time bank deposit limit would be exceeded");
            }
            balance += minutes;
            deposited += minutes;
        } else {
            if (minutes > balance) {
                throw std::invalid_argument("there are not enough minutes in the time bank");
            }
            if (daily_limit > 0 && minutes > daily_limit - withdrawn) {
                throw std::invalid_argument("daily time bank withdrawal limit would be exceeded");
            }
            balance -= minutes;
            withdrawn += minutes;
        }

        Statement update(db,
            "UPDATE accounts SET time_bank_minutes = ?1, time_bank_deposited_today = ?2, "
            "time_bank_withdrawn_today = ?3, time_bank_day = ?4 "
            "WHERE handle = ?5 COLLATE NOCASE");
        check_sqlite(db, sqlite3_bind_int(update.get(), 1, balance), "binding time bank balance");
        check_sqlite(db, sqlite3_bind_int(update.get(), 2, deposited), "binding time bank deposits");
        check_sqlite(db, sqlite3_bind_int(update.get(), 3, withdrawn), "binding time bank withdrawals");
        bind_text(db, update.get(), 4, today);
        bind_text(db, update.get(), 5, handle);
        check_sqlite(db, sqlite3_step(update.get()), "saving time bank transfer");
        check_sqlite(db, sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr),
            "committing time bank transfer");
        return {balance, deposited, withdrawn};
    } catch (...) {
        (void)sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void make_database_private(const std::string& path) {
    struct stat info {};
    if (::stat(path.c_str(), &info) == 0 && (info.st_mode & 0077) != 0) {
        if (::chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
            throw std::system_error(errno, std::generic_category(), "restricting account database permissions");
        }
    }
}

} // namespace

AccountStore::AccountStore(std::string database_path)
    : database_path_(std::move(database_path)) {}

void AccountStore::initialize() const {
    const std::filesystem::path database_path(database_path_);
    if (database_path.has_parent_path()) {
        std::filesystem::create_directories(database_path.parent_path());
    }

    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
    constexpr const char* create_table =
        "CREATE TABLE IF NOT EXISTS accounts ("
        "handle TEXT PRIMARY KEY COLLATE NOCASE,"
        "password_hash TEXT NOT NULL,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "last_login_at TEXT NOT NULL DEFAULT '',"
        "total_logins INTEGER NOT NULL DEFAULT 0 CHECK(total_logins >= 0),"
        "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),"
        "approved INTEGER NOT NULL DEFAULT 1 CHECK(approved IN (0, 1)),"
        "is_sysop INTEGER NOT NULL DEFAULT 0 CHECK(is_sysop IN (0, 1)),"
        "real_name TEXT NOT NULL DEFAULT '',"
        "location TEXT NOT NULL DEFAULT '',"
        "signature TEXT NOT NULL DEFAULT '',"
        "birth_date TEXT NOT NULL DEFAULT '',"
        "sex TEXT NOT NULL DEFAULT '',"
        "country TEXT NOT NULL DEFAULT '',"
        "street TEXT NOT NULL DEFAULT '',"
        "city_state TEXT NOT NULL DEFAULT '',"
        "postal_code TEXT NOT NULL DEFAULT '',"
        "phone TEXT NOT NULL DEFAULT '',"
        "user_answer_1 TEXT NOT NULL DEFAULT '',"
        "user_answer_2 TEXT NOT NULL DEFAULT '',"
        "user_answer_3 TEXT NOT NULL DEFAULT '',"
        "forgot_password_answer_hash TEXT NOT NULL DEFAULT '',"
        "expiration_date TEXT NOT NULL DEFAULT '',"
        "ansi_color INTEGER NOT NULL DEFAULT 1 CHECK(ansi_color IN (0, 1)),"
        "clear_screen INTEGER NOT NULL DEFAULT 1 CHECK(clear_screen IN (0, 1)),"
        "pause_screens INTEGER NOT NULL DEFAULT 1 CHECK(pause_screens IN (0, 1)),"
        "hotkeys INTEGER NOT NULL DEFAULT 1 CHECK(hotkeys IN (0, 1)),"
        "expert_mode INTEGER NOT NULL DEFAULT 0 CHECK(expert_mode IN (0, 1)),"
        "time_bank_minutes INTEGER NOT NULL DEFAULT 0 CHECK(time_bank_minutes >= 0),"
        "time_bank_deposited_today INTEGER NOT NULL DEFAULT 0 CHECK(time_bank_deposited_today >= 0),"
        "time_bank_withdrawn_today INTEGER NOT NULL DEFAULT 0 CHECK(time_bank_withdrawn_today >= 0),"
        "time_bank_day TEXT NOT NULL DEFAULT '',"
        "security_level INTEGER NOT NULL DEFAULT 10 CHECK(security_level BETWEEN 0 AND 255),"
        "download_security_level INTEGER NOT NULL DEFAULT 10 CHECK(download_security_level BETWEEN 0 AND 255),"
        "acs_ar_flags TEXT NOT NULL DEFAULT '',"
        "acs_ac_flags TEXT NOT NULL DEFAULT '',"
        "credits INTEGER NOT NULL DEFAULT 0 CHECK(credits BETWEEN -2147483648 AND 2147483647),"
        "file_points INTEGER NOT NULL DEFAULT 0 CHECK(file_points BETWEEN 0 AND 2147483647),"
        "mailbox_closed INTEGER NOT NULL DEFAULT 0 CHECK(mailbox_closed IN (0, 1)),"
        "subscription_key TEXT NOT NULL DEFAULT '',"
        "expire_to_key TEXT NOT NULL DEFAULT '',"
        "user_start_menu INTEGER NOT NULL DEFAULT 0 CHECK(user_start_menu BETWEEN 0 AND 255)"
        ");";
    check_sqlite(db.get(), sqlite3_exec(db.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr),
        "starting account schema update");
    try {
        char* error = nullptr;
        const int result = sqlite3_exec(db.get(), create_table, nullptr, nullptr, &error);
        if (result != SQLITE_OK) {
            const std::string message = error != nullptr ? error : sqlite3_errmsg(db.get());
            sqlite3_free(error);
            throw std::runtime_error("initializing account database: " + message);
        }
        if (!account_column_exists(db.get(), "enabled")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1))",
                nullptr, nullptr, nullptr), "adding account access status");
        }
        if (!account_column_exists(db.get(), "approved")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN approved INTEGER NOT NULL DEFAULT 1 CHECK(approved IN (0, 1))",
                nullptr, nullptr, nullptr), "adding account approval status");
        }
        if (!account_column_exists(db.get(), "is_sysop")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN is_sysop INTEGER NOT NULL DEFAULT 0 CHECK(is_sysop IN (0, 1))",
                nullptr, nullptr, nullptr), "adding SysOp access status");
        }
        if (!account_column_exists(db.get(), "real_name")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN real_name TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding account display name");
        }
        if (!account_column_exists(db.get(), "location")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN location TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding account location");
        }
        if (!account_column_exists(db.get(), "signature")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN signature TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding account signature");
        }
        if (!account_column_exists(db.get(), "birth_date")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN birth_date TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding account birth date");
        }
        if (!account_column_exists(db.get(), "sex")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN sex TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding account gender");
        }
        if (!account_column_exists(db.get(), "country")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN country TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding account country");
        }
        if (!account_column_exists(db.get(), "street")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN street TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding account street address");
        }
        if (!account_column_exists(db.get(), "city_state")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN city_state TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding account city and state");
        }
        if (!account_column_exists(db.get(), "postal_code")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN postal_code TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding account postal code");
        }
        if (!account_column_exists(db.get(), "phone")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN phone TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding account phone number");
        }
        for (int index = 1; index <= 3; ++index) {
            const std::string column = "user_answer_" + std::to_string(index);
            if (!account_column_exists(db.get(), column)) {
                const std::string migration = "ALTER TABLE accounts ADD COLUMN " + column +
                    " TEXT NOT NULL DEFAULT ''";
                check_sqlite(db.get(), sqlite3_exec(db.get(), migration.c_str(), nullptr, nullptr, nullptr),
                    "adding SysOp-defined account answer");
            }
        }
        if (!account_column_exists(db.get(), "forgot_password_answer_hash")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN forgot_password_answer_hash TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding password-recovery answer hash");
        }
        if (!account_column_exists(db.get(), "expiration_date")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN expiration_date TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding account expiration date");
        }
        if (!account_column_exists(db.get(), "ansi_color")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN ansi_color INTEGER NOT NULL DEFAULT 1 CHECK(ansi_color IN (0, 1))",
                nullptr, nullptr, nullptr), "adding ANSI color preference");
        }
        if (!account_column_exists(db.get(), "clear_screen")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN clear_screen INTEGER NOT NULL DEFAULT 1 CHECK(clear_screen IN (0, 1))",
                nullptr, nullptr, nullptr), "adding screen-clear preference");
        }
        if (!account_column_exists(db.get(), "pause_screens")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN pause_screens INTEGER NOT NULL DEFAULT 1 CHECK(pause_screens IN (0, 1))",
                nullptr, nullptr, nullptr), "adding screen-pause preference");
        }
        if (!account_column_exists(db.get(), "hotkeys")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN hotkeys INTEGER NOT NULL DEFAULT 1 CHECK(hotkeys IN (0, 1))",
                nullptr, nullptr, nullptr), "adding hotkey preference");
        }
        if (!account_column_exists(db.get(), "expert_mode")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN expert_mode INTEGER NOT NULL DEFAULT 0 CHECK(expert_mode IN (0, 1))",
                nullptr, nullptr, nullptr), "adding expert-mode preference");
        }
        if (!account_column_exists(db.get(), "time_bank_minutes")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN time_bank_minutes INTEGER NOT NULL DEFAULT 0 CHECK(time_bank_minutes >= 0)",
                nullptr, nullptr, nullptr), "adding time bank balance");
        }
        if (!account_column_exists(db.get(), "time_bank_deposited_today")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN time_bank_deposited_today INTEGER NOT NULL DEFAULT 0 CHECK(time_bank_deposited_today >= 0)",
                nullptr, nullptr, nullptr), "adding daily time bank deposits");
        }
        if (!account_column_exists(db.get(), "time_bank_withdrawn_today")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN time_bank_withdrawn_today INTEGER NOT NULL DEFAULT 0 CHECK(time_bank_withdrawn_today >= 0)",
                nullptr, nullptr, nullptr), "adding daily time bank withdrawals");
        }
        if (!account_column_exists(db.get(), "time_bank_day")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN time_bank_day TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding time bank day marker");
        }
        if (!account_column_exists(db.get(), "last_login_at")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN last_login_at TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding last-login date");
        }
        if (!account_column_exists(db.get(), "total_logins")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN total_logins INTEGER NOT NULL DEFAULT 0 CHECK(total_logins >= 0)",
                nullptr, nullptr, nullptr), "adding account login count");
        }
        if (!account_column_exists(db.get(), "security_level")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN security_level INTEGER NOT NULL DEFAULT 10 CHECK(security_level BETWEEN 0 AND 255)",
                nullptr, nullptr, nullptr), "adding account security level");
        }
        if (!account_column_exists(db.get(), "download_security_level")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN download_security_level INTEGER NOT NULL DEFAULT 10 CHECK(download_security_level BETWEEN 0 AND 255)",
                nullptr, nullptr, nullptr), "adding download security level");
        }
        if (!account_column_exists(db.get(), "acs_ar_flags")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN acs_ar_flags TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding account AR access flags");
        }
        if (!account_column_exists(db.get(), "acs_ac_flags")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN acs_ac_flags TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding account AC access flags");
        }
        if (!account_column_exists(db.get(), "credits")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN credits INTEGER NOT NULL DEFAULT 0 "
                "CHECK(credits BETWEEN -2147483648 AND 2147483647)",
                nullptr, nullptr, nullptr), "adding account message credits");
        }
        if (!account_column_exists(db.get(), "file_points")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN file_points INTEGER NOT NULL DEFAULT 0 "
                "CHECK(file_points BETWEEN 0 AND 2147483647)",
                nullptr, nullptr, nullptr), "adding account file points");
        }
        if (!account_column_exists(db.get(), "mailbox_closed")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN mailbox_closed INTEGER NOT NULL DEFAULT 0 "
                "CHECK(mailbox_closed IN (0, 1))",
                nullptr, nullptr, nullptr), "adding mailbox-closed preference");
        }
        if (!account_column_exists(db.get(), "subscription_key")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN subscription_key TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding account validation subscription");
        }
        if (!account_column_exists(db.get(), "expire_to_key")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN expire_to_key TEXT NOT NULL DEFAULT ''",
                nullptr, nullptr, nullptr), "adding account expiration transition");
        }
        if (!account_column_exists(db.get(), "user_start_menu")) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE accounts ADD COLUMN user_start_menu INTEGER NOT NULL DEFAULT 0 CHECK(user_start_menu BETWEEN 0 AND 255)",
                nullptr, nullptr, nullptr), "adding account start menu");
        }
        check_sqlite(db.get(), sqlite3_exec(db.get(),
            "CREATE TABLE IF NOT EXISTS validation_levels ("
            "validation_key TEXT PRIMARY KEY CHECK(length(validation_key) = 1),"
            "expire_to_key TEXT NOT NULL DEFAULT '',"
            "description TEXT NOT NULL DEFAULT '',"
            "user_message TEXT NOT NULL DEFAULT '',"
            "new_sl INTEGER NOT NULL CHECK(new_sl BETWEEN 0 AND 255),"
            "new_dsl INTEGER NOT NULL CHECK(new_dsl BETWEEN 0 AND 255),"
            "new_menu INTEGER NOT NULL DEFAULT 0 CHECK(new_menu BETWEEN 0 AND 255),"
            "expiration_days INTEGER NOT NULL DEFAULT 0 CHECK(expiration_days BETWEEN 0 AND 65535),"
            "new_file_points INTEGER NOT NULL DEFAULT 0 CHECK(new_file_points BETWEEN 0 AND 2147483647),"
            "new_credits INTEGER NOT NULL DEFAULT 0 CHECK(new_credits BETWEEN 0 AND 2147483647),"
            "soft_ar INTEGER NOT NULL CHECK(soft_ar IN (0, 1)),"
            "soft_ac INTEGER NOT NULL CHECK(soft_ac IN (0, 1)),"
            "new_ar TEXT NOT NULL DEFAULT '',"
            "new_ac TEXT NOT NULL DEFAULT ''"
            ")",
            nullptr, nullptr, nullptr), "creating validation levels");
        check_sqlite(db.get(), sqlite3_exec(db.get(),
            "CREATE TABLE IF NOT EXISTS signup_question_settings ("
            "source_question INTEGER PRIMARY KEY CHECK(source_question BETWEEN 2 AND 26),"
            "enabled INTEGER NOT NULL CHECK(enabled IN (0, 1))"
            ")",
            nullptr, nullptr, nullptr), "creating signup-question settings");
        bool legacy_signup_question_constraint = false;
        {
            Statement schema(db.get(),
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'signup_question_settings'");
            const int schema_result = sqlite3_step(schema.get());
            check_sqlite(db.get(), schema_result, "checking signup-question schema");
            if (schema_result == SQLITE_ROW) {
                const auto* schema_text = reinterpret_cast<const char*>(sqlite3_column_text(schema.get(), 0));
                legacy_signup_question_constraint = schema_text != nullptr &&
                    std::string_view(schema_text).find("BETWEEN 2 AND 14") != std::string_view::npos;
            }
        }
        if (legacy_signup_question_constraint) {
            check_sqlite(db.get(), sqlite3_exec(db.get(),
                "ALTER TABLE signup_question_settings RENAME TO signup_question_settings_legacy;"
                "CREATE TABLE signup_question_settings ("
                "source_question INTEGER PRIMARY KEY CHECK(source_question BETWEEN 2 AND 26),"
                "enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)));"
                "INSERT INTO signup_question_settings(source_question, enabled) "
                "SELECT source_question, enabled FROM signup_question_settings_legacy;"
                "DROP TABLE signup_question_settings_legacy;",
                nullptr, nullptr, nullptr), "migrating signup-question settings");
        }
        check_sqlite(db.get(), sqlite3_exec(db.get(),
            "INSERT OR IGNORE INTO signup_question_settings(source_question, enabled) VALUES"
            "(2, 1), (3, 0), (4, 0), (5, 1), (6, 0), (7, 0), (8, 1), (9, 1),"
            "(10, 0), (11, 0), (12, 0), (14, 0), (16, 0), (19, 0), (20, 0), "
            "(21, 0), (22, 0), (25, 0)",
            nullptr, nullptr, nullptr), "setting default signup questions");
        check_sqlite(db.get(), sqlite3_exec(db.get(),
            "CREATE TABLE IF NOT EXISTS account_system_settings ("
            "setting_key TEXT PRIMARY KEY, setting_value TEXT NOT NULL"
            ")",
            nullptr, nullptr, nullptr), "creating account-system settings");
        check_sqlite(db.get(), sqlite3_exec(db.get(),
            "INSERT OR IGNORE INTO account_system_settings(setting_key, setting_value) "
            "VALUES('forgot_password_question', ''),"
            "('user_question_1', ''), ('user_question_2', ''), ('user_question_3', '')",
            nullptr, nullptr, nullptr), "setting default password-recovery question");
        check_sqlite(db.get(), sqlite3_exec(db.get(), "COMMIT", nullptr, nullptr, nullptr),
            "saving account schema update");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

void AccountStore::create_user(std::string_view handle, std::string_view password) const {
    if (!valid_handle(handle)) {
        throw std::invalid_argument("handle must be 1-32 characters: letters, digits, dot, dash, or underscore");
    }
    if (password.size() < 12 || password.size() > 128) {
        throw std::invalid_argument("password must be between 12 and 128 characters");
    }

    initialize();
    const std::string encoded_hash = hash_password(password);
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "INSERT INTO accounts(handle, password_hash, enabled, approved) VALUES(?1, ?2, 1, 1)");
    bind_text(db.get(), statement.get(), 1, handle);
    bind_text(db.get(), statement.get(), 2, encoded_hash);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "creating BBS account");
    make_database_private(database_path_);
}

bool AccountStore::create_pending_user(std::string_view handle, std::string_view password) const {
    if (!valid_handle(handle)) {
        throw std::invalid_argument("handle must be 1-32 characters: letters, digits, dot, dash, or underscore");
    }
    if (password.size() < 12 || password.size() > 128) {
        throw std::invalid_argument("password must be between 12 and 128 characters");
    }

    initialize();
    const std::string encoded_hash = hash_password(password);
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "INSERT OR IGNORE INTO accounts(handle, password_hash, enabled, approved) VALUES(?1, ?2, 0, 0)");
    bind_text(db.get(), statement.get(), 1, handle);
    bind_text(db.get(), statement.get(), 2, encoded_hash);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "creating pending BBS application");
    const bool inserted = sqlite3_changes(db.get()) != 0;
    if (inserted) {
        bool has_new_user_level = false;
        {
            Statement default_level(db.get(), "SELECT 1 FROM validation_levels WHERE validation_key = '!' ");
            const int level_result = sqlite3_step(default_level.get());
            has_new_user_level = level_result == SQLITE_ROW;
            if (!has_new_user_level) {
                check_sqlite(db.get(), level_result, "checking default new-user validation");
            }
        }
        if (has_new_user_level) {
            check_sqlite(db.get(), sqlite3_exec(db.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr),
                "starting new-user validation");
            try {
                apply_validation_level_in_transaction(db.get(), handle, '!');
                check_sqlite(db.get(), sqlite3_exec(db.get(), "COMMIT", nullptr, nullptr, nullptr),
                    "committing new-user validation");
            } catch (const std::invalid_argument&) {
                (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
            } catch (...) {
                (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
                throw;
            }
        }
    }
    make_database_private(database_path_);
    return inserted;
}

void AccountStore::set_password(std::string_view handle, std::string_view password) const {
    if (!valid_handle(handle)) {
        throw std::invalid_argument("invalid BBS account handle");
    }
    if (password.size() < 12 || password.size() > 128) {
        throw std::invalid_argument("password must be between 12 and 128 characters");
    }

    initialize();
    const std::string encoded_hash = hash_password(password);
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(), "UPDATE accounts SET password_hash = ?1 WHERE handle = ?2 COLLATE NOCASE");
    bind_text(db.get(), statement.get(), 1, encoded_hash);
    bind_text(db.get(), statement.get(), 2, handle);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "updating BBS account password");
    if (sqlite3_changes(db.get()) == 0) {
        throw std::invalid_argument("BBS account does not exist");
    }
    make_database_private(database_path_);
}

bool AccountStore::verify_password(std::string_view handle, std::string_view password) const {
    if (!valid_handle(handle)) {
        return false;
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "SELECT password_hash FROM accounts WHERE handle = ?1 COLLATE NOCASE");
    bind_text(db.get(), statement.get(), 1, handle);
    const int result = sqlite3_step(statement.get());
    if (result == SQLITE_DONE) {
        return false;
    }
    check_sqlite(db.get(), result, "checking current account password");
    const auto* stored = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 0));
    const std::string_view encoded_hash = stored == nullptr
        ? std::string_view{} : std::string_view(stored);
    return verify_password_hash(encoded_hash, password);
}

void AccountStore::change_password(
    std::string_view handle, std::string_view current_password,
    std::string_view new_password) const {
    if (!valid_handle(handle)) {
        throw std::invalid_argument("invalid BBS account handle");
    }
    if (new_password.size() < 12 || new_password.size() > 128) {
        throw std::invalid_argument("new password must be between 12 and 128 characters");
    }

    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_sqlite(db.get(), sqlite3_exec(db.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr),
        "starting account password change");
    try {
        Statement current(db.get(),
            "SELECT password_hash FROM accounts WHERE handle = ?1 COLLATE NOCASE");
        bind_text(db.get(), current.get(), 1, handle);
        const int lookup_result = sqlite3_step(current.get());
        if (lookup_result == SQLITE_DONE) {
            throw std::invalid_argument("BBS account does not exist");
        }
        check_sqlite(db.get(), lookup_result, "reading current account password");
        const auto* stored = reinterpret_cast<const char*>(sqlite3_column_text(current.get(), 0));
        const std::string_view encoded_hash = stored == nullptr
            ? std::string_view{} : std::string_view(stored);
        if (!verify_password_hash(encoded_hash, current_password)) {
            throw std::invalid_argument("current password is incorrect");
        }
        if (verify_password_hash(encoded_hash, new_password)) {
            throw std::invalid_argument("new password must differ from the current password");
        }

        const std::string encoded_new_password = hash_password(new_password);
        Statement update(db.get(),
            "UPDATE accounts SET password_hash = ?1 WHERE handle = ?2 COLLATE NOCASE");
        bind_text(db.get(), update.get(), 1, encoded_new_password);
        bind_text(db.get(), update.get(), 2, handle);
        check_sqlite(db.get(), sqlite3_step(update.get()), "saving changed account password");
        if (sqlite3_changes(db.get()) == 0) {
            throw std::invalid_argument("BBS account does not exist");
        }
        check_sqlite(db.get(), sqlite3_exec(db.get(), "COMMIT", nullptr, nullptr, nullptr),
            "committing account password change");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

void AccountStore::set_enabled(std::string_view handle, bool enabled) const {
    if (!valid_handle(handle)) {
        throw std::invalid_argument("invalid BBS account handle");
    }

    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "UPDATE accounts SET enabled = ?1, approved = CASE WHEN ?1 = 1 THEN 1 ELSE approved END "
        "WHERE handle = ?2 COLLATE NOCASE");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 1, enabled ? 1 : 0), "binding account access status");
    bind_text(db.get(), statement.get(), 2, handle);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "updating BBS account access");
    if (sqlite3_changes(db.get()) == 0) {
        Statement existence(db.get(), "SELECT 1 FROM accounts WHERE handle = ?1 COLLATE NOCASE");
        bind_text(db.get(), existence.get(), 1, handle);
        const int result = sqlite3_step(existence.get());
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("BBS account does not exist");
        }
        if (result != SQLITE_ROW) {
            check_sqlite(db.get(), result, "checking BBS account");
        }
    }
    make_database_private(database_path_);
}

void AccountStore::set_sysop(std::string_view handle, bool is_sysop) const {
    if (!valid_handle(handle)) {
        throw std::invalid_argument("invalid BBS account handle");
    }

    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(), "UPDATE accounts SET is_sysop = ?1 WHERE handle = ?2 COLLATE NOCASE");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 1, is_sysop ? 1 : 0), "binding SysOp access status");
    bind_text(db.get(), statement.get(), 2, handle);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "updating SysOp access");
    if (sqlite3_changes(db.get()) == 0) {
        Statement existence(db.get(), "SELECT 1 FROM accounts WHERE handle = ?1 COLLATE NOCASE");
        bind_text(db.get(), existence.get(), 1, handle);
        const int result = sqlite3_step(existence.get());
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("BBS account does not exist");
        }
        if (result != SQLITE_ROW) {
            check_sqlite(db.get(), result, "checking BBS account");
        }
    }
    make_database_private(database_path_);
}

void AccountStore::set_security_levels(
    std::string_view handle,
    int security_level,
    int download_security_level) const {
    if (!valid_handle(handle) || security_level < 0 || security_level > 255 ||
        download_security_level < 0 || download_security_level > 255) {
        throw std::invalid_argument("account and download security levels must be between 0 and 255");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "UPDATE accounts SET security_level = ?1, download_security_level = ?2 "
        "WHERE handle = ?3 COLLATE NOCASE");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 1, security_level),
        "binding account security level");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 2, download_security_level),
        "binding download security level");
    bind_text(db.get(), statement.get(), 3, handle);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "updating account security levels");
    if (sqlite3_changes(db.get()) == 0) {
        throw std::invalid_argument("BBS account does not exist");
    }
    make_database_private(database_path_);
}

void AccountStore::set_acs_flags(
    std::string_view handle,
    std::string_view ar_flags,
    std::string_view ac_flags) const {
    if (!valid_handle(handle)) {
        throw std::invalid_argument("invalid BBS account handle");
    }
    const std::string normalized_ar = normalize_acs_flags(ar_flags, false);
    const std::string normalized_ac = normalize_acs_flags(ac_flags, true);
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "UPDATE accounts SET acs_ar_flags = ?1, acs_ac_flags = ?2 WHERE handle = ?3 COLLATE NOCASE");
    bind_text(db.get(), statement.get(), 1, normalized_ar);
    bind_text(db.get(), statement.get(), 2, normalized_ac);
    bind_text(db.get(), statement.get(), 3, handle);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "updating account ACS flags");
    if (sqlite3_changes(db.get()) == 0) {
        throw std::invalid_argument("BBS account does not exist");
    }
    make_database_private(database_path_);
}

void AccountStore::set_credits(std::string_view handle, std::int64_t balance) const {
    if (!valid_handle(handle) ||
        balance < std::numeric_limits<std::int32_t>::min() ||
        balance > std::numeric_limits<std::int32_t>::max()) {
        throw std::invalid_argument("account credits must be between -2147483648 and 2147483647");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "UPDATE accounts SET credits = ?1 WHERE handle = ?2 COLLATE NOCASE");
    check_sqlite(db.get(), sqlite3_bind_int64(statement.get(), 1, balance), "binding account credits");
    bind_text(db.get(), statement.get(), 2, handle);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "setting account credits");
    if (sqlite3_changes(db.get()) == 0) {
        throw std::invalid_argument("BBS account does not exist");
    }
    make_database_private(database_path_);
}

void AccountStore::set_file_points(std::string_view handle, std::int64_t balance) const {
    if (!valid_handle(handle) || balance < 0 || balance > std::numeric_limits<std::int32_t>::max()) {
        throw std::invalid_argument("account file points must be between 0 and 2147483647");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "UPDATE accounts SET file_points = ?1 WHERE handle = ?2 COLLATE NOCASE");
    check_sqlite(db.get(), sqlite3_bind_int64(statement.get(), 1, balance), "binding account file points");
    bind_text(db.get(), statement.get(), 2, handle);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "setting account file points");
    if (sqlite3_changes(db.get()) == 0) {
        throw std::invalid_argument("BBS account does not exist");
    }
    make_database_private(database_path_);
}

void AccountStore::set_mailbox_closed(std::string_view handle, bool closed) const {
    if (!valid_handle(handle)) {
        throw std::invalid_argument("invalid BBS account handle");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "UPDATE accounts SET mailbox_closed = ?1 WHERE handle = ?2 COLLATE NOCASE");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 1, closed ? 1 : 0),
        "binding mailbox-closed setting");
    bind_text(db.get(), statement.get(), 2, handle);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "updating mailbox-closed setting");
    if (sqlite3_changes(db.get()) == 0) {
        throw std::invalid_argument("BBS account does not exist");
    }
    make_database_private(database_path_);
}

void AccountStore::set_expiration_date(std::string_view handle, std::string_view date) const {
    if (!valid_handle(handle)) {
        throw std::invalid_argument("invalid BBS account handle");
    }
    validate_expiration_date(date);
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "UPDATE accounts SET expiration_date = ?1 WHERE handle = ?2 COLLATE NOCASE");
    bind_text(db.get(), statement.get(), 1, date);
    bind_text(db.get(), statement.get(), 2, handle);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "updating account expiration date");
    if (sqlite3_changes(db.get()) == 0) {
        Statement existence(db.get(), "SELECT 1 FROM accounts WHERE handle = ?1 COLLATE NOCASE");
        bind_text(db.get(), existence.get(), 1, handle);
        const int result = sqlite3_step(existence.get());
        if (result == SQLITE_DONE) {
            throw std::invalid_argument("BBS account does not exist");
        }
        check_sqlite(db.get(), result, "checking BBS account");
    }
    make_database_private(database_path_);
}

void AccountStore::set_validation_level(const ValidationLevel& level) const {
    if (!valid_validation_key(level.key)) {
        throw std::invalid_argument("validation key must be one printable character other than Q");
    }
    if (level.expire_to_key != ' ' && !valid_validation_key(level.expire_to_key)) {
        throw std::invalid_argument("expire-to key must be blank or a valid validation key");
    }
    if ((level.expiration_days == 0) != (level.expire_to_key == ' ')) {
        throw std::invalid_argument("expiration days and expire-to key must both be set or both be blank");
    }
    if (level.security_level < 0 || level.security_level > 255 ||
        level.download_security_level < 0 || level.download_security_level > 255 ||
        level.start_menu < 0 || level.start_menu > 255 ||
        level.expiration_days < 0 || level.expiration_days > 65535 ||
        level.file_points < 0 || level.file_points > std::numeric_limits<std::int32_t>::max() ||
        level.credits < 0 ||
        level.credits > std::numeric_limits<std::int32_t>::max()) {
        throw std::invalid_argument("validation level values are outside Renegade's record ranges");
    }
    validate_profile_field(level.description, 30, "validation description");
    validate_profile_field(level.user_message, 78, "validation user message");
    const std::string ar_flags = normalize_acs_flags(level.ar_flags, false);
    const std::string ac_flags = normalize_acs_flags(level.ac_flags, true);

    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "INSERT INTO validation_levels(validation_key, expire_to_key, description, user_message, new_sl, new_dsl, "
        "new_menu, expiration_days, new_file_points, new_credits, soft_ar, soft_ac, new_ar, new_ac) "
        "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14) "
        "ON CONFLICT(validation_key) DO UPDATE SET expire_to_key=excluded.expire_to_key, "
        "description=excluded.description, user_message=excluded.user_message, new_sl=excluded.new_sl, "
        "new_dsl=excluded.new_dsl, new_menu=excluded.new_menu, expiration_days=excluded.expiration_days, "
        "new_file_points=excluded.new_file_points, new_credits=excluded.new_credits, soft_ar=excluded.soft_ar, "
        "soft_ac=excluded.soft_ac, new_ar=excluded.new_ar, new_ac=excluded.new_ac");
    const char key_text[] = {level.key, '\0'};
    const char expire_text[] = {level.expire_to_key, '\0'};
    bind_text(db.get(), statement.get(), 1, std::string_view(key_text, 1));
    bind_text(db.get(), statement.get(), 2,
        level.expire_to_key == ' ' ? std::string_view{} : std::string_view(expire_text, 1));
    bind_text(db.get(), statement.get(), 3, level.description);
    bind_text(db.get(), statement.get(), 4, level.user_message);
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 5, level.security_level), "binding validation SL");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 6, level.download_security_level), "binding validation DSL");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 7, level.start_menu), "binding validation menu");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 8, level.expiration_days), "binding validation expiration");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 9, level.file_points), "binding validation file points");
    check_sqlite(db.get(), sqlite3_bind_int64(statement.get(), 10, level.credits), "binding validation credits");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 11, level.soft_ar_flags ? 1 : 0), "binding validation AR mode");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 12, level.soft_ac_flags ? 1 : 0), "binding validation AC mode");
    bind_text(db.get(), statement.get(), 13, ar_flags);
    bind_text(db.get(), statement.get(), 14, ac_flags);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "saving validation level");
    make_database_private(database_path_);
}

void AccountStore::delete_validation_level(char key) const {
    if (!valid_validation_key(key)) {
        throw std::invalid_argument("validation key must be one printable character other than Q");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_sqlite(db.get(), sqlite3_exec(db.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr),
        "starting validation-level deletion");
    try {
        const char key_text[] = {key, '\0'};
        Statement reference(db.get(),
            "SELECT 1 FROM validation_levels WHERE expire_to_key = ?1 "
            "UNION ALL SELECT 1 FROM accounts WHERE expire_to_key = ?1 LIMIT 1");
        bind_text(db.get(), reference.get(), 1, std::string_view(key_text, 1));
        const int reference_result = sqlite3_step(reference.get());
        if (reference_result == SQLITE_ROW) {
            throw std::invalid_argument("another validation level or account still expires to this key");
        }
        check_sqlite(db.get(), reference_result, "checking validation-level references");
        Statement remove(db.get(), "DELETE FROM validation_levels WHERE validation_key = ?1");
        bind_text(db.get(), remove.get(), 1, std::string_view(key_text, 1));
        check_sqlite(db.get(), sqlite3_step(remove.get()), "deleting validation level");
        if (sqlite3_changes(db.get()) == 0) {
            throw std::invalid_argument("validation level does not exist");
        }
        check_sqlite(db.get(), sqlite3_exec(db.get(), "COMMIT", nullptr, nullptr, nullptr),
            "committing validation-level deletion");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

std::vector<ValidationLevel> AccountStore::validation_levels() const {
    initialize();
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "SELECT validation_key, expire_to_key, description, user_message, new_sl, new_dsl, new_menu, "
        "expiration_days, new_file_points, new_credits, soft_ar, soft_ac, new_ar, new_ac "
        "FROM validation_levels ORDER BY validation_key COLLATE BINARY");
    std::vector<ValidationLevel> levels;
    for (;;) {
        const int result = sqlite3_step(statement.get());
        if (result == SQLITE_DONE) {
            break;
        }
        check_sqlite(db.get(), result, "listing validation levels");
        levels.push_back(read_validation_level(statement.get()));
    }
    return levels;
}

void AccountStore::apply_validation_level(std::string_view handle, char key) const {
    if (!valid_handle(handle) || !valid_validation_key(key)) {
        throw std::invalid_argument("account handle or validation key is invalid");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    check_sqlite(db.get(), sqlite3_exec(db.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr),
        "starting account validation");
    try {
        apply_validation_level_in_transaction(db.get(), handle, key);
        check_sqlite(db.get(), sqlite3_exec(db.get(), "COMMIT", nullptr, nullptr, nullptr),
            "committing account validation");
    } catch (...) {
        (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    make_database_private(database_path_);
}

bool AccountStore::is_sysop(std::string_view handle) const {
    if (!valid_handle(handle)) {
        return false;
    }
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(), "SELECT is_sysop FROM accounts WHERE handle = ?1 COLLATE NOCASE");
    bind_text(db.get(), statement.get(), 1, handle);
    const int result = sqlite3_step(statement.get());
    if (result == SQLITE_DONE) {
        return false;
    }
    check_sqlite(db.get(), result, "looking up SysOp access");
    return sqlite3_column_int(statement.get(), 0) != 0;
}

AccountProfile AccountStore::profile(std::string_view handle) const {
    if (!valid_handle(handle)) {
        throw std::invalid_argument("invalid BBS account handle");
    }
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "SELECT handle, real_name, location, signature, ansi_color, clear_screen, pause_screens, hotkeys, expert_mode, credits, file_points, birth_date, sex, expiration_date, "
        "country, street, city_state, postal_code, phone, user_answer_1, user_answer_2, user_answer_3, "
        "CASE WHEN forgot_password_answer_hash = '' THEN 0 ELSE 1 END, mailbox_closed "
        "FROM accounts "
        "WHERE handle = ?1 COLLATE NOCASE");
    bind_text(db.get(), statement.get(), 1, handle);
    const int result = sqlite3_step(statement.get());
    if (result == SQLITE_DONE) {
        throw std::invalid_argument("BBS account does not exist");
    }
    check_sqlite(db.get(), result, "reading BBS account profile");
    const auto column = [&statement](int index) {
        const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), index));
        return value == nullptr ? std::string{} : std::string(value);
    };
    AccountProfile profile;
    profile.handle = column(0);
    profile.real_name = column(1);
    profile.location = column(2);
    profile.signature = column(3);
    profile.ansi_color = sqlite3_column_int(statement.get(), 4) != 0;
    profile.clear_screen = sqlite3_column_int(statement.get(), 5) != 0;
    profile.pause_screens = sqlite3_column_int(statement.get(), 6) != 0;
    profile.hotkeys = sqlite3_column_int(statement.get(), 7) != 0;
    profile.expert_mode = sqlite3_column_int(statement.get(), 8) != 0;
    profile.credits = sqlite3_column_int64(statement.get(), 9);
    profile.file_points = sqlite3_column_int64(statement.get(), 10);
    profile.birth_date = column(11);
    profile.sex = column(12).empty() ? '\0' : column(12).front();
    profile.expiration_date = column(13);
    profile.country = column(14);
    profile.street = column(15);
    profile.city_state = column(16);
    profile.postal_code = column(17);
    profile.phone = column(18);
    for (std::size_t index = 0; index < profile.user_answers.size(); ++index) {
        profile.user_answers[index] = column(static_cast<int>(19 + index));
    }
    profile.forgot_password_answer_set = sqlite3_column_int(statement.get(), 22) != 0;
    profile.mailbox_closed = sqlite3_column_int(statement.get(), 23) != 0;
    return profile;
}

void AccountStore::update_profile(const AccountProfile& profile) const {
    if (!valid_handle(profile.handle)) {
        throw std::invalid_argument("invalid BBS account handle");
    }
    validate_profile_field(profile.real_name, 48, "real name");
    validate_profile_field(profile.location, 80, "location");
    validate_profile_field(profile.signature, 80, "signature");
    validate_profile_field(profile.country, 16, "country");
    validate_profile_field(profile.street, 30, "street address");
    validate_profile_field(profile.city_state, 30, "city and state");
    validate_profile_field(profile.postal_code, 10, "postal code");
    validate_profile_field(profile.phone, 12, "phone number");
    for (const std::string& answer : profile.user_answers) {
        validate_profile_field(answer, 35, "SysOp-defined answer");
    }
    validate_birth_date(profile.birth_date);
    validate_sex(profile.sex);
    validate_expiration_date(profile.expiration_date);

    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "UPDATE accounts SET real_name = ?1, location = ?2, signature = ?3, "
        "ansi_color = ?4, clear_screen = ?5, pause_screens = ?6, hotkeys = ?7, expert_mode = ?8, "
        "birth_date = ?9, sex = ?10, expiration_date = ?11, country = ?12, street = ?13, "
        "city_state = ?14, postal_code = ?15, phone = ?16, user_answer_1 = ?17, "
        "user_answer_2 = ?18, user_answer_3 = ?19, mailbox_closed = ?20 WHERE handle = ?21 COLLATE NOCASE");
    bind_text(db.get(), statement.get(), 1, profile.real_name);
    bind_text(db.get(), statement.get(), 2, profile.location);
    bind_text(db.get(), statement.get(), 3, profile.signature);
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 4, profile.ansi_color ? 1 : 0),
        "binding ANSI color preference");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 5, profile.clear_screen ? 1 : 0),
        "binding screen-clear preference");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 6, profile.pause_screens ? 1 : 0),
        "binding screen-pause preference");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 7, profile.hotkeys ? 1 : 0),
        "binding hotkey preference");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 8, profile.expert_mode ? 1 : 0),
        "binding expert-mode preference");
    bind_text(db.get(), statement.get(), 9, profile.birth_date);
    const char sex[] = {profile.sex == '\0' ? '\0' : static_cast<char>(
        std::toupper(static_cast<unsigned char>(profile.sex))), '\0'};
    bind_text(db.get(), statement.get(), 10, sex[0] == '\0' ? std::string_view{} : std::string_view(sex, 1));
    bind_text(db.get(), statement.get(), 11, profile.expiration_date);
    bind_text(db.get(), statement.get(), 12, profile.country);
    bind_text(db.get(), statement.get(), 13, profile.street);
    bind_text(db.get(), statement.get(), 14, profile.city_state);
    bind_text(db.get(), statement.get(), 15, profile.postal_code);
    bind_text(db.get(), statement.get(), 16, profile.phone);
    bind_text(db.get(), statement.get(), 17, profile.user_answers[0]);
    bind_text(db.get(), statement.get(), 18, profile.user_answers[1]);
    bind_text(db.get(), statement.get(), 19, profile.user_answers[2]);
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 20, profile.mailbox_closed ? 1 : 0),
        "binding mailbox-closed preference");
    bind_text(db.get(), statement.get(), 21, profile.handle);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "updating BBS account profile");
    if (sqlite3_changes(db.get()) == 0) {
        throw std::invalid_argument("BBS account does not exist");
    }
    make_database_private(database_path_);
}

void AccountStore::set_forgot_password_answer(
    std::string_view handle, std::string_view answer) const {
    if (!valid_handle(handle)) {
        throw std::invalid_argument("invalid BBS account handle");
    }
    validate_profile_field(answer, 40, "password-recovery answer");
    initialize();
    const std::string hash = answer.empty() ? std::string{} : hash_password(answer);
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "UPDATE accounts SET forgot_password_answer_hash = ?1 WHERE handle = ?2 COLLATE NOCASE");
    bind_text(db.get(), statement.get(), 1, hash);
    bind_text(db.get(), statement.get(), 2, handle);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "saving password-recovery answer");
    if (sqlite3_changes(db.get()) == 0) {
        throw std::invalid_argument("BBS account does not exist");
    }
    make_database_private(database_path_);
}

void AccountStore::set_forgot_password_question(std::string_view question) const {
    validate_profile_field(question, 70, "password-recovery question");
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "INSERT INTO account_system_settings(setting_key, setting_value) "
        "VALUES('forgot_password_question', ?1) ON CONFLICT(setting_key) "
        "DO UPDATE SET setting_value = excluded.setting_value");
    bind_text(db.get(), statement.get(), 1, question);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "saving password-recovery question");
    make_database_private(database_path_);
}

std::string AccountStore::forgot_password_question() const {
    initialize();
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "SELECT setting_value FROM account_system_settings "
        "WHERE setting_key = 'forgot_password_question'");
    const int result = sqlite3_step(statement.get());
    if (result == SQLITE_DONE) {
        return {};
    }
    check_sqlite(db.get(), result, "reading password-recovery question");
    const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 0));
    return value == nullptr ? std::string{} : std::string(value);
}

void AccountStore::set_custom_user_question(int question, std::string_view prompt) const {
    if (question < 1 || question > 3) {
        throw std::invalid_argument("custom user question number must be 1, 2, or 3");
    }
    validate_profile_field(prompt, 70, "custom user question");
    initialize();
    const std::string setting_key = "user_question_" + std::to_string(question);
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "INSERT INTO account_system_settings(setting_key, setting_value) VALUES(?1, ?2) "
        "ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value");
    bind_text(db.get(), statement.get(), 1, setting_key);
    bind_text(db.get(), statement.get(), 2, prompt);
    check_sqlite(db.get(), sqlite3_step(statement.get()), "saving custom user question");
    make_database_private(database_path_);
}

std::array<std::string, 3> AccountStore::custom_user_questions() const {
    initialize();
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "SELECT setting_key, setting_value FROM account_system_settings "
        "WHERE setting_key IN ('user_question_1', 'user_question_2', 'user_question_3')");
    std::array<std::string, 3> questions;
    int result = SQLITE_ROW;
    while ((result = sqlite3_step(statement.get())) == SQLITE_ROW) {
        const auto* key = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 0));
        const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 1));
        if (key == nullptr || value == nullptr) {
            continue;
        }
        const std::string_view setting_key(key);
        if (setting_key == "user_question_1") questions[0] = value;
        else if (setting_key == "user_question_2") questions[1] = value;
        else if (setting_key == "user_question_3") questions[2] = value;
    }
    check_sqlite(db.get(), result, "reading custom user questions");
    return questions;
}

bool AccountStore::verify_forgot_password_answer(
    std::string_view handle, std::string_view answer) const {
    if (!valid_handle(handle)) {
        return false;
    }
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "SELECT forgot_password_answer_hash FROM accounts WHERE handle = ?1 COLLATE NOCASE");
    bind_text(db.get(), statement.get(), 1, handle);
    const int result = sqlite3_step(statement.get());
    if (result == SQLITE_DONE) {
        return false;
    }
    check_sqlite(db.get(), result, "reading password-recovery answer");
    const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 0));
    return value != nullptr && value[0] != '\0' && verify_password_hash(value, answer);
}

std::array<bool, 27> AccountStore::signup_question_states() const {
    initialize();
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "SELECT source_question, enabled FROM signup_question_settings");
    std::array<bool, 27> enabled{};
    for (;;) {
        const int result = sqlite3_step(statement.get());
        if (result == SQLITE_DONE) {
            return enabled;
        }
        check_sqlite(db.get(), result, "reading signup-question settings");
        const int source_question = sqlite3_column_int(statement.get(), 0);
        if (source_question >= 0 && source_question < static_cast<int>(enabled.size())) {
            enabled[static_cast<std::size_t>(source_question)] =
                sqlite3_column_int(statement.get(), 1) != 0;
        }
    }
}

void AccountStore::set_signup_question_enabled(int source_question, bool enabled) const {
    const bool personal_question = source_question >= 2 && source_question <= 12;
    const bool supported_preference = source_question == 16 ||
        (source_question >= 19 && source_question <= 22) || source_question == 25;
    if (!personal_question && source_question != 14 && !supported_preference) {
        throw std::invalid_argument(
            "signup question must be a supported source field (2-12, 14, 16, 19-22, or 25)");
    }
    initialize();
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "INSERT INTO signup_question_settings(source_question, enabled) VALUES(?1, ?2) "
        "ON CONFLICT(source_question) DO UPDATE SET enabled = excluded.enabled");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 1, source_question),
        "binding signup question");
    check_sqlite(db.get(), sqlite3_bind_int(statement.get(), 2, enabled ? 1 : 0),
        "binding signup-question state");
    check_sqlite(db.get(), sqlite3_step(statement.get()), "updating signup-question setting");
    make_database_private(database_path_);
}

TimeBankStatus AccountStore::time_bank_status(std::string_view handle) const {
    if (!valid_handle(handle)) {
        throw std::invalid_argument("invalid BBS account handle");
    }
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "SELECT time_bank_minutes, time_bank_deposited_today, time_bank_withdrawn_today, time_bank_day "
        "FROM accounts WHERE handle = ?1 COLLATE NOCASE");
    bind_text(db.get(), statement.get(), 1, handle);
    const int result = sqlite3_step(statement.get());
    if (result == SQLITE_DONE) {
        throw std::invalid_argument("BBS account does not exist");
    }
    check_sqlite(db.get(), result, "reading time bank status");
    if (sqlite_text(statement.get(), 3) != local_date_key()) {
        return {sqlite3_column_int(statement.get(), 0), 0, 0};
    }
    return {
        sqlite3_column_int(statement.get(), 0),
        sqlite3_column_int(statement.get(), 1),
        sqlite3_column_int(statement.get(), 2),
    };
}

TimeBankStatus AccountStore::deposit_time(
    std::string_view handle, int minutes, int bank_limit, int daily_limit) const {
    if (!valid_handle(handle)) {
        throw std::invalid_argument("invalid BBS account handle");
    }
    if (bank_limit < 0 || bank_limit > 32767 || daily_limit < 0 || daily_limit > 32767) {
        throw std::invalid_argument("time bank limits must be between 0 and 32767 minutes");
    }
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    const TimeBankStatus status = mutate_time_bank(
        db.get(), handle, minutes, bank_limit, daily_limit, true);
    make_database_private(database_path_);
    return status;
}

TimeBankStatus AccountStore::withdraw_time(
    std::string_view handle, int minutes, int daily_limit) const {
    if (!valid_handle(handle)) {
        throw std::invalid_argument("invalid BBS account handle");
    }
    if (daily_limit < 0 || daily_limit > 32767) {
        throw std::invalid_argument("daily time bank withdrawal limit must be between 0 and 32767 minutes");
    }
    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    const TimeBankStatus status = mutate_time_bank(
        db.get(), handle, minutes, 0, daily_limit, false);
    make_database_private(database_path_);
    return status;
}

std::vector<AccountSummary> AccountStore::list_accounts() const {
    initialize();
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(),
        "SELECT handle, created_at, enabled, approved, is_sysop, real_name, location, signature, "
        "security_level, download_security_level, acs_ar_flags, acs_ac_flags, credits, file_points, mailbox_closed, birth_date, sex, expiration_date, "
        "country, street, city_state, postal_code, phone, user_answer_1, user_answer_2, user_answer_3, "
        "subscription_key, expire_to_key, user_start_menu "
        "FROM accounts ORDER BY handle COLLATE NOCASE");
    std::vector<AccountSummary> accounts;
    for (;;) {
        const int result = sqlite3_step(statement.get());
        if (result == SQLITE_DONE) {
            break;
        }
        check_sqlite(db.get(), result, "listing BBS accounts");
        const std::string handle = sqlite_text(statement.get(), 0);
        const std::string created_at = sqlite_text(statement.get(), 1);
        if (handle.empty() || created_at.empty()) {
            continue;
        }
        accounts.push_back({
            handle,
            created_at,
            sqlite3_column_int(statement.get(), 2) != 0,
            sqlite3_column_int(statement.get(), 3) != 0,
            sqlite3_column_int(statement.get(), 4) != 0,
            sqlite_text(statement.get(), 5),
            sqlite_text(statement.get(), 6),
            sqlite_text(statement.get(), 7),
            sqlite3_column_int(statement.get(), 8),
            sqlite3_column_int(statement.get(), 9),
            sqlite_text(statement.get(), 10),
            sqlite_text(statement.get(), 11),
            sqlite3_column_int64(statement.get(), 12),
            sqlite3_column_int64(statement.get(), 13),
            sqlite3_column_int(statement.get(), 14) != 0,
            sqlite_text(statement.get(), 15),
            sqlite_text(statement.get(), 16).empty() ? '\0' : sqlite_text(statement.get(), 16).front(),
            sqlite_text(statement.get(), 17),
            sqlite_text(statement.get(), 18),
            sqlite_text(statement.get(), 19),
            sqlite_text(statement.get(), 20),
            sqlite_text(statement.get(), 21),
            sqlite_text(statement.get(), 22),
            {sqlite_text(statement.get(), 23), sqlite_text(statement.get(), 24),
                sqlite_text(statement.get(), 25)},
            sqlite_text(statement.get(), 26).empty() ? '\0' : sqlite_text(statement.get(), 26).front(),
            sqlite_text(statement.get(), 27).empty() ? '\0' : sqlite_text(statement.get(), 27).front(),
            sqlite3_column_int(statement.get(), 28),
        });
    }
    return accounts;
}

std::uint64_t AccountStore::count_approved_accounts() const {
    Database db(database_path_, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX);
    Statement statement(db.get(), "SELECT COUNT(*) FROM accounts WHERE approved = 1");
    const int result = sqlite3_step(statement.get());
    if (result != SQLITE_ROW) {
        throw std::runtime_error("counting approved BBS accounts: " + std::string(sqlite3_errmsg(db.get())));
    }
    const sqlite3_int64 count = sqlite3_column_int64(statement.get(), 0);
    return count > 0 ? static_cast<std::uint64_t>(count) : 0;
}

std::optional<AuthenticatedAccount> AccountStore::authenticate(
    std::string_view handle,
    std::string_view password) const {
    if (!valid_handle(handle) || password.empty() || password.size() > 128) {
        return std::nullopt;
    }

    Database db(database_path_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    std::string authenticated_handle;
    std::string previous_login;
    std::uint64_t login_count{};
    std::string expiration_date;
    std::string expire_to_key;
    {
    Statement statement(db.get(),
        "SELECT handle, password_hash, enabled, approved, last_login_at, created_at, expiration_date, expire_to_key, total_logins "
        "FROM accounts WHERE handle = ?1 COLLATE NOCASE");
    bind_text(db.get(), statement.get(), 1, handle);
    const int result = sqlite3_step(statement.get());
    if (result == SQLITE_DONE) {
        // Keep SSH authentication timing similar for unknown handles and bad passwords.
        (void)argon2id_verify(kUnknownAccountPasswordHash, password.data(), password.size());
        return std::nullopt;
    }
    check_sqlite(db.get(), result, "looking up BBS account");

    const auto* stored_handle = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 0));
    const auto* stored_hash = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 1));
    if (stored_handle == nullptr || stored_hash == nullptr) {
        return std::nullopt;
    }

    const int verify_result = argon2id_verify(stored_hash, password.data(), password.size());
    if (verify_result != ARGON2_OK || sqlite3_column_int(statement.get(), 2) == 0 ||
        sqlite3_column_int(statement.get(), 3) == 0) {
        return std::nullopt;
    }
    expiration_date = sqlite_text(statement.get(), 6);
    expire_to_key = sqlite_text(statement.get(), 7);
    authenticated_handle = stored_handle;
    const auto* previous = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 4));
    const auto* created = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 5));
    previous_login = previous != nullptr && previous[0] != '\0'
        ? previous
        : (created == nullptr ? std::string{} : std::string(created));
    const sqlite3_int64 stored_logins = sqlite3_column_int64(statement.get(), 8);
    login_count = stored_logins > 0 ? static_cast<std::uint64_t>(stored_logins) : 0;
    }
    if (!expiration_date.empty() && expiration_date < local_date_key()) {
        if (expire_to_key.size() != 1 || !valid_validation_key(expire_to_key.front())) {
            return std::nullopt;
        }
        check_sqlite(db.get(), sqlite3_exec(db.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr),
            "starting expired-account validation");
        try {
            apply_validation_level_in_transaction(db.get(), authenticated_handle, expire_to_key.front());
            check_sqlite(db.get(), sqlite3_exec(db.get(), "COMMIT", nullptr, nullptr, nullptr),
                "committing expired-account validation");
        } catch (const std::invalid_argument&) {
            (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
            return std::nullopt;
        } catch (...) {
            (void)sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, nullptr);
            throw;
        }
        Statement renewed(db.get(), "SELECT expiration_date FROM accounts WHERE handle = ?1 COLLATE NOCASE");
        bind_text(db.get(), renewed.get(), 1, authenticated_handle);
        const int renewed_result = sqlite3_step(renewed.get());
        check_sqlite(db.get(), renewed_result, "checking expiration after validation");
        if (sqlite_text(renewed.get(), 0) < local_date_key() &&
            !sqlite_text(renewed.get(), 0).empty()) {
            return std::nullopt;
        }
    }
    Statement update(db.get(),
        "UPDATE accounts SET last_login_at = CURRENT_TIMESTAMP, "
        "total_logins = CASE WHEN total_logins < 9223372036854775807 "
        "THEN total_logins + 1 ELSE total_logins END WHERE handle = ?1 COLLATE NOCASE");
    bind_text(db.get(), update.get(), 1, authenticated_handle);
    check_sqlite(db.get(), sqlite3_step(update.get()), "recording account login date");
    if (login_count < static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        ++login_count;
    }
    return AuthenticatedAccount{
        std::move(authenticated_handle), std::move(previous_login), login_count};
}

const std::string& AccountStore::database_path() const noexcept {
    return database_path_;
}

std::string hash_password(std::string_view password) {
    std::array<unsigned char, kSaltBytes> salt{};
    std::size_t filled = 0;
    while (filled < salt.size()) {
        const ssize_t result = ::getrandom(salt.data() + filled, salt.size() - filled, 0);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::system_error(errno, std::generic_category(), "getting random password salt");
        }
        if (result == 0) {
            throw std::runtime_error("random source returned no password salt bytes");
        }
        filled += static_cast<std::size_t>(result);
    }

    std::array<char, kEncodedHashBytes> encoded{};
    const int result = argon2id_hash_encoded(
        kArgonTimeCost,
        kArgonMemoryKiB,
        kArgonParallelism,
        password.data(),
        password.size(),
        salt.data(),
        salt.size(),
        kHashBytes,
        encoded.data(),
        encoded.size());
    if (result != ARGON2_OK) {
        throw std::runtime_error("could not hash password with Argon2id: " + std::string(argon2_error_message(result)));
    }
    return std::string(encoded.data());
}

bool verify_password_hash(std::string_view encoded_hash, std::string_view password) noexcept {
    if (encoded_hash.empty()) {
        return false;
    }
    try {
        const std::string terminated_hash(encoded_hash);
        return argon2id_verify(terminated_hash.c_str(), password.data(), password.size()) == ARGON2_OK;
    } catch (...) {
        return false;
    }
}

bool valid_handle(std::string_view handle) noexcept {
    if (handle.empty() || handle.size() > 32) {
        return false;
    }
    for (const unsigned char character : handle) {
        const bool valid =
            (character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9') ||
            character == '.' || character == '-' || character == '_';
        if (!valid) {
            return false;
        }
    }
    return true;
}

} // namespace renegade
