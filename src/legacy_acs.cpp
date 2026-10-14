#include "legacy_acs.hpp"

#include <charconv>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <optional>
#include <stdexcept>
#include <string_view>

namespace renegade {
namespace {

int age_from_birth_date(std::string_view birth_date) noexcept {
    if (birth_date.size() != 10 || birth_date[4] != '-' || birth_date[7] != '-') {
        return 0;
    }
    int birth_year{};
    int birth_month{};
    int birth_day{};
    const auto parse = [](std::string_view text, int& output) {
        const auto result = std::from_chars(text.data(), text.data() + text.size(), output);
        return result.ec == std::errc{} && result.ptr == text.data() + text.size();
    };
    if (!parse(birth_date.substr(0, 4), birth_year) ||
        !parse(birth_date.substr(5, 2), birth_month) ||
        !parse(birth_date.substr(8, 2), birth_day)) {
        return 0;
    }
    static constexpr int month_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool leap_year = birth_year % 4 == 0 &&
        (birth_year % 100 != 0 || birth_year % 400 == 0);
    if (birth_month < 1 || birth_month > 12 || birth_day < 1 ||
        birth_day > month_days[birth_month - 1] + (birth_month == 2 && leap_year ? 1 : 0)) {
        return 0;
    }
    const std::time_t current_time = std::time(nullptr);
    std::tm local_date{};
    if (localtime_r(&current_time, &local_date) == nullptr) {
        return 0;
    }
    int age = local_date.tm_year + 1900 - birth_year;
    const int current_month = local_date.tm_mon + 1;
    if (current_month < birth_month || (current_month == birth_month && local_date.tm_mday < birth_day)) {
        --age;
    }
    return age > 0 ? age : 0;
}

std::optional<int> days_until_expiration(std::string_view expiration_date) noexcept {
    if (expiration_date.size() != 10 || expiration_date[4] != '-' || expiration_date[7] != '-') {
        return std::nullopt;
    }
    int year{};
    unsigned int month{};
    unsigned int day{};
    const auto parse = [](std::string_view text, auto& output) {
        const auto result = std::from_chars(text.data(), text.data() + text.size(), output);
        return result.ec == std::errc{} && result.ptr == text.data() + text.size();
    };
    if (!parse(expiration_date.substr(0, 4), year) ||
        !parse(expiration_date.substr(5, 2), month) ||
        !parse(expiration_date.substr(8, 2), day)) {
        return std::nullopt;
    }
    if (year < 1) {
        return std::nullopt;
    }
    const std::chrono::year_month_day expiry{
        std::chrono::year{year}, std::chrono::month{month}, std::chrono::day{day}};
    if (!expiry.ok()) {
        return std::nullopt;
    }
    const std::time_t current_time = std::time(nullptr);
    std::tm local_date{};
    if (localtime_r(&current_time, &local_date) == nullptr) {
        return std::nullopt;
    }
    const std::chrono::year_month_day today{
        std::chrono::year{local_date.tm_year + 1900},
        std::chrono::month{static_cast<unsigned int>(local_date.tm_mon + 1)},
        std::chrono::day{static_cast<unsigned int>(local_date.tm_mday)}};
    const auto difference = std::chrono::sys_days{expiry} - std::chrono::sys_days{today};
    return static_cast<int>(difference.count());
}

class Parser final {
public:
    Parser(std::string_view expression, const AccessLevels& levels)
        : expression_(expression), levels_(levels) {}

    bool evaluate() {
        skip_spaces();
        if (position_ == expression_.size()) {
            valid_ = true;
            return true;
        }
        const bool result = parse_or();
        skip_spaces();
        valid_ = valid_ && position_ == expression_.size();
        if (!valid_) {
            throw std::invalid_argument("unsupported or malformed Renegade ACS expression");
        }
        return result;
    }

    [[nodiscard]] bool valid() const noexcept { return valid_; }

private:
    std::string_view expression_;
    const AccessLevels& levels_;
    std::size_t position_{};
    bool valid_{};

    void skip_spaces() {
        while (position_ < expression_.size() &&
            std::isspace(static_cast<unsigned char>(expression_[position_])) != 0) {
            ++position_;
        }
    }

    bool parse_or() {
        bool value = parse_and();
        skip_spaces();
        while (position_ < expression_.size() && expression_[position_] == '|') {
            ++position_;
            const bool right = parse_and();
            value = value || right;
            skip_spaces();
        }
        return value;
    }

    bool parse_and() {
        bool value = parse_unary();
        for (;;) {
            skip_spaces();
            if (position_ >= expression_.size() || expression_[position_] == ')' ||
                expression_[position_] == '|') {
                return value;
            }
            if (expression_[position_] == '&') {
                ++position_;
                skip_spaces();
                if (position_ >= expression_.size() || expression_[position_] == ')' ||
                    expression_[position_] == '|' || expression_[position_] == '&') {
                    throw std::invalid_argument("missing operand in Renegade ACS expression");
                }
            }
            const bool right = parse_unary();
            value = value && right;
        }
    }

    bool parse_unary() {
        skip_spaces();
        if (position_ >= expression_.size()) {
            throw std::invalid_argument("missing operand in Renegade ACS expression");
        }
        if (expression_[position_] == '!') {
            ++position_;
            return !parse_unary();
        }
        if (expression_[position_] == '(') {
            ++position_;
            const bool value = parse_or();
            skip_spaces();
            if (position_ >= expression_.size() || expression_[position_] != ')') {
                throw std::invalid_argument("unclosed group in Renegade ACS expression");
            }
            ++position_;
            return value;
        }
        if (expression_[position_] == '^') {
            ++position_;
            return true;
        }
        if (expression_[position_] == '%') {
            ++position_;
            return false;
        }

        const char token = static_cast<char>(std::toupper(
            static_cast<unsigned char>(expression_[position_++])));
        if (token != 'A' && token != 'S' && token != 'D' && token != 'F' && token != 'R' &&
            token != 'P' && token != 'H' && token != 'W' && token != 'U' &&
            token != 'B' && token != 'E' && token != 'G' && token != 'K' && token != 'L' &&
            token != 'J' && token != 'M' && token != 'N' && token != 'T' && token != 'X' &&
            token != 'Y' && token != 'Z' && token != 'I' && token != 'O' && token != 'V') {
            throw std::invalid_argument("unsupported token in Renegade ACS expression");
        }
        if (token == 'E') {
            if (position_ >= expression_.size()) {
                throw std::invalid_argument("terminal ACS token needs a capability character");
            }
            const char capability = static_cast<char>(std::toupper(
                static_cast<unsigned char>(expression_[position_++])));
            if (capability == 'A' || capability == '1') {
                return true;
            }
            if (capability == 'N' || capability == 'V' || capability == 'R') {
                return false;
            }
            throw std::invalid_argument("unsupported terminal ACS capability");
        }
        if (token == 'G') {
            if (position_ >= expression_.size() || std::isspace(
                    static_cast<unsigned char>(expression_[position_])) != 0 ||
                expression_[position_] == ')' || expression_[position_] == '|' || expression_[position_] == '&') {
                throw std::invalid_argument("gender ACS token needs a character");
            }
            const char required = static_cast<char>(std::toupper(
                static_cast<unsigned char>(expression_[position_++])));
            return levels_.sex != '\0' &&
                static_cast<char>(std::toupper(static_cast<unsigned char>(levels_.sex))) == required;
        }
        if (token == 'M') {
            return levels_.voted_in_all_polls;
        }
        if (token == 'J') {
            return levels_.novice_help;
        }
        if (token == 'F' || token == 'R') {
            if (position_ >= expression_.size()) {
                throw std::invalid_argument("flag ACS token needs a flag character");
            }
            const char flag = static_cast<char>(std::toupper(
                static_cast<unsigned char>(expression_[position_++])));
            if (token == 'F') {
                if (flag < '@' || flag > 'Z') {
                    throw std::invalid_argument("AR ACS flag must be @ through Z");
                }
                return levels_.ar_flags.find(flag) != std::string::npos;
            }
            constexpr std::string_view supported_ac_flags = "LCVUA*PEKM1234";
            if (supported_ac_flags.find(flag) == std::string_view::npos) {
                throw std::invalid_argument("unsupported AC ACS flag");
            }
            return levels_.ac_flags.find(flag) != std::string::npos;
        }
        if (token == 'Z') {
            if (position_ >= expression_.size() || std::isspace(
                    static_cast<unsigned char>(expression_[position_])) != 0 ||
                expression_[position_] == ')' || expression_[position_] == '|' || expression_[position_] == '&') {
                throw std::invalid_argument("post-ratio ACS token needs a compatibility character");
            }
            ++position_; // The original parser consumes one character here; the condition uses no value.
            const bool exempt = levels_.ac_flags.find('2') != std::string::npos;
            if (exempt || levels_.post_ratio_percent <= 0 || levels_.total_calls == 0 ||
                levels_.total_calls <= static_cast<std::uint64_t>(100 / levels_.post_ratio_percent)) {
                return true;
            }
            return (static_cast<long double>(levels_.public_posts) * 100.0L /
                static_cast<long double>(levels_.total_calls)) >=
                static_cast<long double>(levels_.post_ratio_percent);
        }
        if (token == 'I') {
            if (position_ >= expression_.size() || std::isspace(
                    static_cast<unsigned char>(expression_[position_])) != 0 ||
                expression_[position_] == ')' || expression_[position_] == '|' || expression_[position_] == '&') {
                throw std::invalid_argument("invisible-mode ACS token needs a compatibility character");
            }
            ++position_; // The original ACS parser consumes but does not inspect this character.
            return levels_.invisible;
        }
        if (token == 'O') {
            if (position_ >= expression_.size() || std::isspace(
                    static_cast<unsigned char>(expression_[position_])) != 0 ||
                expression_[position_] == ')' || expression_[position_] == '|' || expression_[position_] == '&') {
                throw std::invalid_argument("SysOp-availability ACS token needs a compatibility character");
            }
            ++position_; // The original ACS parser consumes but does not inspect this character.
            return levels_.sysop_available;
        }
        if (token == 'V') {
            if (position_ >= expression_.size() || std::isspace(
                    static_cast<unsigned char>(expression_[position_])) != 0 ||
                expression_[position_] == ')' || expression_[position_] == '|' || expression_[position_] == '&') {
                throw std::invalid_argument("validation ACS token needs a compatibility character");
            }
            ++position_; // The original ACS parser consumes but does not inspect this character.
            return levels_.validation_key_active &&
                levels_.security_level > levels_.validation_new_security_level;
        }

        const std::size_t value_start = position_;
        while (position_ < expression_.size() &&
            std::isdigit(static_cast<unsigned char>(expression_[position_])) != 0) {
            ++position_;
        }
        if (position_ == value_start) {
            throw std::invalid_argument("security-level ACS token needs a numeric value");
        }
        int required{};
        const char* begin = expression_.data() + value_start;
        const char* end = expression_.data() + position_;
        const auto parsed = std::from_chars(begin, end, required);
        const int max_value = token == 'A' || token == 'N' || token == 'P' || token == 'U' || token == 'B' ||
            token == 'T' || token == 'X' ||
            token == 'K' || token == 'L' ? 32767 :
            token == 'H' ? 23 : token == 'W' ? 6 : token == 'Y' ? 32767 : 255;
        if (parsed.ec != std::errc{} || parsed.ptr != end || required < 0 || required > max_value) {
            if (token == 'P') {
                throw std::invalid_argument("credit ACS value must be between 0 and 32767");
            }
            if (token == 'H') {
                throw std::invalid_argument("hour ACS value must be between 0 and 23");
            }
            if (token == 'W') {
                throw std::invalid_argument("weekday ACS value must be between 0 and 6");
            }
            if (token == 'U') {
                throw std::invalid_argument("user-number ACS value must be between 0 and 32767");
            }
            if (token == 'B') {
                throw std::invalid_argument("baud ACS value must be between 0 and 32767");
            }
            if (token == 'K' || token == 'L') {
                throw std::invalid_argument("area-number ACS value must be between 0 and 32767");
            }
            if (token == 'Y') {
                throw std::invalid_argument("online-minutes ACS value must be between 0 and 32767");
            }
            if (token == 'A') {
                throw std::invalid_argument("age ACS value must be between 0 and 32767");
            }
            if (token == 'X') {
                throw std::invalid_argument("expiration ACS value must be between 0 and 32767 days");
            }
            throw std::invalid_argument("security-level ACS value must be between 0 and 255");
        }
        if (token == 'P') {
            return levels_.message_credits >= required;
        }
        if (token == 'A') {
            return age_from_birth_date(levels_.birth_date) >= required;
        }
        if (token == 'U') {
            return levels_.user_number == required;
        }
        if (token == 'N') {
            return levels_.node_number == required;
        }
        if (token == 'T') {
            return levels_.remaining_minutes >= required;
        }
        if (token == 'X') {
            const std::optional<int> days = days_until_expiration(levels_.expiration_date);
            return days.has_value() && *days <= required;
        }
        if (token == 'K') {
            return levels_.message_area_number == required;
        }
        if (token == 'L') {
            return levels_.file_area_number == required;
        }
        if (token == 'Y') {
            return levels_.online_minutes >= required;
        }
        if (token == 'B') {
            // SSH has no serial COM port, matching Renegade's ComPortSpeed=0 pass case.
            return true;
        }
        if (token == 'H' || token == 'W') {
            const std::time_t current_time = std::time(nullptr);
            std::tm local_time{};
            if (localtime_r(&current_time, &local_time) == nullptr) {
                return false;
            }
            return token == 'H' ? local_time.tm_hour == required : local_time.tm_wday == required;
        }
        if (levels_.is_sysop) {
            return true;
        }
        const int actual = token == 'S' ? levels_.security_level : levels_.download_security_level;
        return actual >= required;
    }
};

} // namespace

bool valid_legacy_acs(std::string_view expression) noexcept {
    if (expression.size() > 20) {
        return false;
    }
    try {
        Parser parser(expression, AccessLevels{});
        (void)parser.evaluate();
        return true;
    } catch (...) {
        return false;
    }
}

bool evaluate_legacy_acs(std::string_view expression, const AccessLevels& levels) noexcept {
    if (expression.empty()) {
        return true;
    }
    if (expression.size() > 20) {
        return false;
    }
    try {
        Parser parser(expression, levels);
        return parser.evaluate();
    } catch (...) {
        return false;
    }
}

} // namespace renegade
