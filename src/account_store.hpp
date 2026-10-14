#pragma once

#include <cstdint>
#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace renegade {

struct AccountSummary {
    std::string handle;
    std::string created_at;
    bool enabled{};
    bool approved{};
    bool is_sysop{};
    std::string real_name;
    std::string location;
    std::string signature;
    int security_level{10};
    int download_security_level{10};
    std::string acs_ar_flags;
    std::string acs_ac_flags;
    std::int64_t credits{};
    std::int64_t file_points{};
    bool mailbox_closed{};
    std::string birth_date;
    char sex{};
    std::string expiration_date;
    std::string country;
    std::string street;
    std::string city_state;
    std::string postal_code;
    std::string phone;
    std::array<std::string, 3> user_answers;
    char subscription_key{};
    char expire_to_key{};
    int start_menu{};
};

struct ValidationLevel {
    char key{};
    char expire_to_key{' '};
    std::string description;
    std::string user_message;
    int security_level{10};
    int download_security_level{10};
    int start_menu{};
    int expiration_days{};
    int file_points{};
    std::int64_t credits{};
    bool soft_ar_flags{true};
    bool soft_ac_flags{true};
    std::string ar_flags;
    std::string ac_flags;
};

struct AccountProfile {
    std::string handle;
    std::string real_name;
    std::string location;
    std::string signature;
    bool ansi_color{true};
    bool clear_screen{true};
    bool pause_screens{true};
    bool hotkeys{true};
    bool expert_mode{};
    std::int64_t credits{};
    std::int64_t file_points{};
    std::string birth_date;
    char sex{};
    std::string expiration_date;
    std::string country;
    std::string street;
    std::string city_state;
    std::string postal_code;
    std::string phone;
    std::array<std::string, 3> user_answers;
    bool forgot_password_answer_set{};
    bool mailbox_closed{};
};

struct TimeBankStatus {
    int minutes{};
    int deposited_today{};
    int withdrawn_today{};
};

struct AuthenticatedAccount {
    std::string handle;
    std::string previous_login;
    std::uint64_t login_count{};
};

class AccountStore {
public:
    explicit AccountStore(std::string database_path);

    void initialize() const;
    void create_user(std::string_view handle, std::string_view password) const;
    [[nodiscard]] bool create_pending_user(std::string_view handle, std::string_view password) const;
    void set_password(std::string_view handle, std::string_view password) const;
    [[nodiscard]] bool verify_password(std::string_view handle, std::string_view password) const;
    void change_password(
        std::string_view handle, std::string_view current_password,
        std::string_view new_password) const;
    void set_enabled(std::string_view handle, bool enabled) const;
    void set_sysop(std::string_view handle, bool is_sysop) const;
    void set_security_levels(std::string_view handle, int security_level, int download_security_level) const;
    void set_acs_flags(
        std::string_view handle, std::string_view ar_flags, std::string_view ac_flags) const;
    void set_credits(std::string_view handle, std::int64_t balance) const;
    void set_file_points(std::string_view handle, std::int64_t balance) const;
    void set_mailbox_closed(std::string_view handle, bool closed) const;
    void set_expiration_date(std::string_view handle, std::string_view date) const;
    void set_validation_level(const ValidationLevel& level) const;
    void delete_validation_level(char key) const;
    [[nodiscard]] std::vector<ValidationLevel> validation_levels() const;
    void apply_validation_level(std::string_view handle, char key) const;
    [[nodiscard]] bool is_sysop(std::string_view handle) const;
    [[nodiscard]] AccountProfile profile(std::string_view handle) const;
    void update_profile(const AccountProfile& profile) const;
    void set_forgot_password_answer(std::string_view handle, std::string_view answer) const;
    void set_forgot_password_question(std::string_view question) const;
    [[nodiscard]] std::string forgot_password_question() const;
    void set_custom_user_question(int question, std::string_view prompt) const;
    [[nodiscard]] std::array<std::string, 3> custom_user_questions() const;
    [[nodiscard]] bool verify_forgot_password_answer(
        std::string_view handle, std::string_view answer) const;
    [[nodiscard]] std::array<bool, 27> signup_question_states() const;
    void set_signup_question_enabled(int source_question, bool enabled) const;
    [[nodiscard]] TimeBankStatus time_bank_status(std::string_view handle) const;
    [[nodiscard]] TimeBankStatus deposit_time(
        std::string_view handle, int minutes, int bank_limit, int daily_limit) const;
    [[nodiscard]] TimeBankStatus withdraw_time(
        std::string_view handle, int minutes, int daily_limit) const;
    [[nodiscard]] std::vector<AccountSummary> list_accounts() const;
    [[nodiscard]] std::uint64_t count_approved_accounts() const;
    [[nodiscard]] std::optional<AuthenticatedAccount> authenticate(
        std::string_view handle,
        std::string_view password) const;

    [[nodiscard]] const std::string& database_path() const noexcept;

private:
    std::string database_path_;
};

[[nodiscard]] std::string hash_password(std::string_view password);
[[nodiscard]] bool verify_password_hash(
    std::string_view encoded_hash, std::string_view password) noexcept;
[[nodiscard]] bool valid_handle(std::string_view handle) noexcept;

} // namespace renegade
