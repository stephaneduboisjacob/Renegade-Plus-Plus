#pragma once

#include <cstdint>
#include <string_view>
#include <string>

namespace renegade {

struct AccessLevels {
    int security_level{10};
    int download_security_level{10};
    bool is_sysop{};
    std::string ar_flags;
    std::string ac_flags;
    std::int64_t message_credits{};
    std::int64_t user_number{};
    std::int64_t message_area_number{};
    std::int64_t file_area_number{};
    std::int64_t online_minutes{};
    std::string birth_date;
    char sex{};
    bool voted_in_all_polls{true};
    bool novice_help{true};
    int node_number{};
    int remaining_minutes{32767};
    std::string expiration_date;
    std::uint64_t public_posts{};
    std::uint64_t total_calls{};
    int post_ratio_percent{};
    bool invisible{};
    bool sysop_available{};
    bool validation_key_active{};
    int validation_new_security_level{};
};

[[nodiscard]] bool valid_legacy_acs(std::string_view expression) noexcept;
[[nodiscard]] bool evaluate_legacy_acs(
    std::string_view expression,
    const AccessLevels& levels) noexcept;

} // namespace renegade
