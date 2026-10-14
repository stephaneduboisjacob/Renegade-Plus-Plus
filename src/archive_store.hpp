#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace renegade {

struct ArchiveEntry {
    std::size_t index{};
    std::string name;
    std::uint64_t size{};
    std::string modified_at;
    bool directory{};
    bool encrypted{};
    bool parent_directory{};
};

struct ArchiveListing {
    std::string format;
    std::vector<ArchiveEntry> entries;
    bool truncated{};
};

class ArchiveStore final {
public:
    static constexpr std::size_t max_entries = 600;
    static constexpr std::size_t max_archive_bytes = 100U * 1024U * 1024U;
    static constexpr std::size_t max_view_bytes = 2U * 1024U * 1024U;
    static constexpr std::size_t max_nested_archive_bytes = 32U * 1024U * 1024U;

    [[nodiscard]] static bool supports_filename(std::string_view filename);
    [[nodiscard]] static ArchiveListing list(std::span<const std::uint8_t> bytes);
    [[nodiscard]] static std::vector<std::uint8_t> read_entry(
        std::span<const std::uint8_t> bytes,
        std::size_t index,
        std::size_t maximum_bytes);
};

} // namespace renegade
