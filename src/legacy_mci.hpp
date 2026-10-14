#pragma once

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace renegade {

using LegacyMciValues = std::unordered_map<std::string, std::string>;

struct LegacyMciPosition {
    int column{};
    int row{};
};

using LegacyMciPositions = std::array<std::optional<LegacyMciPosition>, 10>;

// Expands Renegade's two-character %MCIs, field-width modifiers, and legacy
// color/cursor controls. Unknown codes are preserved verbatim for migration.
[[nodiscard]] std::string render_legacy_display(
    std::string_view source,
    const LegacyMciValues& values,
    int columns,
    int rows,
    LegacyMciPositions* saved_positions = nullptr);

} // namespace renegade
