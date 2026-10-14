#include "legacy_mci.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <string>

namespace renegade {
namespace {

constexpr std::size_t kMaximumRenderedBytes = 2U * 1024U * 1024U;

bool parse_decimal(std::string_view value, int& result);

char upper(char value) {
    return static_cast<char>(std::toupper(static_cast<unsigned char>(value)));
}

std::string key_for(char first, char second) {
    return {upper(first), upper(second)};
}

int csi_value(std::string_view parameters, std::size_t index, int fallback) {
    std::size_t start = 0;
    for (std::size_t current = 0; current <= index; ++current) {
        const std::size_t separator = parameters.find(';', start);
        const std::size_t end = separator == std::string_view::npos ? parameters.size() : separator;
        if (current == index) {
            const std::string_view value = parameters.substr(start, end - start);
            if (value.empty()) {
                return fallback;
            }
            int parsed{};
            return parse_decimal(value, parsed) ? parsed : fallback;
        }
        if (separator == std::string_view::npos) {
            return fallback;
        }
        start = separator + 1;
    }
    return fallback;
}

void advance_cursor(std::string_view value, int columns, int rows, int& column, int& row) {
    for (std::size_t index = 0; index < value.size();) {
        if (value[index] == '\x1b' && index + 1 < value.size() && value[index + 1] == '[') {
            std::size_t end = index + 2;
            while (end < value.size() && !(value[end] >= 0x40 && value[end] <= 0x7e)) {
                ++end;
            }
            if (end == value.size()) {
                break;
            }
            const std::string_view parameters = value.substr(index + 2, end - index - 2);
            const int first = csi_value(parameters, 0, 1);
            switch (value[end]) {
            case 'A': row = std::max(1, row - first); break;
            case 'B': row = std::min(rows, row + first); break;
            case 'C': column = std::min(columns, column + first); break;
            case 'D': column = std::max(1, column - first); break;
            case 'G': column = std::clamp(first, 1, columns); break;
            case 'd': row = std::clamp(first, 1, rows); break;
            case 'H': case 'f':
                row = std::clamp(csi_value(parameters, 0, 1), 1, rows);
                column = std::clamp(csi_value(parameters, 1, 1), 1, columns);
                break;
            default: break;
            }
            index = end + 1;
            continue;
        }
        const unsigned char byte = static_cast<unsigned char>(value[index++]);
        if (byte == '\r') {
            column = 1;
        } else if (byte == '\n') {
            row = std::min(rows, row + 1);
            column = 1;
        } else if (byte == '\b') {
            column = std::max(1, column - 1);
        } else if (byte >= 0x20 && byte != 0x7f) {
            std::size_t sequence_length = 1;
            if ((byte & 0xe0U) == 0xc0U) {
                sequence_length = 2;
            } else if ((byte & 0xf0U) == 0xe0U) {
                sequence_length = 3;
            } else if ((byte & 0xf8U) == 0xf0U) {
                sequence_length = 4;
            }
            bool valid_sequence = sequence_length > 1 &&
                sequence_length - 1 <= value.size() - index;
            for (std::size_t continuation = 1; valid_sequence && continuation < sequence_length;
                 ++continuation) {
                valid_sequence = (static_cast<unsigned char>(value[index + continuation - 1]) & 0xc0U) == 0x80U;
            }
            if (valid_sequence) {
                index += sequence_length - 1;
            }
            if (column >= columns) {
                column = 1;
                row = std::min(rows, row + 1);
            } else {
                ++column;
            }
        }
    }
}

void append_bounded(
    std::string& output,
    std::string_view value,
    int columns,
    int rows,
    int& cursor_column,
    int& cursor_row) {
    if (output.size() >= kMaximumRenderedBytes) {
        return;
    }
    const std::size_t available = kMaximumRenderedBytes - output.size();
    const std::string_view bounded = value.substr(0, available);
    output.append(bounded);
    advance_cursor(bounded, columns, rows, cursor_column, cursor_row);
}

std::string justify(std::string value, char mode, std::size_t width) {
    if (value.size() >= width) {
        return value;
    }
    const std::size_t padding = width - value.size();
    if (mode == '#') {
        value.append(padding, ' ');
    } else if (mode == '{') {
        value.insert(0, padding, ' ');
    } else {
        const std::size_t left = padding / 2;
        value.insert(0, left, ' ');
        value.append(padding - left, ' ');
    }
    return value;
}

bool parse_decimal(std::string_view value, int& result) {
    if (value.empty()) {
        return false;
    }
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size();
}

std::string legacy_foreground(int color) {
    if (color == 0) {
        return "\x1b[0m";
    }
    return "\x1b[" + std::to_string(color < 8 ? 30 + color : 90 + color - 8) + "m";
}

std::string legacy_palette(int value) {
    if (value < 8) {
        return "\x1b[" + std::to_string(30 + value) + "m";
    }
    if (value < 16) {
        return "\x1b[" + std::to_string(90 + value - 8) + "m";
    }
    return "\x1b[" + std::to_string(40 + value - 16) + "m";
}

} // namespace

std::string render_legacy_display(
    std::string_view source,
    const LegacyMciValues& values,
    int columns,
    int rows,
    LegacyMciPositions* saved_positions) {
    columns = std::clamp(columns, 1, 1000);
    rows = std::clamp(rows, 1, 1000);
    std::string output;
    output.reserve(std::min(source.size() + 128, kMaximumRenderedBytes));
    int cursor_column = 1;
    int cursor_row = 1;

    for (std::size_t index = 0; index < source.size() && output.size() < kMaximumRenderedBytes;) {
        const char current = source[index];

        if (current == '\x1b' && index + 1 < source.size() && source[index + 1] == '[') {
            std::size_t end = index + 2;
            while (end < source.size() && !(source[end] >= 0x40 && source[end] <= 0x7e)) {
                ++end;
            }
            if (end < source.size()) {
                append_bounded(output, source.substr(index, end - index + 1),
                    columns, rows, cursor_column, cursor_row);
                index = end + 1;
                continue;
            }
        }

        if (current == '^' && index + 1 < source.size() &&
            source[index + 1] >= '0' && source[index + 1] <= '9') {
            append_bounded(output, legacy_foreground(source[index + 1] - '0'),
                columns, rows, cursor_column, cursor_row);
            index += 2;
            continue;
        }

        if (current == '|' && index + 2 < source.size() &&
            source[index + 1] >= '0' && source[index + 1] <= '9' &&
            source[index + 2] >= '0' && source[index + 2] <= '9') {
            const int color = (source[index + 1] - '0') * 10 + (source[index + 2] - '0');
            if (color <= 23) {
                append_bounded(output, legacy_palette(color), columns, rows, cursor_column, cursor_row);
                index += 3;
                continue;
            }
        }

        if (current == '\t') {
            append_bounded(output, "     ", columns, rows, cursor_column, cursor_row);
            ++index;
            continue;
        }

        if (current != '%' || index + 2 >= source.size()) {
            append_bounded(output, source.substr(index, 1), columns, rows, cursor_column, cursor_row);
            ++index;
            continue;
        }

        const char first = upper(source[index + 1]);
        const char second = upper(source[index + 2]);
        if (first == 'X' && second == 'Y') {
            const std::size_t end = source.find('%', index + 3);
            if (end != std::string_view::npos && end - index <= 12) {
                const std::string_view position = source.substr(index + 3, end - index - 3);
                const std::size_t separator = position.find(';');
                int column{};
                int row{};
                if (separator != std::string_view::npos &&
                    parse_decimal(position.substr(0, separator), column) &&
                    parse_decimal(position.substr(separator + 1), row)) {
                    const int target_column = column == 0 || column > columns
                        ? cursor_column
                        : column;
                    const int target_row = row == 0 || row > rows ? cursor_row : row;
                    append_bounded(output, "\x1b[" + std::to_string(target_row) + ";" +
                        std::to_string(target_column) + "H", columns, rows, cursor_column, cursor_row);
                }
                index = end + 1;
                continue;
            }
        }

        if (first == 'P' && second == 'A') {
            output.push_back('\x01');
            index += 3;
            continue;
        }
        if (first == '0' && second >= '0' && second <= '9') {
            if (saved_positions != nullptr) {
                (*saved_positions)[static_cast<std::size_t>(second - '0')] =
                    LegacyMciPosition{cursor_column, cursor_row};
            }
            index += 3;
            continue;
        }

        const auto found = values.find(key_for(first, second));
        if (found == values.end()) {
            append_bounded(output, source.substr(index, 3), columns, rows,
                cursor_column, cursor_row);
            index += 3;
            continue;
        }

        std::string replacement = found->second;
        std::size_t next = index + 3;
        if (next < source.size() &&
            (source[next] == '#' || source[next] == '{' || source[next] == '}')) {
            const char mode = source[next++];
            const std::size_t width_start = next;
            while (next < source.size() && next - width_start < 2 &&
                source[next] >= '0' && source[next] <= '9') {
                ++next;
            }
            int width{};
            if (parse_decimal(source.substr(width_start, next - width_start), width) && width > 0) {
                replacement = justify(std::move(replacement), mode,
                    static_cast<std::size_t>(std::min(width, 255)));
            } else {
                next = index + 3;
            }
        }
        append_bounded(output, replacement, columns, rows, cursor_column, cursor_row);
        index = next;
    }

    return output;
}

} // namespace renegade
