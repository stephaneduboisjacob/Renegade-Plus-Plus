#include "terminal.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iconv.h>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace renegade {
namespace {

int bounded_columns(int columns) {
    return std::clamp(columns, 40, 200);
}

int bounded_rows(int rows) {
    return std::clamp(rows, 23, 80);
}

char anonymous_mode_code(AnonymousMode mode) {
    switch (mode) {
    case AnonymousMode::Optional: return 'Y';
    case AnonymousMode::Forced: return 'F';
    case AnonymousMode::DearAbby: return 'D';
    case AnonymousMode::AnyName: return 'A';
    default: return 'N';
    }
}

std::string cursor(int row, int column) {
    return "\x1b[" + std::to_string(row) + ";" + std::to_string(column) + "H";
}

void clear_art_rows(std::string& output, int first_row, int last_row) {
    for (int row = first_row; row <= last_row; ++row) {
        output += cursor(row, 1) + "\x1b[40m\x1b[2K\x1b[0m";
    }
}

std::string clipped(std::string_view text, int columns) {
    const std::size_t width = static_cast<std::size_t>(columns);
    if (text.size() <= width) {
        return std::string(text);
    }
    std::size_t end = width;
    while (end > 0 && end < text.size() &&
        (static_cast<unsigned char>(text[end]) & 0xc0U) == 0x80U) {
        --end;
    }
    return std::string(text.substr(0, end));
}

std::string one_line(std::string_view text) {
    std::string result;
    result.reserve(text.size());
    for (const unsigned char byte : text) {
        if (byte == '\r' || byte == '\n' || byte == '\t') {
            result.push_back(' ');
        } else if (byte >= 0x20 && byte != 0x7f && byte != 0x1b) {
            result.push_back(static_cast<char>(byte));
        }
    }
    return result;
}

std::vector<std::string> wrap_body(std::string_view body, std::size_t width) {
    std::vector<std::string> lines;
    std::size_t start = 0;
    do {
        const std::size_t newline = body.find_first_of("\r\n", start);
        const std::size_t end_of_line = newline == std::string_view::npos ? body.size() : newline;
        const std::string clean = one_line(body.substr(start, end_of_line - start));
        if (clean.empty()) {
            lines.emplace_back();
        } else {
            std::size_t offset = 0;
            while (offset < clean.size()) {
                std::size_t end = std::min(offset + width, clean.size());
                if (end < clean.size()) {
                    while (end > offset && (static_cast<unsigned char>(clean[end]) & 0xc0U) == 0x80U) {
                        --end;
                    }
                    if (end == offset) {
                        end = std::min(offset + width + 3, clean.size());
                        while (end < clean.size() && (static_cast<unsigned char>(clean[end]) & 0xc0U) == 0x80U) {
                            ++end;
                        }
                    }
                }
                lines.emplace_back(clean.substr(offset, end - offset));
                offset = end;
            }
        }
        if (newline == std::string_view::npos) {
            break;
        }
        start = newline + 1;
        if (body[newline] == '\r' && start < body.size() && body[start] == '\n') {
            ++start;
        }
    } while (start <= body.size());
    return lines;
}

void put(std::string& output, int row, int column, int color, std::string_view text, int columns) {
    if (row < 1 || column < 1 || row > 80 || column > columns) {
        return;
    }
    const int available = columns - column + 1;
    output += cursor(row, column);
    output += "\x1b[" + std::to_string(color) + "m";
    output += clipped(text, available);
    output += "\x1b[0m";
}

void put_selected(std::string& output, int row, int column, std::string_view text, int columns) {
    if (row < 1 || column < 1 || row > 80 || column > columns) {
        return;
    }
    output += cursor(row, column) + "\x1b[30;103m";
    output += clipped(text, columns - column + 1);
    output += "\x1b[0m";
}

std::string frame(int columns, int rows) {
    constexpr std::string_view plaque = " R E N E G A D E BBS ";
    const int available_border = std::max(0, columns - 2 - static_cast<int>(plaque.size()));
    const int left_border = available_border / 2;
    std::string output = "\x1b[2J\x1b[H\x1b[?25l\x1b[0m";
    output += cursor(1, 1) + "\x1b[1;96m╔";
    for (int column = 0; column < left_border; ++column) {
        output += "═";
    }
    output += "\x1b[1;95m";
    output.append(plaque);
    output += "\x1b[1;96m";
    for (int column = left_border + static_cast<int>(plaque.size()); column < columns - 2; ++column) {
        output += "═";
    }
    output += "╗";
    for (int row = 2; row < rows; ++row) {
        output += cursor(row, 1) + "\x1b[1;96m║";
        output += cursor(row, columns) + "║";
    }
    output += cursor(rows, 1) + "╚";
    for (int column = 0; column < columns - 2; ++column) {
        output += "═";
    }
    output += "╝\x1b[0m";
    return output;
}

void put_key_option(
    std::string& output,
    int row,
    int column,
    char key,
    std::string_view label,
    int columns,
    bool selected = false) {
    if (row < 1 || row > 80 || column < 1 || column > columns) {
        return;
    }
    output += cursor(row, column);
    output += selected ? "\x1b[30;103m[" : "\x1b[96m[\x1b[1;93m";
    output.push_back(key);
    output += selected ? "] " : "\x1b[96m]\x1b[97m ";
    output += clipped(label, static_cast<std::size_t>(std::max(0, columns - column - 3)));
    output += "\x1b[0m";
}

std::string_view welcome_keys_internal(bool is_sysop) {
    return is_sysop ? std::string_view("NCHQDLTGAOBRMFKVPUSIJ")
                    : std::string_view("NCHQDLTGAOBRMFKVPU");
}

void draw_welcome_menu(
    std::string& output,
    bool is_sysop,
    bool expert_mode,
    bool full_screen_art,
    int columns,
    std::size_t selected_index) {
    const std::string_view available = welcome_keys_internal(is_sysop);
    const auto option = [&](std::size_t index, int row, int column, char key, std::string_view label) {
        put_key_option(output, row, column, key, label, columns, index == selected_index);
    };
    if (full_screen_art) {
        if (expert_mode) {
            for (std::size_t index = 0; index < available.size(); ++index) {
                const std::size_t row = index / 4;
                const std::size_t column = index % 4;
                output += cursor(8 + static_cast<int>(row), 5 + static_cast<int>(column) * 8);
                output += index == selected_index ? "\x1b[30;103m" : "\x1b[1;93m";
                output.push_back(available[index]);
                output += "\x1b[0m";
            }
            return;
        }
        option(0, 8, 4, 'N', "Nodes");
        option(1, 8, 23, 'C', "Chat");
        option(2, 8, 42, 'H', "Help");
        option(3, 8, 62, 'Q', "Log off");
        option(4, 9, 4, 'D', "BBS Directory");
        option(5, 9, 23, 'L', "Callers");
        option(6, 9, 42, 'T', "Stats");
        option(7, 9, 62, 'G', "Auto-message");
        option(8, 10, 4, 'A', "ANSI / ASCII art");
        option(9, 10, 27, 'O', "One-liners");
        option(10, 10, 47, 'B', "Bulletins");
        option(11, 10, 65, 'R', "Quotes");
        option(12, 11, 4, 'M', "Message boards");
        option(13, 11, 27, 'F', "File areas");
        option(14, 11, 47, 'K', "Time bank");
        option(15, 11, 65, 'V', "Voting");
        option(16, 12, 4, 'P', "Private mail");
        option(17, 12, 23, 'U', "Profile");
        if (is_sysop) {
            option(18, 12, 42, 'S', "SysOp");
            option(19, 12, 62, 'I', "Uploads");
            option(20, 13, 4, 'J', "Quote review");
        } else {
            put(output, 13, 4, 90, "Explore the ANSI gallery, message boards, files, and live chat.", columns - 7);
        }
        put(output, 18, 4, 93, "↑↓←→ MOVE   ENTER OPEN   LETTER = QUICK SELECT", columns - 6);
        return;
    }

    if (expert_mode) {
        std::string keys_line;
        for (std::size_t index = 0; index < available.size(); ++index) {
            if (!keys_line.empty()) {
                keys_line.push_back(' ');
            }
            keys_line += index == selected_index ? "\x1b[30;103m" : "\x1b[1;93m";
            keys_line.push_back(available[index]);
            keys_line += "\x1b[0m";
        }
        output += cursor(17, 5) + keys_line + "\x1b[0m";
        put(output, 18, 5, 96, "↑↓←→ MOVE   ENTER OPEN", columns);
        return;
    }
    if (columns < 80) {
        put(output, 17, 5, 93, "N Nodes  C Chat  H Help  Q Log off", columns);
        put(output, 18, 5, 93, "D Directory  L Callers  T Stats  G Auto", columns);
        put(output, 19, 5, 93, "A Art  O One-liners  B Bulletins  R Quotes", columns);
        put(output, 20, 5, 93, "M Boards  F Files  K Time bank", columns);
        put(output, 21, 5, 93, is_sysop
            ? "V Votes  P Mail  U Profile  S SysOp  I Uploads  J Quotes"
            : "V Votes  P Mail  U Profile", columns);
        put(output, 13, 5, 96, "Selected: " + std::string(1, available[selected_index]) +
            "  |  ARROWS MOVE  ENTER OPEN", columns - 2);
        return;
    }
    option(0, 17, 5, 'N', "Nodes");
    option(1, 17, 23, 'C', "Chat");
    option(2, 17, 40, 'H', "Help");
    option(3, 17, 57, 'Q', "Log off");
    option(4, 18, 5, 'D', "BBS Directory");
    option(5, 18, 27, 'L', "Callers");
    option(6, 18, 44, 'T', "Stats");
    option(7, 18, 60, 'G', "Auto-message");
    option(8, 19, 5, 'A', "ANSI / ASCII art");
    option(9, 19, 28, 'O', "One-liners");
    option(10, 19, 48, 'B', "Bulletins");
    option(11, 19, 66, 'R', "Quotes");
    option(12, 20, 5, 'M', "Message boards");
    option(13, 20, 30, 'F', "File areas");
    option(14, 20, 51, 'K', "Time bank");
    option(15, 20, 68, 'V', "Voting");
    option(16, 21, 5, 'P', "Mail");
    option(17, 21, 23, 'U', "Profile");
    if (is_sysop) {
        option(18, 21, 40, 'S', "SysOp");
        option(19, 21, 57, 'I', "Uploads");
        option(20, 21, 70, 'J', "Quotes");
    }
    put(output, 13, 5, 96, "↑↓←→ MOVE   ENTER OPEN   LETTER = QUICK SELECT", columns - 2);
}

bool allowed_csi(std::string_view parameters, char final) {
    switch (final) {
    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
    case 'G': case 'H': case 'J': case 'K': case 'f': case 'm':
    case 's': case 'u':
        break;
    default:
        return false;
    }

    if (parameters.find_first_not_of("0123456789;:") != std::string_view::npos) {
        return false;
    }
    std::size_t start = 0;
    while (start < parameters.size()) {
        const std::size_t end = parameters.find_first_of(";:", start);
        const std::string_view value = parameters.substr(
            start, end == std::string_view::npos ? parameters.size() - start : end - start);
        if (value.size() > 4) {
            return false;
        }
        if (end == std::string_view::npos) {
            break;
        }
        start = end + 1;
    }
    return true;
}

std::string sanitized_art_bytes(std::string_view source) {
    const std::size_t sauce = source.find("\x1aSAUCE00");
    if (sauce != std::string_view::npos) {
        source = source.substr(0, sauce);
    }

    std::string output;
    output.reserve(source.size());
    for (std::size_t index = 0; index < source.size();) {
        const unsigned char value = static_cast<unsigned char>(source[index]);
        if (value == 0x1b) {
            if (index + 1 < source.size() && source[index + 1] == '[') {
                std::size_t end = index + 2;
                while (end < source.size() && end - index <= 64) {
                    const unsigned char byte = static_cast<unsigned char>(source[end]);
                    if (byte >= 0x40 && byte <= 0x7e) {
                        break;
                    }
                    ++end;
                }
                if (end < source.size() && end - index <= 64) {
                    const char final = source[end];
                    const std::string_view parameters = source.substr(index + 2, end - index - 2);
                    if (allowed_csi(parameters, final)) {
                        output.append(source.substr(index, end - index + 1));
                    }
                    index = end + 1;
                    continue;
                }
                index = std::min(source.size(), end + 1);
                continue;
            }
            index += index + 1 < source.size() ? 2 : 1;
            continue;
        }
        if (value == '\r' || value == '\n' || value == '\t' || (value >= 0x20 && value != 0x7f)) {
            output.push_back(static_cast<char>(value));
        }
        ++index;
    }

    return output;
}

std::string cp437_to_utf8(const std::string& bytes) {
    iconv_t converter = ::iconv_open("UTF-8", "CP437");
    if (converter == reinterpret_cast<iconv_t>(-1)) {
        std::string fallback;
        fallback.reserve(bytes.size());
        for (const unsigned char byte : bytes) {
            if (byte < 0x80) {
                fallback.push_back(static_cast<char>(byte));
            } else {
                fallback += "\xef\xbf\xbd";
            }
        }
        return fallback;
    }

    std::string converted(bytes.size() * 4 + 8, '\0');
    char* input = const_cast<char*>(bytes.data());
    std::size_t input_left = bytes.size();
    char* output = converted.data();
    std::size_t output_left = converted.size();
    const std::size_t result = ::iconv(converter, &input, &input_left, &output, &output_left);
    (void)::iconv_close(converter);
    if (result == static_cast<std::size_t>(-1) || input_left != 0) {
        return bytes;
    }
    converted.resize(converted.size() - output_left);
    return converted;
}

bool valid_utf8(std::string_view text) {
    for (std::size_t index = 0; index < text.size();) {
        const unsigned char first = static_cast<unsigned char>(text[index]);
        if (first < 0x80) {
            ++index;
            continue;
        }
        std::size_t length = 0;
        std::uint32_t codepoint = 0;
        if ((first & 0xe0U) == 0xc0U) {
            length = 2;
            codepoint = first & 0x1fU;
        } else if ((first & 0xf0U) == 0xe0U) {
            length = 3;
            codepoint = first & 0x0fU;
        } else if ((first & 0xf8U) == 0xf0U) {
            length = 4;
            codepoint = first & 0x07U;
        } else {
            return false;
        }
        if (index + length > text.size()) {
            return false;
        }
        for (std::size_t continuation = 1; continuation < length; ++continuation) {
            const unsigned char next = static_cast<unsigned char>(text[index + continuation]);
            if ((next & 0xc0U) != 0x80U) {
                return false;
            }
            codepoint = (codepoint << 6U) | (next & 0x3fU);
        }
        if ((length == 2 && codepoint < 0x80U) ||
            (length == 3 && codepoint < 0x800U) ||
            (length == 4 && codepoint < 0x10000U) ||
            (codepoint >= 0xd800U && codepoint <= 0xdfffU) || codepoint > 0x10ffffU) {
            return false;
        }
        index += length;
    }
    return true;
}

std::string quote_text_bytes(std::string_view source) {
    std::string output;
    output.reserve(source.size());
    for (std::size_t index = 0; index < source.size();) {
        const unsigned char value = static_cast<unsigned char>(source[index]);
        if (value == 0x1b) {
            if (index + 1 < source.size() && source[index + 1] == '[') {
                std::size_t end = index + 2;
                while (end < source.size() && end - index <= 64) {
                    const unsigned char byte = static_cast<unsigned char>(source[end]);
                    if (byte >= 0x40 && byte <= 0x7e) {
                        break;
                    }
                    ++end;
                }
                index = end < source.size() ? end + 1 : source.size();
            } else {
                index += index + 1 < source.size() ? 2 : 1;
            }
            continue;
        }
        if (value == '\r' || value == '\n' || (value >= 0x20 && value != 0x7f)) {
            output.push_back(static_cast<char>(value));
        } else if (value == '\t') {
            output.push_back(' ');
        }
        ++index;
    }
    return output;
}

std::string decode_quote_text(std::string_view bytes) {
    const std::string plain = quote_text_bytes(bytes);
    return valid_utf8(plain) ? plain : cp437_to_utf8(plain);
}

std::optional<std::string> read_bounded_file(
    const std::filesystem::path& path,
    std::uintmax_t maximum_size) {
    std::error_code error;
    if (std::filesystem::is_symlink(path, error) || error ||
        !std::filesystem::is_regular_file(path, error) || error) {
        return std::nullopt;
    }
    const std::uintmax_t size = std::filesystem::file_size(path, error);
    if (error || size > maximum_size) {
        return std::nullopt;
    }
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }
    std::string contents(static_cast<std::size_t>(size), '\0');
    if (size > 0) {
        file.read(contents.data(), static_cast<std::streamsize>(size));
        if (file.gcount() != static_cast<std::streamsize>(size)) {
            return std::nullopt;
        }
    }
    return contents;
}

std::uint32_t little_endian_u32(std::string_view bytes, std::size_t offset) {
    return static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset])) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset + 1])) << 8U) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset + 2])) << 16U) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset + 3])) << 24U);
}

void centered(std::string& output, int row, int color, std::string_view text, int columns) {
    const int left = std::max(2, (columns - static_cast<int>(text.size())) / 2 + 1);
    put(output, row, left, color, text, columns - 1);
}

} // namespace

std::string load_ansi_art(std::string_view path) {
    std::ifstream file(std::string(path), std::ios::binary);
    if (!file) {
        return {};
    }
    std::vector<char> bytes(1024 * 1024 + 1);
    file.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    const std::streamsize count = file.gcount();
    if (count < 0 || static_cast<std::size_t>(count) > 1024 * 1024 || file.bad()) {
        return {};
    }
    const std::string sanitized = sanitized_art_bytes(
        std::string_view(bytes.data(), static_cast<std::size_t>(count)));
    return cp437_to_utf8(sanitized);
}

std::string sanitize_terminal_art(std::string_view source) {
    const std::size_t sauce = source.find("\x1aSAUCE00");
    if (sauce != std::string_view::npos) {
        source = source.substr(0, sauce);
    }
    std::string clean;
    clean.reserve(source.size());
    for (std::size_t index = 0; index < source.size();) {
        const unsigned char value = static_cast<unsigned char>(source[index]);
        if (value == 0x1b) {
            if (index + 1 < source.size() && source[index + 1] == '[') {
                std::size_t end = index + 2;
                while (end < source.size() && end - index <= 64) {
                    const unsigned char byte = static_cast<unsigned char>(source[end]);
                    if (byte >= 0x40 && byte <= 0x7e) {
                        break;
                    }
                    ++end;
                }
                if (end < source.size() && end - index <= 64 && source[end] == 'm' &&
                    allowed_csi(source.substr(index + 2, end - index - 2), 'm')) {
                    clean.append(source.substr(index, end - index + 1));
                }
                index = end < source.size() ? end + 1 : source.size();
                continue;
            }
            index += index + 1 < source.size() ? 2 : 1;
            continue;
        }
        if (value == '\r' || value == '\n' || value == '\t' || (value >= 0x20 && value != 0x7f)) {
            clean.push_back(static_cast<char>(value));
        }
        ++index;
    }
    return valid_utf8(clean) ? clean : cp437_to_utf8(clean);
}

std::string sanitize_terminal_text(std::string_view source) {
    std::string clean = quote_text_bytes(source);
    return valid_utf8(clean) ? clean : cp437_to_utf8(clean);
}

std::vector<AnsiArtwork> load_ansi_art_catalog(std::string_view directory) {
    std::vector<AnsiArtwork> catalog;
    std::error_code error;
    const std::filesystem::path root(directory);
    std::filesystem::recursive_directory_iterator current(
        root, std::filesystem::directory_options::skip_permission_denied, error);
    const std::filesystem::recursive_directory_iterator end;
    if (error) {
        return catalog;
    }

    while (current != end) {
        const std::filesystem::directory_entry entry = *current;
        current.increment(error);
        if (error) {
            error.clear();
            continue;
        }

        std::error_code entry_error;
        if (entry.is_symlink(entry_error) || !entry.is_regular_file(entry_error) || entry_error) {
            continue;
        }
        std::string extension = entry.path().extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char value) {
            return static_cast<char>(std::tolower(value));
        });
        if (extension != ".ans" && extension != ".asc") {
            continue;
        }

        const std::string contents = load_ansi_art(entry.path().string());
        if (contents.empty()) {
            continue;
        }
        const std::filesystem::path relative = std::filesystem::relative(entry.path(), root, entry_error);
        catalog.push_back({
            entry_error ? entry.path().filename().string() : relative.generic_string(),
            contents,
        });
    }

    std::sort(catalog.begin(), catalog.end(), [](const AnsiArtwork& left, const AnsiArtwork& right) {
        return left.name < right.name;
    });
    return catalog;
}

std::vector<AnsiArtwork> load_quote_catalog(std::string_view directory) {
    std::vector<AnsiArtwork> catalog;
    std::size_t total_quote_bytes = 0;
    std::error_code error;
    const std::filesystem::path root(directory);
    std::filesystem::directory_iterator current(
        root, std::filesystem::directory_options::skip_permission_denied, error);
    const std::filesystem::directory_iterator end;
    if (error) {
        return catalog;
    }

    std::vector<std::filesystem::path> text_files;
    std::vector<std::filesystem::path> pointer_files;
    for (; current != end; current.increment(error)) {
        if (error) {
            error.clear();
            continue;
        }
        const auto& entry = *current;
        std::error_code entry_error;
        if (entry.is_symlink(entry_error) || !entry.is_regular_file(entry_error) || entry_error) {
            continue;
        }
        std::string extension = entry.path().extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char value) {
            return static_cast<char>(std::tolower(value));
        });
        if (extension == ".txt") {
            text_files.push_back(entry.path());
        } else if (extension == ".ptr") {
            pointer_files.push_back(entry.path());
        }
    }
    const auto by_filename = [](const auto& left, const auto& right) {
        return left.filename().string() < right.filename().string();
    };
    std::sort(text_files.begin(), text_files.end(), by_filename);
    std::sort(pointer_files.begin(), pointer_files.end(), by_filename);

    for (const std::filesystem::path& path : text_files) {
        if (catalog.size() >= 4096 || total_quote_bytes >= 4U * 1024U * 1024U) {
            break;
        }
        const std::optional<std::string> bytes = read_bounded_file(path, 8192);
        if (!bytes.has_value() || bytes->empty()) {
            continue;
        }
        const std::string decoded = decode_quote_text(*bytes);
        if (!decoded.empty()) {
            total_quote_bytes += decoded.size();
            catalog.push_back({path.filename().string(), decoded});
        }
    }

    for (const std::filesystem::path& pointer_path : pointer_files) {
        if (catalog.size() >= 4096 || total_quote_bytes >= 4U * 1024U * 1024U) {
            break;
        }
        const std::optional<std::string> pointer_bytes = read_bounded_file(pointer_path, 65535U * 8U);
        if (!pointer_bytes.has_value() || pointer_bytes->empty() || pointer_bytes->size() % 8 != 0) {
            continue;
        }
        std::filesystem::path data_path = pointer_path;
        data_path.replace_extension(".DAT");
        if (!std::filesystem::exists(data_path, error) || error) {
            error.clear();
            for (const auto& candidate : std::filesystem::directory_iterator(
                     root, std::filesystem::directory_options::skip_permission_denied, error)) {
                if (error) {
                    error.clear();
                    break;
                }
                std::error_code candidate_error;
                if (candidate.is_symlink(candidate_error) ||
                    !candidate.is_regular_file(candidate_error) || candidate_error) {
                    continue;
                }
                std::string candidate_extension = candidate.path().extension().string();
                std::transform(candidate_extension.begin(), candidate_extension.end(),
                    candidate_extension.begin(), [](unsigned char value) {
                        return static_cast<char>(std::tolower(value));
                    });
                if (candidate_extension == ".dat" &&
                    candidate.path().stem().string() == pointer_path.stem().string()) {
                    data_path = candidate.path();
                    break;
                }
            }
            error.clear();
        }
        const std::optional<std::string> data_bytes = read_bounded_file(data_path, 16U * 1024U * 1024U);
        if (!data_bytes.has_value()) {
            continue;
        }
        for (std::size_t index = 0; index + 8 <= pointer_bytes->size() &&
             catalog.size() < 4096 && total_quote_bytes < 4U * 1024U * 1024U;
             index += 8) {
            const std::uint32_t pointer = little_endian_u32(*pointer_bytes, index);
            const std::uint32_t text_size = little_endian_u32(*pointer_bytes, index + 4);
            if (pointer == 0 || text_size == 0 || text_size > 8192U) {
                continue;
            }
            const std::size_t offset = static_cast<std::size_t>(pointer - 1U);
            if (offset > data_bytes->size() || text_size > data_bytes->size() - offset) {
                continue;
            }
            const std::size_t end_offset = offset + text_size;
            std::size_t cursor_offset = offset;
            std::string raw;
            bool valid = true;
            while (cursor_offset < end_offset) {
                const std::size_t line_size = static_cast<unsigned char>((*data_bytes)[cursor_offset++]);
                if (line_size > end_offset - cursor_offset) {
                    valid = false;
                    break;
                }
                std::string_view line(data_bytes->data() + cursor_offset, line_size);
                cursor_offset += line_size;
                const bool continue_line = !line.empty() && line.back() == '@';
                if (continue_line) {
                    line.remove_suffix(1);
                }
                raw.append(line);
                if (!continue_line) {
                    raw.push_back('\n');
                }
            }
            if (!valid || raw.empty()) {
                continue;
            }
            const std::string decoded = decode_quote_text(raw);
            if (!decoded.empty()) {
                total_quote_bytes += decoded.size();
                catalog.push_back({pointer_path.stem().string() + " #" +
                    std::to_string(index / 8 + 1), decoded});
            }
        }
    }

    std::sort(catalog.begin(), catalog.end(), [](const AnsiArtwork& left, const AnsiArtwork& right) {
        return left.name < right.name;
    });
    return catalog;
}

RenderedQuotePage quote_screen(
    const AnsiArtwork& quote,
    std::size_t index,
    std::size_t total,
    std::size_t page,
    int columns,
    int rows,
    std::string_view screen_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 8, rows);
    }
    centered(output, use_art ? 8 : 3, 96, "A RENEGADE QUOTE", columns);
    if (total > 0) {
        put(output, use_art ? 10 : 5, 4, 90, quote.name, columns - 6);
    }
    const std::vector<std::string> lines = total == 0
        ? std::vector<std::string>{}
        : wrap_body(quote.contents, static_cast<std::size_t>(columns - 10));
    const int body_start = use_art ? 12 : 7;
    const std::size_t visible = static_cast<std::size_t>(
        std::max(1, rows - body_start - 5));
    const std::size_t page_count = std::max<std::size_t>(
        1, (lines.size() + visible - 1) / visible);
    page = std::min(page, page_count - 1);
    const std::size_t first_line = page * visible;
    for (std::size_t line = first_line; line < std::min(first_line + visible, lines.size()); ++line) {
        put(output, body_start + static_cast<int>(line - first_line), 5, 97, lines[line], columns - 8);
    }
    if (total == 0) {
        put(output, 10, 5, 93, "No approved quotes yet. Be the first to submit one.", columns - 6);
        put(output, rows - 4, 4, 97, "A submit for SysOp review  Q return", columns - 2);
        put(output, rows - 2, 4, 90, "The SysOp reviews caller-submitted quotes before they appear.", columns - 2);
    } else {
        put(output, rows - 4, 4, 97, "↑↓ text  ←→ quotes  N/P text  [/] quotes  R random  A submit  Q return", columns - 2);
        put(output, rows - 2, 4, 90, "Quote " + std::to_string(index + 1) + "/" +
            std::to_string(total) + "  Text " + std::to_string(page + 1) + "/" +
            std::to_string(page_count), columns - 2);
    }
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return {std::move(output), page, page_count};
}

std::string quote_review_screen(
    const QuoteSubmissionPage& page,
    std::optional<std::int64_t> selected_id,
    int columns,
    int rows,
    std::string_view screen_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 8, rows);
    }
    centered(output, use_art ? 8 : 3, 96, "QUOTE SUBMISSIONS FOR REVIEW", columns);
    for (std::size_t row = 0; row < page.entries.size() && row < 10; ++row) {
        const CommunityQuote& quote = page.entries[row];
        const bool selected = selected_id.has_value() && quote.id == *selected_id;
        const std::string first_line = one_line(quote.text.substr(0, quote.text.find('\n')));
        const std::string line = (selected ? ">" : " ") + std::to_string((row + 1) % 10) +
            " " + quote.author + " #" + std::to_string(quote.id) + "  " + first_line;
        if (selected) {
            put_selected(output, (use_art ? 10 : 6) + static_cast<int>(row), 4, line, columns - 5);
        } else {
            put(output, (use_art ? 10 : 6) + static_cast<int>(row), 4, 97, line, columns - 5);
        }
    }
    if (page.entries.empty()) {
        put(output, use_art ? 10 : 10, 5, 93,
            "No caller quote submissions are waiting for review.", columns - 6);
    }
    put(output, rows - 4, 4, 97,
        "Arrows move  Enter select  1-0 select  A approve  D reject  N/P pages  Q return", columns - 2);
    put(output, rows - 2, 4, 90, "Page " + std::to_string(page.page + 1) + "/" +
        std::to_string(page.page_count) + "    " + std::to_string(page.total) + " pending", columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string bbs_directory_screen(
    const BbsListingPage& page,
    std::optional<std::int64_t> selected_id,
    int columns,
    int rows,
    std::string_view screen_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 8, rows - 1);
    }
    centered(output, use_art ? 8 : 3, 96, "RENEGADE BBS DIRECTORY", columns);
    put(output, use_art ? 9 : 5, 4, 90,
        "Community bulletin boards, telnet doors, and modern terminal systems", columns - 6);
    if (use_art) {
        put(output, 10, 4, 36, std::string(static_cast<std::size_t>(columns - 8), '-'), columns - 4);
    }
    for (std::size_t row = 0; row < page.entries.size() && row < 8; ++row) {
        const BbsListing& entry = page.entries[row];
        const bool selected = selected_id.has_value() && entry.id == *selected_id;
        const std::string endpoint = !entry.telnet_url.empty() ? entry.telnet_url : entry.website_url;
        const std::string line = (selected ? ">" : " ") + std::to_string((row + 1) % 10) +
            "  " + one_line(entry.bbs_name) + "  [" + one_line(entry.owner) + "]" +
            (endpoint.empty() ? std::string{} : "  " + one_line(endpoint));
        if (selected) {
            put_selected(output, (use_art ? 11 : 7) + static_cast<int>(row), 4, line, columns - 5);
        } else {
            put(output, (use_art ? 11 : 7) + static_cast<int>(row), 4, 97, line, columns - 5);
        }
    }
    if (page.entries.empty()) {
        put(output, use_art ? 11 : 10, 5, 93,
            "No boards are listed yet. Add the first BBS to this directory.", columns - 6);
    }
    put(output, rows - 4, 4, 97,
        "ARROWS move  ENTER view  1-8 select  A add  E edit selected  D delete  N/P pages", columns - 2);
    put(output, rows - 2, 4, 90, "Page " + std::to_string(page.page + 1) + "/" +
        std::to_string(page.page_count) + "    " + std::to_string(page.total) + " listed  Q return", columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string bbs_listing_detail_screen(
    const BbsListing& listing,
    std::size_t detail_page,
    bool can_manage,
    int columns,
    int rows,
    std::string_view screen_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    detail_page = std::min<std::size_t>(detail_page, 1);
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 8, rows - 1);
    }
    centered(output, use_art ? 8 : 3, 96, "BBS DIRECTORY LISTING", columns);
    const auto display = [](std::string_view value) {
        return value.empty() ? std::string("(not set)") : one_line(value);
    };
    const std::pair<std::string_view, std::string> core_fields[]{
        {"BBS name", display(listing.bbs_name)},
        {"Owned by", display(listing.owner)},
        {"SysOp", display(listing.sysop_name)},
        {"Telnet / SSH", display(listing.telnet_url)},
        {"Web site", display(listing.website_url)},
        {"Phone", display(listing.phone_number)},
        {"Software", display(listing.software)},
        {"Speed", display(listing.speed)},
        {"Added", display(listing.date_added)},
    };
    const std::pair<std::string_view, std::string> extra_fields[]{
        {"Description 1", display(listing.description)},
        {"Description 2", display(listing.description2)},
        {"Custom XA", display(listing.xa)},
        {"Custom XB", display(listing.xb)},
        {"Custom XC", display(listing.xc)},
        {"Custom XD", display(listing.xd)},
        {"Custom XE", display(listing.xe)},
        {"Custom XF", display(listing.xf)},
        {"Last edited", display(listing.date_edited)},
    };
    const auto& fields = detail_page == 0 ? core_fields : extra_fields;
    const std::size_t count = sizeof(fields) / sizeof(fields[0]);
    for (std::size_t index = 0; index < count; ++index) {
        put(output, (use_art ? 10 : 6) + static_cast<int>(index), 5, 93,
            std::string(fields[index].first) + ": " + fields[index].second, columns - 7);
    }
    const std::string controls = can_manage
        ? "Arrows or N/P details  Enter switch  E edit  D delete  B directory  Q return"
        : "Arrows or N/P details  Enter switch  B directory  Q return";
    put(output, rows - 4, 4, 97, controls, columns - 2);
    put(output, rows - 2, 4, 90, "Listing " + std::to_string(listing.id) +
        "  Details " + std::to_string(detail_page + 1) + "/2", columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string short_messages_screen(
    const std::vector<ShortMessage>& messages,
    std::size_t page,
    int columns,
    int rows,
    std::string_view screen_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 8, rows);
    }
    centered(output, use_art ? 8 : 3, 96, "SHORT MESSAGES", columns);
    constexpr std::size_t page_size = 10;
    const std::size_t page_count = std::max<std::size_t>(1,
        (messages.size() + page_size - 1) / page_size);
    page = std::min(page, page_count - 1);
    const std::size_t start = page * page_size;
    for (std::size_t index = start; index < std::min(start + page_size, messages.size()); ++index) {
        const std::size_t row = index - start;
        const std::string line = one_line(messages[index].text) + "  " + messages[index].created_at;
        put(output, (use_art ? 10 : 6) + static_cast<int>(row), 5, 97, line, columns - 8);
    }
    put(output, rows - 4, 4, 97,
        page_count > 1 ? "ARROWS or N/P pages  Press any other key to continue" : "Press any key to continue",
        columns - 2);
    put(output, rows - 2, 4, 90, std::to_string(messages.size()) +
        " short message(s) waiting  Page " + std::to_string(page + 1) + "/" +
        std::to_string(page_count), columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string artwork_screen(
    const AnsiArtwork& artwork,
    std::size_t index,
    std::size_t total,
    int columns,
    int rows) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    std::string output = "\x1b[2J\x1b[H\x1b[?25l";
    output += artwork.contents;
    output += "\x1b[0m";
    output += cursor(rows, 1) + "\x1b[0m\x1b[K\x1b[96m";
    output += clipped("Art " + std::to_string(index) + "/" + std::to_string(total) + "  " +
        artwork.name + "  ←/↑ Previous  →/↓ Next  Q Quit", columns);
    output += "\x1b[0m\x1b[?25h";
    return output;
}

std::string bulletin_list_screen(
    const std::vector<AnsiArtwork>& bulletins,
    int columns,
    int rows,
    std::string_view bulletin_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !bulletin_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(bulletin_art);
        output += "\x1b[0m";
        clear_art_rows(output, 10, rows);
    }
    centered(output, use_art ? 10 : 3, 96, "RENEGADE BULLETINS", columns);
    const std::size_t shown = std::min<std::size_t>(bulletins.size(), 26);
    for (std::size_t index = 0; index < shown; ++index) {
        const std::size_t column_index = index / 13;
        const std::size_t row_index = index % 13;
        const int column = column_index == 0 ? 5 : std::max(5, columns / 2);
        const int row = (use_art ? 11 : 6) + static_cast<int>(row_index);
        const std::string label = "[" + std::string(1, static_cast<char>('A' + index)) + "] " +
            one_line(bulletins[index].name);
        if (index == selected_index) {
            put_selected(output, row, column, label, columns - column);
        } else {
            put(output, row, column, 97, label, columns - column);
        }
    }
    if (bulletins.empty()) {
        put(output, use_art ? 11 : 10, 5, 93, "No bulletin files are available.", columns - 6);
    }
    if (use_art) {
        const int controls_row = rows >= 26 ? rows - 2 : rows;
        put(output, controls_row, 4, 90,
            "ARROWS move  ENTER read  A-Z select  ? redisplay  Q return", columns - 2);
        output += cursor(rows, columns) + "\x1b[?25h";
    } else {
        put(output, rows - 3, 4, 90,
            "ARROWS move  ENTER read  A-Z select  ? redisplay  Q return", columns - 2);
        output += cursor(rows - 1, 1) + "\x1b[?25h";
    }
    return output;
}

std::string bulletin_article_screen(
    const AnsiArtwork& bulletin,
    std::size_t index,
    std::size_t total,
    int columns,
    int rows) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    std::string output = "\x1b[2J\x1b[H\x1b[?25l";
    output += bulletin.contents;
    output += "\x1b[0m";
    output += cursor(rows, 1) + "\x1b[0m\x1b[K\x1b[96m";
    output += clipped("Bulletin " + std::to_string(index) + "/" + std::to_string(total) + "  " +
        bulletin.name + "  ←/↑ Previous  →/↓ Next  Q Quit", columns);
    output += "\x1b[0m\x1b[?25h";
    return output;
}

std::string polls_screen(
    const std::vector<Poll>& polls,
    std::size_t page,
    int columns,
    int rows,
    bool sysop,
    std::string_view screen_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    constexpr std::size_t per_page = 10;
    const std::size_t page_count = std::max<std::size_t>(1, (polls.size() + per_page - 1) / per_page);
    page = std::min(page, page_count - 1);
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 8, rows);
    }
    centered(output, use_art ? 8 : 3, 96, "RENEGADE VOTING", columns);
    if (use_art) {
        put(output, 9, 4, 90,
            "Page " + std::to_string(page + 1) + "/" + std::to_string(page_count) +
                "  |  " + std::to_string(polls.size()) + " topics",
            columns - 2);
    }
    for (std::size_t row = 0; row < per_page && page * per_page + row < polls.size(); ++row) {
        const Poll& poll = polls[page * per_page + row];
        const std::string selection = poll.caller_vote.has_value() ? "VOTED" : "OPEN";
        const std::string line = std::to_string((row + 1) % 10) + "  " + one_line(poll.question) +
            "  (" + std::to_string(poll.total_votes) + " votes, " + selection + ")";
        if (page * per_page + row == selected_index) {
            put_selected(output, (use_art ? 10 : 6) + static_cast<int>(row), 4, line, columns - 5);
        } else {
            put(output, (use_art ? 10 : 6) + static_cast<int>(row), 4,
                poll.caller_vote.has_value() ? 90 : 97, line, columns - 5);
        }
    }
    if (polls.empty()) {
        put(output, use_art ? 10 : 10, 5, 93, "No voting topics are available.", columns - 6);
    }
    put(output, rows - (use_art ? 2 : 4), 4, 97, sysop
        ? "ARROWS move  ENTER open  1-0 open  A add topic  N/P pages  Q return"
        : "ARROWS move  ENTER open  1-0 open  N/P pages  Q return", columns - 2);
    if (!use_art) {
        put(output, rows - 2, 4, 90, "Page " + std::to_string(page + 1) + "/" +
            std::to_string(page_count) + "    " + std::to_string(polls.size()) + " topics", columns - 2);
    }
    output += cursor(use_art ? rows : rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string poll_detail_screen(
    const Poll& poll,
    std::size_t choice_page,
    bool show_results,
    bool sysop,
    bool changing_vote,
    int columns,
    int rows,
    std::string_view screen_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    constexpr std::size_t per_page = 10;
    const std::size_t page_count = std::max<std::size_t>(
        1, (poll.options.size() + per_page - 1) / per_page);
    choice_page = std::min(choice_page, page_count - 1);
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 8, rows);
    }
    centered(output, use_art ? 8 : 3, 96, "RENEGADE VOTING", columns);
    put(output, use_art ? 9 : 5, 4, 97, one_line(poll.question), columns - 5);
    if (!poll.subtitle.empty()) {
        put(output, use_art ? 10 : 6, 4, 90, one_line(poll.subtitle), columns - 5);
    }
    put(output, use_art ? 11 : 7, 4, 90, "Created by " + one_line(poll.created_by) + "  " +
        std::to_string(poll.total_votes) + " total votes", columns - 5);
    for (std::size_t row = 0; row < per_page && choice_page * per_page + row < poll.options.size(); ++row) {
        const PollOption& option = poll.options[choice_page * per_page + row];
        const std::string choice_label = std::to_string((row + 1) % 10) + ". ";
        std::string line = choice_label + one_line(option.text);
        if (show_results) {
            const std::uint64_t percent = poll.total_votes == 0
                ? 0
                : option.votes * 100 / poll.total_votes;
            line += "  " + std::to_string(option.votes) + " (" + std::to_string(percent) + "%)";
        }
        const bool chosen = poll.caller_vote.has_value() && *poll.caller_vote == option.id;
        const std::string entry = (chosen ? "> " : "  ") + line;
        if (choice_page * per_page + row == selected_index) {
            put_selected(output, (use_art ? 12 : 9) + static_cast<int>(row), 5, entry, columns - 6);
        } else {
            put(output, (use_art ? 12 : 9) + static_cast<int>(row), 5, chosen ? 93 : 97,
                entry, columns - 6);
        }
    }
    std::string controls = poll.caller_vote.has_value()
        ? (changing_vote ? "ARROWS move  ENTER replace  1-0 select  R results  N/P choices" :
            "ARROWS move  R results  N/P choices")
        : "ARROWS move  ENTER vote  1-0 vote  R results  N/P choices";
    if (poll.caller_vote.has_value() && poll.allow_vote_changes && !changing_vote) {
        controls += "  C change vote";
    }
    if (poll.allow_new_choices && poll.options.size() < 25) {
        controls += "  A add choice";
    }
    if (show_results && sysop) {
        controls += "  L voters";
    }
    controls += "  Q topics";
    put(output, rows - (use_art ? 1 : 4), 4, 97, controls, columns - 2);
    put(output, rows - (use_art ? 2 : 2), 4, 90,
        "Choice page " + std::to_string(choice_page + 1) + "/" + std::to_string(page_count), columns - 2);
    output += cursor(use_art ? rows : rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string callers_screen(
    const CallerSessionPage& page,
    int columns,
    int rows,
    std::string_view callers_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    if (!callers_art.empty() && columns >= 80 && rows >= 24) {
        std::string output = "\x1b[2J\x1b[H\x1b[?25l";
        output.append(callers_art);
        output += "\x1b[0m";
        clear_art_rows(output, 5, rows - 1);
        put(output, 5, 4, 96, "TODAY'S CALLERS", columns - 2);
        put(output, 7, 4, 97, "NODE  HANDLE                         CONNECTED   DISCONNECTED", columns - 2);
        put(output, 8, 4, 36, "----  ------------------------------ ----------  ------------", columns - 2);
        for (std::size_t row = 0; row < page.entries.size() && row < 10; ++row) {
            const CallerSession& caller = page.entries[row];
            const std::string time_in = caller.connected_at.size() >= 16
                ? caller.connected_at.substr(11, 5)
                : caller.connected_at;
            const std::string time_out = caller.disconnected_at.empty()
                ? "ONLINE"
                : (caller.disconnected_at.size() >= 16
                    ? caller.disconnected_at.substr(11, 5)
                    : caller.disconnected_at);
            const std::string line = std::to_string(caller.node) + "     " +
                clipped(one_line(caller.handle), 30) + "  " + time_in + "       " + time_out;
            put(output, 9 + static_cast<int>(row), 4, caller.disconnected_at.empty() ? 93 : 97,
                line, columns - 2);
        }
        if (page.entries.empty()) {
            put(output, 10, 5, 90, "No BBS sessions have connected today.", columns - 6);
        }
        put(output, rows - 4, 4, 97, "ARROWS pages  N/P pages  Q return", columns - 2);
        put(output, rows - 2, 4, 90, "Page " + std::to_string(page.page + 1) + "/" +
            std::to_string(page.page_count) + "    " + std::to_string(page.total) + " callers today",
            columns - 2);
        output += cursor(rows - 1, 1) + "\x1b[?25h";
        return output;
    }
    std::string output = frame(columns, rows);
    centered(output, 3, 96, "TODAY'S CALLERS", columns);
    for (std::size_t row = 0; row < page.entries.size() && row < 10; ++row) {
        const CallerSession& caller = page.entries[row];
        const std::string time_in = caller.connected_at.size() >= 16
            ? caller.connected_at.substr(11, 5)
            : caller.connected_at;
        const std::string time_out = caller.disconnected_at.empty()
            ? "ONLINE"
            : (caller.disconnected_at.size() >= 16
                ? caller.disconnected_at.substr(11, 5)
                : caller.disconnected_at);
        const std::string line = std::to_string((row + 1) % 10) + "  Node " +
            std::to_string(caller.node) + "  " + caller.handle + "  " + time_in + " - " + time_out;
        put(output, 6 + static_cast<int>(row), 4, caller.disconnected_at.empty() ? 93 : 97,
            line, columns - 5);
    }
    if (page.entries.empty()) {
        put(output, 10, 5, 93, "No BBS sessions have connected today.", columns - 6);
    }
    put(output, rows - 4, 4, 97, "ARROWS pages  N/P pages  Q return", columns - 2);
    put(output, rows - 2, 4, 90, "Page " + std::to_string(page.page + 1) + "/" +
        std::to_string(page.page_count) + "    " + std::to_string(page.total) + " callers today",
        columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string statistics_screen(
    const CommunityStatistics& statistics,
    std::size_t page,
    int columns,
    int rows,
    std::string_view stats_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    page = std::min<std::size_t>(page, 3);
    const bool use_stats_art = !stats_art.empty() && columns >= 80 && rows >= 24;
    if (use_stats_art && page == 3) {
        std::string output = "\x1b[2J\x1b[H\x1b[?25l";
        output.append(stats_art);
        output += "\x1b[0m";
        clear_art_rows(output, 8, rows);
        put(output, 8, 5, 96, "TOP UPLOAD VOLUME (KiB)", 34);
        put(output, 8, 42, 96, "TOP DOWNLOAD VOLUME (KiB)", columns - 1);
        put(output, 9, 5, 90, "CALLER                       KiB", 34);
        put(output, 9, 42, 90, "CALLER                       KiB", columns - 1);
        for (std::size_t index = 0; index < 10; ++index) {
            const int row = 10 + static_cast<int>(index);
            if (index < statistics.top_uploaded_kib.size()) {
                const StatisticLeader& leader = statistics.top_uploaded_kib[index];
                put(output, row, 5, 97, std::to_string(index + 1) + ". " + leader.handle, 25);
                put(output, row, 31, 93, std::to_string(leader.value), columns - 1);
            }
            if (index < statistics.top_downloaded_kib.size()) {
                const StatisticLeader& leader = statistics.top_downloaded_kib[index];
                put(output, row, 42, 97, std::to_string(index + 1) + ". " + leader.handle, columns - 1);
                put(output, row, 70, 93, std::to_string(leader.value), columns - 1);
            }
        }
        if (statistics.top_uploaded_kib.empty() && statistics.top_downloaded_kib.empty()) {
            put(output, 12, 5, 90, "No completed file transfers yet.", columns - 8);
        }
        put(output, rows - 3, 5, 36, std::string(static_cast<std::size_t>(columns - 10), '-'), columns);
        put(output, rows - 2, 5, 90,
            "Page 4/4  ARROWS or N/P pages  (completed SFTP transfers)", columns - 8);
        put(output, rows - 1, 5, 97, "ARROWS or N/P pages  Q Return to the main menu", columns - 8);
        output += cursor(rows - 1, 1) + "\x1b[?25h";
        return output;
    }
    const int row_offset = use_stats_art ? 4 : 0;
    std::string output = use_stats_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_stats_art) {
        output.append(stats_art);
        output += "\x1b[0m";
        clear_art_rows(output, 8, rows);
    }
    const auto put_stat = [&output, row_offset](
        int row, int column, int color, std::string_view text, int width) {
        put(output, row + row_offset, column, color, text, column + width - 1);
    };
    const auto centered_stat = [&output, row_offset](int row, int color,
                                                      std::string_view text, int width) {
        centered(output, row + row_offset, color, text, width);
    };
    if (!use_stats_art) {
        centered_stat(3, 96, "RENEGADE COMMUNITY STATISTICS", columns);
    }
    put_stat(4, 4, 36, std::string(static_cast<std::size_t>(columns - 8), '-'), columns);

    if (page == 0 && columns >= 80) {
        const std::array<std::pair<std::string, std::string>, 4> totals{{
            {"Accounts: " + std::to_string(statistics.accounts),
                "Public posts: " + std::to_string(statistics.public_messages)},
            {"Private mail: " + std::to_string(statistics.private_messages),
                "Public files: " + std::to_string(statistics.public_files)},
            {"Downloads: " + std::to_string(statistics.downloads),
                "Callers today: " + std::to_string(statistics.callers_today)},
            {"One-liners: " + std::to_string(statistics.one_liners),
                "Voting topics: " + std::to_string(statistics.polls)},
        }};
        for (std::size_t index = 0; index < totals.size(); ++index) {
            const int row = 5 + static_cast<int>(index);
            put_stat(row, 5, 97, totals[index].first, 36);
            put_stat(row, 42, 97, totals[index].second, columns - 44);
        }
        put_stat(10, 5, 96, "TOP PUBLIC POSTERS", 35);
        put_stat(10, 42, 96, "MOST DOWNLOADED FILES", columns - 44);
        for (std::size_t index = 0; index < 5; ++index) {
            const int row = 12 + static_cast<int>(index);
            if (index < statistics.top_public_posters.size()) {
                const StatisticLeader& leader = statistics.top_public_posters[index];
                put_stat(row, 5, 97, std::to_string(index + 1) + ". " + leader.handle, 25);
                    put_stat(row, 31, 93, std::to_string(leader.value), 8);
            }
            if (index < statistics.top_downloads.size()) {
                const FileDownloadLeader& leader = statistics.top_downloads[index];
                put_stat(row, 42, 97, std::to_string(index + 1) + ". " + leader.area + "/" +
                    leader.filename, 27);
                put_stat(row, 70, 93, std::to_string(leader.downloads), columns - 71);
            }
        }
    } else if (page == 0) {
        const std::array<std::pair<std::string_view, std::uint64_t>, 8> entries{{
            {"Registered accounts", statistics.accounts},
            {"Public messages", statistics.public_messages},
            {"Private messages", statistics.private_messages},
            {"Files in public areas", statistics.public_files},
            {"Downloads recorded", statistics.downloads},
            {"Callers since midnight", statistics.callers_today},
            {"One-liners", statistics.one_liners},
            {"Voting topics", statistics.polls},
        }};
        const int value_column = std::min(30, columns - 8);
        for (std::size_t index = 0; index < entries.size(); ++index) {
            const int row = 6 + static_cast<int>(index);
            put_stat(row, 4, 97, entries[index].first, value_column - 5);
            put_stat(row, value_column, 93, std::to_string(entries[index].second), columns - 5);
        }
    } else if (page == 1 && columns >= 80) {
        put_stat(6, 5, 90, "Session history keeps the most recent 10,000 callers.", 70);
        put_stat(10, 5, 96, "MOST FREQUENT CALLERS", 35);
        put_stat(10, 42, 96, "MOST PRIVATE MAIL SENT", columns - 44);
        for (std::size_t index = 0; index < 5; ++index) {
            const int row = 12 + static_cast<int>(index);
            if (index < statistics.top_callers.size()) {
                const StatisticLeader& leader = statistics.top_callers[index];
                put_stat(row, 5, 97, std::to_string(index + 1) + ". " + leader.handle, 25);
                put_stat(row, 31, 93, std::to_string(leader.value), 8);
            }
            if (index < statistics.top_private_mail_senders.size()) {
                const StatisticLeader& leader = statistics.top_private_mail_senders[index];
                put_stat(row, 42, 97, std::to_string(index + 1) + ". " + leader.handle, 25);
                put_stat(row, 70, 93, std::to_string(leader.value), columns - 71);
            }
        }
    } else if (page == 2 && columns >= 80) {
        const auto leaders = [&](int column, std::string_view title,
                                 const std::vector<StatisticLeader>& entries) {
            put_stat(6, column, 96, title, 24);
            for (std::size_t index = 0; index < entries.size() && index < 5; ++index) {
                put_stat(8 + static_cast<int>(index), column, 97,
                    std::to_string(index + 1) + ". " + entries[index].handle, 18);
                put_stat(8 + static_cast<int>(index), column + 19, 93,
                    std::to_string(entries[index].value), 5);
            }
        };
        put_stat(5, 5, 90, "Ranked from caller sessions and completed SFTP transfers", columns - 8);
        leaders(4, "TOP BBS TIME (MIN)", statistics.top_online_minutes);
        leaders(30, "TOP UPLOADERS", statistics.top_uploaders);
        leaders(56, "TOP DOWNLOADERS", statistics.top_downloaders);
    } else if (page == 3 && columns >= 80) {
        put_stat(6, 5, 96, "TOP UPLOAD VOLUME (KiB)", 34);
        put_stat(6, 42, 96, "TOP DOWNLOAD VOLUME (KiB)", columns - 44);
        for (std::size_t index = 0; index < 5; ++index) {
            const int row = 8 + static_cast<int>(index);
            if (index < statistics.top_uploaded_kib.size()) {
                const StatisticLeader& leader = statistics.top_uploaded_kib[index];
                put_stat(row, 5, 97, std::to_string(index + 1) + ". " + leader.handle, 25);
                put_stat(row, 31, 93, std::to_string(leader.value), 8);
            }
            if (index < statistics.top_downloaded_kib.size()) {
                const StatisticLeader& leader = statistics.top_downloaded_kib[index];
                put_stat(row, 42, 97, std::to_string(index + 1) + ". " + leader.handle, 25);
                put_stat(row, 70, 93, std::to_string(leader.value), columns - 71);
            }
        }
    } else if (page == 1 && columns < 80) {
        put_stat(6, 4, 90, "Recent caller sessions and private messages sent", columns - 6);
        put_stat(8, 4, 96, "MOST FREQUENT CALLERS", columns - 6);
        for (std::size_t index = 0; index < statistics.top_callers.size() && index < 4; ++index) {
            put_stat(9 + static_cast<int>(index), 5, 97,
                std::to_string(index + 1) + ". " + statistics.top_callers[index].handle +
                    "  " + std::to_string(statistics.top_callers[index].value), columns - 8);
        }
        put_stat(14, 4, 96, "MOST PRIVATE MAIL SENT", columns - 6);
        for (std::size_t index = 0;
             index < statistics.top_private_mail_senders.size() && index < 4; ++index) {
            put_stat(15 + static_cast<int>(index), 5, 97,
                std::to_string(index + 1) + ". " + statistics.top_private_mail_senders[index].handle +
                    "  " + std::to_string(statistics.top_private_mail_senders[index].value), columns - 8);
        }
    } else if (page == 2 && columns < 80) {
        const auto section = [&](int row, std::string_view title,
                                 const std::vector<StatisticLeader>& entries) {
            put_stat(row, 4, 96, title, columns - 6);
            for (std::size_t index = 0; index < entries.size() && index < 3; ++index) {
                put_stat(row + 1 + static_cast<int>(index), 5, 97,
                    std::to_string(index + 1) + ". " + entries[index].handle +
                        "  " + std::to_string(entries[index].value), columns - 8);
            }
        };
        section(5, "TOP CALLER TIME (MINUTES)", statistics.top_online_minutes);
        section(10, "TOP UPLOADERS", statistics.top_uploaders);
        section(15, "TOP DOWNLOADERS", statistics.top_downloaders);
    } else if (page == 3 && columns < 80) {
        const auto section = [&](int row, std::string_view title,
                                 const std::vector<StatisticLeader>& entries) {
        put_stat(row, 4, 96, title, columns - 6);
        for (std::size_t index = 0; index < entries.size() && index < 5; ++index) {
                put_stat(row + 1 + static_cast<int>(index), 5, 97,
                    std::to_string(index + 1) + ". " + entries[index].handle +
                        "  " + std::to_string(entries[index].value), columns - 8);
            }
        };
        section(5, "TOP UPLOAD VOLUME (KiB)", statistics.top_uploaded_kib);
        section(13, "TOP DOWNLOAD VOLUME (KiB)", statistics.top_downloaded_kib);
    } else {
        put_stat(6, 4, 90, "Recent caller sessions and private messages sent", columns - 6);
        put_stat(8, 4, 96, "MOST FREQUENT CALLERS", columns - 6);
        for (std::size_t index = 0; index < statistics.top_callers.size(); ++index) {
            put_stat(9 + static_cast<int>(index), 5, 97,
                std::to_string(index + 1) + ". " + statistics.top_callers[index].handle +
                    "  " + std::to_string(statistics.top_callers[index].value), columns - 8);
        }
        put_stat(15, 4, 96, "MOST PRIVATE MAIL SENT", columns - 6);
        for (std::size_t index = 0;
             index < statistics.top_private_mail_senders.size() && index < 4; ++index) {
            put_stat(16 + static_cast<int>(index), 5, 97,
                std::to_string(index + 1) + ". " + statistics.top_private_mail_senders[index].handle +
                    "  " + std::to_string(statistics.top_private_mail_senders[index].value), columns - 8);
        }
    }
    put(output, rows - 3, 5, 36, std::string(static_cast<std::size_t>(columns - 10), '-'), columns);
    put(output, rows - 2, 5, 90,
        "Page " + std::to_string(page + 1) + "/4  ARROWS or N/P pages  (BBS-wide activity)", columns - 8);
    put(output, rows - 1, 5, 97, "ARROWS or N/P pages  Q Return to the main menu", columns - 8);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

RenderedAutoMessagePage auto_message_screen(
    const std::optional<AutoMessage>& message,
    bool may_read_anonymous,
    bool sysop,
    std::size_t page,
    int columns,
    int rows,
    std::string_view message_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !message_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(message_art);
        output += "\x1b[0m";
        clear_art_rows(output, 9, rows);
    }
    centered(output, use_art ? 9 : 3, 96, "RENEGADE AUTO-MESSAGE", columns);
    std::size_t page_count = 1;
    if (message.has_value()) {
        std::string author = message->anonymous ? "Anonymous" : message->author;
        const bool may_reveal_author = message->anonymous_type == 2 ? sysop : may_read_anonymous;
        if (may_reveal_author && message->anonymous) {
            author += " (" + message->author + ")";
        }
        put(output, use_art ? 10 : 5, use_art ? 4 : 4, 93,
            one_line(author) + "  " + one_line(message->created_at), columns - 5);
        const auto lines = wrap_body(message->text, static_cast<std::size_t>(std::max(20, columns - 10)));
        const std::size_t lines_per_page = static_cast<std::size_t>(
            std::max(1, rows - (use_art ? 16 : 13)));
        page_count = std::max<std::size_t>(1, (lines.size() + lines_per_page - 1) / lines_per_page);
        page = std::min(page, page_count - 1);
        const std::size_t first_line = page * lines_per_page;
        for (std::size_t index = first_line;
            index < std::min(first_line + lines_per_page, lines.size()); ++index) {
            put(output, (use_art ? 12 : 7) + static_cast<int>(index - first_line), 5, 97,
                lines[index], columns - 6);
        }
    } else {
        put(output, use_art ? 12 : 10, 5, 93, "No auto-message has been posted.", columns - 6);
    }
    const bool can_reply = message.has_value() && (!message->anonymous ||
        (message->anonymous_type == 2 ? sysop : may_read_anonymous));
    std::string controls = "W write/update";
    if (can_reply) {
        controls += "  R reply";
    }
    if (page_count > 1) {
        controls += "  ARROWS or N/P pages";
    }
    controls += "  Q return";
    put(output, rows - 4, 4, 97, controls, columns - 2);
    put(output, rows - 2, 4, 90, "Page " + std::to_string(page + 1) + "/" +
        std::to_string(page_count), columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return {std::move(output), page_count};
}

std::string_view welcome_menu_keys(bool is_sysop) {
    return welcome_keys_internal(is_sysop);
}

std::string welcome_screen(
    std::string_view handle,
    int node_number,
    int columns,
    int rows,
    std::string_view welcome_art,
    bool is_sysop,
    std::string_view tagline,
    bool hotkeys,
    bool expert_mode,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const std::size_t menu_count = welcome_keys_internal(is_sysop).size();
    selected_index = menu_count == 0 ? 0 : selected_index % menu_count;
    // Keep the caller-facing command map below the compact welcome banner so
    // every displayed key matches the active menu configuration.
    const bool use_art = !welcome_art.empty() && columns >= 80 && rows >= 24;
    std::string output;
    if (use_art) {
        output = "\x1b[2J\x1b[H\x1b[?25l";
        output.append(welcome_art);
        output += "\x1b[0m";
        // Imported main-menu panels contain their own menu choices below the
        // title. Clear the full body before drawing the live Renegade++ menu.
        clear_art_rows(output, 8, rows);
    } else {
        output = frame(columns, rows);
        centered(output, 3, 96, " _____  _____ _   _ _____ _____ _____ _____ _____", columns);
        centered(output, 4, 96, "|     ||   __| \\ | |   __|  |  |   __|   __|   __|", columns);
        centered(output, 5, 96, "|  |  ||   __|  \\| |   __|     |   __|__   |__   |", columns);
        centered(output, 6, 96, "|_____||_____|_|\\__|_____|__|__|_____|_____|_____|", columns);
        centered(output, 7, 93, "R E N E G A D E", columns);
        centered(output, 8, 93, "BULLETIN BOARD SYSTEM", columns);
        centered(output, 9, 90, "ANSI TERMINAL EDITION", columns);
    }
    if (use_art) {
        draw_welcome_menu(output, is_sysop, expert_mode, true, columns, selected_index);
        put(output, 14, 4, 97, "WELCOME, " + std::string(handle) + "!", columns - 6);
        put(output, 15, 4, 93,
            !tagline.empty() ? one_line(tagline) : "THE UNDERGROUND IS STILL ONLINE.", columns - 6);
        put(output, 16, 4, 96,
            "CONNECTED ON NODE " + std::to_string(node_number) + " THROUGH SECURE SSH.", columns - 6);
        put(output, 17, 4, 95, "ANSI ART  |  MESSAGE BOARDS  |  CHAT  |  FILES  |  COMMUNITY", columns - 6);
    } else {
        put(output, 12, 3, 36, std::string(static_cast<std::size_t>(columns - 6), '='), columns);
        put(output, 14, 5, 97, "Welcome, " + std::string(handle) + "!", columns);
        put(output, 15, 5, 93,
            !tagline.empty() ? one_line(tagline) : "THE UNDERGROUND IS STILL ONLINE.", columns - 7);
        put(output, 16, 5, 96, "You are connected on node " + std::to_string(node_number) + ".", columns);
        draw_welcome_menu(output, is_sysop, expert_mode, false, columns, selected_index);
    }
    const std::string prompt = hotkeys ? "Command > " : "Command (Enter) > ";
    put(output, rows - 1, 5, 97, prompt, columns);
    output += cursor(rows - 1, 5 + static_cast<int>(prompt.size())) + "\x1b[?25h";
    return output;
}

std::string entrance_screen(
    std::string_view handle,
    int node_number,
    int columns,
    int rows,
    std::string_view entrance_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !entrance_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(entrance_art);
        output += "\x1b[0m";
        clear_art_rows(output, 9, rows - 3);
        centered(output, 10, 96, "WELCOME TO THE UNDERGROUND.", columns);
        put(output, 12, 4, 97, "WELCOME BACK, " + one_line(handle), columns - 6);
        put(output, 14, 4, 93, "YOUR RENEGADE SESSION IS READY.", columns - 6);
        put(output, 16, 4, 90,
            "NODE " + std::to_string(node_number) + "   /   SECURE SSH   /   ANSI TERMINAL", columns - 6);
        put(output, 18, 4, 95,
            "NIGHT SHIFT  /  OPEN CHANNELS  /  KEEP THE BOARDS ALIVE", columns - 6);
        put(output, rows - 3, 4, 36,
            std::string(static_cast<std::size_t>(columns - 8), '-'), columns - 6);
        centered(output, rows - 2, 97, "PRESS ANY KEY TO ENTER THE BOARD", columns);
    } else {
        centered(output, 4, 96, "RENEGADE ONLINE", columns);
        centered(output, 6, 93, "WELCOME TO THE UNDERGROUND.", columns);
        put(output, 10, 5, 97, "Welcome back, " + one_line(handle) + "!", columns - 8);
        put(output, 12, 5, 93, "Your Renegade session is ready.", columns - 8);
        put(output, 14, 5, 90,
            "Node " + std::to_string(node_number) + "   Secure SSH terminal", columns - 8);
        put(output, 16, 5, 95,
            "Night shift  /  open channels  /  keep the boards alive", columns - 8);
        centered(output, rows - 3, 97, "PRESS ANY KEY TO ENTER THE BOARD", columns);
    }
    output += cursor(rows, 1) + "\x1b[?25h";
    return output;
}

std::string account_admin_screen(
    const std::vector<AccountSummary>& accounts,
    std::size_t page,
    std::optional<std::size_t> selected_index,
    int columns,
    int rows,
    std::string_view screen_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    constexpr std::size_t page_size = 10;
    const std::size_t page_count = std::max<std::size_t>(1, (accounts.size() + page_size - 1) / page_size);
    page = std::min(page, page_count - 1);
    const std::size_t first = page * page_size;
    const std::size_t end = std::min(accounts.size(), first + page_size);
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 5, rows);
    }
    centered(output, use_art ? 5 : 2, 96, "RENEGADE SYSOP - ACCOUNT CONTROL", columns);
    put(output, use_art ? 7 : 4, 3, 36,
        "Handle                         Status      Role       Created", columns);
    const int visible_rows = std::max(1, std::min(10, rows - 11));
    for (int row = 0; row < visible_rows; ++row) {
        const std::size_t index = first + static_cast<std::size_t>(row);
        if (index >= end) {
            break;
        }
        const AccountSummary& account = accounts[index];
        const std::string status = !account.approved ? "pending" :
            (account.enabled ? "enabled" : "disabled");
        const std::string role = account.is_sysop ? "SysOp" : "user";
        const std::string date = account.created_at.size() > 10
            ? account.created_at.substr(0, 10)
            : account.created_at;
        const std::string line = (selected_index == index ? "> " : "  ") +
            account.handle + "  " + status + "  " + role + "  " + date;
        if (selected_index == index) {
            put_selected(output, (use_art ? 8 : 6) + row, 3, line, columns - 1);
        } else {
            put(output, (use_art ? 8 : 6) + row, 3, 37, line, columns - 1);
        }
    }
    put(output, rows - 4, 3, 36,
        "Page " + std::to_string(page + 1) + "/" + std::to_string(page_count) +
        "  Accounts: " + std::to_string(accounts.size()), columns);
    put(output, rows - 3, 3, 93, columns < 60
        ? "Arrows Move Enter View V/E/D/T/A/W/Y"
        : "Arrows Move Enter View [1-0] Select [V]iew [E]n [D]is [T]Sys [A]rea [W]Sign [Y]Val", columns);
    put(output, rows - 2, 3, 93, columns < 60
        ? "[L]og [N]ext [P]rev [Q]uit"
        : "[N]ext page  [P]revious  [R]efresh  [L]og  [Q] Main menu", columns);
    output += cursor(rows - 1, 2) + "\x1b[?25h";
    return output;
}

std::string signup_question_admin_screen(
    const std::array<bool, 27>& enabled,
    std::string_view recovery_question,
    const std::array<std::string, 3>& user_questions,
    int editing_user_question,
    std::string_view user_question_input,
    bool preferences_page,
    int columns,
    int rows,
    std::string_view screen_art,
    std::size_t selected_index,
    std::size_t selected_prompt_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 5, rows);
    }
    centered(output, use_art ? 5 : 2, 96, preferences_page
        ? "RENEGADE SYSOP - NEW USER PREFERENCES"
        : "RENEGADE SYSOP - NEW USER QUESTIONS", columns);
    if (preferences_page) {
        static constexpr std::pair<char, int> keys_and_ids[]{
            {'O', 16}, {'S', 19}, {'T', 20}, {'U', 21}, {'V', 22}, {'Y', 25},
        };
        static constexpr std::string_view labels[]{
            "ANSI color", "Screen clearing", "Page pauses", "Hotkey input",
            "Expert mode", "Mailbox open / closed",
        };
        for (std::size_t index = 0; index < std::size(keys_and_ids); ++index) {
            const auto [key, source_id] = keys_and_ids[index];
            const bool on = enabled[static_cast<std::size_t>(source_id)];
            const std::string line = "[" + std::string(1, key) + "] " +
                (on ? "ON  " : "off ") + std::string(labels[index]) +
                "  (source question " + std::to_string(source_id) + ")";
            if (index == selected_index) {
                put_selected(output, (use_art ? 7 : 5) + static_cast<int>(index), 4,
                    line, columns - 5);
            } else {
                put(output, (use_art ? 7 : 5) + static_cast<int>(index), 4,
                    on ? 92 : 90, line, columns - 5);
            }
        }
        put(output, use_art ? 15 : 13, 4, 90,
            "Enabled questions are presented to callers during account signup.",
            columns - 5);
        put(output, rows - 3, 4, 93,
            "Arrows move  Enter toggle  O/S/T/U/V/Y shortcuts  Questions 16, 19-22 and 25", columns - 2);
        put(output, rows - 2, 4, 93, "[P] Personal questions  [Q] Account control", columns - 2);
    } else {
        static constexpr std::pair<char, int> keys_and_ids[]{
            {'B', 2}, {'C', 3}, {'D', 4}, {'E', 5}, {'F', 6}, {'G', 7},
            {'H', 8}, {'I', 9}, {'J', 10}, {'K', 11}, {'L', 12}, {'M', 14},
        };
        static constexpr std::string_view labels[]{
            "Real name", "Country", "Street address", "City and state", "ZIP / postal code",
            "Phone number", "Birth date", "Gender", "SysOp answer 1", "SysOp answer 2",
            "SysOp answer 3", "Password-recovery answer",
        };
        const auto question_line = [&](std::size_t index) {
            const auto [key, source_id] = keys_and_ids[index];
            return "[" + std::string(1, key) + "] " +
                (enabled[static_cast<std::size_t>(source_id)] ? "ON  " : "off ") +
                std::string(labels[index]) + "  (Q" + std::to_string(source_id) + ")";
        };
        if (use_art) {
            for (std::size_t index = 0; index < 6; ++index) {
                const auto [left_key, left_id] = keys_and_ids[index];
                const auto [right_key, right_id] = keys_and_ids[index + 6];
                const std::string left = "[" + std::string(1, left_key) + "] " +
                    (enabled[static_cast<std::size_t>(left_id)] ? "ON  " : "off ") +
                    std::string(labels[index]);
                const std::string right = "[" + std::string(1, right_key) + "] " +
                    (enabled[static_cast<std::size_t>(right_id)] ? "ON  " : "off ") +
                    std::string(labels[index + 6]);
                if (selected_index == index) {
                    put_selected(output, 7 + static_cast<int>(index), 4, left, 36);
                } else {
                    put(output, 7 + static_cast<int>(index), 4,
                        enabled[static_cast<std::size_t>(left_id)] ? 92 : 90, left, 36);
                }
                if (selected_index == index + 6) {
                    put_selected(output, 7 + static_cast<int>(index), 42, right, columns - 1);
                } else {
                    put(output, 7 + static_cast<int>(index), 42,
                        enabled[static_cast<std::size_t>(right_id)] ? 92 : 90, right, columns - 1);
                }
            }
            put(output, 14, 4, 36, "Recovery prompt: " +
                (recovery_question.empty() ? std::string("(not configured; question 14 stays hidden)")
                                           : one_line(recovery_question)), columns - 5);
            for (std::size_t index = 0; index < user_questions.size(); ++index) {
                put(output, 16 + static_cast<int>(index), 4, 36,
                    "Answer " + std::to_string(index + 1) + " prompt: " +
                        (user_questions[index].empty() ? "(default label)" : one_line(user_questions[index])),
                    columns - 5);
            }
        } else {
            for (std::size_t index = 0; index < std::size(keys_and_ids); ++index) {
                const auto [key, source_id] = keys_and_ids[index];
                const std::string line = question_line(index);
                if (index == selected_index) {
                    put_selected(output, 5 + static_cast<int>(index), 4, line, columns - 5);
                } else {
                    put(output, 5 + static_cast<int>(index), 4,
                        enabled[static_cast<std::size_t>(source_id)] ? 92 : 90, line, columns - 5);
                }
            }
            put(output, 17, 4, 36, "Recovery prompt: " +
                (recovery_question.empty() ? std::string("(not configured; question 14 stays hidden)")
                                           : one_line(recovery_question)), columns - 5);
            if (rows >= 24) {
                for (std::size_t index = 0; index < user_questions.size(); ++index) {
                    put(output, 18 + static_cast<int>(index), 4, 36,
                        "Answer " + std::to_string(index + 1) + " prompt: " +
                            (user_questions[index].empty() ? "(default label)" : one_line(user_questions[index])),
                        columns - 5);
                }
            }
        }
        if (editing_user_question == -1) {
            if (columns >= 78) {
                put(output, rows - 4, 4, 93, "Choose a caller answer prompt to edit:", columns - 2);
                put_key_option(output, rows - 3, 4, '1', "Answer prompt 1", columns, selected_prompt_index == 0);
                put_key_option(output, rows - 3, 29, '2', "Answer prompt 2", columns, selected_prompt_index == 1);
                put_key_option(output, rows - 3, 54, '3', "Answer prompt 3", columns, selected_prompt_index == 2);
            } else {
                put(output, rows - 7, 4, 93, "Choose a caller answer prompt to edit:", columns - 2);
                put_key_option(output, rows - 6, 4, '1', "Answer prompt 1", columns, selected_prompt_index == 0);
                put_key_option(output, rows - 5, 4, '2', "Answer prompt 2", columns, selected_prompt_index == 1);
                put_key_option(output, rows - 4, 4, '3', "Answer prompt 3", columns, selected_prompt_index == 2);
            }
            put(output, rows - 2, 4, 93, "Arrows move  Enter edit  1-3 select  Esc cancel", columns - 2);
        } else if (editing_user_question >= 1 && editing_user_question <= 3) {
            put(output, rows - 2, 4, 97,
                "Prompt " + std::to_string(editing_user_question) +
                    " (70 chars; blank resets) > " + std::string(user_question_input), columns - 2);
        } else {
            put(output, rows - 3, 4, 93,
                "Arrows move  Enter toggle  B-M shortcuts  Personal questions 2-12 and 14", columns - 2);
            put(output, rows - 2, 4, 93, columns < 60
                ? "[P]Prompts [N]Prefs [Q]Back"
                : "[P] Edit answer prompts  [N] Preference questions  [Q] Account control", columns - 2);
        }
    }
    output += cursor(rows - 1, 2) + "\x1b[?25h";
    return output;
}

std::string validation_level_admin_screen(
    const std::vector<ValidationLevel>& levels,
    std::size_t page,
    std::size_t selected_index,
    char edit_operation,
    std::string_view input,
    std::string_view notice,
    int columns,
    int rows,
    std::string_view screen_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    constexpr std::size_t page_size = 10;
    const std::size_t page_count = std::max<std::size_t>(1, (levels.size() + page_size - 1) / page_size);
    page = std::min(page, page_count - 1);
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    const int offset = use_art ? 3 : 0;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 5, rows);
    }
    centered(output, 2 + offset, 96, "RENEGADE SYSOP - VALIDATION LEVELS", columns);
    if (edit_operation != '\0') {
        if (!notice.empty()) {
            put(output, 4 + offset, 3, 90, notice, columns - 1);
        }
        if (edit_operation == 'S') {
            put(output, 6 + offset, 3, 36, "KEY;DESC;SL;DSL;MENU;DAYS;TO;AR;AC", columns - 1);
            put(output, 7 + offset, 3, 36, "SOFT_AR;SOFT_AC;FP;CREDITS;MESSAGE", columns - 1);
            put(output, 8 + offset, 3, 90, "Use - for blank values; soft modes use on/off.", columns - 1);
            put(output, 10 + offset, 3, 93, "Record:", columns - 1);
            const std::size_t line_width = static_cast<std::size_t>(std::max(12, columns - 6));
            int line = 11 + offset;
            const int last_line = rows - 4;
            std::size_t input_offset = 0;
            while (line <= last_line && input_offset < input.size()) {
                const std::size_t count = std::min(line_width, input.size() - input_offset);
                put(output, line++, 4, 97, input.substr(input_offset, count), columns - 1);
                input_offset += count;
            }
            if (input.empty()) {
                put(output, line, 4, 97, "(enter the full record on one line)", columns - 1);
            } else if (input_offset < input.size() && line <= last_line) {
                put(output, line, 4, 90, "...", columns - 1);
            }
            put(output, rows - 2, 3, 93, "[Enter] Save record  [ESC] Cancel", columns - 1);
        } else {
            put(output, 8 + offset, 3, 97,
                std::string(edit_operation == 'E' ? "Edit" : "Delete") +
                    " validation key > " + std::string(input), columns - 1);
            put(output, rows - 2, 3, 93,
                edit_operation == 'E' ? "[Enter] Edit record  [ESC] Cancel" :
                    "[Enter] Delete record  [ESC] Cancel", columns - 1);
        }
        output += cursor(rows - 1, 2) + "\x1b[?25h";
        return output;
    }
    put(output, 4 + offset, 3, 36,
        "Key Description                    SL DSL Menu Days -> Key FP Credits Flags", columns - 1);
    const std::size_t first = page * page_size;
    const std::size_t end = std::min(levels.size(), first + page_size);
    int row = 5 + offset;
    for (std::size_t index = first; index < end; ++index, ++row) {
        const ValidationLevel& level = levels[index];
        const std::string line = std::string(1, level.key) + "   " + level.description + "  " +
            std::to_string(level.security_level) + "  " + std::to_string(level.download_security_level) + "  " +
            std::to_string(level.start_menu) + "   " + std::to_string(level.expiration_days) + "  " +
            (level.expire_to_key == ' ' ? "-" : std::string(1, level.expire_to_key)) + "   " +
            std::to_string(level.file_points) + "  " + std::to_string(level.credits) + "  " +
            (level.ar_flags.empty() ? "-" : level.ar_flags) + "/" +
            (level.ac_flags.empty() ? "-" : level.ac_flags);
        if (index == selected_index) {
            put_selected(output, row, 3, line, columns - 1);
        } else {
            put(output, row, 3, 37, line, columns - 1);
        }
    }
    if (levels.empty()) {
        put(output, 7 + offset, 4, 90, "No validation levels are configured.", columns - 1);
    }
    if (!notice.empty()) {
        put(output, rows - 6, 3, 90, notice, columns - 1);
    }
    put(output, rows - 4, 3, 36,
        "Page " + std::to_string(page + 1) + "/" + std::to_string(page_count) +
            "   Records: " + std::to_string(levels.size()), columns - 1);
    put(output, rows - 3, 3, 93, columns < 60
        ? "Arrows select Enter edit  [S]et [E]dit [D]el"
        : "Arrows select  [Enter] Edit selected  [S] Set  [E] Edit by key  [D] Delete  [N/P] Page", columns - 1);
    put(output, rows - 2, 3, 93, columns < 60
        ? "[R]efresh [Q] Back" : "[R] Refresh  [Q] Account control", columns - 1);
    output += cursor(rows - 1, 2) + "\x1b[?25h";
    return output;
}

std::string account_review_screen(
    const AccountSummary& account,
    bool editing_security_levels,
    bool editing_acs_flags,
    bool editing_credits,
    bool editing_file_points,
    bool editing_birth_date,
    bool editing_sex,
    bool editing_expiration_date,
    bool editing_validation_level,
    bool confirming_validation_level,
    bool editing_profile,
    char profile_field,
    bool editing_short_message,
    std::string_view security_level_input,
    int columns,
    int rows,
    std::string_view screen_art,
    std::size_t selected_action) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const std::string status = !account.approved ? "Pending approval" :
        (account.enabled ? "Enabled" : "Disabled");
    const auto supplied = [](std::string_view value) {
        return value.empty() ? std::string("(not provided)") : one_line(value);
    };
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 5, rows);
        centered(output, 5, 96, "RENEGADE SYSOP - APPLICATION REVIEW", columns);
        put(output, 6, 4, 36, std::string(static_cast<std::size_t>(columns - 8), '-'), columns - 6);
        const std::array<std::string, 11> left_fields{{
            "Handle: " + one_line(account.handle),
            "Status: " + status,
            "Access: " + std::string(account.is_sysop ? "SysOp" : "User"),
            "Applied: " + one_line(account.created_at),
            "Security level: " + std::to_string(account.security_level),
            "Download level: " + std::to_string(account.download_security_level),
            "Message credits: " + std::to_string(account.credits),
            "File points: " + std::to_string(account.file_points),
            std::string("Mailbox: ") + (account.mailbox_closed ? "Closed" : "Open"),
            "Validation: " + (account.subscription_key == '\0' ? std::string("-") : std::string(1, account.subscription_key)) +
                " -> " + (account.expire_to_key == '\0' ? std::string("-") : std::string(1, account.expire_to_key)),
            "Menu: " + std::to_string(account.start_menu) + "  AR/AC: " +
                (account.acs_ar_flags.empty() ? std::string("-") : account.acs_ar_flags) + "/" +
                (account.acs_ac_flags.empty() ? std::string("-") : account.acs_ac_flags),
        }};
        const std::array<std::string, 13> right_fields{{
            "Real name: " + supplied(account.real_name),
            "Country: " + supplied(account.country),
            "Street: " + supplied(account.street),
            "City/state: " + supplied(account.city_state.empty() ? account.location : account.city_state),
            "Postal code: " + supplied(account.postal_code),
            "Phone: " + supplied(account.phone),
            "Birth date: " + supplied(account.birth_date),
            "Gender: " + (account.sex == '\0' ? std::string("(not provided)") : std::string(1, account.sex)),
            "Expires: " + (account.expiration_date.empty() ? std::string("Never") : one_line(account.expiration_date)),
            "Signature: " + supplied(account.signature),
            "Answer 1: " + supplied(account.user_answers[0]),
            "Answer 2: " + supplied(account.user_answers[1]),
            "Answer 3: " + supplied(account.user_answers[2]),
        }};
        for (std::size_t index = 0; index < right_fields.size(); ++index) {
            const int row = 7 + static_cast<int>(index);
            if (index < left_fields.size()) {
                put(output, row, 4, 36, left_fields[index], 36);
            }
            put(output, row, 42, 97, right_fields[index], columns - 1);
        }
    } else {
        centered(output, 2, 96, "RENEGADE SYSOP - APPLICATION REVIEW", columns);
        put(output, 5, 4, 36, "Handle: " + account.handle, columns - 1);
        put(output, 6, 4, 36, "Status: " + status, columns - 1);
        put(output, 7, 4, 36, "Access: " + std::string(account.is_sysop ? "SysOp" : "User"), columns - 1);
        put(output, 8, 4, 36, "Applied: " + account.created_at, columns - 1);
        put(output, 9, 4, 36,
            "SL: " + std::to_string(account.security_level) +
                "   DSL: " + std::to_string(account.download_security_level) +
                "   Credits: " + std::to_string(account.credits) +
                "   File points: " + std::to_string(account.file_points), columns - 1);
        put(output, 10, 4, 36,
            std::string("Mailbox: ") + (account.mailbox_closed ? "Closed" : "Open") +
                "  Validation: " + (account.subscription_key == '\0' ? std::string("-") : std::string(1, account.subscription_key)) +
                " -> " + (account.expire_to_key == '\0' ? std::string("-") : std::string(1, account.expire_to_key)) +
                "  Menu: " + std::to_string(account.start_menu), columns - 1);
        put(output, 11, 4, 36,
            "ACS flags: AR=" + (account.acs_ar_flags.empty() ? std::string("-") : account.acs_ar_flags) +
                "  AC=" + (account.acs_ac_flags.empty() ? std::string("-") : account.acs_ac_flags), columns - 1);
        put(output, 12, 4, 36,
            "Birth date: " + (account.birth_date.empty() ? std::string("-") : account.birth_date) +
                "   Gender: " + (account.sex == '\0' ? std::string("-") : std::string(1, account.sex)) +
                "   Expires: " + (account.expiration_date.empty() ? std::string("Never") : account.expiration_date), columns - 1);
        put(output, 13, 4, 97, "Real name: " + supplied(account.real_name), columns - 1);
        put(output, 14, 4, 97, "Country: " + supplied(account.country) +
            "   Street: " + supplied(account.street), columns - 1);
        put(output, 15, 4, 97, "City / state: " + supplied(
            account.city_state.empty() ? account.location : account.city_state), columns - 1);
        put(output, 16, 4, 97, "Postal code: " + supplied(account.postal_code) +
            "   Phone: " + supplied(account.phone), columns - 1);
        put(output, 17, 4, 97, "Signature: " + supplied(account.signature), columns - 1);
        put(output, 18, 4, 97, "User answer 1: " + supplied(account.user_answers[0]), columns - 1);
        put(output, 19, 4, 97, "User answer 2: " + supplied(account.user_answers[1]), columns - 1);
        put(output, 20, 4, 97, "User answer 3: " + supplied(account.user_answers[2]), columns - 1);
    }
    if (editing_profile && profile_field != '\0') {
        std::string_view field_name = "profile field";
        bool secret = false;
        switch (profile_field) {
        case 'R': field_name = "real name"; break;
        case 'C': field_name = "country"; break;
        case 'A': field_name = "street address"; break;
        case 'L': field_name = "city and state"; break;
        case 'Z': field_name = "postal code"; break;
        case 'P': field_name = "phone number"; break;
        case 'D': field_name = "birth date YYYY-MM-DD"; break;
        case 'G': field_name = "gender M/F"; break;
        case 'S': field_name = "signature"; break;
        case '1': field_name = "SysOp answer 1"; break;
        case '2': field_name = "SysOp answer 2"; break;
        case '3': field_name = "SysOp answer 3"; break;
        case 'F': field_name = "recovery answer"; secret = true; break;
        case 'W': field_name = "new password (12-128 characters)"; secret = true; break;
        case 'w': field_name = "confirm new password"; secret = true; break;
        default: break;
        }
        const std::string displayed = secret
            ? std::string(security_level_input.size(), '*') : std::string(security_level_input);
        put(output, rows - 2, 4, 97,
            "Set " + std::string(field_name) + " > " + displayed, columns - 1);
    } else if (editing_profile) {
        put(output, rows - 3, 4, 93, columns < 60
            ? "[R]Name [C]Cntry [A]Addr [L]City [Z]ZIP [P]Phone"
            : "[R] Real name  [C] Country  [A] Street  [L] City/state  [Z] Postal  [P] Phone", columns - 1);
        put(output, rows - 2, 4, 93, columns < 60
            ? "[D]DOB [G]Sex [S]Sig [1-3]Ans [F]Rec [W]Pwd [Q]Done"
            : "[D] DOB [G] Gender [S] Signature [1-3] Answers [F] Recovery [W] Password [Q] Done", columns - 1);
    } else if (editing_short_message) {
        put(output, rows - 2, 4, 97,
            "Send one-line message (1-80 chars) > " + std::string(security_level_input), columns - 1);
    } else if (editing_security_levels) {
        put(output, rows - 2, 4, 97,
            "Set security levels as SL,DSL (0-255), e.g. 50,20 > " + std::string(security_level_input),
            columns - 1);
    } else if (editing_acs_flags) {
        put(output, rows - 2, 4, 97,
            "Set ACS flags as AR/AC; use - for none, e.g. AB/EP > " + std::string(security_level_input),
            columns - 1);
    } else if (editing_credits) {
        put(output, rows - 2, 4, 97,
            "Set account balance (-2147483648 to 2147483647) > " + std::string(security_level_input),
            columns - 1);
    } else if (editing_file_points) {
        put(output, rows - 2, 4, 97,
            "Set file-point balance (0 to 2147483647) > " + std::string(security_level_input),
            columns - 1);
    } else if (editing_birth_date) {
        put(output, rows - 2, 4, 97,
            "Set birth date YYYY-MM-DD, blank clears it > " + std::string(security_level_input),
            columns - 1);
    } else if (editing_sex) {
        put(output, rows - 2, 4, 97,
            "Set gender M/F, blank clears it > " + std::string(security_level_input),
            columns - 1);
    } else if (editing_expiration_date) {
        put(output, rows - 2, 4, 97,
            "Set expiry YYYY-MM-DD, blank clears it > " + std::string(security_level_input),
            columns - 1);
    } else if (confirming_validation_level) {
        put(output, rows - 2, 4, 97,
            "Apply this validation level? [Y/N]", columns - 1);
    } else if (editing_validation_level) {
        put(output, rows - 2, 4, 97,
            "Apply validation key (! to ~; Q reserved) > " + std::string(security_level_input),
            columns - 1);
    } else {
        static constexpr std::array<std::pair<char, std::string_view>, 12> actions{{
            {'V', "Validate"}, {'E', "Profile"}, {'I', "Message"},
            {'D', "Birth"}, {'G', "Gender"}, {'X', "Expiry"},
            {'S', "Levels"}, {'F', "ACS"}, {'C', "Credits"},
            {'P', "Points"}, {'M', "Mailbox"}, {'Q', "Back"},
        }};
        const int cell_width = std::max(1, (columns - 8) / 6);
        for (std::size_t index = 0; index < actions.size(); ++index) {
            const int row = rows - 3 + static_cast<int>(index / 6);
            const int column = 4 + static_cast<int>(index % 6) * cell_width;
            const std::string option = std::string(1, actions[index].first) + " " +
                std::string(actions[index].second);
            const int option_end = std::min(columns, column + cell_width - 1);
            if (index == selected_action) {
                put_selected(output, row, column, option, option_end);
            } else {
                put(output, row, column, 93, option, option_end);
            }
        }
        if (use_art) {
            put(output, rows - 4, 4, 96, "ARROWS MOVE    ENTER OPEN    LETTERS QUICK SELECT",
                columns - 5);
        }
    }
    output += cursor(rows - 1, 2) + "\x1b[?25h";
    return output;
}

std::string validation_preview_screen(
    const AccountSummary& account,
    const ValidationLevel& level,
    std::string_view new_ar_flags,
    std::string_view new_ac_flags,
    std::int64_t new_credits,
    std::int64_t new_file_points,
    int columns,
    int rows,
    std::string_view screen_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    const int offset = use_art ? 3 : 0;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 5, rows);
    }
    centered(output, 2 + offset, 96, "RENEGADE SYSOP - VALIDATION PREVIEW", columns);
    put(output, 5 + offset, 4, 36, "Account: " + account.handle, columns - 1);
    put(output, 6 + offset, 4, 36,
        "Level " + std::string(1, level.key) + ": " + level.description, columns - 1);
    put(output, 8 + offset, 4, 36,
        "SL: " + std::to_string(account.security_level) + " -> " + std::to_string(level.security_level) +
            "   DSL: " + std::to_string(account.download_security_level) + " -> " +
            std::to_string(level.download_security_level), columns - 1);
    put(output, 9 + offset, 4, 36,
        "AR: " + (account.acs_ar_flags.empty() ? std::string("-") : account.acs_ar_flags) + " -> " +
            (new_ar_flags.empty() ? std::string("-") : std::string(new_ar_flags)), columns - 1);
    put(output, 10 + offset, 4, 36,
        "AC: " + (account.acs_ac_flags.empty() ? std::string("-") : account.acs_ac_flags) + " -> " +
            (new_ac_flags.empty() ? std::string("-") : std::string(new_ac_flags)), columns - 1);
    put(output, 11 + offset, 4, 36,
        "Credits: " + std::to_string(account.credits) + " -> " + std::to_string(new_credits) +
            "   FP: " + std::to_string(account.file_points) + " -> " + std::to_string(new_file_points), columns - 1);
    put(output, 12 + offset, 4, 36,
        "Menu: " + std::to_string(account.start_menu) + " -> " + std::to_string(level.start_menu), columns - 1);
    put(output, 13 + offset, 4, 36,
        "Expiry: " + (account.expiration_date.empty() ? std::string("Never") : account.expiration_date) +
            " -> " + (level.expiration_days == 0 ? std::string("Never") :
                std::to_string(level.expiration_days) + " days, then " + std::string(1, level.expire_to_key)),
        columns - 1);
    put(output, 15 + offset, 4, 90,
        level.user_message.empty() ? "No validation message is configured." :
            "Validation message will be queued for the account.", columns - 1);
    put(output, rows - 3, 4, 93, "[Y] Apply  [N] Cancel", columns - 1);
    output += cursor(rows - 1, 2) + "\x1b[?25h";
    return output;
}

std::string sysop_audit_screen(
    const SysopAuditPage& page,
    int columns,
    int rows,
    std::string_view screen_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    const int offset = use_art ? 3 : 0;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 5, rows);
    }
    centered(output, 2 + offset, 96, "RENEGADE SYSOP - AUDIT HISTORY", columns);
    put(output, 4 + offset, 3, 36,
        "Recent actions: " + std::to_string(page.total) + " retained", columns - 1);
    for (std::size_t index = 0; index < page.entries.size(); ++index) {
        const SysopAuditEntry& entry = page.entries[index];
        const std::string line = entry.created_at + "  " + entry.actor + "  " + entry.action +
            (entry.subject.empty() ? std::string{} : "  " + entry.subject);
        put(output, 6 + offset + static_cast<int>(index), 3, 37, line, columns - 1);
    }
    if (page.entries.empty()) {
        put(output, 8 + offset, 4, 90, "No SysOp actions have been recorded yet.", columns - 1);
    }
    put(output, rows - 4, 3, 36,
        "Page " + std::to_string(page.page + 1) + "/" + std::to_string(page.page_count), columns - 1);
    put(output, rows - 3, 3, 93,
        "Arrows page  [N] Newer  [P] Older  [R] Refresh  [Q] Account control", columns - 1);
    output += cursor(rows - 1, 2) + "\x1b[?25h";
    return output;
}

std::string sysop_area_admin_screen(
    const std::vector<BoardArea>& message_areas,
    const std::vector<FileAreaSummary>& file_areas,
    bool entering_name,
    bool is_file_area,
    bool renaming_file_area,
    bool renaming_message_area,
    bool deleting_file_area,
    bool editing_file_area_access,
    bool editing_message_area_access,
    bool editing_message_force_read,
    bool editing_message_area_password,
    bool editing_message_taglines,
    bool editing_message_filter,
    bool editing_message_unhidden,
    bool editing_message_tearline,
    bool editing_message_origin,
    bool editing_message_real_names,
    bool editing_message_quote_templates,
    bool editing_private_quote_templates,
    bool editing_global_anonymous_acs,
    bool editing_global_post_acs,
    bool editing_global_post_limits,
    bool editing_global_credit_costs,
    bool editing_global_mail_limits,
    std::string_view file_policy_prompt,
    bool confirming_file_area_deletion,
    bool deleting_message_area,
    bool confirming_message_area_deletion,
    long long deletion_area_id,
    std::string_view deletion_area_name,
    std::string_view input,
    std::string_view notice,
    int columns,
    int rows,
    std::string_view screen_art,
    std::size_t selected_action) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    const int offset = use_art ? 3 : 0;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 5, rows);
    }
    centered(output, 2 + offset, 96, "RENEGADE SYSOP - AREA SETUP", columns);
    put(output, 4 + offset, 3, 36, "MESSAGE AREAS", columns);
    put(output, 4 + offset, columns / 2 + 1, 36, "FILE AREAS", columns);
    const int visible_rows = std::max(1, std::min(7, rows - 13));
    for (int row = 0; row < visible_rows; ++row) {
        const std::size_t index = static_cast<std::size_t>(row);
        if (index < message_areas.size()) {
            const BoardArea& area = message_areas[index];
            put(output, 6 + offset + row, 3, 37,
            std::to_string(area.id) + " " + area.name + " A:" +
                (area.access_acs.empty() ? "*" : area.access_acs) + " P:" +
                (area.post_acs.empty() ? "*" : area.post_acs) + " M:" +
                (area.mci_acs.empty() ? "*" : area.mci_acs) + " S:" +
                (area.sysop_acs.empty() ? "*" : area.sysop_acs) + " AN:" +
                anonymous_mode_code(area.anonymous_mode) + " FR:" + (area.force_read ? "Y" : "N") +
                (area.password_protected ? " PW:LOCK" : "") +
                " TG:" + (area.add_tagline ? "Y" : "N") +
                " FL:" + (area.filter_public_text ? "Y" : "N") +
                " UH:" + (area.unhidden ? "Y" : "N") +
                " TL:" + (area.add_tearline ? "Y" : "N"), columns / 2 - 2);
        }
        if (index < file_areas.size()) {
            const FileAreaSummary& area = file_areas[index];
            const std::string access = area.access_acs.empty() ? "*" : area.access_acs;
            const std::string download = area.download_acs.empty() ? "*" : area.download_acs;
            const std::string upload = area.upload_acs.empty() ? "*" : area.upload_acs;
            put(output, 6 + offset + row, columns / 2 + 1, 37,
                std::to_string(area.id) + " " + area.name + " A:" + access + " D:" + download +
                    " U:" + upload,
                columns - 1);
        }
    }
    put(output, rows - 7, 3, 93, notice, columns - 4);
    if (confirming_file_area_deletion) {
        put(output, rows - 5, 3, 91,
            "Delete " + std::to_string(deletion_area_id) + "  " + std::string(deletion_area_name) + "?",
            columns - 4);
        put(output, rows - 4, 3, 91, "[R] Remove listing, keep files", columns - 4);
        put(output, rows - 3, 3, 91, "[D] Remove listing and files  [N] Cancel", columns - 4);
        output += cursor(rows - 1, 2) + "\x1b[?25h";
    } else if (confirming_message_area_deletion) {
        put(output, rows - 5, 3, 91,
            "Delete message area " + std::to_string(deletion_area_id) + "  " +
                std::string(deletion_area_name) + " and all posts?",
            columns - 4);
        put(output, rows - 4, 3, 91, "[Y] Delete area and posts", columns - 4);
        put(output, rows - 3, 3, 91, "[N] Cancel", columns - 4);
        output += cursor(rows - 1, 2) + "\x1b[?25h";
    } else if (entering_name) {
        const std::string prompt = editing_file_area_access
            ? "File ACS (ID;access;download[;upload]) > " + std::string(input)
            : editing_global_anonymous_acs
                ? "Global anon ACS (pub post;pub read;priv post;priv read) > " + std::string(input)
            : editing_global_post_acs
                ? "Global post ACS (pub post;priv post) > " + std::string(input)
            : editing_global_post_limits
                ? "Post limits per call (public;private, 0-255) > " + std::string(input)
            : editing_global_mail_limits
                ? "Mail waiting limits (normal;SysOp, 0-255) > " + std::string(input)
            : editing_global_credit_costs
                ? "Credit costs (public;private, -32767 to 32767) > " + std::string(input)
            : editing_message_area_access
                ? "Message ACS (ID;access;post;MCI;SysOp[;anon N/Y/F/D/A]) > " + std::string(input)
            : editing_message_force_read
                ? "Forced scan (AREA_ID;on|off) > " + std::string(input)
            : editing_message_area_password
                ? "Area password (AREA_ID;new password or - to clear) > " + std::string(input)
            : editing_message_taglines
                ? "Message taglines (AREA_ID;on|off) > " + std::string(input)
            : editing_message_tearline
                ? "Message tearline (AREA_ID;on|off) > " + std::string(input)
            : editing_message_origin
                ? "Origin (ID;TEXT;ZONE:NET/NODE.POINT, - clears) > " + std::string(input)
            : editing_message_filter
                ? "Public-text filter (AREA_ID;on|off) > " + std::string(input)
            : editing_message_unhidden
                ? "Area visibility (AREA_ID;on|off) > " + std::string(input)
            : editing_message_real_names
                ? "Search real names (AREA_ID;on|off) > " + std::string(input)
            : editing_message_quote_templates
                ? "Quote template (ID;S|E;TEXT) > " + std::string(input)
            : editing_private_quote_templates
                ? "Email quote (S|E;TEXT) > " + std::string(input)
            : !file_policy_prompt.empty()
                ? std::string(file_policy_prompt) + std::string(input)
            : renaming_file_area
            ? "Rename file area (ID=New name) > " + std::string(input)
            : renaming_message_area
                ? "Rename message area (ID=New name) > " + std::string(input)
                : deleting_file_area
                    ? "Delete file area ID > " + std::string(input)
                    : deleting_message_area
                        ? "Delete message area ID > " + std::string(input)
                        : std::string(is_file_area ? "New file area" : "New message area") +
                            " name > " + std::string(input);
        put(output, rows - 2, 3, 97, prompt, columns - 4);
        output += cursor(rows - 1, std::min(columns - 1, 3 + static_cast<int>(prompt.size()))) + "\x1b[?25h";
    } else {
        static constexpr std::array<std::pair<char, std::string_view>, 35> actions{{
            {'M', "New msg"}, {'F', "New file"}, {'E', "File name"},
            {'N', "Msg name"}, {'H', "Force scan"}, {'I', "Real names"},
            {'O', "Area pass"}, {'B', "Msg ACS"}, {'A', "Anonymous"},
            {'G', "Post ACS"}, {'L', "Post caps"}, {'W', "Mail caps"},
            {'K', "Credits"}, {'R', "Ratios"}, {'J', "Quote tpl"},
            {'Y', "Taglines"}, {'T', "Text filter"}, {'U', "Visibility"},
            {'V', "Tearline"}, {'Z', "Origin"}, {'1', "SL ratios"},
            {'2', "Day caps"}, {'3', "Points"}, {'4', "UL verify"},
            {'5', "Unval ACS"}, {'6', "Exempt"}, {'7', "Post ratio"},
            {'8', "Submit ACS"}, {'9', "Invis ACS"}, {'0', "Validate"},
            {'C', "File ACS"}, {'X', "Del msgs"}, {'D', "Del files"},
            {'P', "Email quote"}, {'Q', "Return"},
        }};
        const int cell_width = std::max(1, (columns - 8) / 7);
        put(output, rows - 8, 3, 96,
            "ARROWS MOVE    ENTER RUN    LETTERS AND NUMBERS ALSO WORK", columns - 4);
        put(output, rows - 7, 3, 93, notice, columns - 4);
        for (std::size_t index = 0; index < actions.size(); ++index) {
            const int row = rows - 6 + static_cast<int>(index / 7);
            const int column = 4 + static_cast<int>(index % 7) * cell_width;
            const std::string option = std::string(1, actions[index].first) + " " +
                std::string(actions[index].second);
            const int option_end = std::min(columns, column + cell_width - 1);
            if (index == selected_action) {
                put_selected(output, row, column, option, option_end);
            } else {
                put(output, row, column, 93, option, option_end);
            }
        }
        output += cursor(rows - 1, 2) + "\x1b[?25h";
    }
    return output;
}

std::string profile_screen(
    const AccountProfile& profile,
    bool contact_page,
    int columns,
    int rows,
    std::string_view screen_art,
    std::size_t selected_action) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    const auto put_option = [&](std::string& output, int row, int column, int end_column,
                                std::size_t index, std::string_view label) {
        if (index == selected_action) {
            put_selected(output, row, column, label, end_column);
        } else {
            put(output, row, column, 97, label, end_column);
        }
    };
    if (use_art) {
        std::string output = "\x1b[2J\x1b[H\x1b[?25l";
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 8, rows);
        centered(output, 8, 96,
            contact_page ? "RENEGADE USER CONTACT DETAILS" : "RENEGADE USER PROFILE", columns);
        put(output, 9, 4, 36, "Handle: " + one_line(profile.handle), columns - 6);
        if (contact_page) {
            put_option(output, 11, 4, 36, 0, "[C] Country: " +
                (profile.country.empty() ? "(not set)" : one_line(profile.country)));
            put_option(output, 12, 4, 36, 1, "[A] Street: " +
                (profile.street.empty() ? "(not set)" : one_line(profile.street)));
            put_option(output, 13, 4, 36, 2, "[L] City / state: " +
                one_line(profile.city_state.empty() ? profile.location : profile.city_state));
            put_option(output, 14, 4, 36, 3, "[Z] Postal: " +
                (profile.postal_code.empty() ? "(not set)" : one_line(profile.postal_code)));
            put_option(output, 15, 4, 36, 4, "[P] Phone: " +
                (profile.phone.empty() ? "(not set)" : one_line(profile.phone)));
            put_option(output, 11, 42, columns - 1, 5, "[1] SysOp answer: " +
                (profile.user_answers[0].empty() ? "(not set)" : one_line(profile.user_answers[0])));
            put_option(output, 12, 42, columns - 1, 6, "[2] SysOp answer: " +
                (profile.user_answers[1].empty() ? "(not set)" : one_line(profile.user_answers[1])));
            put_option(output, 13, 42, columns - 1, 7, "[3] SysOp answer: " +
                (profile.user_answers[2].empty() ? "(not set)" : one_line(profile.user_answers[2])));
            put_option(output, 14, 42, columns - 1, 8, std::string("[R] Recovery answer: ") +
                (profile.forgot_password_answer_set ? "configured (hashed)" : "(not set)"));
            put(output, 20, 4, 93, "ARROWS SELECT   ENTER OPENS   HOTKEYS ALSO WORK", columns - 2);
            put(output, 21, 4, 93, profile.hotkeys
                ? "A/C/L/Z/P edit contact  1-3 answers  R recovery answer"
                : "Enter one command. /cancel keeps the current answer.", columns - 2);
            put_option(output, 22, 4, columns / 2 - 2, 9, "[M] Main profile");
            put_option(output, 22, columns / 2 + 1, columns - 1, 10, "[Q] Return to main menu");
        } else {
            put_option(output, 11, 4, 36, 0, "[R] Real name: " +
                (profile.real_name.empty() ? "(not set)" : one_line(profile.real_name)));
            put_option(output, 12, 4, 36, 1, "[L] Location: " +
                (profile.location.empty() ? "(not set)" : one_line(profile.location)));
            put_option(output, 13, 4, 36, 2, "[S] Signature: " +
                (profile.signature.empty() ? "(not set)" : one_line(profile.signature)));
            put(output, 14, 4, 36, "Credits: " + std::to_string(profile.credits), 36);
            put_option(output, 15, 4, 36, 3, "[B] Birth date: " +
                (profile.birth_date.empty() ? "(not set)" : one_line(profile.birth_date)));
            put_option(output, 16, 4, 36, 4, "[G] Gender: " +
                (profile.sex == '\0' ? std::string("(not set)") : std::string(1, profile.sex)));
            put(output, 17, 4, 36, "Expires: " +
                (profile.expiration_date.empty() ? std::string("Never") : one_line(profile.expiration_date)), 36);
            put(output, 18, 4, 36, "File points: " + std::to_string(profile.file_points), 36);
            put_option(output, 11, 42, columns - 1, 5, std::string("[C] ANSI color: ") +
                (profile.ansi_color ? "on" : "off"));
            put_option(output, 12, 42, columns - 1, 6, std::string("[X] Clear screen: ") +
                (profile.clear_screen ? "on" : "off"));
            put_option(output, 13, 42, columns - 1, 7, std::string("[P] Pause pages: ") +
                (profile.pause_screens ? "on" : "off"));
            put_option(output, 14, 42, columns - 1, 8, std::string("[H] Command hotkeys: ") +
                (profile.hotkeys ? "on" : "off"));
            put_option(output, 15, 42, columns - 1, 9, std::string("[E] Expert mode: ") +
                (profile.expert_mode ? "on" : "off"));
            put_option(output, 16, 42, columns - 1, 10, std::string("[M] Mailbox: ") +
                (profile.mailbox_closed ? "closed to private mail" : "open to private mail"));
            put(output, 20, 4, 93, "ARROWS SELECT   ENTER OPENS   HOTKEYS ALSO WORK", columns - 2);
            put_option(output, 21, 4, columns - 2, 11,
                "[W] Change password (current password required)");
            put_option(output, 22, 4, columns / 2 - 2, 12, "[N] Contact details");
            put_option(output, 22, columns / 2 + 1, columns - 1, 13, "[Q] Return to main menu");
        }
        output += cursor(rows - 1, 2) + "\x1b[?25h";
        return output;
    }
    std::string output = frame(columns, rows);
    centered(output, 2, 96, contact_page ? "RENEGADE USER CONTACT DETAILS" : "RENEGADE USER PROFILE", columns);
    put(output, 5, 4, 36, "Handle:      " + profile.handle, columns - 1);
    if (contact_page) {
        put_option(output, 7, 4, columns - 1, 0, "[C] Country: " + (profile.country.empty() ? "(not set)" : profile.country));
        put_option(output, 8, 4, columns - 1, 1, "[A] Street address: " + (profile.street.empty() ? "(not set)" : profile.street));
        put_option(output, 9, 4, columns - 1, 2, "[L] City / state: " + (profile.city_state.empty() ? profile.location : profile.city_state));
        put_option(output, 10, 4, columns - 1, 3, "[Z] Postal code: " + (profile.postal_code.empty() ? "(not set)" : profile.postal_code));
        put_option(output, 11, 4, columns - 1, 4, "[P] Phone: " + (profile.phone.empty() ? "(not set)" : profile.phone));
        put_option(output, 12, 4, columns - 1, 5, "[1] SysOp answer 1: " + (profile.user_answers[0].empty() ? "(not set)" : profile.user_answers[0]));
        put_option(output, 13, 4, columns - 1, 6, "[2] SysOp answer 2: " + (profile.user_answers[1].empty() ? "(not set)" : profile.user_answers[1]));
        put_option(output, 14, 4, columns - 1, 7, "[3] SysOp answer 3: " + (profile.user_answers[2].empty() ? "(not set)" : profile.user_answers[2]));
        put_option(output, 15, 4, columns - 1, 8, std::string("[R] Recovery answer: ") +
            (profile.forgot_password_answer_set ? "configured (stored as a hash)" : "(not set)"));
        put(output, rows - 3, 4, 93, profile.hotkeys
            ? "A/C/L/Z/P edit contact  1-3 answers  R recovery answer"
            : "Enter one command. /cancel keeps the current answer.", columns - 1);
        put(output, 6, 4, 93, "ARROWS SELECT   ENTER OPENS   HOTKEYS ALSO WORK", columns - 1);
        put_option(output, rows - 2, 4, columns / 2 - 2, 9, "[M] Main");
        put_option(output, rows - 2, columns / 2 + 1, columns - 1, 10, "[Q] Menu");
    } else {
        put_option(output, 7, 4, columns - 1, 0, "[R] Real name: " + (profile.real_name.empty() ? "(not set)" : profile.real_name));
        put_option(output, 8, 4, columns - 1, 1, "[L] Location:  " + (profile.location.empty() ? "(not set)" : profile.location));
        put_option(output, 9, 4, columns - 1, 2, "[S] Signature: " + (profile.signature.empty() ? "(not set)" : profile.signature));
        put(output, 10, 4, 36, "Message credit balance: " + std::to_string(profile.credits), columns - 1);
        put_option(output, 11, 4, columns - 1, 3, "[B] Birth date: " +
            (profile.birth_date.empty() ? "(not set)" : profile.birth_date));
        put_option(output, 12, 4, columns - 1, 4, "[G] Gender: " +
            (profile.sex == '\0' ? std::string("(not set)") : std::string(1, profile.sex)));
        put(output, 13, 4, 36, "Account expiration: " +
            (profile.expiration_date.empty() ? std::string("Never") : profile.expiration_date), columns - 1);
        put(output, 14, 4, 36, "File point balance: " + std::to_string(profile.file_points), columns - 1);
        put_option(output, 15, 4, columns - 1, 5, std::string("[C] ANSI color: ") + (profile.ansi_color ? "on" : "off"));
        put_option(output, 16, 4, columns - 1, 6, std::string("[X] Clear screen: ") + (profile.clear_screen ? "on" : "off"));
        put_option(output, 17, 4, columns - 1, 7, std::string("[P] Pause pages: ") + (profile.pause_screens ? "on" : "off"));
        put_option(output, 18, 4, columns - 1, 8, std::string("[H] Command hotkeys: ") + (profile.hotkeys ? "on" : "off"));
        put_option(output, 19, 4, columns - 1, 9, std::string("[E] Expert mode: ") + (profile.expert_mode ? "on" : "off"));
        if (rows == 23) {
            put_option(output, 20, columns / 2 + 1, columns - 1, 10,
                std::string("[M] Mail: ") + (profile.mailbox_closed ? "closed" : "open"));
            put_option(output, 20, 4, columns / 2 - 2, 11, "[W] Password");
            put_option(output, 21, 4, columns / 2 - 2, 12, "[N] Contacts");
            put_option(output, 21, columns / 2 + 1, columns - 1, 13, "[Q] Main menu");
        } else {
            put_option(output, 20, 4, columns - 1, 10, std::string("[M] Mailbox: ") +
                (profile.mailbox_closed ? "closed to private mail" : "open to private mail"));
            put_option(output, rows - 3, 4, columns - 1, 11,
                "[W] Change password (current password required)");
            put_option(output, rows - 2, 4, columns / 2 - 2, 12, "[N] Contacts");
            put_option(output, rows - 2, columns / 2 + 1, columns - 1, 13, "[Q] Menu");
        }
        put(output, 6, 4, 93, "ARROWS SELECT   ENTER OPENS   HOTKEYS ALSO WORK", columns - 1);
    }
    output += cursor(rows - 1, 2) + "\x1b[?25h";
    return output;
}

std::string time_bank_screen(
    const TimeBankStatus& status,
    std::optional<int> remaining_minutes,
    int bank_limit,
    int deposit_daily_limit,
    int withdrawal_daily_limit,
    bool entering_amount,
    bool depositing,
    std::string_view input,
    int columns,
    int rows,
    std::string_view screen_art,
    std::size_t selected_action) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const auto limit_text = [](int limit) {
        return limit == 0 ? std::string("No limit") : std::to_string(limit) + " minutes";
    };
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 8, rows);
    }
    centered(output, use_art ? 8 : 2, 96, "RENEGADE TIME BANK", columns);
    put(output, use_art ? 10 : 5, 4, 97,
        "Time in bank: " + std::to_string(status.minutes) + " minutes", columns - 1);
    put(output, use_art ? 11 : 6, 4, 97, "Time remaining this call: " +
        (remaining_minutes.has_value() ? std::to_string(*remaining_minutes) + " minutes" : "unlimited"), columns - 1);
    put(output, use_art ? 13 : 8, 4, 36, "Account bank limit: " + limit_text(bank_limit), columns - 1);
    put(output, use_art ? 14 : 9, 4, 36, "Deposited today: " + std::to_string(status.deposited_today) +
        " / " + limit_text(deposit_daily_limit), columns - 1);
    put(output, use_art ? 15 : 10, 4, 36, "Withdrawn today: " + std::to_string(status.withdrawn_today) +
        " / " + limit_text(withdrawal_daily_limit), columns - 1);
    const std::array<std::string_view, 3> options{
        "[D] Deposit minutes from this call",
        "[W] Withdraw minutes into this call",
        "[Q] Return to the main menu",
    };
    for (std::size_t index = 0; index < options.size(); ++index) {
        const int row = (use_art ? 17 : 13) + static_cast<int>(index);
        if (selected_action == index) {
            put_selected(output, row, 4, options[index], columns - 1);
        } else {
            put(output, row, 4, 97, options[index], columns - 1);
        }
    }
    if (entering_amount) {
        const std::string prompt = std::string(depositing ? "Deposit" : "Withdraw") +
            " minutes (1-32767) > " + std::string(input);
        put(output, rows - 2, 4, 93, prompt, columns - 1);
        output += cursor(rows - 1, 2 + static_cast<int>(prompt.size())) + "\x1b[?25h";
    } else {
        if (!remaining_minutes.has_value()) {
            put(output, rows - 4, 4, 90,
                "Set --session-time-limit to enable time bank transfers.", columns - 1);
        }
        put(output, rows - 2, 4, 93, "Use arrows and Enter, or choose D, W, or Q.", columns - 1);
        output += cursor(rows - 1, 2) + "\x1b[?25h";
    }
    return output;
}

std::string nodes_screen(
    const std::vector<NodeInfo>& nodes,
    int node_number,
    int columns,
    int rows,
    bool may_toggle_invisible,
    bool invisible,
    bool may_toggle_availability,
    bool sysop_available,
    std::string_view nodes_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    if (!nodes_art.empty() && columns >= 80 && rows >= 24) {
        std::string output = "\x1b[2J\x1b[H\x1b[?25l";
        output.append(nodes_art);
        output += "\x1b[0m";
        clear_art_rows(output, 5, rows - 2);
        put(output, 6, 4, 96, "RENEGADE NODE ACTIVITY", columns - 2);
        put(output, 8, 4, 97, "NODE     HANDLE                         STATUS", columns - 2);
        put(output, 9, 4, 36, "----     ------------------------------ -----------", columns - 2);
        int row = 10;
        for (const NodeInfo& node : nodes) {
            if (row >= rows - 5) {
                break;
            }
            const std::string state = node.invisible ? "Invisible" : (node.in_chat ? "In chat" : "On-line");
            put(output, row++, 4, node.number == node_number ? 93 : 37,
                "  " + std::to_string(node.number) + "      " + node.handle + "  " + state,
                columns - 2);
        }
        if (row < rows - 4 && static_cast<std::size_t>(row - 10) < nodes.size()) {
            put(output, row, 4, 90,
                "+ " + std::to_string(nodes.size() - static_cast<std::size_t>(row - 10)) +
                    " more active nodes", columns - 2);
        }
        std::string prompt;
        if (may_toggle_invisible) {
            prompt += std::string("I invisible ") + (invisible ? "on" : "off") + "; ";
        }
        if (may_toggle_availability) {
            prompt += std::string("A SysOp available ") + (sysop_available ? "on" : "off") + "; ";
        }
        prompt += "any key returns.";
        put(output, rows - 4, 4, 97, prompt, columns - 2);
        put(output, rows - 3, 4, 90, "Node " + std::to_string(node_number) +
            "  Secure SSH terminal", columns - 2);
        output += cursor(rows, 1) + "\x1b[?25h";
        return output;
    }

    std::string output = frame(columns, rows);
    centered(output, 3, 96, "NODE ACTIVITY", columns);
    put(output, 5, 5, 97, "NODE   STATUS       HANDLE", columns);
    put(output, 6, 5, 36, "----   -----------  ------------------------------", columns);

    int row = 8;
    for (const NodeInfo& node : nodes) {
        if (row >= rows - 4) {
            break;
        }
        const std::string state = node.invisible ? "Invisible" : (node.in_chat ? "In chat" : "On-line");
        const int color = node.number == node_number ? 93 : 37;
        put(output, row++, 5, color,
            "  " + std::to_string(node.number) + "    " + state + "       " + node.handle,
            columns - 4);
    }

    std::string prompt;
    if (may_toggle_invisible) {
        prompt += std::string("I toggles invisible mode (") + (invisible ? "on" : "off") + "). ";
    }
    if (may_toggle_availability) {
        prompt += std::string("A toggles SysOp availability (") + (sysop_available ? "on" : "off") + "). ";
    }
    prompt += "Press any other key to return.";
    put(output, rows - 2, 5, 97, prompt, columns);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string help_screen(int columns, int rows, std::string_view help_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    if (!help_art.empty() && columns >= 80 && rows >= 24) {
        std::string output = "\x1b[2J\x1b[H\x1b[?25l";
        output.append(help_art);
        output += "\x1b[0m";
        clear_art_rows(output, 8, 18);
        put(output, 8, 4, 96, "RENEGADE COMMAND GUIDE", columns - 2);
        put(output, 10, 4, 97, "N Nodes  C Chat  H Help  Q Log off", columns - 2);
        put(output, 11, 4, 97, "D BBS Directory  L Callers  T Statistics  G Auto-message", columns - 2);
        put(output, 12, 4, 97, "A ANSI Gallery  O One-liners  B Bulletins  R Quotes", columns - 2);
        put(output, 13, 4, 97, "M Message boards  F File areas  K Time bank  V Voting", columns - 2);
        put(output, 14, 4, 97, "P Private mail  U Profile  S SysOp  A Areas (SysOp)", columns - 2);
        put(output, 15, 4, 93, "Boards: S scan  N/P pages  W write  R read  X search", columns - 2);
        put(output, 16, 4, 93, "Reader: N/P pages  R reply  O parent  B back", columns - 2);
        put(output, 17, 4, 90, "SysOp: I uploads  J quote review; more controls are under S.", columns - 2);
        put(output, 18, 4, 90, "Main menu and message/file lists: ARROWS move, ENTER opens the selection.", columns - 2);
        put(output, rows - 2, 4, 90, "Press any key to return.", columns - 2);
        output += cursor(rows - 1, 1) + "\x1b[?25h";
        return output;
    }

    std::string output = frame(columns, rows);
    centered(output, 3, 96, "RENEGADE BBS - QUICK HELP", columns);
    put(output, 7, 5, 97, "D  Browse, add, edit, or remove BBS directory listings", columns);
    put(output, 8, 5, 97, "N  Show active nodes", columns);
    put(output, 9, 5, 97, "C  Enter multi-node chat", columns);
    put(output, 10, 5, 97, "A  Browse ANSI / ASCII artwork", columns);
    put(output, 11, 5, 97, "O  View and post one-liners", columns);
    put(output, 12, 5, 97, "B  Read ANSI/ASCII bulletins", columns);
    put(output, 13, 5, 97, "V  Browse and vote on poll topics", columns);
    put(output, 14, 5, 97, "G  Read/update the current auto-message", columns);
    put(output, 15, 5, 97, "T  View community statistics", columns);
    put(output, 16, 5, 97, "R  Read a random quote", columns);
    put(output, 17, 5, 97, "H  Show this help", columns);
    put(output, 18, 5, 97, columns < 60 ? "Q Log off U Profile" : "Q Log off U Edit profile P Private mail", columns);
    put(output, 19, 5, 97, columns < 60
        ? "M Boards F Files L Callers"
        : "M Boards F Files L Callers S SysOp (A Areas) I Uploads J Quotes", columns);
    put(output, 20, 5, 97, columns < 60
        ? "Board S scan N/P W write R read; Reader O parent B back"
        : "Board: S scan, N/P pages, W write, R read; Reader: O parent, B back",
        columns);
    put(output, 21, 5, 93,
        "Browse lists: arrows move, Enter opens; letter and number shortcuts still work.", columns);
    put(output, rows - 2, 5, 90, "Art/quotes: N next, P previous, R random quote, Q return.", columns);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string file_areas_screen(
    const std::vector<FileAreaSummary>& areas,
    std::size_t page,
    bool choosing_scan_area,
    bool sysop,
    int columns,
    int rows,
    std::string_view file_areas_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !file_areas_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(file_areas_art);
        output += "\x1b[0m";
        // File-directory ANSI panels include static command text below their
        // title. Replace it with the live area list and current key bindings.
        clear_art_rows(output, 7, rows);
    }
    centered(output, use_art ? 7 : 3, 96, "RENEGADE FILE AREAS", columns);
    const std::size_t page_count = std::max<std::size_t>(1, (areas.size() + 9) / 10);
    page = std::min(page, page_count - 1);
    put(output, use_art ? 8 : 5, 4, 90, choosing_scan_area
        ? "Choose an area number to toggle its new-file scan preference; ESC cancels."
        : "Select an area by number. File transfers use the SSH SFTP subsystem.", columns - 2);
    for (std::size_t row = 0; row < 10 && page * 10 + row < areas.size(); ++row) {
        const FileAreaSummary& area = areas[page * 10 + row];
        const std::string line = std::to_string((row + 1) % 10) + "  [NEW " +
            (area.new_scan_enabled ? "ON" : "OFF") + "]  " + area.name +
            (area.no_ratio ? "  [NO RATIO]" : "") +
            "  [" + std::to_string(area.file_count) + " files, " +
            std::to_string(area.total_bytes) + " bytes]";
        if (page * 10 + row == selected_index) {
            put_selected(output, (use_art ? 9 : 7) + static_cast<int>(row), 5, line, columns - 6);
        } else {
            put(output, (use_art ? 9 : 7) + static_cast<int>(row), 5, 97, line, columns - 6);
        }
    }
    if (areas.empty()) {
        put(output, use_art ? 10 : 9, 5, 93, "No file areas are configured.", columns - 6);
    }
    put(output, rows - 5, 4, 96, "SFTP paths: /files/<area-id>/<filename> and /incoming/<filename>", columns - 2);
    put(output, rows - 4, 4, 97, "SFTP login: sftp -P <port> <handle>@<host>", columns - 2);
    put(output, rows - 3, 4, 97, choosing_scan_area
        ? "ARROWS move  ENTER toggle  1-0 toggle  F all  U none  ESC cancel  N/P pages"
        : (sysop
            ? "ARROWS move  ENTER open  1-0 open  T flags  D date  S new files  V pending  N/P pages  Q menu"
            : "ARROWS move  ENTER open  1-0 open  T flags  D date  S new scan  N/P pages  Q menu"), columns - 2);
    put(output, rows - 2, 4, 90, "Area page " + std::to_string(page + 1) + "/" + std::to_string(page_count), columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string file_validation_screen(
    const FileValidationPage& page,
    bool confirm_bulk_validation,
    int columns,
    int rows,
    std::string_view file_areas_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !file_areas_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(file_areas_art);
        output += "\x1b[0m";
        clear_art_rows(output, 7, rows);
    }
    centered(output, use_art ? 7 : 3, 96, "UNVALIDATED FILES - SYSOP REVIEW", columns);
    put(output, use_art ? 8 : 5, 4, 90,
        std::to_string(page.total) + " files awaiting validation", columns - 2);
    for (std::size_t row = 0; row < page.files.size() && row < 10; ++row) {
        const NewFileEntry& entry = page.files[row];
        const std::string uploader = entry.file.owner_handle.empty()
            ? "unknown uploader" : "by " + one_line(entry.file.owner_handle);
        const std::string line = std::to_string((row + 1) % 10) + "  [" +
            one_line(entry.area_name) + "]  " + one_line(entry.file.name) + "  " + uploader +
            "  " + one_line(entry.file.modified_at);
        if (row == selected_index) {
            put_selected(output, (use_art ? 9 : 7) + static_cast<int>(row), 5, line, columns - 6);
        } else {
            put(output, (use_art ? 9 : 7) + static_cast<int>(row), 5, 97, line, columns - 6);
        }
    }
    if (page.files.empty()) {
        put(output, use_art ? 9 : 9, 5, 93, "No files are waiting for validation.", columns - 6);
    }
    put(output, rows - 4, 4, 97, confirm_bulk_validation
        ? "Validate all " + std::to_string(page.total) + " pending files?  Y confirm  N cancel"
        : "Arrows move  Enter details  1-0 details  A validate all  N/P pages  R refresh  Q areas", columns - 2);
    put(output, rows - 3, 4, 90, "Page " + std::to_string(page.page + 1) + "/" +
        std::to_string(page.page_count), columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string new_file_scan_screen(
    const NewFilePage& page,
    std::string_view since,
    int columns,
    int rows,
    std::string_view file_areas_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !file_areas_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(file_areas_art);
        output += "\x1b[0m";
        clear_art_rows(output, 7, rows);
    }
    centered(output, use_art ? 7 : 3, 96, "RENEGADE NEW FILE SCAN", columns);
    put(output, use_art ? 8 : 5, 4, 90, "Files dated since " + one_line(since) +
        "  |  " + std::to_string(page.total) + " new files", columns - 2);
    for (std::size_t row = 0; row < page.files.size() && row < 10; ++row) {
        const NewFileEntry& entry = page.files[row];
        const std::string description = entry.file.description.empty()
            ? "" : "  " + one_line(entry.file.description);
        const std::string line = std::to_string((row + 1) % 10) + "  [" +
            one_line(entry.area_name) + "]  " + one_line(entry.file.name) + "  " +
            std::to_string(entry.file.size) + " bytes  " + one_line(entry.file.modified_at) +
            (entry.file.validated ? "" : "  UNVALIDATED") + description;
        if (row == selected_index) {
            put_selected(output, (use_art ? 9 : 7) + static_cast<int>(row), 5, line, columns - 6);
        } else {
            put(output, (use_art ? 9 : 7) + static_cast<int>(row), 5, 97, line, columns - 6);
        }
    }
    if (page.files.empty()) {
        put(output, use_art ? 9 : 9, 5, 93,
            "No new files in your enabled file areas.", columns - 6);
    }
    put(output, rows - 4, 4, 97, "Arrows move  Enter details  1-0 details  N/P pages  R refresh  Q areas", columns - 2);
    put(output, rows - 3, 4, 90, "Page " + std::to_string(page.page + 1) + "/" +
        std::to_string(page.page_count), columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string file_listing_screen(
    const FilePage& page,
    int area_id,
    std::string_view area_name,
    std::string_view search,
    int columns,
    int rows,
    std::string_view file_areas_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !file_areas_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(file_areas_art);
        output += "\x1b[0m";
        clear_art_rows(output, 7, rows);
    }
    centered(output, use_art ? 7 : 3, 96,
        "FILE AREA " + std::to_string(area_id) + " - " + one_line(area_name), columns);
    const std::string search_label = search.empty() ? "Search: (none)" : "Search: " + one_line(search);
    put(output, use_art ? 8 : 5, 4, 90,
        search_label + "    " + std::to_string(page.total) + " files", columns - 2);
    for (std::size_t row = 0; row < page.files.size() && row < 10; ++row) {
        const FileEntry& file = page.files[row];
        const std::string description = file.description.empty() ? "" : "  " + file.description;
        const std::string status = file.request_only ? "  REQUEST ONLY" :
            (file.validated ? "" : "  UNVALIDATED");
        const std::string line = std::to_string((row + 1) % 10) + "  " + file.name + "  " +
            std::to_string(file.size) + " bytes  DL:" + std::to_string(file.download_count) +
            "  " + file.modified_at + status + description;
        if (row == selected_index) {
            put_selected(output, (use_art ? 9 : 7) + static_cast<int>(row), 5, line, columns - 6);
        } else {
            put(output, (use_art ? 9 : 7) + static_cast<int>(row), 5, 97, line, columns - 6);
        }
    }
    if (page.files.empty()) {
        put(output, use_art ? 10 : 9, 5, 93, "No files match this listing.", columns - 6);
    }
    put(output, rows - 5, 4, 96,
        "Download: sftp -P <port> <handle>@<host>  then get /files/<id>/<filename>", columns - 2);
    put(output, rows - 4, 4, 96,
        "Upload: put <local-file> /incoming/<filename>  (private to your account)", columns - 2);
    put(output, rows - 3, 4, 97,
        "ARROWS move  ENTER details  1-0 details  B batch  N/P pages  / search  R clear  Q areas", columns - 2);
    put(output, rows - 2, 4, 90, "Page " + std::to_string(page.page + 1) + "/" +
        std::to_string(page.page_count), columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string file_detail_screen(
    const FileEntry& file,
    std::string_view area_name,
    bool tagged,
    bool sysop,
    bool confirm_delete,
    bool confirm_credit_withdrawal,
    int columns,
    int rows,
    std::string_view file_areas_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !file_areas_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(file_areas_art);
        output += "\x1b[0m";
        clear_art_rows(output, 7, rows);
    }
    centered(output, use_art ? 7 : 3, 96, "FILE DETAILS", columns);
    put(output, use_art ? 9 : 7, 5, 97, "Name: " + one_line(file.name), columns - 6);
    put(output, use_art ? 10 : 9, 5, 97, "Area: " + one_line(area_name), columns - 6);
    put(output, 11, 5, 97, "Size: " + std::to_string(file.size) + " bytes", columns - 6);
    put(output, 12, 5, 97, "Modified: " + one_line(file.modified_at), columns - 6);
    put(output, 13, 5, 97,
        "Completed downloads: " + std::to_string(file.download_count), columns - 6);
    put(output, 14, 5, 97, "File points: " + std::to_string(file.file_points), columns - 6);
    if (!file.owner_handle.empty()) {
        put(output, 15, 5, 97, "Uploader: " + one_line(file.owner_handle), columns - 6);
    }
    put(output, 16, 5, file.request_only ? 91 : (file.validated ? 92 : 91),
        file.request_only ? "Status: REQUEST ONLY" :
            (file.validated ? "Status: VALIDATED" : "Status: UNVALIDATED"), columns - 6);
    if (file.request_only) {
        put(output, 17, 5, file.validated ? 92 : 91,
            file.validated ? "Validation: approved" : "Validation: pending", columns - 6);
    }
    if (confirm_delete) {
        put(output, use_art ? 8 : 5, 5, 91,
            "Delete " + one_line(file.name) + " permanently?  Y/N", columns - 6);
    } else if (confirm_credit_withdrawal) {
        put(output, use_art ? 8 : 5, 5, 91, "Withdraw credited file points from " +
            one_line(file.owner_handle) + "?  Y/N", columns - 6);
    }
    put(output, 18, 5, 96, file.description.empty() ? "Description: (none)" :
        "Description: " + one_line(file.description), columns - 6);
    put(output, rows - 4, 4, 97, file.request_only
        ? "Request this file from the SysOp with R"
        : "Download with SFTP: get /files/<area-id>/<filename>", columns - 2);
    if (confirm_delete) {
        put(output, rows - 3, 4, 97, "Y confirm deletion  N cancel", columns - 2);
    } else if (confirm_credit_withdrawal) {
        put(output, rows - 3, 4, 97, "Y withdraw owner credit  N cancel", columns - 2);
    } else if (sysop) {
        std::string primary = file.request_only ? "B queue  "
            : (tagged ? "T untag  B queue  " : "T tag  B queue  ");
        if (!file.validated) {
            primary += "P points  ";
        }
        if (!file.extended_description.empty()) {
            primary += "V desc  ";
        }
        primary += "1 rename  2 size  3 summary  4 owner  5 date  7 points";
        const std::string controls = std::string("A ") +
            (file.validated ? "unval" : "valid") + "  E ext  6 DLs  D del  M move  Y " +
            (file.request_only ? "online" : "request") + "  W credit  Q return";
        put(output, rows - 3, 4, 97, primary, columns - 2);
        put(output, rows - 2, 4, 97, controls, columns - 2);
    } else {
        std::string commands;
        if (file.request_only) {
            commands = "R request";
        } else {
            commands = tagged ? "T untag  B queue  " : "T tag  B queue  ";
            if (!file.extended_description.empty()) {
                commands += "V description  ";
            }
        }
        commands += "Q return";
        put(output, rows - 3, 4, 97, commands, columns - 2);
    }
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string extended_file_description_screen(
    const FileEntry& file,
    std::string_view area_name,
    std::size_t page,
    bool sysop,
    int columns,
    int rows,
    std::string_view file_areas_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start <= file.extended_description.size()) {
        const std::size_t end = file.extended_description.find('\n', start);
        const std::size_t stop = end == std::string::npos ? file.extended_description.size() : end;
        lines.push_back(one_line(std::string_view(file.extended_description).substr(start, stop - start)));
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    const bool use_art = !file_areas_art.empty() && columns >= 80 && rows >= 24;
    const std::size_t page_size = static_cast<std::size_t>(
        std::max(1, rows - (use_art ? 13 : 11)));
    const std::size_t page_count = std::max<std::size_t>(1,
        (lines.size() + page_size - 1) / page_size);
    page = std::min(page, page_count - 1);
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(file_areas_art);
        output += "\x1b[0m";
        clear_art_rows(output, 7, rows);
    }
    centered(output, use_art ? 7 : 3, 96, "EXTENDED FILE DESCRIPTION", columns);
    put(output, use_art ? 8 : 5, 4, 90,
        one_line(area_name) + " / " + one_line(file.name), columns - 2);
    const int body_start = use_art ? 10 : 7;
    for (std::size_t row = 0; row < page_size && page * page_size + row < lines.size(); ++row) {
        put(output, body_start + static_cast<int>(row), 5, 97,
            lines[page * page_size + row], columns - 6);
    }
    if (lines.empty()) {
        put(output, body_start, 5, 93, "No extended description is available.", columns - 6);
    }
    put(output, rows - 3, 4, 97, sysop
        ? "N/P pages  E edit description  Q return to file details"
        : "N/P next/previous page  Q return to file details", columns - 2);
    put(output, rows - 2, 4, 90, "Page " + std::to_string(page + 1) + "/" +
        std::to_string(page_count), columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string file_description_edit_screen(
    const FileEntry& file,
    std::string_view input,
    int columns,
    int rows,
    std::string_view file_areas_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !file_areas_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(file_areas_art);
        output += "\x1b[0m";
        clear_art_rows(output, 7, rows);
    }
    centered(output, use_art ? 7 : 3, 96, "RENEGADE SYSOP - EDIT FILE DESCRIPTION", columns);
    put(output, use_art ? 9 : 6, 4, 90, "File: " + one_line(file.name), columns - 2);
    put(output, use_art ? 11 : 8, 4, 97, "Current: " + one_line(file.description), columns - 2);
    put(output, rows - 4, 4, 97, "New description> " + one_line(input), columns - 2);
    put(output, rows - 3, 4, 90, "Enter saves  ESC cancels", columns - 2);
    output += cursor(rows - 4, std::min(columns - 1, 21 + static_cast<int>(input.size()))) + "\x1b[?25h";
    return output;
}

std::string extended_file_description_edit_screen(
    const FileEntry& file,
    const std::vector<std::string>& draft_lines,
    std::string_view input,
    int columns,
    int rows,
    std::string_view file_areas_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !file_areas_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(file_areas_art);
        output += "\x1b[0m";
        clear_art_rows(output, 7, rows);
    }
    centered(output, use_art ? 7 : 3, 96, "RENEGADE SYSOP - EDIT EXTENDED DESCRIPTION", columns);
    put(output, use_art ? 8 : 5, 4, 90, "File: " + one_line(file.name), columns - 2);
    put(output, use_art ? 9 : 6, 4, 93,
        "Enter up to 99 lines of 50 characters; a blank line saves the replacement.", columns - 2);
    const std::size_t visible = std::min<std::size_t>(8, draft_lines.size());
    const std::size_t start = draft_lines.size() - visible;
    for (std::size_t row = 0; row < visible; ++row) {
        put(output, (use_art ? 11 : 8) + static_cast<int>(row), 5, 97,
            std::to_string(start + row + 1) + ". " + one_line(draft_lines[start + row]), columns - 6);
    }
    put(output, rows - 4, 4, 97, "Line " + std::to_string(draft_lines.size() + 1) + "> " +
        one_line(input), columns - 2);
    put(output, rows - 3, 4, 90, "ESC cancels  Saved text replaces the current extended description", columns - 2);
    output += cursor(rows - 4, std::min(columns - 1,
        11 + static_cast<int>(std::to_string(draft_lines.size() + 1).size()) + static_cast<int>(input.size()))) +
        "\x1b[?25h";
    return output;
}

std::string download_queue_screen(
    const std::vector<DownloadQueueEntry>& files,
    std::size_t page,
    bool confirming_clear,
    int columns,
    int rows,
    std::string_view file_areas_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const std::size_t page_count = std::max<std::size_t>(1, (files.size() + 9) / 10);
    page = std::min(page, page_count - 1);
    const bool use_art = !file_areas_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(file_areas_art);
        output += "\x1b[0m";
        clear_art_rows(output, 7, rows);
    }
    centered(output, use_art ? 7 : 3, 96, "BATCH DOWNLOAD QUEUE", columns);
    std::uint64_t total_bytes = 0;
    for (const DownloadQueueEntry& file : files) {
        if (file.available && total_bytes <= UINT64_MAX - file.size) {
            total_bytes += file.size;
        }
    }
    put(output, use_art ? 8 : 5, 4, 90, std::to_string(files.size()) + " file(s), " +
        std::to_string(total_bytes) + " bytes total", columns - 2);
    for (std::size_t row = 0; row < 10 && page * 10 + row < files.size(); ++row) {
        const DownloadQueueEntry& file = files[page * 10 + row];
        const std::string line = std::to_string((row + 1) % 10) + "  /files/" +
            std::to_string(file.area_id) + "/" + one_line(file.filename) + "  " +
            (file.available ? std::to_string(file.size) + " bytes" : "[file missing]");
        if (page * 10 + row == selected_index) {
            put_selected(output, (use_art ? 9 : 7) + static_cast<int>(row), 5, line, columns - 6);
        } else {
            put(output, (use_art ? 9 : 7) + static_cast<int>(row), 5,
                file.available ? 97 : 91, line, columns - 6);
        }
    }
    if (files.empty()) {
        put(output, use_art ? 9 : 9, 5, 93,
            "No files are queued. Open a file and press T to add it.", columns - 6);
    }
    if (confirming_clear) {
        put(output, rows - 4, 4, 93, "Clear every queued file? Press Y to confirm, any other key to cancel.", columns - 2);
    } else {
        put(output, rows - 4, 4, 96, "SFTP path: /files/<area-id>/<filename>", columns - 2);
        put(output, rows - 3, 4, 97, "Arrows move  Enter remove  1-0 remove  N/P pages  C clear  R refresh  Q return", columns - 2);
    }
    put(output, rows - 2, 4, 90, "Page " + std::to_string(page + 1) + "/" +
        std::to_string(page_count), columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string archive_listing_screen(
    const ArchiveListing& archive,
    std::string_view archive_name,
    std::size_t page,
    int columns,
    int rows,
    std::string_view file_areas_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const std::size_t page_count = std::max<std::size_t>(1, (archive.entries.size() + 9) / 10);
    page = std::min(page, page_count - 1);
    const bool use_art = !file_areas_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(file_areas_art);
        output += "\x1b[0m";
        clear_art_rows(output, 7, rows);
    }
    centered(output, use_art ? 7 : 3, 96,
        "ARCHIVE VIEWER - " + one_line(archive_name), columns);
    put(output, use_art ? 8 : 5, 4, 90, one_line(archive.format) + "  " +
        std::to_string(archive.entries.size()) + (archive.truncated ? "+ entries (showing first 600)" : " entries"),
        columns - 2);
    for (std::size_t row = 0; row < 10 && page * 10 + row < archive.entries.size(); ++row) {
        const ArchiveEntry& entry = archive.entries[page * 10 + row];
        const std::string line = std::to_string((row + 1) % 10) + "  " + one_line(entry.name) + "  " +
            std::to_string(entry.size) + " bytes  " + one_line(entry.modified_at) +
            (entry.encrypted ? "  [encrypted]" : "");
        if (page * 10 + row == selected_index) {
            put_selected(output, (use_art ? 9 : 7) + static_cast<int>(row), 5, line, columns - 6);
        } else {
            put(output, (use_art ? 9 : 7) + static_cast<int>(row), 5, 97, line, columns - 6);
        }
    }
    if (archive.entries.empty()) {
        put(output, 9, 5, 93, "This archive contains no viewable files.", columns - 6);
    }
    put(output, rows - 4, 4, 97, "Arrows move  Enter view/open  1-0 select  N/P pages  B back  Q exit", columns - 2);
    put(output, rows - 2, 4, 90, "Page " + std::to_string(page + 1) + "/" +
        std::to_string(page_count), columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string archive_entry_detail_screen(
    const ArchiveEntry& entry,
    std::string_view parent_archive,
    int columns,
    int rows,
    std::string_view file_areas_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !file_areas_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(file_areas_art);
        output += "\x1b[0m";
        clear_art_rows(output, 7, rows);
    }
    centered(output, use_art ? 7 : 3, 96, "ARCHIVE ENTRY", columns);
    put(output, use_art ? 9 : 7, 5, 97, "Name: " + one_line(entry.name), columns - 6);
    put(output, use_art ? 11 : 9, 5, 97, "Archive: " + one_line(parent_archive), columns - 6);
    put(output, use_art ? 13 : 11, 5, 97, "Size: " + std::to_string(entry.size) + " bytes", columns - 6);
    put(output, use_art ? 14 : 12, 5, 97, "Modified: " + one_line(entry.modified_at), columns - 6);
    put(output, use_art ? 16 : 14, 5, entry.encrypted ? 93 : 96,
        entry.encrypted ? "This entry is encrypted and cannot be viewed." :
        "This file type is not shown in the terminal viewer.", columns - 6);
    put(output, rows - 3, 4, 97, "B returns to the archive directory", columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string archive_text_screen(
    std::string_view name,
    const std::vector<std::string>& lines,
    std::size_t page,
    int columns,
    int rows,
    std::string_view file_areas_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !file_areas_art.empty() && columns >= 80 && rows >= 24;
    const int first_line_row = use_art ? 10 : 6;
    const std::size_t page_size = static_cast<std::size_t>(
        std::max(1, rows - first_line_row - 4));
    const std::size_t page_count = std::max<std::size_t>(1, (lines.size() + page_size - 1) / page_size);
    page = std::min(page, page_count - 1);
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(file_areas_art);
        output += "\x1b[0m";
        clear_art_rows(output, 7, rows);
    }
    centered(output, use_art ? 7 : 3, 96, "TEXT VIEWER - " + one_line(name), columns);
    const std::size_t first = page * page_size;
    const std::size_t last = std::min(lines.size(), first + page_size);
    for (std::size_t line = first; line < last; ++line) {
        put(output, first_line_row + static_cast<int>(line - first), 5, 97,
            lines[line], columns - 6);
    }
    put(output, rows - 3, 4, 97, "N/P pages  Q return", columns - 2);
    put(output, rows - 2, 4, 90, "Page " + std::to_string(page + 1) + "/" +
        std::to_string(page_count) + "  " + std::to_string(lines.size()) + " lines", columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string upload_review_screen(
    const std::vector<IncomingFile>& uploads,
    std::size_t page,
    int columns,
    int rows,
    std::string_view file_areas_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !file_areas_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(file_areas_art);
        output += "\x1b[0m";
        clear_art_rows(output, 7, rows);
    }
    centered(output, use_art ? 7 : 3, 96, "SYSOP - INCOMING FILES", columns);
    const std::size_t page_count = std::max<std::size_t>(1, (uploads.size() + 9) / 10);
    page = std::min(page, page_count - 1);
    for (std::size_t row = 0; row < 10 && page * 10 + row < uploads.size(); ++row) {
        const IncomingFile& upload = uploads[page * 10 + row];
        const std::string line = std::to_string((row + 1) % 10) + "  " + upload.handle + "/" +
            upload.name + "  " + std::to_string(upload.size) + " bytes  " + upload.modified_at;
        if (page * 10 + row == selected_index) {
            put_selected(output, (use_art ? 9 : 6) + static_cast<int>(row), 4, line, columns - 5);
        } else {
            put(output, (use_art ? 9 : 6) + static_cast<int>(row), 4, 97, line, columns - 5);
        }
    }
    if (uploads.empty()) {
        put(output, use_art ? 9 : 9, 5, 93,
            "No caller uploads are waiting for review.", columns - 6);
    }
    put(output, rows - 4, 4, 97, "Arrows move  Enter review  1-0 review  N/P pages  R refresh  Q return", columns - 2);
    put(output, rows - 2, 4, 90, "Page " + std::to_string(page + 1) + "/" + std::to_string(page_count), columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string upload_detail_screen(
    const IncomingFile& upload,
    bool confirm_delete,
    int columns,
    int rows,
    std::string_view file_areas_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !file_areas_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(file_areas_art);
        output += "\x1b[0m";
        clear_art_rows(output, 7, rows);
    }
    centered(output, use_art ? 7 : 3, 96, "INCOMING UPLOAD REVIEW", columns);
    put(output, use_art ? 9 : 7, 5, 97, "Caller: " + one_line(upload.handle), columns - 6);
    put(output, use_art ? 11 : 9, 5, 97, "File: " + one_line(upload.name), columns - 6);
    put(output, use_art ? 13 : 11, 5, 97,
        "Size: " + std::to_string(upload.size) + " bytes", columns - 6);
    put(output, use_art ? 15 : 13, 5, 97, "Uploaded: " + one_line(upload.modified_at), columns - 6);
    if (confirm_delete) {
        put(output, rows - 4, 4, 93, "Press D again to delete this upload, or any other key to cancel.", columns - 2);
        put(output, rows - 3, 4, 97, "Q return to upload list", columns - 2);
    } else {
        put(output, rows - 4, 4, 97, "P publish into a public file area", columns - 2);
        put(output, rows - 3, 4, 97, "D delete this upload   Q return to upload list", columns - 2);
    }
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string upload_publish_area_screen(
    const IncomingFile& upload,
    const std::vector<FileAreaSummary>& areas,
    std::size_t page,
    int columns,
    int rows,
    std::string_view file_areas_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !file_areas_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(file_areas_art);
        output += "\x1b[0m";
        clear_art_rows(output, 7, rows);
    }
    centered(output, use_art ? 7 : 3, 96, "PUBLISH UPLOAD", columns);
    put(output, use_art ? 8 : 5, 4, 90,
        one_line(upload.handle) + "/" + one_line(upload.name), columns - 2);
    const std::size_t page_count = std::max<std::size_t>(1, (areas.size() + 9) / 10);
    page = std::min(page, page_count - 1);
    for (std::size_t row = 0; row < 10 && page * 10 + row < areas.size(); ++row) {
        const FileAreaSummary& area = areas[page * 10 + row];
        const std::string line = std::to_string((row + 1) % 10) + "  " + area.name +
            "  [ID " + std::to_string(area.id) + "]";
        if (page * 10 + row == selected_index) {
            put_selected(output, (use_art ? 9 : 7) + static_cast<int>(row), 5, line, columns - 6);
        } else {
            put(output, (use_art ? 9 : 7) + static_cast<int>(row), 5, 97, line, columns - 6);
        }
    }
    if (areas.empty()) {
        put(output, use_art ? 9 : 9, 5, 93,
            "No public file areas are configured.", columns - 6);
    }
    put(output, rows - 4, 4, 97, "Arrows move  Enter publish  1-0 select  N/P pages  Q cancel", columns - 2);
    put(output, rows - 2, 4, 90, "Page " + std::to_string(page + 1) + "/" + std::to_string(page_count), columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string one_liners_screen(
    const OneLinerPage& page,
    bool sysop,
    bool may_read_anonymous,
    std::optional<std::int64_t> selected_id,
    int columns,
    int rows,
    std::string_view screen_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !screen_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(screen_art);
        output += "\x1b[0m";
        clear_art_rows(output, 8, rows);
    }
    centered(output, use_art ? 8 : 3, 96, "RENEGADE ONE-LINERS", columns);
    for (std::size_t row = 0; row < page.entries.size() && row < 10; ++row) {
        const OneLiner& entry = page.entries[row];
        std::string author = entry.anonymous ? "Anonymous" : entry.author;
        if (may_read_anonymous && entry.anonymous) {
            author += " (" + entry.author + ")";
        }
        const bool selected = sysop && selected_id.has_value() && entry.id == *selected_id;
        const std::string marker = sysop ? (selected ? ">" : " ") : "";
        const std::string number = sysop ? std::to_string((row + 1) % 10) + " " : "";
        const std::string line = marker + number + " " + one_line(author) + ": " + one_line(entry.text);
        put(output, (use_art ? 10 : 6) + static_cast<int>(row), 4,
            selected ? 93 : 97, line, columns - 5);
    }
    if (page.entries.empty()) {
        put(output, use_art ? 10 : 9, 5, 93, "No one-liners have been posted yet.", columns - 6);
    }
    std::string controls = sysop
        ? "ARROWS move  Enter select  1-0 select  A add  E edit  D delete  R random  N/P pages  Q return"
        : "A add  R random  N/P pages  Q return";
    put(output, rows - 4, 4, 97, controls, columns - 2);
    put(output, rows - 2, 4, 90, "Page " + std::to_string(page.page + 1) + "/" +
        std::to_string(page.page_count) + "    " + std::to_string(page.total) + " total", columns - 2);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

RenderedAreaPage message_areas_screen(
    const std::vector<BoardArea>& areas,
    std::size_t page,
    std::string_view current_area,
    int columns,
    int rows,
    std::string_view message_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    constexpr std::size_t kAreasPerPage = 10;
    const std::size_t page_count = std::max<std::size_t>(
        1, (areas.size() + kAreasPerPage - 1) / kAreasPerPage);
    page = std::min(page, page_count - 1);
    const std::size_t first_area = page * kAreasPerPage;
    const std::size_t last_area = std::min(first_area + kAreasPerPage, areas.size());

    const bool use_art = !message_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(message_art);
        output += "\x1b[0m";
        // Keep the compact eight-row ANSI header and put live board choices below it.
        clear_art_rows(output, 9, rows);
        put(output, 9, 4, 96, "MESSAGE AREAS", columns - 2);
        put(output, 10, 4, 90,
            "Select a board  |  Page " + std::to_string(page + 1) + "/" +
                std::to_string(page_count) + "  |  " + std::to_string(areas.size()) + " areas",
            columns - 2);
        int row = 11;
        for (std::size_t index = first_area; index < last_area; ++index) {
            const std::size_t choice = index - first_area;
            const std::string label = choice == 9 ? "0" : std::to_string(choice + 1);
            const std::string current = areas[index].name == current_area ? "> " : "  ";
            const std::string scan = areas[index].force_read ? "[F] " :
                (areas[index].new_scan_enabled ? "[+] " : "[ ] ");
            const std::string lock = !areas[index].accessible ? "[NO ACCESS] "
                : (areas[index].password_protected ? "[LOCK] " : "");
            const std::string unread = areas[index].unread_total == 0
                ? std::string{}
                : " (" + std::to_string(areas[index].unread_total) + " NEW)";
            const int color = !areas[index].accessible ? 90
                : (areas[index].name == current_area ? 96
                    : (areas[index].unread_total > 0 ? 93 : 97));
            const std::string text = "[" + label + "] " + current + scan + lock +
                one_line(areas[index].name) + unread;
            if (index == selected_index) {
                put_selected(output, row++, 4, text, columns - 2);
            } else {
                put(output, row++, 4, color, text, columns - 2);
            }
        }
        if (areas.empty()) {
            put(output, 11, 4, 37, "No message areas configured.", columns - 2);
        }
        put(output, rows - 2, 4, 90,
            "ARROWS Move  ENTER Open  1-0 Select  S Scan  T Flags  D Date  N/P Pages  Q Menu",
            columns - 2);
        output += cursor(rows, 1) + "\x1b[?25h";
    } else {
        centered(output, 3, 96, "MESSAGE AREAS", columns);
        int row = 6;
        for (std::size_t index = first_area; index < last_area; ++index) {
            const std::size_t choice = index - first_area;
            const std::string label = choice == 9 ? "0" : std::to_string(choice + 1);
            const std::string current = areas[index].name == current_area ? "> " : "  ";
            const std::string scan = areas[index].force_read ? "[F] " :
                (areas[index].new_scan_enabled ? "[+] " : "[ ] ");
            const std::string lock = !areas[index].accessible ? "[NO ACCESS] "
                : (areas[index].password_protected ? "[LOCK] " : "");
            const std::string unread = areas[index].unread_total == 0
                ? std::string{}
                : " (" + std::to_string(areas[index].unread_total) + " NEW)";
            const int color = !areas[index].accessible ? 90
                : (areas[index].name == current_area ? 96
                    : (areas[index].unread_total > 0 ? 93 : 97));
            const std::string text = "[" + label + "] " + current + scan + lock +
                one_line(areas[index].name) + unread;
            if (index == selected_index) {
                put_selected(output, row++, 5, text, columns - 4);
            } else {
                put(output, row++, 5, color, text, columns - 4);
            }
        }
        if (areas.empty()) {
            put(output, row, 5, 37, "No message areas configured.", columns - 4);
        }
        put(output, rows - 2, 5, 90,
            columns < 60 ? "Arrows move Enter open 1-0 S T D N/P Q" :
                "ARROWS move  ENTER open  1-0 select  S scan  T flags  D date  N/P pages  Q return  " +
                    std::to_string(page + 1) + "/" + std::to_string(page_count),
            columns);
        output += cursor(rows - 1, 1) + "\x1b[?25h";
    }
    return {std::move(output), page_count};
}

std::string message_scan_settings_screen(
    const std::vector<BoardArea>& areas,
    std::size_t page,
    int columns,
    int rows,
    std::string_view message_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    constexpr std::size_t page_size = 10;
    const std::size_t page_count = std::max<std::size_t>(
        1, (areas.size() + page_size - 1) / page_size);
    page = std::min(page, page_count - 1);
    const std::size_t first = page * page_size;
    const std::size_t last = std::min(first + page_size, areas.size());
    const bool use_art = !message_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(message_art);
        output += "\x1b[0m";
        clear_art_rows(output, 9, rows);
        put(output, 9, 4, 96, "MESSAGE NEW-SCAN SETTINGS", columns - 2);
        put(output, 10, 4, 90,
            "Forced areas always scan; toggle other boards for your personal scan.", columns - 2);
    } else {
        centered(output, 3, 96, "MESSAGE NEW-SCAN SETTINGS", columns);
        put(output, 5, 5, 90, "FORCED areas always scan; choose which other areas are included.", columns - 4);
    }
    int row = use_art ? 11 : 7;
    for (std::size_t index = first; index < last; ++index) {
        const std::size_t slot = index - first;
        const std::string label = slot == 9 ? "0" : std::to_string(slot + 1);
        const std::string scan = areas[index].force_read ? "FORCED" :
            (areas[index].new_scan_enabled ? "ON" : "OFF");
        const int color = areas[index].force_read ? 93 :
            (areas[index].new_scan_enabled ? 97 : 90);
        const std::string line = "[" + label + "] [" + scan + "] " + one_line(areas[index].name);
        if (index == selected_index) {
            put_selected(output, row++, use_art ? 4 : 5, line, columns - (use_art ? 2 : 4));
        } else {
            put(output, row++, use_art ? 4 : 5, color, line, columns - (use_art ? 2 : 4));
        }
    }
    if (areas.empty()) {
        put(output, use_art ? 11 : 8, use_art ? 4 : 5,
            37, "No accessible message areas are configured.", columns - (use_art ? 2 : 4));
    }
    put(output, rows - 2, use_art ? 4 : 5, 90,
        "Arrows move  Enter toggle  1-0 Toggle  F All  U None  N/P Pages  Q Return  " +
            std::to_string(page + 1) + "/" + std::to_string(page_count),
        columns - 4);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string message_board_screen(
    const std::vector<BoardMessage>& messages,
    const std::vector<std::string>& message_areas,
    std::string_view area_name,
    std::size_t page,
    std::size_t page_count,
    std::size_t total,
    std::size_t unread_total,
    bool unread_only,
    bool search_results,
    bool can_validate_all,
    int columns,
    int rows,
    std::string_view message_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    if (!message_art.empty() && columns >= 80 && rows >= 24) {
        std::string output = "\x1b[2J\x1b[H\x1b[?25l";
        output.append(message_art);
        output += "\x1b[0m";
        // Preserve the screen-specific eight-row header while replacing it with live posts.
        clear_art_rows(output, 9, rows);
        std::string heading = search_results
            ? "SEARCH RESULTS - " + one_line(area_name) + " (" + std::to_string(total) + ")"
            : one_line(area_name) + (unread_only
                ? " - NEW MESSAGES (" + std::to_string(total) + ")"
                : " - " + std::to_string(total) + " POSTS");
        if (unread_total > 0 && !unread_only) {
            heading += " / " + std::to_string(unread_total) + " NEW";
        }
        put(output, 9, 4, 96, heading, columns - 2);
        const std::string page_summary = search_results
            ? std::to_string(total) + " matches"
            : std::to_string(total) + (unread_only ? " new messages" : " posts") +
                (unread_total > 0 ? "  |  " + std::to_string(unread_total) + " unread" : "");
        put(output, 10, 4, 90,
            page_summary + "  |  Page " + std::to_string(page + 1) + "/" +
                std::to_string(page_count), columns - 2);
        int row = 11;
        std::size_t message_number = 0;
        for (const BoardMessage& message : messages) {
            if (message_number >= 10 || row > 20) {
                break;
            }
            const std::size_t newline = message.body.find_first_of("\r\n");
            const std::string_view first_line(message.body.data(),
                newline == std::string::npos ? message.body.size() : newline);
            const std::string label = message_number == 9 ? "0" : std::to_string(message_number + 1);
            const std::string thread = message.reply_to.has_value()
                ? " Re:#" + std::to_string(*message.reply_to)
                : std::string{};
            const std::string unread = message.unread ? " NEW" : std::string{};
            const std::string deleted = message.deleted ? " DELETED" : std::string{};
            const std::string unvalidated = message.unvalidated ? " U" : std::string{};
            const std::string permanent = message.permanent ? " P" : std::string{};
            const std::string area_prefix = message_number < message_areas.size()
                ? "{" + one_line(message_areas[message_number]) + "} " : std::string{};
            const std::string summary = area_prefix + "[" + label + "] #" +
                std::to_string(message.id) + unread + deleted +
                unvalidated + permanent + thread + "  " +
                one_line(message.author) + ": " + one_line(message.subject) + " - " + one_line(first_line);
            const int color = message.deleted ? 90
                : (message.unvalidated ? 95 : (message.unread ? 93 : 97));
            if (message_number == selected_index) {
                put_selected(output, row++, 4, summary, columns - 2);
            } else {
                put(output, row++, 4, color, summary, columns - 2);
            }
            ++message_number;
        }
        if (messages.empty()) {
            put(output, 11, 4, 37, search_results
                ? "No messages matched this search."
                : "No posts yet in " + one_line(area_name) + ".", columns - 2);
        }
        const std::string scope = unread_only ? "S All" : "S New";
        const std::string back = search_results ? "Q Board" : "Q Areas";
        put(output, rows - 2, 4, 90,
            std::string("ARROWS Move  ENTER Read  R/1-0 Read  W Write  ") + scope +
                "  N/P Page  " + back + "  X Find" +
                (can_validate_all ? "  V Validate" : ""), columns - 2);
        output += cursor(rows, 1) + "\x1b[?25h";
        return output;
    }

    std::string output = frame(columns, rows);
    centered(output, 3, 96, search_results
        ? "SEARCH RESULTS - " + std::string(area_name)
        : std::string(area_name) + (unread_only ? " NEW MESSAGE SCAN" : " MESSAGE BOARD"), columns);
    const std::string page_summary = search_results
        ? std::to_string(total) + " matches  Page "
        : (unread_only
            ? std::to_string(total) + " unread posts  Page "
            : std::to_string(total) + " posts  " + std::to_string(unread_total) + " new  Page ");
    put(output, 5, 5, 90,
        page_summary + std::to_string(page + 1) + "/" + std::to_string(page_count), columns);

    int row = 7;
    std::size_t message_number = 0;
    for (const BoardMessage& message : messages) {
        if (row >= rows - 3) {
            break;
        }
        const std::string label = message_number == 9 ? "0" : std::to_string(message_number + 1);
        const std::string thread = message.reply_to.has_value()
            ? " Re:#" + std::to_string(*message.reply_to)
            : std::string{};
        const std::string unread = message.unread ? " NEW" : std::string{};
        const std::string deleted = message.deleted ? " DELETED" : std::string{};
        const std::string unvalidated = message.unvalidated ? " U" : std::string{};
        const std::string permanent = message.permanent ? " P" : std::string{};
        const std::string area_prefix = message_number < message_areas.size()
            ? "{" + one_line(message_areas[message_number]) + "} " : std::string{};
        const std::string title = area_prefix + "[" + label + "] #" +
            std::to_string(message.id) + unread + deleted +
            unvalidated + permanent + thread + "  " +
            one_line(message.author) + ": " + one_line(message.subject);
        const std::size_t newline = message.body.find_first_of("\r\n");
        const std::string_view first_line(message.body.data(),
            newline == std::string::npos ? message.body.size() : newline);
        const std::string summary = title + " - " + one_line(first_line);
        if (message_number == selected_index) {
            put_selected(output, row++, 5, summary, columns - 4);
        } else {
            put(output, row++, 5, 97, summary, columns - 4);
        }
        ++message_number;
    }
    if (messages.empty()) {
        put(output, 8, 5, 37, search_results
            ? "No messages matched this search."
            : "No posts yet in " + std::string(area_name) + ". Press W to post.", columns - 4);
    }

    const std::string board_controls = columns < 60
        ? (search_results ? (unread_only ? "Arrows Move Enter Read R/1-0 W Write S All X Find Q Board"
                                         : "Arrows Move Enter Read R/1-0 W Write S New X Find Q Board")
            : (unread_only ? "Arrows Move Enter Read R/1-0 S All W Write Q Areas X Find"
                           : "Arrows Move Enter Read R/1-0 S New W Write Q Areas X Find"))
        : (search_results ? (unread_only
                ? "Arrows Move Enter Read R/1-0 W Write S All N Older P Newer X Find Q Board "
                : "Arrows Move Enter Read R/1-0 W Write S New N Older P Newer X Find Q Board ")
            : (unread_only ? "Arrows Move Enter Read R/1-0 S All W Write N/P Page Q Areas X Find "
                           : "Arrows Move Enter Read R/1-0 S New W Write N/P Page Q Areas X Find ")) +
            std::to_string(page + 1) + "/" + std::to_string(page_count);
    put(output, rows - 2, 5, 97,
        (can_validate_all ? "V Validate all  " : std::string{}) + board_controls, columns);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string message_search_screen(
    std::string_view area_name,
    std::string_view query,
    bool entering_query,
    bool new_only,
    bool all_areas,
    int columns,
    int rows,
    std::string_view message_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !message_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(message_art);
        output += "\x1b[0m";
        clear_art_rows(output, 9, rows);
    }
    const int title_row = use_art ? 9 : 2;
    const int area_row = use_art ? 10 : 4;
    const int query_row = use_art ? 11 : 6;
    centered(output, title_row, 96,
        entering_query ? "SCAN MESSAGE AREA" : "CHOOSE MESSAGE SEARCH FIELD", columns);
    put(output, area_row, use_art ? 4 : 5, 90,
        "Area: " + one_line(area_name), columns - (use_art ? 2 : 6));
    put(output, query_row, use_art ? 4 : 5, 97,
        "Search text: " + one_line(query), columns - (use_art ? 2 : 6));
    if (entering_query) {
        put(output, use_art ? 13 : 9, use_art ? 4 : 5, 93,
            "Enter up to 40 characters. Press Enter to choose a field.", columns - (use_art ? 2 : 8));
        put(output, use_art ? 15 : 11, use_art ? 4 : 5, 90,
            "Leave it blank to search for messages addressed to you or written by you.",
            columns - (use_art ? 2 : 8));
        put(output, rows - (use_art ? 2 : 3), 4, 91, "Enter Continue   Esc Cancel", columns - 6);
    } else {
        const int first_choices_row = use_art ? 13 : 9;
        const int second_choices_row = use_art ? 14 : 10;
        const int toggle_new_row = use_art ? 16 : 12;
        const int toggle_global_row = use_art ? 17 : 13;
        const int first_column = use_art ? 4 : 5;
        const auto put_choice = [&](int row, int column, int right_column, std::size_t index,
                                    std::string_view label) {
            if (selected_index == index) {
                put_selected(output, row, column, label, right_column);
            } else {
                put(output, row, column, 97, label, right_column);
            }
        };
        constexpr int option_step = 18;
        put_choice(first_choices_row, first_column, first_column + 17, 0, "[F] From");
        put_choice(first_choices_row, first_column + option_step, first_column + option_step + 17,
            1, "[T] To");
        put_choice(first_choices_row, first_column + option_step * 2,
            first_column + option_step * 2 + 20, 2, "[S] Subject");
        put_choice(first_choices_row, first_column + option_step * 3, columns, 3, "[A] All text");
        put_choice(second_choices_row, first_column, first_column + 17, 4, "[Y] To you");
        put_choice(second_choices_row, first_column + option_step,
            first_column + option_step + 20, 5, "[U] Written by you");
        put_choice(toggle_new_row, first_column, columns - 2, 6,
            std::string("[N] Toggle new only: ") + (new_only ? "ON" : "OFF"));
        put_choice(toggle_global_row, first_column, columns - 2, 7,
            std::string("[G] Toggle global scan: ") + (all_areas ? "ON" : "OFF"));
        put(output, rows - (use_art ? 2 : 3), 4, 91,
            "Arrows move  Enter choose/toggle  F/T/S/A/Y/U field  N/G filters  Q cancel",
            columns - 2);
    }
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string message_move_screen(
    const std::vector<BoardArea>& targets,
    std::string_view source_area,
    long long message_id,
    std::size_t page,
    std::size_t page_count,
    bool confirming,
    bool private_target_available,
    std::string_view target_area,
    int columns,
    int rows,
    std::string_view message_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !message_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(message_art);
        output += "\x1b[0m";
        clear_art_rows(output, 9, rows);
    }
    centered(output, use_art ? 9 : 2, 96,
        confirming ? "MOVE MESSAGE - CONFIRM" : "MOVE MESSAGE TO AREA", columns);
    const std::string source_line = "Message #" + std::to_string(message_id) +
        " from " + one_line(source_area) +
        (private_target_available ? "  [0] Private mail" : "");
    if (!confirming && private_target_available && selected_index == 0) {
        put_selected(output, use_art ? 10 : 4, 4, source_line, columns - 6);
    } else {
        put(output, use_art ? 10 : 4, 4, 90, source_line, columns - 6);
    }
    if (confirming) {
        put(output, use_art ? 13 : 9, use_art ? 4 : 5, 93,
            "Move this message to " + one_line(target_area) + "?", columns - (use_art ? 2 : 8));
        if (private_target_available && target_area == "Private mail") {
            put(output, use_art ? 15 : 11, use_art ? 4 : 5, 90,
                "The message To field must match an existing account handle.",
                columns - (use_art ? 2 : 8));
        }
        put(output, rows - (use_art ? 2 : 3), 4, 91,
            "Y Confirm move   N Choose another area   Q Cancel", columns - 6);
    } else {
        const std::size_t page_size = private_target_available ? 9 : 10;
        const std::size_t first = page * page_size;
        const std::size_t last = std::min(first + page_size, targets.size());
        int row = use_art ? 12 : 6;
        for (std::size_t index = first; index < last; ++index) {
            const std::size_t slot = index - first;
            const std::string label = slot == 9 ? "0" : std::to_string(slot + 1);
            const std::string line = "[" + label + "] " + std::to_string(targets[index].id) +
                "  " + one_line(targets[index].name);
            if (index + (private_target_available ? 1 : 0) == selected_index) {
                put_selected(output, row++, use_art ? 4 : 5, line, columns - (use_art ? 2 : 8));
            } else {
                put(output, row++, use_art ? 4 : 5, 97, line, columns - (use_art ? 2 : 8));
            }
        }
        if (targets.empty()) {
            put(output, use_art ? 12 : 9, use_art ? 4 : 5, 37,
                "No other accessible message areas are available.", columns - (use_art ? 2 : 8));
        }
        put(output, rows - (use_art ? 2 : 3), 4, 90,
            (private_target_available ? "Arrows move  Enter select  1-9 select  0 Private  N/P pages  Q cancel  Page "
                                      : "Arrows move  Enter select  1-0 select  N/P pages  Q cancel  Page ") +
                std::to_string(page + 1) + "/" +
                std::to_string(std::max<std::size_t>(1, page_count)),
            columns - 6);
    }
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string unread_messages_screen(
    const UnreadBoardPage& page,
    int columns,
    int rows,
    std::string_view message_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool use_art = !message_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(message_art);
        output += "\x1b[0m";
        clear_art_rows(output, 9, rows);
        put(output, 9, 4, 96, "RENEGADE NEW MESSAGE SCAN", columns - 2);
        put(output, 10, 4, 90,
            std::to_string(page.total) + " unread posts  Page " +
                std::to_string(page.page + 1) + "/" + std::to_string(page.page_count),
            columns - 2);
    } else {
        centered(output, 3, 96, "RENEGADE NEW MESSAGE SCAN", columns);
        put(output, 5, 5, 90,
            std::to_string(page.total) + " unread posts  Page " +
                std::to_string(page.page + 1) + "/" + std::to_string(page.page_count),
            columns - 4);
    }
    int row = use_art ? 11 : 7;
    std::size_t message_number = 0;
    for (const UnreadBoardMessage& entry : page.messages) {
        if ((use_art && (message_number >= 10 || row > 20)) || (!use_art && row >= rows - 3)) {
            break;
        }
        const std::size_t newline = entry.message.body.find_first_of("\r\n");
        const std::string_view first_line(entry.message.body.data(),
            newline == std::string::npos ? entry.message.body.size() : newline);
        const std::string label = message_number == 9 ? "0" : std::to_string(message_number + 1);
        const std::string thread = entry.message.reply_to.has_value()
            ? " Re:#" + std::to_string(*entry.message.reply_to)
            : std::string{};
        const std::string summary = "[" + label + "] " + one_line(entry.area_name) +
            " #" + std::to_string(entry.message.id) + thread + "  " +
            one_line(entry.message.author) + ": " + one_line(entry.message.subject) +
            " - " + one_line(first_line);
        if (message_number == selected_index) {
            put_selected(output, row++, use_art ? 4 : 5, summary, columns - (use_art ? 2 : 4));
        } else {
            put(output, row++, use_art ? 4 : 5, 97, summary, columns - (use_art ? 2 : 4));
        }
        ++message_number;
    }
    if (page.messages.empty()) {
        put(output, use_art ? 11 : 8, use_art ? 4 : 5,
            37, "No unread messages across the message areas.", columns - (use_art ? 2 : 4));
    }
    put(output, rows - 2, use_art ? 4 : 5, 97, columns < 60
        ? "Arrows move Enter read  1-0 Read N/P Pg R Q"
        : "ARROWS move ENTER read  1-0 Read N/P Older/Newer R Refresh Q Areas", columns - 4);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

std::string private_mailbox_screen(
    const std::vector<PrivateMessage>& messages,
    PrivateMailbox mailbox,
    std::size_t page,
    std::size_t page_count,
    std::size_t total,
    std::size_t unread_total,
    int columns,
    int rows,
    std::string_view mailbox_art,
    std::size_t selected_index) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool inbox = mailbox == PrivateMailbox::Inbox;
    const std::string title = inbox ? "PRIVATE INBOX" : "PRIVATE OUTBOX";
    const bool use_art = !mailbox_art.empty() && columns >= 80 && rows >= 24;
    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(mailbox_art);
        output += "\x1b[0m";
        // Retain the private-mail banner and clear the unused area below it.
        clear_art_rows(output, 9, rows);
    }
    centered(output, use_art ? 9 : 3, 96,
        title + " - " + std::to_string(total) + " MESSAGES", columns);
    if (inbox && unread_total > 0) {
        put(output, use_art ? 10 : 4, 5, 93,
            std::to_string(unread_total) + " UNREAD", columns - 4);
    }

    int row = use_art ? 11 : 7;
    std::size_t number = 0;
    for (const PrivateMessage& message : messages) {
        if (row >= rows - 3) {
            break;
        }
        const std::string label = number == 9 ? "0" : std::to_string(number + 1);
        const std::string unread = inbox && message.unread ? " NEW" : std::string{};
        const std::string deleted = message.deleted ? " DELETED" : std::string{};
        const std::string reply = message.reply_to.has_value()
            ? " Re:#" + std::to_string(*message.reply_to)
            : std::string{};
        const std::string correspondent = inbox
            ? "From " + one_line(message.sender)
            : "To " + one_line(message.recipient);
        const std::string entry = "[" + label + "] #" + std::to_string(message.id) + unread + deleted + reply +
            "  " + correspondent + ": " + one_line(message.subject);
        if (number == selected_index) {
            put_selected(output, row++, 5, entry, columns - 4);
        } else {
            put(output, row++, 5, 97, entry, columns - 4);
        }
        ++number;
    }
    if (messages.empty()) {
        put(output, row, 5, 37, inbox ? "Your inbox is empty." : "Your outbox is empty.", columns - 4);
    }

    if (use_art) {
        put(output, rows - 3, 5, 90,
            "Page " + std::to_string(page + 1) + "/" + std::to_string(page_count) +
                (inbox ? "  |  " + std::to_string(unread_total) + " unread" : ""),
            columns - 4);
    }
    if (columns < 72) {
        put(output, rows - 3, 5, 90, "Arrows Move Enter Read R/1-0 C Compose N/P", columns - 4);
        put(output, rows - 2, 5, 90,
            "I Inbox  O Outbox  Q Menu  " + std::to_string(page + 1) + "/" + std::to_string(page_count),
            columns - 4);
    } else {
        const std::string controls = "Arrows Move Enter Read R/1-0 C Compose I Inbox O Outbox N/P Page Q Menu  " +
            std::to_string(page + 1) + "/" + std::to_string(page_count);
        put(output, rows - 2, 5, 90, controls, columns - 4);
    }
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return output;
}

RenderedMessagePage message_reader_screen(
    const BoardMessage& message,
    bool can_toggle_deleted,
    bool can_moderate,
    bool can_edit,
    std::size_t page,
    int columns,
    int rows,
    std::string_view reader_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool is_reply = message.reply_to.has_value();
    const bool use_art = !reader_art.empty() && columns >= 80 && rows >= 24;
    const std::vector<std::string> body_lines = wrap_body(
        message.body, static_cast<std::size_t>(std::max(10, columns - 10)));
    const std::size_t status_lines = static_cast<std::size_t>(message.unvalidated) +
        static_cast<std::size_t>(message.permanent);
    const int first_status_row = use_art ? (is_reply ? 14 : 13) : (is_reply ? 9 : 8);
    const int first_body_row = first_status_row + static_cast<int>(status_lines);
    const std::size_t lines_per_page = static_cast<std::size_t>(
        std::max(1, rows - first_body_row - 2));
    const std::size_t page_count = std::max<std::size_t>(
        1, (body_lines.size() + lines_per_page - 1) / lines_per_page);
    page = std::min(page, page_count - 1);

    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(reader_art);
        output += "\x1b[0m";
        clear_art_rows(output, 9, rows);
    }
    const std::string reader_title = message.deleted ? "MESSAGE READER - DELETED"
        : (message.unvalidated ? "MESSAGE READER - UNVALIDATED"
            : (message.permanent ? "MESSAGE READER - PERMANENT" : "MESSAGE READER"));
    centered(output, use_art ? 9 : 3, 96, reader_title, columns);
    const int id_row = use_art ? 10 : 5;
    const int subject_row = use_art ? 11 : 6;
    const int recipient_row = use_art ? 12 : 7;
    put(output, id_row, 5, 90, "#" + std::to_string(message.id) + "  " +
        one_line(message.author) + "  " + one_line(message.created_at), columns - 4);
    put(output, subject_row, 5, 97, "Subject: " + one_line(message.subject), columns - 4);
    put(output, recipient_row, 5, 97,
        "To: " + one_line(message.recipient.empty() ? "All" : message.recipient), columns - 4);
    if (is_reply) {
        put(output, use_art ? 13 : 8, 5, 90,
            "In reply to #" + std::to_string(*message.reply_to), columns - 4);
    }
    if (message.unvalidated) {
        put(output, first_status_row, 5, 93,
            "UNVALIDATED - awaiting area moderator review", columns - 4);
    }
    if (message.permanent) {
        const int row = first_status_row + static_cast<int>(message.unvalidated);
        put(output, row, 5, 95, "PERMANENT PUBLIC MESSAGE", columns - 4);
    }
    const std::size_t first_line = page * lines_per_page;
    const std::size_t last_line = std::min(first_line + lines_per_page, body_lines.size());
    int row = first_body_row;
    for (std::size_t index = first_line; index < last_line; ++index) {
        put(output, row++, 5, 37, body_lines[index], columns - 4);
    }
    std::string reader_controls = columns < 96
        ? (is_reply ? "Arrows or N/P Pages O Parent R Reply" : "Arrows or N/P Pages R Reply")
        : ("Page " + std::to_string(page + 1) + "/" + std::to_string(page_count) +
            (is_reply ? "  [←/↑] Previous [→/↓] Next [O] Parent [R] Reply"
                      : "  [←/↑] Previous [→/↓] Next [R] Reply"));
    if (can_toggle_deleted && !message.permanent) {
        reader_controls += message.deleted ? " [D] Restore" : " [D] Delete";
    }
    if (can_moderate) {
        reader_controls += message.unvalidated ? " [V] Validate" : " [V] Unvalidate";
        reader_controls += message.permanent ? " [K] Unmark permanent" : " [K] Permanent";
        reader_controls += " [M] Move";
        reader_controls += " [X] Extract";
    }
    if (can_edit) {
        reader_controls += " [E] Edit text";
    }
    reader_controls += columns < 96 ? " F Forward" : " [F] Forward";
    reader_controls += columns < 96 ? " G Goto" : " [G] Goto";
    reader_controls += columns < 96 ? " B Back" : " [B] Back";
    put(output, rows - 2, 5, 90, reader_controls, columns);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return {std::move(output), page_count};
}

RenderedMessagePage private_message_reader_screen(
    const PrivateMessage& message,
    bool allow_reply,
    bool allow_forward,
    bool allow_edit,
    bool allow_move,
    bool allow_extract,
    std::size_t page,
    int columns,
    int rows,
    std::string_view reader_art) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    const bool is_reply = message.reply_to.has_value();
    const bool use_art = !reader_art.empty() && columns >= 80 && rows >= 24;
    const std::vector<std::string> body_lines = wrap_body(
        message.body, static_cast<std::size_t>(std::max(10, columns - 10)));
    const std::size_t body_start = use_art
        ? static_cast<std::size_t>(is_reply ? 16 : 15)
        : static_cast<std::size_t>(is_reply ? 11 : 10);
    const std::size_t lines_per_page = static_cast<std::size_t>(std::max(1, rows - static_cast<int>(body_start) - 4));
    const std::size_t page_count = std::max<std::size_t>(
        1, (body_lines.size() + lines_per_page - 1) / lines_per_page);
    page = std::min(page, page_count - 1);

    std::string output = use_art ? "\x1b[2J\x1b[H\x1b[?25l" : frame(columns, rows);
    if (use_art) {
        output.append(reader_art);
        output += "\x1b[0m";
        clear_art_rows(output, 9, rows);
    }
    centered(output, use_art ? 9 : 2, 96,
        message.deleted ? "PRIVATE MESSAGE - DELETED" : "PRIVATE MESSAGE", columns);
    const std::string date = message.anonymous_details_visible
        ? one_line(message.created_at)
        : "[Unknown]";
    const int metadata_row = use_art ? 10 : 4;
    put(output, metadata_row, 5, 90, "#" + std::to_string(message.id) + "  " + date, columns - 4);
    put(output, metadata_row + 1, 5, 97, "From: " + one_line(message.sender), columns - 4);
    put(output, metadata_row + 2, 5, 97, "To: " + one_line(message.recipient), columns - 4);
    put(output, metadata_row + 3, 5, 97, "Subject: " + one_line(message.subject), columns - 4);
    if (is_reply) {
        put(output, metadata_row + 4, 5, 90,
            "In reply to private message #" + std::to_string(*message.reply_to), columns - 4);
    }
    const std::size_t first_line = page * lines_per_page;
    const std::size_t last_line = std::min(first_line + lines_per_page, body_lines.size());
    int row = static_cast<int>(body_start);
    for (std::size_t index = first_line; index < last_line; ++index) {
        put(output, row++, 5, 37, body_lines[index], columns - 4);
    }
    std::string controls = columns < 90
        ? "Arrows or N/P Pages"
        : "Page " + std::to_string(page + 1) + "/" + std::to_string(page_count) +
            "  [←/↑] Previous [→/↓] Next";
    if (allow_reply) {
        controls += columns < 90 ? " R Reply" : " [R] Reply";
    }
    controls += columns < 90 ? " G Goto" : " [G] Goto";
    controls += columns < 90 ? " B Mail" : " [B] Mailbox";
    if (allow_forward) {
        controls += columns < 90 ? " F Fwd" : " [F] Forward";
    }
    if (allow_edit) {
        controls += columns < 90 ? " E Edit" : " [E] Edit text";
    }
    if (allow_move) {
        controls += columns < 90 ? " M Move" : " [M] Move";
    }
    if (allow_extract) {
        controls += columns < 90 ? " X Extract" : " [X] Extract";
    }
    controls += columns < 90
        ? (message.deleted ? " D Restore" : " D Delete")
        : (message.deleted ? " [D] Restore" : " [D] Delete");
    put(output, rows - 2, 5, 90, controls, columns - 4);
    output += cursor(rows - 1, 1) + "\x1b[?25h";
    return {std::move(output), page_count};
}

std::string chat_screen(
    std::string_view handle,
    int node_number,
    int columns,
    int rows,
    std::string_view chat_art,
    std::string_view chat_input) {
    columns = bounded_columns(columns);
    rows = bounded_rows(rows);
    if (!chat_art.empty() && columns >= 80 && rows >= 24) {
        std::string output = "\x1b[2J\x1b[H\x1b[?25l";
        output.append(chat_art);
        output += "\x1b[0m";
        put(output, rows - 4, 4, 96, "RENEGADE MULTI-NODE CHAT", columns - 2);
        put(output, rows - 3, 4, 97,
            "Connected as " + std::string(handle) + " on node " + std::to_string(node_number) + ".",
            columns - 2);
        put(output, rows - 2, 4, 90, "Type /quit to leave chat.", columns - 2);
        output += cursor(rows, 1) + "\x1b[0m\x1b[KChat> ";
        output.append(chat_input);
        output += "\x1b[?25h";
        return output;
    }

    return "\x1b[2J\x1b[H\x1b[?25h\x1b[96m"
        "+------------------------------------------------------------------------------+\r\n"
        "| Renegade multi-node chat                                                     |\r\n"
        "+------------------------------------------------------------------------------+\r\n"
        "\x1b[0mConnected as " + std::string(handle) + " on node " + std::to_string(node_number) +
        "\r\nType /quit to leave chat.\r\n\r\nChat> " + std::string(chat_input);
}

} // namespace renegade
