#include "archive_store.hpp"

#include <archive.h>
#include <archive_entry.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <ctime>
#include <memory>
#include <stdexcept>
#include <string_view>

namespace renegade {
namespace {

struct ArchiveDeleter {
    void operator()(archive* value) const noexcept {
        if (value != nullptr) {
            (void)archive_read_free(value);
        }
    }
};

using Reader = std::unique_ptr<archive, ArchiveDeleter>;

Reader open_reader(std::span<const std::uint8_t> bytes) {
    if (bytes.empty() || bytes.size() > ArchiveStore::max_archive_bytes) {
        throw std::runtime_error("archive is empty or exceeds the 100 MiB browsing limit");
    }
    Reader reader(archive_read_new());
    if (!reader) {
        throw std::runtime_error("could not allocate archive reader");
    }
    (void)archive_read_support_filter_all(reader.get());
    (void)archive_read_support_format_all(reader.get());
    if (archive_read_open_memory(reader.get(), bytes.data(), bytes.size()) != ARCHIVE_OK) {
        const char* detail = archive_error_string(reader.get());
        throw std::runtime_error("could not open archive: " +
            std::string(detail == nullptr ? "unrecognized or damaged format" : detail));
    }
    return reader;
}

std::string entry_time(archive_entry* entry) {
    if (!archive_entry_mtime_is_set(entry)) {
        return {};
    }
    const std::time_t value = static_cast<std::time_t>(archive_entry_mtime(entry));
    std::tm broken_down{};
    if (::gmtime_r(&value, &broken_down) == nullptr) {
        return {};
    }
    std::array<char, 24> formatted{};
    if (std::strftime(formatted.data(), formatted.size(), "%Y-%m-%d %H:%M", &broken_down) == 0) {
        return {};
    }
    return formatted.data();
}

std::string entry_name(archive_entry* entry) {
    const char* path = archive_entry_pathname_utf8(entry);
    if (path == nullptr) {
        path = archive_entry_pathname(entry);
    }
    if (path == nullptr || *path == '\0') {
        return {};
    }
    std::string source(path);
    std::replace(source.begin(), source.end(), '\\', '/');
    if (source.empty() || source.front() == '/') {
        return {};
    }
    const bool trailing_slash = source.back() == '/';
    std::string result;
    std::size_t start = 0;
    while (start < source.size()) {
        const std::size_t slash = source.find('/', start);
        const std::size_t end = slash == std::string::npos ? source.size() : slash;
        const std::string_view component(source.data() + start, end - start);
        if (component == "..") {
            return {};
        }
        if (!component.empty() && component != ".") {
            if (component.find(':') != std::string_view::npos && result.empty()) {
                return {};
            }
            if (!result.empty()) {
                result.push_back('/');
            }
            result.append(component);
        }
        if (slash == std::string::npos) {
            break;
        }
        start = slash + 1;
    }
    if (trailing_slash && !result.empty()) {
        result.push_back('/');
    }
    for (char& value : result) {
        const unsigned char byte = static_cast<unsigned char>(value);
        if (byte < 0x20 || byte == 0x7f || value == '\x1b') {
            value = '?';
        }
    }
    return result;
}

std::string format_name(archive* reader) {
    const char* value = archive_format_name(reader);
    return value == nullptr ? "Archive" : value;
}

} // namespace

bool ArchiveStore::supports_filename(std::string_view filename) {
    const std::size_t dot = filename.find_last_of('.');
    if (dot == std::string_view::npos) {
        return false;
    }
    std::string extension(filename.substr(dot));
    std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    constexpr std::array<std::string_view, 19> extensions{
        ".zip", ".arc", ".pak", ".zoo", ".lzh", ".lha", ".ark", ".arj",
        ".7z", ".rar", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".zst",
        ".tbz", ".tbz2", ".txz"};
    return std::find(extensions.begin(), extensions.end(), extension) != extensions.end();
}

ArchiveListing ArchiveStore::list(std::span<const std::uint8_t> bytes) {
    Reader reader = open_reader(bytes);
    ArchiveListing result;
    std::size_t entry_index = 0;
    std::size_t scanned_entries = 0;
    for (;;) {
        archive_entry* entry = nullptr;
        const int status = archive_read_next_header(reader.get(), &entry);
        if (status == ARCHIVE_EOF) {
            break;
        }
        if (status < ARCHIVE_WARN) {
            const char* detail = archive_error_string(reader.get());
            throw std::runtime_error("reading archive directory: " +
                std::string(detail == nullptr ? "archive is damaged" : detail));
        }
        if (scanned_entries >= max_entries) {
            result.truncated = true;
            break;
        }
        ++scanned_entries;
        if (result.format.empty()) {
            result.format = format_name(reader.get());
        }
        const std::string name = entry_name(entry);
        if (!name.empty()) {
            const la_int64_t reported_size = archive_entry_size(entry);
            const mode_t kind = archive_entry_filetype(entry);
            if (kind == AE_IFDIR) {
                const std::string directory_name = !name.empty() && name.back() == '/'
                    ? name
                    : name + "/";
                result.entries.push_back({entry_index, directory_name, 0, entry_time(entry), true,
                    archive_entry_is_encrypted(entry) > 0, false});
            } else if (kind == AE_IFREG) {
                result.entries.push_back({entry_index, name,
                    reported_size > 0 ? static_cast<std::uint64_t>(reported_size) : 0U,
                    entry_time(entry), false, archive_entry_is_encrypted(entry) > 0, false});
            }
            ++entry_index;
        }
        if (archive_read_data_skip(reader.get()) < ARCHIVE_WARN) {
            const char* detail = archive_error_string(reader.get());
            throw std::runtime_error("reading archive contents: " +
                std::string(detail == nullptr ? "archive data is damaged" : detail));
        }
    }
    if (result.format.empty()) {
        result.format = format_name(reader.get());
    }
    return result;
}

std::vector<std::uint8_t> ArchiveStore::read_entry(
    std::span<const std::uint8_t> bytes,
    std::size_t index,
    std::size_t maximum_bytes) {
    if (maximum_bytes == 0 || maximum_bytes > max_archive_bytes) {
        throw std::invalid_argument("invalid archive entry size limit");
    }
    Reader reader = open_reader(bytes);
    std::size_t current = 0;
    for (;;) {
        archive_entry* entry = nullptr;
        const int status = archive_read_next_header(reader.get(), &entry);
        if (status == ARCHIVE_EOF) {
            throw std::out_of_range("archive entry no longer exists");
        }
        if (status < ARCHIVE_WARN) {
            const char* detail = archive_error_string(reader.get());
            throw std::runtime_error("reading archive entry: " +
                std::string(detail == nullptr ? "archive is damaged" : detail));
        }
        const bool has_name = !entry_name(entry).empty();
        if (!has_name) {
            (void)archive_read_data_skip(reader.get());
            continue;
        }
        if (current++ != index) {
            (void)archive_read_data_skip(reader.get());
            continue;
        }
        if (archive_entry_filetype(entry) != AE_IFREG || archive_entry_is_encrypted(entry) > 0) {
            throw std::runtime_error("directories and encrypted entries cannot be viewed");
        }
        const la_int64_t reported_size = archive_entry_size(entry);
        if (reported_size < 0 || static_cast<std::uint64_t>(reported_size) > maximum_bytes) {
            throw std::runtime_error("archive entry exceeds the viewing limit");
        }
        std::vector<std::uint8_t> result;
        if (reported_size > 0) {
            result.reserve(static_cast<std::size_t>(reported_size));
        }
        std::array<std::uint8_t, 16U * 1024U> buffer{};
        for (;;) {
            const la_ssize_t count = archive_read_data(reader.get(), buffer.data(), buffer.size());
            if (count == 0) {
                break;
            }
            if (count < 0) {
                const char* detail = archive_error_string(reader.get());
                throw std::runtime_error("reading archive entry data: " +
                    std::string(detail == nullptr ? "archive data is damaged" : detail));
            }
            const std::size_t amount = static_cast<std::size_t>(count);
            if (amount > maximum_bytes - result.size()) {
                throw std::runtime_error("archive entry exceeds the viewing limit");
            }
            result.insert(result.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(amount));
        }
        return result;
    }
}

} // namespace renegade
