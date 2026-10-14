#include "secure_sftp.hpp"

#include "file_store.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <system_error>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace renegade {
namespace {

constexpr std::uint8_t kInit = 1;
constexpr std::uint8_t kVersion = 2;
constexpr std::uint8_t kOpen = 3;
constexpr std::uint8_t kClose = 4;
constexpr std::uint8_t kRead = 5;
constexpr std::uint8_t kWrite = 6;
constexpr std::uint8_t kLstat = 7;
constexpr std::uint8_t kFstat = 8;
constexpr std::uint8_t kOpenDir = 11;
constexpr std::uint8_t kReadDir = 12;
constexpr std::uint8_t kRealPath = 16;
constexpr std::uint8_t kStat = 17;
constexpr std::uint8_t kExtended = 200;

constexpr std::uint8_t kStatus = 101;
constexpr std::uint8_t kHandle = 102;
constexpr std::uint8_t kData = 103;
constexpr std::uint8_t kName = 104;
constexpr std::uint8_t kAttrs = 105;

constexpr std::uint32_t kFxOk = 0;
constexpr std::uint32_t kFxEof = 1;
constexpr std::uint32_t kFxNoSuchFile = 2;
constexpr std::uint32_t kFxPermissionDenied = 3;
constexpr std::uint32_t kFxFailure = 4;
constexpr std::uint32_t kFxBadMessage = 5;
constexpr std::uint32_t kFxUnsupported = 8;

constexpr std::uint32_t kFlagRead = 0x00000001U;
constexpr std::uint32_t kFlagWrite = 0x00000002U;
constexpr std::uint32_t kFlagAppend = 0x00000004U;
constexpr std::uint32_t kFlagCreate = 0x00000008U;
constexpr std::uint32_t kFlagTruncate = 0x00000010U;
constexpr std::uint32_t kFlagExclusive = 0x00000020U;

constexpr std::uint32_t kAttrSize = 0x00000001U;
constexpr std::uint32_t kAttrUidGid = 0x00000002U;
constexpr std::uint32_t kAttrPermissions = 0x00000004U;
constexpr std::uint32_t kAttrAccessTime = 0x00000008U;
constexpr std::uint32_t kMaximumPacketBytes = 1024U * 1024U;
constexpr std::uint32_t kMaximumReadBytes = 64U * 1024U;
constexpr std::uint32_t kMaximumWriteBytes = 64U * 1024U;
constexpr std::uint64_t kMaximumUploadFileBytes = 100U * 1024U * 1024U;
constexpr std::uint64_t kMaximumAccountUploadBytes = 500U * 1024U * 1024U;
constexpr std::size_t kMaximumAccountUploadFiles = 4096;
constexpr std::size_t kMaximumDirectoryEntries = 50000;
constexpr std::size_t kMaximumOpenHandles = 256;
constexpr std::string_view kQuotaLockName = ".renegade-quota-lock";

void append_u32(std::string& output, std::uint32_t value) {
    output.push_back(static_cast<char>((value >> 24) & 0xffU));
    output.push_back(static_cast<char>((value >> 16) & 0xffU));
    output.push_back(static_cast<char>((value >> 8) & 0xffU));
    output.push_back(static_cast<char>(value & 0xffU));
}

void append_u64(std::string& output, std::uint64_t value) {
    append_u32(output, static_cast<std::uint32_t>(value >> 32));
    append_u32(output, static_cast<std::uint32_t>(value & 0xffffffffU));
}

void append_string(std::string& output, std::string_view value) {
    if (value.size() > UINT32_MAX) {
        throw std::length_error("SFTP string is too large");
    }
    append_u32(output, static_cast<std::uint32_t>(value.size()));
    output.append(value);
}

std::string frame_packet(std::string payload) {
    if (payload.size() > kMaximumPacketBytes) {
        throw std::length_error("SFTP reply exceeded the packet size limit");
    }
    std::string packet;
    packet.reserve(payload.size() + 4);
    append_u32(packet, static_cast<std::uint32_t>(payload.size()));
    packet += payload;
    return packet;
}

class PacketReader final {
public:
    explicit PacketReader(std::string_view value) : value_(value) {}

    std::uint8_t read_u8() {
        require(1);
        return static_cast<std::uint8_t>(value_[position_++]);
    }

    std::uint32_t read_u32() {
        require(4);
        const auto* bytes = reinterpret_cast<const unsigned char*>(value_.data() + position_);
        position_ += 4;
        return (static_cast<std::uint32_t>(bytes[0]) << 24) |
            (static_cast<std::uint32_t>(bytes[1]) << 16) |
            (static_cast<std::uint32_t>(bytes[2]) << 8) |
            static_cast<std::uint32_t>(bytes[3]);
    }

    std::uint64_t read_u64() {
        const std::uint64_t high = read_u32();
        return (high << 32) | read_u32();
    }

    std::string read_string() {
        const std::uint32_t length = read_u32();
        require(length);
        std::string result(value_.substr(position_, length));
        position_ += length;
        return result;
    }

    [[nodiscard]] std::size_t position() const noexcept { return position_; }

private:
    void require(std::size_t count) const {
        if (count > value_.size() - position_) {
            throw std::runtime_error("truncated SFTP request");
        }
    }

    std::string_view value_;
    std::size_t position_{};
};

std::uint32_t status_from_errno(int error) {
    if (error == ENOENT || error == ENOTDIR) {
        return kFxNoSuchFile;
    }
    if (error == EACCES || error == EPERM || error == ELOOP || error == EROFS) {
        return kFxPermissionDenied;
    }
    return kFxFailure;
}

std::string normalize_path(std::string_view input) {
    if (input.size() > 1024 || input.find('\0') != std::string_view::npos ||
        input.find('\\') != std::string_view::npos) {
        throw std::invalid_argument("invalid SFTP path");
    }
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start < input.size()) {
        while (start < input.size() && input[start] == '/') {
            ++start;
        }
        if (start == input.size()) {
            break;
        }
        const std::size_t end = input.find('/', start);
        const std::string_view part = input.substr(start,
            end == std::string_view::npos ? input.size() - start : end - start);
        if (part == "..") {
            throw std::invalid_argument("parent directory traversal is not allowed");
        }
        if (part != ".") {
            for (const unsigned char value : part) {
                if (value < 0x20 || value == 0x7f) {
                    throw std::invalid_argument("invalid SFTP path");
                }
            }
            parts.emplace_back(part);
        }
        if (end == std::string_view::npos) {
            break;
        }
        start = end + 1;
    }
    std::string result = "/";
    for (std::size_t index = 0; index < parts.size(); ++index) {
        if (index > 0) {
            result.push_back('/');
        }
        result += parts[index];
    }
    return result;
}

std::vector<std::string> path_parts(std::string_view normalized) {
    std::vector<std::string> parts;
    std::size_t start = normalized.starts_with('/') ? 1 : 0;
    while (start < normalized.size()) {
        const std::size_t end = normalized.find('/', start);
        parts.emplace_back(normalized.substr(start,
            end == std::string_view::npos ? normalized.size() - start : end - start));
        if (end == std::string_view::npos) {
            break;
        }
        start = end + 1;
    }
    return parts;
}

bool parse_area_id(std::string_view value, int& area_id) {
    const auto result = std::from_chars(value.data(), value.data() + value.size(), area_id);
    return !value.empty() && result.ec == std::errc{} && result.ptr == value.data() + value.size() && area_id > 0;
}

std::string file_longname(const std::string& name, const struct stat& info) {
    std::array<char, 32> date{};
    std::tm broken_down{};
    const std::time_t modified = info.st_mtime;
    if (::gmtime_r(&modified, &broken_down) != nullptr) {
        (void)std::strftime(date.data(), date.size(), "%b %d %H:%M", &broken_down);
    }
    const char kind = S_ISDIR(info.st_mode) ? 'd' : '-';
    const std::string permissions = S_ISDIR(info.st_mode)
        ? ((info.st_mode & S_IWUSR) != 0 ? "rwx------" : "r-xr-xr-x")
        : ((info.st_mode & S_IWUSR) != 0 ? "rw-------" : "r--r--r--");
    return std::string(1, kind) + permissions + " 1 bbs bbs " +
        std::to_string(static_cast<std::uint64_t>(std::max<off_t>(0, info.st_size))) +
        " " + date.data() + " " + name;
}

} // namespace

struct SecureSftpSession::Impl {
    struct DirectoryEntry {
        std::string name;
        std::string longname;
        struct stat info {};
    };

    struct Handle {
        enum class Kind { File, Directory } kind{Kind::File};
        int descriptor{-1};
        bool writable{};
        bool incoming{};
        int download_area_id{};
        std::string download_filename;
        bool completed_download{};
        std::optional<std::int64_t> download_points_reservation;
        std::optional<std::int64_t> download_daily_reservation;
        int upload_area_id{};
        std::string upload_filename;
        bool wrote_upload{};
        struct stat info {};
        std::vector<DirectoryEntry> entries;
        std::size_t next_entry{};
    };

    FileStore& files;
    std::string handle;
    std::function<void(const FilePointReward&)> on_file_point_reward;
    int areas_fd{-1};
    int incoming_fd{-1};
    int user_incoming_fd{-1};
    int quota_lock_fd{-1};
    std::string input;
    bool initialized{};
    std::uint64_t next_handle{1};
    std::unordered_map<std::string, Handle> handles;
    std::vector<FileAreaSummary> cached_areas;

    Impl(
        FileStore& file_store,
        std::string user_handle,
        std::function<void(const FilePointReward&)> reward_callback)
        : files(file_store), handle(std::move(user_handle)),
          on_file_point_reward(std::move(reward_callback)) {
        files.initialize();
        const std::filesystem::path root(files.root_path());
        areas_fd = ::open((root / "areas").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        incoming_fd = ::open((root / "incoming").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (areas_fd < 0 || incoming_fd < 0) {
            const int error = errno;
            cleanup();
            throw std::system_error(error, std::generic_category(), "opening SFTP storage roots");
        }
        if (::mkdirat(incoming_fd, handle.c_str(), S_IRWXU) != 0 && errno != EEXIST) {
            const int error = errno;
            cleanup();
            throw std::system_error(error, std::generic_category(), "creating private upload directory");
        }
        user_incoming_fd = ::openat(incoming_fd, handle.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (user_incoming_fd < 0) {
            const int error = errno;
            cleanup();
            throw std::system_error(error, std::generic_category(), "opening private upload directory");
        }
        (void)::fchmod(user_incoming_fd, S_IRWXU);
        quota_lock_fd = ::openat(user_incoming_fd, kQuotaLockName.data(),
            O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (quota_lock_fd < 0) {
            const int error = errno;
            cleanup();
            throw std::system_error(error, std::generic_category(), "opening upload quota lock");
        }
        (void)::fchmod(quota_lock_fd, 0600);
    }

    ~Impl() { cleanup(); }

    void record_completed_download(Handle& value) {
        const auto reward = files.record_download(value.download_area_id, value.download_filename,
            handle, value.download_points_reservation, value.download_daily_reservation);
        if (reward.has_value() && on_file_point_reward) {
            try {
                on_file_point_reward(*reward);
            } catch (...) {
            }
        }
    }

    void cleanup() noexcept {
        for (auto& [key, value] : handles) {
            (void)key;
            if (value.download_area_id > 0) {
                try {
                    if (value.completed_download) {
                        record_completed_download(value);
                    } else if (value.download_points_reservation.has_value()) {
                        files.cancel_download_points(*value.download_points_reservation);
                        if (value.download_daily_reservation.has_value()) {
                            files.cancel_daily_download(*value.download_daily_reservation);
                        }
                    } else if (value.download_daily_reservation.has_value()) {
                        files.cancel_daily_download(*value.download_daily_reservation);
                    }
                } catch (...) {
                    if (value.download_points_reservation.has_value()) {
                        try {
                            files.cancel_download_points(*value.download_points_reservation);
                        } catch (...) {
                        }
                    }
                    if (value.download_daily_reservation.has_value()) {
                        try {
                            files.cancel_daily_download(*value.download_daily_reservation);
                        } catch (...) {
                        }
                    }
                }
                value.download_points_reservation.reset();
                value.download_daily_reservation.reset();
            }
            if (value.descriptor >= 0) {
                (void)::close(value.descriptor);
                value.descriptor = -1;
            }
        }
        handles.clear();
        if (quota_lock_fd >= 0) {
            (void)::close(quota_lock_fd);
            quota_lock_fd = -1;
        }
        if (user_incoming_fd >= 0) {
            (void)::close(user_incoming_fd);
            user_incoming_fd = -1;
        }
        if (incoming_fd >= 0) {
            (void)::close(incoming_fd);
            incoming_fd = -1;
        }
        if (areas_fd >= 0) {
            (void)::close(areas_fd);
            areas_fd = -1;
        }
    }

    const std::vector<FileAreaSummary>& area_list() {
        cached_areas = files.areas(handle);
        return cached_areas;
    }

    bool has_area(int area_id) {
        const auto& values = area_list();
        return std::any_of(values.begin(), values.end(), [area_id](const auto& item) {
            return item.id == area_id;
        });
    }

    int area_directory(int area_id) {
        if (!has_area(area_id)) {
            errno = ENOENT;
            return -1;
        }
        const std::string directory = std::to_string(area_id);
        return ::openat(areas_fd, directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    }

    std::uint64_t new_handle_id() {
        if (next_handle == UINT64_MAX) {
            next_handle = 1;
        }
        return next_handle++;
    }

    static std::string opaque_handle(std::uint64_t id) {
        std::string result;
        result.reserve(8);
        append_u64(result, id);
        return result;
    }

    std::string status_packet(std::uint32_t id, std::uint32_t status, std::string_view message = {}) const {
        std::string payload;
        payload.push_back(static_cast<char>(kStatus));
        append_u32(payload, id);
        append_u32(payload, status);
        append_string(payload, message);
        append_string(payload, {});
        return frame_packet(std::move(payload));
    }

    std::string attributes_payload(const struct stat& info, bool directory, bool incoming) const {
        std::string payload;
        const std::uint32_t flags = kAttrSize | kAttrUidGid | kAttrPermissions | kAttrAccessTime;
        append_u32(payload, flags);
        append_u64(payload, static_cast<std::uint64_t>(std::max<off_t>(0, info.st_size)));
        append_u32(payload, static_cast<std::uint32_t>(info.st_uid));
        append_u32(payload, static_cast<std::uint32_t>(info.st_gid));
        mode_t mode = directory
            ? (S_IFDIR | (info.st_mode & 0777))
            : (S_IFREG | (incoming ? 0600 : 0444));
        append_u32(payload, static_cast<std::uint32_t>(mode));
        append_u32(payload, static_cast<std::uint32_t>(std::max<time_t>(0, info.st_atime)));
        append_u32(payload, static_cast<std::uint32_t>(std::max<time_t>(0, info.st_mtime)));
        return payload;
    }

    std::string attrs_packet(std::uint32_t id, const struct stat& info, bool directory, bool incoming) const {
        std::string payload;
        payload.push_back(static_cast<char>(kAttrs));
        append_u32(payload, id);
        payload += attributes_payload(info, directory, incoming);
        return frame_packet(std::move(payload));
    }

    std::string handle_packet(std::uint32_t id, const std::string& token) const {
        std::string payload;
        payload.push_back(static_cast<char>(kHandle));
        append_u32(payload, id);
        append_string(payload, token);
        return frame_packet(std::move(payload));
    }

    std::string data_packet(std::uint32_t id, std::string_view data) const {
        std::string payload;
        payload.push_back(static_cast<char>(kData));
        append_u32(payload, id);
        append_string(payload, data);
        return frame_packet(std::move(payload));
    }

    std::string version_packet(std::uint32_t version) const {
        std::string payload;
        payload.push_back(static_cast<char>(kVersion));
        append_u32(payload, version);
        return frame_packet(std::move(payload));
    }

    std::string name_packet(std::uint32_t id, const std::vector<DirectoryEntry>& entries) const {
        std::string payload;
        payload.push_back(static_cast<char>(kName));
        append_u32(payload, id);
        append_u32(payload, static_cast<std::uint32_t>(entries.size()));
        for (const DirectoryEntry& entry : entries) {
            append_string(payload, entry.name);
            append_string(payload, entry.longname);
            const bool directory = S_ISDIR(entry.info.st_mode);
            const bool incoming = !directory && (entry.info.st_mode & S_IWUSR) != 0;
            payload += attributes_payload(entry.info, directory, incoming);
        }
        return frame_packet(std::move(payload));
    }

    static bool valid_leaf(std::string_view leaf) {
        if (leaf.empty() || leaf == "." || leaf == ".." || leaf == kQuotaLockName || leaf.size() > 255) {
            return false;
        }
        for (const unsigned char value : leaf) {
            if (value < 0x20 || value == 0x7f || value == '/' || value == '\\' || value == 0x1b) {
                return false;
            }
        }
        return true;
    }

    std::uint64_t incoming_usage(std::size_t* file_count = nullptr) const {
        const int duplicate = ::openat(user_incoming_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (duplicate < 0) {
            throw std::system_error(errno, std::generic_category(), "reading upload quota");
        }
        DIR* directory = ::fdopendir(duplicate);
        if (directory == nullptr) {
            const int error = errno;
            (void)::close(duplicate);
            throw std::system_error(error, std::generic_category(), "opening upload quota directory");
        }
        std::uint64_t total = 0;
        std::size_t count = 0;
        int read_error = 0;
        while (true) {
            errno = 0;
            dirent* item = ::readdir(directory);
            if (item == nullptr) {
                read_error = errno;
                break;
            }
            const std::string_view name(item->d_name);
            if (name == "." || name == ".." || name == kQuotaLockName) {
                continue;
            }
            struct stat info {};
            if (::fstatat(user_incoming_fd, item->d_name, &info, AT_SYMLINK_NOFOLLOW) != 0 ||
                !S_ISREG(info.st_mode) || info.st_size < 0) {
                continue;
            }
            ++count;
            const auto size = static_cast<std::uint64_t>(info.st_size);
            if (size > UINT64_MAX - total) {
                total = UINT64_MAX;
                break;
            }
            total += size;
        }
        (void)::closedir(directory);
        if (read_error != 0) {
            throw std::system_error(read_error, std::generic_category(), "reading upload quota directory");
        }
        if (file_count != nullptr) {
            *file_count = count;
        }
        return total;
    }

    int directory_for(const std::vector<std::string>& parts, int& area_id, bool& incoming) {
        area_id = 0;
        incoming = false;
        if (parts.empty()) {
            return ::dup(areas_fd);
        }
        if (parts[0] == "incoming") {
            if (parts.size() == 1) {
                incoming = true;
                return ::dup(user_incoming_fd);
            }
            errno = ENOTDIR;
            return -1;
        }
        if (parts[0] != "files") {
            errno = ENOENT;
            return -1;
        }
        if (parts.size() == 1) {
            return ::dup(areas_fd);
        }
        if (!parse_area_id(parts[1], area_id) || !has_area(area_id)) {
            errno = ENOENT;
            return -1;
        }
        if (parts.size() == 2) {
            return area_directory(area_id);
        }
        errno = ENOTDIR;
        return -1;
    }

    std::vector<DirectoryEntry> list_files(int directory_fd, bool incoming, int area_id = 0) const {
        std::vector<DirectoryEntry> entries;
        const int duplicate = ::openat(directory_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (duplicate < 0) {
            throw std::system_error(errno, std::generic_category(), "duplicating SFTP directory handle");
        }
        DIR* directory = ::fdopendir(duplicate);
        if (directory == nullptr) {
            const int error = errno;
            (void)::close(duplicate);
            throw std::system_error(error, std::generic_category(), "opening SFTP directory stream");
        }
        int saved_error = 0;
        while (true) {
            errno = 0;
            dirent* item = ::readdir(directory);
            if (item == nullptr) {
                saved_error = errno;
                break;
            }
            const std::string name(item->d_name);
            if (!valid_leaf(name)) {
                continue;
            }
            if (!incoming && area_id > 0 && !files.can_download_file(handle, area_id, name)) {
                continue;
            }
            struct stat info {};
            if (::fstatat(directory_fd, name.c_str(), &info, AT_SYMLINK_NOFOLLOW) != 0 ||
                !S_ISREG(info.st_mode)) {
                continue;
            }
            info.st_mode = S_IFREG | (incoming ? 0600 : 0444);
            entries.push_back({name, file_longname(name, info), info});
            if (entries.size() >= kMaximumDirectoryEntries) {
                break;
            }
        }
        (void)::closedir(directory);
        if (saved_error != 0) {
            throw std::system_error(saved_error, std::generic_category(), "reading SFTP directory");
        }
        std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
            return left.name < right.name;
        });
        return entries;
    }

    std::vector<DirectoryEntry> list_directory(const std::string& path) {
        const std::vector<std::string> parts = path_parts(path);
        if (parts.empty()) {
            struct stat directory_info {};
            directory_info.st_mode = S_IFDIR | 0555;
            struct stat incoming_info {};
            incoming_info.st_mode = S_IFDIR | 0700;
            return {
                {"files", "dr-xr-xr-x 1 bbs bbs 0 Jan 01 00:00 files", directory_info},
                {"incoming", "drwx------ 1 bbs bbs 0 Jan 01 00:00 incoming", incoming_info},
            };
        }
        if (parts[0] == "files" && parts.size() == 1) {
            std::vector<DirectoryEntry> entries;
            for (const FileAreaSummary& area : area_list()) {
                struct stat info {};
                info.st_mode = S_IFDIR | 0555;
                const std::string name = std::to_string(area.id);
                entries.push_back({name, "dr-xr-xr-x 1 bbs bbs 0 Jan 01 00:00 " + name + "  " + area.name, info});
            }
            return entries;
        }
        if (parts[0] == "files" && parts.size() == 2) {
            int area_id{};
            if (!parse_area_id(parts[1], area_id) || !has_area(area_id)) {
                throw std::system_error(ENOENT, std::generic_category(), "file area not found");
            }
            const int descriptor = area_directory(area_id);
            if (descriptor < 0) {
                throw std::system_error(errno, std::generic_category(), "opening file area");
            }
            try {
                (void)files.files(handle, area_id, {}, 0, 1);
                const auto entries = list_files(descriptor, false, area_id);
                (void)::close(descriptor);
                return entries;
            } catch (...) {
                (void)::close(descriptor);
                throw;
            }
        }
        if (parts[0] == "incoming" && parts.size() == 1) {
            return list_files(user_incoming_fd, true);
        }
        throw std::system_error(ENOTDIR, std::generic_category(), "not a directory");
    }

    bool stat_path(const std::string& path, struct stat& info, bool& directory, bool& incoming) {
        directory = false;
        incoming = false;
        const std::vector<std::string> parts = path_parts(path);
        if (parts.empty() || (parts.size() == 1 && (parts[0] == "files" || parts[0] == "incoming"))) {
            info = {};
            info.st_mode = S_IFDIR | (parts.size() == 1 && parts[0] == "incoming" ? 0700 : 0555);
            directory = true;
            incoming = parts.size() == 1 && parts[0] == "incoming";
            return true;
        }
        int area_id{};
        if (parts[0] == "files" && parts.size() == 2 &&
            parse_area_id(parts[1], area_id) && has_area(area_id)) {
            const int descriptor = area_directory(area_id);
            if (descriptor < 0) {
                return false;
            }
            const int result = ::fstat(descriptor, &info);
            const int error = errno;
            (void)::close(descriptor);
            if (result != 0) {
                errno = error;
                return false;
            }
            info.st_mode = S_IFDIR | 0555;
            directory = true;
            return true;
        }
        int parent_fd = -1;
        std::string leaf;
        if (parts[0] == "files" && parts.size() == 3 &&
            parse_area_id(parts[1], area_id) && has_area(area_id)) {
            if (!valid_leaf(parts[2])) {
                errno = ENOENT;
                return false;
            }
            try {
                (void)files.files(handle, area_id, {}, 0, 1);
            } catch (...) {
                errno = EACCES;
                return false;
            }
            if (!files.can_download_file(handle, area_id, parts[2])) {
                errno = EACCES;
                return false;
            }
            parent_fd = area_directory(area_id);
            leaf = parts[2];
        } else if (parts[0] == "incoming" && parts.size() == 2 && valid_leaf(parts[1])) {
            parent_fd = ::dup(user_incoming_fd);
            leaf = parts[1];
            incoming = true;
        } else {
            errno = ENOENT;
            return false;
        }
        if (parent_fd < 0) {
            return false;
        }
        const int result = ::fstatat(parent_fd, leaf.c_str(), &info, AT_SYMLINK_NOFOLLOW);
        const int error = errno;
        (void)::close(parent_fd);
        if (result != 0 || !S_ISREG(info.st_mode)) {
            errno = result == 0 ? EACCES : error;
            return false;
        }
        info.st_mode = S_IFREG | (incoming ? 0600 : 0444);
        return true;
    }

    int open_file(const std::string& path, std::uint32_t flags, bool& writable) {
        writable = (flags & kFlagWrite) != 0;
        const bool readable = (flags & kFlagRead) != 0;
        if ((!writable && !readable) || (flags & kFlagAppend) != 0 ||
            (flags & ~(kFlagRead | kFlagWrite | kFlagCreate | kFlagTruncate | kFlagExclusive)) != 0) {
            errno = EINVAL;
            return -1;
        }
        if ((!writable && (flags & (kFlagCreate | kFlagTruncate | kFlagExclusive)) != 0) ||
            ((flags & kFlagExclusive) != 0 && (flags & kFlagCreate) == 0)) {
            errno = EACCES;
            return -1;
        }
        const std::vector<std::string> parts = path_parts(path);
        if (parts.empty()) {
            errno = EACCES;
            return -1;
        }
        int parent_fd = -1;
        std::string leaf;
        bool incoming = false;
        int upload_area_id = 0;
        int public_area_id = 0;
        if (parts[0] == "files" && parts.size() == 3) {
            int area_id{};
            if (!parse_area_id(parts[1], area_id) || !valid_leaf(parts[2])) {
                errno = EACCES;
                return -1;
            }
            public_area_id = area_id;
            if (writable) {
                if ((flags & kFlagCreate) == 0 || !files.can_upload(handle, area_id)) {
                    errno = EACCES;
                    return -1;
                }
                upload_area_id = area_id;
            } else if ((flags & (kFlagCreate | kFlagTruncate | kFlagExclusive)) != 0 ||
                !files.can_download(handle, area_id)) {
                errno = EACCES;
                return -1;
            } else {
                try {
                    (void)files.files(handle, area_id, {}, 0, 1);
                } catch (...) {
                    errno = EACCES;
                    return -1;
                }
                if (!files.can_download_file(handle, area_id, parts[2])) {
                    errno = EACCES;
                    return -1;
                }
                if (!files.can_transfer_file(handle, area_id, parts[2])) {
                    errno = EDQUOT;
                    return -1;
                }
            }
            parent_fd = area_directory(area_id);
            leaf = parts[2];
        } else if (parts[0] == "incoming" && parts.size() == 2 && valid_leaf(parts[1])) {
            incoming = true;
            parent_fd = ::dup(user_incoming_fd);
            leaf = parts[1];
        } else {
            errno = EACCES;
            return -1;
        }
        if (parent_fd < 0) {
            return -1;
        }
        struct QuotaUnlock {
            int descriptor{-1};
            ~QuotaUnlock() {
                if (descriptor >= 0) {
                    (void)::flock(descriptor, LOCK_UN);
                }
            }
            void unlock() noexcept {
                if (descriptor >= 0) {
                    (void)::flock(descriptor, LOCK_UN);
                    descriptor = -1;
                }
            }
        } quota_unlock;
        int open_flags = O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
        if (writable && readable) {
            open_flags |= O_RDWR;
        } else if (writable) {
            open_flags |= O_WRONLY;
        } else {
            open_flags |= O_RDONLY;
        }
        if ((flags & kFlagCreate) != 0) {
            open_flags |= O_CREAT;
        }
        if ((flags & kFlagExclusive) != 0) {
            open_flags |= O_EXCL;
        }
        if (upload_area_id > 0) {
            open_flags |= O_EXCL;
        }
        if (incoming && writable && (flags & kFlagCreate) != 0) {
            if (::flock(quota_lock_fd, LOCK_EX | LOCK_NB) != 0) {
                const int saved_error = errno;
                (void)::close(parent_fd);
                errno = saved_error;
                return -1;
            }
            quota_unlock.descriptor = quota_lock_fd;
            struct stat existing {};
            if (::fstatat(parent_fd, leaf.c_str(), &existing, AT_SYMLINK_NOFOLLOW) != 0) {
                const int saved_error = errno;
                if (saved_error != ENOENT) {
                    (void)::close(parent_fd);
                    errno = saved_error;
                    return -1;
                }
                std::size_t file_count = 0;
                try {
                    (void)incoming_usage(&file_count);
                } catch (...) {
                    (void)::close(parent_fd);
                    throw;
                }
                if (file_count >= kMaximumAccountUploadFiles) {
                    (void)::close(parent_fd);
                    errno = EDQUOT;
                    return -1;
                }
            }
        }
        const bool truncate = (flags & kFlagTruncate) != 0;
        const int descriptor = ::openat(parent_fd, leaf.c_str(), open_flags, incoming ? 0600 : 0);
        const int error = errno;
        quota_unlock.unlock();
        (void)::close(parent_fd);
        if (descriptor < 0) {
            errno = error;
            return -1;
        }
        struct stat info {};
        if (::fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0 ||
            (writable && static_cast<std::uint64_t>(info.st_size) > kMaximumUploadFileBytes)) {
            const int saved_error = errno == 0 ? EFBIG : errno;
            (void)::close(descriptor);
            errno = saved_error;
            return -1;
        }
        if (writable) {
            if (::flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
                const int saved_error = errno;
                (void)::close(descriptor);
                errno = saved_error;
                return -1;
            }
            if (truncate && ::ftruncate(descriptor, 0) != 0) {
                const int saved_error = errno;
                (void)::close(descriptor);
                errno = saved_error;
                return -1;
            }
            (void)::fchmod(descriptor, 0600);
        } else if ((incoming || parts[0] == "files") &&
            ::flock(descriptor, LOCK_SH | LOCK_NB) != 0) {
            const int saved_error = errno;
            (void)::close(descriptor);
            errno = saved_error;
            return -1;
        }
        if (!writable && !incoming && parts[0] == "files" &&
            !files.can_download_file(handle, public_area_id, leaf)) {
            (void)::close(descriptor);
            errno = EACCES;
            return -1;
        }
        if (upload_area_id > 0 && ::flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
            const int saved_error = errno;
            (void)::close(descriptor);
            errno = saved_error;
            return -1;
        }
        return descriptor;
    }

    std::string handle_for(Handle value) {
        const std::string token = opaque_handle(new_handle_id());
        handles.emplace(token, std::move(value));
        return token;
    }

    std::string process(std::string_view payload) {
        if (payload.empty()) {
            throw std::runtime_error("empty SFTP packet");
        }
        PacketReader reader(payload);
        const std::uint8_t type = reader.read_u8();
        if (type == kInit) {
            if (initialized) {
                throw std::runtime_error("repeated SFTP initialization request");
            }
            const std::uint32_t client_version = reader.read_u32();
            initialized = true;
            return version_packet(std::min<std::uint32_t>(3, client_version));
        }
        if (!initialized) {
            throw std::runtime_error("SFTP request received before initialization");
        }
        const std::uint32_t id = reader.read_u32();
        switch (type) {
        case kOpen:
            return process_open(reader, id);
        case kClose:
            return process_close(reader, id);
        case kRead:
            return process_read(reader, id);
        case kWrite:
            return process_write(reader, id);
        case kLstat:
        case kStat:
            return process_stat(reader, id);
        case kFstat:
            return process_fstat(reader, id);
        case kOpenDir:
            return process_open_directory(reader, id);
        case kReadDir:
            return process_read_directory(reader, id);
        case kRealPath:
            return process_realpath(reader, id);
        case kExtended:
            return status_packet(id, kFxUnsupported, "SFTP extensions are not supported");
        default:
            return status_packet(id, kFxUnsupported, "SFTP operation is not supported");
        }
    }

    std::string process_open(PacketReader& reader, std::uint32_t id) {
        if (handles.size() >= kMaximumOpenHandles) {
            return status_packet(id, kFxFailure, "too many open SFTP handles");
        }
        const std::string supplied = reader.read_string();
        const std::uint32_t flags = reader.read_u32();
        std::string path;
        try {
            path = normalize_path(supplied);
        } catch (const std::invalid_argument&) {
            return status_packet(id, kFxPermissionDenied, "invalid SFTP path");
        }
        bool writable = false;
        const int descriptor = open_file(path, flags, writable);
        if (descriptor < 0) {
            const int error = errno;
            return status_packet(id, status_from_errno(error), "could not open file");
        }
        Handle value;
        value.kind = Handle::Kind::File;
        value.descriptor = descriptor;
        value.writable = writable;
        value.incoming = path.starts_with("/incoming/");
        const std::vector<std::string> parts = path_parts(path);
        if (!writable && parts.size() == 3 && parts[0] == "files" &&
            parse_area_id(parts[1], value.download_area_id)) {
            value.download_filename = parts[2];
            try {
                value.download_points_reservation = files.reserve_download_points(
                    handle, value.download_area_id, value.download_filename);
                value.download_daily_reservation = files.reserve_daily_download(
                    handle, value.download_area_id, value.download_filename);
            } catch (const std::exception& error) {
                if (value.download_points_reservation.has_value()) {
                    try {
                        files.cancel_download_points(*value.download_points_reservation);
                    } catch (...) {
                    }
                }
                if (value.download_daily_reservation.has_value()) {
                    try {
                        files.cancel_daily_download(*value.download_daily_reservation);
                    } catch (...) {
                    }
                }
                (void)::close(value.descriptor);
                value.descriptor = -1;
                return status_packet(id, kFxPermissionDenied, error.what());
            }
        }
        if (writable && value.incoming && parts.size() == 2 && parts[0] == "incoming") {
            value.upload_filename = parts[1];
        }
        if (writable && parts.size() == 3 && parts[0] == "files" &&
            parse_area_id(parts[1], value.upload_area_id)) {
            value.upload_filename = parts[2];
            try {
                files.mark_public_upload_pending(handle, value.upload_area_id, value.upload_filename);
            } catch (...) {
                (void)::close(value.descriptor);
                value.descriptor = -1;
                const int area_descriptor = area_directory(value.upload_area_id);
                if (area_descriptor >= 0) {
                    (void)::unlinkat(area_descriptor, value.upload_filename.c_str(), 0);
                    (void)::close(area_descriptor);
                }
                return status_packet(id, kFxPermissionDenied, "could not register public upload");
            }
        }
        return handle_packet(id, handle_for(std::move(value)));
    }

    std::string process_close(PacketReader& reader, std::uint32_t id) {
        const std::string token = reader.read_string();
        const auto found = handles.find(token);
        if (found == handles.end()) {
            return status_packet(id, kFxFailure, "invalid SFTP handle");
        }
        std::string close_error;
        if (found->second.download_area_id > 0) {
            try {
                if (found->second.completed_download) {
                    record_completed_download(found->second);
                    found->second.download_points_reservation.reset();
                    found->second.download_daily_reservation.reset();
                } else if (found->second.download_points_reservation.has_value()) {
                    files.cancel_download_points(*found->second.download_points_reservation);
                    found->second.download_points_reservation.reset();
                    if (found->second.download_daily_reservation.has_value()) {
                        files.cancel_daily_download(*found->second.download_daily_reservation);
                        found->second.download_daily_reservation.reset();
                    }
                } else if (found->second.download_daily_reservation.has_value()) {
                    files.cancel_daily_download(*found->second.download_daily_reservation);
                    found->second.download_daily_reservation.reset();
                }
            } catch (const std::exception& error) {
                close_error = error.what();
                if (found->second.download_points_reservation.has_value()) {
                    try {
                        files.cancel_download_points(*found->second.download_points_reservation);
                        found->second.download_points_reservation.reset();
                    } catch (...) {
                    }
                }
                if (found->second.download_daily_reservation.has_value()) {
                    try {
                        files.cancel_daily_download(*found->second.download_daily_reservation);
                        found->second.download_daily_reservation.reset();
                    } catch (...) {
                    }
                }
            }
        }
        if (found->second.incoming && found->second.writable && found->second.wrote_upload &&
            !found->second.upload_filename.empty()) {
            struct stat info {};
            if (::fstat(found->second.descriptor, &info) == 0 && info.st_size >= 0) {
                files.record_upload(handle, found->second.upload_filename,
                    static_cast<std::uint64_t>(info.st_size));
            }
        }
        if (found->second.upload_area_id > 0 && found->second.writable && found->second.wrote_upload &&
            !found->second.upload_filename.empty()) {
            if (::fdatasync(found->second.descriptor) != 0) {
                close_error = "public upload could not be synced";
            } else {
                struct stat info {};
                if (::fstat(found->second.descriptor, &info) != 0 || info.st_size < 0) {
                    close_error = "public upload size could not be read";
                } else {
                    try {
                        files.complete_public_upload(handle, found->second.upload_area_id,
                            found->second.upload_filename);
                        files.record_upload(handle, found->second.upload_filename,
                            static_cast<std::uint64_t>(info.st_size));
                    } catch (const std::exception& error) {
                        close_error = error.what();
                    }
                }
            }
        }
        if (found->second.descriptor >= 0) {
            (void)::close(found->second.descriptor);
        }
        handles.erase(found);
        if (!close_error.empty()) {
            return status_packet(id, kFxFailure, close_error);
        }
        return status_packet(id, kFxOk);
    }

    std::string process_read(PacketReader& reader, std::uint32_t id) {
        const std::string token = reader.read_string();
        const std::uint64_t offset = reader.read_u64();
        const std::uint32_t requested = reader.read_u32();
        const auto found = handles.find(token);
        if (found == handles.end() || found->second.kind != Handle::Kind::File ||
            offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) ||
            requested > kMaximumReadBytes) {
            return status_packet(id, kFxFailure, "invalid SFTP read request");
        }
        std::string data(std::min(requested, kMaximumReadBytes), '\0');
        const ssize_t count = ::pread(found->second.descriptor, data.data(), data.size(), static_cast<off_t>(offset));
        if (count < 0) {
            const int error = errno;
            return status_packet(id, status_from_errno(error), "file read failed");
        }
        if (count == 0) {
            if (found->second.download_area_id > 0) {
                struct stat info {};
                if (::fstat(found->second.descriptor, &info) == 0 && info.st_size == 0) {
                    found->second.completed_download = true;
                }
            }
            return status_packet(id, kFxEof, "end of file");
        }
        if (found->second.download_area_id > 0) {
            struct stat info {};
            if (::fstat(found->second.descriptor, &info) == 0 && info.st_size >= 0 &&
                offset + static_cast<std::uint64_t>(count) >= static_cast<std::uint64_t>(info.st_size)) {
                found->second.completed_download = true;
            }
        }
        data.resize(static_cast<std::size_t>(count));
        return data_packet(id, data);
    }

    std::string process_write(PacketReader& reader, std::uint32_t id) {
        const std::string token = reader.read_string();
        const std::uint64_t offset = reader.read_u64();
        const std::string data = reader.read_string();
        const auto found = handles.find(token);
        if (found == handles.end() || found->second.kind != Handle::Kind::File ||
            !found->second.writable || data.size() > kMaximumWriteBytes ||
            offset > kMaximumUploadFileBytes || data.size() > kMaximumUploadFileBytes - offset ||
            offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
            return status_packet(id, kFxPermissionDenied, "upload limit or file permission exceeded");
        }
        if (::flock(quota_lock_fd, LOCK_EX | LOCK_NB) != 0) {
            return status_packet(id, kFxFailure, "upload quota is busy; retry the write");
        }
        struct QuotaUnlock {
            int descriptor;
            ~QuotaUnlock() { (void)::flock(descriptor, LOCK_UN); }
        } quota_unlock{quota_lock_fd};
        struct stat current_info {};
        if (::fstat(found->second.descriptor, &current_info) != 0 || current_info.st_size < 0) {
            return status_packet(id, kFxFailure, "could not check upload size");
        }
        const std::uint64_t end_offset = offset + static_cast<std::uint64_t>(data.size());
        const std::uint64_t current_size = static_cast<std::uint64_t>(current_info.st_size);
        const std::uint64_t growth = end_offset > current_size ? end_offset - current_size : 0;
        std::size_t file_count = 0;
        const std::uint64_t used = incoming_usage(&file_count);
        if (file_count > kMaximumAccountUploadFiles || used > kMaximumAccountUploadBytes ||
            growth > kMaximumAccountUploadBytes - used) {
            return status_packet(id, kFxPermissionDenied, "per-account upload storage limit exceeded");
        }
        std::size_t written = 0;
        while (written < data.size()) {
            const ssize_t count = ::pwrite(found->second.descriptor, data.data() + written,
                data.size() - written, static_cast<off_t>(offset + written));
            if (count < 0) {
                if (errno == EINTR) {
                    continue;
                }
                const int error = errno;
                return status_packet(id, status_from_errno(error), "file write failed");
            }
            if (count == 0) {
                return status_packet(id, kFxFailure, "file write made no progress");
            }
            written += static_cast<std::size_t>(count);
        }
        if ((found->second.incoming || found->second.upload_area_id > 0) && !data.empty()) {
            found->second.wrote_upload = true;
        }
        return status_packet(id, kFxOk);
    }

    std::string process_stat(PacketReader& reader, std::uint32_t id) {
        std::string path;
        try {
            path = normalize_path(reader.read_string());
        } catch (const std::invalid_argument&) {
            return status_packet(id, kFxNoSuchFile, "invalid SFTP path");
        }
        struct stat info {};
        bool directory{};
        bool incoming{};
        if (!stat_path(path, info, directory, incoming)) {
            const int error = errno;
            return status_packet(id, status_from_errno(error), "file not found");
        }
        return attrs_packet(id, info, directory, incoming);
    }

    std::string process_fstat(PacketReader& reader, std::uint32_t id) {
        const std::string token = reader.read_string();
        const auto found = handles.find(token);
        if (found == handles.end()) {
            return status_packet(id, kFxFailure, "invalid SFTP handle");
        }
        if (found->second.kind == Handle::Kind::Directory) {
            return attrs_packet(id, found->second.info, true, false);
        }
        if (found->second.descriptor < 0) {
            return status_packet(id, kFxFailure, "invalid SFTP handle");
        }
        struct stat info {};
        if (::fstat(found->second.descriptor, &info) != 0) {
            const int error = errno;
            return status_packet(id, status_from_errno(error), "file status failed");
        }
        const bool directory = found->second.kind == Handle::Kind::Directory;
        return attrs_packet(id, info, directory, found->second.incoming);
    }

    std::string process_open_directory(PacketReader& reader, std::uint32_t id) {
        if (handles.size() >= kMaximumOpenHandles) {
            return status_packet(id, kFxFailure, "too many open SFTP handles");
        }
        std::string path;
        try {
            path = normalize_path(reader.read_string());
        } catch (const std::invalid_argument&) {
            return status_packet(id, kFxNoSuchFile, "invalid SFTP path");
        }
        std::vector<DirectoryEntry> entries;
        try {
            entries = list_directory(path);
        } catch (const std::system_error& error) {
            return status_packet(id, status_from_errno(error.code().value()), "could not open directory");
        } catch (const std::invalid_argument&) {
            return status_packet(id, kFxNoSuchFile, "invalid directory");
        }
        Handle value;
        value.kind = Handle::Kind::Directory;
        bool directory{};
        bool incoming{};
        if (!stat_path(path, value.info, directory, incoming) || !directory) {
            return status_packet(id, kFxNoSuchFile, "directory not found");
        }
        value.entries = std::move(entries);
        return handle_packet(id, handle_for(std::move(value)));
    }

    std::string process_read_directory(PacketReader& reader, std::uint32_t id) {
        const std::string token = reader.read_string();
        const auto found = handles.find(token);
        if (found == handles.end() || found->second.kind != Handle::Kind::Directory) {
            return status_packet(id, kFxFailure, "invalid directory handle");
        }
        if (found->second.next_entry >= found->second.entries.size()) {
            return status_packet(id, kFxEof, "end of directory");
        }
        constexpr std::size_t kEntriesPerReply = 50;
        const std::size_t end = std::min(found->second.next_entry + kEntriesPerReply,
            found->second.entries.size());
        std::vector<DirectoryEntry> entries(
            found->second.entries.begin() + static_cast<std::ptrdiff_t>(found->second.next_entry),
            found->second.entries.begin() + static_cast<std::ptrdiff_t>(end));
        found->second.next_entry = end;
        return name_packet(id, entries);
    }

    std::string process_realpath(PacketReader& reader, std::uint32_t id) {
        std::string path;
        try {
            path = normalize_path(reader.read_string());
        } catch (const std::invalid_argument&) {
            return status_packet(id, kFxNoSuchFile, "invalid path");
        }
        struct stat info {};
        bool directory{};
        bool incoming{};
        if (!stat_path(path, info, directory, incoming)) {
            const int error = errno;
            return status_packet(id, status_from_errno(error), "path not found");
        }
        DirectoryEntry entry{path, path, info};
        std::vector<DirectoryEntry> entries;
        entries.push_back(std::move(entry));
        return name_packet(id, entries);
    }

    std::string consume(std::string_view bytes) {
        if (bytes.size() > kMaximumPacketBytes || input.size() > kMaximumPacketBytes * 2U - bytes.size()) {
            throw std::length_error("SFTP input buffer limit exceeded");
        }
        input.append(bytes);
        std::string output;
        while (input.size() >= 4) {
            PacketReader header(std::string_view(input).substr(0, 4));
            const std::uint32_t packet_length = header.read_u32();
            if (packet_length == 0 || packet_length > kMaximumPacketBytes) {
                throw std::runtime_error("invalid SFTP packet length");
            }
            if (input.size() < static_cast<std::size_t>(packet_length) + 4) {
                break;
            }
            const std::string_view payload(input.data() + 4, packet_length);
            output += process(payload);
            input.erase(0, static_cast<std::size_t>(packet_length) + 4);
            if (output.size() > 4U * kMaximumPacketBytes) {
                throw std::length_error("SFTP response buffer limit exceeded");
            }
        }
        return output;
    }
};

SecureSftpSession::SecureSftpSession(
    FileStore& files,
    std::string handle,
    std::function<void(const FilePointReward&)> on_file_point_reward)
    : impl_(std::make_unique<Impl>(
          files, std::move(handle), std::move(on_file_point_reward))) {}

SecureSftpSession::~SecureSftpSession() = default;

std::string SecureSftpSession::consume(std::string_view bytes) {
    return impl_->consume(bytes);
}

} // namespace renegade
