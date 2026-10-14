#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace renegade {

struct FileAreaSummary {
    int id{};
    std::string name;
    std::uint64_t file_count{};
    std::uint64_t total_bytes{};
    bool new_scan_enabled{true};
    std::string access_acs;
    std::string download_acs;
    std::string upload_acs;
    bool no_ratio{};
};

struct RemovedFileArea {
    std::string name;
    std::string storage_path;
    bool storage_cleanup_pending{};
};

struct FileEntry {
    std::string name;
    std::string description;
    std::string extended_description;
    std::string owner_handle;
    std::uint64_t size{};
    std::string modified_at;
    std::uint64_t download_count{};
    std::uint64_t file_points{};
    bool validated{true};
    bool request_only{};
};

struct FilePointReward {
    std::string owner_handle;
    std::string filename;
    std::uint64_t points{};
};

struct FilePage {
    std::vector<FileEntry> files;
    std::size_t page{};
    std::size_t page_count{};
    std::uint64_t total{};
};

struct NewFileEntry {
    int area_id{};
    std::string area_name;
    FileEntry file;
};

struct NewFilePage {
    std::vector<NewFileEntry> files;
    std::size_t page{};
    std::size_t page_count{};
    std::uint64_t total{};
    std::string since_date;
};

struct FileValidationPage {
    std::vector<NewFileEntry> files;
    std::size_t page{};
    std::size_t page_count{};
    std::uint64_t total{};
};

struct DownloadQueueEntry {
    std::int64_t id{};
    int area_id{};
    std::string area_name;
    std::string filename;
    std::uint64_t size{};
    bool available{};
};

enum class DownloadQueueAddResult { Added, AlreadyQueued, Full };

struct IncomingFile {
    std::string handle;
    std::string name;
    std::uint64_t size{};
    std::string modified_at;
};

struct FileUserUsage {
    std::uint64_t uploads{};
    std::uint64_t uploaded_bytes{};
    std::uint64_t downloads{};
    std::uint64_t downloaded_bytes{};
};

class FileStore {
public:
    FileStore(std::string database_path, std::string root_path);

    void initialize() const;
    void create_area(std::string_view name) const;
    void rename_area(int area_id, std::string_view name) const;
    [[nodiscard]] RemovedFileArea remove_area(int area_id, bool delete_storage) const;
    void set_area_access(
        int area_id,
        std::string_view access_acs,
        std::string_view download_acs,
        std::string_view upload_acs = {}) const;
    void set_unvalidated_access(
        std::string_view see_acs, std::string_view download_acs) const;
    void set_upload_validation_rules(
        std::string_view auto_validate_acs, bool validate_all_files) const;
    void set_area_no_ratio(int area_id, bool no_ratio) const;
    void set_download_ratios(
        std::uint64_t download_count_ratio,
        std::uint64_t download_kib_ratio,
        std::string_view no_ratio_acs) const;
    void set_download_ratios(
        bool enabled,
        std::uint64_t download_count_ratio,
        std::uint64_t download_kib_ratio,
        std::string_view no_ratio_acs) const;
    void set_download_level_ratios(
        int security_level_min,
        int security_level_max,
        std::uint64_t download_count_ratio,
        std::uint64_t download_kib_ratio) const;
    void clear_download_level_ratios(int security_level_min, int security_level_max) const;
    void set_download_daily_limits(
        bool enabled,
        int security_level_min,
        int security_level_max,
        std::uint64_t max_files,
        std::uint64_t max_kib) const;
    void set_file_point_rules(
        bool enabled,
        std::uint32_t base_size_kib,
        std::uint32_t upload_compensation,
        std::uint32_t reward_ratio,
        std::string_view no_file_credits_acs) const;
    [[nodiscard]] std::vector<FileAreaSummary> areas(std::string_view viewer = {}) const;
    [[nodiscard]] bool toggle_new_file_scan(std::string_view handle, int area_id) const;
    void set_new_file_scan_all(std::string_view handle, bool enabled) const;
    [[nodiscard]] NewFilePage new_files_since(
        std::string_view handle,
        std::string_view since,
        std::size_t page,
        std::size_t page_size = 10) const;
    [[nodiscard]] FileValidationPage unvalidated_files(
        std::string_view sysop, std::size_t page, std::size_t page_size = 10) const;
    [[nodiscard]] std::uint64_t validate_pending_files(std::string_view sysop) const;
    void set_new_file_scan_date(std::string_view handle, std::string_view mmddyyyy) const;
    [[nodiscard]] bool can_download(std::string_view handle, int area_id) const;
    [[nodiscard]] bool can_upload(std::string_view handle, int area_id) const;
    [[nodiscard]] bool can_download_file(
        std::string_view handle, int area_id, std::string_view filename) const;
    [[nodiscard]] bool can_transfer_file(
        std::string_view handle, int area_id, std::string_view filename) const;
    void set_file_validated(
        std::string_view actor, int area_id, std::string_view filename, bool validated) const;
    void validate_file_with_points(
        std::string_view actor,
        int area_id,
        std::string_view filename,
        std::uint64_t file_points,
        std::int64_t owner_balance_adjustment) const;
    void set_file_request_only(
        std::string_view actor, int area_id, std::string_view filename, bool request_only) const;
    void set_file_owner(
        std::string_view actor,
        int area_id,
        std::string_view filename,
        std::string_view owner_handle) const;
    void withdraw_file_owner_credit(
        std::string_view actor, int area_id, std::string_view filename) const;
    void set_file_points(
        std::string_view actor, int area_id, std::string_view filename, std::uint64_t points) const;
    void set_file_date(
        std::string_view actor,
        int area_id,
        std::string_view filename,
        std::string_view mmddyyyy) const;
    [[nodiscard]] std::uint64_t refresh_file_size(
        std::string_view actor, int area_id, std::string_view filename) const;
    void delete_public_file(
        std::string_view actor, int area_id, std::string_view filename) const;
    void rename_public_file(
        std::string_view actor,
        int area_id,
        std::string_view filename,
        std::string_view new_filename) const;
    void move_public_file(
        std::string_view actor,
        int source_area_id,
        std::string_view filename,
        int target_area_id) const;
    [[nodiscard]] int open_public_file(
        std::string_view handle, int area_id, std::string_view filename) const;
    [[nodiscard]] std::vector<DownloadQueueEntry> download_queue(std::string_view handle) const;
    [[nodiscard]] DownloadQueueAddResult tag_download(
        std::string_view handle, int area_id, std::string_view filename) const;
    void remove_queued_download(std::string_view handle, std::int64_t queue_id) const;
    void clear_download_queue(std::string_view handle) const;
    [[nodiscard]] FileUserUsage user_usage(std::string_view handle) const;
    [[nodiscard]] std::vector<IncomingFile> incoming_files() const;
    void publish_upload(std::string_view handle, std::string_view filename, int area_id) const;
    void mark_public_upload_pending(
        std::string_view handle, int area_id, std::string_view filename) const;
    void complete_public_upload(
        std::string_view handle, int area_id, std::string_view filename) const;
    void delete_upload(std::string_view handle, std::string_view filename) const;
    void set_description(int area_id, std::string_view filename, std::string_view description) const;
    void set_extended_description(
        int area_id, std::string_view filename, std::string_view description) const;
    void set_download_count(
        std::string_view actor,
        int area_id,
        std::string_view filename,
        std::uint64_t download_count) const;
    [[nodiscard]] std::optional<std::int64_t> reserve_download_points(
        std::string_view downloader, int area_id, std::string_view filename) const;
    void cancel_download_points(std::int64_t reservation_id) const;
    [[nodiscard]] std::optional<std::int64_t> reserve_daily_download(
        std::string_view downloader, int area_id, std::string_view filename) const;
    void cancel_daily_download(std::int64_t reservation_id) const;
    void recover_download_point_reservations() const;
    [[nodiscard]] std::optional<FilePointReward> record_download(
        int area_id,
        std::string_view filename,
        std::string_view downloader,
        std::optional<std::int64_t> points_reservation = std::nullopt,
        std::optional<std::int64_t> daily_reservation = std::nullopt) const;
    void record_upload(std::string_view uploader, std::string_view filename, std::uint64_t size) const;
    [[nodiscard]] FilePage files(
        std::string_view viewer,
        int area_id,
        std::string_view search,
        std::size_t page,
        std::size_t page_size = 10) const;
    [[nodiscard]] const std::string& root_path() const noexcept;

private:
    std::string database_path_;
    std::string root_path_;
};

} // namespace renegade
