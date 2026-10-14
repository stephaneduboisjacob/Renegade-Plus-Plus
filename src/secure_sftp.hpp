#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include "file_store.hpp"

namespace renegade {

class SecureSftpSession {
public:
    SecureSftpSession(
        FileStore& files,
        std::string handle,
        std::function<void(const FilePointReward&)> on_file_point_reward = {});
    ~SecureSftpSession();

    SecureSftpSession(const SecureSftpSession&) = delete;
    SecureSftpSession& operator=(const SecureSftpSession&) = delete;

    [[nodiscard]] std::string consume(std::string_view bytes);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace renegade
