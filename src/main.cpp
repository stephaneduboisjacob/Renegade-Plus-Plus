#include "account_store.hpp"
#include "community_store.hpp"
#include "file_store.hpp"
#include "legacy_acs.hpp"
#include "message_store.hpp"
#include "server.hpp"

#include <libssh/libssh.h>

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <utility>

namespace {

class TerminalEcho final {
public:
    explicit TerminalEcho(int descriptor) : descriptor_(descriptor) {
        if (::tcgetattr(descriptor_, &original_) != 0) {
            throw std::runtime_error("password input requires an interactive terminal");
        }
        termios hidden = original_;
        hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
        if (::tcsetattr(descriptor_, TCSAFLUSH, &hidden) != 0) {
            throw std::runtime_error("could not disable terminal echo");
        }
        active_ = true;
    }

    ~TerminalEcho() {
        if (active_) {
            (void)::tcsetattr(descriptor_, TCSAFLUSH, &original_);
        }
    }

    TerminalEcho(const TerminalEcho&) = delete;
    TerminalEcho& operator=(const TerminalEcho&) = delete;

private:
    int descriptor_{};
    termios original_{};
    bool active_{};
};

void write_terminal(int descriptor, std::string_view value) {
    std::size_t offset = 0;
    while (offset < value.size()) {
        const ssize_t count = ::write(descriptor, value.data() + offset, value.size() - offset);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error("could not write password prompt to terminal");
        }
        if (count == 0) {
            throw std::runtime_error("terminal accepted no password prompt data");
        }
        offset += static_cast<std::size_t>(count);
    }
}

std::string read_secret(std::string_view prompt) {
    const int terminal = ::open("/dev/tty", O_RDWR | O_CLOEXEC);
    if (terminal < 0) {
        throw std::runtime_error("could not open /dev/tty for password input");
    }

    try {
        write_terminal(terminal, prompt);
        std::string value;
        value.reserve(128);
        {
            TerminalEcho hidden(terminal);
            for (;;) {
                char character{};
                const ssize_t count = ::read(terminal, &character, 1);
                if (count < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    throw std::runtime_error("could not read password from terminal");
                }
                if (count == 0 || character == '\n' || character == '\r') {
                    break;
                }
                if (character == 8 || character == 127) {
                    if (!value.empty()) {
                        value.pop_back();
                    }
                } else if (static_cast<unsigned char>(character) >= 32 && value.size() < 128) {
                    value.push_back(character);
                }
            }
        }
        write_terminal(terminal, "\n");
        ::close(terminal);
        return value;
    } catch (...) {
        ::close(terminal);
        throw;
    }
}

unsigned int parse_unsigned(std::string_view value, std::string_view name, unsigned int minimum, unsigned int maximum) {
    unsigned int parsed{};
    const char* begin = value.data();
    const char* end = begin + value.size();
    const auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end || parsed < minimum || parsed > maximum) {
        throw std::invalid_argument(std::string(name) + " must be between " +
            std::to_string(minimum) + " and " + std::to_string(maximum));
    }
    return parsed;
}

int parse_event_time(std::string_view value) {
    if (value.size() != 5 || value[2] != ':') {
        throw std::invalid_argument("event times must use HH:MM");
    }
    const unsigned int hour = parse_unsigned(value.substr(0, 2), "event hour", 0, 23);
    const unsigned int minute = parse_unsigned(value.substr(3, 2), "event minute", 0, 59);
    return static_cast<int>(hour * 60 + minute);
}

std::string user_database_path(int argc, char** argv, int first_option) {
    std::string path = "data/renegade.sqlite3";
    for (int index = first_option; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete user option: " + std::string(option));
        }
    }
    return path;
}

void print_usage(std::ostream& output) {
    output <<
        "Renegade C++ terminal BBS prototype\n\n"
        "Usage:\n"
        "  renegade-cpp serve [options]\n"
        "  renegade-cpp user add HANDLE [--db PATH]\n"
        "  renegade-cpp user list [--db PATH]\n"
        "  renegade-cpp user password HANDLE [--db PATH]\n"
        "  renegade-cpp user disable HANDLE [--db PATH]\n"
        "  renegade-cpp user enable HANDLE [--db PATH]\n"
        "  renegade-cpp user sysop HANDLE on|off [--db PATH]\n"
        "  renegade-cpp user levels HANDLE SL DSL [--db PATH]\n"
        "  renegade-cpp user flags HANDLE AR_FLAGS AC_FLAGS [--db PATH]\n"
        "  renegade-cpp user credits HANDLE BALANCE [--db PATH]\n"
        "  renegade-cpp user file-points HANDLE BALANCE [--db PATH]\n"
        "  renegade-cpp user mailbox HANDLE open|closed [--db PATH]\n"
        "  renegade-cpp user expiration HANDLE YYYY-MM-DD|never [--db PATH]\n"
        "  renegade-cpp user validate HANDLE KEY [--db PATH]\n"
        "  renegade-cpp area add NAME [--db PATH]\n"
        "  renegade-cpp area access AREA_ID ACS PostACS MCIACS SysOpACS [--db PATH]\n\n"
        "  renegade-cpp area force-read AREA_ID on|off [--db PATH]\n\n"
        "  renegade-cpp area password AREA_ID [--db PATH]\n\n"
        "  renegade-cpp area quote AREA_ID QUOTE_START QUOTE_END [--db PATH]\n\n"
        "  renegade-cpp area real-names AREA_ID on|off [--db PATH]\n\n"
        "  renegade-cpp area tagline AREA_ID on|off [--db PATH]\n\n"
        "  renegade-cpp area filter AREA_ID on|off [--db PATH]\n\n"
        "  renegade-cpp area unhidden AREA_ID on|off [--db PATH]\n\n"
        "  renegade-cpp area tearline AREA_ID on|off [--db PATH]\n\n"
        "  renegade-cpp area origin AREA_ID ORIGIN ADDRESS [--db PATH]\n\n"
        "  renegade-cpp mail quote QUOTE_START QUOTE_END [--db PATH]\n\n"
        "  renegade-cpp area anonymous AREA_ID N|Y|F|D|A [--db PATH]\n\n"
        "  renegade-cpp area anon-acs PUBPOST PUBREAD PRIVPOST PRIVREAD [--db PATH]\n\n"
        "  renegade-cpp area post-acs PUBPOST PRIVPOST [--db PATH]\n\n"
        "  renegade-cpp area post-limits MAXPUB MAXPRIV [--db PATH]\n\n"
        "  renegade-cpp system post-ratio SL_MIN SL_MAX PERCENT [--db PATH]\n\n"
        "  renegade-cpp system event list [--db PATH]\n"
        "  renegade-cpp system event delete SLOT [--db PATH]\n"
        "  renegade-cpp system event set SLOT DESCRIPTION TYPE on|off daily|weekly:MASK|monthly:DAY START END ACS NODE [--db PATH]\n\n"
        "  renegade-cpp system signup-question SOURCE_ID on|off [--db PATH]\n\n"
        "  renegade-cpp system signup-questions [--db PATH]\n\n"
        "  renegade-cpp system recovery-question QUESTION|- [--db PATH]\n\n"
        "  renegade-cpp system user-question NUMBER PROMPT|- [--db PATH]\n\n"
        "  renegade-cpp system submission-acs ADDQUOTE ADDONELINER [--db PATH]\n\n"
        "  renegade-cpp system invisibility-acs ACS [--db PATH]\n\n"
        "  renegade-cpp system validation-eligibility on|off NEWSL [--db PATH]\n\n"
        "  renegade-cpp system validation-level list [--db PATH]\n"
        "  renegade-cpp system validation-level delete KEY [--db PATH]\n"
        "  renegade-cpp system validation-level set KEY DESCRIPTION SL DSL MENU DAYS EXPIRE_TO AR AC SOFT_AR SOFT_AC FILE_POINTS CREDITS USER_MESSAGE [--db PATH]\n\n"
        "  renegade-cpp area mail-limits MAXWAIT CSWAIT [--db PATH]\n\n"
        "  renegade-cpp area credit-costs PUBLIC PRIVATE [--db PATH]\n\n"
        "  renegade-cpp file-area add NAME [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area rename AREA_ID NAME [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area remove AREA_ID [--delete-files] [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area list [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area access AREA_ID ACS DLACS [ULACS] [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area unvalidated-access SEEUNVAL DLUNVAL [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area validation AUTO_VALIDATE_ACS ALL_FILES_ON|OFF [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area no-ratio AREA_ID on|off [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area ratios [on|off] DOWNLOADS KIB NODLRATIO_ACS [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area level-ratios SL_MIN SL_MAX DOWNLOADS KIB [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area level-ratios-clear SL_MIN SL_MAX [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area daily-limits on|off SL_MIN SL_MAX MAX_FILES MAX_KIB [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area point-rules on|off BASE_KIB UPLOAD_COMP REWARD_RATIO NOFILECREDITS_ACS [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area rename-file SYSOP AREA FILE NEW_NAME [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area downloads SYSOP AREA FILE COUNT [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area points SYSOP AREA FILE POINTS [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area request SYSOP AREA FILE on|off [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area owner SYSOP AREA FILE OWNER [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area date SYSOP AREA FILE MM-DD-YYYY [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area size SYSOP AREA FILE [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area move SYSOP SOURCE_AREA FILE TARGET_AREA [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area publish HANDLE FILE AREA_ID [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area delete HANDLE FILE [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area describe AREA_ID FILE DESCRIPTION [--db PATH] [--root PATH]\n"
        "  renegade-cpp file-area describe-extended AREA_ID FILE TEXT [--db PATH] [--root PATH]\n\n"
        "Server options:\n"
        "  --bind ADDRESS       Listen address (default: 127.0.0.1)\n"
        "  --port PORT          SSH port (default: 2222)\n"
        "  --host-key PATH      SSH private host key (default: var/ssh_host_ed25519_key)\n"
        "  --db PATH            Account database (default: data/renegade.sqlite3)\n"
        "  --file-dir DIR       File-area root (default: files)\n"
        "  --entrance-art PATH  ANSI splash shown after SSH login (default: ENTRANCE.ANS)\n"
        "  --new-caller-art PATH  ANSI panel for new-user applications (default: NEW-CALLER.ANS)\n"
        "  --welcome-art PATH   ANSI art shown on the welcome screen (default: WELCOME.ANS)\n"
        "  --sysop-art PATH     ANSI banner for SysOp control screens (default: SYSOP.ANS)\n"
        "  --profile-art PATH   ANSI banner for profile screens (default: USER-PROFILE.ANS)\n"
        "  --time-bank-art PATH  ANSI banner for Time Bank (default: TIME-BANK.ANS)\n"
        "  --once-only-art PATH Legacy-style one-time login notice art\n"
        "  --birthday-art PATH  ANSI art for birthday greetings (default: BIRTHDAY.ANS)\n"
        "  --birthday-late-art PATH  ANSI art for belated greetings (default: BIRTHDAY-LATE.ANS)\n"
        "  --nodes-art PATH     ANSI art for nodes (default: NODES.ANS)\n"
        "  --callers-art PATH   ANSI art for caller history (default: CALLER-LOG.ANS)\n"
        "  --stats-art PATH     ANSI art for statistics screens (default: STATISTICS.ANS)\n"
        "  --help-art PATH      ANSI art used on the help screen (default: HELP.ANS)\n"
        "  --bbs-art PATH       ANSI art for BBS directory screens (default: BBS-DIRECTORY.ANS)\n"
        "  --file-areas-art PATH  ANSI art for file screens (default: FILE-AREAS.ANS)\n"
        "  --chat-art PATH      ANSI art for multi-node chat (default: CHAT.ANS)\n"
        "  --bulletin-art PATH  ANSI art used on the bulletin menu (default: BULLETINS.ANS)\n"
        "  --polls-art PATH     ANSI art for voting screens (default: VOTING.ANS)\n"
        "  --auto-message-art PATH  ANSI art for the auto-message area (default: AUTO-MESSAGE.ANS)\n"
        "  --quotes-art PATH    ANSI art for quotes (default: QUOTES.ANS)\n"
        "  --one-liners-art PATH  ANSI art for the one-liner board (default: ONE-LINERS.ANS)\n"
        "  --uploads-art PATH  ANSI art for SysOp upload review (default: UPLOADS.ANS)\n"
        "  --quote-review-art PATH  ANSI art for quote moderation (default: QUOTE-REVIEW.ANS)\n"
        "  --new-files-art PATH  ANSI art for new-file scans (default: NEW-FILES.ANS)\n"
        "  --file-validation-art PATH  ANSI art for file validation (default: FILE-VALIDATION.ANS)\n"
        "  --download-queue-art PATH  ANSI art for batch downloads (default: DOWNLOAD-QUEUE.ANS)\n"
        "  --archive-art PATH  ANSI art for the archive viewer (default: ARCHIVE-VIEWER.ANS)\n"
        "  --message-move-art PATH  ANSI art for moving messages (default: MESSAGE-MOVE.ANS)\n"
        "  --message-search-art PATH  ANSI art for message search (default: MESSAGE-SEARCH.ANS)\n"
        "  --message-scan-art PATH  ANSI art for personal message scan settings (default: MESSAGE-SCAN.ANS)\n"
        "  --new-messages-art PATH  ANSI art for unread message scan (default: NEW-MESSAGES.ANS)\n"
        "  --private-reader-art PATH  ANSI art for private message reader (default: PRIVATE-READER.ANS)\n"
        "  --sysop-accounts-art PATH  ANSI banner for the SysOp account roster (default: ACCOUNT-ADMIN.ANS)\n"
        "  --sysop-account-art PATH  ANSI banner for account review (default: ACCOUNT-REVIEW.ANS)\n"
        "  --sysop-areas-art PATH  ANSI banner for SysOp area setup (default: AREA-ADMIN.ANS)\n"
        "  --sysop-audit-art PATH  ANSI banner for the SysOp audit log (default: SYSOP-AUDIT.ANS)\n"
        "  --signup-questions-art PATH  ANSI banner for signup-question setup (default: SIGNUP-QUESTIONS.ANS)\n"
        "  --validation-levels-art PATH  ANSI banner for validation levels (default: VALIDATION-LEVELS.ANS)\n"
        "  --message-art PATH   Shared fallback ANSI art for message screens\n"
        "  --areas-art PATH     ANSI art for area picker (default: AREAS.ANS)\n"
        "  --board-art PATH     ANSI art for posts/community (default: MESSAGE-BOARD.ANS)\n"
        "  --mailbox-art PATH   ANSI art for private mail (default: MAILBOX.ANS)\n"
        "  --reader-art PATH    ANSI art for full messages (default: MESSAGE-READER.ANS; custom board/shared art can fill it)\n"
        "  --editor-art PATH    ANSI art for composing messages (default: MESSAGE-WRITER.ANS)\n"
        "  --art-dir DIR        ANSI/ASCII gallery directory (default: assets/ansi)\n"
        "  --bulletin-dir DIR   ANSI/ASCII bulletin directory (default: bulletins)\n"
        "  --quote-dir DIR      Legacy .PTR/.DAT and text quote directory (default: quotes)\n"
        "  --tagline-dir DIR    Legacy .PTR/.DAT and text tagline directory (default: taglines)\n"
        "  --nodes COUNT        Simultaneous BBS nodes (default: 4, maximum: 32)\n"
        "  --connections COUNT SSH connections including handshakes (default: nodes + 2, max: 64)\n"
        "  --allow-signup       Allow new SSH users to create accounts pending SysOp approval (default: off)\n"
        "  --idle-timeout SEC   Disconnect idle shells (default: 1800; 0 disables)\n"
        "  --birthday-check-frequency N  Ask for stored birth date every N logins (default: off)\n"
        "  --session-time-limit MIN  Hard online time per call (default: unlimited)\n"
        "  --time-bank-max MIN      Maximum stored time per account (default: unlimited)\n"
        "  --time-bank-deposit-day MIN  Maximum deposited per local day (default: unlimited)\n"
        "  --time-bank-withdraw-day MIN Maximum withdrawn per local day (default: unlimited)\n"
        "  --auth-failures N    Failed logins per address before cooldown (default: 10)\n"
        "  --auth-window SEC    Failure window per address (default: 300)\n"
        "\n"
        "User management:\n"
        "  --db PATH            Account database (default: data/renegade.sqlite3)\n";
}

int add_user(int argc, char** argv) {
    if (argc < 4) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string handle(argv[3]);
    const std::string database_path = user_database_path(argc, argv, 4);

    const std::string password = read_secret("New password (12-128 characters): ");
    const std::string confirmation = read_secret("Repeat password: ");
    if (password != confirmation) {
        std::cerr << "Passwords did not match. No account was created.\n";
        return 1;
    }
    renegade::AccountStore accounts(database_path);
    accounts.create_user(handle, password);
    std::cout << "Created BBS account " << handle << ".\n";
    return 0;
}

int change_user_password(int argc, char** argv) {
    if (argc < 4) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string handle(argv[3]);
    const std::string database_path = user_database_path(argc, argv, 4);

    const std::string password = read_secret("New password (12-128 characters): ");
    const std::string confirmation = read_secret("Repeat password: ");
    if (password != confirmation) {
        std::cerr << "Passwords did not match. The account was not changed.\n";
        return 1;
    }
    renegade::AccountStore accounts(database_path);
    accounts.set_password(handle, password);
    std::cout << "Updated password for BBS account " << handle << ".\n";
    return 0;
}

int list_users(int argc, char** argv) {
    const std::string database_path = user_database_path(argc, argv, 3);
    renegade::AccountStore accounts(database_path);
    const auto records = accounts.list_accounts();
    if (records.empty()) {
        std::cout << "No BBS accounts.\n";
        return 0;
    }

    std::cout << "Handle\tStatus\tRole\tSL\tDSL\tAR\tAC\tCredits\tFilePoints\tMailbox\tExpires\tCreated\n";
    for (const auto& account : records) {
        const char* status = !account.approved ? "pending" : (account.enabled ? "enabled" : "disabled");
        std::cout << account.handle << '\t' << status << '\t'
                  << (account.is_sysop ? "sysop" : "user") << '\t'
                  << account.security_level << '\t' << account.download_security_level << '\t'
                  << (account.acs_ar_flags.empty() ? "-" : account.acs_ar_flags) << '\t'
                  << (account.acs_ac_flags.empty() ? "-" : account.acs_ac_flags) << '\t'
                  << account.credits << '\t'
                  << account.file_points << '\t'
                  << (account.mailbox_closed ? "closed" : "open") << '\t'
                  << (account.expiration_date.empty() ? "never" : account.expiration_date) << '\t'
                  << account.created_at << '\n';
    }
    return 0;
}

int set_user_enabled(int argc, char** argv, bool enabled) {
    if (argc < 4) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string handle(argv[3]);
    const std::string database_path = user_database_path(argc, argv, 4);
    renegade::AccountStore accounts(database_path);
    accounts.set_enabled(handle, enabled);
    std::cout << (enabled ? "Enabled" : "Disabled") << " BBS account " << handle << ".\n";
    return 0;
}

int set_user_sysop(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string handle(argv[3]);
    const std::string_view requested(argv[4]);
    if (requested != "on" && requested != "off") {
        throw std::invalid_argument("SysOp access must be 'on' or 'off'");
    }
    const std::string database_path = user_database_path(argc, argv, 5);
    renegade::AccountStore accounts(database_path);
    accounts.set_sysop(handle, requested == "on");
    std::cout << (requested == "on" ? "Granted" : "Revoked")
              << " SysOp access for " << handle << ".\n";
    return 0;
}

int set_user_security_levels(int argc, char** argv) {
    if (argc < 6) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string handle(argv[3]);
    const int security_level = static_cast<int>(parse_unsigned(argv[4], "security level", 0, 255));
    const int download_security_level = static_cast<int>(
        parse_unsigned(argv[5], "download security level", 0, 255));
    const std::string database_path = user_database_path(argc, argv, 6);
    renegade::AccountStore accounts(database_path);
    accounts.set_security_levels(handle, security_level, download_security_level);
    std::cout << "Set " << handle << " security levels to SL=" << security_level
              << " DSL=" << download_security_level << ".\n";
    return 0;
}

int set_user_acs_flags(int argc, char** argv) {
    if (argc < 6) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string handle(argv[3]);
    const std::string_view ar_flags(argv[4]);
    const std::string_view ac_flags(argv[5]);
    const std::string database_path = user_database_path(argc, argv, 6);
    renegade::AccountStore accounts(database_path);
    accounts.set_acs_flags(handle, ar_flags == "-" ? "" : ar_flags,
        ac_flags == "-" ? "" : ac_flags);
    std::cout << "Updated " << handle << " ACS flags.\n";
    return 0;
}

int set_user_credits(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view balance_text(argv[4]);
    std::int64_t balance{};
    const auto parsed = std::from_chars(
        balance_text.data(), balance_text.data() + balance_text.size(), balance);
    if (balance_text.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != balance_text.data() + balance_text.size()) {
        throw std::invalid_argument("account credit balance must be a signed 32-bit integer");
    }
    const std::string handle(argv[3]);
    const std::string database_path = user_database_path(argc, argv, 5);
    renegade::AccountStore accounts(database_path);
    accounts.set_credits(handle, balance);
    std::cout << "Set " << handle << " credit balance to " << balance << ".\n";
    return 0;
}

int set_user_file_points(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view balance_text(argv[4]);
    std::int64_t balance{};
    const auto parsed = std::from_chars(
        balance_text.data(), balance_text.data() + balance_text.size(), balance);
    if (balance_text.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != balance_text.data() + balance_text.size()) {
        throw std::invalid_argument("file-point balance must be a non-negative 32-bit integer");
    }
    const std::string handle(argv[3]);
    const std::string database_path = user_database_path(argc, argv, 5);
    renegade::AccountStore accounts(database_path);
    accounts.set_file_points(handle, balance);
    std::cout << "Set " << handle << " file-point balance to " << balance << ".\n";
    return 0;
}

int set_user_mailbox(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string handle(argv[3]);
    const std::string_view requested(argv[4]);
    if (requested != "open" && requested != "closed") {
        throw std::invalid_argument("mailbox state must be 'open' or 'closed'");
    }
    const std::string database_path = user_database_path(argc, argv, 5);
    renegade::AccountStore accounts(database_path);
    accounts.set_mailbox_closed(handle, requested == "closed");
    std::cout << "Set " << handle << " mailbox to " << requested << ".\n";
    return 0;
}

int set_user_expiration(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string handle(argv[3]);
    std::string date(argv[4]);
    if (date == "never" || date == "NEVER") {
        date.clear();
    }
    const std::string database_path = user_database_path(argc, argv, 5);
    renegade::AccountStore accounts(database_path);
    accounts.set_expiration_date(handle, date);
    std::cout << "Updated expiration for BBS account " << handle << ".\n";
    return 0;
}

int set_user_validation_level(int argc, char** argv) {
    if (argc < 5 || std::string_view(argv[4]).size() != 1) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string handle(argv[3]);
    const char key = argv[4][0];
    const std::string database_path = user_database_path(argc, argv, 5);
    renegade::AccountStore accounts(database_path);
    const auto levels = accounts.validation_levels();
    const auto level = std::find_if(levels.begin(), levels.end(),
        [key](const renegade::ValidationLevel& item) { return item.key == key; });
    if (level == levels.end()) {
        throw std::invalid_argument("validation level does not exist");
    }
    const std::string user_message = level->user_message;
    accounts.apply_validation_level(handle, key);
    if (!user_message.empty()) {
        try {
            renegade::CommunityStore(database_path).send_short_message(handle, user_message, true);
        } catch (const std::exception& error) {
            std::cerr << "Validation applied, but its user message could not be queued: "
                      << error.what() << '\n';
        }
    }
    std::cout << "Applied validation level " << key << " to " << handle << ".\n";
    return 0;
}

int configure_validation_level(int argc, char** argv) {
    if (argc < 4) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view action(argv[3]);
    if (action == "list") {
        const std::string database_path = user_database_path(argc, argv, 4);
        renegade::AccountStore accounts(database_path);
        const auto levels = accounts.validation_levels();
        if (levels.empty()) {
            std::cout << "No validation levels are configured.\n";
            return 0;
        }
        std::cout << "Key\tDescription\tSL\tDSL\tMenu\tDays\tExpireTo\tAR\tAC\tSoftAR\tSoftAC\tFP\tCredits\tUserMessage\n";
        for (const auto& level : levels) {
            std::cout << level.key << '\t' << level.description << '\t'
                      << level.security_level << '\t' << level.download_security_level << '\t'
                      << level.start_menu << '\t' << level.expiration_days << '\t'
                      << (level.expire_to_key == ' ' ? "-" : std::string(1, level.expire_to_key)) << '\t'
                      << (level.ar_flags.empty() ? "-" : level.ar_flags) << '\t'
                      << (level.ac_flags.empty() ? "-" : level.ac_flags) << '\t'
                      << (level.soft_ar_flags ? "on" : "off") << '\t'
                      << (level.soft_ac_flags ? "on" : "off") << '\t'
                      << level.file_points << '\t' << level.credits << '\t'
                      << level.user_message << '\n';
        }
        return 0;
    }
    if (action == "delete") {
        if (argc < 5 || std::string_view(argv[4]).size() != 1) {
            print_usage(std::cerr);
            return 2;
        }
        const char key = argv[4][0];
        const std::string database_path = user_database_path(argc, argv, 5);
        renegade::AccountStore accounts(database_path);
        accounts.delete_validation_level(key);
        std::cout << "Deleted validation level " << key << ".\n";
        return 0;
    }
    if (action != "set" || argc < 18 || std::string_view(argv[4]).size() != 1) {
        print_usage(std::cerr);
        return 2;
    }
    const auto boolean = [](std::string_view value, std::string_view name) {
        if (value == "on") return true;
        if (value == "off") return false;
        throw std::invalid_argument(std::string(name) + " must be 'on' or 'off'");
    };
    renegade::ValidationLevel level;
    level.key = argv[4][0];
    level.description = argv[5];
    level.security_level = static_cast<int>(parse_unsigned(argv[6], "validation SL", 0, 255));
    level.download_security_level = static_cast<int>(parse_unsigned(argv[7], "validation DSL", 0, 255));
    level.start_menu = static_cast<int>(parse_unsigned(argv[8], "validation start menu", 0, 255));
    level.expiration_days = static_cast<int>(parse_unsigned(argv[9], "validation expiration days", 0, 65535));
    if (std::string_view(argv[10]) != "-") {
        if (std::string_view(argv[10]).size() != 1) {
            throw std::invalid_argument("validation expire-to must be one key or '-'");
        }
        level.expire_to_key = argv[10][0];
    }
    level.ar_flags = std::string_view(argv[11]) == "-" ? "" : argv[11];
    level.ac_flags = std::string_view(argv[12]) == "-" ? "" : argv[12];
    level.soft_ar_flags = boolean(argv[13], "SoftAR");
    level.soft_ac_flags = boolean(argv[14], "SoftAC");
    level.file_points = static_cast<int>(parse_unsigned(argv[15], "validation file points", 0,
        static_cast<unsigned int>(std::numeric_limits<std::int32_t>::max())));
    level.credits = static_cast<std::int64_t>(parse_unsigned(argv[16], "validation credits", 0,
        static_cast<unsigned int>(std::numeric_limits<std::int32_t>::max())));
    level.user_message = std::string_view(argv[17]) == "-" ? "" : argv[17];
    const std::string database_path = user_database_path(argc, argv, 18);
    renegade::AccountStore accounts(database_path);
    accounts.set_validation_level(level);
    std::cout << "Saved validation level " << level.key << " (" << level.description << ").\n";
    return 0;
}

int add_area(int argc, char** argv) {
    if (argc < 4) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string name(argv[3]);
    std::string database_path = "data/renegade.sqlite3";
    for (int index = 4; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete area option: " + std::string(option));
        }
    }
    renegade::MessageStore messages(database_path);
    messages.create_area(name);
    std::cout << "Created message area " << name << ".\n";
    return 0;
}

int set_message_area_access(int argc, char** argv) {
    if (argc < 8) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view id_text(argv[3]);
    long long area_id{};
    const auto parsed_id = std::from_chars(id_text.data(), id_text.data() + id_text.size(), area_id);
    if (id_text.empty() || parsed_id.ec != std::errc{} ||
        parsed_id.ptr != id_text.data() + id_text.size() || area_id < 1) {
        throw std::invalid_argument("message-area ID must be a positive number");
    }
    const std::string access_acs = argv[4];
    const std::string post_acs = argv[5];
    const std::string mci_acs = argv[6];
    const std::string sysop_acs = argv[7];
    std::string database_path = "data/renegade.sqlite3";
    for (int index = 8; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete area option: " + std::string(option));
        }
    }
    renegade::MessageStore messages(database_path);
    messages.set_area_access(area_id, access_acs == "-" ? "" : access_acs,
        post_acs == "-" ? "" : post_acs, mci_acs == "-" ? "" : mci_acs,
        sysop_acs == "-" ? "" : sysop_acs);
    std::cout << "Updated ACS, PostACS, MCIACS, and SysOpACS for message area " << area_id << ".\n";
    return 0;
}

int set_message_area_force_read(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view id_text(argv[3]);
    long long area_id{};
    const auto parsed_id = std::from_chars(id_text.data(), id_text.data() + id_text.size(), area_id);
    if (id_text.empty() || parsed_id.ec != std::errc{} ||
        parsed_id.ptr != id_text.data() + id_text.size() || area_id < 1) {
        throw std::invalid_argument("message-area ID must be a positive number");
    }
    const std::string_view state(argv[4]);
    if (state != "on" && state != "off") {
        throw std::invalid_argument("forced-scan state must be 'on' or 'off'");
    }
    const std::string database_path = user_database_path(argc, argv, 5);
    renegade::MessageStore messages(database_path);
    messages.set_area_force_read(area_id, state == "on");
    std::cout << "Forced new scans " << state << " for message area " << area_id << ".\n";
    return 0;
}

int set_message_area_password(int argc, char** argv) {
    if (argc < 4) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view id_text(argv[3]);
    long long area_id{};
    const auto parsed = std::from_chars(id_text.data(), id_text.data() + id_text.size(), area_id);
    if (id_text.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != id_text.data() + id_text.size() || area_id < 1) {
        throw std::invalid_argument("message-area ID must be a positive number");
    }
    const std::string database_path = user_database_path(argc, argv, 4);
    std::string password;
    for (;;) {
        password = read_secret("New shared password (1-20 printable bytes; blank clears): ");
        const bool valid = password.size() <= 20 &&
            std::none_of(password.begin(), password.end(), [](unsigned char value) {
                return value < 32 || value == 127;
            });
        if (!valid) {
            std::cerr << "Area passwords must be at most 20 printable bytes. Try again.\n";
            continue;
        }
        const std::string confirmation = read_secret("Repeat password (blank to confirm clearing): ");
        if (password != confirmation) {
            std::cerr << "Passwords did not match. No change was made. Try again.\n";
            continue;
        }
        break;
    }
    renegade::MessageStore messages(database_path);
    messages.set_area_password(area_id, password);
    std::cout << (password.empty() ? "Cleared" : "Updated")
              << " the shared password for message area " << area_id << ".\n";
    return 0;
}

int set_message_area_quote_templates(int argc, char** argv) {
    if (argc < 6) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view id_text(argv[3]);
    long long area_id{};
    const auto parsed_id = std::from_chars(id_text.data(), id_text.data() + id_text.size(), area_id);
    if (id_text.empty() || parsed_id.ec != std::errc{} ||
        parsed_id.ptr != id_text.data() + id_text.size() || area_id < 1) {
        throw std::invalid_argument("message-area ID must be a positive number");
    }
    const std::string_view quote_start = std::string_view(argv[4]) == "-"
        ? std::string_view{} : std::string_view(argv[4]);
    const std::string_view quote_end = std::string_view(argv[5]) == "-"
        ? std::string_view{} : std::string_view(argv[5]);
    const std::string database_path = user_database_path(argc, argv, 6);
    renegade::MessageStore messages(database_path);
    messages.set_area_quote_templates(area_id, quote_start, quote_end);
    std::cout << "Updated reply quote templates for message area " << area_id << ".\n";
    return 0;
}

int set_message_area_real_name_search(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view id_text(argv[3]);
    long long area_id{};
    const auto parsed_id = std::from_chars(id_text.data(), id_text.data() + id_text.size(), area_id);
    if (id_text.empty() || parsed_id.ec != std::errc{} ||
        parsed_id.ptr != id_text.data() + id_text.size() || area_id < 1) {
        throw std::invalid_argument("message-area ID must be a positive number");
    }
    const std::string_view state(argv[4]);
    if (state != "on" && state != "off") {
        throw std::invalid_argument("real-name search state must be 'on' or 'off'");
    }
    const std::string database_path = user_database_path(argc, argv, 5);
    renegade::MessageStore messages(database_path);
    messages.set_area_real_name_search(area_id, state == "on");
    std::cout << "Real-name searches " << state << " for message area " << area_id << ".\n";
    return 0;
}

int set_message_area_taglines(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view id_text(argv[3]);
    long long area_id{};
    const auto parsed = std::from_chars(id_text.data(), id_text.data() + id_text.size(), area_id);
    if (id_text.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != id_text.data() + id_text.size() || area_id < 1) {
        throw std::invalid_argument("message-area ID must be a positive number");
    }
    const std::string_view state(argv[4]);
    if (state != "on" && state != "off") {
        throw std::invalid_argument("tagline setting must be 'on' or 'off'");
    }
    const std::string database_path = user_database_path(argc, argv, 5);
    renegade::MessageStore messages(database_path);
    messages.set_area_taglines_enabled(area_id, state == "on");
    std::cout << "Message-area taglines " << state << " for area " << area_id << ".\n";
    return 0;
}

int set_message_area_text_filter(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view id_text(argv[3]);
    long long area_id{};
    const auto parsed = std::from_chars(id_text.data(), id_text.data() + id_text.size(), area_id);
    if (id_text.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != id_text.data() + id_text.size() || area_id < 1) {
        throw std::invalid_argument("message-area ID must be a positive number");
    }
    const std::string_view state(argv[4]);
    if (state != "on" && state != "off") {
        throw std::invalid_argument("message-area text-filter state must be 'on' or 'off'");
    }
    const std::string database_path = user_database_path(argc, argv, 5);
    renegade::MessageStore messages(database_path);
    messages.set_area_public_text_filter(area_id, state == "on");
    std::cout << "Public-message text filtering " << state << " for area " << area_id << ".\n";
    return 0;
}

int set_message_area_unhidden(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view id_text(argv[3]);
    long long area_id{};
    const auto parsed = std::from_chars(id_text.data(), id_text.data() + id_text.size(), area_id);
    if (id_text.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != id_text.data() + id_text.size() || area_id < 1) {
        throw std::invalid_argument("message-area ID must be a positive number");
    }
    const std::string_view state(argv[4]);
    if (state != "on" && state != "off") {
        throw std::invalid_argument("message-area visibility state must be 'on' or 'off'");
    }
    const std::string database_path = user_database_path(argc, argv, 5);
    renegade::MessageStore messages(database_path);
    messages.set_area_unhidden(area_id, state == "on");
    std::cout << "Message-area visibility without ACS " << state << " for area " << area_id << ".\n";
    return 0;
}

int set_message_area_tearline(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view id_text(argv[3]);
    long long area_id{};
    const auto parsed = std::from_chars(id_text.data(), id_text.data() + id_text.size(), area_id);
    if (id_text.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != id_text.data() + id_text.size() || area_id < 1) {
        throw std::invalid_argument("message-area ID must be a positive number");
    }
    const std::string_view state(argv[4]);
    if (state != "on" && state != "off") {
        throw std::invalid_argument("tearline setting must be 'on' or 'off'");
    }
    const std::string database_path = user_database_path(argc, argv, 5);
    renegade::MessageStore messages(database_path);
    messages.set_area_tearline_enabled(area_id, state == "on");
    std::cout << "Message-area tearline " << state << " for area " << area_id << ".\n";
    return 0;
}

int set_message_area_origin(int argc, char** argv) {
    if (argc < 6) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view id_text(argv[3]);
    long long area_id{};
    const auto parsed = std::from_chars(id_text.data(), id_text.data() + id_text.size(), area_id);
    if (id_text.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != id_text.data() + id_text.size() || area_id < 1) {
        throw std::invalid_argument("message-area ID must be a positive number");
    }
    const std::string_view origin = std::string_view(argv[4]) == "-"
        ? std::string_view{} : std::string_view(argv[4]);
    const std::string_view address = std::string_view(argv[5]) == "-"
        ? std::string_view{} : std::string_view(argv[5]);
    const std::string database_path = user_database_path(argc, argv, 6);
    renegade::MessageStore messages(database_path);
    messages.set_area_origin(area_id, origin, address);
    std::cout << "Updated message-area origin for area " << area_id << ".\n";
    return 0;
}

int set_private_quote_templates(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view quote_start = std::string_view(argv[3]) == "-"
        ? std::string_view{} : std::string_view(argv[3]);
    const std::string_view quote_end = std::string_view(argv[4]) == "-"
        ? std::string_view{} : std::string_view(argv[4]);
    const std::string database_path = user_database_path(argc, argv, 5);
    renegade::MessageStore messages(database_path);
    messages.set_private_quote_templates(quote_start, quote_end);
    std::cout << "Updated private-mail quote templates.\n";
    return 0;
}

int set_message_area_anonymous(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view id_text(argv[3]);
    long long area_id{};
    const auto parsed_id = std::from_chars(id_text.data(), id_text.data() + id_text.size(), area_id);
    if (id_text.empty() || parsed_id.ec != std::errc{} ||
        parsed_id.ptr != id_text.data() + id_text.size() || area_id < 1) {
        throw std::invalid_argument("message-area ID must be a positive number");
    }
    const std::string_view mode_text(argv[4]);
    if (mode_text.size() != 1) {
        throw std::invalid_argument("anonymous mode must be N, Y, F, D, or A");
    }
    renegade::AnonymousMode mode;
    switch (std::toupper(static_cast<unsigned char>(mode_text.front()))) {
    case 'N': mode = renegade::AnonymousMode::Disabled; break;
    case 'Y': mode = renegade::AnonymousMode::Optional; break;
    case 'F': mode = renegade::AnonymousMode::Forced; break;
    case 'D': mode = renegade::AnonymousMode::DearAbby; break;
    case 'A': mode = renegade::AnonymousMode::AnyName; break;
    default: throw std::invalid_argument("anonymous mode must be N, Y, F, D, or A");
    }
    std::string database_path = "data/renegade.sqlite3";
    for (int index = 5; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete area option: " + std::string(option));
        }
    }
    renegade::MessageStore messages(database_path);
    messages.set_area_anonymous_mode(area_id, mode);
    std::cout << "Updated anonymous-posting mode for message area " << area_id << ".\n";
    return 0;
}

int set_message_anonymous_acs(int argc, char** argv) {
    if (argc < 7) {
        print_usage(std::cerr);
        return 2;
    }
    const auto expression = [](const char* value) {
        return std::string_view(value) == "-" ? std::string{} : std::string(value);
    };
    const std::string public_post = expression(argv[3]);
    const std::string public_read = expression(argv[4]);
    const std::string private_post = expression(argv[5]);
    const std::string private_read = expression(argv[6]);
    std::string database_path = "data/renegade.sqlite3";
    for (int index = 7; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete area option: " + std::string(option));
        }
    }
    renegade::MessageStore messages(database_path);
    messages.set_anonymous_acs(public_post, public_read, private_post, private_read);
    std::cout << "Updated global public/private anonymous-post and anonymous-read ACS rules.\n";
    return 0;
}

int set_message_normal_post_acs(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const auto expression = [](const char* value) {
        return std::string_view(value) == "-" ? std::string{} : std::string(value);
    };
    const std::string public_post = expression(argv[3]);
    const std::string private_post = expression(argv[4]);
    std::string database_path = "data/renegade.sqlite3";
    for (int index = 5; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete area option: " + std::string(option));
        }
    }
    renegade::MessageStore messages(database_path);
    messages.set_normal_post_acs(public_post, private_post);
    std::cout << "Updated global public/private posting ACS rules.\n";
    return 0;
}

int set_message_post_limits(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const auto parse_limit = [](const char* value) {
        const std::string_view text(value);
        int result{};
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
        if (text.empty() || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
            result < 0 || result > 255) {
            throw std::invalid_argument("message post limits must be between 0 and 255 per call");
        }
        return result;
    };
    const int public_limit = parse_limit(argv[3]);
    const int private_limit = parse_limit(argv[4]);
    std::string database_path = "data/renegade.sqlite3";
    for (int index = 5; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete area option: " + std::string(option));
        }
    }
    renegade::MessageStore messages(database_path);
    messages.set_post_limits(public_limit, private_limit);
    std::cout << "Updated public/private message limits per call.\n";
    return 0;
}

int set_post_call_ratio(int argc, char** argv) {
    if (argc < 6) {
        print_usage(std::cerr);
        return 2;
    }
    const auto parse_number = [](const char* value, std::string_view label, int maximum) {
        const std::string_view text(value);
        int result{};
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
        if (text.empty() || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
            result < 0 || result > maximum) {
            throw std::invalid_argument(std::string(label) + " is outside its valid range");
        }
        return result;
    };
    const int minimum_level = parse_number(argv[3], "SL_MIN", 255);
    const int maximum_level = parse_number(argv[4], "SL_MAX", 255);
    const int percent = parse_number(argv[5], "PERCENT", 100);
    if (minimum_level > maximum_level) {
        throw std::invalid_argument("SL_MIN must not exceed SL_MAX");
    }
    std::string database_path = "data/renegade.sqlite3";
    for (int index = 6; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete system option: " + std::string(option));
        }
    }
    renegade::MessageStore messages(database_path);
    messages.set_post_ratio_range(minimum_level, maximum_level, percent);
    std::cout << "Updated post-call ratio for security levels " << minimum_level << "-" <<
        maximum_level << ".\n";
    return 0;
}

int configure_signup_question(int argc, char** argv) {
    const bool listing = argc >= 3 && std::string_view(argv[2]) == "signup-questions";
    if ((!listing && argc < 5) || (listing && argc < 3)) {
        print_usage(std::cerr);
        return 2;
    }
    static constexpr std::pair<int, std::string_view> questions[]{
        {2, "Real name"}, {3, "Country"}, {4, "Street address"},
        {5, "City and state"}, {6, "ZIP / postal code"}, {7, "Phone number"},
        {8, "Birth date"}, {9, "Gender"}, {10, "SysOp-defined answer 1"},
        {11, "SysOp-defined answer 2"}, {12, "SysOp-defined answer 3"},
        {14, "Password-recovery answer"}, {16, "ANSI color"},
        {19, "Screen clearing"}, {20, "Page pauses"}, {21, "Hotkey input"},
        {22, "Expert mode"}, {25, "Mailbox open/closed"},
    };
    std::string database_path = "data/renegade.sqlite3";
    if (listing) {
        for (int index = 3; index < argc; ++index) {
            const std::string_view option(argv[index]);
            if (option == "--db" && index + 1 < argc) {
                database_path = argv[++index];
            } else {
                throw std::invalid_argument("unknown or incomplete system option: " + std::string(option));
            }
        }
        renegade::AccountStore accounts(database_path);
        const auto states = accounts.signup_question_states();
        for (const auto& [source_id, label] : questions) {
            std::cout << source_id << '\t' << (states[static_cast<std::size_t>(source_id)] ? "on" : "off")
                      << '\t' << label << '\n';
        }
        std::cout << "100\ton\tSignature (C++ extension)\n";
        return 0;
    }

    const std::string_view id_text(argv[3]);
    int source_id{};
    const auto parsed = std::from_chars(id_text.data(), id_text.data() + id_text.size(), source_id);
    if (id_text.empty() || parsed.ec != std::errc{} || parsed.ptr != id_text.data() + id_text.size() ||
        std::none_of(std::begin(questions), std::end(questions), [source_id](const auto& item) {
            return item.first == source_id;
        })) {
        throw std::invalid_argument("SOURCE_ID must be one of 2-12, 14, 16, 19-22, or 25");
    }
    const std::string_view state(argv[4]);
    if (state != "on" && state != "off") {
        throw std::invalid_argument("signup-question state must be 'on' or 'off'");
    }
    for (int index = 5; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete system option: " + std::string(option));
        }
    }
    renegade::AccountStore accounts(database_path);
    accounts.set_signup_question_enabled(source_id, state == "on");
    std::cout << "Signup question " << source_id << ' ' << state << ".\n";
    return 0;
}

int set_recovery_question(int argc, char** argv) {
    if (argc < 4) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string question = std::string_view(argv[3]) == "-" ? "" : argv[3];
    std::string database_path = "data/renegade.sqlite3";
    for (int index = 4; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete system option: " + std::string(option));
        }
    }
    renegade::AccountStore accounts(database_path);
    accounts.set_forgot_password_question(question);
    std::cout << (question.empty() ? "Cleared" : "Set") << " the password-recovery question.\n";
    return 0;
}

int set_custom_user_question(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view number_text(argv[3]);
    int number{};
    const auto parsed = std::from_chars(number_text.data(), number_text.data() + number_text.size(), number);
    if (number_text.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != number_text.data() + number_text.size() || number < 1 || number > 3) {
        throw std::invalid_argument("custom user question number must be 1, 2, or 3");
    }
    const std::string prompt = std::string_view(argv[4]) == "-" ? "" : argv[4];
    std::string database_path = "data/renegade.sqlite3";
    for (int index = 5; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete system option: " + std::string(option));
        }
    }
    renegade::AccountStore accounts(database_path);
    accounts.set_custom_user_question(number, prompt);
    std::cout << (prompt.empty() ? "Cleared" : "Set") << " SysOp-defined user question "
              << number << ".\n";
    return 0;
}

int set_submission_acs(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const auto expression = [](const char* value) {
        return std::string_view(value) == "-" ? std::string{} : std::string(value);
    };
    const std::string quote_acs = expression(argv[3]);
    const std::string one_liner_acs = expression(argv[4]);
    std::string database_path = "data/renegade.sqlite3";
    for (int index = 5; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete system option: " + std::string(option));
        }
    }
    renegade::MessageStore messages(database_path);
    messages.set_submission_acs(quote_acs, one_liner_acs);
    std::cout << "Updated quote and one-liner submission ACS rules.\n";
    return 0;
}

int set_invisibility_acs(int argc, char** argv) {
    if (argc < 4) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string expression = std::string_view(argv[3]) == "-" ? "" : argv[3];
    std::string database_path = "data/renegade.sqlite3";
    for (int index = 4; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete system option: " + std::string(option));
        }
    }
    renegade::MessageStore messages(database_path);
    messages.set_invisibility_acs(expression);
    std::cout << "Updated invisible-mode access ACS.\n";
    return 0;
}

int set_validation_eligibility(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view state(argv[3]);
    if (state != "on" && state != "off") {
        throw std::invalid_argument("validation state must be on or off");
    }
    const std::string_view level_text(argv[4]);
    int new_level{};
    const auto parsed = std::from_chars(level_text.data(), level_text.data() + level_text.size(), new_level);
    if (level_text.empty() || parsed.ec != std::errc{} || parsed.ptr != level_text.data() + level_text.size() ||
        new_level < 0 || new_level > 255) {
        throw std::invalid_argument("NEWSL must be between 0 and 255");
    }
    std::string database_path = "data/renegade.sqlite3";
    for (int index = 5; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete system option: " + std::string(option));
        }
    }
    renegade::MessageStore messages(database_path);
    messages.set_validation_eligibility(state == "on", new_level);
    std::cout << "Updated validation eligibility; NewSL=" << new_level << ".\n";
    return 0;
}

int set_private_mail_waiting_limits(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const auto parse_limit = [](const char* value) {
        const std::string_view text(value);
        int result{};
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
        if (text.empty() || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
            result < 0 || result > 255) {
            throw std::invalid_argument("private-mail waiting limits must be between 0 and 255");
        }
        return result;
    };
    const int normal_limit = parse_limit(argv[3]);
    const int sysop_limit = parse_limit(argv[4]);
    std::string database_path = "data/renegade.sqlite3";
    for (int index = 5; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete area option: " + std::string(option));
        }
    }
    renegade::MessageStore messages(database_path);
    messages.set_private_mail_waiting_limits(normal_limit, sysop_limit);
    std::cout << "Updated normal/SysOp private-mail waiting limits.\n";
    return 0;
}

int set_message_credit_costs(int argc, char** argv) {
    if (argc < 5) {
        print_usage(std::cerr);
        return 2;
    }
    const auto parse_cost = [](const char* value) {
        const std::string_view text(value);
        int result{};
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
        if (text.empty() || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
            result < -32767 || result > 32767) {
            throw std::invalid_argument("message credit costs must be between -32767 and 32767");
        }
        return result;
    };
    const int public_cost = parse_cost(argv[3]);
    const int private_cost = parse_cost(argv[4]);
    std::string database_path = "data/renegade.sqlite3";
    for (int index = 5; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete area option: " + std::string(option));
        }
    }
    renegade::MessageStore messages(database_path);
    messages.set_credit_costs(public_cost, private_cost);
    std::cout << "Updated public/private message credit costs.\n";
    return 0;
}

int file_area_command(int argc, char** argv) {
    if (argc < 3) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view action(argv[2]);
    if (action != "add" && action != "rename" && action != "list" && action != "access" &&
        action != "unvalidated-access" && action != "validation" && action != "no-ratio" && action != "ratios" &&
        action != "level-ratios" && action != "level-ratios-clear" &&
        action != "point-rules" && action != "points" && action != "daily-limits" &&
        action != "move" && action != "rename-file" && action != "downloads" &&
        action != "request" && action != "owner" && action != "date" && action != "size" && action != "publish" &&
        action != "remove" && action != "delete" && action != "describe" &&
        action != "describe-extended") {
        throw std::invalid_argument("unsupported file-area action");
    }
    std::string name;
    std::string owner;
    std::string filename;
    std::string new_filename;
    std::string new_owner;
    std::string file_date;
    std::string description;
    std::string access_acs;
    std::string download_acs;
    std::string upload_acs;
    std::string no_ratio_acs;
    int area_id{};
    int target_area_id{};
    bool delete_area_storage = false;
    bool no_ratio_enabled = false;
    bool validate_all_files = false;
    bool request_only = false;
    unsigned int download_count_ratio = 0;
    unsigned int download_kib_ratio = 0;
    bool download_ratios_enabled = true;
    unsigned int file_download_count = 0;
    unsigned int file_points = 0;
    unsigned int point_base_size_kib = 0;
    unsigned int point_upload_compensation = 1;
    unsigned int point_reward_ratio = 0;
    bool file_points_enabled = false;
    unsigned int ratio_security_min = 0;
    unsigned int ratio_security_max = 0;
    unsigned int level_download_count_ratio = 0;
    unsigned int level_download_kib_ratio = 0;
    bool daily_limits_enabled = false;
    unsigned int daily_security_min = 0;
    unsigned int daily_security_max = 0;
    unsigned int daily_max_files = 0;
    unsigned int daily_max_kib = 0;
    int option_index = 3;
    if (action == "add") {
        if (argc < 4) {
            print_usage(std::cerr);
            return 2;
        }
        name = argv[3];
        option_index = 4;
    } else if (action == "rename") {
        if (argc < 5) {
            print_usage(std::cerr);
            return 2;
        }
        area_id = static_cast<int>(parse_unsigned(argv[3], "file-area ID", 1, INT_MAX));
        name = argv[4];
        option_index = 5;
    } else if (action == "remove") {
        if (argc < 4) {
            print_usage(std::cerr);
            return 2;
        }
        area_id = static_cast<int>(parse_unsigned(argv[3], "file-area ID", 1, INT_MAX));
        option_index = 4;
    } else if (action == "publish") {
        if (argc < 6) {
            print_usage(std::cerr);
            return 2;
        }
        owner = argv[3];
        filename = argv[4];
        area_id = static_cast<int>(parse_unsigned(argv[5], "file-area ID", 1, INT_MAX));
        option_index = 6;
    } else if (action == "delete") {
        if (argc < 5) {
            print_usage(std::cerr);
            return 2;
        }
        owner = argv[3];
        filename = argv[4];
        option_index = 5;
    } else if (action == "access") {
        if (argc < 6) {
            print_usage(std::cerr);
            return 2;
        }
        area_id = static_cast<int>(parse_unsigned(argv[3], "file-area ID", 1, INT_MAX));
        access_acs = argv[4];
        download_acs = argv[5];
        if (argc > 6 && std::string_view(argv[6]).substr(0, 2) != "--") {
            upload_acs = argv[6];
            option_index = 7;
        } else {
            option_index = 6;
        }
    } else if (action == "unvalidated-access") {
        if (argc < 5) {
            print_usage(std::cerr);
            return 2;
        }
        access_acs = argv[3];
        download_acs = argv[4];
        option_index = 5;
    } else if (action == "validation") {
        if (argc < 5) {
            print_usage(std::cerr);
            return 2;
        }
        access_acs = argv[3];
        const std::string_view requested(argv[4]);
        if (requested != "on" && requested != "off") {
            throw std::invalid_argument("validate-all-files state must be 'on' or 'off'");
        }
        validate_all_files = requested == "on";
        option_index = 5;
    } else if (action == "no-ratio") {
        if (argc < 5) {
            print_usage(std::cerr);
            return 2;
        }
        area_id = static_cast<int>(parse_unsigned(argv[3], "file-area ID", 1, INT_MAX));
        const std::string_view requested(argv[4]);
        if (requested != "on" && requested != "off") {
            throw std::invalid_argument("file-area no-ratio state must be 'on' or 'off'");
        }
        no_ratio_enabled = requested == "on";
        option_index = 5;
    } else if (action == "ratios") {
        if (argc >= 7 && (std::string_view(argv[3]) == "on" || std::string_view(argv[3]) == "off")) {
            download_ratios_enabled = std::string_view(argv[3]) == "on";
            download_count_ratio = parse_unsigned(argv[4], "download-count ratio", 0, 2147483647U);
            download_kib_ratio = parse_unsigned(argv[5], "download-KiB ratio", 0, 2147483647U);
            no_ratio_acs = argv[6];
            option_index = 7;
        } else if (argc >= 6) {
            download_count_ratio = parse_unsigned(argv[3], "download-count ratio", 0, 2147483647U);
            download_kib_ratio = parse_unsigned(argv[4], "download-KiB ratio", 0, 2147483647U);
            no_ratio_acs = argv[5];
            option_index = 6;
        } else {
            print_usage(std::cerr);
            return 2;
        }
    } else if (action == "level-ratios") {
        if (argc < 7) {
            print_usage(std::cerr);
            return 2;
        }
        ratio_security_min = parse_unsigned(argv[3], "minimum security level", 0, 255);
        ratio_security_max = parse_unsigned(argv[4], "maximum security level", 0, 255);
        if (ratio_security_min > ratio_security_max) {
            throw std::invalid_argument("minimum security level must not exceed maximum security level");
        }
        level_download_count_ratio = parse_unsigned(argv[5], "download-count ratio", 0, 2147483647U);
        level_download_kib_ratio = parse_unsigned(argv[6], "download-KiB ratio", 0, 2147483647U);
        option_index = 7;
    } else if (action == "level-ratios-clear") {
        if (argc < 5) {
            print_usage(std::cerr);
            return 2;
        }
        ratio_security_min = parse_unsigned(argv[3], "minimum security level", 0, 255);
        ratio_security_max = parse_unsigned(argv[4], "maximum security level", 0, 255);
        if (ratio_security_min > ratio_security_max) {
            throw std::invalid_argument("minimum security level must not exceed maximum security level");
        }
        option_index = 5;
    } else if (action == "point-rules") {
        if (argc < 8) {
            print_usage(std::cerr);
            return 2;
        }
        const std::string_view requested(argv[3]);
        if (requested != "on" && requested != "off") {
            throw std::invalid_argument("file-point state must be 'on' or 'off'");
        }
        file_points_enabled = requested == "on";
        point_base_size_kib = parse_unsigned(argv[4], "file-point base size", 0, 32767);
        point_upload_compensation = parse_unsigned(argv[5], "upload point compensation", 0, 32767);
        point_reward_ratio = parse_unsigned(argv[6], "file-owner reward ratio", 0, 32767);
        no_ratio_acs = argv[7];
        option_index = 8;
    } else if (action == "daily-limits") {
        if (argc < 8) {
            print_usage(std::cerr);
            return 2;
        }
        const std::string_view requested(argv[3]);
        if (requested != "on" && requested != "off") {
            throw std::invalid_argument("daily file-limit state must be 'on' or 'off'");
        }
        daily_limits_enabled = requested == "on";
        daily_security_min = parse_unsigned(argv[4], "minimum security level", 0, 255);
        daily_security_max = parse_unsigned(argv[5], "maximum security level", 0, 255);
        daily_max_files = parse_unsigned(argv[6], "daily file limit", 0, INT_MAX);
        daily_max_kib = parse_unsigned(argv[7], "daily KiB limit", 0, INT_MAX);
        option_index = 8;
    } else if (action == "move") {
        if (argc < 7) {
            print_usage(std::cerr);
            return 2;
        }
        owner = argv[3];
        area_id = static_cast<int>(parse_unsigned(argv[4], "source file-area ID", 1, INT_MAX));
        filename = argv[5];
        target_area_id = static_cast<int>(parse_unsigned(argv[6], "target file-area ID", 1, INT_MAX));
        option_index = 7;
    } else if (action == "rename-file") {
        if (argc < 7) {
            print_usage(std::cerr);
            return 2;
        }
        owner = argv[3];
        area_id = static_cast<int>(parse_unsigned(argv[4], "file-area ID", 1, INT_MAX));
        filename = argv[5];
        new_filename = argv[6];
        option_index = 7;
    } else if (action == "downloads") {
        if (argc < 7) {
            print_usage(std::cerr);
            return 2;
        }
        owner = argv[3];
        area_id = static_cast<int>(parse_unsigned(argv[4], "file-area ID", 1, INT_MAX));
        filename = argv[5];
        file_download_count = parse_unsigned(argv[6], "file download count", 0, INT_MAX);
        option_index = 7;
    } else if (action == "points") {
        if (argc < 7) {
            print_usage(std::cerr);
            return 2;
        }
        owner = argv[3];
        area_id = static_cast<int>(parse_unsigned(argv[4], "file-area ID", 1, INT_MAX));
        filename = argv[5];
        file_points = parse_unsigned(argv[6], "file points", 0, 32767);
        option_index = 7;
    } else if (action == "request") {
        if (argc < 7) {
            print_usage(std::cerr);
            return 2;
        }
        owner = argv[3];
        area_id = static_cast<int>(parse_unsigned(argv[4], "file-area ID", 1, INT_MAX));
        filename = argv[5];
        const std::string_view requested(argv[6]);
        if (requested != "on" && requested != "off") {
            throw std::invalid_argument("request-file state must be 'on' or 'off'");
        }
        request_only = requested == "on";
        option_index = 7;
    } else if (action == "owner") {
        if (argc < 7) {
            print_usage(std::cerr);
            return 2;
        }
        owner = argv[3];
        area_id = static_cast<int>(parse_unsigned(argv[4], "file-area ID", 1, INT_MAX));
        filename = argv[5];
        new_owner = argv[6];
        option_index = 7;
    } else if (action == "date") {
        if (argc < 7) {
            print_usage(std::cerr);
            return 2;
        }
        owner = argv[3];
        area_id = static_cast<int>(parse_unsigned(argv[4], "file-area ID", 1, INT_MAX));
        filename = argv[5];
        file_date = argv[6];
        option_index = 7;
    } else if (action == "size") {
        if (argc < 6) {
            print_usage(std::cerr);
            return 2;
        }
        owner = argv[3];
        area_id = static_cast<int>(parse_unsigned(argv[4], "file-area ID", 1, INT_MAX));
        filename = argv[5];
        option_index = 6;
    } else if (action == "describe" || action == "describe-extended") {
        if (argc < 6) {
            print_usage(std::cerr);
            return 2;
        }
        area_id = static_cast<int>(parse_unsigned(argv[3], "file-area ID", 1, INT_MAX));
        filename = argv[4];
        description = argv[5];
        option_index = 6;
    }
    std::string database_path = "data/renegade.sqlite3";
    std::string root_path = "files";
    for (int index = option_index; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (action == "remove" && option == "--delete-files") {
            delete_area_storage = true;
        } else if (option == "--db" && index + 1 < argc) {
            database_path = argv[++index];
        } else if (option == "--root" && index + 1 < argc) {
            root_path = argv[++index];
        } else {
            throw std::invalid_argument("unknown or incomplete file-area option: " + std::string(option));
        }
    }
    renegade::AccountStore accounts(database_path);
    accounts.initialize();
    renegade::FileStore files(database_path, root_path);
    if (action == "add") {
        files.create_area(name);
        std::cout << "Created file area " << name << ".\n";
        return 0;
    }
    if (action == "access") {
        files.set_area_access(area_id, access_acs == "-" ? "" : access_acs,
            download_acs == "-" ? "" : download_acs,
            upload_acs == "-" ? "" : upload_acs);
        std::cout << "Updated ACS, DLACS, and ULACS for file area " << area_id << ".\n";
        return 0;
    }
    if (action == "unvalidated-access") {
        files.set_unvalidated_access(access_acs == "-" ? "" : access_acs,
            download_acs == "-" ? "" : download_acs);
        std::cout << "Updated SeeUnVal and DLUnVal ACS rules.\n";
        return 0;
    }
    if (action == "validation") {
        files.set_upload_validation_rules(access_acs == "-" ? "" : access_acs, validate_all_files);
        std::cout << "Updated upload auto-validation ACS and validate-all-files policy.\n";
        return 0;
    }
    if (action == "no-ratio") {
        files.set_area_no_ratio(area_id, no_ratio_enabled);
        std::cout << (no_ratio_enabled ? "Disabled" : "Enabled")
                  << " upload/download ratio checks for file area " << area_id << ".\n";
        return 0;
    }
    if (action == "ratios") {
        files.set_download_ratios(download_ratios_enabled, download_count_ratio, download_kib_ratio,
            no_ratio_acs == "-" ? "" : no_ratio_acs);
        std::cout << (download_ratios_enabled ? "Enabled" : "Disabled")
                  << " download ratios and updated NoDLRatio ACS.\n";
        return 0;
    }
    if (action == "level-ratios") {
        files.set_download_level_ratios(static_cast<int>(ratio_security_min),
            static_cast<int>(ratio_security_max), level_download_count_ratio, level_download_kib_ratio);
        std::cout << "Updated download ratios for security levels " << ratio_security_min
                  << " through " << ratio_security_max << ".\n";
        return 0;
    }
    if (action == "level-ratios-clear") {
        files.clear_download_level_ratios(static_cast<int>(ratio_security_min),
            static_cast<int>(ratio_security_max));
        std::cout << "Cleared download-ratio overrides for security levels " << ratio_security_min
                  << " through " << ratio_security_max << ".\n";
        return 0;
    }
    if (action == "point-rules") {
        files.set_file_point_rules(file_points_enabled, point_base_size_kib,
            point_upload_compensation, point_reward_ratio, no_ratio_acs == "-" ? "%" : no_ratio_acs);
        std::cout << "Updated file-point charging, upload compensation, owner rewards, and NoFileCredits ACS.\n";
        return 0;
    }
    if (action == "daily-limits") {
        files.set_download_daily_limits(daily_limits_enabled,
            static_cast<int>(daily_security_min), static_cast<int>(daily_security_max),
            daily_max_files, daily_max_kib);
        std::cout << (daily_limits_enabled ? "Enabled" : "Disabled")
                  << " per-security-level daily download limits for SL " << daily_security_min
                  << " through " << daily_security_max << ".\n";
        return 0;
    }
    if (action == "move") {
        files.move_public_file(owner, area_id, filename, target_area_id);
        std::cout << "Moved " << filename << " from area " << area_id
                  << " to area " << target_area_id << ".\n";
        return 0;
    }
    if (action == "rename-file") {
        files.rename_public_file(owner, area_id, filename, new_filename);
        std::cout << "Renamed " << filename << " to " << new_filename
                  << " in area " << area_id << ".\n";
        return 0;
    }
    if (action == "downloads") {
        files.set_download_count(owner, area_id, filename, file_download_count);
        std::cout << "Set the completed-download count for " << filename
                  << " to " << file_download_count << ".\n";
        return 0;
    }
    if (action == "points") {
        files.set_file_points(owner, area_id, filename, file_points);
        std::cout << "Set " << filename << " file-point cost to " << file_points << ".\n";
        return 0;
    }
    if (action == "request") {
        files.set_file_request_only(owner, area_id, filename, request_only);
        std::cout << (request_only ? "Marked " : "Made ") << filename
                  << (request_only ? " request-only." : " available for download again.") << "\n";
        return 0;
    }
    if (action == "owner") {
        files.set_file_owner(owner, area_id, filename, new_owner);
        std::cout << "Assigned " << filename << " to " << new_owner << ".\n";
        return 0;
    }
    if (action == "date") {
        files.set_file_date(owner, area_id, filename, file_date);
        std::cout << "Updated the upload date for " << filename << ".\n";
        return 0;
    }
    if (action == "size") {
        const std::uint64_t size = files.refresh_file_size(owner, area_id, filename);
        std::cout << "Updated " << filename << " to " << size << " bytes.\n";
        return 0;
    }
    if (action == "rename") {
        files.rename_area(area_id, name);
        std::cout << "Renamed file area " << area_id << " to " << name << ".\n";
        return 0;
    }
    if (action == "remove") {
        const renegade::RemovedFileArea removed = files.remove_area(area_id, delete_area_storage);
        std::cout << "Removed file area " << area_id << " (" << removed.name << "). ";
        if (removed.storage_cleanup_pending) {
            std::cout << "Storage cleanup is pending at " << removed.storage_path << ".\n";
        } else if (!removed.storage_path.empty()) {
            std::cout << "Stored files were retained at " << removed.storage_path << ".\n";
        } else {
            std::cout << "Area storage was removed.\n";
        }
        return 0;
    }
    if (action == "publish") {
        files.publish_upload(owner, filename, area_id);
        std::cout << "Published " << owner << '/' << filename << " into file area " << area_id << ".\n";
        return 0;
    }
    if (action == "delete") {
        files.delete_upload(owner, filename);
        std::cout << "Deleted incoming upload " << owner << '/' << filename << ".\n";
        return 0;
    }
    if (action == "describe") {
        files.set_description(area_id, filename, description);
        std::cout << "Updated description for " << filename << " in file area " << area_id << ".\n";
        return 0;
    }
    if (action == "describe-extended") {
        files.set_extended_description(area_id, filename, description);
        std::cout << "Updated extended description for " << filename << " in file area " << area_id << ".\n";
        return 0;
    }
    const auto areas = files.areas();
    std::cout << "ID\tName\tFiles\tBytes\tACS\tDLACS\tULACS\n";
    for (const auto& area : areas) {
        std::cout << area.id << '\t' << area.name << '\t' << area.file_count
                  << '\t' << area.total_bytes << '\t'
                  << (area.access_acs.empty() ? "*" : area.access_acs) << '\t'
                  << (area.download_acs.empty() ? "*" : area.download_acs) << '\t'
                  << (area.upload_acs.empty() ? "*" : area.upload_acs) << '\n';
    }
    return 0;
}

int serve(int argc, char** argv) {
    renegade::ServerConfig config;
    for (int index = 2; index < argc; ++index) {
        const std::string_view option(argv[index]);
        if (option == "--allow-signup") {
            config.allow_signup = true;
            continue;
        }
        if (index + 1 >= argc) {
            throw std::invalid_argument("missing value for " + std::string(option));
        }
        const std::string_view value(argv[++index]);
        if (option == "--bind") {
            config.bind_address = value;
        } else if (option == "--port") {
            config.port = parse_unsigned(value, "port", 1, 65535);
        } else if (option == "--host-key") {
            config.host_key_path = value;
        } else if (option == "--db") {
            config.database_path = value;
        } else if (option == "--file-dir") {
            config.file_directory = value;
        } else if (option == "--entrance-art") {
            config.entrance_art_path = value;
        } else if (option == "--new-caller-art") {
            config.new_caller_art_path = value;
        } else if (option == "--welcome-art") {
            config.welcome_art_path = value;
        } else if (option == "--sysop-art") {
            config.sysop_art_path = value;
        } else if (option == "--profile-art") {
            config.profile_art_path = value;
        } else if (option == "--time-bank-art") {
            config.time_bank_art_path = value;
        } else if (option == "--once-only-art") {
            config.once_only_art_path = value;
        } else if (option == "--birthday-art") {
            config.birthday_art_path = value;
        } else if (option == "--birthday-late-art") {
            config.birthday_late_art_path = value;
        } else if (option == "--nodes-art") {
            config.nodes_art_path = value;
        } else if (option == "--callers-art") {
            config.callers_art_path = value;
        } else if (option == "--stats-art") {
            config.stats_art_path = value;
        } else if (option == "--help-art") {
            config.help_art_path = value;
        } else if (option == "--bbs-art") {
            config.bbs_art_path = value;
        } else if (option == "--file-areas-art") {
            config.file_areas_art_path = value;
        } else if (option == "--chat-art") {
            config.chat_art_path = value;
        } else if (option == "--bulletin-art") {
            config.bulletin_art_path = value;
        } else if (option == "--polls-art") {
            config.polls_art_path = value;
        } else if (option == "--auto-message-art") {
            config.auto_message_art_path = value;
        } else if (option == "--quotes-art") {
            config.quotes_art_path = value;
        } else if (option == "--one-liners-art") {
            config.one_liners_art_path = value;
        } else if (option == "--uploads-art") {
            config.uploads_art_path = value;
        } else if (option == "--quote-review-art") {
            config.quote_review_art_path = value;
        } else if (option == "--new-files-art") {
            config.new_files_art_path = value;
        } else if (option == "--file-validation-art") {
            config.file_validation_art_path = value;
        } else if (option == "--download-queue-art") {
            config.download_queue_art_path = value;
        } else if (option == "--archive-art") {
            config.archive_art_path = value;
        } else if (option == "--message-move-art") {
            config.message_move_art_path = value;
        } else if (option == "--message-search-art") {
            config.message_search_art_path = value;
        } else if (option == "--message-scan-art") {
            config.message_scan_art_path = value;
        } else if (option == "--new-messages-art") {
            config.unread_messages_art_path = value;
        } else if (option == "--private-reader-art") {
            config.private_reader_art_path = value;
        } else if (option == "--sysop-accounts-art") {
            config.sysop_accounts_art_path = value;
        } else if (option == "--sysop-account-art") {
            config.sysop_account_art_path = value;
        } else if (option == "--sysop-areas-art") {
            config.sysop_areas_art_path = value;
        } else if (option == "--sysop-audit-art") {
            config.sysop_audit_art_path = value;
        } else if (option == "--signup-questions-art") {
            config.signup_questions_art_path = value;
        } else if (option == "--validation-levels-art") {
            config.validation_levels_art_path = value;
        } else if (option == "--message-art") {
            config.message_art_path = value;
        } else if (option == "--areas-art") {
            config.areas_art_path = value;
        } else if (option == "--board-art") {
            config.board_art_path = value;
        } else if (option == "--mailbox-art") {
            config.mailbox_art_path = value;
        } else if (option == "--reader-art") {
            config.reader_art_path = value;
        } else if (option == "--editor-art") {
            config.editor_art_path = value;
        } else if (option == "--art-dir") {
            config.art_directory = value;
        } else if (option == "--bulletin-dir") {
            config.bulletin_directory = value;
        } else if (option == "--quote-dir") {
            config.quote_directory = value;
        } else if (option == "--tagline-dir") {
            config.tagline_directory = value;
        } else if (option == "--nodes") {
            config.max_nodes = static_cast<int>(parse_unsigned(value, "node count", 1, 32));
        } else if (option == "--connections") {
            config.max_connections = static_cast<int>(parse_unsigned(value, "connection count", 1, 64));
        } else if (option == "--idle-timeout") {
            config.idle_timeout_seconds = parse_unsigned(value, "idle timeout", 0, 86400);
        } else if (option == "--birthday-check-frequency") {
            config.birthday_check_frequency = parse_unsigned(value, "birthday check frequency", 0, 32767);
        } else if (option == "--session-time-limit") {
            config.session_time_limit_minutes = parse_unsigned(value, "session time limit", 0, 32767);
        } else if (option == "--time-bank-max") {
            config.time_bank_max_minutes = parse_unsigned(value, "time bank maximum", 0, 32767);
        } else if (option == "--time-bank-deposit-day") {
            config.time_bank_deposit_daily_limit = parse_unsigned(value, "daily time bank deposit limit", 0, 32767);
        } else if (option == "--time-bank-withdraw-day") {
            config.time_bank_withdrawal_daily_limit = parse_unsigned(value, "daily time bank withdrawal limit", 0, 32767);
        } else if (option == "--auth-failures") {
            config.auth_failures_per_address = parse_unsigned(value, "auth failure limit", 1, 100);
        } else if (option == "--auth-window") {
            config.auth_failure_window_seconds = parse_unsigned(value, "auth failure window", 30, 86400);
        } else {
            throw std::invalid_argument("unknown server option: " + std::string(option));
        }
    }
    return renegade::run_server(config);
}

int configure_scheduled_event(int argc, char** argv) {
    if (argc < 4) {
        print_usage(std::cerr);
        return 2;
    }
    const std::string_view operation(argv[3]);
    if (operation == "list") {
        const std::string database_path = user_database_path(argc, argv, 4);
        renegade::CommunityStore community(database_path);
        const auto events = community.scheduled_events();
        if (events.empty()) {
            std::cout << "No scheduled events are configured.\n";
            return 0;
        }
        for (const renegade::ScheduledEvent& event : events) {
            const int start_hour = event.start_minute / 60;
            const int start_minute = event.start_minute % 60;
            const int finish_hour = event.finish_minute / 60;
            const int finish_minute = event.finish_minute % 60;
            std::cout << event.slot << ". " << event.description << " [" << event.type << "] "
                      << (event.active ? "active" : "inactive") << " ";
            if (event.monthly) {
                std::cout << "monthly day " << event.day_of_month;
            } else {
                std::cout << "weekly mask " << event.day_mask;
            }
            std::cout << ' ' << std::setfill('0') << std::setw(2) << start_hour << ':'
                      << std::setw(2) << start_minute << "-" << std::setw(2) << finish_hour
                      << ':' << std::setw(2) << finish_minute << std::setfill(' ')
                      << " node=" << event.node << " ACS="
                      << (event.access_acs.empty() ? "-" : event.access_acs) << '\n';
        }
        return 0;
    }
    if (operation == "delete") {
        if (argc < 5) {
            print_usage(std::cerr);
            return 2;
        }
        const int slot = static_cast<int>(parse_unsigned(argv[4], "event slot", 1, 10));
        const std::string database_path = user_database_path(argc, argv, 5);
        renegade::CommunityStore(database_path).delete_scheduled_event(slot);
        std::cout << "Deleted event slot " << slot << ".\n";
        return 0;
    }
    if (operation != "set" || argc < 13) {
        print_usage(std::cerr);
        return 2;
    }
    renegade::ScheduledEvent event;
    event.slot = static_cast<int>(parse_unsigned(argv[4], "event slot", 1, 10));
    event.description = argv[5];
    event.type = argv[6];
    const std::string_view active(argv[7]);
    if (active != "on" && active != "off") {
        throw std::invalid_argument("event active state must be on or off");
    }
    event.active = active == "on";
    const std::string_view schedule(argv[8]);
    if (schedule == "daily") {
        event.day_mask = 127;
    } else if (schedule.starts_with("weekly:")) {
        event.day_mask = static_cast<int>(parse_unsigned(
            schedule.substr(7), "weekday bit mask", 1, 127));
    } else if (schedule.starts_with("monthly:")) {
        event.monthly = true;
        event.day_of_month = static_cast<int>(parse_unsigned(
            schedule.substr(8), "monthly day", 1, 31));
    } else {
        throw std::invalid_argument("schedule must be daily, weekly:MASK, or monthly:DAY");
    }
    event.start_minute = parse_event_time(argv[9]);
    event.finish_minute = parse_event_time(argv[10]);
    const std::string_view access(argv[11]);
    event.access_acs = access == "-" ? std::string{} : std::string(access);
    if (!renegade::valid_legacy_acs(event.access_acs)) {
        throw std::invalid_argument("event ACS rule is invalid");
    }
    event.node = static_cast<int>(parse_unsigned(argv[12], "event node", 0, 32));
    const std::string database_path = user_database_path(argc, argv, 13);
    renegade::CommunityStore(database_path).set_scheduled_event(event);
    std::cout << "Saved event slot " << event.slot << ".\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    (void)::umask(0077);
    if (argc < 2 || std::string_view(argv[1]) == "--help" || std::string_view(argv[1]) == "-h") {
        print_usage(std::cout);
        return argc < 2 ? 0 : 0;
    }

    try {
        const std::string_view command(argv[1]);
        if (command == "user" && argc >= 3 && std::string_view(argv[2]) == "add") {
            return add_user(argc, argv);
        }
        if (command == "user" && argc >= 3 && std::string_view(argv[2]) == "password") {
            return change_user_password(argc, argv);
        }
        if (command == "user" && argc >= 3 && std::string_view(argv[2]) == "list") {
            return list_users(argc, argv);
        }
        if (command == "user" && argc >= 3 && std::string_view(argv[2]) == "disable") {
            return set_user_enabled(argc, argv, false);
        }
        if (command == "user" && argc >= 3 && std::string_view(argv[2]) == "enable") {
            return set_user_enabled(argc, argv, true);
        }
        if (command == "user" && argc >= 3 && std::string_view(argv[2]) == "sysop") {
            return set_user_sysop(argc, argv);
        }
        if (command == "user" && argc >= 3 && std::string_view(argv[2]) == "levels") {
            return set_user_security_levels(argc, argv);
        }
        if (command == "user" && argc >= 3 && std::string_view(argv[2]) == "flags") {
            return set_user_acs_flags(argc, argv);
        }
        if (command == "user" && argc >= 3 && std::string_view(argv[2]) == "credits") {
            return set_user_credits(argc, argv);
        }
        if (command == "user" && argc >= 3 && std::string_view(argv[2]) == "file-points") {
            return set_user_file_points(argc, argv);
        }
        if (command == "user" && argc >= 3 && std::string_view(argv[2]) == "mailbox") {
            return set_user_mailbox(argc, argv);
        }
        if (command == "user" && argc >= 3 && std::string_view(argv[2]) == "expiration") {
            return set_user_expiration(argc, argv);
        }
        if (command == "user" && argc >= 3 && std::string_view(argv[2]) == "validate") {
            return set_user_validation_level(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "add") {
            return add_area(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "access") {
            return set_message_area_access(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "force-read") {
            return set_message_area_force_read(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "password") {
            return set_message_area_password(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "quote") {
            return set_message_area_quote_templates(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "real-names") {
            return set_message_area_real_name_search(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "tagline") {
            return set_message_area_taglines(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "filter") {
            return set_message_area_text_filter(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "unhidden") {
            return set_message_area_unhidden(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "tearline") {
            return set_message_area_tearline(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "origin") {
            return set_message_area_origin(argc, argv);
        }
        if (command == "mail" && argc >= 3 && std::string_view(argv[2]) == "quote") {
            return set_private_quote_templates(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "anonymous") {
            return set_message_area_anonymous(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "anon-acs") {
            return set_message_anonymous_acs(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "post-acs") {
            return set_message_normal_post_acs(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "post-limits") {
            return set_message_post_limits(argc, argv);
        }
        if (command == "system" && argc >= 3 && std::string_view(argv[2]) == "post-ratio") {
            return set_post_call_ratio(argc, argv);
        }
        if (command == "system" && argc >= 3 && std::string_view(argv[2]) == "event") {
            return configure_scheduled_event(argc, argv);
        }
        if (command == "system" && argc >= 3 && std::string_view(argv[2]) == "signup-question") {
            return configure_signup_question(argc, argv);
        }
        if (command == "system" && argc >= 3 && std::string_view(argv[2]) == "signup-questions") {
            return configure_signup_question(argc, argv);
        }
        if (command == "system" && argc >= 3 && std::string_view(argv[2]) == "recovery-question") {
            return set_recovery_question(argc, argv);
        }
        if (command == "system" && argc >= 3 && std::string_view(argv[2]) == "user-question") {
            return set_custom_user_question(argc, argv);
        }
        if (command == "system" && argc >= 3 && std::string_view(argv[2]) == "submission-acs") {
            return set_submission_acs(argc, argv);
        }
        if (command == "system" && argc >= 3 && std::string_view(argv[2]) == "invisibility-acs") {
            return set_invisibility_acs(argc, argv);
        }
        if (command == "system" && argc >= 3 && std::string_view(argv[2]) == "validation-eligibility") {
            return set_validation_eligibility(argc, argv);
        }
        if (command == "system" && argc >= 3 && std::string_view(argv[2]) == "validation-level") {
            return configure_validation_level(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "mail-limits") {
            return set_private_mail_waiting_limits(argc, argv);
        }
        if (command == "area" && argc >= 3 && std::string_view(argv[2]) == "credit-costs") {
            return set_message_credit_costs(argc, argv);
        }
        if (command == "file-area") {
            return file_area_command(argc, argv);
        }
        if (command == "serve") {
            if (ssh_init() != SSH_OK) {
                std::cerr << "Could not initialize libssh.\n";
                return 1;
            }
            try {
                const int result = serve(argc, argv);
                ssh_finalize();
                return result;
            } catch (...) {
                ssh_finalize();
                throw;
            }
        }
        print_usage(std::cerr);
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
