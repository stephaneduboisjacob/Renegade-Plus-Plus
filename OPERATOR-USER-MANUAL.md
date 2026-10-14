# Renegade++ v1.7.5 for Linux

## Operator and User Manual

**Contact:** Stephane Jacob / [jacobstephane@outlook.com](mailto:jacobstephane@outlook.com)

This manual covers installation, day-to-day operation, account administration, terminal use, ANSI artwork, file transfers, configuration, backup, and troubleshooting for Renegade++ on Linux.

## Contents

1. [Overview](#1-overview)
2. [Requirements and installation](#2-requirements-and-installation)
3. [First start and first login](#3-first-start-and-first-login)
4. [SSH and SFTP access](#4-ssh-and-sftp-access)
5. [Server configuration](#5-server-configuration)
6. [Terminal basics and main menu](#6-terminal-basics-and-main-menu)
7. [Caller features](#7-caller-features)
8. [SysOp operation](#8-sysop-operation)
9. [Local command-line administration](#9-local-command-line-administration)
10. [Access Control Strings](#10-access-control-strings-acs)
11. [ANSI artwork and MCI](#11-ansi-artwork-and-mci)
12. [Files, storage, backup, and restore](#12-files-storage-backup-and-restore)
13. [Linux service deployment](#13-linux-service-deployment)
14. [Troubleshooting](#14-troubleshooting)
15. [Current behavior and limits](#15-current-behavior-and-limits)

## 1. Overview

Renegade++ is a multi-user, text-terminal BBS service for Linux. Callers connect with SSH for the interactive ANSI/ASCII interface or SFTP for file transfers. The interactive session provides messaging, private mail, chat, file areas, polls, a BBS directory, callers and statistics, bulletins, quotes, one-liners, an artwork gallery, and a time bank.

The server stores accounts, BBS activity, messages, community content, and file-area metadata in SQLite. Public files reside below a configurable file root. The service accepts SSH password authentication for BBS accounts. It does not provide a general Linux shell or SSH `exec` command to callers.

A newly initialized database starts with a `General` message area. File areas are created by the SysOp as needed.

### Default layout

When run from the project directory, default paths are relative to the current working directory:

| Path | Purpose |
| --- | --- |
| `build/renegade-cpp` | Executable produced by CMake |
| `data/renegade.sqlite3` | Account and BBS database |
| `var/ssh_host_ed25519_key` | SSH server private host key |
| `files/` | Public file-area storage root |
| `assets/ansi/` | ANSI/ASCII art collection, including built-in Renegade++ panels |
| `bulletins/` | Bulletin files |
| `quotes/` | Quote packs or text quotes |
| `taglines/` | Tagline packs or text taglines |

Create the directories that you use before starting the server. The database and host key are created or opened at the paths supplied to the program.

## 2. Requirements and installation

### Build requirements

On Debian or Ubuntu, install the compiler and libraries:

```sh
sudo apt-get update
sudo apt-get install build-essential cmake pkg-config libssh-dev libargon2-dev libsqlite3-dev libarchive-dev openssh-client
```

From the `cpp/` directory, configure and build:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The executable is `build/renegade-cpp`. To see the command index at any time:

```sh
./build/renegade-cpp --help
```

### Create the host key and SysOp account

Run the following from the `cpp/` directory:

```sh
mkdir -p var data files
ssh-keygen -t ed25519 -N '' -f var/ssh_host_ed25519_key
./build/renegade-cpp user add SYSOP
./build/renegade-cpp user sysop SYSOP on
```

`user add` asks for the password twice without echoing it. Handles must be 1–32 characters using letters, digits, dot, dash, or underscore. Passwords must contain 12–128 characters. The program stores a password hash in the SQLite database. A newly created account is not automatically a SysOp; grant that role explicitly with the `user sysop` command.

Protect the host key so only the service account can read it:

```sh
chmod 600 var/ssh_host_ed25519_key
```

The private key must be a regular file with mode `0600`. The database is created with private permissions. Keep both files in a directory writable only by the service operator.

## 3. First start and first login

Start the BBS in the foreground:

```sh
./build/renegade-cpp serve
```

The default listener is `127.0.0.1:2222`, which is reachable only from the same machine. The server reports its address, node limit, and connection limit after startup. Press `Ctrl-C` to stop it; connected callers receive a shutdown notice.

Connect from another terminal on the same machine:

```sh
ssh -p 2222 SYSOP@127.0.0.1
```

At the first connection, OpenSSH asks whether to trust the server host key. Verify that you are connecting to the intended host before accepting it. Enter the BBS account password at the SSH password prompt. After authentication, the entrance artwork and login notices lead to the BBS menu.

### Make the BBS reachable from another computer

To listen on all IPv4 interfaces:

```sh
./build/renegade-cpp serve --bind 0.0.0.0
```

Then connect using the server's reachable address:

```sh
ssh -p 2222 SYSOP@bbs.example.net
```

For public or LAN exposure, allow TCP port `2222` only from networks that should reach the BBS. Keep the private host key safe, use unique account passwords, and avoid running the process as root. SSH encrypts the connection, but the BBS account is separate from a Linux shell account.

## 4. SSH and SFTP access

### Interactive SSH

The interactive terminal client is OpenSSH or another SSH client with ANSI terminal support:

```sh
ssh -p 2222 HANDLE@HOST
```

Example for a local server:

```sh
ssh -p 2222 SYSOP@127.0.0.1
```

The BBS uses the caller's terminal dimensions for screen rendering. An 80-column by 24-row terminal or larger is recommended for full-screen ANSI layouts. Terminal profile preferences can disable ANSI colors or screen clearing.

### SFTP file transfers

SFTP uses the same SSH port and BBS account:

```sh
sftp -P 2222 HANDLE@HOST
```

Useful SFTP commands:

```text
ls /files/1
get /files/1/README.TXT
put local-file.zip /incoming/local-file.zip
put local-file.zip /files/1/local-file.zip
```

`/files/<area-id>/` contains publicly listed files, subject to area access, download access, file validation, and file-point rules. `/incoming/` is a private upload inbox for SysOp review. A caller may upload directly to `/files/<area-id>/` only when the account passes that area's upload ACS. Public uploads may remain pending until approved. SFTP paths are virtual; they do not expose arbitrary host filesystem paths.

The terminal session and SFTP transfer use separate SSH connections. A public upload is attributed to the BBS account and is subject to quota and validation rules. The service does not overwrite an existing file of the same name.

## 5. Server configuration

All server options follow `serve`:

```sh
./build/renegade-cpp serve [options]
```

### Network, storage, and admission options

| Option | Default | Meaning |
| --- | --- | --- |
| `--bind ADDRESS` | `127.0.0.1` | Address to listen on. Use `0.0.0.0` for all IPv4 interfaces. |
| `--port PORT` | `2222` | TCP SSH port; valid range 1–65535. |
| `--host-key PATH` | `var/ssh_host_ed25519_key` | SSH server private key. Must be a regular file with mode `0600`. |
| `--db PATH` | `data/renegade.sqlite3` | SQLite database path. Use the same path for server and local administration commands. |
| `--file-dir DIR` | `files` | Root directory for public file areas and upload storage. |
| `--nodes COUNT` | `4` | Maximum simultaneous authenticated BBS terminal nodes; range 1–32. |
| `--connections COUNT` | `nodes + 2` | Maximum simultaneous SSH connections, including handshakes; range 1–64. |
| `--allow-signup` | Off | Allows self-registration. New accounts wait for SysOp approval. |
| `--idle-timeout SEC` | `1800` | Disconnect idle terminal sessions after this many seconds; range 0–86400. `0` disables this timeout. |
| `--auth-failures N` | `10` | Failed logins per remote address before cooldown; range 1–100. |
| `--auth-window SEC` | `300` | Login-failure tracking window; range 30–86400 seconds. |

`--nodes` controls BBS sessions. `--connections` separately limits SSH connections that are still authenticating or using SFTP. If a lower connection limit is set than the node limit, the connection cap can prevent all nodes from being occupied.

### Session and time-bank options

| Option | Default | Meaning |
| --- | --- | --- |
| `--session-time-limit MIN` | Unlimited | Hard online-time limit per call; range 0–32767. `0` means unlimited. |
| `--time-bank-max MIN` | Unlimited | Maximum saved time per account; range 0–32767. `0` means unlimited. |
| `--time-bank-deposit-day MIN` | Unlimited | Maximum deposited per account per local day; range 0–32767. `0` means unlimited. |
| `--time-bank-withdraw-day MIN` | Unlimited | Maximum withdrawn per account per local day; range 0–32767. `0` means unlimited. |

Time-bank transfers require a finite `--session-time-limit`. A deposit reduces the remaining time in the current call; a withdrawal adds time, subject to the account balance and configured caps.

### Signup and birthday options

| Option | Default | Meaning |
| --- | --- | --- |
| `--birthday-check-frequency N` | Off | Ask a caller to confirm or enter a birth date every N logins; range 0–32767. `0` disables the prompt. |
| `--birthday-art PATH` | `assets/ansi/renegade/BIRTHDAY.ANS` | ANSI panel for a same-day birthday greeting. |
| `--birthday-late-art PATH` | `assets/ansi/renegade/BIRTHDAY-LATE.ANS` | ANSI panel for a belated birthday greeting. |

Birthday greetings are also shown when the saved birth date falls between the previous login and the current date.

### Artwork and content paths

Each artwork option accepts a path to an `.ANS` or `.ASC` file. Relative paths are resolved from the server's working directory.

| Option | Screen/content |
| --- | --- |
| `--entrance-art PATH` | Entrance splash shown after SSH login; default is `assets/ansi/renegade/ENTRANCE.ANS`. |
| `--new-caller-art PATH` | New-user questionnaire and pending-application panel; default `assets/ansi/renegade/NEW-CALLER.ANS`. |
| `--welcome-art PATH` | Main welcome/menu art; default is `assets/ansi/imported/Roy_EarlyANSI/MAINMENU.ANS`. |
| `--sysop-art PATH` | Fallback panel used when a dedicated SysOp panel cannot be loaded; default `assets/ansi/renegade/SYSOP.ANS`. |
| `--profile-art PATH` | User profile screens; default `assets/ansi/renegade/USER-PROFILE.ANS`. |
| `--time-bank-art PATH` | Time Bank screen; default `assets/ansi/renegade/TIME-BANK.ANS`. |
| `--once-only-art PATH` | One-time notice panel, shown when its art file changes since that caller's previous login. |
| `--nodes-art PATH` | Live node status; default `assets/ansi/renegade/NODES.ANS`. |
| `--callers-art PATH` | Caller history; default `assets/ansi/renegade/CALLER-LOG.ANS`. |
| `--stats-art PATH` | Statistics; default `assets/ansi/renegade/STATISTICS.ANS`. |
| `--help-art PATH` | Help screen; default `assets/ansi/renegade/HELP.ANS`. |
| `--bbs-art PATH` | BBS directory; default `assets/ansi/renegade/BBS-DIRECTORY.ANS`. |
| `--file-areas-art PATH` | File-area screens; default `assets/ansi/imported/Roy_EarlyANSI/FILEDIR.ANS`. |
| `--chat-art PATH` | Multi-node chat; default `assets/ansi/imported/Roy_EarlyANSI/CHATMENU.ANS`. |
| `--bulletin-art PATH` | Bulletin index; default `assets/ansi/renegade/BULLETINS.ANS`. |
| `--message-art PATH` | Shared fallback for message screens that do not have a screen-specific path; default `assets/ansi/imported/Roy_EarlyANSI/MMSMENU.ANS`. |
| `--areas-art PATH` | Message-area picker; defaults to the shared message panel. |
| `--board-art PATH` | Message post lists and other board screens; defaults to the shared message panel. |
| `--mailbox-art PATH` | Private-message and short-message screens; default `assets/ansi/renegade/MAILBOX.ANS`. |
| `--reader-art PATH` | Public message reader; default `assets/ansi/renegade/MESSAGE-READER.ANS`. |
| `--editor-art PATH` | Message composer; default `assets/ansi/renegade/MESSAGE-WRITER.ANS`. |
| `--polls-art PATH` | Voting topic and detail screens; default `assets/ansi/renegade/VOTING.ANS`. |
| `--auto-message-art PATH` | Auto-message reader/editor; default `assets/ansi/renegade/AUTO-MESSAGE.ANS`. |
| `--quotes-art PATH` | Quote viewer and submission screens; default `assets/ansi/renegade/QUOTES.ANS`. |
| `--one-liners-art PATH` | One-liner list and editor; default `assets/ansi/renegade/ONE-LINERS.ANS`. |
| `--uploads-art PATH` | SysOp upload review and publish screens; default `assets/ansi/renegade/UPLOADS.ANS`. |
| `--quote-review-art PATH` | SysOp quote moderation queue; default `assets/ansi/renegade/QUOTE-REVIEW.ANS`. |
| `--new-files-art PATH` | New-file scan; default `assets/ansi/renegade/NEW-FILES.ANS`. |
| `--file-validation-art PATH` | Pending-file review; default `assets/ansi/renegade/FILE-VALIDATION.ANS`. |
| `--download-queue-art PATH` | Batch download queue; default `assets/ansi/renegade/DOWNLOAD-QUEUE.ANS`. |
| `--archive-art PATH` | Archive browser; default `assets/ansi/renegade/ARCHIVE-VIEWER.ANS`. |
| `--message-move-art PATH` | Message destination picker; default `assets/ansi/renegade/MESSAGE-MOVE.ANS`. |
| `--message-search-art PATH` | Message search prompt; default `assets/ansi/renegade/MESSAGE-SEARCH.ANS`. |
| `--message-scan-art PATH` | Personal new-message scan settings; default `assets/ansi/renegade/MESSAGE-SCAN.ANS`. |
| `--new-messages-art PATH` | Unread message scan; default `assets/ansi/renegade/NEW-MESSAGES.ANS`. |
| `--private-reader-art PATH` | Private message reader; default `assets/ansi/renegade/PRIVATE-READER.ANS`. |
| `--sysop-accounts-art PATH` | SysOp account roster; default `assets/ansi/renegade/ACCOUNT-ADMIN.ANS`. |
| `--sysop-account-art PATH` | Account dossier and action menu; default `assets/ansi/renegade/ACCOUNT-REVIEW.ANS`. |
| `--sysop-areas-art PATH` | SysOp message/file area setup; default `assets/ansi/renegade/AREA-ADMIN.ANS`. |
| `--sysop-audit-art PATH` | SysOp audit history; default `assets/ansi/renegade/SYSOP-AUDIT.ANS`. |
| `--signup-questions-art PATH` | Signup field and preference configuration; default `assets/ansi/renegade/SIGNUP-QUESTIONS.ANS`. |
| `--validation-levels-art PATH` | Validation-level management; default `assets/ansi/renegade/VALIDATION-LEVELS.ANS`. |
| `--art-dir DIR` | Art gallery collection; default `assets/ansi` (includes `imported/` and built-in panels). |
| `--bulletin-dir DIR` | Bulletin content directory; default `bulletins`. |
| `--quote-dir DIR` | Quote source directory; default `quotes`. |
| `--tagline-dir DIR` | Tagline source directory; default `taglines`. |

Use matching extensions and terminal dimensions when selecting artwork. ANSI art is shown in art-backed screens when the terminal is at least 80×24; narrower terminals use text layouts. The caller's ANSI preference controls ANSI color output.

### Example: local testing with four nodes

```sh
./build/renegade-cpp serve \
  --bind 127.0.0.1 \
  --port 2222 \
  --nodes 4 \
  --connections 6 \
  --db data/renegade.sqlite3 \
  --file-dir files
```

### Example: time limits and banking

```sh
./build/renegade-cpp serve \
  --session-time-limit 90 \
  --time-bank-max 240 \
  --time-bank-deposit-day 60 \
  --time-bank-withdraw-day 60
```

## 6. Terminal basics and main menu

After login, the entrance panel accepts any key to continue. Login notices, profile prompts, and configured checks appear before the main menu.

With hotkeys enabled, enter a command letter at the main menu or use the arrow keys to highlight a menu item and press Enter. Arrow-key selection also works in message/file area pickers, public and private mail, polls, the BBS directory, bulletins, user profile settings, the SysOp account roster and dossier, validation-level lists, file scans, download queues, archive listings, and message move destinations. The SysOp account dossier and area setup each have an arrow-selectable action grid. Use Up/Down to move through a list; Left/Right also move between choices. Press Enter to open the highlighted item or choose a destination. On paged reading screens, arrows move through pages or entries as shown in the footer. When hotkeys are disabled, enter one command and press Enter; arrows and Enter continue to work as menu navigation. Expert mode presents a compact menu of command letters. A screen's footer lists its available controls; the controls below are the main-menu commands.

| Key | Feature | Key | Feature |
| --- | --- | --- | --- |
| `N` | Active nodes | `C` | Multi-node chat |
| `H` | Help | `Q` | Log off |
| `D` | BBS directory | `L` | Today's callers |
| `T` | Statistics | `G` | Auto-message |
| `A` | ANSI/ASCII gallery | `O` | One-liners |
| `B` | Bulletins | `R` | Quotes |
| `M` | Message areas | `F` | File areas |
| `K` | Time bank | `V` | Voting |
| `P` | Private mail | `U` | User profile |
| `S` | SysOp controls (SysOps only) | `I` | Incoming upload review (SysOps only) |
| `J` | Quote review (SysOps only) |  |  |

`Esc` or a screen's `Q`/`B` command generally returns to its parent screen; use the key stated by that screen. `/quit` leaves multi-node chat. `Ctrl-C` closes the local SSH client and disconnects the caller.

## 7. Caller features

### Nodes and chat

`N` shows active BBS nodes. A caller who passes the configured invisibility ACS can press `I` to toggle whether their node is visible to ordinary callers. SysOps can see invisible nodes and press `A` to toggle node availability. An available connected SysOp satisfies the `O` ACS condition.

`C` enters multi-node chat. Type `/quit` to return to the menu. Chat is limited to connected BBS users and available nodes.

### ANSI/ASCII gallery

`A` opens the artwork gallery. Use arrows or `N` and `P` to move through available `.ANS` and `.ASC` files and `Q` to leave. The gallery reads from `--art-dir`.

### Bulletins

`B` opens the bulletin index. Use arrows and Enter or letter keys `A`–`Z` to select an available entry. While reading, arrows or `N` and `P` move between bulletins and `Q` returns to the index. Bulletin files are loaded from `--bulletin-dir`.

### BBS directory

`D` opens the shared BBS directory. Use arrows and Enter to view a listing, or select one with keys `1`–`8`. `A` adds a listing. On a listing, use arrows or `N`/`P` to switch between detail pages; Enter also switches pages. A caller can edit or delete their own listing; SysOps can manage all entries. The form includes BBS name, owner and SysOp, connection addresses and methods, web and phone details, software, speed, dates, descriptions, and custom fields. In the editor, Enter keeps an existing value, `/clear` empties the current field, and Escape cancels.

### Caller history and statistics

`L` lists callers for the current day, including node and connection times. Use arrows or `N`/`P` to move between pages. Up to 10,000 caller-session records are retained.

`T` displays statistics in pages. The pages show board totals and top-five rankings for public message posters and downloaded files; frequent callers and private-mail senders; online minutes and SFTP transfer counts; and uploaded/downloaded KiB. Use arrows or `N` and `P` to page.

### Auto-message

`G` displays the current auto-message. Use arrows or `N` and `P` to page through long text. `R` privately replies when the caller may see the author's identity. Eligible callers can press `W` to edit the auto-message; enter `/save` to publish the replacement. Anonymous posting eligibility affects whether the author may select an anonymous identity.

### Quotes

`R` displays a random quote. Use Up/Down or `N`/`P` to page through long quotes, Left/Right or `[`/`]` to move through the quote catalog, and `R` to choose another random quote. Eligible callers press `A` to submit a multiline quote for SysOp review. SysOps review submissions with `J` at the main menu. Quote content is filtered before display.

Quote and tagline directories can contain text files or `.PTR`/`.DAT` packs. Text content may be UTF-8 or CP437. Set the paths with `--quote-dir` and `--tagline-dir`.

### One-liners

`O` opens one-liners. Arrows or `N` and `P` page through entries, `A` submits a line, and `R` displays a random entry. Anonymous posting and identity visibility follow the configured ACS rules. SysOps select entries with arrows and Enter or `1`–`0`, press `E` to edit, or `D` and confirm with `Y` to delete.

### Polls

`V` opens poll topics. Use arrows and Enter or number keys to open a topic. On the detail screen, use arrows or `1`–`0` to select a choice, then vote with `V`; `R` toggles results and `N`/`P` page through long choice lists. If the poll permits caller-submitted choices, eligible callers use `A`. If changing votes is enabled, a voter can use `C`. SysOps create topics with `A` and can show the voter list with `L` while viewing results.

### Private mail

`P` opens private mail. Use `I` for inbox, `O` for outbox, `N`/`P` to change pages, and `C` to compose. Open a message with `R` or `1`–`0`; `G` opens a message by ID. In the reader, `R` replies when the sender's identity is visible, `F` forwards, and `B` returns to the folder. Private messages support up to 500 lines with 78 characters per line. Outbox messages can be edited with `E`. SysOps can move a private message with `M` and export it to their SFTP inbox with `X`. For an export, choose `Y` to strip color codes or `N` to keep them. A message reply or newly read unread message may queue a short notice for the other account, delivered at its next login.

The recipient's mailbox must accept mail, and normal callers are subject to mailbox waiting limits. SysOps may message closed mailboxes. The sender or recipient can soft-delete private mail with `D`; deleted mail is hidden from folders and can be restored from its open reader. Forwarding checks that the destination mailbox is open and below its waiting limit.

### Message areas

`M` opens the area picker. Use arrows and Enter or `1`–`9`/`0` to select an area; arrows or `N` and `P` page through area lists. The picker marks the current area with `>` and restores the last accessible area from the previous login. Password-protected areas prompt for a shared password; after a successful entry, the area stays unlocked for the current SSH session. Unread counts are shown for accessible areas.

In the area picker:

- `S` scans unread posts across accessible areas. Opening a post marks it read; `B` returns to the scan.
- `T` opens personal new-scan preferences. Use arrows and Enter or `1`–`0` to toggle an area; areas marked `FORCED` are controlled by the SysOp.
- `D` sets the date cutoff for new-message scans using `MM/DD/YYYY`. Posts before the cutoff are marked read, and newer read markers are reset.
- In an individual area, `S` switches between unread-only and all-post views.

In a post list, use arrows and Enter or `1`–`0` to read a post; `R` reads the first post shown. Arrows or `N` and `P` move between older/newer list pages. Press `X` to search: enter up to 40 characters, then use the arrow keys to highlight and Enter to choose `F` (from), `T` (to), `S` (subject), or `A` (all text). `Y` finds posts addressed to you and `U` posts written by you; those two searches do not require text. Letter shortcuts remain available. `N` toggles new-only results, and `G` toggles searching all accessible areas. In the reader, arrows or `N`/`P` page through long posts, `R` replies in the thread, `G` opens a post by ID, `F` forwards it to private mail, and `B` returns. `O` opens a parent post; `B` walks back through the posts opened in the session. `W` composes a post. Enter `/save` to publish or `/cancel` to discard. `Q` returns to the area picker.

Public posts have a recipient field up to 36 characters (default `All`), a subject, and a body of up to 500 lines with 78 characters per line. Replies retain their parent and suggested `Re:` subject. If the area has taglines enabled, the editor offers a random tagline. `/mci off` disables MCI interpretation for the current post when the caller has permission to enable MCI. Cursor and pause MCI controls are not interpreted inside message bodies.

Authors can soft-delete their own posts with `D`. Area moderators can view deleted posts and restore them. Authors and moderators can edit post text with `E`; `/clear` clears existing text before replacement, then `/save` commits. Moderators can validate a post with `V` and mark or clear permanent status with `K`. Permanent posts must have that status removed before deletion. A moderator can move a public post with `M` to another accessible message area or to private mail when its `To` field identifies an account. A moderator can export a post to the SFTP inbox with `X`; choose `Y` to strip colors or `N` to preserve them. Flagged accounts' posts may enter the unvalidated queue.

Area access, post access, anonymous identity, real-name search, forced reading, password, quote templates, text filtering, taglines, hidden-area listing, tearline, origin, and MCI permissions are configured by SysOps. A caller may see an area row marked `[NO ACCESS]` if its visibility setting permits listing, but cannot read it without passing its access rules.

### File areas and download queue

`F` opens file areas. Use arrows and Enter or a number to select an area and browse its files. Use `/` to search names and descriptions and `R` to clear the search. Arrows or `N` and `P` move through file lists; Enter opens the highlighted file's details and SFTP paths.

New-file scanning:

- `S` starts a scan for files added since the previous successful login.
- `T` enters scan-area selection; use arrows and Enter or a number to toggle an area's participation.
- In scan-area selection, `F` includes every area and `U` skips every area.
- `D` sets the scan date using `MM/DD/YYYY`.

File details can add files to a download queue with `T` or `B`, depending on the detail screen. The queue holds up to 99 files. In the queue, arrows and Enter or `1`–`0` remove the selected file, `N`/`P` pages, `C` clears all after confirmation, `R` refreshes, and `Q` returns. Downloads are performed with SFTP using the virtual path shown on screen.

Request-only files remain visible in the BBS but are not available through SFTP. Press `R` on a request-only file to send a private request to an active SysOp. On ordinary file details, `V` opens the extended description, `T` toggles a queue tag, and `B` opens the batch queue. SysOp details provide `A` validation toggle, `1` rename, `2` refresh size, `3` edit short description, `4` change owner, `5` change date, `6` set completed downloads, `7` set points, `E` edit extended description, `D` delete with confirmation, `M` move, `Y` toggle request-only status, and `W` withdraw an uploader point award. Downloads may be restricted by area ACS, file validation, daily and cumulative ratios, points, or per-account limits.

When a supported archive is selected, `1`–`0` opens a directory or file, `N`/`P` pages through entries, `B` returns to the parent archive/directory, and `Q` exits the viewer. Nested archives open in the same viewer. Text files are displayed in pages with `N`/`P`; unsupported or encrypted entries show their details but cannot be rendered. The viewer does not extract files to disk.

### Profile and preferences

`U` opens the profile. The main page edits real name (`R`), location (`L`), signature (`S`), birth date (`B`, `YYYY-MM-DD`), gender (`G`, `M` or `F`), ANSI color (`C`), clear-screen behavior (`X`), page pauses (`P`), hotkeys (`H`), expert mode (`E`), and mailbox open/closed status (`M`). Use the arrow keys to move the highlight and Enter to activate a profile option; the letter shortcuts remain available. Press `N` for contact details: country (`C`), street (`A`), city/state (`L`), postal code (`Z`), phone (`P`), custom answers (`1`–`3`), and recovery answer (`R`). The contact page also supports arrow-key selection and Enter. Press `W` to change the account password after entering the current password. Password input is masked.

The profile displays account expiration, message credits, and file points where applicable. The password must be 12–128 characters, differ from the current password, and cannot exactly match the handle or real name. Recovery answers are masked and stored as hashes.

### Time bank

`K` opens the time bank when a finite per-call limit has been configured by the operator. Use Up/Down or Left/Right and Enter to select deposit, withdraw, or return; `D`, `W`, and `Q` remain available. Deposits reduce the remaining time in the active call. Withdrawals add time, subject to the account balance, maximum balance, and daily caps. A configured limit of `0` means unlimited. Daily counters roll over at server-local midnight.

## 8. SysOp operation

### Main SysOp commands

SysOps have three additional main-menu commands:

- `S` opens account and system controls.
- `I` reviews private incoming uploads.
- `J` reviews quote submissions.

Actions such as account security changes, ACS edits, area changes, validation, moderation, poll creation, and file moderation are written to the audit history. The retained audit history is capped at the newest 20,000 actions. A SysOp cannot revoke their own SysOp status from the in-BBS account screen; use a different SysOp account or the local CLI.

### Account control

The account list displays 10 accounts per page. Use `1`–`0` to select a listed account, `N`/`P` to page, and `R` to refresh. Other controls:

| Key | Action |
| --- | --- |
| `V` | View account profile and review pending signup information |
| `E` | Enable or approve the selected account |
| `D` | Disable the selected account |
| `T` | Toggle SysOp status |
| `A` | Open area and system setup |
| `W` | Configure signup questions |
| `Y` | Configure validation levels |
| `L` | Read audit log |
| `Q` | Return to the BBS menu |

Account detail controls:

| Key | Action |
| --- | --- |
| `V` | Preview and apply a configured validation level |
| `D` | Edit birth date |
| `G` | Edit gender |
| `X` | Edit expiration |
| `S` | Set security level (SL) and download security level (DSL) |
| `F` | Edit AR and AC flag sets |
| `E` | Edit account profile fields |
| `W` | Reset the selected account's password |
| `L` | View account audit history |
| `C` | Set message-credit balance |
| `P` | Set file-point balance |
| `I` | Queue an 80-character SysOp short message for next login |
| `M` | Toggle whether the account accepts private mail |

When editing profile fields, the form includes real name, country, street, city/state, postal code, phone, birth date, gender, signature, three custom answers, and recovery answer. Validation-level application can atomically set SL/DSL, start-menu number, expiration transition, flags, credits, and file points, and queue a notice for the account.

### Signup and caller questions

Self-registration is off by default. Enable it only when desired with `--allow-signup`. Pending accounts cannot enter the BBS until approved. The in-memory signup limiter allows at most three applications per remote address per 24-hour period.

Configure signup fields from account control `W`, or with the local `system signup-question` command. Supported question source IDs are `2`–`12`, `14`, `16`, `19`–`22`, and `25`. The system can ask for real name, country, street, city/state, postal code, phone, birth date, gender, custom answers, and a recovery answer. Country is requested during signup when address, postal code, or phone fields are enabled. Blank answers can be completed later from the profile or during login prompts.

The initial profile prompts include real name, city/state, birth date, gender, and signature. Other personal fields, recovery answers, and preference questions can be enabled by the SysOp.

In the `W` screen, `N`/`P` change pages. Use arrows and Enter or the screen's letter keys to toggle individual signup fields and preference questions; `P` opens the editor for custom prompts 1–3; use arrows and Enter or `1`–`3` to choose a prompt, and Escape to cancel. The screen displays each field name next to its key. The local `system signup-question` interface changes supported field IDs; custom prompt text is managed with `system user-question`.

Configure the three custom prompts with `system user-question NUMBER PROMPT|-`. Set the recovery prompt using `system recovery-question QUESTION`; `-` clears it. A configured `!` validation record may be applied to pending accounts. The profile completion flow saves each answer as soon as it is entered; Enter or Escape skips a field.

### Validation levels

Validation levels are named by one printable character other than `Q` or `q`. They define account levels, menu, expiry transition, flags, file points, credits, and an optional notice. Use the account-control `Y` screen or the `system validation-level` CLI. The terminal list uses arrows to highlight records; Enter opens the selected record for editing, while `S`, `E`, and `D` retain their set, edit-by-key, and delete shortcuts. A level with expiry must have a positive number of days and a valid expire-to level. Soft flag settings add the level's flags; hard settings replace stored flags.

When a caller's account expires, the configured expire-to validation level is applied after password verification. If no valid transition exists, login is denied. The special `!` level can define the level applied to a new signup.

### Area and system setup

Account control `A` opens area setup. The screen's numbered policy options and letters configure message and file areas, access rules, ratios, limits, and community settings. The displayed footer is authoritative for the current screen. Key functions include:

| Key | Setup |
| --- | --- |
| `M` / `F` | Create message area / file area |
| `N` / `E` | Rename message area / file area |
| `H` | Toggle forced reading for a message area |
| `I` | Toggle real-name searching |
| `O` | Set or clear message-area password |
| `B` | Message-area ACS, post ACS, MCI ACS, SysOp ACS |
| `A` | Anonymous post/read ACS and anonymous mode |
| `G` | Global public/private post ACS |
| `L` | Per-call public/private post limits |
| `W` | Normal/SysOp private-mail waiting limits |
| `K` | Public/private message credit costs |
| `R` | File download ratios |
| `J` | Quote settings |
| `Y` | Message taglines |
| `T` | Public message text filter |
| `U` | List inaccessible message areas (entry still requires access) |
| `V` | Tearline behavior |
| `Z` | Area origin and address |
| `C` | File-area access, download, and upload ACS |
| `X` / `D` | Delete message area / remove file area |
| `P` | Private-mail quote templates |
| `1` | Security-level file-ratio overrides |
| `2` | File daily limits |
| `3` | File point rules |
| `4` | Automatic file validation rules |
| `5` | Unvalidated-file visibility/download ACS |
| `6` | Per-file-area no-ratio setting |
| `7` | Per-login message-post ratio |
| `8` | Quote and one-liner submission ACS |
| `9` | Invisibility toggle ACS |
| `0` | Validation-level eligibility |
| `Q` | Return |

The area setup interface confirms destructive actions such as deleting an area. Deleting a message area removes its posts. Removing a file area can retain or delete its file storage according to the action and options used.

### Incoming uploads and file moderation

`I` opens the incoming-upload queue. Use arrows and Enter or `1`–`0` to inspect a pending upload; from its detail screen, a SysOp can publish it into a selected file area or delete it. The publish-area picker also supports arrows and Enter. `V` from file-area browsing opens the cross-area unvalidated-file queue, and `S` opens the new-file scan. Both lists support arrows and Enter to open a file. `A` can validate all pending files after confirmation; opening a file and pressing `A` toggles its validation status. `P` on a pending file opens its point-entry workflow and can adjust the uploader's balance.

File details support SysOp actions to validate, rename, refresh size, reassign owner, change upload date, correct completed-download count, withdraw an uploader award, mark request-only, delete, or move the file. The local `file-area` commands provide the same operational controls.

An uploaded archive may provide `FILE_ID.DIZ` or `DESC.SDI`. When found, the first line becomes the short description and up to 99 following lines become extended description. Archive reading is done without extracting files to arbitrary paths.

### Public message moderation

An account with AC flag `V` can have public posts marked unvalidated. Moderators can validate or unvalidate an individual post with `V` in the reader, or validate all pending posts in an area with the board's `V` control and confirmation. Moderators can view deleted posts and restore them. `K` in the reader toggles permanent status; permanent messages cannot be deleted until that status is cleared. Moderation actions are audited.

### Events

Up to ten scheduled event records can be configured with `system event`. The supported event labels are `logon`, `chat`, `permission`, and `external`. Currently, active `logon` events are evaluated when a terminal caller enters the BBS; the schedule, node scope, time window, and event ACS are applied. SFTP-only connections do not run this terminal admission check. Other labels can be stored and listed but do not currently trigger an action.

## 9. Local command-line administration

Local commands are run from a Linux shell. Unless specified, they use `data/renegade.sqlite3`. Add `--db PATH` to use the same database path configured for the running server. Commands that manage files also accept `--root PATH`; this should match the server's `--file-dir`.

Quote or escape values containing spaces. For example:

```sh
./build/renegade-cpp area add "Tech Talk" --db data/renegade.sqlite3
```

### User/account commands

| Command | Purpose |
| --- | --- |
| `user add HANDLE [--db PATH]` | Create an enabled account and prompt for a masked password. |
| `user list [--db PATH]` | List accounts, including enabled status, levels, flags, credits, and file points. |
| `user password HANDLE [--db PATH]` | Set a new masked password locally. |
| `user enable HANDLE [--db PATH]` | Enable or approve an account. |
| `user disable HANDLE [--db PATH]` | Block future logins for an account. |
| `user sysop HANDLE on\|off [--db PATH]` | Grant or revoke SysOp access. |
| `user levels HANDLE SL DSL [--db PATH]` | Set security and download security levels (0–255). |
| `user flags HANDLE AR_FLAGS AC_FLAGS [--db PATH]` | Set AR and AC flags; use `-` for an empty set. |
| `user credits HANDLE BALANCE [--db PATH]` | Set signed message-credit balance. |
| `user file-points HANDLE BALANCE [--db PATH]` | Set non-negative file-point balance. |
| `user mailbox HANDLE open\|closed [--db PATH]` | Set whether the account accepts private mail. |
| `user expiration HANDLE YYYY-MM-DD\|never [--db PATH]` | Set or clear account expiration. |
| `user validate HANDLE KEY [--db PATH]` | Apply a configured validation level. |

Disabling an account blocks future SSH logins; an already connected session remains active until it disconnects. Existing posts, mail, and account data remain stored.

### Message-area and mail commands

| Command | Purpose |
| --- | --- |
| `area add NAME [--db PATH]` | Create a message area. |
| `area access AREA_ID ACS PostACS MCIACS SysOpACS [--db PATH]` | Set area read, post, MCI, and moderation ACS. Use `-` for open access. |
| `area force-read AREA_ID on\|off [--db PATH]` | Toggle forced reading. |
| `area password AREA_ID [--db PATH]` | Set or clear a shared area password; prompts are masked. |
| `area quote AREA_ID QUOTE_START QUOTE_END [--db PATH]` | Set public-message quote prefix/suffix templates. |
| `area real-names AREA_ID on\|off [--db PATH]` | Enable real-name search. |
| `area tagline AREA_ID on\|off [--db PATH]` | Enable random taglines when composing. |
| `area filter AREA_ID on\|off [--db PATH]` | Filter control/high-byte text in new public posts. |
| `area unhidden AREA_ID on\|off [--db PATH]` | List area even when the caller fails read ACS; does not grant entry. |
| `area tearline AREA_ID on\|off [--db PATH]` | Add an area tearline to new public posts. |
| `area origin AREA_ID ORIGIN ADDRESS [--db PATH]` | Set origin text and FTN-style address; use `-` to clear a value. |
| `mail quote QUOTE_START QUOTE_END [--db PATH]` | Set private-mail quote templates. |
| `area anonymous AREA_ID N\|Y\|F\|D\|A [--db PATH]` | Set anonymous posting behavior for an area. |
| `area anon-acs PUBPOST PUBREAD PRIVPOST PRIVREAD [--db PATH]` | Set global anonymous identity ACS rules. |
| `area post-acs PUBPOST PRIVPOST [--db PATH]` | Set global public/private posting ACS. |
| `area post-limits MAXPUB MAXPRIV [--db PATH]` | Set per-call post caps (0–255). |
| `area mail-limits MAXWAIT CSWAIT [--db PATH]` | Set normal and SysOp unread-mail waiting limits (0–255). |
| `area credit-costs PUBLIC PRIVATE [--db PATH]` | Set public/private message credit adjustment; positive charges, negative awards. |
| `system post-ratio SL_MIN SL_MAX PERCENT [--db PATH]` | Set public-post-per-login percentage for an SL range (0–100). |

Anonymous mode values: `N` never anonymous; `Y` asks whether to post anonymously; `F` forces anonymous posting; `D` presents a set of display identities; `A` asks for a display name. ACS rules determine eligibility to post anonymously and whether another caller can see the author's identity.

Per-call public/private post caps range from 0 to 255; SysOps are exempt. Normal and SysOp unread-mail waiting limits also range from 0 to 255, with normal callers subject to mailbox availability and waiting limits. Message credit costs default to zero. Positive values charge credits and negative values add credits; public posting requires sufficient balance when a positive public cost is active. AC restriction `3` bypasses the public-post credit check. Set these policies conservatively and verify the intended ACS and account flags before enabling charges.

### System and signup commands

| Command | Purpose |
| --- | --- |
| `system signup-questions [--db PATH]` | List supported signup question IDs and their state. |
| `system signup-question SOURCE_ID on\|off [--db PATH]` | Enable or disable a supported signup prompt. |
| `system recovery-question QUESTION\|- [--db PATH]` | Set or clear the recovery prompt; use `-` as the clear value. |
| `system user-question NUMBER PROMPT\|- [--db PATH]` | Set or clear custom prompt 1, 2, or 3. |
| `system submission-acs ADDQUOTE ADDONELINER [--db PATH]` | Set quote and one-liner submission ACS. |
| `system invisibility-acs ACS [--db PATH]` | Set who may toggle invisible mode. |
| `system validation-eligibility on\|off NEWSL [--db PATH]` | Configure eligibility for validation-level application and the new-user SL threshold. |
| `system validation-level list [--db PATH]` | List validation levels. |
| `system validation-level delete KEY [--db PATH]` | Delete a validation level if no account references it. |
| `system validation-level set KEY DESCRIPTION SL DSL MENU DAYS EXPIRE_TO AR AC SOFT_AR SOFT_AC FILE_POINTS CREDITS USER_MESSAGE [--db PATH]` | Create/update a validation level. |
| `system event list [--db PATH]` | List scheduled event records. |
| `system event delete SLOT [--db PATH]` | Delete event slot 1–10. |
| `system event set SLOT DESCRIPTION TYPE on\|off daily\|weekly:MASK\|monthly:DAY START END ACS NODE [--db PATH]` | Create/update an event record. |

For validation-level `set`, use `-` for an empty expiration target, flag set, or message. `SOFT_AR` and `SOFT_AC` take `on` or `off`. Keys are one printable character other than `Q` or `q`. `DAYS` must be positive when an expiration transition is configured. Awards are non-negative signed 32-bit values.

For `system event set`, `START` and `END` use `HH:MM`. A weekly mask is 1–127, with Sunday as bit 0; `daily` selects all days. A monthly day is 1–31. `NODE` is 0–32, where 0 is not restricted to one node. Use `-` for open event ACS.

### File-area commands

| Command | Purpose |
| --- | --- |
| `file-area add NAME [--db PATH] [--root PATH]` | Create a file area and storage directory. |
| `file-area rename AREA_ID NAME [--db PATH] [--root PATH]` | Rename a file area. |
| `file-area remove AREA_ID [--delete-files] [--db PATH] [--root PATH]` | Remove an area; `--delete-files` also removes its stored files. |
| `file-area list [--db PATH] [--root PATH]` | List IDs, names, file counts, bytes, and ACS rules. |
| `file-area access AREA_ID ACS DLACS [ULACS] [--db PATH] [--root PATH]` | Set browse, download, and optional upload ACS. |
| `file-area unvalidated-access SEEUNVAL DLUNVAL [--db PATH] [--root PATH]` | Set who can see/download unvalidated files. |
| `file-area validation AUTO_VALIDATE_ACS ALL_FILES_ON\|OFF [--db PATH] [--root PATH]` | Configure auto-validation and global validate-all behavior. |
| `file-area no-ratio AREA_ID on\|off [--db PATH] [--root PATH]` | Exempt an area from file ratios. |
| `file-area ratios [on\|off] DOWNLOADS KIB NODLRATIO_ACS [--db PATH] [--root PATH]` | Enable/configure global download and KiB ratios and exemptions. |
| `file-area level-ratios SL_MIN SL_MAX DOWNLOADS KIB [--db PATH] [--root PATH]` | Set ratio overrides for an SL range. |
| `file-area level-ratios-clear SL_MIN SL_MAX [--db PATH] [--root PATH]` | Clear overrides so the range inherits global ratios. |
| `file-area daily-limits on\|off SL_MIN SL_MAX MAX_FILES MAX_KIB [--db PATH] [--root PATH]` | Set daily file and KiB caps for an SL range. |
| `file-area point-rules on\|off BASE_KIB UPLOAD_COMP REWARD_RATIO NOFILECREDITS_ACS [--db PATH] [--root PATH]` | Configure file points, upload compensation, download rewards, and exemption ACS. |
| `file-area rename-file SYSOP AREA FILE NEW_NAME [--db PATH] [--root PATH]` | Rename a public file. |
| `file-area downloads SYSOP AREA FILE COUNT [--db PATH] [--root PATH]` | Correct a file's completed-download count. |
| `file-area points SYSOP AREA FILE POINTS [--db PATH] [--root PATH]` | Set a file's point cost. |
| `file-area request SYSOP AREA FILE on\|off [--db PATH] [--root PATH]` | Toggle request-only status. |
| `file-area owner SYSOP AREA FILE OWNER [--db PATH] [--root PATH]` | Change file owner/uploader. |
| `file-area date SYSOP AREA FILE MM-DD-YYYY [--db PATH] [--root PATH]` | Change upload date. |
| `file-area size SYSOP AREA FILE [--db PATH] [--root PATH]` | Refresh indexed size from storage. |
| `file-area move SYSOP SOURCE_AREA FILE TARGET_AREA [--db PATH] [--root PATH]` | Move a file to another area. |
| `file-area publish HANDLE FILE AREA_ID [--db PATH] [--root PATH]` | Publish a private incoming upload. |
| `file-area delete HANDLE FILE [--db PATH] [--root PATH]` | Delete an incoming upload. |
| `file-area describe AREA_ID FILE DESCRIPTION [--db PATH] [--root PATH]` | Set a short file description. |
| `file-area describe-extended AREA_ID FILE TEXT [--db PATH] [--root PATH]` | Set an extended file description. |

For ratio settings, zero thresholds disable that particular ratio. `NODLRATIO_ACS` determines an exemption; `-` allows everyone. AC flag `1` and per-area no-ratio settings also exempt accounts/areas. `MAX_FILES` and `MAX_KIB` are daily caps. File-point rules are disabled by default. Use the `--help` output for argument ordering if invoking a command from a script.

### Consistent database and file-root selection

If the server starts as:

```sh
./build/renegade-cpp serve --db /srv/renegade/renegade.sqlite3 --file-dir /srv/renegade/files
```

then local administration commands should include both matching paths where supported:

```sh
./build/renegade-cpp user list --db /srv/renegade/renegade.sqlite3
./build/renegade-cpp file-area list --db /srv/renegade/renegade.sqlite3 --root /srv/renegade/files
```

Using a different database path can make a valid account or area appear to be missing because the command would be looking at a different BBS instance.

## 10. Access Control Strings (ACS)

ACS rules are used for account access, message areas, file areas, moderation, anonymous identity, and other permissions. A blank value or `-` means open access in configuration fields that accept an ACS expression. Unsupported tokens are rejected when set and fail closed if encountered in stored configuration.

### Operators

| Syntax | Meaning |
| --- | --- |
| `&` or adjacent expressions | AND |
| `|` | OR |
| `!` | NOT the following expression |
| `( ... )` | Group expressions |
| `^` | Always true |
| `%` | Always false |

Examples:

```text
S50                 Security level 50 or higher
D20                 Download security level 20 or higher
S50 & F@            SL 50+ and has AR flag @
(S50|D20) & !R1     SL 50+ or DSL 20+, and does not have AC restriction 1
-                   Open, where the setting accepts the open marker
```

### Conditions

| Token | Checks |
| --- | --- |
| `S<number>` | Minimum security level; SysOps bypass this check. |
| `D<number>` | Minimum download security level; SysOps bypass this check. |
| `B<number>` | Minimum baud threshold. All SSH callers pass because SSH has no serial baud rate. |
| `E<char>` | Terminal capability. `EA` and `E1` pass; `EN`, `EV`, and `ER` fail. |
| `P<number>` | Minimum message-credit balance; thresholds 0–32767. |
| `A<number>` | Minimum age from stored birth date. |
| `G<char>` | Stored gender (`M` or `F`). |
| `J` | Caller has novice help enabled. |
| `M` | Caller has voted in every poll. |
| `N<number>` | Caller is on the specified active node. |
| `T<number>` | Remaining minutes in a configured call. Unlimited calls pass any threshold. |
| `X<number>` | Account expires within the specified number of days. |
| `H<number>` | Server-local hour, 0–23. |
| `W<number>` | Server-local weekday, 0 Sunday through 6 Saturday. |
| `U<number>` | SQLite account number. |
| `K<number>` | Message-area number. |
| `L<number>` | File-area number. |
| `Y<number>` | Minutes elapsed in the active SSH session. |
| `I<char>` | Current-session invisibility state. |
| `O<char>` | A connected SysOp node is available. |
| `V<char>` | Validation key is active and caller SL exceeds NewSL; compatibility character is ignored. |
| `Z<char>` | Message-post-per-login ratio check; compatibility character is ignored. |
| `F<flag>` | AR flag, using `@` through `Z`. |
| `R<flag>` | True when the account has that AC restriction. Supported flags: `L`, `C`, `V`, `U`, `A`, `*`, `P`, `E`, `K`, `M`, and `1`–`4`. |

SysOp bypass applies only to the `S` and `D` security-level checks. ACS checks are used at the point described by the configured feature; for example, message post access is checked before composing and again when saving.

## 11. ANSI artwork and MCI

### ANSI and CP437

The art loader reads `.ANS` and `.ASC` content, converts CP437 characters to UTF-8, and permits standard ANSI color and cursor-control sequences. ANSI art is selected in art-backed screens when the terminal is at least 80×24. Smaller terminals receive a text-layout fallback. The profile's ANSI preference controls color output; disabling ANSI colors removes SGR color sequences.

Set a screen's artwork with its matching `--*-art` option. SysOp account, account dossier, area setup, audit, signup-question, and validation-level screens each have a dedicated panel; `--sysop-art` remains available for other SysOp screens. `--profile-art` controls profile screens and `--time-bank-art` controls the Time Bank. `--message-art` supplies a shared fallback for message screens; individual area, board, mailbox, reader, editor, search, personal scan settings, unread scan, and private reader art options can override it. Artwork paths are resolved from the server's working directory unless absolute.

### MCI codes

Screen artwork supports these MCI fields:

| Group | Codes |
| --- | --- |
| Caller identity | `%UN` handle, `%RN` real name, `%FN` first name, `%LN` last name, `%LO` location |
| Node/board/terminal | `%ND`, `%BN`, `%VR`, `%BD`, `%O1`, `%O2`, `%MB`, `%FB` |
| Area information | `%A1`–`%A4`, `%M#`, `%F#`, `%MA`, `%FA`, `%MM` |
| Date/session | `%DA`, `%DT`, `%LC`, `%TI`, `%MO`, `%TC`, `%UC`, `%TT`, `%TO` |
| Message information | `%CM`, `%HM`, `%MR`, `%MS`, `%ES`, `%EW`, `%PC`, `%PS` |
| File/transfer information | `%DL`, `%DK`, `%UL`, `%UK`, `%NR` |
| User settings/rank | `%O3`–`%O9`, `%OL`, `%TU` |

Additional formatting:

- `^0`–`^9` and `|00`–`|23` set ANSI colors.
- `%XYcolumn;row%` moves the cursor.
- `%00`–`%09` save cursor positions for the session.
- `#`, `{`, or `}` followed by a width applies field alignment.
- `%PA` pauses for a key when the caller has page pauses enabled.
- Unknown MCI codes remain visible so an artwork author can find unsupported codes.

Counter fields reflect activity recorded by the running service. Message-body MCI is separately gated by the area's MCI ACS, and `/mci off` disables it for a post. Cursor positioning and pause controls are discarded in message bodies.

### Replacing artwork

Use the corresponding server option to select a new panel. For example:

```sh
./build/renegade-cpp serve \
  --entrance-art /srv/renegade/art/ENTRANCE.ANS \
  --welcome-art /srv/renegade/art/MAIN.ANS \
  --chat-art /srv/renegade/art/CHAT.ANS \
  --art-dir /srv/renegade/art
```

Restart the server after changing startup options. Keep the collection readable by the service account.

## 12. Files, storage, backup, and restore

### File transfer rules and quotas

The server enforces a maximum size of 100 MiB per file, 500 MiB of uploads per account, and 4096 files per account. It does not overwrite an existing name. A public upload is validated according to the file area's upload ACS, auto-validation ACS, and validate-all setting. Pending files can be visible to their uploader and to accounts passing `SEEUNVAL`; downloads additionally require `DLUNVAL` and area download ACS.

Archive browsing is performed in memory and is read-only. Nested archives are supported within limits. The outer archive limit is 100 MiB, nested archives are limited to 32 MiB, rendered display entries to 2 MiB, and the viewer displays up to 600 entries. Paths that attempt parent traversal or absolute extraction are blocked. Encrypted or unsupported archive formats may not be viewable.

File ratios use SFTP transfer counters recorded in this BBS database. Ratio checks include completed transfers and active reservations. Point costs may be charged when a transfer opens; incomplete transfers are refunded. Interrupted reservations are released when the service restarts. Upload compensation and completed-download rewards are controlled by point rules.

### What to back up

Stop the service before copying the SQLite database to ensure a consistent snapshot. Back up:

1. The SQLite database configured by `--db`.
2. The SSH private host key configured by `--host-key` and its `.pub` companion if present.
3. Public file storage configured by `--file-dir`.
4. Artwork, bulletins, quotes, and taglines that are not otherwise reproducible.
5. The service unit or startup command and any custom configuration notes.

Example local backup after stopping the foreground process or systemd service:

```sh
mkdir -p /srv/backup/renegade
cp -a data/renegade.sqlite3 var/ssh_host_ed25519_key var/ssh_host_ed25519_key.pub files /srv/backup/renegade/
```

Store backups with access controls appropriate for account data and the private SSH key. A database backup contains account profile information, private mail, messages, and other BBS data.

### Restore

Stop the service. Restore the database, host key, and file tree to the same paths configured for the service. Preserve file ownership and permissions, then start the service and confirm that the expected account and file areas are present. If restoring to different paths, update the service command and use the new database consistently for local CLI administration.

## 13. Linux service deployment

For a persistent server, run Renegade++ as a dedicated unprivileged Linux user. The project includes an example systemd unit and deployment guide under `deploy/`.

The deployment layout separates read-only executable/artwork under `/opt/renegade` from writable state under `/var/lib/renegade`. A typical service account should have no interactive shell, and only the BBS state directory should be writable by it. The sample unit enables systemd hardening and restarts on failure.

Common systemd operations:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now renegade-bbs.service
sudo systemctl status renegade-bbs.service
sudo journalctl -u renegade-bbs.service -f
sudo systemctl restart renegade-bbs.service
sudo systemctl stop renegade-bbs.service
```

The sample unit listens on all interfaces at TCP port 2222. Review its `ExecStart`, paths, user, firewall, and artwork settings before enabling it. `SIGTERM` and `SIGINT` initiate graceful shutdown; systemd can restart the process after an unexpected failure.

## 14. Troubleshooting

### SSH reports “Connection refused”

Confirm the server is running and listening on the address and port used by the client. By default it binds to `127.0.0.1`, so remote computers cannot connect. Use `--bind 0.0.0.0` or an appropriate interface address, and allow the chosen TCP port through the firewall.

### “Login failed” for a newly created account

Check the handle spelling and that the server and `user add`/`user sysop` commands point at the same database. Handle matching is case-insensitive. If the database was created in another working directory, the relative default `data/renegade.sqlite3` may refer to a different file. Use an explicit `--db PATH` consistently. Confirm the account is enabled with `user list`; pending signup accounts must be approved with `user enable HANDLE`. A password reset can be made with `user password HANDLE`.

### The server reports a database schema error

Stop the service and make a backup of the database. Confirm the executable is opening the intended database path and that the database is writable by the service account. Use the same database file for all CLI changes. Do not create a new database in a different directory as a workaround unless a new empty BBS is intended.

### Host key permission or key errors

The server expects a readable regular private-key file. Check the path, owner, and mode:

```sh
ls -l var/ssh_host_ed25519_key
chmod 600 var/ssh_host_ed25519_key
```

If the key is missing, create it using `ssh-keygen -t ed25519 -N '' -f PATH`. The service user must be able to read it.

### No ANSI art, wrong colors, or text layout

Check the server log for artwork load failures and verify the configured art path is readable by the service. Confirm the caller profile has ANSI colors enabled and the terminal is at least 80 columns by 24 rows for art-backed layouts. A smaller terminal uses the text fallback. Some SSH clients disable ANSI processing or use a font without CP437-compatible glyphs; use a UTF-8 terminal with ANSI escape support and a suitable CP437 glyph mapping.

### File transfers fail

Confirm SFTP is connecting to the same port as SSH and the server's `--file-dir` is writable by the service account. Check that the destination area exists and that the caller passes its upload or download ACS. Public downloads can also be blocked by validation status, `DLUNVAL`, point balance, or ratio/daily limits. `/incoming/` uploads are private until a SysOp publishes them. Existing filenames cannot be overwritten.

### The caller reaches the node limit

Increase `--nodes` up to 32 if the host can support more sessions. Check `--connections` as well; it caps all SSH connections, including SFTP and authentication handshakes, up to 64. Idle terminal sessions are disconnected after 1800 seconds by default; tune `--idle-timeout` if appropriate.

### A caller cannot see a menu option or enter an area

The account may lack an ACS flag, security/download level, validation state, or required poll/profile information. Message areas can independently require read, post, MCI, and SysOp ACS. File areas can independently require browse, download, and upload ACS. Inspect the account with `user list`, review its validation level and flags, and verify the relevant area configuration.

### A signup account cannot enter the BBS

Self-registration creates a pending account. A SysOp must approve it using `S` → account selection → `E`, or locally with:

```sh
./build/renegade-cpp user enable HANDLE --db data/renegade.sqlite3
```

The caller then reconnects with the approved account.

## 15. Current behavior and limits

- The service runs on Linux and uses SSH for encrypted terminal and SFTP sessions.
- SSH BBS accounts do not receive general shell or remote command execution.
- Authentication currently uses BBS account passwords. Client public-key account authentication is not exposed as an account login mode.
- The default listener is loopback only. Network access requires an explicit bind address and firewall rule.
- Full ANSI layouts require an 80×24 terminal; smaller terminals use text-layout fallbacks.
- File transfers and recorded statistics are based on activity handled by this service and its SQLite data.
- Scheduled `logon` events are evaluated for interactive terminal entry. Other supported event labels are stored configuration records and do not currently launch actions.
- Archive support depends on libarchive and the format. Encrypted and unsupported archives may not be browsable.
- The service supports a defined MCI and ACS subset; unsupported MCI remains visible and unsupported ACS fails closed.

---

**Renegade++ v1.7.5 for Linux**

**Contact:** Stephane Jacob / [jacobstephane@outlook.com](mailto:jacobstephane@outlook.com)
