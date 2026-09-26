// SPDX-License-Identifier: GPL-2.0
#include "sync.hpp"

#include <sys/stat.h>

#include <array>
#include <cstring>
#include <set>
#include <string_view>
#include <vector>

#include "common.hpp"
#include "hma.hpp"
#include "packages.hpp"

namespace uidfake {
namespace {

constexpr std::string_view kDataUserPrefix = "/data/user/0/";
constexpr std::string_view kDataDataPrefix = "/data/data/";

std::filesystem::path resolve_config_path(const std::filesystem::path& path) {
    std::error_code ignored;
    if (std::filesystem::exists(path, ignored)) return path;

    auto text = path.string();
    if (text.starts_with(kDataUserPrefix)) {
        text.replace(0, kDataUserPrefix.size(), kDataDataPrefix);
        const std::filesystem::path alternative{text};
        if (std::filesystem::exists(alternative, ignored)) return alternative;
    }
    return path;
}

/*
 * The apk files of one app. The kernel compares their inodes, so what is collected here is
 * exactly that: nothing but numbers, and only for the apps that have rules.
 */
constexpr std::array<std::string_view, 6> kApkRoots = {"/data/app",        "/system/app",
                                                       "/system/priv-app", "/system_ext/app",
                                                       "/product/app",     "/vendor/app"};
constexpr std::size_t kApkLimit = 1024; /* the kernel takes the same number */

bool dir_matches(std::string_view name, std::string_view pkg) {
    if (name == pkg) return true;
    return name.size() > pkg.size() && name.compare(0, pkg.size(), pkg) == 0 &&
           name[pkg.size()] == '-';
}

/*
 * One entry per app: the directory its code lives in. That directory always exists, whatever
 * dexopt left behind, and the kernel matches it by inode while walking up from any file the app
 * opens -- so the apk, a vdex, an odex or a library inside it all name the same app without any
 * of them having to be listed.
 */
void collect_app_dir(const std::filesystem::path& dir, std::uint32_t uid,
                     std::vector<ApkEntry>& out) {
    struct stat info{};
    if (::stat(dir.c_str(), &info) != 0) return;
    if (out.size() >= kApkLimit) return;
    static std::size_t logged;
    if (logged < 12) {
        logged++;
        Log::info("app dir {} dev {} ino {} uid {}", dir.string(),
                  static_cast<std::uint32_t>(info.st_dev), static_cast<std::uint64_t>(info.st_ino),
                  uid);
    }
    out.push_back(ApkEntry{.dev = static_cast<std::uint32_t>(info.st_dev),
                           .ino = static_cast<std::uint64_t>(info.st_ino),
                           .uid = uid});
}

/* /data/app holds the app dir one level deeper than the system roots do. */
void find_app_dir(const std::filesystem::path& base, std::string_view pkg, std::uint32_t uid,
                  std::vector<ApkEntry>& out, int depth) {
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator{base, ec}) {
        if (ec) return;
        if (!entry.is_directory(ec)) continue;
        if (dir_matches(entry.path().filename().string(), pkg)) {
            collect_app_dir(entry.path(), uid, out);
        } else if (depth > 0) {
            find_app_dir(entry.path(), pkg, uid, out, depth - 1);
        }
    }
}

void collect_app_apks(std::string_view pkg, std::uint32_t uid, std::vector<ApkEntry>& out) {
    for (const auto root : kApkRoots) find_app_dir(root, pkg, uid, out, 1);
}

}  // namespace

std::optional<Config> parse_args(int argc, char** argv) {
    Config config;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        const bool has_value = i + 1 < argc;
        if (arg == "--once") {
            config.once = true;
        } else if (arg == "--config" && has_value) {
            config.config = argv[++i];
        } else if (arg == "--list" && has_value) {
            config.packages_list = argv[++i];
        } else {
            std::fprintf(stderr, "usage: %s [--once] [--config <json>] [--list <packages.list>]\n",
                         argc > 0 ? argv[0] : "sync-tool");
            return std::nullopt;
        }
    }
    config.config = resolve_config_path(config.config);
    return config;
}

void Syncer::sync_now() {
    const auto policy = HmaPolicy::load(config_.config);
    if (!policy) {
        /* Once per outage: before the unlock this used to repeat on every tick. */
        if (!config_refused_) {
            config_refused_ = true;
            Log::warn("cannot read {} yet (keeping the previous policy)", config_.config.string());
        }
        return;
    }
    if (config_refused_) {
        config_refused_ = false;
        Log::info("{} is readable again", config_.config.string());
    }

    const auto packages = PackageDb::load(config_.packages_list);
    if (!packages) {
        Log::warn("cannot read {} (will retry on the next event)", config_.packages_list.string());
        return;
    }

    const Pairs pairs = policy->expand(*packages);

    if (!netlink_.push(pairs)) return;
    Log::info("synced {} pair(s)", pairs.size());

    /*
     * Then the code directory of each caller: one inode per app, the directory that always exists
     * whatever dexopt left behind. An isolated child of such an app is named as soon as it opens
     * anything inside it. A rule with caller == 0 applies to anyone, so then every app can be a
     * caller and every directory is registered.
     */
    std::set<std::uint32_t> callers;
    bool wild = false;
    for (const auto& pair : pairs) {
        if (pair.caller == 0) {
            wild = true;
        } else {
            callers.insert(pair.caller);
        }
    }
    std::vector<ApkEntry> apks;
    for (const auto& [name, uid] : packages->by_name()) {
        if (!wild && !callers.contains(uid)) continue;
        collect_app_apks(name, uid, apks);
    }
    if (!netlink_.push_apks(apks)) return;
    Log::info("registered {} caller code dir(s)", apks.size());
}

bool Syncer::run() {
    sync_now();
    if (config_.once) return true;

    if (!watcher_.open(config_.config, config_.packages_list)) return false;
    Log::info("watching {}", config_.config.string());

    for (;;) {
        if (!watcher_.wait()) return false;
        /*
         * Re-arm on every tick, not only on events: before the first unlock none of the
         * encrypted paths exist, so there are no events to react to and the watches would
         * otherwise never come back.
         */
        watcher_.apply_watches();
        sync_now();
    }
}

}  // namespace uidfake
