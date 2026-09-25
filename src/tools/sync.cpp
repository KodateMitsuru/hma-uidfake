// SPDX-License-Identifier: GPL-2.0
#include "sync.hpp"

#include <cstring>
#include <string_view>

#include "common.hpp"
#include "hma.hpp"
#include "packages.hpp"

namespace uidfake {
namespace {

constexpr std::string_view kDataUserPrefix = "/data/user/0/";
constexpr std::string_view kDataDataPrefix = "/data/data/";

/* HMA is reachable through /data/data on some devices. */
std::filesystem::path resolve_config_path(const std::filesystem::path &path) {
    std::error_code ignored;
    if (std::filesystem::exists(path, ignored))
        return path;

    auto text = path.string();
    if (text.starts_with(kDataUserPrefix)) {
        text.replace(0, kDataUserPrefix.size(), kDataDataPrefix);
        const std::filesystem::path alternative{ text };
        if (std::filesystem::exists(alternative, ignored))
            return alternative;
    }
    return path;
}

}  // namespace

std::optional<Config> parse_args(int argc, char **argv) {
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
        } else if (arg == "--xml" && has_value) {
            config.packages_xml = argv[++i];
        } else {
            std::fprintf(stderr,
                         "usage: %s [--once] [--config <json>] [--list <packages.list>] [--xml <packages.xml>]\n",
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
        Log::warn("cannot read {} (keeping the previous policy)", config_.config.string());
        return;
    }

    const auto packages = PackageDb::load(config_.packages_list, config_.packages_xml);
    if (!packages) {
        Log::warn("cannot read {} (will retry on the next event)", config_.packages_list.string());
        return;
    }

    const Pairs pairs = policy->expand(*packages);
    if (!netlink_.push(pairs))
        return;
    Log::info("synced {} pair(s)", pairs.size());
}

bool Syncer::run() {
    sync_now();
    if (config_.once)
        return true;

    if (!watcher_.open(config_.config, config_.packages_list, config_.packages_xml))
        return false;
    Log::info("watching {}", config_.config.string());

    for (;;) {
        if (!watcher_.wait())
            return false;
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
