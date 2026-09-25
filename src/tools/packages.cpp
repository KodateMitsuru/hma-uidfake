// SPDX-License-Identifier: GPL-2.0
#include "packages.hpp"

#include <array>
#include <fstream>
#include <sstream>
#include <string>

#include "common.hpp"

namespace uidfake {
namespace {

std::optional<std::uint32_t> parse_uid(std::string_view text) {
    if (text.empty() || text.size() > 10)
        return std::nullopt;
    std::uint64_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9')
            return std::nullopt;
        value = value * 10 + static_cast<std::uint64_t>(c - '0');
    }
    if (value == 0 || value >= (1ULL << 31))
        return std::nullopt;
    return static_cast<std::uint32_t>(value);
}

/*
 * "Is this a system app?" without packages.xml. On Android 12+ that file is binary XML (it
 * starts with ABX), so a text parser reads nothing at all and the answer silently became "no
 * app is a system app" - which quietly disabled excludeSystemApps. packages.list does carry
 * the seapp seinfo, and the honest proxy for ApplicationInfo.FLAG_SYSTEM is the "partition="
 * tag MIUI appends to the seinfo of anything whose code lives on a system partition.
 *
 * It has to be that tag and not the label: on this ROM 290 of 514 packages (nearly every
 * preinstalled app) are labelled "platform", so matching that would call almost everything a
 * system app. Apps on shared system uids never reach this check: the policy drops any uid
 * below 10000 by itself.
 */
std::set<std::string, std::less<>> read_system_apps(const std::filesystem::path &list_path) {
    std::set<std::string, std::less<>> result;
    std::ifstream in(list_path);
    if (!in)
        return result;

    /* Set for anything installed on /system, /system_ext, /product or /vendor. */
    constexpr std::string_view kPartitionTag = "partition=";
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream fields(line);
        std::string name, uid, debug, data_dir, seinfo;
        if (!(fields >> name >> uid >> debug >> data_dir >> seinfo))
            continue;
        if (seinfo.find(kPartitionTag) != std::string::npos)
            result.insert(std::move(name));
    }
    return result;
}

}  // namespace

std::optional<PackageDb> PackageDb::load(const std::filesystem::path &list_path) {
    PackageDb db;
    std::ifstream in(list_path);
    if (!in)
        return std::nullopt;

    std::string line;
    std::size_t malformed = 0;
    while (std::getline(in, line)) {
        std::istringstream fields(line);
        std::string name, uid;
        if (!(fields >> name >> uid)) {
            ++malformed;
            continue;
        }
        const auto value = parse_uid(uid);
        if (!value) {
            ++malformed;
            continue;
        }
        db.by_name_[std::move(name)] = *value;
    }
    if (malformed > 0)
        Log::warn("packages.list: {} unparsable line(s)", malformed);

    db.system_apps_ = read_system_apps(list_path);
    if (db.system_apps_.empty())
        Log::warn("no system packages recognised in {}; excludeSystemApps will do nothing",
                  list_path.string());
    else
        Log::info("{} system app(s) recognised", db.system_apps_.size());
    return db;
}

std::optional<std::uint32_t> PackageDb::uid_of(std::string_view name) const {
    const auto it = by_name_.find(name);
    if (it == by_name_.end())
        return std::nullopt;
    return it->second;
}

bool PackageDb::is_system(std::string_view name) const {
    return system_apps_.contains(name);
}

}  // namespace uidfake
