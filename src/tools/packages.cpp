// SPDX-License-Identifier: GPL-2.0
#include "packages.hpp"

#include <fstream>
#include <regex>
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

std::set<std::string, std::less<>> read_system_apps(const std::filesystem::path &path) {
    std::set<std::string, std::less<>> result;
    std::ifstream in(path);
    if (!in)
        return result;

    const std::string text{ std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>() };
    const std::regex entry(R"re(<package[^>]*name="([^"]+)"[^>]*flags="([0-9]+)")re");
    for (auto it = std::sregex_iterator(text.begin(), text.end(), entry);
         it != std::sregex_iterator(); ++it) {
        const auto flags = std::stoul((*it)[2].str());
        if (flags & 1UL)  /* ApplicationInfo.FLAG_SYSTEM */
            result.insert((*it)[1].str());
    }
    return result;
}

}  // namespace

std::optional<PackageDb> PackageDb::load(const std::filesystem::path &list_path,
                                        const std::filesystem::path &xml_path) {
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

    db.system_apps_ = read_system_apps(xml_path);
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
