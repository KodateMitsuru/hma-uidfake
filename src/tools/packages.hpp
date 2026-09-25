// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>

namespace uidfake {

/*
 * The package manager's view: uid per package name and the system-app set, both taken from
 * /data/system/packages.list (packages.xml is binary XML on Android 12+ and no longer read).
 */
class PackageDb {
public:
    [[nodiscard]] static std::optional<PackageDb> load(const std::filesystem::path &list_path);

    [[nodiscard]] std::optional<std::uint32_t> uid_of(std::string_view name) const;
    [[nodiscard]] bool is_system(std::string_view name) const;

    [[nodiscard]] const std::map<std::string, std::uint32_t, std::less<>> &by_name() const noexcept {
        return by_name_;
    }

private:
    std::map<std::string, std::uint32_t, std::less<>> by_name_;
    std::set<std::string, std::less<>> system_apps_;
};

}  // namespace uidfake
