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
 * The package manager's view: uid per package name (/data/system/packages.list) plus the
 * set of system packages (FLAG_SYSTEM from packages.xml).
 */
class PackageDb {
public:
    [[nodiscard]] static std::optional<PackageDb> load(const std::filesystem::path &list_path,
                                                      const std::filesystem::path &xml_path);

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
