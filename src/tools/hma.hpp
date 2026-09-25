// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "common.hpp"
#include "packages.hpp"

namespace uidfake {

/*
 * HMA's own rules, evaluated in userspace:
 *
 *   hidden(caller) = | extraAppList | (union of templates[*].appList) |, minus xj.a
 *
 *   useWhitelist     : the computed set is the *visible* one
 *   excludeSystemApps: skip system packages
 *   the caller itself is never hidden
 */
class HmaPolicy {
public:
    /* Logs and returns nullopt when the config cannot be read or parsed. */
    [[nodiscard]] static std::optional<HmaPolicy> load(const std::filesystem::path &path);

    /* Expands the rules into the (caller, target) pairs the kernel wants. */
    [[nodiscard]] Pairs expand(const PackageDb &packages) const;

private:
    explicit HmaPolicy(nlohmann::json config) : config_(std::move(config)) {}

    nlohmann::json config_;

    static bool is_builtin(std::string_view name);
    static std::set<std::string, std::less<>> string_set(const nlohmann::json &object,
                                                        std::string_view key);
};

}  // namespace uidfake
