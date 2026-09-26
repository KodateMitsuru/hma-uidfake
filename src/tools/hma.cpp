// SPDX-License-Identifier: GPL-2.0
#include "hma.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <ranges>
#include <utility>

namespace uidfake {
namespace {

/* HMA treats these as always-present system packages (defpackage/xj.java, field
 * xj.a). */
constexpr std::array kBuiltinPackages{
    std::string_view{"android"},
    std::string_view{"com.android.shell"},
    std::string_view{"com.android.systemui"},
    std::string_view{"com.android.permissioncontroller"},
    std::string_view{"com.android.providers.downloads"},
    std::string_view{"com.android.providers.downloads.ui"},
    std::string_view{"com.android.providers.media"},
    std::string_view{"com.android.providers.media.module"},
    std::string_view{"com.android.providers.settings"},
    std::string_view{"com.google.android.webview"},
    std::string_view{"com.google.android.providers.media.module"},
};

} // namespace

bool HmaPolicy::is_builtin(std::string_view name) {
  return std::ranges::contains(kBuiltinPackages, name);
}

std::set<std::string, std::less<>>
HmaPolicy::string_set(const nlohmann::json &object, std::string_view key) {
  std::set<std::string, std::less<>> result;
  const auto it = object.find(key);
  if (it == object.end() || !it->is_array())
    return result;
  for (const auto &item : *it)
    if (item.is_string())
      result.insert(item.get<std::string>());
  return result;
}

std::optional<HmaPolicy> HmaPolicy::load(const std::filesystem::path &path) {
  nlohmann::json config;
  try {
    std::ifstream in(path);
    if (!in)
      return std::nullopt; /* sync_now() reports the outage once */
    in >> config;
  } catch (const std::exception &e) {
    Log::warn("cannot parse {}: {}", path.string(), e.what());
    return std::nullopt;
  }
  return HmaPolicy{std::move(config)};
}

Pairs HmaPolicy::expand(const PackageDb &packages) const {
  const auto &scope = config_.value("scope", nlohmann::json::object());
  const auto &templates = config_.value("templates", nlohmann::json::object());

  Pairs pairs;
  std::size_t callers = 0;

  for (const auto &[name, caller] : scope.items()) {
    if (is_builtin(name))
      continue;

    auto hidden = string_set(caller, "extraAppList");
    for (const auto &template_name : string_set(caller, "applyTemplates")) {
      const auto it = templates.find(template_name);
      if (it != templates.end())
        for (const auto &package : string_set(*it, "appList"))
          hidden.insert(package);
    }

    const bool whitelist = caller.value("useWhitelist", false);
    if (whitelist)
      hidden.insert(kBuiltinPackages.begin(), kBuiltinPackages.end());
    else
      for (const auto &builtin : kBuiltinPackages)
        hidden.erase(std::string{builtin});

    const bool exclude_system = caller.value("excludeSystemApps", false);
    const auto caller_uid = packages.uid_of(name);
    if (!caller_uid || *caller_uid < kFirstAppUid)
      continue;

    for (const auto &[target_name, target_uid] : packages.by_name()) {
      if (target_name == name)
        continue;
      const bool listed = hidden.contains(target_name);
      if (whitelist ? listed : !listed)
        continue;
      if (exclude_system && packages.is_system(target_name))
        continue;
      if (target_uid < kFirstAppUid)
        continue;
      pairs.push_back(Pair{.caller = *caller_uid, .target = target_uid});
    }
    ++callers;
  }

  Log::info("policy: {} caller(s), {} pair(s)", callers, pairs.size());
  return pairs;
}

} // namespace uidfake
