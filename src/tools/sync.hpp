// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

#include "netlink.hpp"
#include "watcher.hpp"

namespace uidfake {

/* Paths and flags coming from the command line. */
struct Config {
  std::filesystem::path config =
      "/data/user/0/com.tsng.hidemyapplist/files/config.json";
  std::filesystem::path packages_list = "/data/system/packages.list";
  bool once = false;
};

/* Prints the usage line to stderr and returns nullopt on a bad command line. */
[[nodiscard]] std::optional<Config> parse_args(int argc, char **argv);

/*
 * Ties everything together: evaluate HMA's rules against the package database
 * and hand the result to the kernel. One process, no helper binaries, no
 * temporary files.
 */
class Syncer {
public:
  explicit Syncer(Config config) : config_(std::move(config)) {}

  /* Parses and pushes once; failures are logged, never fatal. */
  void sync_now();

  /* Syncs once, then keeps following the files until it is killed. */
  [[nodiscard]] bool run();

private:
  Config config_;
  bool config_refused_ = false;
  NetlinkClient netlink_;
  Watcher watcher_;
};

} // namespace uidfake
