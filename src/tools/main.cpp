// SPDX-License-Identifier: GPL-2.0
#include <cstdio>
#include <exception>

#include "sync.hpp"

int main(int argc, char **argv) {
  /* The daemon has to be quiet about it: an exception that escapes main would
   * take it down with a message nobody reads, after it has been supervisoring
   * the policy for days. */
  try {
    const auto config = uidfake::parse_args(argc, argv);
    if (!config)
      return 2;

    uidfake::Syncer syncer(*config);
    return syncer.run() ? 0 : 1;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "sync-tool: %s\n", e.what());
    return 1;
  }
}
