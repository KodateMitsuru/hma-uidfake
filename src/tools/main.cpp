// SPDX-License-Identifier: GPL-2.0
#include <cstdio>

#include "sync.hpp"

int main(int argc, char **argv) {
    const auto config = uidfake::parse_args(argc, argv);
    if (!config)
        return 2;

    uidfake::Syncer syncer(*config);
    return syncer.run() ? 0 : 1;
}
