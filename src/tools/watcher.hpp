// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>

#include "common.hpp"

namespace uidfake {

/*
 * fsnotify watches on HMA's config and the package manager files, plus the debounce and
 * periodic-resync timers. watch() also follows directory events, so an atomic
 * write-to-temp-then-rename of config.json is caught.
 */
class Watcher {
public:
    /* What the caller should do next. */
    enum class Tick { Debounce, Resync };

    static constexpr auto kDebounce = std::chrono::milliseconds{ 400 };
    static constexpr auto kResync = std::chrono::seconds{ 600 };

    [[nodiscard]] bool open(const std::filesystem::path &config,
                            const std::filesystem::path &packages_list,
                            const std::filesystem::path &packages_xml);

    /* Blocks until something worth resyncing happens; nullopt if polling broke. */
    [[nodiscard]] std::optional<Tick> wait();

private:
    struct Watch {
        int wd = -1;
        std::filesystem::path path;
        std::uint32_t mask = 0;
    };

    void add(const std::filesystem::path &path, std::uint32_t mask);
    [[nodiscard]] bool handle_inotify_events();
    void arm_debounce();

    Fd inotify_;
    Fd debounce_;
    Fd resync_;
    std::vector<Watch> watches_;
};

}  // namespace uidfake
