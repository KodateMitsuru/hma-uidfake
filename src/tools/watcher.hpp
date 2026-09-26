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
 * periodic-resync timers. Directory events are followed too, so an atomic
 * write-to-temp-then-rename of config.json is caught.
 *
 * Watches are declared first and armed best effort afterwards: a file that does not exist yet,
 * or that is being replaced while we look, used to be dropped for good when
 * inotify_add_watch() failed, which is how changes went missing entirely. Now anything can ask
 * for a re-arm: the directory events, an IN_IGNORED, or the periodic tick.
 */
class Watcher {
   public:
    /* What the caller should do next. */
    enum class Tick { Debounce, Resync };

    static constexpr auto kDebounce = std::chrono::milliseconds{400};
    /* A continuous stream of changes must not postpone the sync forever. */
    static constexpr auto kDebounceMax = std::chrono::seconds{2};
    /*
     * Short on purpose: the periodic pass is also what re-arms a watch that could not be
     * created earlier (config.json appearing later, packages.list mid-replace) and what
     * retries an upload that failed while the module was unloaded.
     */
    static constexpr auto kResync = std::chrono::seconds{60};
    /* While some watch is still missing, come back much sooner: this is the retry that picks
     * up /data/user/0 once the device has been unlocked, and inotify cannot see a mount. */
    static constexpr auto kResyncPending = std::chrono::seconds{10};

    [[nodiscard]] bool open(const std::filesystem::path& config,
                            const std::filesystem::path& packages_list);

    /* Blocks until something worth resyncing happens; nullopt if polling broke. */
    [[nodiscard]] std::optional<Tick> wait();

    /* (Re)arms every watch we want. Cheap and idempotent, so it runs after events too. */
    void apply_watches();

    /* False while a wanted watch is still missing (typically /data before the first unlock). */
    [[nodiscard]] bool watches_complete() const;

   private:
    struct Watch {
        int wd = -1;
        std::filesystem::path path;
        std::uint32_t mask = 0;
        bool warned = false; /* only for desired_: a failure already logged */
    };

    void add(const std::filesystem::path& path, std::uint32_t mask);
    [[nodiscard]] bool handle_inotify_events();
    void arm_debounce();

    Fd inotify_;
    Fd debounce_;
    Fd resync_;
    std::vector<Watch> watches_; /* what inotify actually gave us */
    std::vector<Watch> desired_; /* what we want, whether or not it exists yet */
    std::optional<std::chrono::steady_clock::time_point> pending_; /* burst in progress */
    bool ce_ = false; /* sys.user.0.ce_available as last seen */
};

}  // namespace uidfake
