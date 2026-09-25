// SPDX-License-Identifier: GPL-2.0
#include "watcher.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <ranges>

#include <poll.h>
#include <sys/inotify.h>
#include <sys/timerfd.h>
#include <unistd.h>

namespace uidfake {
namespace {

/* /data/system is noisy; only packages.* events matter there. */
constexpr std::string_view kPackagesPrefix = "packages.";

constexpr std::uint32_t kFileEvents =
    IN_MODIFY | IN_CLOSE_WRITE | IN_ATTRIB | IN_MOVE_SELF | IN_DELETE_SELF;
constexpr std::uint32_t kDirEvents =
    IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE | IN_ATTRIB | IN_DELETE | IN_MOVED_FROM;

}  // namespace

bool Watcher::open(const std::filesystem::path &config,
                   const std::filesystem::path &packages_list,
                   const std::filesystem::path &packages_xml) {
    inotify_.reset(::inotify_init1(IN_CLOEXEC | IN_NONBLOCK));
    if (!inotify_.valid()) {
        Log::warn("inotify_init1: {}", std::strerror(errno));
        return false;
    }

    debounce_.reset(::timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK));
    resync_.reset(::timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK));
    if (!debounce_.valid() || !resync_.valid()) {
        Log::warn("timerfd_create: {}", std::strerror(errno));
        return false;
    }

    add(config, kFileEvents);
    add(config.parent_path(), kDirEvents);
    add(packages_list, kFileEvents);
    add(packages_xml, kFileEvents);
    add("/data/system", kDirEvents);

    itimerspec timer{};
    timer.it_value.tv_sec = kResync.count();
    timer.it_interval.tv_sec = kResync.count();
    if (::timerfd_settime(resync_.get(), 0, &timer, nullptr) < 0) {
        Log::warn("timerfd_settime: {}", std::strerror(errno));
        return false;
    }
    return true;
}

void Watcher::add(const std::filesystem::path &path, std::uint32_t mask) {
    const int wd = ::inotify_add_watch(inotify_.get(), path.c_str(), mask);
    if (wd < 0) {
        Log::warn("cannot watch {}: {}", path.string(), std::strerror(errno));
        return;
    }
    for (auto &watch : watches_) {
        if (watch.wd == wd) {
            watch = Watch{ .wd = wd, .path = path, .mask = mask };
            return;
        }
    }
    watches_.push_back(Watch{ .wd = wd, .path = path, .mask = mask });
}

void Watcher::arm_debounce() {
    itimerspec timer{};
    timer.it_value.tv_nsec = std::chrono::duration_cast<std::chrono::nanoseconds>(kDebounce).count();
    ::timerfd_settime(debounce_.get(), 0, &timer, nullptr);
}

bool Watcher::handle_inotify_events() {
    std::array<char, 64 * 1024> buffer{};
    const ssize_t count = ::read(inotify_.get(), buffer.data(), buffer.size());
    if (count <= 0)
        return false;

    bool interesting = false;
    for (ssize_t offset = 0; offset < count;) {
        const auto *event = reinterpret_cast<const inotify_event *>(buffer.data() + offset);
        offset += static_cast<ssize_t>(sizeof(*event)) + event->len;

        if (event->mask & IN_Q_OVERFLOW) {
            Log::warn("inotify queue overflow, resyncing");
            interesting = true;
            continue;
        }
        if (event->mask & IN_IGNORED) {
            for (const auto &watch : watches_) {
                if (watch.wd == event->wd) {
                    add(watch.path, watch.mask);
                    break;
                }
            }
            continue;
        }
        if (event->len > 0 && !std::string_view{ event->name }.starts_with(kPackagesPrefix)) {
            const bool watches_data_system = std::ranges::any_of(watches_, [&](const Watch &w) {
                return w.wd == event->wd && w.path == "/data/system";
            });
            if (watches_data_system)
                continue;
        }
        interesting = true;
    }
    return interesting;
}

std::optional<Watcher::Tick> Watcher::wait() {
    for (;;) {
        std::array<pollfd, 3> fds{{
            { .fd = inotify_.get(), .events = POLLIN, .revents = 0 },
            { .fd = debounce_.get(), .events = POLLIN, .revents = 0 },
            { .fd = resync_.get(), .events = POLLIN, .revents = 0 },
        }};

        if (::poll(fds.data(), fds.size(), -1) < 0) {
            if (errno == EINTR)
                continue;
            Log::warn("poll: {}", std::strerror(errno));
            return std::nullopt;
        }
        if (fds[0].revents != 0 && handle_inotify_events())
            arm_debounce();

        std::uint64_t expirations = 0;
        if (fds[1].revents != 0 && ::read(debounce_.get(), &expirations, sizeof(expirations)) > 0)
            return Tick::Debounce;
        if (fds[2].revents != 0 && ::read(resync_.get(), &expirations, sizeof(expirations)) > 0)
            return Tick::Resync;
    }
}

}  // namespace uidfake
