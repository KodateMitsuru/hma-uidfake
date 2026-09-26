// SPDX-License-Identifier: GPL-2.0
#include "watcher.hpp"

#include <dlfcn.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/system_properties.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <ranges>

namespace uidfake {
namespace {

/* /data/system is noisy; only packages.* events matter there. */
constexpr std::string_view kPackagesPrefix = "packages.";

/*
 * Android's own "this user's credential-encrypted storage is open" flag, set
 * after the first unlock. /data/user/0 appears through a vold mount and inotify
 * cannot report a mount, so this is what turns the unlock into an immediate
 * event instead of a poll guess.
 */
[[nodiscard]] bool ce_available() {
  char value[PROP_VALUE_MAX] = {};
  return __system_property_get("sys.user.0.ce_available", value) > 0 &&
         value[0] == 't';
}

/*
 * There is no file descriptor to poll for a property, so before the unlock -
 * when there is nothing to watch and nothing readable anyway - block on the
 * property itself instead of waking up every second. Returns whether the
 * storage is open now.
 */
/*
 * The unlock is a key being added and a bind mount being made: inotify reports
 * neither. The platform's own waiting call is not part of the NDK's symbols, so
 * it and the serial accessor that closes the gap between looking at the flag
 * and waiting on it are resolved at run time. If a ROM lacks either, the flag
 * is polled instead and nothing else notices.
 */
using PropSerial = std::uint32_t (*)(const prop_info *);
using PropWait = bool (*)(const prop_info *, std::uint32_t, std::uint32_t *,
                          const timespec *);

constexpr long kUnlockPollMs = 250;

[[nodiscard]] bool wait_for_unlock() {
  if (ce_available())
    return true;

  const prop_info *info = __system_property_find("sys.user.0.ce_available");
  const auto serial_fn = reinterpret_cast<PropSerial>(
      dlsym(RTLD_DEFAULT, "__system_property_serial"));
  const auto wait_fn =
      reinterpret_cast<PropWait>(dlsym(RTLD_DEFAULT, "__system_property_wait"));

  if (info != nullptr && serial_fn != nullptr && wait_fn != nullptr) {
    std::uint32_t seen = serial_fn(info);
    while (!ce_available()) {
      std::uint32_t fresh = 0;
      timespec watchdog{.tv_sec = 30, .tv_nsec = 0};
      if (!wait_fn(info, seen, &fresh, &watchdog))
        continue;
      seen = fresh;
    }
    return true;
  }

  timespec slice{.tv_sec = 0, .tv_nsec = kUnlockPollMs * 1000 * 1000};
  while (!ce_available())
    ::nanosleep(&slice, nullptr);
  return true;
}

constexpr std::uint32_t kFileEvents =
    IN_MODIFY | IN_CLOSE_WRITE | IN_ATTRIB | IN_MOVE_SELF | IN_DELETE_SELF;
constexpr std::uint32_t kDirEvents = IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE |
                                     IN_ATTRIB | IN_DELETE | IN_MOVED_FROM;

} // namespace

bool Watcher::open(const std::filesystem::path &config,
                   const std::filesystem::path &packages_list) {
  inotify_.reset(::inotify_init1(IN_CLOEXEC | IN_NONBLOCK));
  if (!inotify_.valid()) {
    Log::warn("inotify_init1: {}", std::strerror(errno));
    return false;
  }

  debounce_.reset(
      ::timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK));
  resync_.reset(::timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK));
  if (!debounce_.valid() || !resync_.valid()) {
    Log::warn("timerfd_create: {}", std::strerror(errno));
    return false;
  }

  /*
   * Declare what we want and arm it best effort: config.json in particular may
   * not exist yet, and a failed watch used to mean the file stayed invisible
   * for the whole lifetime of the process (that is how changes went missing).
   */
  desired_ = {
      {.path = config, .mask = kFileEvents},
      {.path = config.parent_path(), .mask = kDirEvents},
      {.path = packages_list, .mask = kFileEvents},
      {.path = "/data/system", .mask = kDirEvents},
  };
  apply_watches();

  itimerspec timer{};
  timer.it_value.tv_sec = kResync.count();
  timer.it_interval.tv_sec = kResync.count();
  if (::timerfd_settime(resync_.get(), 0, &timer, nullptr) < 0) {
    Log::warn("timerfd_settime: {}", std::strerror(errno));
    return false;
  }
  return true;
}

void Watcher::apply_watches() {
  for (const auto &want : desired_)
    add(want.path, want.mask);
}

bool Watcher::watches_complete() const {
  return std::ranges::all_of(desired_,
                             [](const Watch &w) { return !w.warned; });
}

void Watcher::add(const std::filesystem::path &path, std::uint32_t mask) {
  /* Remember which of the wanted watches are not armed yet: that is also what
   * tells the resync timer to come back sooner, since these paths only appear
   * once /data is unlocked. */
  const auto wanted = std::ranges::find_if(
      desired_, [&](const Watch &w) { return w.path == path; });

  const int wd = ::inotify_add_watch(inotify_.get(), path.c_str(), mask);
  if (wd < 0) {
    if (wanted != desired_.end() && !wanted->warned) {
      wanted->warned = true;
      Log::warn(
          "cannot watch {} yet: {} (retrying; /data may still be encrypted)",
          path.string(), std::strerror(errno));
    }
    return;
  }
  if (wanted != desired_.end() && wanted->warned) {
    wanted->warned = false;
    Log::info("watching {} now", path.string());
  }
  for (auto &watch : watches_) {
    if (watch.wd == wd) {
      watch = Watch{.wd = wd, .path = path, .mask = mask};
      return;
    }
  }
  watches_.push_back(Watch{.wd = wd, .path = path, .mask = mask});
}

void Watcher::arm_debounce() {
  const auto now = std::chrono::steady_clock::now();

  /* First event of a burst: wait out the quiet period. */
  if (!pending_) {
    pending_ = now;
    itimerspec timer{};
    timer.it_value.tv_nsec =
        std::chrono::duration_cast<std::chrono::nanoseconds>(kDebounce).count();
    ::timerfd_settime(debounce_.get(), 0, &timer, nullptr);
    return;
  }

  /* Changes keep arriving: sync anyway, no later than kDebounceMax after the
   * first one. */
  if (now - *pending_ >= kDebounceMax) {
    itimerspec timer{};
    timer.it_value.tv_nsec = 1;
    ::timerfd_settime(debounce_.get(), 0, &timer, nullptr);
  }
}

bool Watcher::handle_inotify_events() {
  std::array<char, kReadBuffer> buffer{};
  const ssize_t count = ::read(inotify_.get(), buffer.data(), buffer.size());
  if (count <= 0)
    return false;

  bool interesting = false;
  bool rearm = false;
  for (ssize_t offset = 0; offset < count;) {
    const auto *event =
        reinterpret_cast<const inotify_event *>(buffer.data() + offset);
    offset += static_cast<ssize_t>(sizeof(*event)) + event->len;

    if (event->mask & IN_Q_OVERFLOW) {
      Log::warn("inotify queue overflow, resyncing");
      interesting = true;
      rearm = true;
      continue;
    }
    if (event->mask & IN_IGNORED) {
      /* The inode went away (an atomic replace) or the watch was dropped:
       * re-arm. */
      interesting = true;
      rearm = true;
      continue;
    }
    if (event->mask & (IN_CREATE | IN_MOVED_TO | IN_DELETE | IN_MOVED_FROM)) {
      /* A file we could not watch before may exist now, or vice versa. */
      rearm = true;
    }
    if (event->len > 0 &&
        !std::string_view{event->name}.starts_with(kPackagesPrefix)) {
      const bool watches_data_system =
          std::ranges::any_of(watches_, [&](const Watch &w) {
            return w.wd == event->wd && w.path == "/data/system";
          });
      if (watches_data_system)
        continue;
    }
    interesting = true;
  }

  if (rearm)
    apply_watches();

  return interesting;
}

std::optional<Watcher::Tick> Watcher::wait() {
  for (;;) {
    std::array<pollfd, 3> fds{{
        {.fd = inotify_.get(), .events = POLLIN, .revents = 0},
        {.fd = debounce_.get(), .events = POLLIN, .revents = 0},
        {.fd = resync_.get(), .events = POLLIN, .revents = 0},
    }};

    /*
     * Before the unlock there is nothing to watch and nothing to read, so wait
     * on the property instead of waking up every second. ce_ has to be updated
     * here: returning without it made the caller come straight back and spin.
     */
    if (!ce_) {
      if (!wait_for_unlock())
        continue;
      ce_ = true;
      Log::info("credential storage is open (device unlocked)");
      return Tick::Resync;
    }

    /* After the unlock a one second tick doubles as the closure check. */
    const int ready = ::poll(fds.data(), fds.size(), 1000);
    if (ready < 0) {
      if (errno == EINTR)
        continue;
      Log::warn("poll: {}", std::strerror(errno));
      return std::nullopt;
    }
    if (ready == 0) {
      if (!ce_available()) {
        ce_ = false;
        Log::info("credential storage closed");
        return Tick::Resync;
      }
      continue;
    }
    if (fds[0].revents != 0 && handle_inotify_events())
      arm_debounce();

    std::uint64_t expirations = 0;
    if (fds[1].revents != 0 &&
        ::read(debounce_.get(), &expirations, sizeof(expirations)) > 0) {
      pending_.reset();
      return Tick::Debounce;
    }
    if (fds[2].revents != 0 &&
        ::read(resync_.get(), &expirations, sizeof(expirations)) > 0) {
      /* Retry sooner while a watch is still missing, so an unlock is picked up
       * quickly. */
      itimerspec next{};
      next.it_value.tv_sec =
          watches_complete() ? kResync.count() : kResyncPending.count();
      next.it_interval.tv_sec = kResync.count();
      ::timerfd_settime(resync_.get(), 0, &next, nullptr);
      return Tick::Resync;
    }
  }
}

} // namespace uidfake
