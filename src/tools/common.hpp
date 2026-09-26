// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <format>
#include <print>
#include <string>
#include <utility>
#include <vector>

namespace uidfake {

/* Only app uids take part in hiding; touching system/shared uids breaks the
 * system view. */
inline constexpr std::uint32_t kFirstAppUid = 10000;

/* One rule: `caller` must not be able to see that `target` exists. */
struct Pair {
  std::uint32_t caller = 0;
  std::uint32_t target = 0;
};

using Pairs = std::vector<Pair>;

/* Owns a file descriptor. */
class Fd {
public:
  Fd() = default;
  explicit Fd(int fd) noexcept : fd_(fd) {}

  Fd(const Fd &) = delete;
  Fd &operator=(const Fd &) = delete;

  Fd(Fd &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
  Fd &operator=(Fd &&other) noexcept {
    if (this != &other)
      reset(std::exchange(other.fd_, -1));
    return *this;
  }

  ~Fd() { reset(); }

  [[nodiscard]] int get() const noexcept { return fd_; }
  [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

  void reset(int fd = -1) noexcept {
    if (fd_ >= 0)
      ::close(fd_);
    fd_ = fd;
  }

private:
  int fd_ = -1;
};

/* Timestamped logging to stderr (service.sh redirects it into state/sync.log).
 */
class Log {
public:
  template <class... Args>
  static void info(std::format_string<Args...> fmt, Args &&...args) {
    emit("", fmt, std::forward<Args>(args)...);
  }

  template <class... Args>
  static void warn(std::format_string<Args...> fmt, Args &&...args) {
    emit("! ", fmt, std::forward<Args>(args)...);
  }

private:
  template <class... Args>
  static void emit(std::string_view prefix, std::format_string<Args...> fmt,
                   Args &&...args) {
    std::println(stderr, "[sync-tool {}] {}{}", timestamp(), prefix,
                 std::format(fmt, std::forward<Args>(args)...));
  }

  [[nodiscard]] static std::string timestamp() {
    const std::time_t now = std::time(nullptr);
    std::tm tm{};
    localtime_r(&now, &tm);
    return std::format("{:02}-{:02} {:02}:{:02}:{:02}", tm.tm_mon + 1,
                       tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
  }
};

} // namespace uidfake
