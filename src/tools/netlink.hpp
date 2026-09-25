// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "common.hpp"

namespace uidfake {

/*
 * Talks to the module's generic netlink family. The family itself only accepts requests
 * from processes holding CAP_NET_ADMIN and is invisible to app domains, so the policy
 * never travels over a path an app could read.
 */
class NetlinkClient {
public:
    NetlinkClient() = default;

    NetlinkClient(const NetlinkClient &) = delete;
    NetlinkClient &operator=(const NetlinkClient &) = delete;

    /* Replaces the kernel's policy with `pairs` (an empty list clears it).
     * Failures are logged; false means the kernel side is not reachable yet. */
    [[nodiscard]] bool push(std::span<const Pair> pairs);

private:
    static constexpr std::string_view kFamilyName = "kaux";
    static constexpr std::uint8_t kCmdSet = 1;
    static constexpr std::uint16_t kAttrBlob = 1;
    static constexpr std::size_t kReplySize = 4096;

    [[nodiscard]] bool ensure_connected();
    [[nodiscard]] bool send_once(std::span<const Pair> pairs);
    [[nodiscard]] std::optional<std::uint16_t> resolve_family();
    [[nodiscard]] bool exchange(std::span<const std::byte> request, std::span<std::byte> reply);

    Fd socket_;
    std::optional<std::uint16_t> family_;
    std::uint32_t seq_ = 0;   /* one per request; replies are matched against it */
};

}  // namespace uidfake
