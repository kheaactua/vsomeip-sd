//
// CONFIDENTIAL - FORD MOTOR COMPANY
//
// This is an unpublished work, which is a trade secret, created in
// 2024.  Ford Motor Company owns all rights to this work and intends
// to maintain it in confidence to preserve its trade secret status.
// Ford Motor Company reserves the right to protect this work as an
// unpublished copyrighted work in the event of an inadvertent or
// deliberate unauthorized publication.  Ford Motor Company also
// reserves its rights under the copyright laws to protect this work
// as a published work.  Those having access to this work may not copy
// it, use it, or disclose the information contained in it without
// the written authorization of Ford Motor Company.
//

#pragma once

namespace vsomeip_v3 {

template <typename Enum>
auto constexpr get_underlying(Enum const &value) ->
    typename std::enable_if<std::is_enum<Enum>::value,
                            typename std::underlying_type<Enum>::type>::type {
  return static_cast<typename std::underlying_type<Enum>::type>(value);
}

} // namespace vsomeip_v3
