// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_LOGGER_CONFIGURATION_HPP_
#define VSOMEIP_V3_LOGGER_CONFIGURATION_HPP_

#include <chrono>
#include <memory>
#include <mutex>
#include <queue>

#ifdef __QNX__
#include <sys/slog2.h>
#endif
#ifdef USE_DLT
#ifndef ANDROID
#include <dlt/dlt.h>
#endif
#endif

#include <vsomeip/internal/logger.hpp>

namespace vsomeip_v3 {

class configuration;

namespace logger {

class logger_impl {
public:
    VSOMEIP_IMPORT_EXPORT auto init(const std::shared_ptr<configuration> &_configuration) -> void;
    static auto get() -> logger_impl&;

    std::shared_ptr<configuration> get_configuration() const;

    void log(level_e const _level, std::chrono::system_clock::time_point const when_, const char* _data);
    void do_log(level_e const _level, std::chrono::system_clock::time_point const when_, const char* _data);

private:
#ifdef USE_DLT
    void enable_dlt(const std::string &_application, const std::string &_context);
#endif
    std::mutex mutex_;

    logger_impl() = default;
    ~logger_impl();

    logger_impl(logger_impl const&) = delete;
    auto operator=(logger_impl const&) -> logger_impl& = delete;

    void set_configuration(const std::shared_ptr<configuration> &_configuration);
    mutable std::mutex configuration_mutex_;

    // Flag for whether init was called and processed (didn't immediately exit
    // from a guard)
    bool is_initialized_ = false;

    std::queue<std::tuple<level_e, std::chrono::system_clock::time_point, std::string>> log_queue_;

#ifdef __QNX__
    // Flag whether slog2 was successfully initialized.
    bool slog2_is_initialized_ = false;
#endif
    std::shared_ptr<configuration> configuration_;
    static const char * levelAsString(level_e const _level);

#ifdef __QNX__
    static slog2_buffer_set_config_t   buffer_config;
    static slog2_buffer_t              buffer_handle[1];
    static std::uint8_t levelAsSlog2(level_e const _level);
#endif
#ifdef USE_DLT
#ifndef ANDROID
    DLT_DECLARE_CONTEXT(dlt_)
#endif
#endif
};

} // namespace logger
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_LOGGER_CONFIGURATION_HPP_
