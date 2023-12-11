// Copyright (C) 2020-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <chrono>
#include <fstream>
#include <iostream>
#include <iomanip>

#include <vsomeip/runtime.hpp>

#include "../include/logger_impl.hpp"
#include "../../configuration/include/configuration.hpp"

#ifdef __QNX__
#include <sys/slog2.h>
extern char * __progname;
#elif __linux__
extern char * __progname;
#endif

#ifdef ANDROID
#include <android/log.h>

#ifndef LOG_TAG
#define LOG_TAG NULL
#endif
#endif


namespace vsomeip_v3 {
namespace logger {

#ifdef __QNX__
slog2_buffer_set_config_t   logger_impl::buffer_config = {0};
slog2_buffer_t              logger_impl::buffer_handle[1] = {0};
#endif

void
logger_impl::init(std::shared_ptr<configuration> const& _configuration) {
    std::lock_guard<std::mutex> its_lock(mutex_);

    if (!_configuration)
        return;

    // logger_impl is a singleton, configuration isn't.  With
    // VSOMEIP_ENABLE_MULTIPLE_ROUTING_MANAGERS every new connection causes a
    // config to load and be passed into logger_impl.init.  Thus, we only accept
    // a config object IF it has loaded logging info AND we don't have one. This
    // results in logger holding on to the first ready config object it gets,
    // rather than always taking on the newest.

    if (!_configuration->is_logging_loaded())
        return;

    if (!configuration_)
        configuration_ = _configuration;

    if (is_initialized_)
        return;

#ifdef __QNX__
    logger_impl::buffer_config.buffer_set_name = __progname;
    logger_impl::buffer_config.num_buffers = 1;
    logger_impl::buffer_config.verbosity_level = levelAsSlog2(configuration_->get_loglevel());

    // Use a 16kB log buffer by default
    // Override with a size specified by environment variable
    auto num_pages = 4;
    auto s = getenv("VSOMEIP_SLOG2_NUM_PAGES");
    if (s != nullptr)
    {
        char * endptr = nullptr;
        num_pages = strtoul(s, &endptr, 0);
    }
    logger_impl::buffer_config.buffer_config[0].buffer_name = "vsomeip";
    logger_impl::buffer_config.buffer_config[0].num_pages = static_cast<int>(num_pages);

    // Register the buffer set.
    if (-1 == slog2_register(&logger_impl::buffer_config, logger_impl::buffer_handle, 0))
    {
        std::fprintf(stderr, "Error registering slogger2 buffer!\n");
        return;
    }
    else
    {
        slog2_is_initialized_ = true;
    }
#endif

#ifdef USE_DLT
#   define VSOMEIP_LOG_DEFAULT_CONTEXT_ID              "VSIP"
#   define VSOMEIP_LOG_DEFAULT_CONTEXT_NAME            "vSomeIP context"

    std::string its_context_id = runtime::get_property("LogContext");
    if (its_context_id == "")
        its_context_id = VSOMEIP_LOG_DEFAULT_CONTEXT_ID;

    DLT_REGISTER_CONTEXT(dlt_, its_context_id.c_str(), VSOMEIP_LOG_DEFAULT_CONTEXT_NAME);
#endif
    is_initialized_ = true;
}

logger_impl::~logger_impl() {
#ifdef USE_DLT
#ifndef ANDROID
    DLT_UNREGISTER_CONTEXT(dlt_);
#endif
#endif
}

std::shared_ptr<configuration>
logger_impl::get_configuration() const {

    std::lock_guard<std::mutex> its_lock(configuration_mutex_);
    return configuration_;
}

void
logger_impl::set_configuration(
    const std::shared_ptr<configuration> &_configuration) {

    std::lock_guard<std::mutex> its_lock(configuration_mutex_);
    configuration_ = _configuration;
}

#ifdef ANDROID
inline constexpr auto level_to_aosp_level(level_e _level) {
    switch (_level) {
    case level_e::LL_FATAL:
        return ANDROID_LOG_ERROR;
    case level_e::LL_ERROR:
        return ANDROID_LOG_ERROR;
    case level_e::LL_WARNING:
        return ANDROID_LOG_WARN;
    case level_e::LL_INFO:
        return ANDROID_LOG_INFO;
    case level_e::LL_DEBUG:
        return ANDROID_LOG_DEBUG;
    case level_e::LL_VERBOSE:
        return ANDROID_LOG_VERBOSE;
    default:
        return ANDROID_LOG_INFO;
    }
}
#endif // !ANDROID

void
logger_impl::log(level_e const _level, std::chrono::system_clock::time_point const when_, const char *_data) {
    auto const& its_configuration = get_configuration();
    if (!its_configuration.get())
    {
        std::cerr << __FILE__ << ": " << __func__
            << " No configuration object available!  Was logger invoked before the application was started?\n";
        std::cerr << " Failed message: " << _data << "\n";
        return;
    }

    std::lock_guard<std::mutex> its_lock(mutex_);

    if (its_configuration->has_console_log()
            || its_configuration->has_file_log()) {

        // Prepare log level
        auto* const its_level = levelAsString(_level);

        // Prepare time stamp
        auto const its_time_t = std::chrono::system_clock::to_time_t(when_);
        auto const its_time = std::localtime(&its_time_t);
        auto const its_ms = (when_.time_since_epoch().count() / 100) % 1000000;

        // Write to logcat before filtering on the level.  This way we can employ
        // the `[persist.]log.tag.<tag>=<V|I||W|F>`
        if (its_configuration->has_logcat_log()) {
#ifdef ANDROID
            static_cast<void>(__android_log_print(level_to_aosp_level(_level), LOG_TAG, "%s", _data));
#endif // !ANDROID
        }

        // Logging threshold filter
        if (_level > its_configuration->get_loglevel())
            return;

        if (its_configuration->has_console_log()) {
            std::cout
                << std::dec << std::setw(4) << its_time->tm_year + 1900 << "-"
                << std::dec << std::setw(2) << std::setfill('0') << its_time->tm_mon << "-"
                << std::dec << std::setw(2) << std::setfill('0') << its_time->tm_mday << " "
                << std::dec << std::setw(2) << std::setfill('0') << its_time->tm_hour << ":"
                << std::dec << std::setw(2) << std::setfill('0') << its_time->tm_min << ":"
                << std::dec << std::setw(2) << std::setfill('0') << its_time->tm_sec << "."
                << std::dec << std::setw(6) << std::setfill('0') << its_ms << " ["
                << its_level << "] "
                << _data
                << std::endl;
        }

        if (its_configuration->has_file_log()) {
            std::ofstream its_logfile(
                    its_configuration->get_logfile(),
                    std::ios_base::app);
            if (its_logfile.is_open()) {
                its_logfile
                    << std::dec << std::setw(4) << its_time->tm_year + 1900 << "-"
                    << std::dec << std::setw(2) << std::setfill('0') << its_time->tm_mon << "-"
                    << std::dec << std::setw(2) << std::setfill('0') << its_time->tm_mday << " "
                    << std::dec << std::setw(2) << std::setfill('0') << its_time->tm_hour << ":"
                    << std::dec << std::setw(2) << std::setfill('0') << its_time->tm_min << ":"
                    << std::dec << std::setw(2) << std::setfill('0') << its_time->tm_sec << "."
                    << std::dec << std::setw(6) << std::setfill('0') << its_ms << " ["
                    << its_level << "] "
                    << _data
                    << std::endl;
            }
        }
    }

#ifdef __QNX__
    // Write to slog before filtering on the level.  This way we can modify
    // the threshold in the pps settings, e.g.
    // echo buffer_name:n:7 >> /var/pps/slog2/verbose
    if (its_configuration->has_slog2_log() && slog2_is_initialized_) {
        // Truncates after 508 characters (and adds ellipsis)
        slog2c(logger_impl::buffer_handle[0], 0x0000, levelAsSlog2(_level), _data);
    }
#endif

#ifdef USE_DLT
#ifndef ANDROID
    if (its_configuration->has_dlt_log()) {
        // Prepare log level
        DltLogLevelType its_level;
        switch (_level) {
        case level_e::LL_FATAL:
            its_level = DLT_LOG_FATAL;
            break;
        case level_e::LL_ERROR:
            its_level = DLT_LOG_ERROR;
            break;
        case level_e::LL_WARNING:
            its_level = DLT_LOG_WARN;
            break;
        case level_e::LL_INFO:
            its_level = DLT_LOG_INFO;
            break;
        case level_e::LL_DEBUG:
            its_level = DLT_LOG_DEBUG;
            break;
        case level_e::LL_VERBOSE:
            its_level = DLT_LOG_VERBOSE;
            break;
        default:
            its_level = DLT_LOG_DEFAULT;
        };

        DLT_LOG_STRING(dlt_, its_level, _data);
    }
#endif
#endif
}

const char * logger_impl::levelAsString(level_e const _level)
{
    // Prepare log level
    const char *its_level;
    switch (_level) {
    case level_e::LL_FATAL:
        its_level = "fatal";
        break;
    case level_e::LL_ERROR:
        its_level = "error";
        break;
    case level_e::LL_WARNING:
        its_level = "warning";
        break;
    case level_e::LL_INFO:
        its_level = "info";
        break;
    case level_e::LL_DEBUG:
        its_level = "debug";
        break;
    case level_e::LL_VERBOSE:
        its_level = "verbose";
        break;
    default:
        its_level = "none";
    }

    return its_level;
}

#ifdef __QNX__
std::uint8_t logger_impl::levelAsSlog2(level_e const _level)
{
    uint8_t severity = 0;
    switch (_level) {
    case level_e::LL_FATAL:
        severity = SLOG2_CRITICAL;
        break;
    case level_e::LL_ERROR:
        severity = SLOG2_ERROR;
        break;
    case level_e::LL_WARNING:
        severity = SLOG2_WARNING;
        break;
    case level_e::LL_INFO:
        severity = SLOG2_INFO;
        break;
    case level_e::LL_DEBUG:
        severity = SLOG2_DEBUG1;
        break;
    case level_e::LL_VERBOSE:
    default:
        severity = SLOG2_DEBUG2;
        break;
    }
    return severity;
}
#endif

auto logger_impl::get() -> logger_impl&
{
    // Leaky singleton to ensure it stays available during destruction
    static auto ptr = new logger_impl;
    return *ptr;
}

} // namespace logger
} // namespace vsomeip_v3
