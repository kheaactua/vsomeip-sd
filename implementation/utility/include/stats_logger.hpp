//
// CONFIDENTIAL - FORD MOTOR COMPANY
//
// This is an unpublished work, which is a trade secret, created in
// 2023.  Ford Motor Company owns all rights to this work and intends
// to maintain it in confidence to preserve its trade secret status.
// Ford Motor Company reserves the right to protect this work as an
// unpublished copyrighted work in the event of an inadvertent or
// deliberate unauthorized publication.  Ford Motor Company also
// reserves its rights under the copyright laws to protect this work
// as a published work.  Those having access to this work may not copy
// it, use it, or disclose the information contained in it without
// the written authorization of Ford Motor Company.
//

#ifdef STATS_LOGGER_ON

#ifndef STATSLOGGER_HPP
#define STATSLOGGER_HPP

#ifdef __QNX__
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#endif

#include <atomic>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

#include <boost/circular_buffer.hpp>

#include <vsomeip/constants.hpp>
#include <vsomeip/primitive_types.hpp>

namespace vsomeip_v3 {

struct handler_stat {
  /** The real handler type is the private application_impl::handler_type_e */
  using handler_type_t = uint8_t;

  handler_stat() = default;

  handler_stat(client_t _client, service_t _service_id, instance_t _instance_id,
               method_t _method_id, handler_type_t _handler_type,
               std::chrono::milliseconds _duration,
               std::chrono::system_clock::time_point _time_stamp)
      : client{_client}, service_id{_service_id}, instance_id{_instance_id},
        method_id{_method_id}, handler_type{_handler_type}, duration{_duration},
        time_stamp(_time_stamp) {}
  std::string toString();
  static std::string bannerString();

  client_t client = ANY_CLIENT;
  service_t service_id = ANY_SERVICE;
  instance_t instance_id = ANY_INSTANCE;
  method_t method_id = ANY_METHOD;
  handler_type_t handler_type = 0;

  std::chrono::milliseconds duration = std::chrono::milliseconds(0);
  std::chrono::system_clock::time_point time_stamp =
      std::chrono::system_clock::time_point::min();
};

using c_buffer = boost::circular_buffer<handler_stat>;
using histogram_t = std::vector<unsigned long>;

class statsLogger;
class DeviceProperty;
class statsResourceManager;

struct DeviceAttribute {
#ifdef __QNX__
  iofunc_attr_t attr; // Default io function attr -- MUST BE FIRST
#endif
  DeviceProperty *pDevProp = nullptr;
};

class DeviceProperty {
public:
  DeviceProperty() = default;
  DeviceProperty(const DeviceProperty &) = delete;
  DeviceProperty(const DeviceProperty &&) = delete;
  auto operator=(const DeviceProperty &) -> DeviceProperty & = delete;
  auto operator=(DeviceProperty &&) -> DeviceProperty & = delete;
  virtual ~DeviceProperty() = default;

  void initialize(long, DeviceProperty *, std::shared_ptr<statsLogger>&);

  // Takes a string that is formatted (propVal + '/n') to be set primarily from
  // io_write
  virtual void set(const std::string) = 0;

  // Returns pointer to formatted property val (propVal + '\n) to be used by
  // io_read, value persists
  [[nodiscard]] auto getValPtr() const -> const char * {
    return formattedPropVal_.c_str();
  }

  // Returns property value without '\n', used to get "real" value of property,
  // value does not persist
  [[nodiscard]] auto getVal() const -> std::string {
    return formattedPropVal_.substr(0, formattedPropVal_.find('\n'));
  }

  auto getDevAttrPtr() -> DeviceAttribute * { return &devAttr_; }

protected:
  std::string formattedPropVal_; // defined as [ propVal + '\n' (nbytes) ]
  DeviceAttribute devAttr_;
  std::shared_ptr<statsLogger> pLogger_;
};

class DpEnable : public DeviceProperty {
public:
  DpEnable() = default;
  DpEnable(const DpEnable &) = delete;
  DpEnable(const DpEnable &&) = delete;
  auto operator=(DpEnable const &) -> DpEnable & = delete;
  auto operator=(DpEnable &&) -> DpEnable & = delete;
  ~DpEnable() = default;

  void set(std::string) override;
};

class DpStorageSize : public DeviceProperty {
public:
  DpStorageSize() = default;
  DpStorageSize(const DpStorageSize &) = delete;
  DpStorageSize(const DpStorageSize &&) = delete;
  auto operator=(DpStorageSize const &) -> DpStorageSize & = delete;
  auto operator=(DpStorageSize &&) -> DpStorageSize & = delete;
  ~DpStorageSize() = default;

  void set(std::string) override;
};

class DpHandlerDurationThreshold : public DeviceProperty {
public:
  DpHandlerDurationThreshold() = default;
  DpHandlerDurationThreshold(const DpHandlerDurationThreshold &) = delete;
  DpHandlerDurationThreshold(const DpHandlerDurationThreshold &&) = delete;
  auto operator=(DpHandlerDurationThreshold const &)
      -> DpHandlerDurationThreshold & = delete;
  auto operator=(DpHandlerDurationThreshold &&)
      -> DpHandlerDurationThreshold & = delete;
  ~DpHandlerDurationThreshold() = default;

  void set(std::string) override;
};

class EventsAboveThreshold : public DeviceProperty {
public:
  EventsAboveThreshold() = default;
  EventsAboveThreshold(const EventsAboveThreshold &) = delete;
  EventsAboveThreshold(const EventsAboveThreshold &&) = delete;
  auto operator=(EventsAboveThreshold const &)
      -> EventsAboveThreshold & = delete;
  auto operator=(EventsAboveThreshold &&) -> EventsAboveThreshold & = delete;
  ~EventsAboveThreshold() = default;

  void set(std::string) override;
};

class Snapshot : public DeviceProperty {
public:
  Snapshot() = default;
  Snapshot(const Snapshot &) = delete;
  Snapshot(const Snapshot &&) = delete;
  auto operator=(Snapshot const &) -> Snapshot & = delete;
  auto operator=(Snapshot &&) -> Snapshot & = delete;
  ~Snapshot() = default;

  void set(const std::string);
};

class Histogram : public DeviceProperty {
public:
  Histogram() {}
  Histogram(const Histogram &) = delete;
  Histogram(const Histogram &&) = delete;
  auto operator=(Histogram const &) -> Histogram & = delete;
  auto operator=(Histogram &&) -> Histogram & = delete;
  ~Histogram() = default;

  void set(const std::string);
};

class Event : public DeviceProperty {
public:
  Event() = default;
  Event(const Event &) = delete;
  Event(const Event &&) = delete;
  auto operator=(Event const &) -> Event & = delete;
  auto operator=(Event &&) -> Event & = delete;
  ~Event() = default;

  void set(const std::string) override;
};

class statsLogger {
public:
  using buffer_size_t = size_t;
  statsLogger()
      : upper_limit_{400}, bucket_size_{10},
        number_of_buckets_{
            static_cast<unsigned>(ceil(upper_limit_ / bucket_size_))},
        overflow_bucket_{number_of_buckets_} {}

  statsLogger(statsLogger const &) = delete;
  statsLogger(statsLogger &&) = delete;
  auto operator=(statsLogger const &) = delete;
  auto operator=(statsLogger &&) = delete;

  bool isLogging() { return loggingStatus_; }

  friend class statsResourceManager;
  friend void DpEnable::set(std::string);
  void setThreshold(std::chrono::milliseconds _threshold) {
    const std::lock_guard<std::mutex> loggerLock(loggerMutex_);
    threshold_ = _threshold;
  }
  void setBufferSize(buffer_size_t _bufferSize) {
    const std::lock_guard<std::mutex> loggerLock(loggerMutex_);
    bufferSize_ = _bufferSize;
  }
  void log(const handler_stat &h_stat);
  void dumpStats(void);

private:
  std::atomic_bool loggingStatus_ = false;
  std::chrono::milliseconds threshold_ = std::chrono::milliseconds(500);
  buffer_size_t bufferSize_ = 5000;

  std::mutex loggerMutex_;

  DpEnable *pDpEnable_ = nullptr;
  DpStorageSize *pDpStorageSize_ = nullptr;
  DpHandlerDurationThreshold *pDpHandlerDurationThreshold_ = nullptr;
  Snapshot *pSnapshotStats_ = nullptr;
  EventsAboveThreshold *pEventsAboveThreshold_ = nullptr;
  Histogram *pHistogram_ = nullptr;
  Event *pEvent_ = nullptr;

  handler_stat max_handler;
  std::unique_ptr<c_buffer> dump_buffer_;

  std::unique_ptr<histogram_t> histogram_;
  std::string histogram_axis_;

  WatchpointCounter watchpointCounter_;

  size_t const upper_limit_ = 0;
  size_t const bucket_size_ = 0;
  size_t const number_of_buckets_ = 0;
  size_t const overflow_bucket_ = 0;

  std::string toString();

  void turnLoggerOn();
  void turnLoggerOff();
  void histogram_snapshot();
  void events_above_threshold_snapshot();
};

#ifndef __QNX__
using dispatch_t = void *;
#endif

class statsResourceManager {
public:
  static auto getInstance() -> statsResourceManager &;

  void log(const handler_stat &h_stat) { pLogger_->log(h_stat); }
  void start(std::string app_name, size_t _storageSize = 60000,
             std::chrono::milliseconds _durationThreshold =
                 std::chrono::milliseconds(4));

  std::atomic<bool> running_ = false;
  std::mutex running_mutex_;

private:
#ifdef __QNX__
  resmgr_connect_funcs_t connectFuncs_;
  resmgr_io_funcs_t ioFuncs_;
  resmgr_attr_t resmgrAttr_;
#endif

  DpEnable dpEnable_;
  DpStorageSize dpStorageSize_;
  DpHandlerDurationThreshold dpHandlerDurationThreshold_;
  Snapshot snapshotStats_;
  EventsAboveThreshold eventsAboveThreshold;
  Histogram dpHistogram_;
  Event event_;

  std::shared_ptr<statsLogger> pLogger_;

  std::string appName_ = "unknown_app";
  std::filesystem::path devRoot_ = "/dev/vsomeip/";

  statsResourceManager() : pLogger_{std::make_shared<statsLogger>()} {};
  ~statsResourceManager() = default;

  statsResourceManager(statsLogger const &) = delete;
  statsResourceManager(statsLogger &&) = delete;
  auto operator=(statsResourceManager const &) = delete;
  auto operator=(statsResourceManager &&) = delete;

  void runResourceManagerThread(std::string initDpEnableVal,
                                std::string initDpStorageSizeVal,
                                std::string initDpHandlerDurationThresholdVal);
  void init(dispatch_t *pDispatch, const std::string &formattedInitDpEnableVal,
            const std::string &formattedInitDpStorageSizeVal,
            const std::string &formattedInitDpHandlerDurationThresholdVal);
};

} // namespace vsomeip_v3

#endif // STATSLOGGER_HPP
#endif // STATS_LOGGER_ON
