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

#include <sys/dispatch.h>
#include <sys/iofunc.h>

#include <atomic>
#include <mutex>
#include <string>
#include <vector>

#include <boost/circular_buffer.hpp>

namespace vsomeip_v3 {

struct handler_stat {
  handler_stat()
      : client{0}, service_id{0}, instance_id{0}, method_id{0}, handler_type{0},
        duration_ms{0}, time_stamp(0) {}

  handler_stat(std::uint32_t _client, std::uint32_t _service_id,
               std::uint32_t _instance_id, std::uint32_t _method_id,
               std::uint32_t _handler_type, long long int _duration_ms,
               long long int _time_stamp)
      : client{_client}, service_id{_service_id}, instance_id{_instance_id},
        method_id{_method_id}, handler_type{_handler_type},
        duration_ms{_duration_ms}, time_stamp(_time_stamp) {}
  std::string toString();
  static std::string bannerString();

  std::uint32_t client;
  std::uint32_t service_id;
  std::uint32_t instance_id;
  std::uint32_t method_id;
  std::uint32_t handler_type;
  long long int duration_ms;
  long long int time_stamp;
};

typedef boost::circular_buffer<handler_stat> c_buffer;
typedef std::vector<unsigned long> histogram_t;

class statsLogger;
class DeviceProperty;
class statsResourceManager;

struct DeviceAttribute {
  iofunc_attr_t attr; // Default io function attr -- MUST BE FIRST
  DeviceProperty *pDevProp = nullptr;
};

class DeviceProperty {
public:
  DeviceProperty() : pLogger_{nullptr} {}
  DeviceProperty(const DeviceProperty &) = delete;
  DeviceProperty(const DeviceProperty &&) = delete;
  DeviceProperty &operator=(const DeviceProperty &) = delete;
  virtual ~DeviceProperty() = default;

  void initialize(long, DeviceProperty *, std::shared_ptr<statsLogger>);

  // Takes a string that is formatted (propVal + '/n') to be set primarily from
  // io_write
  virtual void set(const std::string) = 0;

  // Returns pointer to formatted property val (propVal + '\n) to be used by
  // io_read, value persists
  const char *getValPtr() const { return formattedPropVal_.c_str(); }

  // Returns property value without '\n', used to get "real" value of property,
  // value does not persist
  std::string getVal() const {
    return formattedPropVal_.substr(0, formattedPropVal_.find("\n"));
  }

  DeviceAttribute *getDevAttrPtr() { return &devAttr_; }

protected:
  std::string formattedPropVal_; // defined as [ propVal + '\n' (nbytes) ]
  DeviceAttribute devAttr_;
  std::shared_ptr<statsLogger> pLogger_;
};

class DpEnable : public DeviceProperty {
public:
  DpEnable() {}
  DpEnable(const DpEnable &) = delete;
  DpEnable(const DpEnable &&) = delete;
  DpEnable &operator=(const DpEnable &) = delete;
  ~DpEnable() = default;

  void set(std::string);
};

class DpStorageSize : public DeviceProperty {
public:
  DpStorageSize() {}
  DpStorageSize(const DpStorageSize &) = delete;
  DpStorageSize(const DpStorageSize &&) = delete;
  DpStorageSize &operator=(const DpStorageSize &) = delete;
  ~DpStorageSize() = default;

  void set(std::string);
};

class DpHandlerDurationThreshold : public DeviceProperty {
public:
  DpHandlerDurationThreshold() {}
  DpHandlerDurationThreshold(const DpHandlerDurationThreshold &) = delete;
  DpHandlerDurationThreshold(const DpHandlerDurationThreshold &&) = delete;
  DpHandlerDurationThreshold &
  operator=(const DpHandlerDurationThreshold &) = delete;
  ~DpHandlerDurationThreshold() = default;

  void set(std::string);
};

class EventsAboveThreshold : public DeviceProperty {
public:
  EventsAboveThreshold() {}
  EventsAboveThreshold(const EventsAboveThreshold &) = delete;
  EventsAboveThreshold(const EventsAboveThreshold &&) = delete;
  EventsAboveThreshold &operator=(const EventsAboveThreshold &) = delete;
  ~EventsAboveThreshold() = default;

  void set(std::string);
};

class Snapshot : public DeviceProperty {
public:
  Snapshot() {}
  Snapshot(const Snapshot &) = delete;
  Snapshot(const Snapshot &&) = delete;
  Snapshot &operator=(const Snapshot &) = delete;
  ~Snapshot() = default;

  void set(const std::string);

private:
};

class Histogram : public DeviceProperty {
public:
  Histogram() {}
  Histogram(const Histogram &) = delete;
  Histogram(const Histogram &&) = delete;
  Histogram &operator=(const Histogram &) = delete;
  ~Histogram() = default;

  void set(const std::string);

private:
};

class Event : public DeviceProperty {
public:
  Event() {}
  Event(const Event &) = delete;
  Event(const Event &&) = delete;
  Event &operator=(const Event &) = delete;
  ~Event() = default;

  void set(const std::string);

private:
};

class statsLogger {
public:
  statsLogger()
      : loggingStatus_{false}, threshold_{500}, bufferSize_{5000},
        dumpFilePath_{""}, pDpEnable_{nullptr}, pDpStorageSize_{nullptr},
        pDpHandlerDurationThreshold_{nullptr}, pHistogram_{nullptr},
        pEvent_{nullptr}, pSnapshotStats_{nullptr},
        pEventsAboveThreshold_{nullptr}, dump_buffer_{nullptr},
        histogram_{nullptr}, histogram_axis_{""}, upper_limit_{400},
        bucket_size_{10}, number_of_buckets_{static_cast<unsigned>(
                              ceil(upper_limit_ / bucket_size_))},
        overflow_bucket_{number_of_buckets_} {}

  bool isLogging() { return loggingStatus_; }

  friend class statsResourceManager;
  friend void DpEnable::set(std::string);
  void setThreshold(std::uint32_t _threshold) {
    const std::lock_guard<std::mutex> loggerLock(loggerMutex_);
    threshold_ = _threshold;
  }
  void setBufferSize(std::uint32_t _bufferSize) {
    const std::lock_guard<std::mutex> loggerLock(loggerMutex_);
    bufferSize_ = _bufferSize;
  }
  void setFilePath(const std::string &_dumpFilePath) {
    const std::lock_guard<std::mutex> loggerLock(loggerMutex_);
    dumpFilePath_ = _dumpFilePath;
  }
  void log(const handler_stat &h_stat);
  void dumpStats(void);

private:
  std::string toString();

  void turnLoggerOn();
  void turnLoggerOff();
  void histogram_snapshot();
  void events_above_threshold_snapshot();

  std::atomic_bool loggingStatus_;
  std::uint32_t threshold_;
  std::uint32_t bufferSize_;
  std::string dumpFilePath_;

  std::mutex loggerMutex_;

  DpEnable *pDpEnable_ = nullptr;
  DpStorageSize *pDpStorageSize_;
  DpHandlerDurationThreshold *pDpHandlerDurationThreshold_ = nullptr;
  Snapshot *pSnapshotStats_ = nullptr;
  EventsAboveThreshold *pEventsAboveThreshold_ = nullptr;
  Histogram *pHistogram_ = nullptr;
  Event *pEvent_ = nullptr;

  handler_stat max_handler;
  std::unique_ptr<c_buffer> dump_buffer_;

  std::unique_ptr<histogram_t> histogram_;
  std::string histogram_axis_;

  const unsigned upper_limit_;
  const unsigned bucket_size_;
  unsigned number_of_buckets_;
  unsigned overflow_bucket_;
};

class statsResourceManager {
public:
  static std::unique_ptr<statsResourceManager>
  init(const std::string &_appName);
  statsResourceManager()
      : pLogger_{nullptr}, appName_{"unknown_app"}, devRoot_{"/dev/vsomeip/"} {}
  statsResourceManager(const statsResourceManager &) = delete;
  statsResourceManager(const statsResourceManager &&) = delete;
  statsResourceManager &operator=(const statsResourceManager &) = delete;
  ~statsResourceManager() = default;

  void log(const handler_stat &h_stat) { pLogger_->log(h_stat); }

private:
  void start(const std::string &_appName, size_t _storageSize,
             size_t _durationThreshol_MS);
  void runResourceManagerThread(std::string initDpEnableVal,
                                std::string initDpStorageSizeVal,
                                std::string initDpHandlerDurationThresholdVal);
  void init(dispatch_t *pDispatch, const std::string &formattedInitDpEnableVal,
            const std::string &formattedInitDpStorageSizeVal,
            const std::string &formattedInitDpHandlerDurationThresholdVal);

  resmgr_connect_funcs_t connectFuncs_;
  resmgr_io_funcs_t ioFuncs_;
  resmgr_attr_t resmgrAttr_;

  DpEnable dpEnable_;
  DpStorageSize dpStorageSize_;
  DpHandlerDurationThreshold dpHandlerDurationThreshold_;
  Snapshot snapshotStats_;
  EventsAboveThreshold eventsAboveThreshold;
  Histogram dpHistogram_;
  Event event_;

  std::shared_ptr<statsLogger> pLogger_;

  std::string appName_;
  std::string devRoot_;
};

} // namespace vsomeip_v3

#endif // STATSLOGGER_HPP
#endif // STATS_LOGGER_ON
