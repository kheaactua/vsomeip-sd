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

#include <unistd.h>

#include <array>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <thread>

#ifdef ANDROID
#include "internal_android.hpp"
#else
#include "internal.hpp"
#endif // ANDROID

#include "../include/stats_logger.hpp"
#include <vsomeip/internal/logger.hpp>

extern char *__progname;

namespace vsomeip_v3 {

#ifdef STATS_USE_WHITE_LIST
static constexpr std::array<std::string_view, 83> apps_white_list = {
    "power",
    "power-client",
    "power-diag-client",
    "power-ucl-client",
    "ucl",
    "diagnostic",
    "data_identifier",
    "data_identifier_subfield",
    "trouble_code",
    "routine_control",
    "self_test",
    "data_identifier_gip",
    "status_bit",
    "diag-pm-client",
    "health_monitor",
    "vehicle_signal",
    "can_signal",
    "lin_signal",
    "tp_signal",
    "vehicle_settings",
    "adc_manager",
    "adc_manager_proxies",
    "adc_manager_test",
    "nvh_service",
    "nvh_service_proxies",
    "nvh_service_vsll_proxy",
    "nvh_service_vsnl_proxy",
    "nvh_service_test",
    "wf-client",
    "wf-ci-service",
    "wf-ar-service",
    "amf_ping-client",
    "amf_ping-service",
    "capicxx-example-service",
    "capicxx-example-client",
    "cabin-client",
    "max_defrost_client",
    "keymgr",
    "keymgr-vss-client",
    "keymgr-diagnostic-service-client",
    "keymgr-service-client",
    "service-uclsimulator",
    "client-uclsimulator",
    "chimes-client",
    "swua-data-transfer-service",
    "calibration-installer",
    "calibration-installer-proxies",
    "calibration-installer-test",
    "client-tss_clock",
    "clock-service",
    "tm_agent",
    "TokenMgr-Service-Client",
    "token_update",
    "fscr",
    "fscr-dataid",
    "fusalayout-service",
    "fusa-simulator-ucl-proxy-service",
    "client-sm",
    "vsc-pm-client",
    "temperature_monitor_client",
    "partition-monitor",
    "serial_log_retriever_client",
    "cluster",
    "cluster_configuration",
    "ClusterInfo",
    "libcluster",
    "ClusterService",
    "clusterWfClient",
    "illumination_client",
    "misr_relay",
    "display-client-QDRM1_PANO_L",
    "display-client-QDRM3_CNTRSK",
    "display-client-QDRM2_PANO_R",
    "display-client-QDRM2_CNTRSK",
    "display-client-QDRM1_CLUSTR",
    "camera-diag-proxy",
    "camera-vss-proxy",
    "camera-service",
    "device_identity-client",
    "inhibit_farewell_test",
    "launch-cluster-proxy",
    "RCN_DiagnosticsAgent",
    "max-defrost-qnx-service"
};

bool is_appl_enabled_at_boot(const std::string &name) {
  auto it =
      std::find(std::begin(apps_white_list), std::end(apps_white_list), name);
  if (it == std::end(apps_white_list)) {
    return false;
  } else {
    return true;
  }
}
#endif // STATS_USE_WHITE_LIST

std::string handler_stat::toString(void) {
  struct tm *timeinfo = nullptr;
  char time_stamp_buffer[80];

  std::chrono::system_clock::time_point const stamp_time_point{
      std::chrono::system_clock::duration{time_stamp}};
  std::time_t const stamp_time_t{
      std::chrono::system_clock::to_time_t(stamp_time_point)};
  timeinfo = localtime(&stamp_time_t);
  strftime(time_stamp_buffer, 80, "%T", timeinfo);

  std::ostringstream sstr;
  sstr << time_stamp_buffer << " (" << std::hex << std::setw(4)
       << std::setfill('0') << client << "): [" << std::hex << std::setw(4)
       << std::setfill('0') << service_id << "." << std::hex << std::setw(4)
       << std::setfill('0') << instance_id << "." << std::hex << std::setw(4)
       << std::setfill('0') << method_id << "]"
       << " " << std::dec << handler_type << " " << std::dec << duration_ms
       << std::endl;

  return std::string(sstr.str());
}

std::string handler_stat::bannerString(void) {
  return std::string("time_stamp (client_id): "
                     "[service_id.instance_id.method_id] type duration");
}

void DeviceProperty::initialize(long _nbytes, DeviceProperty *_pDevProp,
                                std::shared_ptr<statsLogger> _pLogger) {
  iofunc_attr_init(&devAttr_.attr, S_IFNAM | 0666, 0, 0);
  devAttr_.attr.nbytes = _nbytes;
  devAttr_.pDevProp = _pDevProp;
  pLogger_ = _pLogger;
}

void DpEnable::set(const std::string v) {
  std::string shortV = v.substr(0, v.find("\n"));
  if (shortV == "0" && getVal() != "0") {
    formattedPropVal_ = v;
    pLogger_->turnLoggerOff();
  } else if (shortV == "1" && getVal() != "1") {
    pLogger_->turnLoggerOn();
    formattedPropVal_ = v;
  }
}

void DpStorageSize::set(const std::string v) {
  std::string shortV = v.substr(0, v.find("\n"));
  if (std::all_of(shortV.begin(), shortV.end(), ::isdigit)) {
    pLogger_->setBufferSize(std::stoi(shortV));
    formattedPropVal_ = v;
  } else {
    VSOMEIP_ERROR << "[vsomeip_stats]: DpStorageSize::set() not a digit: "
                  << shortV;
  }

  // Update nbytes, consumed by io_read
  devAttr_.attr.nbytes = static_cast<long>(formattedPropVal_.size());
}

void DpHandlerDurationThreshold::set(const std::string v) {
  std::string shortV = v.substr(0, v.find("\n"));
  if (std::all_of(shortV.begin(), shortV.end(), ::isdigit)) {
    formattedPropVal_ = v;
    pLogger_->setThreshold(std::stoi(shortV));
  } else {
    VSOMEIP_ERROR
        << "[vsomeip_stats]: DpHandlerDurationThreshold::set() not a digit: "
        << shortV;
  }

  // Update nbytes, consumed by io_read
  devAttr_.attr.nbytes = static_cast<long>(formattedPropVal_.size());
}

void EventsAboveThreshold::set(const std::string v) {
  formattedPropVal_ = v;

  // Update nbytes, consumed by io_read
  devAttr_.attr.nbytes = static_cast<long>(formattedPropVal_.size());
}

void Snapshot::set(const std::string v) {
  if (!pLogger_->isLogging()) {
    return;
  }

  formattedPropVal_ = v;
  // Update nbytes, consumed by io_read
  devAttr_.attr.nbytes = static_cast<long>(formattedPropVal_.size());

  pLogger_->dumpStats();
}

void Histogram::set(const std::string v) {
  if (!pLogger_->isLogging()) {
    formattedPropVal_ = std::string("stats are disabled\n");
  } else {
    formattedPropVal_ = v;
  }

  // Update nbytes, consumed by io_read
  devAttr_.attr.nbytes = static_cast<long>(formattedPropVal_.size());
}

void Event::set(const std::string v) {
  // Update nbytes, consumed by io_read
  devAttr_.attr.nbytes = static_cast<long>(formattedPropVal_.size());
}

void statsLogger::dumpStats(void) {
  const std::lock_guard<std::mutex> loggerLock(loggerMutex_);

  histogram_snapshot();
  events_above_threshold_snapshot();
}

void statsLogger::events_above_threshold_snapshot(void) {
  try {
    std::ostringstream sstr;
    sstr << handler_stat::bannerString() << std::endl;

    if (dump_buffer_) {
      for (auto i : *dump_buffer_) {
        sstr << i.toString();
      }
    }
    pEventsAboveThreshold_->set(sstr.str());
  } catch (const std::exception &e) {
    VSOMEIP_ERROR << "[vsomeip_stats]: events_above_threshold_snapshot(): "
                  << e.what();
    pEventsAboveThreshold_->set("processing error");
  }
}

static constexpr size_t BUCKET_PRINT_WIDTH = 6;

void statsLogger::histogram_snapshot(void) {
  try {

    if (!histogram_ || !dump_buffer_) {
      pHistogram_->set("processing error");
      return;
    }

    for (auto &i : *histogram_) {
      i = 0;
    }

    for (auto const i : *dump_buffer_) {
      auto bucket = static_cast<unsigned>(floor(i.duration_ms / bucket_size_));
      if (bucket > number_of_buckets_) {
        (*histogram_)[overflow_bucket_]++;
      } else {
        (*histogram_)[bucket]++;
      }
    }

    std::ostringstream sstr;
    sstr << histogram_axis_;
    for (auto const i : *histogram_) {
      sstr.width(BUCKET_PRINT_WIDTH);
      sstr << std::left << i;
    }
    sstr << "\n" << std::endl;

    sstr << "max duration handler:\n";
    sstr << handler_stat::bannerString() << "\n";
    sstr << max_handler.toString();
    sstr << std::endl;

    pHistogram_->set(sstr.str());
  } catch (const std::exception &e) {
    VSOMEIP_ERROR << "[vsomeip_stats]: histogram_snapshot(): " << e.what();
    pHistogram_->set("processing error");
  }
}

void statsLogger::turnLoggerOn() {
  const std::lock_guard<std::mutex> loggerLock(loggerMutex_);
  try {
    if (!dump_buffer_) {
      dump_buffer_ = std::make_unique<c_buffer>(bufferSize_);
    }

    if (!histogram_) {
      histogram_ = std::make_unique<histogram_t>(overflow_bucket_ + 1);

      std::ostringstream sstr;
      for (int i = 0; i < overflow_bucket_; i++) {
        sstr.width(BUCKET_PRINT_WIDTH);
        sstr.fill('.');
        sstr << std::right << (i + 1) * bucket_size_;
      }
      sstr << ".overflow" << std::endl;
      histogram_axis_ = sstr.str();
    }
    loggingStatus_ = true;
  } catch (const std::exception &e) {
    loggingStatus_ = false;
    VSOMEIP_ERROR << "[vsomeip_stats]: turnLoggerOn(): " << e.what();
  }
  return;
}

void statsLogger::turnLoggerOff() {
  const std::lock_guard<std::mutex> loggerLock(loggerMutex_);
  loggingStatus_ = false;
}

void statsLogger::log(const handler_stat &h_stat) {
  if (!isLogging()) {
    return;
  }

  const std::lock_guard<std::mutex> loggerLock(loggerMutex_);
  if (!dump_buffer_) {
    return;
  }
  try {
    if (h_stat.duration_ms >= threshold_) {
      dump_buffer_->push_back(std::move(h_stat));
    }
    if (h_stat.duration_ms > max_handler.duration_ms) {
      max_handler = h_stat;
    }
  } catch (const std::exception &e) {
    loggingStatus_ = false;
    VSOMEIP_ERROR << "[vsomeip_stats]: log(): " << e.what();
    return;
  }
}

void statsResourceManager::start(const std::string &_appName,
                                 size_t _storageSize,
                                 size_t _durationThreshol_MS) {
  appName_ = _appName;
  VSOMEIP_INFO << "[vsomeip_stats]: start() " << __progname << " : "
               << appName_;

  pLogger_ = std::make_shared<statsLogger>();

#ifdef STATS_USE_WHITE_LIST
  bool _enableStats = false;
  if (is_appl_enabled_at_boot(appName_)) {
    _enableStats = true;
  } else {
    _enableStats = false;
  }
#else
  bool _enableStats = true;
#endif // STATS_USE_WHITE_LIST

  auto *env_enable_logging = getenv(VSOMEIP_ENV_ENABLE_LOGGING);
  if (env_enable_logging != nullptr) {
    _enableStats = true;
  }

  pLogger_->pDpEnable_ = &dpEnable_;
  pLogger_->pDpStorageSize_ = &dpStorageSize_;
  pLogger_->pDpHandlerDurationThreshold_ = &dpHandlerDurationThreshold_;
  pLogger_->pSnapshotStats_ = &snapshotStats_;
  pLogger_->pEventsAboveThreshold_ = &eventsAboveThreshold;
  pLogger_->pHistogram_ = &dpHistogram_;

  // Correctly format init values for runResourceManagerThread function
  auto const formattedInitDpEnableVal =
      std::string(_enableStats ? "1" : "0") + "\n";
  auto const formattedInitDpStorageSizeVal =
      std::to_string(_storageSize) + "\n";
  auto const formattedInitDpHandlerDurationThresholdVal =
      std::to_string(_durationThreshol_MS) + "\n";

  std::thread resmgrThread(&statsResourceManager::runResourceManagerThread,
                           this, formattedInitDpEnableVal,
                           formattedInitDpStorageSizeVal,
                           formattedInitDpHandlerDurationThresholdVal);
  resmgrThread.detach();
}

static int io_write(resmgr_context_t *const pDispatchContext, io_write_t *pMsg,
                    RESMGR_OCB_T *const pOcb) {
  auto *const ocb = static_cast<iofunc_ocb_t *>(pOcb);
  int status;
  if ((status = iofunc_write_verify(pDispatchContext, pMsg, ocb, nullptr)) !=
      EOK) {
    return status;
  }

  if ((pMsg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) {
    return ENOSYS;
  }

  // Filter out malicious write requests that attempt to write more data than
  // they provide in the message
  size_t nbytes = _IO_WRITE_GET_NBYTES(pMsg);
  if (nbytes > static_cast<size_t>(pDispatchContext->info.srcmsglen) -
                   pDispatchContext->offset - sizeof(io_write_t)) {
    return EBADMSG;
  }

  // Set up the number of bytes (returned by client's write())
  _IO_SET_WRITE_NBYTES(pDispatchContext, static_cast<long>(nbytes));

  auto pDevAttr =
      static_cast<DeviceAttribute *>(static_cast<void *>(ocb->attr));
  auto *attr = static_cast<iofunc_attr_t *>(&pDevAttr->attr);
  auto *pDevProp = pDevAttr->pDevProp;

  // Alloc space for [ text + '\n' (nbytes) + 1 ('\0') ]
  auto buf = std::make_unique<char[]>(nbytes + 1);
  if (buf == nullptr) {
    return ENOMEM;
  }

  resmgr_msgget(pDispatchContext, buf.get(), nbytes, sizeof(pMsg->i));
  buf[nbytes] = '\0';
  std::string formattedStr(buf.get());
  pDevProp->set(formattedStr);

  if (nbytes > 0) {
    attr->flags |= IOFUNC_ATTR_MTIME | IOFUNC_ATTR_CTIME;
  }

  return _RESMGR_NPARTS(0);
}

static int io_read(resmgr_context_t *const pDispatchContext, io_read_t *pMsg,
                   RESMGR_OCB_T *const pOcb) {
  auto *const ocb = static_cast<iofunc_ocb_t *>(pOcb);
  int status;
  if ((status = iofunc_read_verify(pDispatchContext, pMsg, ocb, nullptr)) !=
      EOK) {
    return status;
  }

  if ((pMsg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) {
    return ENOSYS;
  }

  auto pDevAttr =
      static_cast<DeviceAttribute *>(static_cast<void *>(ocb->attr));
  iofunc_attr_t *attr = &pDevAttr->attr;
  DeviceProperty *pDevProp = pDevAttr->pDevProp;

  auto nleft = static_cast<size_t>(attr->nbytes - ocb->offset);
  size_t nbytes =
      (_IO_READ_GET_NBYTES(pMsg) < nleft) ? _IO_READ_GET_NBYTES(pMsg) : nleft;

  int nparts = -1;
  if (nbytes > 0) {
    // Set up the return data IOV
    SETIOV(pDispatchContext->iov, pDevProp->getValPtr() + ocb->offset, nbytes);

    // Set up the number of bytes (returned by client's read())
    _IO_SET_READ_NBYTES(pDispatchContext, static_cast<long>(nbytes));

    ocb->offset += static_cast<long>(nbytes);
    nparts = 1;
  } else {
    _IO_SET_READ_NBYTES(pDispatchContext, 0);
    nparts = 0;
  }

  // Mark the access time as invalid (we just accessed it)
  if (pMsg->i.nbytes > 0) {
    attr->flags |= IOFUNC_ATTR_ATIME;
  }

  return _RESMGR_NPARTS(nparts);
}

void statsResourceManager::runResourceManagerThread(
    const std::string formattedInitDpEnableVal,
    const std::string formattedInitDpStorageSizeVal,
    const std::string formattedInitDpHandlerDurationThresholdVal) {
  pthread_setname_np(pthread_self(), "vsomeip_stats_resmgr");
  dispatch_t *pDispatch = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);
  if (pDispatch == nullptr) {
    VSOMEIP_ERROR << "[vsomeip_stats]: dispatch_create_channel() failed: "
                  << __progname << " : " << appName_;
    return;
  }

  init(pDispatch, formattedInitDpEnableVal, formattedInitDpStorageSizeVal,
       formattedInitDpHandlerDurationThresholdVal);

  dispatch_context_t *pDispatchContext = dispatch_context_alloc(pDispatch);

  while (1) {
    if ((pDispatchContext = dispatch_block(pDispatchContext)) == nullptr) {
      VSOMEIP_ERROR << "[vsomeip_stats]: nullptr dispatch block: "
                    << std::strerror(errno);
    } else {
      dispatch_handler(pDispatchContext);
    }
    std::this_thread::yield();
  }
}

std::unique_ptr<statsResourceManager>
statsResourceManager::init(const std::string &_appName) {
  auto resMng = std::make_unique<statsResourceManager>();
  resMng->start(_appName, 60000, 4);
  return std::move(resMng);
}

void statsResourceManager::init(
    dispatch_t *pDispatch, const std::string &formattedInitDpEnableVal,
    const std::string &formattedInitDpStorageSizeVal,
    const std::string &formattedInitDpHandlerDurationThresholdVal) {

  std::string dumpFilePath =
      std::string("/dev/shmem/vsomeip_stats_") + appName_;

  std::memset(&resmgrAttr_, 0, sizeof resmgrAttr_);
  resmgrAttr_.nparts_max = 1;
  resmgrAttr_.msg_max_size = 2048;

  iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connectFuncs_, _RESMGR_IO_NFUNCS,
                   &ioFuncs_);

  ioFuncs_.write = io_write;
  ioFuncs_.write64 = io_write;
  ioFuncs_.read = io_read;
  ioFuncs_.read64 = io_read;

  // Setup Device Properties + each Attribute Structure
  // Attach Device Properties
  int id = -1;

  dpStorageSize_.initialize(
      static_cast<long>(formattedInitDpStorageSizeVal.size()), &dpStorageSize_,
      pLogger_);
  dpStorageSize_.set(formattedInitDpStorageSizeVal);

  std::string base_path(devRoot_ + __progname + "/" + appName_);

  std::string storage_size = base_path + "/storage_size";
  id = resmgr_attach(pDispatch,            // Dispatch handle
                     &resmgrAttr_,         // Resource manager attrs
                     storage_size.c_str(), // Device name
                     _FTYPE_ANY,           // Open type
                     0,                    // Flags
                     &connectFuncs_,       // Connect routines
                     &ioFuncs_,            // I/O routines
                     static_cast<RESMGR_HANDLE_T *>(static_cast<void *>(
                         dpStorageSize_.getDevAttrPtr())) // Handle
  );
  if (id == -1) {
    VSOMEIP_ERROR << "[vsomeip_stats]: resmgr_attach failed:"
                  << std::strerror(errno) << ". Device property name -> "
                  << storage_size;
    return;
  }

  dpHandlerDurationThreshold_.initialize(
      static_cast<long>(formattedInitDpHandlerDurationThresholdVal.size()),
      &dpHandlerDurationThreshold_, pLogger_);
  dpHandlerDurationThreshold_.set(formattedInitDpHandlerDurationThresholdVal);

  std::string thresholdPath = base_path + "/threshold";
  id = resmgr_attach(pDispatch,             // Dispatch handle
                     &resmgrAttr_,          // Resource manager attrs
                     thresholdPath.c_str(), // Device name
                     _FTYPE_ANY,            // Open type
                     0,                     // Flags
                     &connectFuncs_,        // Connect routines
                     &ioFuncs_,             // I/O routines
                     static_cast<RESMGR_HANDLE_T *>(static_cast<void *>(
                         dpHandlerDurationThreshold_.getDevAttrPtr())) // Handle
  );
  if (id == -1) {
    VSOMEIP_ERROR << "[vsomeip_stats]: resmgr_attach failed:"
                  << std::strerror(errno) << ". Device property name -> "
                  << thresholdPath;
    return;
  }

  snapshotStats_.initialize(2, &snapshotStats_,
                            pLogger_); // nbytes = 2 is size for [ val + \n ]
  snapshotStats_.set(std::string("0"));

  std::string snapshotPath = base_path + "/snapshot";
  id = resmgr_attach(pDispatch,            // Dispatch handle
                     &resmgrAttr_,         // Resource manager attrs
                     snapshotPath.c_str(), // Device name
                     _FTYPE_ANY,           // Open type
                     0,                    // Flags
                     &connectFuncs_,       // Connect routines
                     &ioFuncs_,            // I/O routines
                     static_cast<RESMGR_HANDLE_T *>(static_cast<void *>(
                         snapshotStats_.getDevAttrPtr())) // Handle
  );
  if (id == -1) {
    VSOMEIP_ERROR << "[vsomeip_stats]: resmgr_attach failed:"
                  << std::strerror(errno) << ". Device property name -> "
                  << snapshotPath;
    return;
  }

  eventsAboveThreshold.initialize(static_cast<long>(dumpFilePath.size()),
                                  &eventsAboveThreshold, pLogger_);
  eventsAboveThreshold.set(dumpFilePath);

  std::string events_above_thresholdPath =
      base_path + "/events_above_threshold";
  id = resmgr_attach(pDispatch,    // Dispatch handle
                     &resmgrAttr_, // Resource manager attrs
                     events_above_thresholdPath.c_str(), // Device name
                     _FTYPE_ANY,                         // Open type
                     0,                                  // Flags
                     &connectFuncs_,                     // Connect routines
                     &ioFuncs_,                          // I/O routines
                     static_cast<RESMGR_HANDLE_T *>(static_cast<void *>(
                         eventsAboveThreshold.getDevAttrPtr())) // Handle
  );
  if (id == -1) {
    VSOMEIP_ERROR << "[vsomeip_stats]: resmgr_attach failed:"
                  << std::strerror(errno) << ". Device property name -> "
                  << events_above_thresholdPath;
    return;
  }

  std::string stats = std::string("stats:");
  dpHistogram_.initialize(static_cast<long>(stats.size()), &dpHistogram_,
                          pLogger_);
  dpHistogram_.set(stats);

  std::string histogramPath = base_path + "/histogram";
  id = resmgr_attach(pDispatch,             // Dispatch handle
                     &resmgrAttr_,          // Resource manager attrs
                     histogramPath.c_str(), // Device name
                     _FTYPE_ANY,            // Open type
                     0,                     // Flags
                     &connectFuncs_,        // Connect routines
                     &ioFuncs_,             // I/O routines
                     static_cast<RESMGR_HANDLE_T *>(static_cast<void *>(
                         dpHistogram_.getDevAttrPtr())) // Handle
  );
  if (id == -1) {
    VSOMEIP_ERROR << "[vsomeip_stats]: resmgr_attach failed:"
                  << std::strerror(errno) << ". Device property name -> "
                  << histogramPath;
    return;
  }

  std::string emptyStr = std::string("");
  event_.initialize(static_cast<long>(emptyStr.size()), &event_, pLogger_);
  event_.set(emptyStr);

  std::string eventPath = base_path + "/event";
  id = resmgr_attach(pDispatch,         // Dispatch handle
                     &resmgrAttr_,      // Resource manager attrs
                     eventPath.c_str(), // Device name
                     _FTYPE_ANY,        // Open type
                     0,                 // Flags
                     &connectFuncs_,    // Connect routines
                     &ioFuncs_,         // I/O routines
                     static_cast<RESMGR_HANDLE_T *>(
                         static_cast<void *>(event_.getDevAttrPtr())) // Handle
  );
  if (id == -1) {
    VSOMEIP_ERROR << "[vsomeip_stats]: resmgr_attach failed:"
                  << std::strerror(errno) << ". Device property name -> "
                  << eventPath;
    return;
  }

  dpEnable_.initialize(2, &dpEnable_,
                       pLogger_); // nbytes = 2 is size for [ val + \n ]
  dpEnable_.set(formattedInitDpEnableVal); // if logging from bootup, starts NOW

  std::string enablePath = base_path + "/vsomeip_enable";
  id = resmgr_attach(pDispatch,          // Dispatch handle
                     &resmgrAttr_,       // Resource manager attrs
                     enablePath.c_str(), // Device name
                     _FTYPE_ANY,         // Open type
                     0,                  // Flags
                     &connectFuncs_,     // Connect routines
                     &ioFuncs_,          // I/O routines
                     static_cast<RESMGR_HANDLE_T *>(static_cast<void *>(
                         dpEnable_.getDevAttrPtr())) // Handle
  );
  if (id == -1) {
    VSOMEIP_ERROR << "[vsomeip_stats]: resmgr_attach failed:"
                  << std::strerror(errno) << ". Device property name -> "
                  << enablePath;
    return;
  }
}

} // namespace vsomeip_v3

#endif // STATS_LOGGER_ON
