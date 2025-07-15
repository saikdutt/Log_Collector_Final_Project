#ifndef NVM_LOG_COLLECTOR_H
#define NVM_LOG_COLLECTOR_H

#include <string>
#include <memory>
#include "BaseCollector.h"
#include "../Utils/Error.h"
class NVMLogCollector : public virtual BaseCollector {
protected:
    bool enable_debug_logs;
    int debug_level;
    std::string nvm_version;

public:

    NVMLogCollector(const std::map<std::string, std::string>& config, 
                  std::shared_ptr<Logger> logger,
                  bool enable_debug_logs = false,
                  int debug_level = 0,
                  const std::string& nvm_version = "5.1");
    virtual ~NVMLogCollector() = default;
    virtual LogCollectorError::ErrorType get_nvm_version() = 0;
    virtual LogCollectorError::ErrorType writeDebugConf() = 0;
    virtual LogCollectorError::ErrorType removeDebugConf() = 0;
    virtual LogCollectorError::ErrorType backupServiceProfile() = 0;
    virtual LogCollectorError::ErrorType restoreServiceProfile() = 0;
    virtual LogCollectorError::ErrorType addTroubleshootTag() = 0;
    virtual LogCollectorError::ErrorType setKDFDebugFlag() = 0;
    virtual LogCollectorError::ErrorType clearKDFDebugFlag() = 0;
    virtual LogCollectorError::ErrorType collectKdfLogs() = 0;
    virtual LogCollectorError::ErrorType stopKdfLogs() = 0;
    virtual LogCollectorError::ErrorType collectNvmLogs() = 0;
    virtual LogCollectorError::ErrorType stopNvmLogs() = 0;
    virtual LogCollectorError::ErrorType collectPacketCapture() = 0;
    virtual LogCollectorError::ErrorType stopPacketCapture() = 0;
};

#endif // NVM_LOG_COLLECTOR_H
