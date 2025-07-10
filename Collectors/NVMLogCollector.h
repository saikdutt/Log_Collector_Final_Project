#ifndef NVM_LOG_COLLECTOR_H
#define NVM_LOG_COLLECTOR_H

#include <string>
#include <memory>
#include "BaseCollector.h"

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
    
    virtual void get_nvm_version() = 0;
    virtual void writeDebugConf() = 0;
    virtual void removeDebugConf() = 0;
    virtual void backupServiceProfile() = 0;
    virtual void restoreServiceProfile() = 0;
    virtual void addTroubleshootTag() = 0;
    virtual void setKDFDebugFlag() = 0;
    virtual void clearKDFDebugFlag() = 0;
    virtual void collectKdfLogs() = 0;
    virtual void stopKdfLogs() = 0;
    virtual void collectNvmLogs() = 0;
    virtual void stopNvmLogs() = 0;
    virtual void collectPacketCapture() = 0;
    virtual void stopPacketCapture() = 0;
};

#endif // NVM_LOG_COLLECTOR_H
