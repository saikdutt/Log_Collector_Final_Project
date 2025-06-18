#ifndef NVM_LOG_COLLECTOR_H
#define NVM_LOG_COLLECTOR_H

#include <string>
#include <memory>
#include "BaseCollector.h"

class NVMLogCollector : public BaseCollector {
protected:
    bool enable_debug_logs;
    int debug_level;
    bool kdf_flags_set;
    bool packet_capture_enabled;
    bool enable_kdf_logging;
    std::string nvm_version;

public:

    NVMLogCollector(const std::map<std::string, std::string>& config, 
                  std::shared_ptr<Logger> logger,
                  bool enable_debug_logs = false,
                  int debug_level = 0,
                  const std::string& nvm_version = "5.1");
    
     // NVM configuration functions
    void writeDebugConf();
    void addTroubleshootTag();
    void removeTroubleshootTag();
    void findNVMAgentProcesses();
    // KDF debugging functions
    void setKDFDebugFlag();
    void resetKDFDebugFlag();

    // Umbrella configuration
    void AddupdateOrgInfo();
    void backupServiceProfile();
    void restoreServiceProfile();
    void collectKDFLogs();
    void collectAllLogsSimultaneously();
    void collectDARTLogs();
    void organizeAndArchiveLogs();
    void removeDebugConf();
    void clearKDFDebugFlag();
    void resetOrgInfo();
    void collectLogsWithTimer();
};

#endif // NVM_LOG_COLLECTOR_H
