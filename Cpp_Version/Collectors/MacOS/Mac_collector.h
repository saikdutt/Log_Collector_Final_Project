#ifndef MAC_COLLECTOR_H
#define MAC_COLLECTOR_H
#include "../NVMLogCollector.h"
#include "../SWGLogCollector.h"
#include "../BaseCollector.h"
class NVMLogCollectorMac : public virtual NVMLogCollector, public virtual SWGLogCollector {
public:
    NVMLogCollectorMac(const std::map<std::string, std::string>& config, 
                      std::shared_ptr<Logger> logger,
                      bool enable_debug_logs = false,
                      int debug_level = 0);
    ~NVMLogCollectorMac();

    void get_nvm_version();

    std::string get_nvm_version_string() const;
    // Path initialization functions
    void findpath();
    void initializePaths();
    // NVM configuration functions
    void writeDebugConf();
    void addTroubleshootTag();
    void findNVMAgentProcesses();
    void setKDFDebugFlag();
    void resetKDFDebugFlag();
    void createSWGConfigOverride();
    void backupServiceProfile();
    void restoreServiceProfile();
    void collectAllLogsSimultaneously();
    void collectDARTLogs();
    void organizeAndArchiveLogs();
    void removeDebugConf();
    void clearKDFDebugFlag();
    void LogCollectorFile();
    void deleteSWGConfigOverride();
    void collectLogsWithTimer();
};

#endif // MAC_COLLECTOR_H