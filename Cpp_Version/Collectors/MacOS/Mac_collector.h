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
    // void collectBrowserHarLogs();
    // std::string formatBrowserTime(const std::chrono::system_clock::time_point& time);
};

#endif // MAC_COLLECTOR_H