#ifndef LINUX_COLLECTOR_H
#define LINUX_COLLECTOR_H
#include "../NVMLogCollector.h"
#include "../SWGLogCollector.h"
#include "../BaseCollector.h"
class NVMLogCollectorLinux : public virtual NVMLogCollector, public virtual SWGLogCollector {
public:
    NVMLogCollectorLinux(const std::map<std::string, std::string>& config, 
                      std::shared_ptr<Logger> logger,
                      bool enable_debug_logs = false,
                      int debug_level = 0);
    ~NVMLogCollectorLinux();
    void get_nvm_version();
    std::string get_nvm_version_string();
    void findpath();
    void initializePaths();
    void writeDebugConf();
    void backupServiceProfile();
    void addTroubleshootTag();
    void restoreServiceProfile();
    void removeDebugConf();
    void setKDFDebugFlag();
    void resetKDFDebugFlag();
    void findNVMAgentProcesses();
    void collectDARTLogs();
    void collectAllLogsSimultaneously();
    void collectLogsWithTimer();
    void LogCollectorFile();
    void organizeAndArchiveLogs();
};

#endif // LINUX_COLLECTOR_H