#ifndef LINUX_COLLECTOR_H
#define LINUX_COLLECTOR_H
#include "../NVMLogCollector.h"
#include "../SWGLogCollector.h"
#include "../BaseCollector.h"
#include "../ISEPostureCollector.h"
#include "../ZTALogCollector.h"
#include "../../Utils/Common.h"
class NVMLogCollectorLinux : 
    public virtual NVMLogCollector, 
    public virtual SWGLogCollector,
    public virtual ISEPostureCollector, 
    public virtual ZTACollector {
private:
    CommonUtils utils;  
public:
    NVMLogCollectorLinux(const std::map<std::string, std::string>& config, 
                      std::shared_ptr<Logger> logger,
                      bool enable_debug_logs = false,
                      int debug_level = 0);
    ~NVMLogCollectorLinux();
    void get_nvm_version();
    void writeDebugConf();
    void backupServiceProfile();
    void addTroubleshootTag();
    void restoreServiceProfile();
    void removeDebugConf();
    void setKDFDebugFlag();
    void clearKDFDebugFlag();
    void findAllAgentProcesses();
    void collectDARTLogs();
    void collectAllLogsSimultaneously();
    void collectLogsWithTimer();
    void LogCollectorFile();
    void createAllFilesISEPosture();
    void deleteAllFilesISEPosture();
    void createAllFilesZTA();
    void deleteAllFilesZTA();
    void organizeAndArchiveLogs();
};

#endif // LINUX_COLLECTOR_H