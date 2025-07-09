#ifndef MAC_COLLECTOR_H
#define MAC_COLLECTOR_H
#include "../NVMLogCollector.h"
#include "../SWGLogCollector.h"
#include "../BaseCollector.h"
#include "../ISEPostureCollector.h"
#include "../ZTALogCollector.h"
#include "../../Utils/Common.h"
class NVMLogCollectorWindows : 
    public virtual NVMLogCollector,
    public virtual SWGLogCollector,
    public virtual ISEPostureCollector, 
    public virtual ZTACollector {
private:
    CommonUtils utils;
public:
   NVMLogCollectorWindows(const std::map<std::string, std::string>& config, 
                      std::shared_ptr<Logger> logger,
                      bool enable_debug_logs = false,
                      int debug_level = 0);
    ~NVMLogCollectorWindows();

    void get_nvm_version();
    // NVM configuration functions
    void writeDebugConf();
    void addTroubleshootTag();
    void findAllAgentProcesses();
    void setKDFDebugFlag();
    void createSWGConfigOverride();
    void deleteSWGConfigOverride();
    void backupServiceProfile();
    void restoreServiceProfile();
    void collectAllLogsSimultaneously();
    std::string getUserProfilePath();
    void collectDARTBundle();
    void collectLogsWithTimer();
    void clearKDFDebugFlag();
    void removeDebugConf();
    void LogCollectorFile();
    void createAllFilesISEPosture();
    void deleteAllFilesISEPosture();
    void createAllFilesZTA();
    void deleteAllFilesZTA();
    void organizeAndArchiveLogs();
};

#endif // WINDOWS_COLLECTOR_H