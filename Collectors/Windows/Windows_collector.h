#ifndef MAC_COLLECTOR_H
#define MAC_COLLECTOR_H
#include "../NVMLogCollector.h"
#include "../SWGLogCollector.h"
#include "../BaseCollector.h"
class NVMLogCollectorWindows : public virtual NVMLogCollector, public virtual SWGLogCollector {
public:
    NVMLogCollectorWindows(const std::map<std::string, std::string>& config, 
                    std::shared_ptr<Logger> logger);
    ~NVMLogCollectorWindows();

    void get_nvm_version();

    std::string get_nvm_version_string() const;
    // // Path initialization functions
    void findpath();
    void initializePaths();
    // NVM configuration functions
    void writeDebugConf();
    void addTroubleshootTag();
    void findNVMAgentProcesses();
    void setKDFDebugFlag();
    void collectAllLogs();
    void backupServiceProfile();
    void createSWGConfigOverride();
    std::string getUserProfilePath();
    void collectDARTBundle();
    void collectLogsWithTimer();
    void deleteSWGConfigOverride();
    void clearKDFDebugFlag();
    void restoreServiceProfile();
    void removeDebugConf();
    void LogCollectorFile();
    void organizeAndArchiveLogs();
};

#endif // WINDOWS_COLLECTOR_H