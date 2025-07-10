#ifndef MAC_COLLECTOR_H
#define MAC_COLLECTOR_H
#include "../NVMLogCollector.h"
#include "../SWGLogCollector.h"
#include "../BaseCollector.h"
#include "../ISEPostureCollector.h"
#include "../ZTALogCollector.h"
#include "../../Utils/Common.h" 
class NVMLogCollectorMac : 
    public virtual NVMLogCollector, 
    public virtual SWGLogCollector, 
    public virtual ISEPostureCollector, 
    public virtual ZTACollector {
private:
    CommonUtils utils;  
public:
    NVMLogCollectorMac(const std::map<std::string, std::string>& config, 
                      std::shared_ptr<Logger> logger,
                      bool enable_debug_logs=false,
                      int debug_level=0);
    ~NVMLogCollectorMac();
    // Implement BaseCollector functions
    void findAllAgentProcesses() override;
    void collectLogsWithTimer() override;
    void LogCollectorFile() override;
    void organizeAndArchiveLogs() override;
    void collectDARTLogs() override;

    // Implement NVMLogCollector functions
    // NVM configuration functions
    void get_nvm_version() override;
    void writeDebugConf() override;
    void removeDebugConf() override;
    void backupServiceProfile() override;
    void restoreServiceProfile() override;
    void addTroubleshootTag() override;
    void setKDFDebugFlag() override;
    void clearKDFDebugFlag() override;
    void collectKdfLogs() override;
    void stopKdfLogs() override;
    void collectNvmLogs() override;
    void stopNvmLogs() override;
    void collectPacketCapture() override;
    void stopPacketCapture() override;

    // Implement SWGLogCollector functions
    void createSWGConfigOverride() override;
    void deleteSWGConfigOverride() override;
    void collectUmbrellaLogs() override;
    void stopUmbrellaLogs() override;

    // Implement ISEPostureCollector functions
    void createAllFilesISEPosture() override;
    void deleteAllFilesISEPosture() override;
    void collectIsePostureLogs() override;
    void stopIsePostureLogs() override;

    // Implement ZTACollector functions
    void createAllFilesZTA() override;
    void deleteAllFilesZTA() override;
    void collectZtaLogs() override;
    void stopZtaLogs() override;
};

#endif // MAC_COLLECTOR_H