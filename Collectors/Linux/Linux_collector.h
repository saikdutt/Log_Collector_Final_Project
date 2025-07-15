#ifndef LINUX_COLLECTOR_H
#define LINUX_COLLECTOR_H
#include "../NVMLogCollector.h"
#include "../SWGLogCollector.h"
#include "../BaseCollector.h"
#include "../ISEPostureCollector.h"
#include "../ZTALogCollector.h"
#include "../../Utils/Common.h"
class LogCollectorLinux : 
    public virtual NVMLogCollector, 
    public virtual SWGLogCollector,
    public virtual ISEPostureCollector, 
    public virtual ZTACollector {
private:
    CommonUtils utils;  
public:
    LogCollectorLinux(const std::map<std::string, std::string>& config, 
                      std::shared_ptr<Logger> logger,
                      bool enable_debug_logs = false,
                      int debug_level = 0);
    ~LogCollectorLinux();
    // Implement BaseCollector functions
    LogCollectorError::ErrorType checkAdminPrivileges() override;
    LogCollectorError::ErrorType findAllAgentProcesses() override;
    LogCollectorError::ErrorType collectLogsWithTimer() override;
    LogCollectorError::ErrorType LogCollectorFile() override;
    LogCollectorError::ErrorType organizeAndArchiveLogs() override;
    LogCollectorError::ErrorType collectDARTLogs() override;

    // Implement NVMLogCollector functions
    // NVM configuration functions
    LogCollectorError::ErrorType get_nvm_version() override;
    LogCollectorError::ErrorType writeDebugConf() override;
    LogCollectorError::ErrorType removeDebugConf() override;
    LogCollectorError::ErrorType backupServiceProfile() override;
    LogCollectorError::ErrorType restoreServiceProfile() override;
    LogCollectorError::ErrorType addTroubleshootTag() override;
    LogCollectorError::ErrorType setKDFDebugFlag() override;
    LogCollectorError::ErrorType clearKDFDebugFlag() override;
    LogCollectorError::ErrorType collectKdfLogs() override;
    LogCollectorError::ErrorType stopKdfLogs() override;
    LogCollectorError::ErrorType collectNvmLogs() override;
    LogCollectorError::ErrorType stopNvmLogs() override;
    LogCollectorError::ErrorType collectPacketCapture() override;
    LogCollectorError::ErrorType stopPacketCapture() override;

    // Implement SWGLogCollector functions
    LogCollectorError::ErrorType createSWGConfigOverride() override;
    LogCollectorError::ErrorType deleteSWGConfigOverride() override;
    LogCollectorError::ErrorType collectUmbrellaLogs() override;
    LogCollectorError::ErrorType stopUmbrellaLogs() override;

    // Implement ISEPostureCollector functions
    LogCollectorError::ErrorType createAllFilesISEPosture() override;
    LogCollectorError::ErrorType deleteAllFilesISEPosture() override;
    LogCollectorError::ErrorType collectIsePostureLogs() override;
    LogCollectorError::ErrorType stopIsePostureLogs() override;

    // Implement ZTACollector functions
    LogCollectorError::ErrorType createAllFilesZTA() override;
    LogCollectorError::ErrorType deleteAllFilesZTA() override;
    LogCollectorError::ErrorType collectZtaLogs() override;
    LogCollectorError::ErrorType stopZtaLogs() override;
};

#endif // LINUX_COLLECTOR_H