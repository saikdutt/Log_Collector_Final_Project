#include <iostream>
#include "Utils/Logger.h"
#include "Utils/Error.h"
// Platform-specific collector includes
#ifdef __APPLE__
    #include "./Collectors/MacOS/Mac_collector.h"
#elif defined(_WIN32)
    #include "./Collectors/Windows/Windows_collector.h"
#elif defined(__linux__)
    #include "./Collectors/Linux/Linux_collector.h"
#else
    #error "Unsupported platform"
#endif

using namespace std;

int main() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    // Create configuration
    std::map<std::string, std::string> config;
    config["log_file"] = "logcollector.log";
    #ifdef __APPLE__
        // Create NVM collector for macOS
        LogCollectorMac collector(config, logger);
    #elif defined(_WIN32)
        // Create NVM collector for Windows
        LogCollectorWindows collector(config, logger);
    #elif defined(__linux__)
        // Create NVM collector for Linux
        LogCollectorLinux collector(config, logger);
    #else
        #error "Unsupported platform"
    #endif
    logger->info("Logger initialized");
    logger->info("Log Collector Application Started");
    collector.LogCollectorFile();
    try
    {
        //Get NVM version
        collector.get_nvm_version();
        collector.writeDebugConf();
        collector.backupServiceProfile();
        collector.addTroubleshootTag();
        collector.setKDFDebugFlag();
        collector.createSWGConfigOverride();
        collector.createAllFilesISEPosture();
        collector.createAllFilesZTA();
        collector.findAllAgentProcesses();
        collector.collectKdfLogs();
        collector.collectNvmLogs();
        collector.collectPacketCapture();
        collector.collectUmbrellaLogs();
        collector.collectIsePostureLogs();
        collector.collectZtaLogs();
        collector.collectLogsWithTimer();
        collector.stopKdfLogs();
        collector.stopNvmLogs();
        collector.stopPacketCapture();
        collector.stopUmbrellaLogs();
        collector.stopIsePostureLogs();
        collector.stopZtaLogs();
        logger->info("All logs collected successfully");
        collector.collectDARTLogs();
        logger->info("DART logs collected successfully");
        collector.removeDebugConf();
        collector.clearKDFDebugFlag();
        collector.restoreServiceProfile();
        collector.deleteSWGConfigOverride();
        collector.deleteAllFilesISEPosture();
        collector.deleteAllFilesZTA();
        collector.findAllAgentProcesses();
        collector.organizeAndArchiveLogs();
    }
    catch(const std::exception& e)
    {
        logger->error("Error Occured");
    }
    return 0;
}