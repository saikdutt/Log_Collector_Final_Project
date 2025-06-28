#include <iostream>
#include "Utils/Logger.h"
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
    logger->info("Log Collector Application Started");
    // Create configuration
    std::map<std::string, std::string> config;
    config["log_file"] = "logcollector.log";
    #ifdef __APPLE__
        // Create NVM collector for macOS
        NVMLogCollectorMac collector(config, logger);
    #elif defined(_WIN32)
        // Create NVM collector for Windows
        NVMLogCollectorWindows collector(config, logger);
    #elif defined(__linux__)
        // Create NVM collector for Linux
        NVMLogCollectorLinux collector(config, logger);
    #else
        #error "Unsupported platform"
    #endif
    try
    {
        // Get NVM version
        collector.get_nvm_version();
        logger->info("NVM version: " + collector.get_nvm_version_string());
        collector.findpath();
        logger->info("Path successfully found in the system");
        collector.initializePaths();
        collector.writeDebugConf();
        collector.backupServiceProfile();
        collector.addTroubleshootTag();
        collector.createSWGConfigOverride();
        logger->info("Enter the hexadecimal KDF value");
        collector.setKDFDebugFlag();
        collector.findNVMAgentProcesses();
        logger->info("KDF Logs Collected Sucessfully");
        collector.collectAllLogsSimultaneously();
        collector.collectDARTLogs();
        collector.removeDebugConf();
        collector.clearKDFDebugFlag();
        collector.restoreServiceProfile();
        collector.findNVMAgentProcesses();
        collector.deleteSWGConfigOverride();
        collector.organizeAndArchiveLogs();
        collector.deleteLogCollectorFile();
    }
    catch(const std::exception& e)
    {
        logger->error("Error Occured");
    }
    return 0;
}