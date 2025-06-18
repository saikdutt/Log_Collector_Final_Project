#include <iostream>
#include "Utils/Logger.h"
// Platform-specific collector includes
#ifdef __APPLE__
    #include "./Collectors/MacOS/Mac_collector.h"
    using CollectorType = NVMLogCollectorMac;
#elif defined(_WIN32)
    #include "./Collectors/Windows/Windows_collector.h"
    using CollectorType = NVMLogCollectorWindows;
#elif defined(__linux__)
    #include "./Collectors/Linux/Linux_collector.h"
    using CollectorType = NVMLogCollectorLinux;
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
            
    // Create NVM collector for macOS
    NVMLogCollectorMac collector(config, logger);
    try
    {
        try
        {            
            // Get NVM version
            collector.get_nvm_version();
            logger->info("NVM version: " + collector.get_nvm_version_string());
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            collector.findpath();
            logger->info("Path successfully found in the system");
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            collector.initializePaths();
        }
        catch(const std::exception& e)
        {
           logger->error("Error Occured");
        }
        try
        {
           logger->info("Enter the debug value");
           collector.writeDebugConf();
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            collector.backupServiceProfile();
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            collector.addTroubleshootTag();
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            collector.findNVMAgentProcesses();
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            collector.AddupdateOrgInfo();
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            logger->info("Enter the hexadecimal KDF value");
            collector.setKDFDebugFlag();
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            collector.collectKDFLogs();
            logger->info("KDF Logs Collected Sucessfully");
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            collector.collectAllLogsSimultaneously();
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            collector.collectDARTLogs();
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            collector.removeDebugConf();
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            collector.clearKDFDebugFlag();
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            collector.restoreServiceProfile();
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            collector.findNVMAgentProcesses();
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            collector.resetOrgInfo();
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
        try
        {
            collector.organizeAndArchiveLogs();
        }
        catch(const std::exception& e)
        {
            logger->error("Error Occured");
        }
    }
    catch(const std::exception& e)
    {
        logger->error("Error Occured");
    }
    return 0;
}