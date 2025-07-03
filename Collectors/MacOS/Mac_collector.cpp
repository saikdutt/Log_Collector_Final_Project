#if defined(__cplusplus) && __cplusplus >= 201703L
#include <filesystem>
namespace fs = std::filesystem;
#else
#error "Need C++17 for filesystem support"
#endif
#include <iostream>
#include <fstream>
#include <filesystem>
#include <unistd.h>
#include <array>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <cctype> 
#include <sstream> 
#include <atomic>
#include <chrono>
#include <thread>
#include <signal.h>
#include <iomanip>
#include <regex>
#include <curl/curl.h>
#include "Mac_collector.h"
#include "../../Utils/Logger.h"
#include "../../Utils/Error.h"
#include "../../Utils/Common.h"
// Declare the global signal status variable from main.cpp
using namespace std;

// Constructor implementation
NVMLogCollectorMac::NVMLogCollectorMac(const std::map<std::string, std::string>& config, 
    std::shared_ptr<Logger> logger)
    :BaseCollector(config, logger),
    NVMLogCollector(config, logger),
    SWGLogCollector(config, logger),
    utils(logger) {

    logger->info("NVMCollectorMac initialized with NVM and SWG support.");
}
NVMLogCollectorMac::~NVMLogCollectorMac() {
    logger->info("NVMLogCollectorMac destroyed");
}
void NVMLogCollectorMac::get_nvm_version() {
    logger->info("Getting NVM agent version...");
    try {
        // Create a pipe to capture command output
        std::array<char, 128> buffer;
        std::string result;
        
        // Command to get NVM agent version
        std::string cmd = "sudo " + MacPaths::NVM_AGENT + " -v";

        // Execute command and capture output
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            throw std::runtime_error("Failed to execute command to get NVM version");
        }
        
        // Read output
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
            result += buffer.data();
        }
        
        // Close pipe
        int status = pclose(pipe);
        if (status != 0) {
            logger->warning("Command returned to non-zero status: " + std::to_string(status));
        }
        
        // Parse version from output - improved pattern matching
        std::regex versionPattern("Version\\s*:\\s*(\\d+\\.\\d+\\.\\d+(?:-\\w+)?)");
        std::smatch matches;
        if (std::regex_search(result, matches, versionPattern) && matches.size() > 1) {
            nvm_version = matches[1].str();
            logger->info("NVM agent version found: " + nvm_version);
        } else {
            logger->warning("Could not parse the NVM version from output : " + result);
            nvm_version = "unknown";
        }
        
    } catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("Error getting NVM version: " + std::string(e.what()));
        nvm_version = "error";
    }
}
void NVMLogCollectorMac::writeDebugConf() {
    utils.writeDebugConfSystem(MacPaths::DEBUG_CONF);
}
void NVMLogCollectorMac::removeDebugConf() {
    utils.removeDebugConfSystem(MacPaths::DEBUG_CONF);
}
void NVMLogCollectorMac::addTroubleshootTag() {  
    utils.addTroubleshootTagSystem(MacPaths::SERVICE_PROFILE);
}
void NVMLogCollectorMac::setKDFDebugFlag() {
    string hexInput;
    logger->info("\nEnter debug flag (hexadecimal, e.g., 0x20): ");
    cin >> hexInput;
    utils.setKDFDebugFlagSystem(MacPaths::ACSOCKTOOL, hexInput);
}
void NVMLogCollectorMac::clearKDFDebugFlag() {
    utils.clearKDFDebugFlagsSystem(MacPaths::ACSOCKTOOL);
}
void NVMLogCollectorMac::createSWGConfigOverride() {
    utils.createSWGConfigOverrideSystem(MacPaths::UMBRELLA_PATH);
}
void NVMLogCollectorMac::deleteSWGConfigOverride() {
    utils.deleteSWGConfigOverrideSystem(MacPaths::UMBRELLA_PATH);
}
void NVMLogCollectorMac::findNVMAgentProcesses() {
    try{
        logger->info("Searching for NVM agent processes...");
        logger->info("Searching for NVM agent processes...");
        
        // Command to find NVM agent processes
        std::string cmd1 = "ps -ef | grep acnvmagent";
        
        int result1 = system(cmd1.c_str());
        
        if (result1 == 0) {
            logger->info("NVM agent processes found and displayed");
        } else {
            logger->warning("Command execution returned non-zero status: " + std::to_string(result1));
        }
        
        // Create a pipe to capture command output
        std::array<char, 128> buffer;
        std::string result;
        std::string cmd = "ps -ef | grep acnvmagent";
        
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            logger->error("Failed to execute process search command");
            return;
        }
        
        // Read the command output
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
            result += buffer.data();
        }
        pclose(pipe);
        
        // Parse the output to get PID
        std::istringstream stream(result);
        std::string line;
        std::string pid;
        
        if (std::getline(stream, line)) {
            std::istringstream iss(line);
            std::string column;
            int columnCount = 0;
                
            while (iss >> column && columnCount < 2) {
                if (columnCount == 1) { // Second column
                    pid = column;
                    break;
                }
                columnCount++;
            }
        }
        if (!pid.empty()) {
            logger->info("Found NVM agent PID: " + pid);
            
            // Use the PID (example: kill the process)
            std::string killCmd = "sudo kill -9 " + pid;
            int result = system(killCmd.c_str());
            
            if (result == 0) {
                logger->info("Successfully terminated NVM agent process");
            } else {
                logger->error("Failed to terminate process with PID: " + pid);
            }
            std::string startCmd = "sudo /opt/cisco/secureclient/NVM/bin/acnvmagent.app/Contents/MacOS/acnvmagent &";
            int startResult = system(startCmd.c_str());
            
            if (startResult == 0) {
                logger->info("[+] Successfully started NVM agent");
            } else {
                logger->error("[!] Failed to start NVM agent");
            }
        } else {
            logger->warning("No NVM agent PID found");
        }
        logger->info("Searching for Umbrella agent processes...");

        // Command to find Umbrella agent processes
        std::string umbrellaCmd1 = "ps -ef | grep acumbrellaagent";

        int umbrellaResult1 = system(umbrellaCmd1.c_str());

        if (umbrellaResult1 == 0) {
            logger->info("Umbrella agent processes found and displayed");
        } else {
            logger->warning("Command execution returned non-zero status: " + std::to_string(umbrellaResult1));
        }

        // Create a pipe to capture command output
        std::array<char, 128> umbrellaBuffer;
        std::string umbrellaResult;
        std::string umbrellaCmd = "ps -ef | grep acumbrellaagent";

        FILE* umbrellaPipe = popen(umbrellaCmd.c_str(), "r");
        if (!umbrellaPipe) {
            logger->error("Failed to execute Umbrella process search command");
            return;
        }

        // Read the command output
        while (fgets(umbrellaBuffer.data(), umbrellaBuffer.size(), umbrellaPipe) != nullptr) {
            umbrellaResult += umbrellaBuffer.data();
        }
        pclose(umbrellaPipe);

        // Parse the output to get PID
        std::istringstream umbrellaStream(umbrellaResult);
        std::string umbrellaLine;
        std::string umbrellaPid;

        if (std::getline(umbrellaStream, umbrellaLine)) {
            std::istringstream umbrellaIss(umbrellaLine);
            std::string umbrellaColumn;
            int umbrellaColumnCount = 0;
                
            while (umbrellaIss >> umbrellaColumn && umbrellaColumnCount < 2) {
                if (umbrellaColumnCount == 1) { // Second column
                    umbrellaPid = umbrellaColumn;
                    break;
                }
                umbrellaColumnCount++;
            }
        }

        if (!umbrellaPid.empty()) {
            logger->info("Found Umbrella agent PID: " + umbrellaPid);
            
            // Use the PID to kill the process
            std::string umbrellaKillCmd = "sudo kill -9 " + umbrellaPid;
            int umbrellaKillResult = system(umbrellaKillCmd.c_str());
            
            if (umbrellaKillResult == 0) {
                logger->info("Successfully terminated Umbrella agent process");
            } else {
                logger->error("Failed to terminate Umbrella process with PID: " + umbrellaPid);
            }
            std::string startCmd1 = "sudo /opt/cisco/secureclient/bin/acumbrellaagent &";
            int startResult1 = system(startCmd1.c_str());

            if (startResult1 == 0) {
                logger->info("[+] Successfully started Umbrella agent");
            } else {
                logger->error("[!] Failed to start Umbrella agent");
            }
        } else {
            logger->warning("No Umbrella agent PID found");
        }
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error finding NVM agent processes: " + std::string(e.what()));
    }
}
void NVMLogCollectorMac::backupServiceProfile() {
    try{
        logger->info("Creating backup of NVM_ServiceProfile.xml...");
        
        std::string cmd = "sudo cp /opt/cisco/secureclient/NVM/NVM_ServiceProfile.xml /opt/cisco/secureclient/NVM/NVM_ServiceProfile.xml.bak";
        
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("Backup created successfully as NVM_ServiceProfile.xml.bak");
        } else {
            logger->error("Failed to create backup, error code: " + std::to_string(result));
        }
    }
    catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error creating backup: " + std::string(e.what()));
    }
}
void NVMLogCollectorMac::restoreServiceProfile() {
    try{
        logger->info("Restoring NVM_ServiceProfile.xml from backup...");
    
        std::string cmd = "sudo cp /opt/cisco/secureclient/NVM/NVM_ServiceProfile.xml.bak /opt/cisco/secureclient/NVM/NVM_ServiceProfile.xml";
        
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("NVM_ServiceProfile.xml restored successfully from backup");
        } else {
            logger->error("Failed to restore from backup, error code: " + std::to_string(result));
        }
        std::string cmd1 = "sudo rm /opt/cisco/secureclient/NVM/NVM_ServiceProfile.xml.bak";

        int result1 = system(cmd1.c_str());
        
        if (result1 == 0) {
            logger->info("Successfully removed backup file: " + cmd1);
        } else {
            logger->error("Failed to remove backup file. Error code: " + std::to_string(result1));
        }
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error restoring service profile: " + std::string(e.what()));
    }
}
void NVMLogCollectorMac::collectAllLogsSimultaneously() {
    try{
        logger->info("Starting all log collections simultaneously...");
        logger->info("Press Ctrl+C to stop all collections when ready");

        const char* homeDir = getenv("HOME");
        if (!homeDir) {
            logger->error("Could not determine home directory");
            return;
        }

        // Define paths for different log files
        std::string kdfLogsPath = std::string(homeDir) + "/Desktop/kdf_logs.log";
        std::string nvmLogsPath = std::string(homeDir) + "/Desktop/nvm_system_logs.log";
        std::string umbrellaLogsPath = std::string(homeDir) + "/Desktop/swg_umbrella_logs.log";
        std::string packetCapturePath = std::string(homeDir) + "/Desktop/PacketCapture.pcap";

        // Construct commands for different log collections
        // Create a vector of pairs containing both command and description
        std::vector<std::pair<std::string, std::string>> commands = {
            {
                + "sudo log stream --predicate 'process == \"com.cisco.anyconnect.macos.acsockext\"' "
                "--style syslog > " + kdfLogsPath + " &",
                "KDF Logs"
            },
            {
                "sudo log stream --predicate 'process == \"acnvmagent\"' --style syslog > " + 
                nvmLogsPath + " &",
                "NVM System Logs"
            },
            {
                "sudo tcpdump -w " + packetCapturePath + " &",
                "Packet Capture"
            },
            {
                "sudo log stream --predicate 'process == \"acumbrellaagent\"' --style syslog > " + 
                umbrellaLogsPath + " &",
                "Umbrella/SWG Logs"
            }
        };

        // Start all collections with descriptive logging
        logger->info("Starting all log collections...");
        for (const auto& [cmd, description] : commands) {
            logger->info("[*] Starting " + description + " collection...");
            int result = system(cmd.c_str());
            if (result == 0) {
                logger->info("[+] Successfully started " + description + " collection");
            } else {
                logger->error("[!] Failed to start " + description + " collection");
            }
        }
        utils.collectLogsWithTimer();
        // When Ctrl+C is pressed, stop all collections
        logger->info("\nStopping all log collections...");
        
        // Kill all collection processes
        std::vector<std::pair<std::string, std::string>> killCommands = {
            {"sudo pkill -f 'log stream.*com.cisco.anyconnect.macos.acsockext' || true", "KDF Logs"},
            {"sudo killall tcpdump || true", "Packet Capture"},
        };

        // Stop each process with descriptive logging
        for (const auto& [cmd, description] : killCommands) {
            logger->info("Stopping " + description + " collection...");
            int result = system(cmd.c_str());
            if (result == 0) {
                logger->info("[+] Successfully stopped " + description + " collection");
            } else {
                logger->warning("[!] Failed to stop " + description + " collection");
            }
        }
        logger->info("Logs have been saved to the Desktop");
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error collecting logs: " + std::string(e.what()));
    }
}
void NVMLogCollectorMac::collectDARTLogs() {
    try{
        logger->info("Starting DART log collection...");
    
        // Get user's desktop path
        const char* homeDir = getenv("HOME");
        if (!homeDir) {
            logger->error("Could not determine home directory");
            return;
        }
        
        std::string desktopPath = std::string(homeDir) + "/Desktop/DART_Bundle.zip";
        
        // Construct the DART CLI command with proper escaping
        std::string cmd = "sudo /Applications/Cisco/Cisco\\ Secure\\ Client\\ -\\ DART.app/Contents/Resources/dartcli "
                        "-dst " + desktopPath + " -syslogs";
        
        logger->info("Dart log are Collecting...");
        int result = system(cmd.c_str());
        logger->info("DART bundle saved to: " + desktopPath);
        if (result == 0) {
            logger->info("DART logs collected successfully");
        } else {
            logger->error("Failed to collect DART logs. Error code: " + std::to_string(result));
        }
    }
    catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error collecting logs: " + std::string(e.what()));
    }
}
void NVMLogCollectorMac::LogCollectorFile(){
    try{
        std::string buildPath = fs::current_path().string();
        std::string logCollectorPath = buildPath + "/logcollector.log"; 
        if(fs::exists(logCollectorPath)){
            std::ifstream logFile(logCollectorPath, std::ios::trunc);
            logger->info("Log file found and truncated: " + logCollectorPath);
            if(logFile.is_open()) {
                logFile.close();
            } else {
                return ;
            }
        }
        else{
            return ;
        }
    }catch (const std::exception& e) {
        return ;
    }
}
void NVMLogCollectorMac::organizeAndArchiveLogs() {
    try{
        logger->info("Organizing and archiving collected logs...");
        
        const char* homeDir = getenv("HOME");
        if (!homeDir) {
            logger->error("Could not determine home directory");
            return;
        }
        
        std::string desktopPath = std::string(homeDir) + "/Desktop";
        std::string nvmLogsDir = desktopPath + "/nvm_logs";
        std::string buildPath = fs::current_path().string();
        std::string logCollectorPath = buildPath + "/logcollector.log";
        
        // 1. Create nvm_logs directory
        std::string mkdirCmd = "mkdir -p " + nvmLogsDir;
        logger->info("Creating logs directory: " + nvmLogsDir);
        if (system(mkdirCmd.c_str()) != 0) {
            logger->error("Failed to create nvm_logs directory");
            return;
        }
        logger->info("Successfully created nvm_logs directory");
        logger->info("Moving log files to nvm_logs directory");
        logger->info("Creating zip archive of logs...");
        logger->info("Successfully created archive: secure_client_logs.zip");
        logger->info("Cleaned up temporary logs directory");
        logger->info("Cleaning up the logcollector.log file");
        logger->info("Logcollector file cleared successfully");
        logger->info("LogCollectorMacOS destroyed");
        logger->info("Log Collection completed successfully");
        // 2. First copy logcollector.log to nvm_logs (don't move it)
        std::string copyLogCmd = "cp " + logCollectorPath + " " + nvmLogsDir + "/";
        system(copyLogCmd.c_str());
        
        // 3. Move all other log files to nvm_logs directory
        std::string moveCmd = "mv " + desktopPath + "/kdf_logs.log " +
                            desktopPath + "/nvm_system_logs.log " +
                            desktopPath + "/PacketCapture.pcap " +
                            desktopPath + "/DART_Bundle.zip " +
                            desktopPath + "/swg_umbrella_logs.log " +
                            nvmLogsDir + "/ 2>/dev/null";
        
        system(moveCmd.c_str());
        // 4. Create timestamped zip archive
        std::string timestamp = "";
        {
            time_t now = time(nullptr);
            char buf[20];
            strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", localtime(&now));
            timestamp = buf;
        }
        
        std::string zipCmd = "cd " + desktopPath + " && zip -r secure_client_logs_" + 
                            timestamp + ".zip nvm_logs/";
        
        logger->info("Creating zip archive of logs...");
        if (system(zipCmd.c_str()) == 0) {
            logger->info("Successfully created archive: secure_client_logs_" + timestamp + ".zip");
            // Optional: Clean up nvm_logs directory after successful archive
            std::string cleanupCmd = "rm -rf " + nvmLogsDir;
            if (system(cleanupCmd.c_str()) == 0) {
                logger->info("Cleaned up temporary logs directory");
            }
        } else {
            logger->error("Failed to create zip archive");
        }
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error organizing and archiving logs: " + std::string(e.what()));
    }
}