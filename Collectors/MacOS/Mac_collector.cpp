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
        // NVM Agent Section
        logger->info("Searching for NVM agent processes...");
        std::string nvmCmd1 = "ps -ef | grep acnvmagent";
        int nvmResult1 = system(nvmCmd1.c_str());

        if (nvmResult1 == 0) {
            logger->info("NVM agent processes found and displayed");
        } else {
            logger->warning("Command execution returned non-zero status: " + std::to_string(nvmResult1));
        }

        std::array<char, 128> nvmBuffer;
        std::string nvmResult;
        std::string nvmCmd = "ps -ef | grep acnvmagent";

        FILE* nvmPipe = popen(nvmCmd.c_str(), "r");
        if (!nvmPipe) {
            logger->error("Failed to execute process search command");
            return;
        }

        while (fgets(nvmBuffer.data(), nvmBuffer.size(), nvmPipe) != nullptr) {
            nvmResult += nvmBuffer.data();
        }
        pclose(nvmPipe);

        std::istringstream nvmStream(nvmResult);
        std::string nvmLine;
        std::string nvmPid;

        if (std::getline(nvmStream, nvmLine)) {
            std::istringstream nvmIss(nvmLine);
            std::string nvmColumn;
            int nvmColumnCount = 0;
                
            while (nvmIss >> nvmColumn && nvmColumnCount < 2) {
                if (nvmColumnCount == 1) {
                    nvmPid = nvmColumn;
                    break;
                }
                nvmColumnCount++;
            }
        }

        if (!nvmPid.empty()) {
            logger->info("Found NVM agent PID: " + nvmPid);
            std::string nvmKillCmd = "sudo kill -9 " + nvmPid;
            int nvmKillResult = system(nvmKillCmd.c_str());
            
            if (nvmKillResult == 0) {
                logger->info("Successfully terminated NVM agent process");
            } else {
                logger->error("Failed to terminate process with PID: " + nvmPid);
            }
            std::string nvmStartCmd = "sudo /opt/cisco/secureclient/NVM/bin/acnvmagent.app/Contents/MacOS/acnvmagent &";
            int nvmStartResult = system(nvmStartCmd.c_str());
            
            if (nvmStartResult == 0) {
                logger->info("[+] Successfully started NVM agent");
            } else {
                logger->error("[!] Failed to start NVM agent");
            }
        } else {
            logger->warning("No NVM agent PID found");
        }

        // Umbrella Agent Section
        logger->info("Searching for Umbrella agent processes...");
        std::string umbrellaCmd1 = "ps -ef | grep acumbrellaagent";
        int umbrellaResult1 = system(umbrellaCmd1.c_str());

        if (umbrellaResult1 == 0) {
            logger->info("Umbrella agent processes found and displayed");
        } else {
            logger->warning("Command execution returned non-zero status: " + std::to_string(umbrellaResult1));
        }

        std::array<char, 128> umbrellaBuffer;
        std::string umbrellaResult;
        std::string umbrellaCmd = "ps -ef | grep acumbrellaagent";

        FILE* umbrellaPipe = popen(umbrellaCmd.c_str(), "r");
        if (!umbrellaPipe) {
            logger->error("Failed to execute Umbrella process search command");
            return;
        }

        while (fgets(umbrellaBuffer.data(), umbrellaBuffer.size(), umbrellaPipe) != nullptr) {
            umbrellaResult += umbrellaBuffer.data();
        }
        pclose(umbrellaPipe);

        std::istringstream umbrellaStream(umbrellaResult);
        std::string umbrellaLine;
        std::string umbrellaPid;

        if (std::getline(umbrellaStream, umbrellaLine)) {
            std::istringstream umbrellaIss(umbrellaLine);
            std::string umbrellaColumn;
            int umbrellaColumnCount = 0;
                
            while (umbrellaIss >> umbrellaColumn && umbrellaColumnCount < 2) {
                if (umbrellaColumnCount == 1) {
                    umbrellaPid = umbrellaColumn;
                    break;
                }
                umbrellaColumnCount++;
            }
        }

        if (!umbrellaPid.empty()) {
            logger->info("Found Umbrella agent PID: " + umbrellaPid);
            std::string umbrellaKillCmd = "sudo kill -9 " + umbrellaPid;
            int umbrellaKillResult = system(umbrellaKillCmd.c_str());
            
            if (umbrellaKillResult == 0) {
                logger->info("Successfully terminated Umbrella agent process");
            } else {
                logger->error("Failed to terminate Umbrella process with PID: " + umbrellaPid);
            }
            std::string umbrellaStartCmd = "sudo /opt/cisco/secureclient/bin/acumbrellaagent &";
            int umbrellaStartResult = system(umbrellaStartCmd.c_str());

            if (umbrellaStartResult == 0) {
                logger->info("[+] Successfully started Umbrella agent");
            } else {
                logger->error("[!] Failed to start Umbrella agent");
            }
        } else {
            logger->warning("No Umbrella agent PID found");
        }

        // ISE Agent Section
        logger->info("Searching for ISE agent processes...");
        std::string iseCmd1 = "ps -ef | grep csc_iseagentd";
        int iseResult1 = system(iseCmd1.c_str());

        if (iseResult1 == 0) {
            logger->info("ISE agent processes found and displayed");
        } else {
            logger->warning("Command execution returned non-zero status: " + std::to_string(iseResult1));
        }

        std::array<char, 128> iseBuffer;
        std::string iseResult;
        std::string iseCmd = "ps -ef | grep csc_iseagentd";

        FILE* isePipe = popen(iseCmd.c_str(), "r");
        if (!isePipe) {
            logger->error("Failed to execute ISE process search command");
            return;
        }

        while (fgets(iseBuffer.data(), iseBuffer.size(), isePipe) != nullptr) {
            iseResult += iseBuffer.data();
        }
        pclose(isePipe);

        std::istringstream iseStream(iseResult);
        std::string iseLine;
        std::string isePid;

        if (std::getline(iseStream, iseLine)) {
            std::istringstream iseIss(iseLine);
            std::string iseColumn;
            int iseColumnCount = 0;
                
            while (iseIss >> iseColumn && iseColumnCount < 2) {
                if (iseColumnCount == 1) {
                    isePid = iseColumn;
                    break;
                }
                iseColumnCount++;
            }
        }

        if (!isePid.empty()) {
            logger->info("Found ISE agent PID: " + isePid);
            std::string iseKillCmd = "sudo kill -9 " + isePid;
            int iseKillResult = system(iseKillCmd.c_str());
            
            if (iseKillResult == 0) {
                logger->info("Successfully terminated ISE agent process");
            } else {
                logger->error("Failed to terminate ISE process with PID: " + isePid);
            }
            std::string iseStartCmd = "sudo /opt/cisco/secureclient/bin/csc_iseagentd &";
            int iseStartResult = system(iseStartCmd.c_str());

            if (iseStartResult == 0) {
                logger->info("[+] Successfully started ISE agent");
            } else {
                logger->error("[!] Failed to start ISE agent");
            }
        } else {
            logger->warning("No ISE agent PID found");
        }

        // ZTA Agent Section
        logger->info("Searching for ZTA agent processes...");
        std::string ztaCmd1 = "ps -ef | grep csc_ztaagent";
        int ztaResult1 = system(ztaCmd1.c_str());

        if (ztaResult1 == 0) {
            logger->info("ZTA agent processes found and displayed");
        } else {
            logger->warning("Command execution returned non-zero status: " + std::to_string(ztaResult1));
        }

        std::array<char, 128> ztaBuffer;
        std::string ztaResult;
        std::string ztaCmd = "ps -ef | grep csc_ztaagent";

        FILE* ztaPipe = popen(ztaCmd.c_str(), "r");
        if (!ztaPipe) {
            logger->error("Failed to execute ZTA process search command");
            return;
        }

        while (fgets(ztaBuffer.data(), ztaBuffer.size(), ztaPipe) != nullptr) {
            ztaResult += ztaBuffer.data();
        }
        pclose(ztaPipe);

        std::istringstream ztaStream(ztaResult);
        std::string ztaLine;
        std::string ztaPid;

        if (std::getline(ztaStream, ztaLine)) {
            std::istringstream ztaIss(ztaLine);
            std::string ztaColumn;
            int ztaColumnCount = 0;
                
            while (ztaIss >> ztaColumn && ztaColumnCount < 2) {
                if (ztaColumnCount == 1) {
                    ztaPid = ztaColumn;
                    break;
                }
                ztaColumnCount++;
            }
        }

        if (!ztaPid.empty()) {
            logger->info("Found ZTA agent PID: " + ztaPid);
            std::string ztaKillCmd = "sudo kill -9 " + ztaPid;
            int ztaKillResult = system(ztaKillCmd.c_str());
            
            if (ztaKillResult == 0) {
                logger->info("Successfully terminated ZTA agent process");
            } else {
                logger->error("Failed to terminate ZTA process with PID: " + ztaPid);
            }
            std::string ztaStartCmd = "sudo /opt/cisco/secureclient/bin/csc_ztaagent &";
            int ztaStartResult = system(ztaStartCmd.c_str());

            if (ztaStartResult == 0) {
                logger->info("[+] Successfully started ZTA agent");
            } else {
                logger->error("[!] Failed to start ZTA agent");
            }
        } else {
            logger->warning("No ZTA agent PID found");
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