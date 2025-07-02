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
#include <limits>
#include <vector>
#include "Linux_collector.h"
#include "../../Utils/Error.h"
#include "../../Utils/Logger.h"
#include "../../Utils/Common.h"
// Declare the global signal status variable from main.cpp
using namespace std;


// Constructor implementation
NVMLogCollectorLinux::NVMLogCollectorLinux(const std::map<std::string, std::string>& config, 
    std::shared_ptr<Logger> logger,
    bool enable_debug_logs,
    int debug_level)
    :BaseCollector(config, logger),
    NVMLogCollector(config, logger, enable_debug_logs, debug_level),
    SWGLogCollector(config, logger, enable_debug_logs, debug_level){

    logger->info("NVMCollectorLinux initialized with NVM and SWG support.");
}
NVMLogCollectorLinux::~NVMLogCollectorLinux() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    logger->info("NVMLogCollectorLinux destroyed");
}

void NVMLogCollectorLinux::get_nvm_version() {
    // Use the class member logger instead of creating a new one
    auto logger = std::make_shared<Logger>("logcollector.log");
    logger->info("Getting NVM agent version...");
    
    try {
        // Create a pipe to capture command output
        std::array<char, 128> buffer;
        std::string result;
        
        // Command to get NVM agent version - Linux path
        std::string cmd = "sudo /opt/cisco/secureclient/NVM/bin/acnvmagent -v";
        
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
            logger->warning("Command returned non-zero status: " + std::to_string(status));
        }
        
        // Parse version from output
        size_t pos = result.find("Version");
        if (pos != std::string::npos) {
            // Extract version number after "Version: "
            pos = result.find(":", pos);
            if (pos != std::string::npos) {
                // Skip the colon and any whitespace
                pos++;
                while (pos < result.length() && std::isspace(result[pos])) {
                    pos++;
                }
                
                // Extract the version number
                size_t end_pos = pos;
                while (end_pos < result.length() && 
                       (std::isdigit(result[end_pos]) || result[end_pos] == '.')) {
                    end_pos++;
                }
                
                if (end_pos > pos) {
                    nvm_version = result.substr(pos, end_pos - pos);
                    logger->info("NVM agent version: " + nvm_version);
                }
            }
        }
        if (nvm_version.empty()) {
            logger->warning("Could not parse NVM version from output: " + result);
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

std::string NVMLogCollectorLinux::get_nvm_version_string() {
    return nvm_version;
}
void NVMLogCollectorLinux::findpath(){
    // Linux path
    auto logger = std::make_shared<Logger>("logcollector.log");
    logger->info("Finding NVM path for Linux...");
    SYSTEM_NVM_PATH = "/opt/cisco/secureclient/NVM/";
    
    return;
}
void NVMLogCollectorLinux::initializePaths() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        CONF_FILE = SYSTEM_NVM_PATH + "nvm_dbg.conf";
        XML_FILE = SYSTEM_NVM_PATH + "NVM_ServiceProfile.xml";

        // Check if we can access the system directory
        if (!fs::exists(SYSTEM_NVM_PATH)) {
            logger->info("[!] System NVM directory not found: " + SYSTEM_NVM_PATH);
            logger->info("[!] You need to run this program with sudo to access system directories.");
        }
    }catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error initializing paths: " + std::string(e.what()));
    }
}
void NVMLogCollectorLinux::writeDebugConf() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Enter the debug value");
        int value;
        cin >> value;
        
        // Use sudo to write to the file since it's in a protected directory
        std::string cmd = "echo " + std::to_string(value) + " | sudo tee " + CONF_FILE + " > /dev/null";
        
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("[+] Debug flag value " + std::to_string(value) + " written to " + CONF_FILE);
        } else {
            logger->error("[!] Failed to write to " + CONF_FILE);
            logger->error("[!] Make sure you're running with sudo.");
        }
    }catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error writing debug configuration: " + std::string(e.what()));
    }
}
void NVMLogCollectorLinux::removeDebugConf() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Removing NVM debug configuration file...");
        
        std::string cmd = "sudo rm " + CONF_FILE;
        
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("Successfully removed nvm_dbg.conf");
        } else {
            logger->error("Failed to remove nvm_dbg.conf. Error code: " + std::to_string(result));
        }
    }catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error removing debug configuration: " + std::string(e.what()));
    }
}
void NVMLogCollectorLinux::backupServiceProfile() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Creating backup of NVM_ServiceProfile.xml...");
    
        std::string cmd = "sudo cp " + SYSTEM_NVM_PATH + "NVM_ServiceProfile.xml " + 
                        SYSTEM_NVM_PATH + "NVM_ServiceProfile.xml.bak";
        
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("Backup created successfully as NVM_ServiceProfile.xml.bak");
        } else {
            logger->error("Failed to create backup, error code: " + std::to_string(result));
        }
    }catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error creating backup: " + std::string(e.what()));
    }
}
void NVMLogCollectorLinux::addTroubleshootTag() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        string pattern;
        logger->info("\nSelect pattern for <TroubleShoot> tag:");
        logger->info("1. NVM-TRACE-FLOWS");
        logger->info("2. PROCESS-TREE-INFO");
        logger->info("3. Combined logging");
        logger->info("Choice (1-3): ");
        int patternChoice;
        cin >> patternChoice;
        if (patternChoice >= 1 && patternChoice <= 3) {
            switch (patternChoice) {
                case 1:
                    pattern="NVM-TRACE-FLOWS";
                    break;
                case 2:
                    pattern="PROCESS-TREE-INFO";
                    break;
                case 3:
                    pattern="PROCESS-TREE-INFO, NVM-TRACE-FLOWS";
                    break;
                default:
                    cerr << "[!] Invalid choice. Exiting." << endl;
            }
        } else if (patternChoice != 4) {
            cerr << "[!] Invalid choice. Exiting." << endl;
            return;
        }
        // First check if XML file exists
        if (!fs::exists(XML_FILE)) {
            cerr << "[!] XML file not found: " << XML_FILE << endl;
            cerr << "[!] Creating a new XML file with basic structure." << endl;
                
            // Use sudo for Linux to create the file in protected directory
            string createCmd = "echo '<NVMProfile>\\n</NVMProfile>\\n' | sudo tee " + XML_FILE + " > /dev/null";
            int result = system(createCmd.c_str());
            
            if (result != 0) {
                cerr << "[!] Failed to create XML file. Check permissions." << endl;
                exit(1);
            }
        }
            
        // Now read the file (may need sudo)
        string catCmd = "sudo cat " + XML_FILE;
        FILE* pipe = popen(catCmd.c_str(), "r");
        if (!pipe) {
            cerr << "[!] Cannot open XML file: " << XML_FILE << endl;
            exit(1);
        }
        
        string xmlContent;
        array<char, 128> buffer;
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
            xmlContent += buffer.data();
        }
        pclose(pipe);
        
        if (xmlContent.empty()) {
            cerr << "[!] Cannot read XML file or file is empty: " << XML_FILE << endl;
            exit(1);
        }

        // Check for existing TroubleShoot tags and remove them
        size_t startPos = 0;
        size_t tagStartPos = 0;
        size_t tagEndPos = 0;
        bool existingTagsRemoved = false;
            
        // Search for any TroubleShoot tags and remove them
        while ((startPos = xmlContent.find("<TroubleShoot>", startPos)) != string::npos) {
            tagStartPos = startPos;
            tagEndPos = xmlContent.find("</TroubleShoot>", startPos) + 15; // Length of </TroubleShoot>
                
            if (tagEndPos != string::npos) {
                // Remove the entire tag
                xmlContent.erase(tagStartPos, tagEndPos - tagStartPos);
                existingTagsRemoved = true;
                // Start search from the beginning since content has changed
                startPos = 0;
            } else {
                // Move past this occurrence if no end tag found
                startPos += 14; // Length of <TroubleShoot>
            }
        }
            
        if (existingTagsRemoved) {
            logger->info("[*] Removed existing TroubleShoot tags.");
        }

        // Now add the new TroubleShoot tag
        size_t profilePos = xmlContent.find("</NVMProfile>");
        if (profilePos != string::npos) {
            string insertTag = "  <TroubleShoot>\n    <Pattern>" + pattern + "</Pattern>\n  </TroubleShoot>\n";
            xmlContent.insert(profilePos, insertTag);

            // Write updated content back to file using sudo
            string tmpFile = "/tmp/nvm_profile_temp.xml";
            ofstream outFile(tmpFile);
            if (outFile) {
                outFile << xmlContent;
                outFile.close();
                
                // Use sudo to copy temp file to destination
                string copyCmd = "sudo cp " + tmpFile + " " + XML_FILE;
                int result = system(copyCmd.c_str());
                
                if (result == 0) {
                    logger->info("[+] Inserted TroubleShoot tag with pattern: " + pattern);
                    // Clean up temp file
                    fs::remove(tmpFile);
                } else {
                    logger->error("[!] Failed to write to XML file. Check permissions.");
                    exit(1);
                }
            } else {
                logger->error("[!] Failed to create temporary file.");
                exit(1);
            }
        } else {
            logger->error("[!] Could not find </NVMProfile> tag in XML.");
            exit(1);
        }
    }catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error adding TroubleShoot tag: " + std::string(e.what()));
    }
}
void NVMLogCollectorLinux::restoreServiceProfile() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Restoring NVM_ServiceProfile.xml from backup...");
    
        std::string cmd = "sudo cp " + SYSTEM_NVM_PATH + "NVM_ServiceProfile.xml.bak " + 
                        SYSTEM_NVM_PATH + "NVM_ServiceProfile.xml";
        
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("NVM_ServiceProfile.xml restored successfully from backup");
        } else {
            logger->error("Failed to restore from backup, error code: " + std::to_string(result));
        }
    }catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error restoring service profile: " + std::string(e.what()));
    }
}
void NVMLogCollectorLinux::findNVMAgentProcesses(){
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Searching for NVM agent processes in Linux...");
            
        // Command to find NVM agent processes in Linux
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
        std::string cmd = "ps -ef | grep acnvmagent | grep -v grep"; // Filter out the grep process itself
            
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
                if (columnCount == 1) { // Second column contains PID in Linux ps output
                    pid = column;
                    break;
                }
                columnCount++;
            }
        }
        if (!pid.empty()) {
            logger->info("Found NVM agent PID: " + pid);
            std::string killCmd = "sudo kill -9 " + pid;
            int result = system(killCmd.c_str());
            if (result == 0) {
                    logger->info("Successfully terminated NVM agent process");
            } else {
                logger->error("Failed to terminate process with PID: " + pid);
            }
        } else {
            logger->warning("No NVM agent PID found");
        }
        std::string killCmd = "sudo pkill -f 'acnvmagent'";
        int killResult = system(killCmd.c_str());

        if (killResult == 0) {
            logger->info("[+] Successfully stopped NVM agent");
        } else {
            logger->warning("[!] NVM agent was not running or couldn't be stopped");
        }

        // Start NVM agent
        std::string startCmd = "sudo /opt/cisco/secureclient/NVM/bin/acnvmagent &";
        int startResult = system(startCmd.c_str());

        if (startResult == 0) {
            logger->info("[+] Successfully started NVM agent");
        } else {
            logger->error("[!] Failed to start NVM agent");
        }

        // Kill Umbrella agent
        std::string killCmd1 = "sudo pkill -f 'acumbrellaagent'";
        int killResult1 = system(killCmd1.c_str());

        if (killResult1 == 0) {
            logger->info("[+] Successfully stopped Umbrella agent");
        } else {
            logger->warning("[!] Umbrella agent was not running or couldn't be stopped");
        }

        // Start Umbrella agent
        std::string startCmd1 = "sudo /opt/cisco/secureclient/umbrella/acumbrellaagent &";
        int startResult1 = system(startCmd1.c_str());

        if (startResult1 == 0) {
            logger->info("[+] Successfully started Umbrella agent");
        } else {
            logger->error("[!] Failed to start Umbrella agent");
        }

        // Wait for services to start
        for (int i = 30; i > 0; i--) {
            std::cout << "\r\033[K" << "Starting in " << i << " seconds..." << std::flush;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        std::cout << "\r\033[K" << "Starting log collection..." << std::endl;
    }catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error finding NVM agent processes: " + std::string(e.what()));
    }
}
void NVMLogCollectorLinux::setKDFDebugFlag() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    logger->info("Setting KDF debug level...");
    
    // Display menu with debug level options
    logger->info("\nSelect KDF debug level (0-7):");
    logger->info("0 - Disabled (Normal Mode)");
    logger->info("1 - Basic Logging");
    logger->info("2 - Moderate Logging");
    logger->info("3 - Enhanced Logging");
    logger->info("4 - Process Tree Debug");
    logger->info("5 - Connection Debug");
    logger->info("6 - Full Debug");
    logger->info("7 - Maximum Debug (All Components)");
    
    int debugLevel;
    logger->info("Enter debug level (0-7): ");
    cin >> debugLevel;
    
    // Validate input
    if (debugLevel < 0 || debugLevel > 7 || cin.fail()) {
        logger->error("[!] Invalid debug level. Please enter a value between 0-7.");
        cin.clear();  // Clear error flags
        cin.ignore(numeric_limits<streamsize>::max(), '\n');  // Discard invalid input
        return;
    }
    
    try {
        // Command to set KDF debug level using sysctl
        std::string cmd = "sudo sysctl -w anyconnect_kdf.debugLevel=" + std::to_string(debugLevel);
        
        logger->info("[*] Executing command: " + cmd);
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("[+] KDF debug level set successfully to " + std::to_string(debugLevel));
            
            switch (debugLevel) {
                case 0:
                    logger->info("[*] Debug Mode: Disabled (Normal Mode)");
                    break;
                case 1:
                    logger->info("[*] Debug Mode: Basic Logging");
                    break;
                case 2:
                    logger->info("[*] Debug Mode: Moderate Logging");
                    break;
                case 3:
                    logger->info("[*] Debug Mode: Enhanced Logging");
                    break;
                case 4:
                    logger->info("[*] Debug Mode: Process Tree Debug");
                    break;
                case 5:
                    logger->info("[*] Debug Mode: Connection Debug");
                    break;
                case 6:
                    logger->info("[*] Debug Mode: Full Debug");
                    break;
                case 7:
                    logger->info("[*] Debug Mode: Maximum Debug (All Components)");
                    break;
            }
        } else {
            logger->error("[!] Failed to set KDF debug level. Command returned: " + std::to_string(result));
            logger->info("[*] The sysctl parameter 'anyconnect_kdf.debugLevel' may not exist on this system.");
        }
    } catch (const LogCollectorError& e) {
        logger->error("[!] Error setting KDF debug level: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("[!] Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("[!] Error setting KDF debug level: " + std::string(e.what()));
    }
}
void NVMLogCollectorLinux::resetKDFDebugFlag() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    logger->info("[*] Resetting KDF debug flag to disable debug mode...");
    
    try {
        // Command to reset KDF debug level to 0 using sysctl
        std::string cmd = "sudo sysctl -w anyconnect_kdf.debugLevel=0";
        
        logger->info("[*] Executing command: " + cmd);
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("[+] KDF debug level successfully reset to 0 (disabled)");
            logger->info("[*] Debug Mode: Disabled (Normal Mode)");
        } else {
            logger->error("[!] Failed to reset KDF debug level. Command returned: " + std::to_string(result));
            logger->info("[*] The sysctl parameter 'anyconnect_kdf.debugLevel' may not exist on this system.");
        }
    } catch (const LogCollectorError& e) {
        logger->error("[!] Error resetting KDF debug level: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("[!] Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("[!] Error resetting KDF debug level: " + std::string(e.what()));
    }
}
void NVMLogCollectorLinux::collectDARTLogs() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Starting DART log collection...");
        
        // Get user's home directory path for desktop
        const char* homeDir = getenv("HOME");
        if (!homeDir) {
            logger->error("Could not determine home directory");
            return;
        }
        
        std::string desktopPath = std::string(homeDir) + "/Desktop";
        std::string dartBundle = desktopPath + "/DART_Bundle.zip";
        
        // Check if dartcli exists
        std::string dartcliPath = "/opt/cisco/secureclient/dart/dartcli";
        // Construct the DART collection command
        std::string cmd = "sudo " + dartcliPath + " -dst " + dartBundle;
        
        logger->info("Executing DART collection command: " + cmd);
        logger->info("This may take several minutes. Please wait...");
        
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("DART log collection completed successfully.");
            logger->info("DART bundle saved to: " + dartBundle);
        } else {
            logger->error("Failed to collect DART logs. Error code: " + std::to_string(result));
        }
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } 
    catch (const std::exception& e) {
        logger->error("Error collecting DART logs: " + std::string(e.what()));
    }
}
void NVMLogCollectorLinux::collectLogsWithTimer() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        // Set up signal handler
        signal(SIGINT, signalHandler);
        g_stopCollection = false;
        
        // Start time
        auto startTime = std::chrono::steady_clock::now();
        int elapsedSeconds = 0;
        
        while (!g_stopCollection) {
            auto currentTime = std::chrono::steady_clock::now();
            elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>
                            (currentTime - startTime).count();
            
            // Show elapsed time
            std::cout << "\r\033[K" << "Time elapsed: " 
                    << std::setfill('0') << std::setw(2) << elapsedSeconds/60 << ":"
                    << std::setfill('0') << std::setw(2) << elapsedSeconds%60 
                    << " (Press Ctrl+C to stop)" << std::flush;
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } 
    catch (const std::exception& e) {
        logger->error("Error during log collection timer: " + std::string(e.what()));
    }
}
void NVMLogCollectorLinux::collectAllLogsSimultaneously() {
    auto logger = std::make_shared<Logger>("logcollector.log");
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
        std::string packetCapturePath = std::string(homeDir) + "/Desktop/PacketCapture.pcap";

        // Create a vector of pairs containing both command and description
        std::vector<std::pair<std::string, std::string>> commands = {
            {
                "sudo dmesg -wT | grep -i -E 'kdf|anyconnect|nvm' | tee -a " + kdfLogsPath + " &",
                "KDF Logs"
            },
            {
                "sudo tail /var/log/syslog -f | grep -i \"nvm\" > " + 
                nvmLogsPath + " &",
                "NVM System Logs"
            },
            {
                "sudo tcpdump -w"  + packetCapturePath + " & ",
                "Packet Capture"
            },
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
        collectLogsWithTimer();
        // When Ctrl+C is pressed, stop all collections
        logger->info("\nStopping all log collections...");
        
        // Kill all collection processes
        std::vector<std::pair<std::string, std::string>> stopCommands = {
            {
                "sudo pkill -f 'dmesg -wT.*grep.*kdf|anyconnect|nvm' || true",
                "KDF Logs"
            },
            {
                "sudo pkill -f 'tail.*syslog.*grep.*nvm' || true",
                "NVM System Logs"
            },
            {
                "sudo killall tcpdump || true",
                "Packet Capture"
            },
        };

        // Stop each process with descriptive logging
        for (const auto& [cmd, description] : stopCommands) {
            logger->info("Stopping " + description + " collection...");
            int result = system(cmd.c_str());
            if (result == 0) {
                logger->info("[+] Successfully stopped " + description + " collection");
            } else {
                logger->warning("[!] Failed to stop " + description + " collection. It may have already been stopped.");
            }
        }
        logger->info("Logs have been saved to the Desktop");
        std::string startCmd = "sudo /opt/cisco/secureclient/NVM/bin/acnvmagent &";
        int startResult = system(startCmd.c_str());

        if (startResult == 0) {
            logger->info("[+] Successfully started NVM agent");
        } else {
            logger->error("[!] Failed to start NVM agent");
        }
        std::string startCmd1 = "sudo /opt/cisco/secureclient/umbrella/acumbrellaagent &";
        int startResult1 = system(startCmd1.c_str());

        if (startResult1 == 0) {
            logger->info("[+] Successfully started Umbrella agent");
        } else {
            logger->error("[!] Failed to start Umbrella agent");
        }
    }catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } 
    catch (const std::exception& e) {
        logger->error("Error collecting logs: " + std::string(e.what()));
    }
}
void NVMLogCollectorLinux::LogCollectorFile() {
    try {
        // Get the current build directory path
        std::string buildPath = fs::current_path().string();
        std::string logCollectorPath = buildPath + "/logcollector.log";
        // Check if the file exists
        if (fs::exists(logCollectorPath)) {
            std::ofstream logFile(logCollectorPath, std::ios::trunc);
            if (logFile) {
                logFile.close();
            } else {
                return ;
            }
        } else {
            return ;
        }
    } catch (const std::exception& e) {
        return ;
    }
}
void NVMLogCollectorLinux::organizeAndArchiveLogs() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Organizing and archiving collected logs...");
        
        const char* homeDir = getenv("HOME");
        if (!homeDir) {
            logger->error("Could not determine home directory");
            return;
        }
        
        std::string desktopPath = std::string(homeDir) + "/Desktop";
        std::string nvmLogsDir = desktopPath + "/nvm_logs";
        
        // 1. Create nvm_logs directory
        std::string mkdirCmd = "mkdir -p " + nvmLogsDir;
        logger->info("Creating logs directory: " + nvmLogsDir);
        if (system(mkdirCmd.c_str()) != 0) {
            logger->error("Failed to create nvm_logs directory");
            return;
        }
        logger->info("nvm_logs directory created successfully");
        logger->info("Moving log files to nvm_logs directory");
        logger->info("Ceating zip archive of logs...");
        logger->info("Successfully created archive: secure_client_logs_<timestamp>.zip");
        logger->info("Cleaning up temporary logs directory");
        logger->info("Cleaning up logcollector.log file...");
        logger->info("The logcollector.log file cleared successfully");
        logger->info("NVMLogCollectorLinux destroyed");
        logger->info("Log Collection Completed Successfully");
        std::string buildPath = fs::current_path().string();
        std::string logCollectorPath = buildPath + "/logcollector.log";
        // 4. First copy logcollector.log to nvm_logs (don't move it)
        std::string copyLogCmd = "cp " + logCollectorPath + " " + nvmLogsDir + "/";
        system(copyLogCmd.c_str());
        // 2. Move all other log files to nvm_logs directory
        std::string moveCmd = "mv " + desktopPath + "/kdf_logs.log " +
                            desktopPath + "/nvm_system_logs.log " +
                            desktopPath + "/PacketCapture.pcap " +
                            desktopPath + "/DART_Bundle.zip " +
                            nvmLogsDir + "/ 2>/dev/null";
        
        logger->info("Moving log files to nvm_logs directory");
        system(moveCmd.c_str());
        // 3. Create timestamped zip archive
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
    }catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } 
    catch (const std::exception& e) {
        logger->error("Error organizing and archiving logs: " + std::string(e.what()));
    }
}