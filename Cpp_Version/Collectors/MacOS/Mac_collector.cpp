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
#include <json/json.h> 
#include <curl/curl.h>
#include "Mac_collector.h"
#include "../../Utils/Logger.h"
#include "../../Utils/Error.h"
// Declare the global signal status variable from main.cpp
using namespace std;
extern volatile sig_atomic_t gSignalStatus;
std::string SYSTEM_NVM_PATH;
std::string NVM_PATH;
std::string CONF_FILE;
std::string XML_FILE;

// Constructor implementation
NVMLogCollectorMac::NVMLogCollectorMac(const std::map<std::string, std::string>& config, 
    std::shared_ptr<Logger> logger,
    bool enable_debug_logs,
    int debug_level)
    :BaseCollector(config, logger),
    NVMLogCollector(config, logger, enable_debug_logs, debug_level),
    SWGLogCollector(config, logger, enable_debug_logs, debug_level){

    logger->info("NVMCollectorMac initialized with NVM and SWG support.");
}
NVMLogCollectorMac::~NVMLogCollectorMac() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    logger->info("NVMLogCollectorMac destroyed");
}
std::atomic<bool> g_stopCollection(false);

// Signal handler
void signalHandler(int signum) {
    if (signum == SIGINT) {
        g_stopCollection = true;
    }
}
void NVMLogCollectorMac::get_nvm_version() {
    // Use the class member logger instead of creating a new one
    auto logger = std::make_shared<Logger>("logcollector.log");
    logger->info("Getting NVM agent version...");
    
    try {
        // Create a pipe to capture command output
        std::array<char, 128> buffer;
        std::string result;
        
        // Command to get NVM agent version
        std::string cmd = "sudo /opt/cisco/secureclient/NVM/bin/acnvmagent.app/Contents/MacOS/acnvmagent -v";
        
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
std::string NVMLogCollectorMac::get_nvm_version_string() const {
    return nvm_version;
}
void NVMLogCollectorMac::findpath(){
    #ifdef _WIN32
        // Windows path
        SYSTEM_NVM_PATH="C:/ProgramData/Cisco/Cisco Secure Client/NVM/";
        return;
    #elif defined(__APPLE__)
        // macOS path
        SYSTEM_NVM_PATH="/opt/cisco/secureclient/NVM/";
        return;
    #elif defined(__linux__)
        // Linux path
        SYSTEM_NVM_PATH="/opt/cisco/secure-client/nvm/";
        return;
    #else
        // Fallback path
        SYSTEM_NVM_PATH="./cisco_nvm_test/";
        return;
    #endif
}
// Initialize paths and check permissions
void NVMLogCollectorMac::initializePaths() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        CONF_FILE = SYSTEM_NVM_PATH + "nvm_dbg.conf";
        XML_FILE = SYSTEM_NVM_PATH + "NVM_ServiceProfile.xml";

        // Check if we can access the system directory
        if (!fs::exists(SYSTEM_NVM_PATH)) {
            logger->info("[!] System NVM directory not found: " + SYSTEM_NVM_PATH);
            logger->info("[!] You need to run this program with sudo to access system directories.");
            exit(1);
        }
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        exit(1);
    }
    catch (const std::exception& e) {
        logger->error("Error initializing paths: " + std::string(e.what()));
        exit(1);
    }   
}

// Write the debug flag to nvm_dbg.conf
void NVMLogCollectorMac::writeDebugConf() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try
    {
        logger->info("Enter the debug value");
        int value;
        cin >> value;
        ofstream conf(CONF_FILE);
        if (conf) {
            conf << value;
            conf.close();
            logger->info("[+] Debug flag value " + std::to_string(value) + " written to " + CONF_FILE);
        } else {
            logger->error("[!] Failed to write to " + CONF_FILE);
            logger->error("[!] Make sure you're running with sudo.");
            exit(1);
        }
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        exit(1);
    }
    catch (const std::exception& e) {
        logger->error("Error writing debug configuration: " + std::string(e.what()));
        exit(1);
    }
}
void NVMLogCollectorMac::addTroubleshootTag() {
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
                
            ofstream newXml(XML_FILE);
            if (newXml) {
                newXml << "<NVMProfile>\n</NVMProfile>\n";
                newXml.close();
            } else {
                cerr << "[!] Failed to create XML file. Check permissions." << endl;
                exit(1);
            }
        }
            
        // Now read the file
        ifstream inFile(XML_FILE);
        string xmlContent;
        string line;

        if (!inFile) {
            cerr << "[!] Cannot open XML file: " << XML_FILE << endl;
            exit(1);
        }

        while (getline(inFile, line)) {
        xmlContent += line + "\n";
        }
        inFile.close();

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

            ofstream outFile(XML_FILE);
            if (outFile) {
                outFile << xmlContent;
                outFile.close();
                logger->info("[+] Inserted TroubleShoot tag with pattern: " + pattern);
            } else {
                logger->error("[!] Failed to write to XML file. Check permissions.");
                exit(1);
            }
        } else {
            logger->error("[!] Could not find </NVMProfile> tag in XML.");
            exit(1);
        }
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        exit(1);
    }
    catch (const std::exception& e) {
        logger->error("Error adding TroubleShoot tag: " + std::string(e.what()));
        exit(1);
    }
}
void NVMLogCollectorMac::setKDFDebugFlag() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    string SYSTEM_KDF_PATH = "/opt/cisco/secureclient/kdf/";
    string KDF_BIN_PATH = SYSTEM_KDF_PATH + "bin/";
    
    string hexInput;
    logger->info("\nEnter debug flag (hexadecimal, e.g., 0x20): ");
    cin >> hexInput;
    
    try {
        // Remove "0x" prefix if present
        if (hexInput.size() > 2 && hexInput.substr(0, 2) == "0x") {
            hexInput = hexInput.substr(2);
        }
        
        // Convert hex string to unsigned long to handle large values
        unsigned long debugFlag = stoul(hexInput, nullptr, 16);
        
        string acsocktoolPath = KDF_BIN_PATH + "acsocktool";
        
        // Check if acsocktool exists
        if (!fs::exists(acsocktoolPath)) {
            logger->error("[!] acsocktool not found at: " + acsocktoolPath);
            return;
        }
        
        // Execute acsocktool command with hex value
        string cmd = acsocktoolPath + " -sdf 0x" + hexInput;
        logger->info("[*] Setting KDF debug flag to 0x" + hexInput + "...");
        
        if (system(cmd.c_str()) == 0) {
            logger->info("[+] KDF debug flag set successfully");
            logger->info("[*] Debug mode: ");
            
            if (debugFlag == 0x0) logger->info("Normal Mode (Disabled)");
            else if (debugFlag == 0x20) logger->info("Process Parameter Collection");
            else if (debugFlag == 0x40) logger->info("CMID and Token Logging");
            else if (debugFlag == 0x60) logger->info("Combined Process and Auth");
            else if (debugFlag == 0x80) logger->info("Process Tree Debug");
            else if (debugFlag == 0x100) logger->info("EVE Mercury Info");
            else if (debugFlag == 0xFFFFFFFF) logger->info("Full Debug (all components)");
            else logger->info("Custom Debug Level");
        } else {
            cerr << "[!] Failed to set KDF debug flag" << endl;
        }
    } catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("Error setting KDF debug flag: " + std::string(e.what()));
    }
}
void NVMLogCollectorMac::resetKDFDebugFlag() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try
    {
        string SYSTEM_KDF_PATH = "/opt/cisco/secureclient/kdf/";
        string KDF_BIN_PATH = SYSTEM_KDF_PATH + "bin/";
        string acsocktoolPath = KDF_BIN_PATH + "acsocktool";

        if (!fs::exists(acsocktoolPath)) {
            cerr << "[!] acsocktool not found at: " << acsocktoolPath << endl;
            return;
        }

        logger->info("[*] Resetting KDF debug flag...");
        string cmd = acsocktoolPath + " -cdf";  // Clear Debug Flag command
        
        if (system(cmd.c_str()) == 0) {
            logger->info("[+] KDF debug flag reset successfully");
        } else {
            logger->error("[!] Failed to reset KDF debug flag");
        }
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error resetting KDF debug flag: " + std::string(e.what()));
    }  
}
void NVMLogCollectorMac::createSWGConfigOverride() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try
    {
        string UMBRELLA_PATH = "/opt/cisco/secureclient/umbrella/";
        string CONFIG_OVERRIDE_FILE = UMBRELLA_PATH + "SWGConfigOverride.json";

        // Check if directory exists, create if it doesn't
        if (!fs::exists(UMBRELLA_PATH)) {
            try {
                fs::create_directories(UMBRELLA_PATH);
                logger->info("[+] Created Umbrella directory at: " + UMBRELLA_PATH);
            } catch (const fs::filesystem_error& e) {
                logger->error("[!] Error creating directory: " + string(e.what()));
                return;
            }
        }
        // Create or overwrite the SWGConfigOverride.json file
        ofstream configFile(CONFIG_OVERRIDE_FILE, ios::trunc);
        if (configFile) {
            // Format the JSON with proper indentation
            configFile << "{\n"
                    << "\t\"organisationId\": \"2598416\",\n"
                    << "\t\"fingerprint\": \"2ed3f2d2a8a6d5f4441ee349f7315a9a\",\n"
                    << "\t\"UserId\": \"10789072\"\n"
                    << "}" << endl;
            
            configFile.close();
            logger->info("[+] Successfully created " + CONFIG_OVERRIDE_FILE);
        } else {
            logger->error("[!] Failed to write to " + CONFIG_OVERRIDE_FILE);
            logger->error("[!] Make sure you're running with sudo privileges.");
        }
        
        logger->info("[+] SWG Config Override setup completed successfully");
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error creating SWGConfigOverride.json: " + std::string(e.what()));
    }
}
void NVMLogCollectorMac::deleteSWGConfigOverride() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    string UMBRELLA_PATH = "/opt/cisco/secureclient/umbrella/";
    string CONFIG_OVERRIDE_FILE = UMBRELLA_PATH + "SWGConfigOverride.json";

    // Check if file exists before attempting to delete
    if (fs::exists(CONFIG_OVERRIDE_FILE)) {
        try {
            // Remove the file
            fs::remove(CONFIG_OVERRIDE_FILE);
            logger->info("[+] Successfully deleted " + CONFIG_OVERRIDE_FILE);
            logger->info("[*] Restarting Cisco Umbrella service...");
            
            // First, find and kill the Umbrella process
            string killCmd = "sudo pkill -f 'acumbrellaagent'";
            int killResult = system(killCmd.c_str());
            
            if (killResult == 0) {
                logger->info("[+] Successfully stopped Umbrella agent");
            } else {
                logger->warning("[!] Umbrella agent was not running or couldn't be stopped");
            }

            // Give the system a moment to clean up
            std::this_thread::sleep_for(std::chrono::seconds(2));

            // Start the Umbrella agent again
            string startCmd = "sudo /opt/cisco/secureclient/bin/acumbrellaagent &";
            int startResult = system(startCmd.c_str());
            
            if (startResult == 0) {
                logger->info("[+] Successfully restarted Umbrella agent");
            } else {
                logger->error("[!] Failed to restart Umbrella agent");
            }

        } 
        catch (const LogCollectorError& e) {
            logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
            logger->error("Details: " + std::string(e.what()));
        } catch (const fs::filesystem_error& e) {
            logger->error("[!] Error deleting file: " + string(e.what()));
            logger->error("[!] Make sure you have proper permissions");
        }
    } else {
        logger->warning("[!] SWGConfigOverride.json file not found at: " + CONFIG_OVERRIDE_FILE);
    }
}
void NVMLogCollectorMac::findNVMAgentProcesses() {
    auto logger = std::make_shared<Logger>("logcollector.log");
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
        } else {
            logger->warning("No NVM agent PID found");
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
    auto logger = std::make_shared<Logger>("logcollector.log");
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
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Restoring NVM_ServiceProfile.xml from backup...");
    
        std::string cmd = "sudo cp /opt/cisco/secureclient/NVM/NVM_ServiceProfile.xml.bak /opt/cisco/secureclient/NVM/NVM_ServiceProfile.xml";
        
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("NVM_ServiceProfile.xml restored successfully from backup");
        } else {
            logger->error("Failed to restore from backup, error code: " + std::to_string(result));
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
        collectLogsWithTimer();
        // When Ctrl+C is pressed, stop all collections
        logger->info("\nStopping all log collections...");
        
        // Kill all collection processes
        std::vector<std::pair<std::string, std::string>> killCommands = {
            {"sudo pkill -f 'log stream.*com.cisco.anyconnect.macos.acsockext' || true", "KDF Logs"},
            {"sudo pkill -f 'log stream.*acnvmagent' || true", "NVM System Logs"},
            {"sudo pkill -f 'log stream.*acumbrellaagent' || true", "Umbrella/SWG Logs"},
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
    auto logger = std::make_shared<Logger>("logcollector.log");
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
void NVMLogCollectorMac::removeDebugConf() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Removing NVM debug configuration file...");
    
        std::string cmd = "sudo rm /opt/cisco/secureclient/NVM/nvm_dbg.conf";
        
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("Successfully removed nvm_dbg.conf");
        } else {
            logger->error("Failed to remove nvm_dbg.conf. Error code: " + std::to_string(result));
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
void NVMLogCollectorMac::clearKDFDebugFlag() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Clearing KDF debug flag...");
    
        std::string SYSTEM_KDF_PATH = "/opt/cisco/secureclient/kdf/";
        std::string KDF_BIN_PATH = SYSTEM_KDF_PATH + "bin/";
        std::string acsocktoolPath = KDF_BIN_PATH + "acsocktool";
        
        // Check if acsocktool exists
        if (!fs::exists(acsocktoolPath)) {
            logger->error("acsocktool not found at: " + acsocktoolPath);
            return;
        }
        
        // Construct and execute command
        std::string cmd = "sudo " + acsocktoolPath + " -cdf";
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("KDF debug flag cleared successfully");
        } else {
            logger->error("Failed to clear KDF debug flag. Error code: " + std::to_string(result));
        }
    }
    catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error clearing KDF debug flag: " + std::string(e.what()));
    }
}
void NVMLogCollectorMac::collectLogsWithTimer() {
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
    }
    catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error collecting logs with timer: " + std::string(e.what()));
    }
}
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}
void NVMLogCollectorMac::LogCollectorFile(){
    try{
        std::string buildPath = fs::current_path().string();
        std::string logCollectorPath = buildPath + "/logcollector.log"; 
        if(fs::exists(logCollectorPath)){
            std::ifstream logFile(logCollectorPath, std::ios::trunc);
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