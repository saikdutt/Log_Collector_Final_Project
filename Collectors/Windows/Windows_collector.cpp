
#if defined(__cplusplus) && __cplusplus >= 201703L
#include <filesystem>
namespace fs = std::filesystem;
#else
#error "Need C++17 for filesystem support"
#endif
#include <iostream>
#include <fstream>
// Add this include at the top of Windows_collector.cpp with the other includes
#include <vector>
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
#include <future>
#include <atomic>
#include <vector>
#include "./Windows_collector.h"
#include "../../Utils/Logger.h"
#include "../../Utils/Error.h"
#include "../../Utils/Common.h"
// Declare the global signal status variable from main.cpp
using namespace std;
#ifdef _WIN32
    #define POPEN _popen
    #define PCLOSE _pclose
#else
    #define POPEN popen
    #define PCLOSE pclose
#endif
// Constructor implementation
NVMLogCollectorWindows::NVMLogCollectorWindows(const std::map<std::string, std::string>& config, 
    std::shared_ptr<Logger> logger)
    :BaseCollector(config, logger),
    NVMLogCollector(config, logger),
    SWGLogCollector(config, logger){

    logger->info("NVMCollectorWindows initialized with NVM and SWG support.");
}
NVMLogCollectorWindows::~NVMLogCollectorWindows() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    logger->info("NVMLogCollectorWindows destroyed");
}

void NVMLogCollectorWindows::get_nvm_version() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    logger->info("Getting NVM agent version...");
    
    try {
        // Create a pipe to capture command output
        std::array<char, 128> buffer;
        std::string result;
        
        // Command to get NVM agent version (Windows version)
        std::string cmd ="\"C:\\Program Files (x86)\\Cisco\\Cisco Secure Client\\NVM\\acnvmagent.exe\" -v";
        
        // Execute command and capture output
        FILE* pipe = POPEN(cmd.c_str(), "r");
        if (!pipe) {
            throw std::runtime_error("Failed to execute command to get NVM version");
        }
        
        // Read output
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
            result += buffer.data();
        }
        
        // Close pipe
        int status = PCLOSE(pipe);
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
        
    } catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }    catch (const std::exception& e) {
        logger->error("Error getting NVM version: " + std::string(e.what()));
        nvm_version = "error";
    }
}

std::string NVMLogCollectorWindows::get_nvm_version_string() const {
    return nvm_version;
}
void NVMLogCollectorWindows::findpath(){
    // Windows path
    SYSTEM_NVM_PATH = "C:\\ProgramData\\Cisco\\Cisco Secure Client\\NVM\\";
}
void NVMLogCollectorWindows::initializePaths() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        CONF_FILE = SYSTEM_NVM_PATH + "nvm_dbg.conf";
        XML_FILE = SYSTEM_NVM_PATH + "NVM_ServiceProfile.xml";
        logger->info("Initialization has been done");
        // Check if we can access the system directory
        if (!fs::exists(SYSTEM_NVM_PATH)) {
            logger->info("[!] System NVM directory not found: " + SYSTEM_NVM_PATH);
            logger->info("[!] You need to run this program with administrator privileges.");
            exit(1);
        }
    } 
    catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("Error initializing paths: " + std::string(e.what()));
        exit(1);
    }
}
// Write the debug flag to nvm_dbg.conf
void NVMLogCollectorWindows::writeDebugConf() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        int value;
        cin >> value;
        ofstream conf(CONF_FILE);
        if (conf) {
            conf << value;
            conf.close();
            logger->info("[+] Debug flag value " + std::to_string(value) + " written to " + CONF_FILE);
        } else {
            logger->error("[!] Failed to write to " + CONF_FILE);
            logger->error("[!] Make sure you're running with administrator privileges.");
            exit(1);
        }
    }catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("Error writing debug configuration: " + std::string(e.what()));
        exit(1);
    }
}
void NVMLogCollectorWindows::addTroubleshootTag() {
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
                logger->error("[!] Make sure you're running with administrator privileges.");
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
                logger->error("[!] Make sure you're running with administrator privileges.");
            }
        } else {
            logger->error("[!] Could not find </NVMProfile> tag in XML.");
        }
    }catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("Error adding TroubleShoot tag: " + std::string(e.what()));
    }
}
void NVMLogCollectorWindows::backupServiceProfile() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Creating backup of NVM_ServiceProfile.xml...");
    
        std::string cmd = "copy \"C:\\ProgramData\\Cisco\\Cisco Secure Client\\NVM\\NVM_ServiceProfile.xml\" \"C:\\ProgramData\\Cisco\\Cisco Secure Client\\NVM\\NVM_ServiceProfile.xml.bak\"";
        
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("Backup created successfully as NVM_ServiceProfile.xml.bak");
        } else {
            logger->error("Failed to create backup, error code: " + std::to_string(result));
        }
    }catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("Error creating backup of NVM_ServiceProfile.xml: " + std::string(e.what()));
    }
}
void NVMLogCollectorWindows::findNVMAgentProcesses() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Searching for NVM agent processes...");
    
        // Command to find NVM agent processes in Windows
        std::string cmd1 = "tasklist /FI \"IMAGENAME eq acnvmagent.exe\" /FO TABLE";
        
        int result1 = system(cmd1.c_str());
        
        if (result1 == 0) {
            logger->info("NVM agent processes found and displayed");
        } else {
            logger->warning("Command execution returned non-zero status: " + std::to_string(result1));
        }
        
        // Create a pipe to capture command output
        std::array<char, 128> buffer;
        std::string result;
        std::string cmd = "tasklist /FI \"IMAGENAME eq acnvmagent.exe\" /FO CSV";
        
        FILE* pipe = POPEN(cmd.c_str(), "r");
        if (!pipe) {
            logger->error("Failed to execute process search command");
            return;
        }
        
        // Read the command output
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
            result += buffer.data();
        }
        PCLOSE(pipe);
        
        // Parse the output to get PID
        std::istringstream stream(result);
        std::string line;
        std::string pid;
        
        // Skip header line
        std::getline(stream, line);
        
        if (std::getline(stream, line)) {
            // CSV format: "Image Name","PID","Session Name","Session#","Mem Usage"
            // Parse CSV format
            size_t firstQuote = line.find('"');
            size_t secondQuote = line.find('"', firstQuote + 1);
            size_t thirdQuote = line.find('"', secondQuote + 1);
            size_t fourthQuote = line.find('"', thirdQuote + 1);
            
            if (firstQuote != std::string::npos && secondQuote != std::string::npos && 
                thirdQuote != std::string::npos && fourthQuote != std::string::npos) {
                // Extract PID which is between 3rd and 4th quotes
                pid = line.substr(thirdQuote + 1, fourthQuote - thirdQuote - 1);
            }
        }
        
        if (!pid.empty()) {
            logger->info("Found NVM agent PID: " + pid);
            
            // Stop the NVM agent
            std::string killCmd = "taskkill /F /PID " + pid;
            int result = system(killCmd.c_str());
            
            if (result == 0) {
                logger->info("Successfully terminated NVM agent process");
                
                // Wait briefly to ensure clean shutdown
                std::this_thread::sleep_for(std::chrono::seconds(2));
                
                // Start the NVM agent
                std::string startCmd = "\"C:\\Program Files (x86)\\Cisco\\Cisco Secure Client\\NVM\\acnvmagent.exe\"";
                int startResult = system(startCmd.c_str());
                
                if (startResult == 0) {
                    logger->info("[+] Successfully restarted NVM agent");
                } else {
                    logger->error("[!] Failed to start NVM agent");
                }
            } else {
                logger->error("Failed to terminate process with PID: " + pid);
            }
        } else {
            logger->warning("No NVM agent PID found");
        }
        logger->info("Searching for Umbrella agent processes...");

        // Command to find Umbrella agent processes in Windows
        std::string umbrellaCmd1 = "tasklist /FI \"IMAGENAME eq acumbrellaagent.exe\" /FO TABLE";

        int umbrellaResult1 = system(umbrellaCmd1.c_str());

        if (umbrellaResult1 == 0) {
            logger->info("Umbrella agent processes found and displayed");
        } else {
            logger->warning("Command execution returned non-zero status: " + std::to_string(umbrellaResult1));
        }

        // Create a pipe to capture command output
        std::array<char, 128> umbrellaBuffer;
        std::string umbrellaResult;
        std::string umbrellaCmd = "tasklist /FI \"IMAGENAME eq acumbrellaagent.exe\" /FO CSV";

        FILE* umbrellaPipe = POPEN(umbrellaCmd.c_str(), "r");
        if (!umbrellaPipe) {
            logger->error("Failed to execute Umbrella process search command");
            return;
        }

        // Read the command output
        while (fgets(umbrellaBuffer.data(), umbrellaBuffer.size(), umbrellaPipe) != nullptr) {
            umbrellaResult += umbrellaBuffer.data();
        }
        PCLOSE(umbrellaPipe);

        // Parse the output to get PID
        std::istringstream umbrellaStream(umbrellaResult);
        std::string umbrellaLine;
        std::string umbrellaPid;

        // Skip header line
        std::getline(umbrellaStream, umbrellaLine);

        if (std::getline(umbrellaStream, umbrellaLine)) {
            // CSV format: "Image Name","PID","Session Name","Session#","Mem Usage"
            // Parse CSV format
            size_t firstQuote = umbrellaLine.find('"');
            size_t secondQuote = umbrellaLine.find('"', firstQuote + 1);
            size_t thirdQuote = umbrellaLine.find('"', secondQuote + 1);
            size_t fourthQuote = umbrellaLine.find('"', thirdQuote + 1);
            
            if (firstQuote != std::string::npos && secondQuote != std::string::npos && 
                thirdQuote != std::string::npos && fourthQuote != std::string::npos) {
                // Extract PID which is between 3rd and 4th quotes
                umbrellaPid = umbrellaLine.substr(thirdQuote + 1, fourthQuote - thirdQuote - 1);
            }
        }

        if (!umbrellaPid.empty()) {
            logger->info("Found Umbrella agent PID: " + umbrellaPid);
            
            // Stop the Umbrella agent
            std::string umbrellaKillCmd = "taskkill /F /PID " + umbrellaPid;
            int umbrellaResult = system(umbrellaKillCmd.c_str());
            
            if (umbrellaResult == 0) {
                logger->info("Successfully terminated Umbrella agent process");
                
                // Wait briefly to ensure clean shutdown
                std::this_thread::sleep_for(std::chrono::seconds(2));
                
                // Start the Umbrella agent
                std::string umbrellaStartCmd = "\"C:\\Program Files (x86)\\Cisco\\Cisco Secure Client\\umbrella\\acumbrellaagent.exe\"";
                int umbrellaStartResult = system(umbrellaStartCmd.c_str());
                
                if (umbrellaStartResult == 0) {
                    logger->info("[+] Successfully restarted Umbrella agent");
                } else {
                    logger->error("[!] Failed to start Umbrella agent");
                }
            } else {
                logger->error("Failed to terminate Umbrella process with PID: " + umbrellaPid);
            }
        } else {
            logger->warning("No Umbrella agent PID found");
        }
    }catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("Error finding NVM agent processes: " + std::string(e.what()));
    }
}
void NVMLogCollectorWindows::removeDebugConf() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Removing NVM debug configuration file...");
        std::string cmd = "del \"C:\\ProgramData\\Cisco\\Cisco Secure Client\\NVM\\nvm_dbg.conf\"";

        int result = system(cmd.c_str());

        if (result == 0) {
            logger->info("Successfully removed nvm_dbg.conf");
        } else {
            logger->error("Failed to remove nvm_dbg.conf. Error code: " + std::to_string(result));
        }
    } catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("Error removing NVM debug configuration file: " + std::string(e.what()));
    }
}
void NVMLogCollectorWindows::restoreServiceProfile() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Restoring NVM_ServiceProfile.xml from backup...");
    
        std::string cmd = "copy \"C:\\ProgramData\\Cisco\\Cisco Secure Client\\NVM\\NVM_ServiceProfile.xml.bak\" \"C:\\ProgramData\\Cisco\\Cisco Secure Client\\NVM\\NVM_ServiceProfile.xml\"";
        
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("NVM_ServiceProfile.xml restored successfully from backup");
        } else {
            logger->error("Failed to restore from backup, error code: " + std::to_string(result));
        }
    } catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("Error restoring NVM_ServiceProfile.xml: " + std::string(e.what()));
    }
}
void NVMLogCollectorWindows::setKDFDebugFlag() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    string SYSTEM_KDF_PATH = "C:\\Program Files (x86)\\Cisco\\Cisco Secure Client\\";
    string KDF_BIN_PATH = SYSTEM_KDF_PATH;
    
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
        
        string acsocktoolPath = KDF_BIN_PATH + "acsocktool.exe";
        
        // Check if acsocktool exists
        if (!fs::exists(acsocktoolPath)) {
            logger->error("[!] acsocktool not found at: " + acsocktoolPath);
            return;
        }
        
        // Execute acsocktool command with hex value
        string cmd = "\"" + acsocktoolPath + "\" -sdf 0x" + hexInput;
        logger->info("[*] Executing command: " + cmd);
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
            logger->error("[!] Failed to set KDF debug flag");
        }
    } catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("Error setting KDF debug flag: " + std::string(e.what()));
    }
}
void NVMLogCollectorWindows::clearKDFDebugFlag() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        string SYSTEM_KDF_PATH = "C:\\Program Files (x86)\\Cisco\\Cisco Secure Client\\";
        string KDF_BIN_PATH = SYSTEM_KDF_PATH;
        string acsocktoolPath = KDF_BIN_PATH + "acsocktool.exe";

        if (!fs::exists(acsocktoolPath)) {
            logger->error("[!] acsocktool not found at: " + acsocktoolPath);
            return;
        }

        logger->info("[*] Resetting KDF debug flag...");
        string cmd = "\"" + acsocktoolPath + "\" -cdf"; // Clear Debug Flag command
        logger->info("[*] Executing command: " + cmd);
        if (system(cmd.c_str()) == 0) {
            logger->info("[+] KDF debug flag reset successfully");
        } else {
            logger->error("[!] Failed to reset KDF debug flag");
        }
    }catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("Error resetting KDF debug flag: " + std::string(e.what()));
    }
}
void NVMLogCollectorWindows::createSWGConfigOverride() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        string UMBRELLA_PATH = "C:\\Program Files (x86)\\Cisco\\Cisco Secure Client\\umbrella\\";
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
            logger->error("[!] Make sure you're running with administrator privileges.");
        }
        
        logger->info("[+] SWG Config Override setup completed successfully");
    }catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("Error creating SWGConfigOverride.json: " + std::string(e.what()));
    }
}
void NVMLogCollectorWindows::deleteSWGConfigOverride() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    string UMBRELLA_PATH = "C:\\Program Files (x86)\\Cisco\\Cisco Secure Client\\umbrella\\";
    string CONFIG_OVERRIDE_FILE = UMBRELLA_PATH + "SWGConfigOverride.json";

    // Check if file exists before attempting to delete
    if (fs::exists(CONFIG_OVERRIDE_FILE)) {
        try {
            // Remove the file
            fs::remove(CONFIG_OVERRIDE_FILE);
            logger->info("[+] Successfully deleted " + CONFIG_OVERRIDE_FILE);
        } catch (const fs::filesystem_error& e) {
            logger->error("[!] Error deleting file: " + string(e.what()));
            logger->error("[!] Make sure you have administrator privileges");
        }
    } else {
        logger->warning("[!] SWGConfigOverride.json file not found at: " + CONFIG_OVERRIDE_FILE);
    }
}
void NVMLogCollectorWindows::collectLogsWithTimer() {
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
// Combined log collection function
void NVMLogCollectorWindows::collectAllLogs() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Starting unified log collection (KDF, Packet Capture, NVM System, Umbrella)...");
    
        // Get user's profile path
        std::string userProfilePath = getUserProfilePath();
        if (userProfilePath.empty()) {
            logger->error("Could not determine user profile directory");
            return;
        }
        // Create paths for all log files
        std::string kdfLogPath = userProfilePath + "\\Desktop\\kdf_logs" + ".log";
        std::string etlPath = userProfilePath + "\\Desktop\\PacketCapture" + ".etl";
        std::string pcapPath = userProfilePath + "\\Desktop\\packetCapture" + ".pcap";
        std::string nvmLogPath = userProfilePath + "\\Desktop\\nvm_system_logs" + ".log";
        std::string umbrellaLogPath = userProfilePath + "\\Desktop\\swg_umbrella_logs" + ".log";
        std::string debugViewPath = userProfilePath + "\\Downloads\\Debugview\\Dbgview.exe";
        
        // Debug output to verify paths
        logger->info("Debug info - userProfilePath: " + userProfilePath);
        logger->info("Debug info - KDF log path: " + kdfLogPath);
        logger->info("Debug info - ETL capture path: " + etlPath);
        logger->info("Debug info - PCAP output path: " + pcapPath);
        logger->info("Debug info - NVM system log path: " + nvmLogPath);
        logger->info("Debug info - Umbrella log path: " + umbrellaLogPath);
        logger->info("Debug info - DebugView path: " + debugViewPath);
        std::vector<std::pair<std::string, std::string>> commands = {
            {
                "start \"KDF Log Collection\" \"" + debugViewPath + "\" /k /v /l \"" + kdfLogPath + "\"",
                "KDF Logs"
            },
            {
                "wevtutil qe \"Cisco Secure Client - Network Visibility Module\" /f:text > \"" + nvmLogPath + "\"",
                "NVM System Logs"
            },
            {
                "pktmon start --capture --file-name \"" + etlPath + "\"",
                "Packet Capture"
            },
            {
                "wevtutil qe \"Cisco Secure Client - Umbrella\" /f:text > \"" + umbrellaLogPath + "\"",
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
        std::vector<std::pair<std::string, std::string>> killCommands = {
            {"taskkill /F /IM Dbgview.exe > nul 2>&1", "KDF Logs"},
            //{"taskkill /F /FI \"WINDOWTITLE eq *wevtutil*NVM*\" > nul 2>&1", "NVM System Logs"},
            {"pktmon stop", "Packet Capture"},
            //{"taskkill /F /FI \"WINDOWTITLE eq *wevtutil*Umbrella*\" > nul 2>&1", "Umbrella/SWG Logs"}
        };
        // Stop each process with descriptive logging    
        logger->info("\nStopping all log collections...");
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
        logger->info("Converting ETL file to PCAP format...");
        std::string convertCmd = "pktmon etl2pcap \"" + etlPath + "\" -o \"" + pcapPath + "\"";
        logger->info("Executing conversion command: " + convertCmd);
            
        int convertResult = system(convertCmd.c_str());
        if (convertResult == 0) {
            logger->info("Successfully converted ETL to PCAP format");
            logger->info("PCAP file saved to: " + pcapPath);
        } else {
            logger->error("Failed to convert ETL to PCAP format. Error code: " + std::to_string(convertResult));
        }
        std::string startCmd = "\"C:\\Program Files (x86)\\Cisco\\Cisco Secure Client\\nvm\\bin\\acnvmagent.exe\"";
        int startResult = system(startCmd.c_str());

        if (startResult == 0) {
            logger->info("[+] Successfully started NVM agent");
        } else {
            logger->error("[!] Failed to start NVM agent");
        }
        std::string startCmd1 = "\"C:\\Program Files (x86)\\Cisco\\Cisco Secure Client\\umbrella\\acumbrellaagent.exe\"";
        int startResult1 = system(startCmd1.c_str());

        if (startResult1 == 0) {
            logger->info("[+] Successfully started Umbrella agent");
        } else {
            logger->error("[!] Failed to start Umbrella agent");
        }
    }catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("Error collecting all logs: " + std::string(e.what()));
    }
}
void NVMLogCollectorWindows::collectDARTBundle() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Starting DART bundle collection...");
    
        // Get user's profile path
        std::string userProfilePath = getUserProfilePath();
        if (userProfilePath.empty()) {
            logger->error("Could not determine user profile directory");
            return;
        }
        // Create path for the DART bundle
        std::string dartBundlePath = userProfilePath + "\\Desktop\\DART_Bundle" + ".zip";
        // Path to dartcli.exe
        std::string dartCliPath = "C:\\Program Files (x86)\\Cisco\\Cisco Secure Client\\DART\\dartcli.exe";
        std::string cmd = "\"" + dartCliPath + "\" -dst \"" + dartBundlePath + "\"";
        
        logger->info("Generating DART bundle...");
        logger->info("This may take several minutes depending on the system and log size.");
        logger->info("DART bundle will be saved to: " + dartBundlePath);
        std::string Cmd = "powershell -Command \"Start-Process '" + dartCliPath + 
            "' -ArgumentList '-dst', '" + dartBundlePath + 
            "' -Verb RunAs -Wait\"";
        int result = system(Cmd.c_str());
        if (result == 0) {
            logger->info("DART bundle collected successfully");
            logger->info("DART bundle saved to: " + dartBundlePath);
        } else {
            logger->error("Failed to collect DART bundle. Error code: " + std::to_string(result));
            logger->error("Make sure you're running with administrator privileges.");
        }
    }catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    } catch (const std::exception& e) {
        logger->error("Error collecting DART bundle: " + std::string(e.what()));
    }
}
std::string NVMLogCollectorWindows::getUserProfilePath() {
    const char* userProfile = getenv("USERPROFILE");
    if (userProfile) {
        return std::string(userProfile);
    }
    return "";
}
void NVMLogCollectorWindows::LogCollectorFile(){
    try {
        std::string buildPath = fs::current_path().string();
        std::string logCollectorPath = buildPath + "\\logcollector.log";
        if (fs::exists(logCollectorPath)) {
            std::ofstream logFile(logCollectorPath, std::ios::trunc);
            if (logFile.is_open()) {
                logFile.close();
            } else {
                return;
            }
        } else {
            return;
        }
    } catch (const std::exception& e) {
        return;
    }
}
void NVMLogCollectorWindows::organizeAndArchiveLogs() {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try {
        logger->info("Organizing and archiving collected logs...");

        const char* userProfile = getenv("USERPROFILE");
        if (!userProfile) {
            logger->error("Could not determine user profile directory");
            return;
        }

        std::string desktopPath = std::string(userProfile) + "/Desktop";
        std::string nvmLogsDir = desktopPath + "/nvm_logs";
        std::string buildPath = fs::current_path().string();
        std::string logCollectorPath = buildPath + "/logcollector.log";
        
        // 1. Create nvm_logs directory
        std::string mkdirCmd = "mkdir \"" + nvmLogsDir + "\" 2>nul";
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
        std::string copyCmd = "copy /Y \"" + logCollectorPath + "\" \"" + nvmLogsDir + "\\\" >nul 2>&1";
        system(copyCmd.c_str());
        logger->info("Copied logcollector.log to nvm_logs directory");
        // Move each file individually (Windows doesn't support moving multiple files in one command)
        std::vector<std::string> logFiles = {
            "kdf_logs.log",
            "nvm_system_logs.log",
            "PacketCapture.pcap",
            "PacketCapture.etl",
            "DART_Bundle.zip",
            "swg_umbrella_logs.log"
        };
        
        for (const auto& file : logFiles) {
            std::string sourceFile = desktopPath + "\\" + file;
            // Check if file exists before attempting to move
            if (fs::exists(sourceFile)) {
                std::string moveCmd = "move /Y \"" + sourceFile + "\" \"" + nvmLogsDir + "\\\" >nul 2>&1";
                system(moveCmd.c_str());
            }
        }
        
        // 4. Create timestamped zip archive using PowerShell
        std::string timestamp = "";
        {
            time_t now = time(nullptr);
            char buf[20];
            strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", localtime(&now));
            timestamp = buf;
        }
        
        std::string zipOutputPath = desktopPath + "\\secure_client_logs_" + timestamp + ".zip";
        
        // Use PowerShell to create the zip archive
        logger->info("Creating zip archive of logs...");
        std::string zipCmd = "powershell -Command \"Compress-Archive -Path '" + 
                            nvmLogsDir + "' -DestinationPath '" + zipOutputPath + "'\"";
        
        int zipResult = system(zipCmd.c_str());
        if (zipResult == 0) {
            logger->info("Successfully created archive: secure_client_logs_" + timestamp + ".zip");
            
            // Optional: Clean up nvm_logs directory after successful archive
            std::string cleanupCmd = "rmdir /S /Q \"" + nvmLogsDir + "\"";
            if (system(cleanupCmd.c_str()) == 0) {
                logger->info("Cleaned up temporary logs directory");
            }
        } else {
            logger->error("Failed to create zip archive. Error code: " + std::to_string(zipResult));
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