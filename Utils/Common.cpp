#if defined(__cplusplus) && __cplusplus >= 201703L
#include <filesystem>
namespace fs = std::filesystem;
#else
#error "Need C++17 for filesystem support"
#endif
#include "Common.h"
#include <iostream>
#include <array>
#include <regex>
#include <cstdio>
#include <filesystem>
#include <thread>
#include <chrono>
#include <fstream>
#include <unistd.h>
#include <stdexcept>
#include <string>
#include <cctype> 
#include <sstream> 
#include <atomic>
#include <signal.h>
#include <iomanip>
#include <regex>
#include <curl/curl.h>
#include "Error.h"
using namespace std;
CommonUtils::CommonUtils(std::shared_ptr<Logger> logger) : logger(logger) {}
std::atomic<bool> g_stopCollection{false};
std::string SYSTEM_NVM_PATH = "";
std::string CONF_FILE = "";
std::string XML_FILE = "";
void signalHandler(int signum) {
    if (signum == SIGINT) {
        g_stopCollection = true;
    }
}   
void CommonUtils::addTroubleshootTagSystem(const std::string& XML_FILE) {
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
                    logger->error("[!] Invalid choice. Exiting.");
            }
        } else if (patternChoice != 4) {
            logger->error("[!] Invalid choice. Exiting.");
            return;
        }
        // First check if XML file exists
        if (!fs::exists(XML_FILE)) {
            logger->error("[!] XML file not found: " + XML_FILE);
            logger->info("[!] Creating a new XML file with basic structure.");

            ofstream newXml(XML_FILE);
            if (newXml) {
                newXml << "<NVMProfile>\n</NVMProfile>\n";
                newXml.close();
            } else {
                logger->error("[!] Failed to create XML file. Check permissions.");
            }
        }
            
        // Now read the file
        ifstream inFile(XML_FILE);
        string xmlContent;
        string line;

        if (!inFile) {
            logger->error("[!] Cannot open XML file: " + XML_FILE);
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
            }
        } else {
            logger->error("[!] Could not find </NVMProfile> tag in XML.");
        }
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error adding TroubleShoot tag: " + std::string(e.what()));
    }
}
void CommonUtils::setKDFDebugFlagSystem(const std::string& PATH, const std::string& hexValue) {
    auto logger = std::make_shared<Logger>("logcollector.log");
    
    try {
        // Remove "0x" prefix if present
        std::string hexValueCopy = hexValue; // Create a copy since hexValue is const
        if (hexValueCopy.size() > 2 && hexValueCopy.substr(0, 2) == "0x") {
            hexValueCopy = hexValueCopy.substr(2);
        }
        
        // Convert hex string to unsigned long to handle large values
        unsigned long debugFlag = stoul(hexValueCopy, nullptr, 16);
        // Check if acsocktool exists
        if (!fs::exists(PATH)) {
            logger->error("[!] acsocktool not found at: " + PATH);
            return;
        }

        // Execute acsocktool command with hex value
        string cmd = PATH + " -sdf 0x" + hexValueCopy;
        logger->info("[*] Setting KDF debug flag to 0x" + hexValueCopy + "...");
        logger->info("[*] Executing command: " + cmd);
        if (system(cmd.c_str()) == 0) {
            logger->info("[+] KDF debug flag set successfully");
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
void CommonUtils::clearKDFDebugFlagsSystem(const std::string& PATH) {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Clearing KDF debug flag...");
        
        // Check if acsocktool exists
        if (!fs::exists(PATH)) {
            logger->error("acsocktool not found at: " + PATH);
            return;
        }
        
        // Construct and execute command
        std::string cmd = PATH + " -cdf";
        logger->info("Executing command: " + cmd);
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
void CommonUtils::writeDebugConfSystem(const std::string& PATH) {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try
    {
        logger->info("Enter the debug value");
        int value;
        cin >> value;
        ofstream conf(PATH);
        if (conf) {
            conf << value;
            conf.close();
            logger->info("[+] Debug flag value " + std::to_string(value) + " written to " + PATH);
        } else {
            logger->error("[!] Failed to write to " + PATH);
            logger->error("[!] Make sure you're running with sudo.");
            exit(1);
        }
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        logger->error("Error writing debug configuration: " + std::string(e.what()));
    }
}
void CommonUtils::removeDebugConfSystem(const std::string& PATH) {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try{
        logger->info("Removing NVM debug configuration file...");

        std::string cmd = "sudo rm " + PATH;

        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("Successfully removed debug configuration file: " + PATH);
        } else {
            logger->error("Failed to remove debug configuration file. Error code: " + std::to_string(result));
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
void CommonUtils::createSWGConfigOverrideSystem(const std::string& PATH) {
    auto logger = std::make_shared<Logger>("logcollector.log");
    try
    {
        string CONFIG_OVERRIDE_FILE = PATH + "SWGConfigOverride.json";

        // Check if directory exists, create if it doesn't
        if (!fs::exists(PATH)) {
            try {
                fs::create_directories(PATH);
                logger->info("[+] Created Umbrella directory at: " + PATH);
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
void CommonUtils::deleteSWGConfigOverrideSystem(const std::string& PATH) {
    auto logger = std::make_shared<Logger>("logcollector.log");
    string CONFIG_OVERRIDE_FILE = PATH + "SWGConfigOverride.json";

    // Check if file exists before attempting to delete
    if (fs::exists(CONFIG_OVERRIDE_FILE)) {
        try {
            // Remove the file
            fs::remove(CONFIG_OVERRIDE_FILE);
            logger->info("[+] Successfully deleted " + CONFIG_OVERRIDE_FILE);
        } 
        catch (const LogCollectorError& e) {
            logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
            logger->error("Details: " + std::string(e.what()));
        } catch (const std::exception& e) {
            logger->error("Error creating SWGConfigOverride.json: " + std::string(e.what()));
        }
    } else {
        logger->warning("[!] SWGConfigOverride.json file not found at: " + CONFIG_OVERRIDE_FILE);
    }
}