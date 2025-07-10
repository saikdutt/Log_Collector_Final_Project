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
#include <thread>
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
LogCollectorError::ErrorType CommonUtils::addTroubleshootTagSystem(const std::string& XML_FILE) {
#if defined(__linux__) // Linux platform
    try {
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
                    pattern = "NVM-TRACE-FLOWS";
                    break;
                case 2:
                    pattern = "PROCESS-TREE-INFO";
                    break;
                case 3:
                    pattern = "PROCESS-TREE-INFO, NVM-TRACE-FLOWS";
                    break;
                default:
                    logger->error("[!] Invalid choice. Exiting.");
                    logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                    return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
        } else {
            logger->error("[!] Invalid choice. Exiting.");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // Create a temp file path in /tmp directory
        std::string tmpFile = "/tmp/nvm_profile_temp.xml";
        
        // Copy the XML to temp file with sudo for reading
        std::string copyCmd = "sudo cp " + XML_FILE + " " + tmpFile + 
                             " && sudo chmod 666 " + tmpFile;
        int copyResult = system(copyCmd.c_str());
        
        if (copyResult != 0) {
            // Check if file exists, if not create basic structure
            std::string checkCmd = "sudo [ -f " + XML_FILE + " ] && echo \"exists\" || echo \"not exists\"";
            FILE* pipe = popen(checkCmd.c_str(), "r");
            if (!pipe) {
                logger->error("[!] Failed to check XML file existence");
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
            
            char buffer[128];
            std::string result = "";
            while (!feof(pipe)) {
                if (fgets(buffer, 128, pipe) != NULL)
                    result += buffer;
            }
            pclose(pipe);
            
            if (result.find("not exists") != std::string::npos) {
                logger->error("[!] XML file not found: " + XML_FILE);
                logger->info("[!] Creating a new XML file with basic structure.");
                
                std::string createCmd = "echo \"<NVMProfile>\n</NVMProfile>\" | sudo tee " + XML_FILE + 
                                       " > /dev/null && sudo cp " + XML_FILE + " " + tmpFile + 
                                       " && sudo chmod 666 " + tmpFile;
                int createResult = system(createCmd.c_str());
                
                if (createResult != 0) {
                    logger->error("[!] Failed to create XML file. Check permissions.");
                    logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                    return LogCollectorError::ErrorType::COMMAND_FAILED;
                }
            } else {
                logger->error("[!] Failed to copy XML file for editing.");
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
        }
        
        // Now read the temporary file
        ifstream inFile(tmpFile);
        string xmlContent;
        string line;

        if (!inFile) {
            logger->error("[!] Cannot open temporary XML file");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
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

            // Write to temp file
            ofstream outFile(tmpFile);
            if (outFile) {
                outFile << xmlContent;
                outFile.close();
                
                // Copy back with sudo
                std::string writeCmd = "sudo cp " + tmpFile + " " + XML_FILE;
                int writeResult = system(writeCmd.c_str());
                
                if (writeResult == 0) {
                    logger->info("[+] Inserted TroubleShoot tag with pattern: " + pattern);
                    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
                } else {
                    logger->error("[!] Failed to write to XML file. Check permissions.");
                    logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                    return LogCollectorError::ErrorType::COMMAND_FAILED;
                }
            } else {
                logger->error("[!] Failed to write to temporary file.");
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
        } else {
            logger->error("[!] Could not find </NVMProfile> tag in XML.");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception& e) {
        logger->error("Error adding TroubleShoot tag: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
#else // macOS and Windows platforms
    try {
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
                    pattern = "NVM-TRACE-FLOWS";
                    break;
                case 2:
                    pattern = "PROCESS-TREE-INFO";
                    break;
                case 3:
                    pattern = "PROCESS-TREE-INFO, NVM-TRACE-FLOWS";
                    break;
                default:
                    logger->error("[!] Invalid choice. Exiting.");
                    logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                    return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
        } else {
            logger->error("[!] Invalid choice. Exiting.");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
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
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
        }

        // Now read the file
        ifstream inFile(XML_FILE);
        string xmlContent;
        string line;

        if (!inFile) {
            logger->error("[!] Cannot open XML file: " + XML_FILE);
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
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
                return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
            } else {
                logger->error("[!] Failed to write to XML file. Check permissions.");
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
        } else {
            logger->error("[!] Could not find </NVMProfile> tag in XML.");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception& e) {
        logger->error("Error adding TroubleShoot tag: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
#endif
}

LogCollectorError::ErrorType CommonUtils::setKDFDebugFlagSystem(const std::string& PATH, const std::string& hexValue) {
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
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::FILE_NOT_FOUND));
            return LogCollectorError::ErrorType::FILE_NOT_FOUND;
        }

        // Execute acsocktool command with hex value
        #ifdef _WIN32
        string cmd = "\"" + PATH + "\" -sdf 0x" + hexValueCopy;  // Windows needs quotes
        #else
        string cmd = PATH + " -sdf 0x" + hexValueCopy;  // Mac/Linux version
        #endif
        
        logger->info("[*] Setting KDF debug flag to 0x" + hexValueCopy + "...");
        logger->info("[*] Executing command: " + cmd);
        if (system(cmd.c_str()) == 0) {
            logger->info("[+] KDF debug flag set successfully");
        } else {
            logger->error("[!] Failed to set KDF debug flag");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
    } catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    } catch (const std::exception& e) {
        logger->error("Error setting KDF debug flag: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

LogCollectorError::ErrorType CommonUtils::clearKDFDebugFlagSystem(const std::string& PATH) {
    try {
        logger->info("Clearing KDF debug flag...");
        
        // Check if acsocktool exists
        if (!fs::exists(PATH)) {
            logger->error("acsocktool not found at: " + PATH);
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::FILE_NOT_FOUND));
            return LogCollectorError::ErrorType::FILE_NOT_FOUND;
        }
        
        // Construct and execute command
        #ifdef _WIN32
        std::string cmd = "\"" + PATH + "\" -cdf";  // Windows needs quotes for paths with spaces
        #else
        std::string cmd = PATH + " -cdf";  // Mac/Linux version
        #endif
        
        logger->info("Executing command: " + cmd);
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("KDF debug flag cleared successfully");
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        } else {
            logger->error("Failed to clear KDF debug flag. Error code: " + std::to_string(result));
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
    } catch(const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    } catch (const std::exception& e) {
        logger->error("Error clearing KDF debug flag: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

LogCollectorError::ErrorType CommonUtils::writeDebugConfSystem(const std::string& PATH) {
    try {
        logger->info("Enter the debug value");
        int value;
        cin >> value;
        
#if defined(__linux__)
        // Linux implementation - use sudo to write to protected directories
        std::string cmd = "echo " + std::to_string(value) + " | sudo tee " + PATH + " > /dev/null";
        
        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("[+] Debug flag value " + std::to_string(value) + " written to " + PATH);
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        } else {
            logger->error("[!] Failed to write to " + PATH);
            logger->error("[!] Make sure you're running with sudo.");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
#else
        // macOS/Windows implementation - use direct file access
        ofstream conf(PATH);
        if (conf) {
            conf << value;
            conf.close();
            logger->info("[+] Debug flag value " + std::to_string(value) + " written to " + PATH);
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        } else {
            logger->error("[!] Failed to write to " + PATH);
            logger->error("[!] Make sure you're running with sudo.");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
#endif
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception& e) {
        logger->error("Error writing debug configuration: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

LogCollectorError::ErrorType CommonUtils::removeDebugConfSystem(const std::string& PATH) {
    try {
        logger->info("Removing NVM debug configuration file...");

        std::string cmd;
        #ifdef _WIN32
            cmd = "del \"" + PATH + "\"";
        #else
            cmd = "sudo rm " + PATH;
        #endif

        int result = system(cmd.c_str());
        
        if (result == 0) {
            logger->info("Successfully removed nvm_dbg.conf");
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        } else {
            logger->error("Failed to remove nvm_dbg.conf. Error code: " + std::to_string(result));
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception& e) {
        logger->error("Error removing NVM debug configuration file: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

LogCollectorError::ErrorType CommonUtils::createSWGConfigOverrideSystem(const std::string& PATH) {
    try {
        string CONFIG_OVERRIDE_FILE = PATH + "SWGConfigOverride.json";

        // Check if directory exists, create if it doesn't
        if (!fs::exists(PATH)) {
            try {
                fs::create_directories(PATH);
                logger->info("[+] Created Umbrella directory at: " + PATH);
            } catch (const fs::filesystem_error& e) {
                logger->error("[!] Error creating directory: " + string(e.what()));
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
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
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        } else {
            logger->error("[!] Failed to write to " + CONFIG_OVERRIDE_FILE);
            logger->error("[!] Make sure you're running with sudo privileges.");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
    }
    catch (const LogCollectorError& e) {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception& e) {
        logger->error("Error creating SWGConfigOverride.json: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

LogCollectorError::ErrorType CommonUtils::deleteSWGConfigOverrideSystem(const std::string& PATH) {
    string CONFIG_OVERRIDE_FILE = PATH + "SWGConfigOverride.json";

    // Check if file exists before attempting to delete
    if (fs::exists(CONFIG_OVERRIDE_FILE)) {
        try {
            // Remove the file
            fs::remove(CONFIG_OVERRIDE_FILE);
            logger->info("[+] Successfully deleted " + CONFIG_OVERRIDE_FILE);
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        } 
        catch (const LogCollectorError& e) {
            logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
            logger->error("Details: " + std::string(e.what()));
            return e.getType();
        } catch (const std::exception& e) {
            logger->error("Error deleting SWGConfigOverride.json: " + std::string(e.what()));
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
    } else {
        logger->warning("[!] SWGConfigOverride.json file not found at: " + CONFIG_OVERRIDE_FILE);
        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
}