
#if defined(__cplusplus) && __cplusplus >= 201703L
#include <filesystem>
namespace fs = std::filesystem;
#else
#error "Need C++17 for filesystem support"
#endif
#include <iostream>
#include <thread>
#include <regex>
#include <array>
#include "./Windows_collector.h"
#include "../../Utils/Logger.h"
#include "../../Utils/Error.h"
#include "../../Utils/Common.h"
#ifdef _WIN32
#define POPEN _popen
#define PCLOSE _pclose
#else
#define POPEN popen
#define PCLOSE pclose
#endif

using namespace std;

/**
 * @brief Constructs a Windows NVM log collector with multiple module support.
 * @param config Configuration settings map for collector initialization.
 * @param logger Shared pointer to logger instance for output messages.
 * @param enable_debug_logs Optional flag to enable detailed debug logging (default: false).
 * @param debug_level Optional debug verbosity level (default: 0).
 * @note Initializes all collector modules (NVM, SWG, ISE, ZTA) and utilities.
 */
LogCollectorWindows::LogCollectorWindows(const std::map<std::string, std::string> &config,
                                         std::shared_ptr<Logger> logger,
                                         bool enable_debug_logs,
                                         int debug_level)
    : BaseCollector(config, logger),
      NVMLogCollector(config, logger, enable_debug_logs, debug_level),
      SWGLogCollector(config, logger),
      ISEPostureCollector(config, logger),
      ZTACollector(config, logger),
      utils(logger)
{

    logger->info("CollectorWindows initialized with NVM and SWG support.");
}

/**
 * @brief Destroys the Windows NVM log collector instance.
 * @note Logs a destruction message before cleanup.
 */
LogCollectorWindows::~LogCollectorWindows()
{
    logger->info("LogCollectorWindows destroyed");
}
/**
 * @brief Retrieves the version of the NVM agent on Windows.
 * @note Executes the NVM agent binary with the `-v` flag and parses the output.
 * @details Logs the version or any errors encountered during the process.
 */
LogCollectorError::ErrorType LogCollectorWindows::get_nvm_version()
{
    logger->info("Getting NVM agent version...");
    try
    {
        // Use the specific path provided
        std::string nvmAgentPath = WinPaths::NVM_AGENT;

        // Check if the path exists
        if (!fs::exists(nvmAgentPath))
        {
            logger->error("NVM agent (acnvmagent.exe) not found at: " + nvmAgentPath);
            nvm_version = "not_installed";
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        logger->info("Found NVM agent at: " + nvmAgentPath);

        // Create a pipe to capture command output
        std::array<char, 128> buffer;
        std::string result;

        // Command to get NVM agent version
        std::string cmd = "\"" + nvmAgentPath + "\" -v";
        logger->info("Executing command: " + cmd);

        // Execute command and capture output
        FILE *pipe = POPEN(cmd.c_str(), "r");
        if (!pipe)
        {
            throw std::runtime_error("Failed to execute command to get NVM version");
        }

        // Read output
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
        {
            result += buffer.data();
        }

        // Close pipe and check status
        int status = PCLOSE(pipe);
        // Parse version from output even if status is non-zero
        if (!result.empty())
        {
            // Try using regex to match version with up to 4 decimal points (X.X.X.X)
            std::regex versionRegex("Version\\s*:\\s*(\\d+(?:\\.\\d+){0,3})");
            std::smatch matches;

            if (std::regex_search(result, matches, versionRegex) && matches.size() > 1)
            {
                nvm_version = matches[1].str();
                logger->info("NVM agent version: " + nvm_version);
                logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
                return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
            }
            // Fallback to manual parsing if regex doesn't match
            size_t pos = result.find("Version");
            if (pos != std::string::npos)
            {
                // Extract version number after "Version: "
                pos = result.find(":", pos);
                if (pos != std::string::npos)
                {
                    // Skip the colon and any whitespace
                    pos++;
                    while (pos < result.length() && std::isspace(result[pos]))
                    {
                        pos++;
                    }

                    // Extract the version number including up to 4 decimal points
                    size_t end_pos = pos;
                    int decimal_points = 0;

                    while (end_pos < result.length())
                    {
                        if (std::isdigit(result[end_pos]))
                        {
                            end_pos++;
                        }
                        else if (result[end_pos] == '.' && decimal_points < 3)
                        {
                            // Allow up to 3 decimal points (for a total of 4 numbers)
                            decimal_points++;
                            end_pos++;
                        }
                        else
                        {
                            break;
                        }
                    }

                    if (end_pos > pos)
                    {
                        nvm_version = result.substr(pos, end_pos - pos);
                        logger->info("NVM agent version: " + nvm_version);
                        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
                        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
                    }
                }
            }
        }
        if (nvm_version.empty())
        {
            logger->warning("Could not parse NVM version from output: " + result);
            nvm_version = status == 2 ? "not_installed" : "unknown";
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
    }
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error getting NVM version: " + std::string(e.what()));
        nvm_version = "error";
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

// Write the debug flag to nvm_dbg.conf
/**
 * @brief Writes the debug configuration file for the NVM agent.
 * @note Uses the utility function to write the debug configuration to `nvm_dbg.conf`.
 */
LogCollectorError::ErrorType LogCollectorWindows::writeDebugConf()
{
    utils.writeDebugConfSystem(WinPaths::DEBUG_CONF);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Removes the debug configuration file for the NVM agent.
 * @note Uses the utility function to delete `nvm_dbg.conf`.
 */
LogCollectorError::ErrorType LogCollectorWindows::removeDebugConf()
{
    utils.removeDebugConfSystem(WinPaths::DEBUG_CONF);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Adds a troubleshoot tag to the NVM service profile.
 * @note Uses the utility function to modify the service profile file.
 */
LogCollectorError::ErrorType LogCollectorWindows::addTroubleshootTag()
{
    utils.addTroubleshootTagSystem(WinPaths::SERVICE_PROFILE);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Sets the KDF debug flag on Windows.
 * @note Prompts the user for a hexadecimal debug flag and applies it using `acsocktool`.
 */
LogCollectorError::ErrorType LogCollectorWindows::setKDFDebugFlag()
{
    string hexInput;
    logger->info("\nEnter debug flag (hexadecimal, e.g., 0x20): ");
    cin >> hexInput;
    utils.setKDFDebugFlagSystem(WinPaths::ACSOCKTOOL, hexInput);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Clears the KDF debug flag on Windows.
 * @note Uses `acsocktool` to reset the debug flag to its default state.
 */
LogCollectorError::ErrorType LogCollectorWindows::clearKDFDebugFlag()
{
    utils.clearKDFDebugFlagSystem(WinPaths::ACSOCKTOOL);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Creates a configuration override for the SWG module.
 * @note Uses the utility function to create the override in the Umbrella path.
 */
LogCollectorError::ErrorType LogCollectorWindows::createSWGConfigOverride()
{
    utils.createSWGConfigOverrideSystem(WinPaths::UMBRELLA_PATH);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Deletes the configuration override for the SWG module.
 * @note Uses the utility function to remove the override from the Umbrella path.
 */
LogCollectorError::ErrorType LogCollectorWindows::deleteSWGConfigOverride()
{
    utils.deleteSWGConfigOverrideSystem(WinPaths::UMBRELLA_PATH);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Creates a backup of the NVM service profile.
 * @note Copies `NVM_ServiceProfile.xml` to a `.bak` file in the same directory.
 */
LogCollectorError::ErrorType LogCollectorWindows::backupServiceProfile()
{
    try
    {
        logger->info("Creating backup of NVM_ServiceProfile.xml...");
        std::string cmd = "copy \"" + WinPaths::SERVICE_PROFILE + "\" \"" + WinPaths::SERVICE_PROFILE + ".bak\"";
        int result = system(cmd.c_str());

        if (result == 0)
        {
            logger->info("Backup created successfully as NVM_ServiceProfile.xml.bak");
        }
        else
        {
            logger->error("Failed to create backup, error code: " + std::to_string(result));
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
    }
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error creating backup of NVM_ServiceProfile.xml: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Restores the NVM service profile from a backup.
 * @note Copies the `.bak` file back to `NVM_ServiceProfile.xml`.
 */
LogCollectorError::ErrorType LogCollectorWindows::restoreServiceProfile()
{
    try
    {
        logger->info("Restoring NVM_ServiceProfile.xml from backup...");
        std::string cmd = "copy \"" + WinPaths::SERVICE_PROFILE + ".bak\" \"" + WinPaths::SERVICE_PROFILE + "\"";
        int result = system(cmd.c_str());

        if (result == 0)
        {
            logger->info("NVM_ServiceProfile.xml restored successfully from backup");
        }
        else
        {
            logger->error("Failed to restore from backup, error code: " + std::to_string(result));
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
    }
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error restoring NVM_ServiceProfile.xml: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}
/**
 * @brief Searches for and terminates agent processes (NVM, Umbrella, ISE, ZTA) on Windows.
 * @note Uses `tasklist` to find processes and `taskkill` to terminate them by PID.
 * @details Logs the results of the search and termination attempts.
 */
LogCollectorError::ErrorType LogCollectorWindows::findAllAgentProcesses()
{
    try
    {
        logger->info("Searching for NVM agent processes...");

        // Command to find NVM agent processes in Windows
        std::string cmd1 = "tasklist /FI \"IMAGENAME eq acnvmagent.exe\" /FO TABLE";

        int result1 = system(cmd1.c_str());

        if (result1 == 0)
        {
            logger->info("NVM agent processes found and displayed");
        }
        else
        {
            logger->warning("Command execution returned non-zero status: " + std::to_string(result1));
        }

        // Create a pipe to capture command output
        std::array<char, 128> buffer;
        std::string result;
        std::string cmd = "tasklist /FI \"IMAGENAME eq acnvmagent.exe\" /FO CSV";

        FILE *pipe = POPEN(cmd.c_str(), "r");
        if (!pipe)
        {
            logger->error("Failed to execute process search command");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // Read the command output
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
        {
            result += buffer.data();
        }
        PCLOSE(pipe);

        // Parse the output to get PID
        std::istringstream stream(result);
        std::string line;
        std::string pid;

        // Skip header line
        std::getline(stream, line);

        if (std::getline(stream, line))
        {
            // CSV format: "Image Name","PID","Session Name","Session#","Mem Usage"
            // Parse CSV format
            size_t firstQuote = line.find('"');
            size_t secondQuote = line.find('"', firstQuote + 1);
            size_t thirdQuote = line.find('"', secondQuote + 1);
            size_t fourthQuote = line.find('"', thirdQuote + 1);

            if (firstQuote != std::string::npos && secondQuote != std::string::npos &&
                thirdQuote != std::string::npos && fourthQuote != std::string::npos)
            {
                // Extract PID which is between 3rd and 4th quotes
                pid = line.substr(thirdQuote + 1, fourthQuote - thirdQuote - 1);
            }
        }

        if (!pid.empty())
        {
            logger->info("Found NVM agent PID: " + pid);

            // Use the PID to terminate the process in Windows
            std::string killCmd = "taskkill /F /PID " + pid;
            int result = system(killCmd.c_str());

            if (result == 0)
            {
                logger->info("Successfully terminated NVM agent process");
            }
            else
            {
                logger->error("Failed to terminate process with PID: " + pid);
            }
        }
        else
        {
            logger->warning("No NVM agent PID found");
        }
        logger->info("Searching for Umbrella agent processes...");

        // Command to find Umbrella agent processes in Windows
        std::string umbrellaCmd1 = "tasklist /FI \"IMAGENAME eq acumbrellaagent.exe\" /FO TABLE";

        int umbrellaResult1 = system(umbrellaCmd1.c_str());

        if (umbrellaResult1 == 0)
        {
            logger->info("Umbrella agent processes found and displayed");
        }
        else
        {
            logger->warning("Command execution returned non-zero status: " + std::to_string(umbrellaResult1));
        }

        // Create a pipe to capture command output
        std::array<char, 128> umbrellaBuffer;
        std::string umbrellaResult;
        std::string umbrellaCmd = "tasklist /FI \"IMAGENAME eq acumbrellaagent.exe\" /FO CSV";

        FILE *umbrellaPipe = POPEN(umbrellaCmd.c_str(), "r");
        if (!umbrellaPipe)
        {
            logger->error("Failed to execute Umbrella process search command");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // Read the command output
        while (fgets(umbrellaBuffer.data(), umbrellaBuffer.size(), umbrellaPipe) != nullptr)
        {
            umbrellaResult += umbrellaBuffer.data();
        }
        PCLOSE(umbrellaPipe);

        // Parse the output to get PID
        std::istringstream umbrellaStream(umbrellaResult);
        std::string umbrellaLine;
        std::string umbrellaPid;

        // Skip header line
        std::getline(umbrellaStream, umbrellaLine);

        if (std::getline(umbrellaStream, umbrellaLine))
        {
            // CSV format: "Image Name","PID","Session Name","Session#","Mem Usage"
            // Parse CSV format
            size_t umbrellaFirstQuote = umbrellaLine.find('"');
            size_t umbrellaSecondQuote = umbrellaLine.find('"', umbrellaFirstQuote + 1);
            size_t umbrellaThirdQuote = umbrellaLine.find('"', umbrellaSecondQuote + 1);
            size_t umbrellaFourthQuote = umbrellaLine.find('"', umbrellaThirdQuote + 1);

            if (umbrellaFirstQuote != std::string::npos && umbrellaSecondQuote != std::string::npos &&
                umbrellaThirdQuote != std::string::npos && umbrellaFourthQuote != std::string::npos)
            {
                // Extract PID which is between 3rd and 4th quotes
                umbrellaPid = umbrellaLine.substr(umbrellaThirdQuote + 1, umbrellaFourthQuote - umbrellaThirdQuote - 1);
            }
        }

        if (!umbrellaPid.empty())
        {
            logger->info("Found Umbrella agent PID: " + umbrellaPid);

            // Use the PID to terminate the process in Windows
            std::string umbrellaKillCmd = "taskkill /F /PID " + umbrellaPid;
            int umbrellaKillResult = system(umbrellaKillCmd.c_str());

            if (umbrellaKillResult == 0)
            {
                logger->info("Successfully terminated Umbrella agent process");
            }
            else
            {
                logger->error("Failed to terminate Umbrella process with PID: " + umbrellaPid);
            }
        }
        else
        {
            logger->warning("No Umbrella agent PID found");
        }
        logger->info("Searching for ISE Posture processes...");

        // Command to find ISE Posture processes in Windows
        std::string iseCmd1 = "tasklist /FI \"IMAGENAME eq csc_iseagentd.exe\" /FO TABLE";

        int iseResult1 = system(iseCmd1.c_str());

        if (iseResult1 == 0)
        {
            logger->info("ISE Posture processes found and displayed");
        }
        else
        {
            logger->warning("Command execution returned non-zero status: " + std::to_string(iseResult1));
        }

        // Create a pipe to capture command output
        std::array<char, 128> iseBuffer;
        std::string iseResult;
        std::string iseCmd = "tasklist /FI \"IMAGENAME eq csc_iseagentd.exe\" /FO CSV";

        FILE *isePipe = POPEN(iseCmd.c_str(), "r");
        if (!isePipe)
        {
            logger->error("Failed to execute ISE Posture process search command");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // Read the command output
        while (fgets(iseBuffer.data(), iseBuffer.size(), isePipe) != nullptr)
        {
            iseResult += iseBuffer.data();
        }
        PCLOSE(isePipe);

        // Parse the output to get PID
        std::istringstream iseStream(iseResult);
        std::string iseLine;
        std::string isePid;

        // Skip header line
        std::getline(iseStream, iseLine);

        if (std::getline(iseStream, iseLine))
        {
            // CSV format: "Image Name","PID","Session Name","Session#","Mem Usage"
            // Parse CSV format
            size_t iseFirstQuote = iseLine.find('"');
            size_t iseSecondQuote = iseLine.find('"', iseFirstQuote + 1);
            size_t iseThirdQuote = iseLine.find('"', iseSecondQuote + 1);
            size_t iseFourthQuote = iseLine.find('"', iseThirdQuote + 1);

            if (iseFirstQuote != std::string::npos && iseSecondQuote != std::string::npos &&
                iseThirdQuote != std::string::npos && iseFourthQuote != std::string::npos)
            {
                // Extract PID which is between 3rd and 4th quotes
                isePid = iseLine.substr(iseThirdQuote + 1, iseFourthQuote - iseThirdQuote - 1);
            }
        }

        if (!isePid.empty())
        {
            logger->info("Found ISE Posture PID: " + isePid);

            // Use the PID to terminate the process in Windows
            std::string iseKillCmd = "taskkill /F /PID " + isePid;
            int iseKillResult = system(iseKillCmd.c_str());

            if (iseKillResult == 0)
            {
                logger->info("Successfully terminated ISE Posture process");
            }
            else
            {
                logger->error("Failed to terminate ISE Posture process with PID: " + isePid);
            }
        }
        else
        {
            logger->warning("No ISE Posture PID found");
        }
        logger->info("Searching for ZTA processes...");

        // Command to find ZTA processes in Windows
        std::string ztaCmd1 = "tasklist /FI \"IMAGENAME eq csc_zta_agent.exe\" /FO TABLE";

        int ztaResult1 = system(ztaCmd1.c_str());

        if (ztaResult1 == 0)
        {
            logger->info("ZTA processes found and displayed");
        }
        else
        {
            logger->warning("Command execution returned non-zero status: " + std::to_string(ztaResult1));
        }

        // Create a pipe to capture command output
        std::array<char, 128> ztaBuffer;
        std::string ztaResult;
        std::string ztaCmd = "tasklist /FI \"IMAGENAME eq csc_zta_agent.exe\" /FO CSV";

        FILE *ztaPipe = POPEN(ztaCmd.c_str(), "r");
        if (!ztaPipe)
        {
            logger->error("Failed to execute ZTA process search command");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // Read the command output
        while (fgets(ztaBuffer.data(), ztaBuffer.size(), ztaPipe) != nullptr)
        {
            ztaResult += ztaBuffer.data();
        }
        PCLOSE(ztaPipe);

        // Parse the output to get PID
        std::istringstream ztaStream(ztaResult);
        std::string ztaLine;
        std::string ztaPid;

        // Skip header line
        std::getline(ztaStream, ztaLine);

        if (std::getline(ztaStream, ztaLine))
        {
            // CSV format: "Image Name","PID","Session Name","Session#","Mem Usage"
            // Parse CSV format
            size_t ztaFirstQuote = ztaLine.find('"');
            size_t ztaSecondQuote = ztaLine.find('"', ztaFirstQuote + 1);
            size_t ztaThirdQuote = ztaLine.find('"', ztaSecondQuote + 1);
            size_t ztaFourthQuote = ztaLine.find('"', ztaThirdQuote + 1);

            if (ztaFirstQuote != std::string::npos && ztaSecondQuote != std::string::npos &&
                ztaThirdQuote != std::string::npos && ztaFourthQuote != std::string::npos)
            {
                // Extract PID which is between 3rd and 4th quotes
                ztaPid = ztaLine.substr(ztaThirdQuote + 1, ztaFourthQuote - ztaThirdQuote - 1);
            }
        }

        if (!ztaPid.empty())
        {
            logger->info("Found ZTA PID: " + ztaPid);

            // Use the PID to terminate the process in Windows
            std::string ztaKillCmd = "taskkill /F /PID " + ztaPid;
            int ztaKillResult = system(ztaKillCmd.c_str());

            if (ztaKillResult == 0)
            {
                logger->info("Successfully terminated ZTA process");
            }
            else
            {
                logger->error("Failed to terminate ZTA process with PID: " + ztaPid);
            }
        }
        else
        {
            logger->warning("No ZTA PID found");
        }
    }
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error finding NVM agent processes: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}
/**
 * @brief Collects a DART bundle and saves it as a zip file on the Desktop.
 * @note Executes the DART CLI tool to generate the bundle.
 * @details Logs the success or failure of the collection process.
 */
LogCollectorError::ErrorType LogCollectorWindows::collectDARTLogs()
{
    try
    {
        logger->info("Starting DART bundle collection...");

        // Get user's profile path
        std::string userProfilePath = getUserProfilePath();
        if (userProfilePath.empty())
        {
            logger->error("Could not determine user profile directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
        // Create path for the DART bundle
        std::string dartBundlePath = userProfilePath + "\\Desktop\\DART_Bundle" + ".zip";
        // Path to dartcli.exe
        std::string dartCliPath = WinPaths::DART_CLI;
        std::string cmd = "\"" + dartCliPath + "\" -dst \"" + dartBundlePath + "\"";

        logger->info("Generating DART bundle...");
        logger->info("This may take several minutes depending on the system and log size.");
        logger->info("DART bundle will be saved to: " + dartBundlePath);
        std::string Cmd = "powershell -Command \"Start-Process '" + dartCliPath +
                          "' -ArgumentList '-dst', '" + dartBundlePath +
                          "' -Verb RunAs -Wait\"";
        int result = system(Cmd.c_str());
        if (result == 0)
        {
            logger->info("DART bundle collected successfully");
            logger->info("DART bundle saved to: " + dartBundlePath);
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->error("Failed to collect DART bundle. Error code: " + std::to_string(result));
            logger->error("Make sure you're running with administrator privileges.");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
    }
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error collecting DART bundle: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Retrieves the user profile directory path on Windows.
 * @note Uses the `USERPROFILE` environment variable to determine the path.
 * @return The user profile path as a string, or an empty string if not found.
 */
std::string LogCollectorWindows::getUserProfilePath()
{
    const char *userProfile = getenv("USERPROFILE");
    if (userProfile)
    {
        return std::string(userProfile);
    }
    return "";
}

/**
 * @brief Displays a timer and waits for user to press Ctrl+C to stop collection
 * @note Uses signal handler to catch SIGINT (Ctrl+C)
 * @note Displays elapsed time in MM:SS format with real-time updates
 * @note Sets g_stopCollection flag to true when interrupted
 */
LogCollectorError::ErrorType LogCollectorWindows::collectLogsWithTimer()
{
    try
    {
        // Set up signal handler
        signal(SIGINT, signalHandler);
        g_stopCollection = false;

        // Start time
        auto startTime = std::chrono::steady_clock::now();
        int elapsedSeconds = 0;

        while (!g_stopCollection)
        {
            auto currentTime = std::chrono::steady_clock::now();
            elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime).count();

            // Show elapsed time
            std::cout << "\r\033[K" << "Time elapsed: "
                      << std::setfill('0') << std::setw(2) << elapsedSeconds / 60 << ":"
                      << std::setfill('0') << std::setw(2) << elapsedSeconds % 60
                      << " (Press Ctrl+C to stop)" << std::flush;

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error collecting logs with timer: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}
/**
 * @brief Clears the `logcollector.log` file in the current build directory.
 * @note Ensures the log file is reset before starting a new collection.
 * @details Checks if the file exists and truncates it if necessary.
 */
LogCollectorError::ErrorType LogCollectorWindows::LogCollectorFile()
{
    try
    {
        std::string buildPath = fs::current_path().string();
        std::string logCollectorPath = buildPath + "\\logcollector.log";
        if (fs::exists(logCollectorPath))
        {
            std::ofstream logFile(logCollectorPath, std::ios::trunc);
            if (logFile.is_open())
            {
                logFile.close();
            }
            else
            {
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
        }
        else
        {
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    catch (const std::exception &e)
    {
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Organizes collected logs into a directory and creates a zip archive.
 * @note Moves logs to a dedicated folder and compresses them with a timestamp.
 * @details Cleans up temporary files after archiving.
 */
LogCollectorError::ErrorType LogCollectorWindows::organizeAndArchiveLogs()
{
    try
    {
        logger->info("Organizing and archiving collected logs...");

        const char *userProfile = getenv("USERPROFILE");
        if (!userProfile)
        {
            logger->error("Could not determine user profile directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string desktopPath = std::string(userProfile) + "/Desktop";
        std::string nvmLogsDir = desktopPath + "/nvm_logs";
        std::string buildPath = fs::current_path().string();
        std::string logCollectorPath = buildPath + "/logcollector.log";

        // 1. Create nvm_logs directory
        std::string mkdirCmd = "mkdir \"" + nvmLogsDir + "\" 2>nul";
        logger->info("Creating logs directory: " + nvmLogsDir);
        if (system(mkdirCmd.c_str()) != 0)
        {
            logger->error("Failed to create nvm_logs directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
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
            "swg_umbrella_logs.log",
            "ise_posture_logs.log",
            "zta_logs.log"};

        for (const auto &file : logFiles)
        {
            std::string sourceFile = desktopPath + "\\" + file;
            // Check if file exists before attempting to move
            if (fs::exists(sourceFile))
            {
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
        if (zipResult == 0)
        {
            logger->info("Successfully created archive: secure_client_logs_" + timestamp + ".zip");

            // Optional: Clean up nvm_logs directory after successful archive
            std::string cleanupCmd = "rmdir /S /Q \"" + nvmLogsDir + "\"";
            if (system(cleanupCmd.c_str()) == 0)
            {
                logger->info("Cleaned up temporary logs directory");
            }
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->error("Failed to create zip archive. Error code: " + std::to_string(zipResult));
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
    }
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error organizing and archiving logs: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}
/**
 * @brief Creates necessary debug files for ISE posture logs.
 * @note Creates `debuglogs.json` and `v4debug.json` in their respective paths.
 * @details Logs the success or failure of file creation.
 */
LogCollectorError::ErrorType LogCollectorWindows::createAllFilesISEPosture()
{
    try
    {
        // Get user profile directory
        std::string userProfile = getUserProfilePath();
        if (userProfile.empty())
        {
            logger->error("Could not determine user profile directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // For ISE debuglogs.json
        logger->info("Creating empty debuglogs.json file...");

        std::string isePath = WinPaths::SECURECLIENT_LOCALAPPDATA;

        // Create directory structure if it doesn't exist
        std::string mkdirCmd1 = "mkdir \"" + isePath + "\" 2>nul";
        if (system(mkdirCmd1.c_str()) != 0)
        {
            logger->info("Directory already exists" + isePath);
        }

        std::string jsonPath1 = isePath + "\\debuglogs.json";
        std::ofstream jsonFile1(jsonPath1);

        if (jsonFile1.is_open())
        {
            jsonFile1.close();
            logger->info("Successfully created empty debuglogs.json at: " + jsonPath1);
        }
        else
        {
            logger->error("Failed to create debuglogs.json at: " + jsonPath1);
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // For Secure Firewall Posture v4debug.json in Program Files
        logger->info("Creating empty v4debug.json in secure firewall posture program path...");

        std::string firewallPath1 = WinPaths::SECURECLIENT_ISEFIREWALL;

        // Create directory structure if it doesn't exist
        std::string mkdirCmd2 = "mkdir \"" + firewallPath1 + "\" 2>nul";
        if (system(mkdirCmd2.c_str()) != 0)
        {
            logger->info("Directory already exists" + firewallPath1);
        }

        std::string jsonPath2 = firewallPath1 + "\\v4debug.json";
        std::ofstream jsonFile2(jsonPath2);

        if (jsonFile2.is_open())
        {
            jsonFile2.close();
            logger->info("Successfully created empty v4debug.json at: " + jsonPath2);
        }
        else
        {
            logger->error("Failed to create v4debug.json at: " + jsonPath2);
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // For Secure Firewall Posture v4debug.json in AppData
        logger->info("Creating empty v4debug.json in AppData secure firewall posture path...");

        std::string firewallPath2 = WinPaths::SECURECLIENT_ISEFIREWALL_HOME;

        // Create directory structure if it doesn't exist
        std::string mkdirCmd3 = "mkdir \"" + firewallPath2 + "\" 2>nul";
        if (system(mkdirCmd3.c_str()) != 0)
        {
            logger->info("Directory already exists" + firewallPath2);
        }

        std::string jsonPath3 = firewallPath2 + "\\v4debug.json";
        std::ofstream jsonFile3(jsonPath3);

        if (jsonFile3.is_open())
        {
            jsonFile3.close();
            logger->info("Successfully created empty v4debug.json at: " + jsonPath3);
        }
        else
        {
            logger->error("Failed to create v4debug.json at: " + jsonPath3);
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error creating debug files: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Deletes debug files for ISE posture logs if they exist.
 * @note Removes `debuglogs.json` and `v4debug.json` from their respective paths.
 * @details Logs the success or failure of the deletion process.
 */
LogCollectorError::ErrorType LogCollectorWindows::deleteAllFilesISEPosture()
{
    try
    {
        logger->info("Removing all debug configuration files...");

        // Get user profile directory
        std::string userProfile = getUserProfilePath();
        if (userProfile.empty())
        {
            logger->error("Could not determine user profile directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // For ISE debuglogs.json
        std::string isePath = WinPaths::SECURECLIENT_LOCALAPPDATA;
        std::string iseJsonPath = isePath + "\\debuglogs.json";

        std::string rmCmd1 = "del /F /Q \"" + iseJsonPath + "\" 2>nul";
        logger->info("Executing command: " + rmCmd1);
        if (system(rmCmd1.c_str()) == 0)
        {
            logger->info("Successfully removed debuglogs.json");
        }
        else
        {
            logger->error("Failed to remove debuglogs.json");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // For Secure Firewall Posture v4debug.json in Program Files
        std::string firewallPath = WinPaths::SECURECLIENT_ISEFIREWALL;
        std::string programJsonPath = firewallPath + "\\v4debug.json";

        std::string rmCmd2 = "del /F /Q \"" + programJsonPath + "\" 2>nul";
        logger->info("Executing command: " + rmCmd2);
        if (system(rmCmd2.c_str()) == 0)
        {
            logger->info("Successfully removed program v4debug.json");
        }
        else
        {
            logger->error("Failed to remove program v4debug.json");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // For Secure Firewall Posture v4debug.json in AppData
        std::string firewallPathLocal = WinPaths::SECURECLIENT_ISEFIREWALL_HOME;
        std::string localJsonPath = firewallPathLocal + "\\v4debug.json";

        std::string rmCmd3 = "del /F /Q \"" + localJsonPath + "\" 2>nul";
        logger->info("Executing command: " + rmCmd3);
        if (system(rmCmd3.c_str()) == 0)
        {
            logger->info("Successfully removed local v4debug.json");
        }
        else
        {
            logger->error("Failed to remove local v4debug.json");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error deleting debug files: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}
/**
 * @brief Creates necessary debug files for ZTA logs.
 * @note Creates `logconfig.json` and `flags.json` in the ZTA directory.
 * @details Logs the success or failure of file creation.
 */
LogCollectorError::ErrorType LogCollectorWindows::createAllFilesZTA()
{
    try
    {
        // Get user profile directory
        std::string userProfile = getUserProfilePath();
        if (userProfile.empty())
        {
            logger->error("Could not determine user profile directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // Creating logconfig.json in ZTA path
        logger->info("Creating logconfig.json in ZTA path...");
        std::string ztaPath = WinPaths::SECURECLIENT_ZTA;

        // Create directory structure if it doesn't exist
        std::string mkdirCmd4 = "mkdir \"" + ztaPath + "\" 2>nul";
        if (system(mkdirCmd4.c_str()) != 0)
        {
            logger->info("Directory already exists: " + ztaPath);
        }

        std::string jsonPath4 = ztaPath + "\\logconfig.json";
        std::ofstream jsonFile4(jsonPath4);

        if (jsonFile4.is_open())
        {
            jsonFile4 << "{\n    \"global\": \"DBG_TRACE\"\n}" << std::endl;
            jsonFile4.close();
            logger->info("Successfully created logconfig.json at: " + jsonPath4);
        }
        else
        {
            logger->error("Failed to create logconfig.json at: " + jsonPath4);
            logger->error("Note: You may need administrator privileges to write to this location");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // Creating flags.json in ZTA path
        logger->info("Creating flags.json in ZTA path...");
        std::string jsonPath5 = ztaPath + "\\flags.json";
        std::ofstream jsonFile5(jsonPath5);

        if (jsonFile5.is_open())
        {
            jsonFile5 << "{\n"
                      << "    \"datapath\": {\n"
                      << "        \"quic\": {\n"
                      << "            \"enabled\": false,\n"
                      << "            \"unreliable_datagram\": true,\n"
                      << "            \"fallback_http2\": true,\n"
                      << "            \"max_datagram_size\": 1350\n"
                      << "        }\n"
                      << "    },\n"
                      << "    \"flow_log\": {\"max_count\": 35000},\n"
                      << "    \"enrollment\": {\n"
                      << "        \"acme\": {\n"
                      << "            \"cert_renewal_interval_seconds\": 86400\n"
                      << "        }\n"
                      << "    }\n"
                      << "}" << std::endl;
            jsonFile5.close();
            logger->info("Successfully created flags.json at: " + jsonPath5);
        }
        else
        {
            logger->error("Failed to create flags.json at: " + jsonPath5);
            logger->error("Note: You may need administrator privileges to write to this location");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error creating debug files: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Deletes debug files for ZTA logs if they exist.
 * @note Removes `logconfig.json` and `flags.json` from the ZTA directory.
 * @details Logs the success or failure of the deletion process.
 */
LogCollectorError::ErrorType LogCollectorWindows::deleteAllFilesZTA()
{
    try
    {
        // Get user profile directory
        std::string userProfile = getUserProfilePath();
        if (userProfile.empty())
        {
            logger->error("Could not determine user profile directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // For ZTA logconfig.json
        std::string ztaPath = WinPaths::SECURECLIENT_ZTA;
        std::string logconfigPath = ztaPath + "\\logconfig.json";

        std::string rmCmd4 = "del /F /Q \"" + logconfigPath + "\" 2>nul";
        logger->info("Executing command: " + rmCmd4);
        if (system(rmCmd4.c_str()) == 0)
        {
            logger->info("Successfully removed logconfig.json");
        }
        else
        {
            logger->error("Failed to remove logconfig.json");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // For ZTA flags.json
        std::string flagsPath = ztaPath + "\\flags.json";
        std::string rmCmd5 = "del /F /Q \"" + flagsPath + "\" 2>nul";
        logger->info("Executing command: " + rmCmd5);
        if (system(rmCmd5.c_str()) == 0)
        {
            logger->info("Successfully removed flags.json");
        }
        else
        {
            logger->error("Failed to remove flags.json");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error deleting debug files: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}
/**
 * @brief Starts the collection of KDF logs on Windows.
 * @note Uses DebugView to capture logs and saves them to the Desktop.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorWindows::collectKdfLogs()
{
    std::string userProfilePath = getUserProfilePath();
    if (userProfilePath.empty())
    {
        logger->error("Could not determine user profile directory");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    std::string kdfLogPath = userProfilePath + "\\Desktop\\kdf_logs.log";
    std::string debugViewPath = userProfilePath + "\\Downloads\\Debugview\\Dbgview.exe";
    std::string cmd = "start \"KDF Log Collection\" \"" + debugViewPath + "\" /k /v /om /l \"" + kdfLogPath + "\"";
    logger->info("[*] Starting KDF Logs collection...");
    int result = system(cmd.c_str());
    if (result == 0)
    {
        logger->info("[+] Successfully started KDF Logs collection");
        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    else
    {
        logger->error("[!] Failed to start KDF Logs collection");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Starts the collection of NVM system logs on Windows.
 * @note Uses `wevtutil` to query logs and saves them to the Desktop.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorWindows::collectNvmLogs()
{
    std::string userProfilePath = getUserProfilePath();
    if (userProfilePath.empty())
    {
        logger->error("Could not determine user profile directory");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    std::string nvmLogPath = userProfilePath + "\\Desktop\\nvm_system_logs.log";
    std::string cmd = "wevtutil qe \"Cisco Secure Client - Network Visibility Module\" /f:text > \"" + nvmLogPath + "\"";
    logger->info("[*] Starting NVM System Logs collection...");
    int result = system(cmd.c_str());
    if (result == 0)
    {
        logger->info("[+] Successfully started NVM System Logs collection");
        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    else
    {
        logger->error("[!] Failed to start NVM System Logs collection");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Starts a packet capture on Windows.
 * @note Uses `pktmon` to capture packets and saves them as an `.etl` file on the Desktop.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorWindows::collectPacketCapture()
{
    std::string userProfilePath = getUserProfilePath();
    if (userProfilePath.empty())
    {
        logger->error("Could not determine user profile directory");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    std::string etlPath = userProfilePath + "\\Desktop\\PacketCapture.etl";
    std::string cmd = "pktmon start --capture --file-name \"" + etlPath + "\"";
    logger->info("[*] Starting Packet Capture collection...");
    int result = system(cmd.c_str());
    if (result == 0)
    {
        logger->info("[+] Successfully started Packet Capture collection");
        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    else
    {
        logger->error("[!] Failed to start Packet Capture collection");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Starts the collection of Umbrella logs on Windows.
 * @note Uses `wevtutil` to query logs and saves them to the Desktop.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorWindows::collectUmbrellaLogs()
{
    std::string userProfilePath = getUserProfilePath();
    if (userProfilePath.empty())
    {
        logger->error("Could not determine user profile directory");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    std::string umbrellaLogPath = userProfilePath + "\\Desktop\\swg_umbrella_logs.log";
    std::string cmd = "wevtutil qe \"Cisco Secure Client - Umbrella\" /f:text > \"" + umbrellaLogPath + "\"";
    logger->info("[*] Starting Umbrella/SWG Logs collection...");
    int result = system(cmd.c_str());
    if (result == 0)
    {
        logger->info("[+] Successfully started Umbrella/SWG Logs collection");
        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    else
    {
        logger->error("[!] Failed to start Umbrella/SWG Logs collection");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Starts the collection of ISE Posture logs on Windows.
 * @note Uses `wevtutil` to query logs and saves them to the Desktop.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorWindows::collectIsePostureLogs()
{
    std::string userProfilePath = getUserProfilePath();
    if (userProfilePath.empty())
    {
        logger->error("Could not determine user profile directory");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    std::string isePostureLogPath = userProfilePath + "\\Desktop\\ise_posture_logs.log";
    std::string cmd = "wevtutil qe \"Cisco Secure Client - ISE Posture\" /f:text > \"" + isePostureLogPath + "\"";
    logger->info("[*] Starting ISE Posture Logs collection...");
    int result = system(cmd.c_str());
    if (result == 0)
    {
        logger->info("[+] Successfully started ISE Posture Logs collection");
        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    else
    {
        logger->error("[!] Failed to start ISE Posture Logs collection");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Starts the collection of ZTA logs on Windows.
 * @note Uses `wevtutil` to query logs and saves them to the Desktop.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorWindows::collectZtaLogs()
{
    std::string userProfilePath = getUserProfilePath();
    if (userProfilePath.empty())
    {
        logger->error("Could not determine user profile directory");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    std::string ztaLogPath = userProfilePath + "\\Desktop\\zta_logs.log";
    std::string cmd = "wevtutil qe \"Cisco Secure Client - Zero Trust Access\" /f:text > \"" + ztaLogPath + "\"";
    logger->info("[*] Starting ZTA Logs collection...");
    int result = system(cmd.c_str());
    if (result == 0)
    {
        logger->info("[+] Successfully started ZTA Logs collection");
        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    else
    {
        logger->error("[!] Failed to start ZTA Logs collection");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Stops the collection of KDF logs on Windows.
 * @note Uses `taskkill` to terminate the DebugView process.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorWindows::stopKdfLogs()
{
    std::string cmd = "taskkill /F /IM Dbgview.exe > nul 2>&1";
    logger->info("Stopping KDF Logs collection...");
    int result = system(cmd.c_str());
    if (result == 0)
    {
        logger->info("[+] Successfully stopped KDF Logs collection");
        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    else
    {
        logger->warning("[!] Failed to stop KDF Logs collection");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Stops the collection of NVM system logs on Windows.
 * @note Placeholder function for stopping NVM log collection.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorWindows::stopNvmLogs()
{
    logger->info("Stopping NVM System Logs collection...");
    // Placeholder for stopping NVM logs if needed
    logger->info("[+] Successfully stopped NVM System Logs collection");
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Stops the packet capture on Windows.
 * @note Uses `pktmon` to stop the capture and save the file.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorWindows::stopPacketCapture()
{
    std::string cmd = "pktmon stop";
    logger->info("Stopping Packet Capture collection...");
    int result = system(cmd.c_str());
    if (result == 0)
    {
        logger->info("[+] Successfully stopped Packet Capture collection");
        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    else
    {
        logger->warning("[!] Failed to stop Packet Capture collection");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Stops the collection of Umbrella logs on Windows.
 * @note Placeholder function for stopping Umbrella log collection.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorWindows::stopUmbrellaLogs()
{
    logger->info("Stopping Umbrella/SWG Logs collection...");
    // Placeholder for stopping Umbrella logs if needed
    logger->info("[+] Successfully stopped Umbrella/SWG Logs collection");
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Stops the collection of ISE Posture logs on Windows.
 * @note Placeholder function for stopping ISE Posture log collection.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorWindows::stopIsePostureLogs()
{
    logger->info("Stopping ISE Posture Logs collection...");
    // Placeholder for stopping ISE Posture logs if needed
    logger->info("[+] Successfully stopped ISE Posture Logs collection");
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Stops the collection of ZTA logs on Windows.
 * @note Placeholder function for stopping ZTA log collection.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorWindows::stopZtaLogs()
{
    logger->info("Stopping ZTA Logs collection...");
    // Placeholder for stopping ZTA logs if needed
    logger->info("[+] Successfully stopped ZTA Logs collection");
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}