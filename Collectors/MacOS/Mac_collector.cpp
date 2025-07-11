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
#include "Mac_collector.h"
#include "../../Utils/Logger.h"
#include "../../Utils/Error.h"
#include "../../Utils/Common.h"

using namespace std;

/**
 * @brief Constructs a MacOS NVM log collector with multiple module support
 * @param config Configuration settings map for collector initialization
 * @param logger Shared pointer to logger instance for output messages
 * @param enable_debug_logs Optional flag to enable detailed debug logging (default: false)
 * @param debug_level Optional debug verbosity level (default: 0)
 * @note Initializes all collector modules (NVM, SWG, ISE, ZTA) and utilities
 */
LogCollectorMac::LogCollectorMac(const std::map<std::string, std::string> &config,
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

    logger->info("CollectorMac initialized with NVM and SWG support.");
}

/**
 * @brief Destroys the MacOS NVM log collector instance
 * @note Logs destruction message before cleanup
 */
LogCollectorMac::~LogCollectorMac()
{
    logger->info("LogCollectorMac destroyed");
}

/**
 * @brief Gets NVM agent version by executing agent with -v flag
 * @note Requires sudo privileges. Sets nvm_version to "unknown" on failure
 */
LogCollectorError::ErrorType LogCollectorMac::get_nvm_version()
{
    logger->info("Getting NVM agent version...");
    try
    {
        // Create a pipe to capture command output
        std::array<char, 128> buffer;
        std::string result;

        // Command to get NVM agent version
        std::string cmd = "sudo " + MacPaths::NVM_AGENT + " -v";

        // Execute command and capture output
        FILE *pipe = popen(cmd.c_str(), "r");
        if (!pipe)
        {
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // Read output
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
        {
            result += buffer.data();
        }

        // Close pipe
        int status = pclose(pipe);
        if (status != 0)
        {
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // Parse version from output - improved pattern matching
        std::regex versionPattern("Version\\s*:\\s*(\\d+\\.\\d+\\.\\d+(?:-\\w+)?)");
        std::smatch matches;
        if (std::regex_search(result, matches, versionPattern) && matches.size() > 1)
        {
            nvm_version = matches[1].str();
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->info("NVM agent version found: " + result);
            nvm_version = "unknown";
            return LogCollectorError::ErrorType::FILE_NOT_FOUND;
        }
    }
    catch (const LogCollectorError &e)
    {
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Creates debug configuration file for NVM agent
 * @note Uses MacPaths::DEBUG_CONF path
 */
LogCollectorError::ErrorType LogCollectorMac::writeDebugConf()
{
    utils.writeDebugConfSystem(MacPaths::DEBUG_CONF);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Removes NVM agent debug configuration file
 * @note Uses MacPaths::DEBUG_CONF path
 */
LogCollectorError::ErrorType LogCollectorMac::removeDebugConf()
{
    utils.removeDebugConfSystem(MacPaths::DEBUG_CONF);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Adds troubleshooting tag to NVM service profile
 * @note Uses MacPaths::SERVICE_PROFILE path
 */
LogCollectorError::ErrorType LogCollectorMac::addTroubleshootTag()
{
    utils.addTroubleshootTagSystem(MacPaths::SERVICE_PROFILE);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Sets KDF debug flag using user input hexadecimal value
 * @note Prompts for hex input (e.g., 0x20)
 */
LogCollectorError::ErrorType LogCollectorMac::setKDFDebugFlag()
{
    string hexInput;
    logger->info("\nEnter debug flag (hexadecimal, e.g., 0x20): ");
    cin >> hexInput;
    utils.setKDFDebugFlagSystem(MacPaths::ACSOCKTOOL, hexInput);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Clears KDF debug flag settings
 * @note Uses MacPaths::ACSOCKTOOL path
 */
LogCollectorError::ErrorType LogCollectorMac::clearKDFDebugFlag()
{
    utils.clearKDFDebugFlagSystem(MacPaths::ACSOCKTOOL);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Creates SWG configuration override file
 * @note Uses MacPaths::UMBRELLA_PATH location
 */
LogCollectorError::ErrorType LogCollectorMac::createSWGConfigOverride()
{
    utils.createSWGConfigOverrideSystem(MacPaths::UMBRELLA_PATH);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Removes SWG configuration override file
 * @note Uses MacPaths::UMBRELLA_PATH location
 */
LogCollectorError::ErrorType LogCollectorMac::deleteSWGConfigOverride()
{
    utils.deleteSWGConfigOverrideSystem(MacPaths::UMBRELLA_PATH);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Finds, stops and restarts all agent processes (NVM, Umbrella, ISE, ZTA)
 * @details Searches for running processes, captures their PIDs, terminates them,
 *          then restarts them using appropriate paths from MacPaths namespace
 * @note Requires sudo privileges for process management operations
 * @note Uses ps, kill, and process restart commands
 * @note Uses `ps -ef` to list processes and `grep` to filter for specific agents
 * @note Terminates processes using `kill -9` if their PIDs are found
 */
LogCollectorError::ErrorType LogCollectorMac::findAllAgentProcesses()
{
    try
    {
        // NVM Agent Section
        logger->info("Searching for NVM agent processes...");
        std::string nvmCmd1 = "ps -ef | grep acnvmagent";
        int nvmResult1 = system(nvmCmd1.c_str());

        if (nvmResult1 == 0)
        {
            logger->info("NVM agent processes found and displayed");
        }
        else
        {
            logger->warning("Command execution returned non-zero status: " + std::to_string(nvmResult1));
        }

        std::array<char, 128> nvmBuffer;
        std::string nvmResult;
        std::string nvmCmd = "ps -ef | grep acnvmagent";

        FILE *nvmPipe = popen(nvmCmd.c_str(), "r");
        if (!nvmPipe)
        {
            logger->error("Failed to execute process search command");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        while (fgets(nvmBuffer.data(), nvmBuffer.size(), nvmPipe) != nullptr)
        {
            nvmResult += nvmBuffer.data();
        }
        pclose(nvmPipe);

        std::istringstream nvmStream(nvmResult);
        std::string nvmLine;
        std::string nvmPid;

        if (std::getline(nvmStream, nvmLine))
        {
            std::istringstream nvmIss(nvmLine);
            std::string nvmColumn;
            int nvmColumnCount = 0;

            while (nvmIss >> nvmColumn && nvmColumnCount < 2)
            {
                if (nvmColumnCount == 1)
                {
                    nvmPid = nvmColumn;
                    break;
                }
                nvmColumnCount++;
            }
        }

        if (!nvmPid.empty())
        {
            logger->info("Found NVM agent PID: " + nvmPid);
            std::string nvmKillCmd = "sudo kill -9 " + nvmPid;
            int nvmKillResult = system(nvmKillCmd.c_str());

            if (nvmKillResult == 0)
            {
                logger->info("Successfully terminated NVM agent process");
            }
            else
            {
                logger->error("Failed to terminate process with PID: " + nvmPid);
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
            std::string nvmStartCmd = "sudo " + MacPaths::NVM_AGENT_BIN + " &";
            int nvmStartResult = system(nvmStartCmd.c_str());
            if (nvmStartResult == 0)
            {
                logger->info("[+] Successfully started NVM agent");
            }
            else
            {
                logger->error("[!] Failed to start NVM agent");
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
        }
        else
        {
            logger->warning("No NVM agent PID found");
        }

        // Umbrella Agent Section
        logger->info("Searching for Umbrella agent processes...");
        std::string umbrellaCmd1 = "ps -ef | grep acumbrellaagent";
        int umbrellaResult1 = system(umbrellaCmd1.c_str());

        if (umbrellaResult1 == 0)
        {
            logger->info("Umbrella agent processes found and displayed");
        }
        else
        {
            logger->warning("Command execution returned non-zero status: " + std::to_string(umbrellaResult1));
        }

        std::array<char, 128> umbrellaBuffer;
        std::string umbrellaResult;
        std::string umbrellaCmd = "ps -ef | grep acumbrellaagent";

        FILE *umbrellaPipe = popen(umbrellaCmd.c_str(), "r");
        if (!umbrellaPipe)
        {
            logger->error("Failed to execute Umbrella process search command");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        while (fgets(umbrellaBuffer.data(), umbrellaBuffer.size(), umbrellaPipe) != nullptr)
        {
            umbrellaResult += umbrellaBuffer.data();
        }
        pclose(umbrellaPipe);

        std::istringstream umbrellaStream(umbrellaResult);
        std::string umbrellaLine;
        std::string umbrellaPid;

        if (std::getline(umbrellaStream, umbrellaLine))
        {
            std::istringstream umbrellaIss(umbrellaLine);
            std::string umbrellaColumn;
            int umbrellaColumnCount = 0;

            while (umbrellaIss >> umbrellaColumn && umbrellaColumnCount < 2)
            {
                if (umbrellaColumnCount == 1)
                {
                    umbrellaPid = umbrellaColumn;
                    break;
                }
                umbrellaColumnCount++;
            }
        }

        if (!umbrellaPid.empty())
        {
            logger->info("Found Umbrella agent PID: " + umbrellaPid);
            std::string umbrellaKillCmd = "sudo kill -9 " + umbrellaPid;
            int umbrellaKillResult = system(umbrellaKillCmd.c_str());

            if (umbrellaKillResult == 0)
            {
                logger->info("Successfully terminated Umbrella agent process");
            }
            else
            {
                logger->error("Failed to terminate Umbrella process with PID: " + umbrellaPid);
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }

            // For Umbrella Agent
            std::string umbrellaStartCmd = "sudo " + MacPaths::UMBRELLA_AGENT + " &";
            int umbrellaStartResult = system(umbrellaStartCmd.c_str());
            if (umbrellaStartResult == 0)
            {
                logger->info("[+] Successfully started Umbrella agent");
            }
            else
            {
                logger->error("[!] Failed to start Umbrella agent");
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
        }
        else
        {
            logger->warning("No Umbrella agent PID found");
        }

        // ISE Agent Section
        logger->info("Searching for ISE agent processes...");
        std::string iseCmd1 = "ps -ef | grep csc_iseagentd";
        int iseResult1 = system(iseCmd1.c_str());

        if (iseResult1 == 0)
        {
            logger->info("ISE agent processes found and displayed");
        }
        else
        {
            logger->warning("Command execution returned non-zero status: " + std::to_string(iseResult1));
        }

        std::array<char, 128> iseBuffer;
        std::string iseResult;
        std::string iseCmd = "ps -ef | grep csc_iseagentd";

        FILE *isePipe = popen(iseCmd.c_str(), "r");
        if (!isePipe)
        {
            logger->error("Failed to execute ISE process search command");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        while (fgets(iseBuffer.data(), iseBuffer.size(), isePipe) != nullptr)
        {
            iseResult += iseBuffer.data();
        }
        pclose(isePipe);

        std::istringstream iseStream(iseResult);
        std::string iseLine;
        std::string isePid;

        if (std::getline(iseStream, iseLine))
        {
            std::istringstream iseIss(iseLine);
            std::string iseColumn;
            int iseColumnCount = 0;

            while (iseIss >> iseColumn && iseColumnCount < 2)
            {
                if (iseColumnCount == 1)
                {
                    isePid = iseColumn;
                    break;
                }
                iseColumnCount++;
            }
        }

        if (!isePid.empty())
        {
            logger->info("Found ISE agent PID: " + isePid);
            std::string iseKillCmd = "sudo kill -9 " + isePid;
            int iseKillResult = system(iseKillCmd.c_str());

            if (iseKillResult == 0)
            {
                logger->info("Successfully terminated ISE agent process");
            }
            else
            {
                logger->error("Failed to terminate ISE process with PID: " + isePid);
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
            // For ISE Agent
            std::string iseStartCmd = "sudo " + MacPaths::ISE_AGENT_BIN + " &";
            int iseStartResult = system(iseStartCmd.c_str());

            if (iseStartResult == 0)
            {
                logger->info("[+] Successfully started ISE agent");
            }
            else
            {
                logger->error("[!] Failed to start ISE agent");
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
        }
        else
        {
            logger->warning("No ISE agent PID found");
        }

        // ZTA Agent Section
        logger->info("Searching for ZTA agent processes...");
        std::string ztaCmd1 = "ps -ef | grep csc_zta_agent";
        int ztaResult1 = system(ztaCmd1.c_str());

        if (ztaResult1 == 0)
        {
            logger->info("ZTA agent processes found and displayed");
        }
        else
        {
            logger->warning("Command execution returned non-zero status: " + std::to_string(ztaResult1));
        }

        std::array<char, 128> ztaBuffer;
        std::string ztaResult;
        std::string ztaCmd = "ps -ef | grep csc_zta_agent";

        FILE *ztaPipe = popen(ztaCmd.c_str(), "r");
        if (!ztaPipe)
        {
            logger->error("Failed to execute ZTA process search command");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        while (fgets(ztaBuffer.data(), ztaBuffer.size(), ztaPipe) != nullptr)
        {
            ztaResult += ztaBuffer.data();
        }
        pclose(ztaPipe);

        std::istringstream ztaStream(ztaResult);
        std::string ztaLine;
        std::string ztaPid;

        if (std::getline(ztaStream, ztaLine))
        {
            std::istringstream ztaIss(ztaLine);
            std::string ztaColumn;
            int ztaColumnCount = 0;

            while (ztaIss >> ztaColumn && ztaColumnCount < 2)
            {
                if (ztaColumnCount == 1)
                {
                    ztaPid = ztaColumn;
                    break;
                }
                ztaColumnCount++;
            }
        }

        if (!ztaPid.empty())
        {
            logger->info("Found ZTA agent PID: " + ztaPid);
            std::string ztaKillCmd = "sudo kill -9 " + ztaPid;
            int ztaKillResult = system(ztaKillCmd.c_str());

            if (ztaKillResult == 0)
            {
                logger->info("Successfully terminated ZTA agent process");
            }
            else
            {
                logger->error("Failed to terminate ZTA process with PID: " + ztaPid);
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
            // For ZTA Agent
            std::string ztaStartCmd = "sudo " + MacPaths::ZTA_AGENT_BIN + " &";
            int ztaStartResult = system(ztaStartCmd.c_str());

            if (ztaStartResult == 0)
            {
                logger->info("[+] Successfully started ZTA agent");
            }
            else
            {
                logger->error("[!] Failed to start ZTA agent");
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
        }
        else
        {
            logger->warning("No ZTA agent PID found");
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
        logger->error("Error finding NVM agent processes: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}
/**
 * @brief Creates backup of NVM_ServiceProfile.xml in NVM path
 * @note Uses MacPaths::SERVICE_PROFILE and requires sudo
 */
LogCollectorError::ErrorType LogCollectorMac::backupServiceProfile()
{
    try
    {
        logger->info("Creating backup of NVM_ServiceProfile.xml...");

        std::string cmd = "sudo cp " + MacPaths::SERVICE_PROFILE + " " +
                          MacPaths::NVM_PATH + "NVM_ServiceProfile.xml.bak";

        logger->debug("Executing command: " + cmd);
        int result = system(cmd.c_str());

        if (result == 0)
        {
            logger->info("Backup created successfully as NVM_ServiceProfile.xml.bak");
            return LogCollectorError::ErrorType::FILE_NOT_FOUND;
        }
        else
        {
            logger->error("Failed to create backup, error code: " + std::to_string(result));
            logger->error("Make sure you're running with sudo privileges.");
            return LogCollectorError::ErrorType::PERMISSION_DENIED;
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
        logger->error("Error creating backup: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Restores NVM_ServiceProfile.xml from backup
 * @note Uses MacPaths::NVM_PATH and MacPaths::SERVICE_PROFILE
 *       Removes backup after successful restoration
 */
LogCollectorError::ErrorType LogCollectorMac::restoreServiceProfile()
{
    try
    {
        logger->info("Restoring NVM_ServiceProfile.xml from backup...");

        // Use MacPaths constants for correct path handling
        std::string cmd = "sudo cp " + MacPaths::NVM_PATH + "NVM_ServiceProfile.xml.bak " +
                          MacPaths::SERVICE_PROFILE;

        logger->debug("Executing command: " + cmd);
        int result = system(cmd.c_str());

        if (result == 0)
        {
            logger->info("NVM_ServiceProfile.xml restored successfully from backup");
        }
        else
        {
            logger->error("Failed to restore from backup, error code: " + std::to_string(result));
            logger->error("Make sure you're running with sudo privileges.");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // Remove the backup file after successful restoration
        std::string cmd1 = "sudo rm " + MacPaths::NVM_PATH + "NVM_ServiceProfile.xml.bak";

        logger->debug("Executing command: " + cmd1);
        int result1 = system(cmd1.c_str());

        if (result1 == 0)
        {
            logger->info("Successfully removed backup file");
        }
        else
        {
            logger->error("Failed to remove backup file. Error code: " + std::to_string(result1));
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
        logger->error("Error restoring service profile: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}
/**
 * @brief Collects KDF-specific logs on macOS
 * @note Saves logs to Desktop/kdf_logs.log
 * @note Uses log stream to capture kernel extension logs
 */
LogCollectorError::ErrorType LogCollectorMac::collectKdfLogs()
{
    try
    {
        logger->info("Starting KDF log collection...");

        const char *homeDir = getenv("HOME");
        if (!homeDir)
        {
            logger->error("Could not determine home directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string kdfLogsPath = std::string(homeDir) + "/Desktop/kdf_logs.log";

        std::string cmd = "sudo log stream --predicate 'process == \"com.cisco.anyconnect.macos.acsockext\"' "
                          "--style syslog > " +
                          kdfLogsPath + " &";

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
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error collecting KDF logs: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}
/**
 * @brief Stops KDF log collection
 * @note Terminates log stream process for KDF
 */
LogCollectorError::ErrorType LogCollectorMac::stopKdfLogs()
{
    try
    {
        logger->info("Stopping KDF log collection...");

        std::string cmd = "sudo pkill -f 'log stream.*com.cisco.anyconnect.macos.acsockext' || true";
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
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error stopping KDF logs: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Collects NVM-specific logs on macOS
 * @note Saves logs to Desktop/nvm_system_logs.log
 * @note Uses log stream to capture NVM agent logs
 */
LogCollectorError::ErrorType LogCollectorMac::collectNvmLogs()
{
    try
    {
        logger->info("Starting NVM log collection...");

        const char *homeDir = getenv("HOME");
        if (!homeDir)
        {
            logger->error("Could not determine home directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string nvmLogsPath = std::string(homeDir) + "/Desktop/nvm_system_logs.log";

        std::string cmd = "sudo log stream --predicate 'process == \"acnvmagent\"' --style syslog > " +
                          nvmLogsPath + " &";

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
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error collecting NVM logs: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}
/**
 * @brief Stops NVM log collection
 * @note Terminates log stream process for NVM
 */
LogCollectorError::ErrorType LogCollectorMac::stopNvmLogs()
{
    try
    {
        logger->info("Stopping NVM log collection...");

        std::string cmd = "sudo pkill -f 'log stream.*acnvmagent' || true";
        int result = system(cmd.c_str());

        if (result == 0)
        {
            logger->info("[+] Successfully stopped NVM Logs collection");
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->warning("[!] Failed to stop NVM Logs collection");
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
        logger->error("Error stopping NVM logs: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}
/**
 * @brief Collects packet capture on macOS
 * @note Saves capture to Desktop/PacketCapture.pcap
 * @note Uses tcpdump for packet capture
 */
LogCollectorError::ErrorType LogCollectorMac::collectPacketCapture()
{
    try
    {
        logger->info("Starting packet capture...");

        const char *homeDir = getenv("HOME");
        if (!homeDir)
        {
            logger->error("Could not determine home directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string packetCapturePath = std::string(homeDir) + "/Desktop/PacketCapture.pcap";

        std::string cmd = "sudo tcpdump -w " + packetCapturePath + " &";

        logger->info("[*] Starting Packet Capture...");
        int result = system(cmd.c_str());

        if (result == 0)
        {
            logger->info("[+] Successfully started Packet Capture");
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->error("[!] Failed to start Packet Capture");
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
        logger->error("Error collecting packet capture: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Stops packet capture
 * @note Terminates tcpdump process
 */
LogCollectorError::ErrorType LogCollectorMac::stopPacketCapture()
{
    try
    {
        logger->info("Stopping packet capture...");

        std::string cmd = "sudo killall tcpdump || true";
        int result = system(cmd.c_str());

        if (result == 0)
        {
            logger->info("[+] Successfully stopped Packet Capture");
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->warning("[!] Failed to stop Packet Capture");
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
        logger->error("Error stopping packet capture: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Collects Umbrella/SWG logs on macOS
 * @note Saves logs to Desktop/swg_umbrella_logs.log
 * @note Uses log stream to capture Umbrella agent logs
 */
LogCollectorError::ErrorType LogCollectorMac::collectUmbrellaLogs()
{
    try
    {
        logger->info("Starting Umbrella/SWG log collection...");

        const char *homeDir = getenv("HOME");
        if (!homeDir)
        {
            logger->error("Could not determine home directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string umbrellaLogsPath = std::string(homeDir) + "/Desktop/swg_umbrella_logs.log";

        std::string cmd = "sudo log stream --predicate 'process == \"acumbrellaagent\"' --style syslog > " +
                          umbrellaLogsPath + " &";

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
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error collecting Umbrella/SWG logs: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Stops Umbrella/SWG log collection
 * @note Terminates log stream process for Umbrella
 */
LogCollectorError::ErrorType LogCollectorMac::stopUmbrellaLogs()
{
    try
    {
        logger->info("Stopping Umbrella/SWG log collection...");

        std::string cmd = "sudo pkill -f 'log stream.*acumbrellaagent' || true";
        int result = system(cmd.c_str());

        if (result == 0)
        {
            logger->info("[+] Successfully stopped Umbrella Logs collection");
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->warning("[!] Failed to stop Umbrella Logs collection");
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
        logger->error("Error stopping Umbrella/SWG logs: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Collects ISE Posture logs on macOS
 * @note Saves logs to Desktop/ise_posture_logs.log
 * @note Uses log stream to capture ISE agent logs
 */
LogCollectorError::ErrorType LogCollectorMac::collectIsePostureLogs()
{
    try
    {
        logger->info("Starting ISE Posture log collection...");

        const char *homeDir = getenv("HOME");
        if (!homeDir)
        {
            logger->error("Could not determine home directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string isePostureLogsPath = std::string(homeDir) + "/Desktop/ise_posture_logs.log";

        std::string cmd = "sudo log stream --predicate 'process == \"csc_iseagentd\"' --style syslog > " +
                          isePostureLogsPath + " &";

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
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error collecting ISE Posture logs: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Stops ISE Posture log collection
 * @note Terminates log stream process for ISE
 */
LogCollectorError::ErrorType LogCollectorMac::stopIsePostureLogs()
{
    try
    {
        logger->info("Stopping ISE Posture log collection...");

        std::string cmd = "sudo pkill -f 'log stream.*csc_iseagentd' || true";
        int result = system(cmd.c_str());

        if (result == 0)
        {
            logger->info("[+] Successfully stopped ISE Posture Logs collection");
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->warning("[!] Failed to stop ISE Posture Logs collection");
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
        logger->error("Error stopping ISE Posture logs: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Collects ZTA logs on macOS
 * @note Saves logs to Desktop/zta_logs.log
 * @note Uses log stream to capture ZTA agent logs
 */
LogCollectorError::ErrorType LogCollectorMac::collectZtaLogs()
{
    try
    {
        logger->info("Starting ZTA log collection...");

        const char *homeDir = getenv("HOME");
        if (!homeDir)
        {
            logger->error("Could not determine home directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string ztaLogsPath = std::string(homeDir) + "/Desktop/zta_logs.log";

        std::string cmd = "sudo log stream --predicate 'process == \"csc_zta_agent\"' --style syslog > " +
                          ztaLogsPath + " &";

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
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("Error collecting ZTA logs: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Stops ZTA log collection
 * @note Terminates log stream process for ZTA
 */
LogCollectorError::ErrorType LogCollectorMac::stopZtaLogs()
{
    try
    {
        logger->info("Stopping ZTA log collection...");

        std::string cmd = "sudo pkill -f 'log stream.*csc_zta_agent' || true";
        int result = system(cmd.c_str());

        if (result == 0)
        {
            logger->info("[+] Successfully stopped ZTA Logs collection");
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->warning("[!] Failed to stop ZTA Logs collection");
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
        logger->error("Error stopping ZTA logs: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Displays a timer and waits for user to press Ctrl+C to stop collection
 * @note Uses signal handler to catch SIGINT (Ctrl+C)
 * @note Displays elapsed time in MM:SS format with real-time updates
 * @note Sets g_stopCollection flag to true when interrupted
 */
LogCollectorError::ErrorType LogCollectorMac::collectLogsWithTimer()
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
    }
    catch (const LogCollectorError &e)
    {
        logger->error("Error: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("Details: " + std::string(e.what()));
    }
    catch (const std::exception &e)
    {
        logger->error("Error collecting logs with timer: " + std::string(e.what()));
    }
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}
/**
 * @brief Collects DART logs using the DART CLI tool
 * @note Saves the DART bundle to the user's Desktop
 * @note Requires sudo privileges for DART CLI execution
 */
LogCollectorError::ErrorType LogCollectorMac::collectDARTLogs()
{
    try
    {
        logger->info("Starting DART log collection...");

        // Get user's desktop path
        const char *homeDir = getenv("HOME");
        if (!homeDir)
        {
            logger->error("Could not determine home directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string desktopPath = std::string(homeDir) + "/Desktop/DART_Bundle.zip";

        // Construct the DART CLI command with proper escaping
        std::string cmd = "sudo " + MacPaths::DART_CLI + " -dst " + desktopPath + " -syslogs";

        logger->info("Dart log are Collecting...");
        int result = system(cmd.c_str());
        logger->info("DART bundle saved to: " + desktopPath);
        if (result == 0)
        {
            logger->info("DART logs collected successfully");
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->error("Failed to collect DART logs. Error code: " + std::to_string(result));
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
        logger->error("Error collecting logs: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Clears the log collector file by truncating it
 * @note Uses fs::current_path() to determine the build path
 *       and checks if logcollector.log exists before truncating
 */
LogCollectorError::ErrorType LogCollectorMac::LogCollectorFile()
{
    try
    {
        std::string buildPath = fs::current_path().string();
        std::string logCollectorPath = buildPath + "/logcollector.log";
        if (fs::exists(logCollectorPath))
        {
            std::ifstream logFile(logCollectorPath, std::ios::trunc);
            if (logFile.is_open())
            {
                logFile.close();
                logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
                return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
            }
            else
            {
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
        }
        else
        {
            return LogCollectorError::ErrorType::FILE_NOT_FOUND;
        }
    }
    catch (const std::exception &e)
    {
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}
/**
 * @brief Organizes collected logs, creates a zip archive, and cleans up
 * @note Moves log files to a dedicated directory on the Desktop
 *       Creates a timestamped zip archive of the logs
 *       Cleans up temporary directories and files after archiving
 */
LogCollectorError::ErrorType LogCollectorMac::organizeAndArchiveLogs()
{
    try
    {
        logger->info("Organizing and archiving collected logs...");

        const char *homeDir = getenv("HOME");
        if (!homeDir)
        {
            logger->error("Could not determine home directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string desktopPath = std::string(homeDir) + "/Desktop";
        std::string nvmLogsDir = desktopPath + "/nvm_logs";
        std::string buildPath = fs::current_path().string();
        std::string logCollectorPath = buildPath + "/logcollector.log";

        // 1. Create nvm_logs directory
        std::string mkdirCmd = "mkdir -p " + nvmLogsDir;
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
        std::string copyLogCmd = "cp " + logCollectorPath + " " + nvmLogsDir + "/";
        system(copyLogCmd.c_str());

        // 3. Move all other log files to nvm_logs directory
        std::string moveCmd = "mv " + desktopPath + "/kdf_logs.log " +
                              desktopPath + "/nvm_system_logs.log " +
                              desktopPath + "/PacketCapture.pcap " +
                              desktopPath + "/DART_Bundle.zip " +
                              desktopPath + "/swg_umbrella_logs.log " +
                              desktopPath + "/ise_posture_logs.log " +
                              desktopPath + "/zta_logs.log " +
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
        if (system(zipCmd.c_str()) == 0)
        {
            logger->info("Successfully created archive: secure_client_logs_" + timestamp + ".zip");
            // Optional: Clean up nvm_logs directory after successful archive
            std::string cleanupCmd = "rm -rf " + nvmLogsDir;
            if (system(cleanupCmd.c_str()) == 0)
            {
                logger->info("Cleaned up temporary logs directory");
            }
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->error("Failed to create zip archive");
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
 * @brief Creates all necessary files for ISE Posture logs and secure firewall posture
 * @note Creates debuglogs.json and v4debug.json in specified directories
 *       Uses MacPaths constants for paths
 */
LogCollectorError::ErrorType LogCollectorMac::createAllFilesISEPosture()
{
    try
    {
        // For ISE debuglogs.json
        logger->info("Creating empty debuglogs.json file...");

        const char *homeDir1 = getenv("HOME");
        if (!homeDir1)
        {
            logger->error("Could not determine home directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
        std::string isePath = MacPaths::ISE_POSTURE_LOG;
        if (isePath[0] == '~')
        {
            isePath = std::string(homeDir1) + isePath.substr(1);
        }

        std::string mkdirCmd1 = "mkdir -p " + isePath;
        if (system(mkdirCmd1.c_str()) != 0)
        {
            logger->error("Failed to create directory structure");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string jsonPath1 = isePath + "/debuglogs.json";
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

        // For opt firewall v4debug.json
        logger->info("Creating empty v4debug.json in secure firewall posture path...");

        std::string firewallPath1 = MacPaths::SECURE_FIREWALL_POSTURE_OPT;

        std::string mkdirCmd2 = "sudo mkdir -p " + firewallPath1;
        if (system(mkdirCmd2.c_str()) != 0)
        {
            logger->error("Failed to create directory structure: " + firewallPath1);
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string jsonPath2 = firewallPath1 + "/v4debug.json";
        std::string touchCmd = "sudo touch " + jsonPath2;

        if (system(touchCmd.c_str()) == 0)
        {
            std::string chmodCmd = "sudo chmod 666 " + jsonPath2;
            system(chmodCmd.c_str());
            logger->info("Successfully created empty v4debug.json at: " + jsonPath2);
        }
        else
        {
            logger->error("Failed to create v4debug.json at: " + jsonPath2);
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // For home firewall v4debug.json
        logger->info("Creating empty v4debug.json in home secure firewall posture path...");
        std::string firewallPath2 = MacPaths::SECURE_FIREWALL_POSTURE_HOME;
        if (firewallPath2[0] == '~')
        {
            firewallPath2 = std::string(homeDir1) + firewallPath2.substr(1);
        }

        std::string mkdirCmd3 = "mkdir -p " + firewallPath2;
        if (system(mkdirCmd3.c_str()) != 0)
        {
            logger->error("Failed to create directory structure: " + firewallPath2);
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string jsonPath3 = firewallPath2 + "/v4debug.json";
        std::ofstream jsonFile2(jsonPath3);

        if (jsonFile2.is_open())
        {
            jsonFile2.close();
            logger->info("Successfully created empty v4debug.json at: " + jsonPath3);
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->error("Failed to create v4debug.json at: " + jsonPath3);
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
        logger->error("Error creating debuglogs.json: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Deletes all debug configuration files for ISE Posture and secure firewall posture
 * @note Removes debuglogs.json and v4debug.json files from specified directories
 *       Uses MacPaths constants for paths
 */
LogCollectorError::ErrorType LogCollectorMac::deleteAllFilesISEPosture()
{
    try
    {
        logger->info("Removing all debug configuration files...");

        // Get home directory
        const char *homeDir6 = getenv("HOME");
        if (!homeDir6)
        {
            logger->error("Could not determine home directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // For ISE debuglogs.json
        std::string isePath6 = MacPaths::ISE_POSTURE_LOG;
        if (isePath6[0] == '~')
        {
            isePath6 = std::string(homeDir6) + isePath6.substr(1);
        }
        std::string iseJsonPath6 = isePath6 + "/debuglogs.json";
        std::string rmCmd1 = "rm -f " + iseJsonPath6;
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

        // For opt firewall v4debug.json
        std::string firewallPath6 = MacPaths::SECURE_FIREWALL_POSTURE_OPT;
        std::string optJsonPath6 = firewallPath6 + "/v4debug.json";
        std::string rmCmd2 = "sudo rm -f " + optJsonPath6;
        if (system(rmCmd2.c_str()) == 0)
        {
            logger->info("Successfully removed opt v4debug.json");
        }
        else
        {
            logger->error("Failed to remove opt v4debug.json");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // For home firewall v4debug.json
        std::string firewallPath7 = MacPaths::SECURE_FIREWALL_POSTURE_HOME;
        if (firewallPath7[0] == '~')
        {
            firewallPath7 = std::string(homeDir6) + firewallPath7.substr(1);
        }
        std::string homeJsonPath6 = firewallPath7 + "/v4debug.json";
        std::string rmCmd3 = "rm -f " + homeJsonPath6;
        if (system(rmCmd3.c_str()) == 0)
        {
            logger->info("Successfully removed home v4debug.json");
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->error("Failed to remove home v4debug.json");
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
        logger->error("Error deleting debug files: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Creates all necessary files for ZTA logs
 * @note Creates logconfig.json and flags.json in the ZTA path
 *       Uses MacPaths constants for paths
 */
LogCollectorError::ErrorType LogCollectorMac::createAllFilesZTA()
{
    try
    {
        logger->info("Creating logconfig.json in ZTA path...");

        std::string ztaPath4 = MacPaths::ZTA_PATH;

        std::string mkdirCmd4 = "sudo mkdir -p " + ztaPath4;
        if (system(mkdirCmd4.c_str()) != 0)
        {
            logger->error("Failed to create directory structure: " + ztaPath4);
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string jsonPath4 = ztaPath4 + "logconfig.json";
        std::string touchCmd4 = "sudo touch " + jsonPath4;

        if (system(touchCmd4.c_str()) == 0)
        {
            std::string chmodCmd4 = "sudo chmod 666 " + jsonPath4;
            system(chmodCmd4.c_str());

            std::ofstream jsonFile4(jsonPath4);
            if (jsonFile4.is_open())
            {
                jsonFile4 << "{\n    \"global\": \"DBG_TRACE\"\n}" << std::endl;
                jsonFile4.close();
                logger->info("Successfully created logconfig.json at: " + jsonPath4);
            }
            else
            {
                logger->error("Failed to write to logconfig.json at: " + jsonPath4);
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
        }
        else
        {
            logger->error("Failed to create logconfig.json at: " + jsonPath4);
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        logger->info("Creating flags.json in ZTA path...");

        std::string ztaPath5 = MacPaths::ZTA_PATH;

        std::string mkdirCmd5 = "sudo mkdir -p " + ztaPath5;
        if (system(mkdirCmd5.c_str()) != 0)
        {
            logger->error("Failed to create directory structure: " + ztaPath5);
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string jsonPath5 = ztaPath5 + "flags.json";
        std::string touchCmd5 = "sudo touch " + jsonPath5;

        if (system(touchCmd5.c_str()) == 0)
        {
            std::string chmodCmd5 = "sudo chmod 666 " + jsonPath5;
            system(chmodCmd5.c_str());

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
                logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
                return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
            }
            else
            {
                logger->error("Failed to write to flags.json at: " + jsonPath5);
                logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                return LogCollectorError::ErrorType::COMMAND_FAILED;
            }
        }
        else
        {
            logger->error("Failed to create flags.json at: " + jsonPath5);
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
        logger->error("Error creating debuglogs.json: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Deletes all debug configuration files for ZTA logs
 * @note Removes logconfig.json and flags.json from the ZTA path
 *       Uses MacPaths constants for paths
 */
LogCollectorError::ErrorType LogCollectorMac::deleteAllFilesZTA()
{
    try
    {
        // For ZTA logconfig.json
        std::string ztaPath6 = MacPaths::ZTA_PATH;
        std::string logconfigPath6 = ztaPath6 + "logconfig.json";
        std::string rmCmd4 = "sudo rm -f " + logconfigPath6;
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
        std::string flagsPath6 = ztaPath6 + "flags.json";
        std::string rmCmd5 = "sudo rm -f " + flagsPath6;
        if (system(rmCmd5.c_str()) == 0)
        {
            logger->info("Successfully removed flags.json");
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->error("Failed to remove flags.json");
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
        logger->error("Error deleting debug files: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}