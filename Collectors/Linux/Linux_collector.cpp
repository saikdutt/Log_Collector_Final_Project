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
#include <csignal>
#include "Linux_collector.h"
#include "../../Utils/Error.h"
#include "../../Utils/Logger.h"
#include "../../Utils/Common.h"

using namespace std;

/**
 * @brief Constructs a Linux NVM log collector with multiple module support
 * @param config Configuration settings map for collector initialization
 * @param logger Shared pointer to logger instance for output messages
 * @param enable_debug_logs Optional flag to enable detailed debug logging (default: false)
 * @param debug_level Optional debug verbosity level (default: 0)
 * @note Initializes all collector modules (NVM, SWG, ISE, ZTA) and utilities
 */
LogCollectorLinux::LogCollectorLinux(const std::map<std::string, std::string> &config,
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

    logger->info("CollectorLinux initialized with NVM, SWG, ISE Posture, ZTA support.");
}

/**
 * @brief Destroys the Linux NVM log collector instance
 * @note Logs destruction message before cleanup
 */
LogCollectorLinux::~LogCollectorLinux()
{
    logger->info("LogCollectorLinux destroyed");
}

/**
 * @brief Retrieves the version of the NVM agent on Linux
 * @note Executes the NVM agent binary with the `-v` flag to get the version
 */
LogCollectorError::ErrorType LogCollectorLinux::get_nvm_version()
{
    logger->info("Getting NVM agent version...");
    try
    {
        std::array<char, 128> buffer;
        std::string result;

        // Correct Linux path to NVM agent
        std::string cmd = "sudo " + LinuxPaths::NVM_AGENT + " -v";

        FILE *pipe = popen(cmd.c_str(), "r");
        if (!pipe)
        {
            throw std::runtime_error("Failed to execute command to get NVM version");
        }

        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
        {
            result += buffer.data();
        }

        int status = pclose(pipe);
        if (status != 0)
        {
            logger->warning("Command returned non-zero status: " + std::to_string(status));
        }

        // Improved version extraction using regex
        std::regex versionPattern("Version\\s*:\\s*(\\d+\\.\\d+\\.\\d+(?:-\\w+)?)");
        std::smatch matches;
        if (std::regex_search(result, matches, versionPattern) && matches.size() > 1)
        {
            nvm_version = matches[1].str();
        }
        else
        {
            logger->info("NVM agent version found: " + result);
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
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
/**
 * @brief Checks if the user has administrative privileges
 * @note Uses CommonUtils::checkAdminPrivilegesSystem() for system-specific checks
 * @return LogCollectorError::ErrorType indicating success or failure
 */
LogCollectorError::ErrorType LogCollectorLinux::checkAdminPrivileges(){
    return utils.checkAdminPrivilegesSystem();
}
/**
 * @brief Writes the debug configuration file for the NVM agent
 * @note Uses the utility function to write the debug configuration
 * @param LinuxPaths::DEBUG_CONF Path to the debug configuration file
 */
LogCollectorError::ErrorType LogCollectorLinux::writeDebugConf()
{
    utils.writeDebugConfSystem(LinuxPaths::DEBUG_CONF);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Removes the debug configuration file for the NVM agent
 * @note Uses the utility function to remove the debug configuration
 * @param LinuxPaths::DEBUG_CONF Path to the debug configuration file
 */
LogCollectorError::ErrorType LogCollectorLinux::removeDebugConf()
{
    utils.removeDebugConfSystem(LinuxPaths::DEBUG_CONF);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Adds a troubleshoot tag to the NVM service profile
 * @note Uses the utility function to modify the service profile
 * @param LinuxPaths::SERVICE_PROFILE Path to the NVM service profile
 */
LogCollectorError::ErrorType LogCollectorLinux::addTroubleshootTag()
{
    utils.addTroubleshootTagSystem(LinuxPaths::SERVICE_PROFILE);
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Creates a backup of the NVM service profile
 * @note Copies the service profile to a backup file in the NVM path
 */
LogCollectorError::ErrorType LogCollectorLinux::backupServiceProfile()
{
    try
    {
        logger->info("Creating backup of NVM_ServiceProfile.xml...");

        // LinuxPaths::SERVICE_PROFILE already includes the filename, so don't append it again
        std::string cmd = "sudo cp " + LinuxPaths::SERVICE_PROFILE + " " +
                          LinuxPaths::NVM_PATH + "NVM_ServiceProfile.xml.bak";

        logger->debug("Executing command: " + cmd);
        int result = system(cmd.c_str());

        if (result == 0)
        {
            logger->info("Backup created successfully as NVM_ServiceProfile.xml.bak");
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->error("Failed to create backup, error code: " + std::to_string(result));
            logger->error("Make sure you're running with sudo privileges.");
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
        logger->error("Error creating backup: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Restores the NVM service profile from a backup
 * @note Copies the backup file back to the service profile path
 */
LogCollectorError::ErrorType LogCollectorLinux::restoreServiceProfile()
{
    try
    {
        logger->info("Restoring NVM_ServiceProfile.xml from backup...");

        // Use LinuxPaths constants for correct path handling
        std::string cmd = "sudo cp " + LinuxPaths::NVM_PATH + "NVM_ServiceProfile.xml.bak " +
                          LinuxPaths::SERVICE_PROFILE;

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
        std::string cmd1 = "sudo rm " + LinuxPaths::NVM_PATH + "NVM_ServiceProfile.xml.bak";

        logger->debug("Executing command: " + cmd1);
        int result1 = system(cmd1.c_str());

        if (result1 == 0)
        {
            logger->info("Successfully removed backup file");
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->error("Failed to remove backup file. Error code: " + std::to_string(result1));
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
        logger->error("Error restoring service profile: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}
/**
 * @brief Finds, stops and restarts all agent processes (NVM, ISE, ZTA)
 * @details Searches for running processes, captures their PIDs, terminates them,
 *          then restarts them using appropriate paths from LinuxPaths namespace
 * @note Requires sudo privileges for process management operations
 * @note Uses ps, kill, and process restart commands
 * @note Uses `ps -ef` to list processes and `grep` to filter for specific agents
 * @note Terminates processes using `kill -9` if their PIDs are found
 */
LogCollectorError::ErrorType LogCollectorLinux::findAllAgentProcesses()
{
    try
    {
        logger->info("Searching for NVM agent processes in Linux...");

        // Command to find NVM agent processes in Linux
        std::string cmd1 = "ps -ef | grep acnvmagent";

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
        std::string cmd = "ps -ef | grep acnvmagent"; // Filter out the grep process itself

        FILE *pipe = popen(cmd.c_str(), "r");
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
        pclose(pipe);

        // Parse the output to get PID
        std::istringstream stream(result);
        std::string line;
        std::string pid;

        if (std::getline(stream, line))
        {
            std::istringstream iss(line);
            std::string column;
            int columnCount = 0;

            while (iss >> column && columnCount < 2)
            {
                if (columnCount == 1)
                { // Second column contains PID in Linux ps output
                    pid = column;
                    break;
                }
                columnCount++;
            }
        }
        if (!pid.empty())
        {
            logger->info("Found NVM agent PID: " + pid);
            std::string killCmd = "sudo kill -9 " + pid;
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
 * @brief Sets the KDF debug level on Linux.
 * @note Prompts the user to enter a debug level (0-7) and applies it using `sysctl`.
 * @details Logs the selected debug mode and validates the input.
 */
LogCollectorError::ErrorType LogCollectorLinux::setKDFDebugFlag()
{
    logger->info("Setting KDF debug level...");
    int debugLevel;
    logger->info("Enter debug level (0-7): ");
    cin >> debugLevel;

    // Validate input
    if (debugLevel < 0 || debugLevel > 7 || cin.fail())
    {
        logger->error("[!] Invalid debug level. Please enter a value between 0-7.");
        cin.clear();                                         // Clear error flags
        cin.ignore(numeric_limits<streamsize>::max(), '\n'); // Discard invalid input
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }

    try
    {
        // Command to set KDF debug level using sysctl
        std::string cmd = "sudo sysctl -w anyconnect_kdf.debugLevel=" + std::to_string(debugLevel);

        logger->info("[*] Executing command: " + cmd);
        int result = system(cmd.c_str());

        if (result == 0)
        {
            logger->info("[+] KDF debug level set successfully to " + std::to_string(debugLevel));

            switch (debugLevel)
            {
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
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->error("[!] Failed to set KDF debug level. Command returned: " + std::to_string(result));
            logger->info("[*] The sysctl parameter 'anyconnect_kdf.debugLevel' may not exist on this system.");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
    }
    catch (const LogCollectorError &e)
    {
        logger->error("[!] Error setting KDF debug level: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("[!] Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("[!] Error setting KDF debug level: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Resets the KDF debug level to 0 (disabled).
 * @note Uses `sysctl` to disable debug mode for KDF.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorLinux::clearKDFDebugFlag()
{
    logger->info("[*] Resetting KDF debug flag to disable debug mode...");

    try
    {
        // Command to reset KDF debug level to 0 using sysctl
        std::string cmd = "sudo sysctl -w anyconnect_kdf.debugLevel=0";

        logger->info("[*] Executing command: " + cmd);
        int result = system(cmd.c_str());

        if (result == 0)
        {
            logger->info("[+] KDF debug level successfully reset to 0 (disabled)");
            logger->info("[*] Debug Mode: Disabled (Normal Mode)");
            logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
            return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
        }
        else
        {
            logger->error("[!] Failed to reset KDF debug level. Command returned: " + std::to_string(result));
            logger->info("[*] The sysctl parameter 'anyconnect_kdf.debugLevel' may not exist on this system.");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
    }
    catch (const LogCollectorError &e)
    {
        logger->error("[!] Error resetting KDF debug level: " + LogCollectorError::getErrorTypeString(e.getType()));
        logger->error("[!] Details: " + std::string(e.what()));
        return e.getType();
    }
    catch (const std::exception &e)
    {
        logger->error("[!] Error resetting KDF debug level: " + std::string(e.what()));
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Collects DART logs and saves them as a zip file on the Desktop.
 * @note Executes the DART CLI tool to generate the logs.
 * @details Logs the success or failure of the collection process.
 */
LogCollectorError::ErrorType LogCollectorLinux::collectDARTLogs()
{
    try
    {
        logger->info("Starting DART log collection...");

        // Get user's home directory path for desktop
        const char *homeDir = getenv("HOME");
        if (!homeDir)
        {
            logger->error("Could not determine home directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string desktopPath = std::string(homeDir) + "/Desktop";
        std::string dartBundle = desktopPath + "/DART_Bundle.zip";

        // Construct the DART collection command
        std::string cmd = "sudo " + LinuxPaths::DART_CLI + " -dst " + dartBundle;

        logger->info("Executing DART collection command: " + cmd);
        logger->info("This may take several minutes. Please wait...");

        int result = system(cmd.c_str());

        if (result == 0)
        {
            logger->info("DART log collection completed successfully.");
            logger->info("DART bundle saved to: " + dartBundle);
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
        logger->error("Error collecting DART logs: " + std::string(e.what()));
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
LogCollectorError::ErrorType LogCollectorLinux::collectLogsWithTimer()
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
 * @brief Organizes collected logs into a directory and creates a zip archive.
 * @note Moves logs to a dedicated folder and compresses them with a timestamp.
 * @details Cleans up temporary files after archiving.
 */
LogCollectorError::ErrorType LogCollectorLinux::organizeAndArchiveLogs()
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
        std::string secureClientDir = desktopPath + "/secure_client";

        // 1. Create secure_client directory
        std::string mkdirCmd = "mkdir -p " + secureClientDir;
        logger->info("Creating logs directory: " + secureClientDir);
        if (system(mkdirCmd.c_str()) != 0)
        {
            logger->error("Failed to create secure_client directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }
        logger->info("secure_client directory created successfully");

        // 2. Move all other log files to secure_client directory
        std::string moveCmd = "mv " + desktopPath + "/kdf_logs.log " +
                              desktopPath + "/nvm_system_logs.log " +
                              desktopPath + "/PacketCapture.pcap " +
                              desktopPath + "/DART_Bundle.zip " +
                              desktopPath + "/ise_posture_logs.log " +
                              desktopPath + "/zta_logs.log " +
                              secureClientDir + "/ 2>/dev/null";

        logger->info("Moving log files to secure_client directory");
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
                             timestamp + ".zip secure_client/";

        logger->info("Creating zip archive of logs...");
        if (system(zipCmd.c_str()) == 0)
        {
            logger->info("Successfully created archive: secure_client_logs_" + timestamp + ".zip");

            // Optional: Clean up secure_client directory after successful archive
            std::string cleanupCmd = "rm -rf " + secureClientDir;
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
 * @brief Creates necessary debug files for ISE posture logs.
 * @note Checks for required directories and creates `debuglogs.json` and `v4debug.json`.
 * @details Logs the success or failure of file creation.
 */
LogCollectorError::ErrorType LogCollectorLinux::createAllFilesISEPosture()
{
    try
    {
        logger->info("Checking and creating debug files for ISE and ZTA modules...");

        // For ISE debuglogs.json
        logger->info("Checking ISE posture log path...");

        const char *homeDir = getenv("HOME");
        if (!homeDir)
        {
            logger->error("Could not determine home directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        std::string isePath = LinuxPaths::ISE_POSTURE_LOG;
        if (isePath[0] == '~')
        {
            isePath = std::string(homeDir) + isePath.substr(1);
        }

        // Check if directory exists - only proceed if it does
        std::string checkDirCmd = "test -d " + isePath + " && echo exists";
        FILE *pipe = popen(checkDirCmd.c_str(), "r");
        char buffer[128];
        std::string result = "";

        if (pipe)
        {
            while (!feof(pipe))
            {
                if (fgets(buffer, 128, pipe) != NULL)
                {
                    result += buffer;
                }
            }
            pclose(pipe);

            if (result.find("exists") != std::string::npos)
            {
                logger->info("ISE posture log directory exists, creating debuglogs.json");

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
            }
            else
            {
                logger->info("ISE posture log directory does not exist, skipping debuglogs.json creation");
            }
        }

        // For secure firewall posture v4debug.json in /opt path
        logger->info("Checking secure firewall posture path in /opt...");
        std::string firewallPath1 = LinuxPaths::SECURE_FIREWALL_POSTURE_OPT;

        std::string checkDirCmd2 = "sudo test -d " + firewallPath1 + " && echo exists";
        pipe = popen(checkDirCmd2.c_str(), "r");
        result = "";

        if (pipe)
        {
            while (!feof(pipe))
            {
                if (fgets(buffer, 128, pipe) != NULL)
                {
                    result += buffer;
                }
            }
            pclose(pipe);

            if (result.find("exists") != std::string::npos)
            {
                logger->info("Secure firewall posture directory exists in /opt, creating v4debug.json");

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
            }
            else
            {
                logger->info("Secure firewall posture directory in /opt does not exist, skipping v4debug.json creation");
            }
        }

        // For secure firewall posture v4debug.json in home directory
        logger->info("Checking secure firewall posture path in home directory...");
        std::string firewallPath2 = LinuxPaths::SECURE_FIREWALL_POSTURE_HOME;
        if (firewallPath2[0] == '~')
        {
            firewallPath2 = std::string(homeDir) + firewallPath2.substr(1);
        }

        std::string checkDirCmd3 = "test -d " + firewallPath2 + " && echo exists";
        pipe = popen(checkDirCmd3.c_str(), "r");
        result = "";

        if (pipe)
        {
            while (!feof(pipe))
            {
                if (fgets(buffer, 128, pipe) != NULL)
                {
                    result += buffer;
                }
            }
            pclose(pipe);

            if (result.find("exists") != std::string::npos)
            {
                logger->info("Secure firewall posture directory exists in home, creating v4debug.json");

                std::string jsonPath3 = firewallPath2 + "/v4debug.json";
                std::ofstream jsonFile2(jsonPath3);

                if (jsonFile2.is_open())
                {
                    jsonFile2.close();
                    logger->info("Successfully created empty v4debug.json at: " + jsonPath3);
                }
                else
                {
                    logger->error("Failed to create v4debug.json at: " + jsonPath3);
                    logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                    return LogCollectorError::ErrorType::COMMAND_FAILED;
                }
            }
            else
            {
                logger->info("Secure firewall posture directory in home does not exist, skipping v4debug.json creation");
            }
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
LogCollectorError::ErrorType LogCollectorLinux::deleteAllFilesISEPosture()
{
    try
    {
        logger->info("Removing debug configuration files if they exist...");

        // Get home directory
        const char *homeDir = getenv("HOME");
        if (!homeDir)
        {
            logger->error("Could not determine home directory");
            logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
            return LogCollectorError::ErrorType::COMMAND_FAILED;
        }

        // For ISE debuglogs.json
        std::string isePath = LinuxPaths::ISE_POSTURE_LOG;
        if (isePath[0] == '~')
        {
            isePath = std::string(homeDir) + isePath.substr(1);
        }
        std::string iseJsonPath = isePath + "/debuglogs.json";

        // Check if ISE debuglogs.json exists
        std::string checkCmd1 = "test -f " + iseJsonPath + " && echo exists";
        FILE *pipe = popen(checkCmd1.c_str(), "r");
        char buffer[128];
        std::string result = "";

        if (pipe)
        {
            while (!feof(pipe))
            {
                if (fgets(buffer, 128, pipe) != NULL)
                {
                    result += buffer;
                }
            }
            pclose(pipe);

            if (result.find("exists") != std::string::npos)
            {
                // File exists, delete it
                std::string rmCmd1 = "rm -f " + iseJsonPath;
                if (system(rmCmd1.c_str()) == 0)
                {
                    logger->info("Successfully removed ISE debuglogs.json");
                }
                else
                {
                    logger->error("Failed to remove ISE debuglogs.json");
                    logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                    return LogCollectorError::ErrorType::COMMAND_FAILED;
                }
            }
            else
            {
                logger->info("ISE debuglogs.json not found, skipping");
            }
        }

        // For opt firewall v4debug.json
        std::string firewallPath = LinuxPaths::SECURE_FIREWALL_POSTURE_OPT;
        std::string optJsonPath = firewallPath + "/v4debug.json";

        // Check if opt v4debug.json exists
        std::string checkCmd2 = "sudo test -f " + optJsonPath + " && echo exists";
        pipe = popen(checkCmd2.c_str(), "r");
        result = "";

        if (pipe)
        {
            while (!feof(pipe))
            {
                if (fgets(buffer, 128, pipe) != NULL)
                {
                    result += buffer;
                }
            }
            pclose(pipe);

            if (result.find("exists") != std::string::npos)
            {
                // File exists, delete it
                std::string rmCmd2 = "sudo rm -f " + optJsonPath;
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
            }
            else
            {
                logger->info("Opt v4debug.json not found, skipping");
            }
        }

        // For home firewall v4debug.json
        std::string firewallPath2 = LinuxPaths::SECURE_FIREWALL_POSTURE_HOME;
        if (firewallPath2[0] == '~')
        {
            firewallPath2 = std::string(homeDir) + firewallPath2.substr(1);
        }
        std::string homeJsonPath = firewallPath2 + "/v4debug.json";

        // Check if home v4debug.json exists
        std::string checkCmd3 = "test -f " + homeJsonPath + " && echo exists";
        pipe = popen(checkCmd3.c_str(), "r");
        result = "";

        if (pipe)
        {
            while (!feof(pipe))
            {
                if (fgets(buffer, 128, pipe) != NULL)
                {
                    result += buffer;
                }
            }
            pclose(pipe);

            if (result.find("exists") != std::string::npos)
            {
                // File exists, delete it
                std::string rmCmd3 = "rm -f " + homeJsonPath;
                if (system(rmCmd3.c_str()) == 0)
                {
                    logger->info("Successfully removed home v4debug.json");
                }
                else
                {
                    logger->error("Failed to remove home v4debug.json");
                    logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                    return LogCollectorError::ErrorType::COMMAND_FAILED;
                }
            }
            else
            {
                logger->info("Home v4debug.json not found, skipping");
            }
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
LogCollectorError::ErrorType LogCollectorLinux::createAllFilesZTA()
{
    try
    {
        FILE *pipe = nullptr;
        char buffer[128];
        std::string result;

        // For ZTA logconfig.json
        logger->info("Checking ZTA path for logconfig.json...");
        std::string ztaPath = LinuxPaths::ZTA_PATH;

        std::string checkDirCmd4 = "sudo test -d " + ztaPath + " && echo exists";
        pipe = popen(checkDirCmd4.c_str(), "r");
        result = "";

        if (pipe)
        {
            while (!feof(pipe))
            {
                if (fgets(buffer, 128, pipe) != NULL)
                {
                    result += buffer;
                }
            }
            pclose(pipe);

            if (result.find("exists") != std::string::npos)
            {
                logger->info("ZTA directory exists, creating logconfig.json");

                std::string jsonPath4 = ztaPath + "logconfig.json";
                std::string touchCmd4 = "sudo touch " + jsonPath4;

                if (system(touchCmd4.c_str()) == 0)
                {
                    std::string chmodCmd4 = "sudo chmod 666 " + jsonPath4;
                    system(chmodCmd4.c_str());

                    std::string writeCmd4 = "echo '{\n    \"global\": \"DBG_TRACE\"\n}' | sudo tee " + jsonPath4 + " > /dev/null";
                    if (system(writeCmd4.c_str()) == 0)
                    {
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
            }
            else
            {
                logger->info("ZTA directory does not exist, skipping logconfig.json creation");
            }
        }

        // For ZTA flags.json
        logger->info("Checking ZTA path for flags.json...");

        std::string checkDirCmd5 = "sudo test -d " + ztaPath + " && echo exists";
        pipe = popen(checkDirCmd5.c_str(), "r");
        result = "";

        if (pipe)
        {
            while (!feof(pipe))
            {
                if (fgets(buffer, 128, pipe) != NULL)
                {
                    result += buffer;
                }
            }
            pclose(pipe);

            if (result.find("exists") != std::string::npos)
            {
                logger->info("ZTA directory exists, creating flags.json");

                std::string jsonPath5 = ztaPath + "flags.json";
                std::string touchCmd5 = "sudo touch " + jsonPath5;

                if (system(touchCmd5.c_str()) == 0)
                {
                    std::string chmodCmd5 = "sudo chmod 666 " + jsonPath5;
                    system(chmodCmd5.c_str());

                    std::string flagsContent = "{\n"
                                               "    \"datapath\": {\n"
                                               "        \"quic\": {\n"
                                               "            \"enabled\": false,\n"
                                               "            \"unreliable_datagram\": true,\n"
                                               "            \"fallback_http2\": true,\n"
                                               "            \"max_datagram_size\": 1350\n"
                                               "        }\n"
                                               "    },\n"
                                               "    \"flow_log\": {\"max_count\": 35000},\n"
                                               "    \"enrollment\": {\n"
                                               "        \"acme\": {\n"
                                               "            \"cert_renewal_interval_seconds\": 86400\n"
                                               "        }\n"
                                               "    }\n"
                                               "}";

                    std::string writeCmd5 = "echo '" + flagsContent + "' | sudo tee " + jsonPath5 + " > /dev/null";
                    if (system(writeCmd5.c_str()) == 0)
                    {
                        logger->info("Successfully created flags.json at: " + jsonPath5);
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
            else
            {
                logger->info("ZTA directory does not exist, skipping flags.json creation");
            }
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
LogCollectorError::ErrorType LogCollectorLinux::deleteAllFilesZTA()
{
    try
    {
        FILE *pipe = nullptr;
        char buffer[128];
        std::string result;

        // For ZTA logconfig.json
        std::string ztaPath = LinuxPaths::ZTA_PATH;
        std::string logconfigPath = ztaPath + "logconfig.json";

        std::string checkCmd4 = "sudo test -f " + logconfigPath + " && echo exists";
        pipe = popen(checkCmd4.c_str(), "r");
        result = "";

        if (pipe)
        {
            while (!feof(pipe))
            {
                if (fgets(buffer, 128, pipe) != NULL)
                {
                    result += buffer;
                }
            }
            pclose(pipe);

            if (result.find("exists") != std::string::npos)
            {
                std::string rmCmd4 = "sudo rm -f " + logconfigPath;
                if (system(rmCmd4.c_str()) == 0)
                {
                    logger->info("Successfully removed ZTA logconfig.json");
                }
                else
                {
                    logger->error("Failed to remove ZTA logconfig.json");
                    logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                    return LogCollectorError::ErrorType::COMMAND_FAILED;
                }
            }
            else
            {
                logger->info("ZTA logconfig.json not found, skipping");
            }
        }

        // For ZTA flags.json
        std::string flagsPath = ztaPath + "flags.json";

        std::string checkCmd5 = "sudo test -f " + flagsPath + " && echo exists";
        pipe = popen(checkCmd5.c_str(), "r");
        result = "";

        if (pipe)
        {
            while (!feof(pipe))
            {
                if (fgets(buffer, 128, pipe) != NULL)
                {
                    result += buffer;
                }
            }
            pclose(pipe);

            if (result.find("exists") != std::string::npos)
            {
                std::string rmCmd5 = "sudo rm -f " + flagsPath;
                if (system(rmCmd5.c_str()) == 0)
                {
                    logger->info("Successfully removed ZTA flags.json");
                }
                else
                {
                    logger->error("Failed to remove ZTA flags.json");
                    logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
                    return LogCollectorError::ErrorType::COMMAND_FAILED;
                }
            }
            else
            {
                logger->info("ZTA flags.json not found, skipping");
            }
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
LogCollectorError::ErrorType LogCollectorLinux::createSWGConfigOverride()
{
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

LogCollectorError::ErrorType LogCollectorLinux::deleteSWGConfigOverride()
{
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Starts the collection of KDF logs on Linux.
 * @note Uses `dmesg` with filters to capture logs and saves them to the Desktop.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorLinux::collectKdfLogs()
{
    const char *homeDir = getenv("HOME");
    if (!homeDir)
    {
        logger->error("Could not determine home directory");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    std::string kdfLogsPath = std::string(homeDir) + "/Desktop/kdf_logs.log";
    std::string cmd = "sudo dmesg -wT | grep -i -E 'kdf|anyconnect|nvm' | tee -a " + kdfLogsPath + " &";
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
 * @brief Starts the collection of Umbrella logs on Linux.
 * @note Placeholder function for Umbrella log collection.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorLinux::collectUmbrellaLogs()
{
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Starts the collection of NVM system logs on Linux.
 * @note Uses `tail` with filters to capture logs from `/var/log/syslog`.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorLinux::collectNvmLogs()
{
    const char *homeDir = getenv("HOME");
    if (!homeDir)
    {
        logger->error("Could not determine home directory");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    std::string nvmLogsPath = std::string(homeDir) + "/Desktop/nvm_system_logs.log";
    std::string cmd = "sudo tail /var/log/syslog -f | grep -i \"nvm\" > " + nvmLogsPath + " &";
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
 * @brief Starts a packet capture on Linux.
 * @note Uses `tcpdump` to capture packets and saves them as a `.pcap` file on the Desktop.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorLinux::collectPacketCapture()
{
    const char *homeDir = getenv("HOME");
    if (!homeDir)
    {
        logger->error("Could not determine home directory");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    std::string packetCapturePath = std::string(homeDir) + "/Desktop/PacketCapture.pcap";
    std::string cmd = "sudo tcpdump -w " + packetCapturePath + " &";
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
 * @brief Starts the collection of ISE posture logs on Linux.
 * @note Uses `tail` with filters to capture logs from `/var/log/syslog`.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorLinux::collectIsePostureLogs()
{
    const char *homeDir = getenv("HOME");
    if (!homeDir)
    {
        logger->error("Could not determine home directory");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    std::string isePostureLogsPath = std::string(homeDir) + "/Desktop/ise_posture_logs.log";
    std::string cmd = "sudo tail /var/log/syslog -f | grep -i \"posture\" > " + isePostureLogsPath + " &";
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
 * @brief Starts the collection of ZTA logs on Linux.
 * @note Uses `tail` with filters to capture logs from `/var/log/syslog`.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorLinux::collectZtaLogs()
{
    const char *homeDir = getenv("HOME");
    if (!homeDir)
    {
        logger->error("Could not determine home directory");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
    std::string ztaLogsPath = std::string(homeDir) + "/Desktop/zta_logs.log";
    std::string cmd = "sudo tail /var/log/syslog -f | grep -i \"zta\" > " + ztaLogsPath + " &";
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
 * @brief Stops the collection of KDF logs on Linux.
 * @note Uses `pkill` to terminate the `dmesg` command capturing KDF logs.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorLinux::stopKdfLogs()
{
    std::string cmd = "sudo pkill -f 'dmesg -wT.*grep.*kdf|anyconnect|nvm' || true";
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
        logger->error("[!] Failed to stop KDF Logs collection");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Stops the collection of NVM system logs on Linux.
 * @note Uses `pkill` to terminate the `tail` command capturing NVM logs.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorLinux::stopNvmLogs()
{
    std::string cmd = "sudo pkill -f 'tail.*syslog.*grep.*nvm' || true";
    logger->info("Stopping NVM System Logs collection...");
    int result = system(cmd.c_str());
    if (result == 0)
    {
        logger->info("[+] Successfully stopped NVM System Logs collection");
        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    else
    {
        logger->error("[!] Failed to stop NVM System Logs collection");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Stops the collection of Umbrella logs on Linux.
 * @note Placeholder function for stopping Umbrella log collection.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorLinux::stopUmbrellaLogs()
{
    logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
    return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
}

/**
 * @brief Stops the packet capture on Linux.
 * @note Uses `killall` to terminate the `tcpdump` process capturing packets.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorLinux::stopPacketCapture()
{
    std::string cmd = "sudo killall tcpdump || true";
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
        logger->error("[!] Failed to stop Packet Capture collection");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Stops the collection of ISE posture logs on Linux.
 * @note Uses `pkill` to terminate the `tail` command capturing ISE posture logs.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorLinux::stopIsePostureLogs()
{
    std::string cmd = "sudo pkill -f 'tail.*syslog.*grep.*posture' || true";
    logger->info("Stopping ISE Posture Logs collection...");
    int result = system(cmd.c_str());
    if (result == 0)
    {
        logger->info("[+] Successfully stopped ISE Posture Logs collection");
        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    else
    {
        logger->error("[!] Failed to stop ISE Posture Logs collection");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}

/**
 * @brief Stops the collection of ZTA logs on Linux.
 * @note Uses `pkill` to terminate the `tail` command capturing ZTA logs.
 * @details Logs the success or failure of the operation.
 */
LogCollectorError::ErrorType LogCollectorLinux::stopZtaLogs()
{
    std::string cmd = "sudo pkill -f 'tail.*syslog.*grep.*zta' || true";
    logger->info("Stopping ZTA Logs collection...");
    int result = system(cmd.c_str());
    if (result == 0)
    {
        logger->info("[+] Successfully stopped ZTA Logs collection");
        logger->info("Returning success: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::SUCCESSFULLY_RUN));
        return LogCollectorError::ErrorType::SUCCESSFULLY_RUN;
    }
    else
    {
        logger->error("[!] Failed to stop ZTA Logs collection");
        logger->error("Returning error: " + LogCollectorError::getErrorTypeString(LogCollectorError::ErrorType::COMMAND_FAILED));
        return LogCollectorError::ErrorType::COMMAND_FAILED;
    }
}