#ifndef COMMON_H
#define COMMON_H

#include "Logger.h"
extern std::atomic<bool> g_stopCollection;

void signalHandler(int signum);
extern std::string SYSTEM_NVM_PATH;
extern std::string CONF_FILE;
extern std::string XML_FILE;


// Add a class for common utility functions
class CommonUtils {
public:
    // Constructor takes a logger
    CommonUtils(std::shared_ptr<Logger> logger);
    void addTroubleshootTagSystem(const std::string& PATH);
    void setKDFDebugFlagSystem(const std::string& PATH, const std::string& hexValue);
    void clearKDFDebugFlagSystem(const std::string& PATH);
    void writeDebugConfSystem(const std::string& PATH);
    void removeDebugConfSystem(const std::string& PATH);
    void createSWGConfigOverrideSystem(const std::string& PATH);
    void deleteSWGConfigOverrideSystem(const std::string& PATH);
    void collectLogsWithTimer();
private:
    std::shared_ptr<Logger> logger;
};
namespace MacPaths {
    // Base directories
    const std::string SECURECLIENT_BASE = "/opt/cisco/secureclient/";
    const std::string NVM_PATH = SECURECLIENT_BASE + "NVM/";
    const std::string KDF_PATH = SECURECLIENT_BASE + "kdf/";
    const std::string UMBRELLA_PATH = SECURECLIENT_BASE + "umbrella/";
    const std::string ZTA_PATH = SECURECLIENT_BASE + "zta/";
    
    // Executables
    const std::string NVM_AGENT = NVM_PATH + "bin/acnvmagent.app/Contents/MacOS/acnvmagent";
    const std::string UMBRELLA_AGENT = SECURECLIENT_BASE + "bin/acumbrellaagent";
    const std::string ACSOCKTOOL = KDF_PATH + "bin/acsocktool";
    const std::string DART_CLI = "/Applications/Cisco/Cisco\\ Secure\\ Client\\ -\\ DART.app/Contents/Resources/dartcli";
    
    // Config files
    const std::string DEBUG_CONF = NVM_PATH + "nvm_dbg.conf";
    const std::string SERVICE_PROFILE = NVM_PATH + "NVM_ServiceProfile.xml";
    //ISE and Secure Firewall Posture paths
    const std::string ISE_POSTURE_LOG = "~/.cisco/iseposture/log";
    const std::string SECURE_FIREWALL_POSTURE_OPT = SECURECLIENT_BASE + "securefirewallposture";
    const std::string SECURE_FIREWALL_POSTURE_HOME = "~/.cisco/secureclient/securefirewallposture";
    const std::string NVM_AGENT_BIN = SECURECLIENT_BASE + "NVM/bin/acnvmagent.app/Contents/MacOS/acnvmagent";
    const std::string ISE_AGENT_BIN = SECURECLIENT_BASE + "bin/csc_iseagentd";
    const std::string ZTA_AGENT_BIN = SECURECLIENT_BASE + "bin/csc_zta_agent";
    
}

// Windows paths
namespace WinPaths {
    // Base directories
    const std::string SECURECLIENT_BASE = "C:\\Program Files (x86)\\Cisco\\Cisco Secure Client\\";
    const std::string NVM_PATH = SECURECLIENT_BASE + "nvm\\";
    const std::string UMBRELLA_PATH = SECURECLIENT_BASE + "umbrella\\";
    
    // Executables
    const std::string NVM_AGENT = NVM_PATH + "bin\\acnvmagent.exe";
    const std::string UMBRELLA_AGENT = UMBRELLA_PATH + "acumbrellaagent.exe";
    const std::string DART_CLI = SECURECLIENT_BASE + "DART\\dartcli.exe";
    
    // Config files
    const std::string DEBUG_CONF = NVM_PATH + "nvm_dbg.conf";
    const std::string SERVICE_PROFILE = NVM_PATH + "NVM_ServiceProfile.xml";
    const std::string SWG_CONFIG_OVERRIDE = UMBRELLA_PATH + "SWGConfigOverride.json";
}

// Linux paths
namespace LinuxPaths {
    // Base directories
    const std::string SECURECLIENT_BASE = "/opt/cisco/secure-client/";
    const std::string NVM_PATH = SECURECLIENT_BASE + "nvm/";
    const std::string UMBRELLA_PATH = SECURECLIENT_BASE + "umbrella/";
    
    // Executables
    const std::string NVM_AGENT = NVM_PATH + "acnvmagent";
    const std::string UMBRELLA_AGENT = UMBRELLA_PATH + "acumbrellaagent";
    
    // Config files
    const std::string DEBUG_CONF = NVM_PATH + "nvm_dbg.conf";
    const std::string SERVICE_PROFILE = NVM_PATH + "NVM_ServiceProfile.xml";
    const std::string SWG_CONFIG_OVERRIDE = UMBRELLA_PATH + "SWGConfigOverride.json";
}

#endif // COMMON_H