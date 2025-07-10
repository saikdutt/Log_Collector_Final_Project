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
    const std::string SECURECLIENT_BASE = "C:\\ProgramData\\Cisco\\Cisco Secure Client\\";
    const std::string SECURECLIENT_BASE_HOME = "C:\\Program Files (x86)\\Cisco\\Cisco Secure Client\\";
    const std::string NVM_PATH = SECURECLIENT_BASE + "NVM\\";
    const std::string NVM_PATH_HOME = SECURECLIENT_BASE_HOME + "NVM\\";
    const std::string UMBRELLA_PATH = SECURECLIENT_BASE + "umbrella\\";
    
    // Executables
    const std::string NVM_AGENT = NVM_PATH_HOME + "acnvmagent.exe";
    const std::string ACSOCKTOOL = SECURECLIENT_BASE_HOME + "acsocktool.exe";
    const std::string UMBRELLA_AGENT = UMBRELLA_PATH + "acumbrellaagent.exe";
    const std::string DART_CLI = SECURECLIENT_BASE_HOME + "DART\\dartcli.exe";
    
    // Config files
    const std::string DEBUG_CONF = NVM_PATH + "nvm_dbg.conf";
    const std::string SERVICE_PROFILE = NVM_PATH + "NVM_ServiceProfile.xml";
    // ISE Posture and ZTA
    static std::string getLocalAppDataPath() {
        #ifdef _WIN32
            char* localAppData = nullptr;
            size_t len = 0;
            _dupenv_s(&localAppData, &len, "LOCALAPPDATA");
            if (localAppData) {
                std::string path = std::string(localAppData) + "\\Cisco\\Cisco Secure Client\\";
                free(localAppData);
                return path;
            }
            return "";
        #else
            return "";
        #endif
    }

    const std::string SECURECLIENT_LOCALAPPDATA = getLocalAppDataPath();
    const std::string SECURECLIENT_ISEFIREWALL = SECURECLIENT_BASE_HOME + "Secure Firewall Posture\\";
    const std::string SECURECLIENT_ISEFIREWALL_HOME = SECURECLIENT_LOCALAPPDATA  + "Secure Firewall Posture\\";
    const std::string SECURECLIENT_ZTA = SECURECLIENT_BASE  + "ZTA\\";
}

// Linux paths
namespace LinuxPaths {
    // Base directories
    const std::string SECURECLIENT_BASE = "/opt/cisco/secureclient/";
    const std::string NVM_PATH = SECURECLIENT_BASE + "NVM/";
    const std::string UMBRELLA_PATH = SECURECLIENT_BASE + "umbrella/";
    const std::string ZTA_PATH = SECURECLIENT_BASE + "zta/";

    // Executables
    const std::string NVM_AGENT = NVM_PATH + "bin/acnvmagent";
    const std::string UMBRELLA_AGENT = UMBRELLA_PATH + "acumbrellaagent";
    const std::string DART_CLI = "/opt/cisco/secureclient/dart/dartcli";
    // Config files
    const std::string DEBUG_CONF = NVM_PATH + "nvm_dbg.conf";
    const std::string SERVICE_PROFILE = NVM_PATH + "NVM_ServiceProfile.xml";
    const std::string ISE_POSTURE_LOG = "~/.cisco/iseposture/log";
    const std::string SECURE_FIREWALL_POSTURE_OPT = SECURECLIENT_BASE + "securefirewallposture";
    const std::string SECURE_FIREWALL_POSTURE_HOME = "~/.cisco/secureclient/securefirewallposture";
}

#endif // COMMON_H