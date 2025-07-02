#include "Common.h"
std::atomic<bool> g_stopCollection{false};

void signalHandler(int signum) {
    if (signum == SIGINT) {
        g_stopCollection = true;
    }
}
std::string SYSTEM_NVM_PATH;
std::string CONF_FILE;
std::string XML_FILE;
