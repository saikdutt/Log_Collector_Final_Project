#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <signal.h>
extern std::atomic<bool> g_stopCollection;

void signalHandler(int signum);
extern std::string SYSTEM_NVM_PATH;
extern std::string CONF_FILE;
extern std::string XML_FILE;


#endif // COMMON_H