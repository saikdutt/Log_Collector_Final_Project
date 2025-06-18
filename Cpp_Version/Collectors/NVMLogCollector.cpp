#include "NVMLogCollector.h"
#include "NVMLogCollector.h"
#if defined(__APPLE__) || defined(__linux__)
    #if __cplusplus >= 201703L && __has_include(<filesystem>)
        #include <filesystem>
        namespace fs = std::filesystem;
    #else
        #include <experimental/filesystem>
        namespace fs = std::experimental::filesystem;
    #endif
#elif defined(_WIN32)
    #include <filesystem>
    namespace fs = std::filesystem;
#endif
#include <fstream>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <regex>
#include <thread>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
// Using std::filesystem directly instead of namespace alias
NVMLogCollector::NVMLogCollector(
    const std::map<std::string, std::string>& config, 
    std::shared_ptr<Logger> logger,
    bool enable_debug_logs,
    int debug_level,
    const std::string& nvm_version)
    : BaseCollector(config, logger),
      enable_debug_logs(enable_debug_logs),
      debug_level(debug_level),
      kdf_flags_set(false),
      packet_capture_enabled(false),
      enable_kdf_logging(false),
      nvm_version(nvm_version) {
    
    logger->debug("NVMLogCollector initialized with NVM version: " + nvm_version);
}