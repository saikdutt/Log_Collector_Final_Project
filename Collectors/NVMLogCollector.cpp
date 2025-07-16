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
      nvm_version(nvm_version) {
    
    logger->info("NVMLogCollector initialized");
}