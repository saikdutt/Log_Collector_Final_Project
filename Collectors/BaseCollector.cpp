#include "BaseCollector.h"
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

BaseCollector::BaseCollector(const std::map<std::string, std::string>& config, std::shared_ptr<Logger> logger)
    : config(config), logger(logger), log_path("") {
    if (logger == nullptr) {
        throw std::runtime_error("Logger cannot be null");
    }
    logger->debug("BaseCollector initialized");
}

