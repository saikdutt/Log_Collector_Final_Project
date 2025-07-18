#ifndef BASE_COLLECTOR_H
#define BASE_COLLECTOR_H

#include <string>
#include <map>
#include <memory>
#if __has_include(<filesystem>)
    #include <filesystem>
    namespace fs = std::filesystem;
#else
    #include <experimental/filesystem>
    namespace fs = std::experimental::filesystem;
#endif
#include "../Utils/Logger.h"

class BaseCollector {
protected:
    std::map<std::string, std::string> config;
    std::shared_ptr<Logger> logger;
    std::string log_path;

public:
    BaseCollector(const std::map<std::string, std::string>& config, std::shared_ptr<Logger> logger);
    //virtual void cleanup_logs(bool keep_source = false);

    virtual ~BaseCollector() = default;
};

#endif // BASE_COLLECTOR_H
