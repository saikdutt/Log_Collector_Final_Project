#include "ISEPostureCollector.h"
#include <filesystem>

namespace fs = std::filesystem;

ISEPostureCollector::ISEPostureCollector(
    const std::map<std::string, std::string>& config, 
    std::shared_ptr<Logger> logger)
    : BaseCollector(config, logger) {

    logger->info("ISEPostureCollector initialized");
}
