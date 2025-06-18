#include "SWGLogCollector.h"
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;

SWGLogCollector::SWGLogCollector(
    const std::map<std::string, std::string>& config, 
    std::shared_ptr<Logger> logger,
    bool enable_debug_logs,
    int debug_level)
    : BaseCollector(config, logger),
      enable_debug_logs(enable_debug_logs),
      debug_level(debug_level) {
    
    logger->debug("SWGLogCollector initialized");
}
