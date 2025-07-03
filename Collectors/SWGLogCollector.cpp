#include "SWGLogCollector.h"
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;

SWGLogCollector::SWGLogCollector(
    const std::map<std::string, std::string>& config, 
    std::shared_ptr<Logger> logger)
    : BaseCollector(config, logger) {

    logger->debug("SWGLogCollector initialized");
}
