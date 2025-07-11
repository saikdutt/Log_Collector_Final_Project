#include "Logger.h"
#include <sstream>
#include <iomanip>
#include <ctime>
std::string Logger::get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto now_tm = *std::localtime(&now_time_t);
    
    std::stringstream ss;
    ss << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void Logger::log(LogLevel level, const std::string& message) {
    std::string level_str;
    switch (level) {
        case DEBUG: level_str = "DEBUG"; break;
        case INFO: level_str = "INFO"; break;
        case WARNING: level_str = "WARNING"; break;
        case ERROR: level_str = "ERROR"; break;
        case CRITICAL: level_str = "CRITICAL"; break;
        default: level_str = "UNKNOWN"; break;
    }
    
    std::string log_message = get_timestamp() + " [" + level_str + "] " + message;
    
    std::lock_guard<std::mutex> lock(log_mutex);
    log_stream << log_message << std::endl;
    log_stream.flush();
    
    // Also print to console
    std::cout << log_message << std::endl;
}

Logger::Logger(const std::string& log_file) : log_file(log_file) {
    log_stream.open(log_file, std::ios::out | std::ios::app);
    if (!log_stream.is_open()) {
        throw std::runtime_error("Failed to open log file: " + log_file);
    }
    log(INFO, "Logger initialized");
}

Logger::~Logger() {
    if (log_stream.is_open()) {
        log(INFO, "Logger shutting down");
        log_stream.close();
    }
}

void Logger::debug(const std::string& message) { log(DEBUG, message); }
void Logger::info(const std::string& message) { log(INFO, message); }
void Logger::warning(const std::string& message) { log(WARNING, message); }
void Logger::error(const std::string& message) { log(ERROR, message); }
void Logger::critical(const std::string& message) { log(CRITICAL, message); }