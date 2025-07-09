#ifndef LOGGER_H
#define LOGGER_H

#include <fstream>
#include <iostream>

class Logger;

// Logger class definition
class Logger {
private:
    std::string log_file;
    std::ofstream log_stream;
    std::mutex log_mutex;
    
    enum LogLevel {
        DEBUG,
        INFO,
        WARNING,
        ERROR,
        CRITICAL
    };
    
    std::string get_timestamp();
    void log(LogLevel level, const std::string& message);

public:
    Logger(const std::string& log_file);
    ~Logger();
    
    void debug(const std::string& message);
    void info(const std::string& message);
    void warning(const std::string& message);
    void error(const std::string& message);
    void critical(const std::string& message);
};

#endif