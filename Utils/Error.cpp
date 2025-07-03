#include "Error.h"

LogCollectorError::LogCollectorError(ErrorType type, const std::string& message)
    : std::runtime_error(message), errorType(type) {}

LogCollectorError::ErrorType LogCollectorError::getType() const {
    return errorType;
}

std::string LogCollectorError::getErrorTypeString(ErrorType type) {
    switch (type) {
        case SYSTEM_NOT_FOUND:
            return "System Component Not Found";
        case PATH_NOT_FOUND:
            return "Path Not Found";
        case PERMISSION_DENIED:
            return "Permission Denied";
        case PROCESS_FAILED:
            return "Process Execution Failed";
        case FILE_ERROR:
            return "File Operation Error";
        case NETWORK_ERROR:
            return "Network Operation Error";
        default:
            return "Unknown Error";
    }
}