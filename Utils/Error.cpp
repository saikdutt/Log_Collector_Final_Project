#include "Error.h"

LogCollectorError::LogCollectorError(ErrorType type, const std::string& message)
    : std::runtime_error(message), errorType(type) {}

LogCollectorError::ErrorType LogCollectorError::getType() const {
    return errorType;
}

std::string LogCollectorError::getErrorTypeString(ErrorType type) {
    switch (type) {
        case SUCCESSFULLY_RUN:
            return "0: Successfully Run";
        case PATH_NOT_FOUND:
            return "1: Path Not Found";
        case COMMAND_FAILED:
            return "2: Command Failed to Run";
        case PERMISSION_DENIED:
            return "3: Permission Denied";
        case FILE_NOT_FOUND:
            return "4: File Not Found";
        default:
            return "Unknown Error";
    }
}
