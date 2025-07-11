#ifndef ERROR_H
#define ERROR_H

#include <string>
#include <stdexcept>

class LogCollectorError : public std::runtime_error {
public:
    enum ErrorType {
        SUCCESSFULLY_RUN = 0,
        PATH_NOT_FOUND = 1,
        COMMAND_FAILED = 2,
        PERMISSION_DENIED = 3,
        FILE_NOT_FOUND = 4
    };

    LogCollectorError(ErrorType type, const std::string& message);
    ErrorType getType() const;
    static std::string getErrorTypeString(ErrorType type);

private:
    ErrorType errorType;
};

#endif // ERROR_H
