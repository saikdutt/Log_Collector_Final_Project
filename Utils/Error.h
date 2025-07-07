#ifndef ERROR_H
#define ERROR_H
#include <string>

class LogCollectorError : public std::runtime_error {
public:
    enum ErrorType {
        SYSTEM_NOT_FOUND,
        PATH_NOT_FOUND,
        PERMISSION_DENIED,
        PROCESS_FAILED,
        FILE_ERROR,
        NETWORK_ERROR
    };

    LogCollectorError(ErrorType type, const std::string& message);
    ErrorType getType() const;
    static std::string getErrorTypeString(ErrorType type);

private:
    ErrorType errorType;
};

#endif // ERROR_H