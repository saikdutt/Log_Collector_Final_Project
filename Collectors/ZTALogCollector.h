#ifndef ZTA_LOG_COLLECTOR_H
#define ZTA_LOG_COLLECTOR_H

#include "BaseCollector.h"
#include "../Utils/Error.h"
class ZTACollector : public virtual BaseCollector {
public:
    ZTACollector(const std::map<std::string, std::string>& config, 
               std::shared_ptr<Logger> logger);

    virtual LogCollectorError::ErrorType createAllFilesZTA() = 0;
    virtual LogCollectorError::ErrorType deleteAllFilesZTA() = 0;
    virtual LogCollectorError::ErrorType collectZtaLogs() = 0;
    virtual LogCollectorError::ErrorType stopZtaLogs() = 0;
};

#endif // ZTA_LOG_COLLECTOR_H