#ifndef ISE_POSTURE_COLLECTOR_H
#define ISE_POSTURE_COLLECTOR_H

#include <string>
#include <memory>
#include "BaseCollector.h"
#include "../Utils/Error.h"
class ISEPostureCollector : public virtual BaseCollector {
public:
    ISEPostureCollector(const std::map<std::string, std::string>& config, 
                     std::shared_ptr<Logger> logger);
    virtual ~ISEPostureCollector() = default;
    virtual LogCollectorError::ErrorType createAllFilesISEPosture() = 0;
    virtual LogCollectorError::ErrorType deleteAllFilesISEPosture() = 0;
    virtual LogCollectorError::ErrorType collectIsePostureLogs() = 0;
    virtual LogCollectorError::ErrorType stopIsePostureLogs() = 0;
};

#endif // ISE_POSTURE_COLLECTOR_H