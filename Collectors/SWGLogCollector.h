#ifndef SWG_COLLECTOR_H
#define SWG_COLLECTOR_H

#include <string>
#include <memory>
#include "BaseCollector.h"
#include "../Utils/Error.h"
class SWGLogCollector : public virtual BaseCollector {
public:
    SWGLogCollector(const std::map<std::string, std::string>& config, 
                std::shared_ptr<Logger> logger);
    
    virtual LogCollectorError::ErrorType createSWGConfigOverride() = 0;
    virtual LogCollectorError::ErrorType deleteSWGConfigOverride() = 0;
    virtual LogCollectorError::ErrorType collectUmbrellaLogs() = 0;
    virtual LogCollectorError::ErrorType stopUmbrellaLogs() = 0;
};
#endif // SWG_COLLECTOR_H