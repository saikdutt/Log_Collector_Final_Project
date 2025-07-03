#ifndef NVM_LOG_COLLECTOR_H
#define NVM_LOG_COLLECTOR_H

#include <string>
#include <memory>
#include "BaseCollector.h"

class NVMLogCollector : public virtual BaseCollector {
protected:
    std::string nvm_version;
public:
    NVMLogCollector(const std::map<std::string, std::string>& config, 
                  std::shared_ptr<Logger> logger);
};

#endif // NVM_LOG_COLLECTOR_H
