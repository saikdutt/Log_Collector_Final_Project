#ifndef ISE_POSTURE_COLLECTOR_H
#define ISE_POSTURE_COLLECTOR_H

#include <string>
#include <memory>
#include "BaseCollector.h"

class ISEPostureCollector : public virtual BaseCollector {
public:
    ISEPostureCollector(const std::map<std::string, std::string>& config, 
                     std::shared_ptr<Logger> logger);
};

#endif // ISE_POSTURE_COLLECTOR_H