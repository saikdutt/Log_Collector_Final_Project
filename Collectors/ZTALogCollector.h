#ifndef ZTA_LOG_COLLECTOR_H
#define ZTA_LOG_COLLECTOR_H

#include "BaseCollector.h"

class ZTACollector : public virtual BaseCollector {
public:
    ZTACollector(const std::map<std::string, std::string>& config, 
               std::shared_ptr<Logger> logger);
};

#endif // ZTA_LOG_COLLECTOR_H