#ifndef SWG_COLLECTOR_H
#define SWG_COLLECTOR_H

#include <string>
#include <memory>
#include "BaseCollector.h"

class SWGLogCollector : public virtual BaseCollector {
public:
    SWGLogCollector(const std::map<std::string, std::string>& config, 
                std::shared_ptr<Logger> logger);
};
#endif // SWG_COLLECTOR_H