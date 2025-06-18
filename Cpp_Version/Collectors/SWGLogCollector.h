#ifndef SWG_COLLECTOR_H
#define SWG_COLLECTOR_H

#include <string>
#include <memory>
#include "BaseCollector.h"

class SWGLogCollector : public virtual BaseCollector {
protected:
    bool enable_debug_logs;
    int debug_level;

public:

    SWGLogCollector(const std::map<std::string, std::string>& config, 
                std::shared_ptr<Logger> logger,
                bool enable_debug_logs = false,
                int debug_level = 0);
};

#endif // SWG_COLLECTOR_H