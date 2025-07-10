#ifndef ISE_POSTURE_COLLECTOR_H
#define ISE_POSTURE_COLLECTOR_H

#include <string>
#include <memory>
#include "BaseCollector.h"

class ISEPostureCollector : public virtual BaseCollector {
public:
    ISEPostureCollector(const std::map<std::string, std::string>& config, 
                     std::shared_ptr<Logger> logger);

    virtual void createAllFilesISEPosture() = 0;
    virtual void deleteAllFilesISEPosture() = 0;
    virtual void collectIsePostureLogs() = 0;
    virtual void stopIsePostureLogs() = 0;
};

#endif // ISE_POSTURE_COLLECTOR_H