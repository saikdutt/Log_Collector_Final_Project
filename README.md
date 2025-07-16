# Cisco Secure Client Log Collector

## Description
A comprehensive diagnostic tool for collecting logs from various Cisco Secure Client components across macOS, Windows, and Linux platforms. The tool provides automated log collection, debug configuration, and organized output for troubleshooting purposes.

## Features
- **Cross-Platform Support**
  - macOS
  - Windows
  - Linux

- **Component Log Collection**
  - Network Visibility Module (NVM)
  - Kernel Driver Framework (KDF)
  - Secure Web Gateway (SWG)/Umbrella
  - Identity Services Engine (ISE) Posture
  - Zero Trust Architecture (ZTA)

- **Advanced Debug Options**
  - Debug flag configuration
  - KDF debug level settings
  - Troubleshooting tag management
  - Service profile backup/restore

- **Log Collection Features**
  - Real-time process monitoring
  - System log capture
  - Packet capture capabilities
  - Version information retrieval
  - Agent process management

## Prerequisites
- Administrative/root privileges
- Cisco Secure Client installation
- C++17 compatible compiler
- CMake 3.10 or higher

## Building the Project
```bash
# Create build directory
mkdir -p build
cd build

# Generate build files
cmake ..

# Compile
make
```

## Usage
```bash
# Run with administrative privileges
sudo ./LogCollector
```

## Project Structure
```
├── Collectors/
│   ├── BaseCollector
│   ├── NVMLogCollector
│   ├── SWGLogCollector
│   ├── ISEPostureCollector
│   ├── ZTALogCollector
│   ├── MacOS/
│   ├── Windows/
│   └── Linux/
├── Utils/
│   ├── Logger
│   ├── Common
│   └── Error
└── main.cpp
```

## Log Collection Process
1. Administrative privilege verification
2. Component version detection
3. Debug flag configuration
4. Log collection initiation
5. Process monitoring and management
6. Log organization and archiving

## Logging System
- **Thread Safety**: Implemented thread-safe logging for concurrent operations
- **Log Levels**
  - INFO: General operational information
  - DEBUG: Detailed debugging information
  - WARNING: Non-critical issues and warnings
  - ERROR: Critical issues requiring attention
- **Features**
  - Timestamp-based logging
  - Component-specific log channels
  - File and console output support
  - Log rotation and archival

## Security Considerations
- **Administrative Privileges**
  - Verification on startup
  - Elevated permissions for system operations
  - Secure privilege dropping when possible
- **File Operations**
  - Secure file handling
  - Permission-based access control
  - Safe configuration management
- **Process Management**
  - Secure process monitoring
  - Safe termination procedures
  - Resource cleanup

## Output
- All collected logs are organized in a timestamped directory
- Logs are archived in a ZIP file on the Desktop
- Includes debug configurations and system information

## Error Handling
- Comprehensive error type system
- Detailed logging of all operations
- Graceful failure handling

## License
This project is proprietary and confidential.

## Author
Saikat Dutta

---

**Note**: This tool requires administrative privileges and should be used in accordance with your organization's security policies.
