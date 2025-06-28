cmake_minimum_required(VERSION 3.10)
project(LogCollector VERSION 1.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Define source files
set(SOURCES
    main.cpp
    Utils/Logger.cpp
    Utils/Error.cpp
    Collectors/BaseCollector.cpp
    Collectors/NVMLogCollector.cpp
    Collectors/SWGLogCollector.cpp
    Collectors/MacOS/Mac_collector.cpp 
    Collectors/Windows/Windows_collector.cpp
    Collectors/Linux/Linux_collector.cpp # Add this line
)

# Create executable
add_executable(LogCollector ${SOURCES})

# Add include directories
target_include_directories(LogCollector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/Utils
    ${CMAKE_CURRENT_SOURCE_DIR}/Collectors
)
find_package(CURL REQUIRED)
find_package(JsonCpp REQUIRED)
target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
    CURL::libcurl 
    JsonCpp::JsonCpp
)
# Check compiler and version for filesystem support
if(APPLE)
    if(CMAKE_CXX_COMPILER_ID MATCHES "AppleClang|Clang|GNU")
        if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1)
            target_link_libraries(LogCollector PRIVATE stdc++fs)
        endif()
    endif()
    
elseif(UNIX AND NOT APPLE)
    target_link_libraries(LogCollector PRIVATE stdc++fs)
endif()