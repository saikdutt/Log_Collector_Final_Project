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
    Utils/Common.cpp 
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
# Link stdc++fs for filesystem support if needed
if(APPLE)
    if(CMAKE_CXX_COMPILER_ID MATCHES "AppleClang|Clang|GNU")
        # Modern Apple Clang doesn't need stdc++fs
        if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1)
            target_link_libraries(LogCollector PRIVATE stdc++fs)
        endif()
    endif()
elseif(UNIX AND NOT APPLE)
    # Linux might still need stdc++fs
    target_link_libraries(LogCollector PRIVATE stdc++fs)
elseif(WIN32)
    target_compile_definitions(LogCollector PRIVATE
        _WIN32_WINNT=0x0601
        UNICODE
        _UNICODE
    )
endif()