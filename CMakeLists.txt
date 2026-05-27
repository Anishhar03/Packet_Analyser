cmake_minimum_required(VERSION 3.16)

project(PacketAnalyzer
    VERSION 2.0.0
    DESCRIPTION "Offline packet analyzer with DPI filtering and HTML reporting"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(packet_analyzer
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

target_include_directories(packet_analyzer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(MSVC)
    target_compile_options(packet_analyzer PRIVATE /W4)
else()
    target_compile_options(packet_analyzer PRIVATE -Wall -Wextra -Wpedantic)
    find_package(Threads REQUIRED)
    target_link_libraries(packet_analyzer PRIVATE Threads::Threads)
endif()

enable_testing()
add_test(
    NAME sample_analysis
    COMMAND $<TARGET_FILE:packet_analyzer>
            analyze
            ${CMAKE_CURRENT_SOURCE_DIR}/test_dpi.pcap
            --output ${CMAKE_CURRENT_BINARY_DIR}/reports/filtered.pcap
            --json ${CMAKE_CURRENT_BINARY_DIR}/reports/analysis.json
            --csv ${CMAKE_CURRENT_BINARY_DIR}/reports/flows.csv
            --html ${CMAKE_CURRENT_BINARY_DIR}/reports/dashboard.html
            --block-app YouTube
            --quiet
)

install(TARGETS packet_analyzer RUNTIME DESTINATION bin)
