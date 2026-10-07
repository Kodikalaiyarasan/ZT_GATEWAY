cmake_minimum_required(VERSION 3.16)
project(zt-data-plane-proxy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Find system-installed libcurl ─────────────────────────────
find_package(CURL REQUIRED)

# ── Fetch header-only dependencies ────────────────────────────
include(FetchContent)

FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG        v0.15.3
)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)

FetchContent_MakeAvailable(httplib nlohmann_json)

# ── Build the proxy executable ────────────────────────────────
add_executable(zt_proxy main.cpp)

target_link_libraries(zt_proxy
    PRIVATE
        httplib::httplib
        nlohmann_json::nlohmann_json
        CURL::libcurl
        pthread
)

target_compile_options(zt_proxy PRIVATE -Wall -Wextra -O2)
