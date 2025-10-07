cmake_minimum_required(VERSION 3.19)
project(OnvifRtspBrowser LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Qt 자동 MOC/UIC/RCC
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Qt6 우선, 없으면 Qt5
find_package(Qt6 COMPONENTS Widgets Network Concurrent QUIET)
if(NOT Qt6_FOUND)
  find_package(Qt5 COMPONENTS Widgets Network Concurrent REQUIRED)
  set(USE_QT5 ON)
endif()

find_package(OpenCV REQUIRED)

# ---- tinyxml2: CONFIG → pkg-config → FetchContent ----
find_package(tinyxml2 CONFIG QUIET)
if(NOT tinyxml2_FOUND)
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(TINYXML2 QUIET tinyxml2)
    if(TINYXML2_FOUND)
      add_library(tinyxml2::tinyxml2 INTERFACE IMPORTED)
      set_target_properties(tinyxml2::tinyxml2 PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${TINYXML2_INCLUDE_DIRS}"
        INTERFACE_LINK_LIBRARIES "${TINYXML2_LINK_LIBRARIES}")
    endif()
  endif()
endif()

if(NOT TARGET tinyxml2::tinyxml2)
  include(FetchContent)
  FetchContent_Declare(
    tinyxml2
    GIT_REPOSITORY https://github.com/leethomason/tinyxml2.git
    GIT_TAG        10.0.0
  )
  FetchContent_MakeAvailable(tinyxml2)
endif()

add_executable(onvif_browser
  src/main.cpp
)

if(USE_QT5)
  target_link_libraries(onvif_browser PRIVATE
    Qt5::Widgets Qt5::Network Qt5::Concurrent
    ${OpenCV_LIBS} tinyxml2::tinyxml2
  )
else()
  target_link_libraries(onvif_browser PRIVATE
    Qt6::Widgets Qt6::Network Qt6::Concurrent
    ${OpenCV_LIBS} tinyxml2::tinyxml2
  )
endif()

# 윈도우 소켓
if(WIN32)
  target_link_libraries(onvif_browser PRIVATE ws2_32)
endif()

# 경고 레벨
if(MSVC)
  target_compile_options(onvif_browser PRIVATE /W4)
else()
  target_compile_options(onvif_browser PRIVATE -Wall -Wextra -Wpedantic)
endif()
