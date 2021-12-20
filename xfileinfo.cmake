include_directories(${CMAKE_CURRENT_LIST_DIR})

include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xformats.cmake)

set(XFILEINFO_SOURCES
    ${XFORMATS_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xfileinfo.cpp
)
