include_directories(${CMAKE_CURRENT_LIST_DIR})

include(${CMAKE_CURRENT_LIST_DIR}/xfileinfo.cmake)

set(XFILEINFOWIDGET_SOURCES
    ${XFILEINFO_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xfileinfowidget.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xfileinfowidget.ui
)