include_directories(${CMAKE_CURRENT_LIST_DIR})

include(${CMAKE_CURRENT_LIST_DIR}/xfileinfo.cmake)

set(XFILEINFOWIDGET_SOURCES
    ${XFILEINFO_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xfileinfowidget.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xfileinfowidget.ui
    ${CMAKE_CURRENT_LIST_DIR}/dialogxfileinfoprocess.cpp
    ${CMAKE_CURRENT_LIST_DIR}/dialogxfileinfoprocess.ui
    ${CMAKE_CURRENT_LIST_DIR}/dialogxfileinfo.cpp
    ${CMAKE_CURRENT_LIST_DIR}/dialogxfileinfo.ui
)
