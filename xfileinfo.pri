INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xfileinfo.h

SOURCES += \
    $$PWD/xfileinfo.cpp

!contains(XCONFIG, xformats) {
    XCONFIG += xformats
    include($$PWD/../Formats/xformats.pri)
}

DISTFILES += \
    $$PWD/xfileinfo.cmake

