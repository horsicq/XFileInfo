INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xfileinfo.h \
    $$PWD/xfileinfoitem.h \
    $$PWD/xfileinfomodel.h

SOURCES += \
    $$PWD/xfileinfo.cpp \
    $$PWD/xfileinfoitem.cpp \
    $$PWD/xfileinfomodel.cpp

!contains(XCONFIG, xformats) {
    XCONFIG += xformats
    include($$PWD/../Formats/xformats.pri)
}

DISTFILES += \
    $$PWD/xfileinfo.cmake

