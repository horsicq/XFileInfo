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

contains(XCONFIG, use_capstone_x86) {
    !contains(XCONFIG, xcapstone_x86) {
        XCONFIG += xcapstone_x86
        include($$PWD/../XCapstone/xcapstone_x86.pri)
    }
}

!contains(XCONFIG, use_capstone_x86) {
    !contains(XCONFIG, xcapstone) {
        XCONFIG += xcapstone
        include($$PWD/../XCapstone/xcapstone.pri)
    }
}

DISTFILES += \
    $$PWD/LICENSE \
    $$PWD/README.md \
    $$PWD/xfileinfo.cmake

