INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xfileinfo.h \
    $$PWD/xfileinfoitem.h \
    $$PWD/xfileinfomodel.h \
    $$PWD/xfileinfovalues.h

SOURCES += \
    $$PWD/xfileinfo.cpp \
    $$PWD/xfileinfoitem.cpp \
    $$PWD/xfileinfomodel.cpp \
    $$PWD/xfileinfovalues.cpp

!contains(XCONFIG, xformats) {
    XCONFIG += xformats
    include($$PWD/../Formats/xformats.pri)
}

!contains(XCONFIG, xoptions) {
    XCONFIG += xoptions
    include($$PWD/../XOptions/xoptions.pri)
}

!contains(XCONFIG, xdisasmcore) {
    XCONFIG += xdisasmcore
    include($$PWD/../XDisasmCore/xdisasmcore.pri)
}

!contains(XCONFIG, specabstract) {
    XCONFIG += specabstract
    include($$PWD/../SpecAbstract/specabstract.pri)
}

!contains(XCONFIG, die_script) {
    XCONFIG += die_script
    include($$PWD/../die_script/die_script.pri)
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
