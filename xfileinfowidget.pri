INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xfileinfowidget.h

SOURCES += \
    $$PWD/xfileinfowidget.cpp

FORMS += \
    $$PWD/xfileinfowidget.ui

!contains(XCONFIG, xformats) {
    XCONFIG += xformats
    include($$PWD/xfileinfo.pri)
}

DISTFILES += \
    $$PWD/xfileinfowidget.cmake
