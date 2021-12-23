INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/dialogxfileinfoprocess.h \
    $$PWD/xfileinfowidget.h

SOURCES += \
    $$PWD/dialogxfileinfoprocess.cpp \
    $$PWD/xfileinfowidget.cpp

FORMS += \
    $$PWD/dialogxfileinfoprocess.ui \
    $$PWD/xfileinfowidget.ui

!contains(XCONFIG, xformats) {
    XCONFIG += xformats
    include($$PWD/xfileinfo.pri)
}

DISTFILES += \
    $$PWD/xfileinfowidget.cmake
