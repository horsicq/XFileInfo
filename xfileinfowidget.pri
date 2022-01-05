INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/dialogxfileinfo.h \
    $$PWD/dialogxfileinfoprocess.h \
    $$PWD/xfileinfowidget.h

SOURCES += \
    $$PWD/dialogxfileinfo.cpp \
    $$PWD/dialogxfileinfoprocess.cpp \
    $$PWD/xfileinfowidget.cpp

FORMS += \
    $$PWD/dialogxfileinfo.ui \
    $$PWD/dialogxfileinfoprocess.ui \
    $$PWD/xfileinfowidget.ui

!contains(XCONFIG, xfileinfo) {
    XCONFIG += xfileinfo
    include($$PWD/xfileinfo.pri)
}

DISTFILES += \
    $$PWD/xfileinfowidget.cmake
