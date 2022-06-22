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

!contains(XCONFIG, xdialogprocess) {
    XCONFIG += xdialogprocess
    include($$PWD/../FormatDialogs/xdialogprocess.pri)
}

DISTFILES += \
    $$PWD/xfileinfowidget.cmake
