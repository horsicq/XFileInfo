INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/dialogxfileinfo.h \
    $$PWD/xfileinfowidget.h

SOURCES += \
    $$PWD/dialogxfileinfo.cpp \
    $$PWD/xfileinfowidget.cpp

FORMS += \
    $$PWD/dialogxfileinfo.ui \
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
    $$PWD/LICENSE \
    $$PWD/README.md \
    $$PWD/xfileinfowidget.cmake
