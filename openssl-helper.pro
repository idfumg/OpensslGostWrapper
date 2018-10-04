TEMPLATE = lib
CONFIG += staticlib link_pkgconfig
CONFIG -= qt
LIBS += -ldl

QMAKE_LINK = $$QMAKE_LINK_C
QMAKE_LFLAGS_RPATH =
QMAKE_CFLAGS += -Wall -Wextra -std=c99
QMAKE_CFLAGS_DEBUG += -O0 -ggdb -fno-inline -fno-omit-frame-pointer
QMAKE_CFLAGS_RELEASE += -O2

HEADERS = openssl-helper.h
SOURCES = openssl-helper.c

unix {
    headers.path = /usr/include/openssl-helper
    headers.files += $$HEADERS
    INSTALLS += headers
    target.path = /usr/lib
    INSTALLS += target
}
