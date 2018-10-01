TEMPLATE=app
TARGET=test

CONFIG -= qt

include($$PWD/../openssl-helper.pri)

QMAKE_LINK = $$QMAKE_LINK_C
QMAKE_LFLAGS_RPATH =
QMAKE_CFLAGS += -Wall -Wextra -std=c99
QMAKE_CFLAGS_DEBUG += -O0 -ggdb
QMAKE_CFLAGS_RELEASE +=

SOURCES = openssl-helper-test.c
