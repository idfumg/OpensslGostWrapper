CONFIG += link_pkgconfig
PKGCONFIG += libcrypto

LIBS += -L$$shadowed($$PWD) -lopenssl-helper -ldl -pthread

INCLUDEPATH += $$PWD
DEPENDPATH = $$INCLUDEPATH
