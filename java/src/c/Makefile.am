if MINGW
JAVA_CFLAGS = -mno-cygwin -mwindows -D_MSC_VER=1 \
    -D_WIN32 -DWIN32 -DLASSO_DEBUG \
    -I$(top_srcdir) \
    -I. -g \
    -I/usr/local/include \
    -I/usr/local/include/glib-2.0 -I/usr/local/lib/glib-2.0/include \
    -I/usr/local/include/libxml2 \
    -DXMLSEC_CRYPTO="openssl" -DXMLSEC_LIBXML_260=1 \
    -D__XMLSEC_FUNCTION__=__FUNCTION__ -DXMLSEC_NO_XKMS=1 \
    -DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1 -DXMLSEC_CRYPTO_OPENSSL=1 
else
JAVA_CFLAGS = \
    -g \
    -I. -I/opt/jdk/include -I/opt/jdk/include/linux \
    -I$(top_srcdir) \
    -I/usr/include/libxml2 \
    -I/usr/include/glib-2.0 \
    -I/usr/lib/glib-2.0/include \
    -DXMLSEC_LIBXML_260=1 -D__XMLSEC_FUNCTION__=__FUNCTION__ -DXMLSEC_NO_XKMS=1 -DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1 -I/usr/include/xmlsec1 -I/usr/include/libxml2 -DXMLSEC_CRYPTO_OPENSSL=1 -DXMLSEC_CRYPTO=\"openssl\"
endif
C_SOURCE = ${wildcard *.c}
C_OBJECT = ${C_SOURCE:.c=.o}

.PHONY: clean all

all: ${C_OBJECT}

%.o: %.c %.h
	${CC} $(JAVA_CFLAGS) -c $<

clean:
	rm -f ${C_OBJECT} *~
