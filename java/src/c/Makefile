CFLAGS = \
    -g \
    -I. -I/opt/jdk/include -I/opt/jdk/include/linux \
    -I../../.. \
    -I/usr/include/libxml2 \
    -I/usr/include/glib-2.0 \
    -I/usr/lib/glib-2.0/include \
    -DXMLSEC_LIBXML_260=1 -D__XMLSEC_FUNCTION__=__FUNCTION__ -DXMLSEC_NO_XKMS=1 -DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1 -I/usr/include/xmlsec1 -I/usr/include/libxml2 -DXMLSEC_CRYPTO_OPENSSL=1 -DXMLSEC_CRYPTO=\"openssl\"

C_SOURCE = ${wildcard *.c}
C_OBJECT = ${C_SOURCE:.c=.o}

.PHONY: clean all

all: ${C_OBJECT}

%.o: %.c %.h
	${CC} $(CFLAGS) -c $<

clean:
	rm -f ${C_OBJECT} *~
