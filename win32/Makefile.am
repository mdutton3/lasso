SUBDIRS = nsis

EXTRA_DIST = lasso.rc

.PHONY = all dll install-dll

all: dll

dll:
	/usr/bin/windres -i lasso.rc -o lasso.rc.o
	mkdir -p .libs
	gcc -mno-cygwin -shared -o .libs/lasso.dll \
            -Wl,--out-implib=.libs/lasso.a \
            -Wl,--add-stdcall-alias \
            -Wl,--export-all-symbols \
            lasso.rc.o \
            -Wl,--enable-auto-import \
            -Wl,--whole-archive \
                ../lasso/lasso.o \
                ../lasso/xml/.libs/liblasso-xml.al \
                ../lasso/protocols/.libs/liblasso-protocols.al \
                ../lasso/environs/.libs/liblasso-environs.al \
            -Wl,--no-whole-archive -L/usr/local/lib \
                -lgobject-2.0 -lglib-2.0 -lxmlsec-openssl -lxmlsec \
                -lssl -lcrypto \
                -lxslt -lxml2 \
                -lpthread -lz -lm

            
install-dll:        
	cp -f .libs/lasso.dll /usr/local/lib
	cp -f .libs/lasso.a /usr/local/lib
	mkdir -p /usr/local/include/lasso
	cp -f ../lasso/*.h /usr/local/include/lasso
	mkdir -p /usr/local/include/lasso/environs
	cp -f ../lasso/environs/*.h /usr/local/include/lasso/environs
	mkdir -p /usr/local/include/lasso/protocols
	cp -f ../lasso/protocols/*.h /usr/local/include/lasso/protocols
	mkdir -p /usr/local/include/lasso/protocols/elements
	cp -f ../lasso/protocols/elements/*.h /usr/local/include/lasso/protocols/elements
	mkdir -p /usr/local/include/lasso/xml
	cp -f ../lasso/xml/*.h /usr/local/include/lasso/xml

