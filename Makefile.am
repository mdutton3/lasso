dll:
	-/usr/bin/windres -i lasso/lasso.rc -o lasso/lasso.rc.o
	-/usr/bin/dllwrap.exe --target=i386-mingw32 --def lasso/lasso.def -o lasso/.libs/liblasso.dll -mno-cygwin --add-stdcall-alias -mwindows -s lasso/lasso.o lasso/lasso.rc.o lasso/xml/.libs/liblasso-xml.al lasso/protocols/.libs/liblasso-protocols.al lasso/environs/.libs/liblasso-environs.al -L/usr/local/lib /usr/local/lib/libglib-2.0-0.dll /usr/local/lib/libxmlsec-openssl.dll /usr/local/lib/libxmlsec.dll -lssl -lcrypto /usr/local/lib/libxslt.dll /usr/local/lib/libxml2.dll -lpthread -lz -lm /usr/local/lib/libgobject-2.0-0.dll
install-dll:        
	-cp -f lasso/.libs/liblasso.dll /usr/local/lib
	-cp -f lasso/.libs/liblasso.a /usr/local/lib/liblasso.dll.a
	-mkdir -p /usr/local/include/lasso
	-cp -f lasso/*.h /usr/local/include/lasso
	-mkdir -p /usr/local/include/lasso/environs
	-cp -f lasso/environs/*.h /usr/local/include/lasso/environs
	-mkdir -p /usr/local/include/lasso/protocols
	-cp -f lasso/protocols/*.h /usr/local/include/lasso/protocols
	-mkdir -p /usr/local/include/lasso/protocols/elements
	-cp -f lasso/protocols/elements/*.h /usr/local/include/lasso/protocols/elements
	-mkdir -p /usr/local/include/lasso/xml
	-cp -f lasso/xml/*.h /usr/local/include/lasso/xml



SUBDIRS		= lasso docs

ABS_BUILDDIR	= $(shell pwd)

EXTRA_DIST	= TODO COPYING


pkgconfig_DATA	= lasso.pc
pkgconfigdir	= $(libdir)/pkgconfig
