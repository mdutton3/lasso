dll:
	-/usr/bin/windres -i win32/lasso.rc -o win32/lasso.rc.o
	-mkdir -p win32/.libs
	#-dlltool.exe --dllname liblasso.dll --def win32/lasso.def \
            --output-lib win32/.libs/liblasso.a
	-/usr/bin/dllwrap.exe --target=i386-mingw32 --def win32/lasso.def \
            -o win32/.libs/liblasso.dll -mno-cygwin --add-stdcall-alias \
            lasso/lasso.o win32/lasso.rc.o \
            lasso/xml/.libs/liblasso-xml.al \
            lasso/protocols/.libs/liblasso-protocols.al \
            lasso/environs/.libs/liblasso-environs.al \
            -L/usr/local/lib -lglib-2.0 -lgobject-2.0 \
            -lxmlsec-openssl -lxmlsec \
            -lssl -lcrypto \
            -lxslt -lxml2 \
            -lpthread -lz -lm \
            --output-lib win32/.libs/liblasso.a \
            --dllname liblasso.dll 

            
install-dll:        
	-cp -f win32/.libs/liblasso.dll /usr/local/lib
	-cp -f win32/.libs/liblasso.a /usr/local/lib
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

SUBDIRS		= lasso docs python win32

ABS_BUILDDIR	= $(shell pwd)

EXTRA_DIST	= TODO COPYING lasso.pc.in


pkgconfig_DATA	= lasso.pc
pkgconfigdir	= $(libdir)/pkgconfig
