NULL = 
TARGET=target
#JAVAC=/usr/lib/kaffe/bin/javac
#JAVAH=/usr/lib/kaffe/bin/javah
#JAVAH_CLASSPATH_PREFIX=/usr/share/kaffe/Klasses.jar:
#JAR=/usr/lib/kaffe/bin/jar


C_SOURCE_DIR=../c
C_SOURCE=${wildcard ${C_SOURCE_DIR}/*.c}
C_BUILD_DIR=${C_SOURCE_DIR}
C_OBJECT=${C_SOURCE:.c=.o}
if MINGW
# JAVA_LDFLAGS=-L/usr/local/lib -lgobject-2.0-0 -lglib-2.0-0 -llasso 
    LASSO_DLL=${TARGET}/jlasso.dll
else
# JAVA_LDFLAGS=-lgobject-2.0 -lglib-2.0 -llasso 
    LASSO_SO=${TARGET}/libjlasso.so
endif


if MINGW
binary-c: ${LASSO_DLL}
else
binary-c: ${LASSO_SO}
endif

if MINGW
mylibs = -L../win32/.libs -llasso -L/usr/local/lib
${LASSO_DLL}:
	gcc -mno-cygwin -shared -o ${TARGET}/jlasso.dll \
            -Wl,--out-implib=${TARGET}/jlasso.a \
            -Wl,--add-stdcall-alias \
            -Wl,--export-all-symbols \
            -Wl,--enable-auto-import \
            -Wl,--whole-archive ${C_OBJECT} \
            -Wl,--no-whole-archive -lgobject-2.0-0 -lglib-2.0-0 ${mylibs}
else
mylibs = ../lasso/.libs/liblasso.so
${LASSO_SO}:
	$(CC) -shared -lgobject-2.0 -lglib-2.0 $(mylibs) ${C_OBJECT} -o $@
endif

lib_LTLIBRARIES = \
                libjlasso.la \
                $(NULL)

libjlasso_la_SOURCES = $(NULL)

libjlasso_la_LIBADD = \
        binary-c \
        $(NULL)

all-redirect: binary-c 

clean: clean-recursive
	rm -fr ${TARGET} *~ *.log


EXTRA_DIST = $(NULL)
SUBDIRS = src $(NULL)

