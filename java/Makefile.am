NULL = 

TARGET=target
#JAVAC=/usr/lib/kaffe/bin/javac
#JAVAH=/usr/lib/kaffe/bin/javah
#JAVAH_CLASSPATH_PREFIX=/usr/share/kaffe/Klasses.jar:
#JAR=/usr/lib/kaffe/bin/jar


JAVA_BUILD_DIR=${TARGET}/classes
JAVA_SOURCE_DIR=src/java
JAVA_PACKAGE=com.entrouvert.lasso
JAVA_SOURCE=${wildcard ${JAVA_SOURCE_DIR}/${subst .,/,${JAVA_PACKAGE}}/*.java}
JAVA_CLASSES=${addprefix ${JAVA_PACKAGE}., ${filter-out LassoTest, ${basename ${notdir ${JAVA_SOURCE}}}}}
LASSO_JAR=${TARGET}/lasso.jar

C_SOURCE_DIR=src/c
C_BUILD_DIR=${C_SOURCE_DIR}
C_SOURCE=${wildcard ${C_SOURCE_DIR}/*.c}
C_OBJECT=${C_SOURCE:.c=.o}
if MINGW
    LDFLAGS=-L/usr/local/lib -lgobject-2.0-0 -lglib-2.0-0 -llasso 
    LASSO_DLL=${TARGET}/jlasso.dll
else
    LDFLAGS=-lgobject-2.0 -lglib-2.0 -llasso 
    LASSO_SO=${TARGET}/libjlasso.so
endif

binary-java:
	mkdir -p ${JAVA_BUILD_DIR}
	${JAVAC} ${JAVAC_FLAGS} -d ${JAVA_BUILD_DIR} ${JAVA_SOURCE}
	${JAR} cf ${LASSO_JAR} -C ${JAVA_BUILD_DIR} com

generate-header: binary-java
	${JAVAH} ${JAVAH_FLAGS} -d ${C_SOURCE_DIR} -classpath ${JAVAH_CLASSPATH_PREFIX}${JAVA_BUILD_DIR} ${JAVA_CLASSES}

if MINGW
binary-c: ${LASSO_DLL}
else
binary-c: ${LASSO_SO}
endif

if MINGW
mylibs = -L../win32/.libs -llasso -L/usr/local/lib
${LASSO_DLL}: generate-header
	gcc -mno-cygwin -shared -o ${TARGET}/jlasso.dll \
            -Wl,--out-implib=${TARGET}/jlasso.a \
            -Wl,--add-stdcall-alias \
            -Wl,--export-all-symbols \
            -Wl,--enable-auto-import \
            -Wl,--whole-archive ${C_OBJECT} \
            -Wl,--no-whole-archive -lgobject-2.0-0 -lglib-2.0-0 ${mylibs}
else
mylibs = ../lasso/.libs/liblasso.so
${LASSO_SO}: generate-header
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

clean:
	rm -fr ${TARGET} *~ *.log


EXTRA_DIST = $(NULL)
SUBDIRS = src $(NULL)

