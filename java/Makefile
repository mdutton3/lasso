TARGET=target

JAVAC=/opt/jdk/bin/javac
JAVAH=/opt/jdk/bin/javah
JAR=/opt/jdk/bin/jar

JAVA_BUILD_DIR=${TARGET}/classes
JAVA_SOURCE_DIR=src/java
JAVA_PACKAGE=com.entrouvert.lasso
JAVA_SOURCE=${wildcard ${JAVA_SOURCE_DIR}/${subst .,/,${JAVA_PACKAGE}}/*.java}
JAVA_CLASSES=${addprefix ${JAVA_PACKAGE}., ${filter-out LassoTest, ${basename ${notdir ${JAVA_SOURCE}}}}}
LASSO.JAR=${TARGET}/lasso.jar

C_SOURCE_DIR=src/c
C_BUILD_DIR=${C_SOURCE_DIR}
C_SOURCE=${wildcard ${C_SOURCE_DIR}/*.c}
C_OBJECT=${C_SOURCE:.c=.o}
LASSO.SO=${TARGET}/libjlasso.so

.PHONY: clean all binary-java binary-c generate-header

all: binary-java binary-c

binary-java:
	mkdir -p ${JAVA_BUILD_DIR}
	${JAVAC} -d ${JAVA_BUILD_DIR} ${JAVA_SOURCE}
	${JAR} cf ${LASSO.JAR} -C ${JAVA_BUILD_DIR} com

generate-header: binary-java
	${JAVAH} -d ${C_SOURCE_DIR} -classpath ${JAVA_BUILD_DIR} ${JAVA_CLASSES}

binary-c: ${LASSO.SO}

${C_OBJECT}: ${C_SOURCE}
	${MAKE} -C ${C_SOURCE_DIR}

${LASSO.SO}: generate-header ${C_OBJECT}
	$(CC) -shared ${C_OBJECT} -o $@

clean:
	${MAKE} -C ${C_SOURCE_DIR} clean
	rm -fr ${TARGET} *~ *.log
