TARGET=target

#JAVAC=/usr/bin/javac
#JAVAH=/usr/bin/javah
#JAVAH_CLASSPATH_PREFIX=
#JAR=/usr/bin/jar

#JAVAC=/opt/jdk/bin/javac
#JAVAH=/opt/jdk/bin/javah
#JAVAH_CLASSPATH_PREFIX=
#JAR=/opt/jdk/bin/jar

JAVAC=/usr/lib/kaffe/bin/javac
JAVAH=/usr/lib/kaffe/bin/javah
JAVAH_CLASSPATH_PREFIX=/usr/share/kaffe/Klasses.jar:
JAR=/usr/lib/kaffe/bin/jar

#JAVAC=/usr/bin/gcj -C
#JAVAH=/usr/bin/gcjh -jni
#JAVAH_CLASSPATH_PREFIX=
#JAR=/usr/bin/fastjar

JAVA_BUILD_DIR=${TARGET}/classes
JAVA_SOURCE_DIR=src
JAVA_SOURCE=${wildcard ${JAVA_SOURCE_DIR}/*.java}
JAVA_CLASSES=${basename ${notdir ${JAVA_SOURCE}}}
LASSO.JAR=${TARGET}/CFLasso.jar

.PHONY: clean all binary-java

all: binary-java

binary-java:
	mkdir -p ${JAVA_BUILD_DIR}
	${JAVAC} -classpath ../target/lasso.jar -d ${JAVA_BUILD_DIR} ${JAVA_SOURCE}
	${JAR} cf ${LASSO.JAR} -C ${JAVA_BUILD_DIR} CFLasso.class

clean:
	rm -rf ${TARGET} *~ *.log
