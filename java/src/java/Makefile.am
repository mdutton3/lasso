TARGET=../../target
JAVA_BUILD_DIR=${TARGET}/classes
JAVA_PACKAGE=com.entrouvert.lasso
JAVA_SOURCE=${wildcard ${subst .,/,${JAVA_PACKAGE}}/*.java}
LASSO_JAR=${TARGET}/lasso.jar
C_SOURCE_DIR=../c
C_SOURCE=${wildcard ${C_SOURCE_DIR}/*.c}
JAVA_CLASSES=${addprefix ${JAVA_PACKAGE}., ${filter-out LassoTest, ${basename ${notdir ${JAVA_SOURCE}}}}}

binary-java:
	mkdir -p ${JAVA_BUILD_DIR}
	${JAVAC} ${JAVAC_FLAGS} -d ${JAVA_BUILD_DIR} ${JAVA_SOURCE}
	${JAR} cf ${LASSO_JAR} -C ${JAVA_BUILD_DIR} com

generate-header: binary-java
	${JAVAH} ${JAVAH_FLAGS} -d ${C_SOURCE_DIR} -classpath ${JAVAH_CLASSPATH_PREFIX}${JAVA_BUILD_DIR} ${JAVA_CLASSES}

all: generate-header

