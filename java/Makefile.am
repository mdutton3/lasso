# Define the java module
JAVA_MODULE = lasso
# Define java package name
JAVA_PACKAGE = com.entrouvert.lasso
# Define java Package directory, the tailing '/' is mandatory.
JAVA_PATH = com/entrouvert/lasso/
JDK_INCLUDES = @JDK_INCLUDE@
CLASSPATH = .

javalibdir = $(prefix)/lib/java
javasharedir = $(prefix)/share/java

# Shared library.
javalib_LTLIBRARIES = libjlasso.la

libjlasso_la_SOURCES =	$(JAVA_MODULE)_wrap.c

libjlasso_la_CFLAGS =	$(JDK_INCLUDES) \
			$(LASSO_CFLAGS) \
			-I$(top_srcdir)

libjlasso_la_LIBADD =	$(top_builddir)/lasso/liblasso.la $(LASSO_LIBS)

libjlasso_la_LDFLAGS =	-no-undefined -avoid-version -module

# Java package
javashare_DATA = lasso.jar
JAVA_JAR = lasso.jar

SWIG_OUTPUTS = $(JAVA_PATH)$(JAVA_MODULE).java $(JAVA_MODULE)_wrap.c $(JAVA_MODULE)JNI.java
JAVA_CRUFT = $(JAVA_PATH)$(JAVA_MODULE).class $(JAVA_MODULE)_wrap.o \
	$(JAVA_JAR) \
	$(JAVA_PATH)$(JAVA_MODULE).java

# The SWIG outputs are included in the distribution so SWIG is not
# required to use the Java interface
EXTRA_DIST = $(SWIG_OUTPUTS)

CLEANFILES = $(JAVA_CRUFT)
MAINTAINERCLEANFILES = $(SWIG_OUTPUTS)


$(JAVA_MODULE)_wrap.c $(JAVA_MODULE).java: $(top_srcdir)/swig/Lasso.i
	here=`pwd`; \
	$(SWIG) -v -java -module $(JAVA_MODULE) -package $(JAVA_PACKAGE) -o $(JAVA_MODULE)_wrap.c $$here/$<

# FIXME There must be a better way to do this with SWIG
$(JAVA_PATH)$(JAVA_MODULE).java: $(JAVA_MODULE).java
	mkdir -p $(JAVA_PATH)
	test -f $(JAVA_PATH)$(JAVA_MODULE).java || cp *.java $(JAVA_PATH)

clean-local:
	rm -f *.class
	rm -rf com

all-local: $(JAVA_JAR)

$(JAVA_PATH)$(JAVA_MODULE).class: $(JAVA_PATH)$(JAVA_MODULE).java
	$(JAVAC) $(JAVAC_FLAGS) $(JAVA_PATH)*.java

$(JAVA_JAR): $(JAVA_PATH)$(JAVA_MODULE).class 
	rm -f $@
	jar cf $@ $(JAVA_PATH)*.class 

$(DEPDIR)/libjlasso_la-lasso_wrap.Plo:
	mkdir -p $(DEPDIR)
	echo "#dummy" > $(DEPDIR)/libjlasso_la-lasso_wrap.Plo 

$(DEPDIR)/com/entrouvert/lasso/lasso.Po:
	mkdir -p $(DEPDIR)/com/entrouvert/lasso 
	echo "#dummy" > $(DEPDIR)/com/entrouvert/lasso/lasso.Po  
