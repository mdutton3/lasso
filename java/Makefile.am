
NULL=
# Define the java module
JAVA_MODULE=lasso
# Define java package name
JAVA_PACKAGE=com.entrouvert.lasso
# Define java Package directory, the tailing '/' is mandatory.
JAVA_PATH=com/entrouvert/lasso/
JDK_INCLUDES=@JDK_INCLUDE@
CLASSPATH=.

javalibdir=$(prefix)/lib/java
javasharedir=$(prefix)/share/java

# Shared library.
javalib_LTLIBRARIES=libjlasso.la

libjlasso_la_SOURCES=	$(JAVA_MODULE)_wrap.c
libjlasso_la_CFLAGS=	$(JDK_INCLUDES) \
			$(LASSO_CFLAGS) \
			-I$(top_srcdir) -I$(top_srcdir)/lasso \
			$(NULL)
libjlasso_la_LIBADD=	$(top_builddir)/lasso/liblasso.la \
                   	$(LASSO_LIBS) \
                   	$(NULL)
libjlasso_la_LDFLAGS=	-no-undefined \
			-version-info @LASSO_VERSION_INFO@ \
			-avoid-version -module \
                     	$(NULL)

# Java package
javashare_DATA=lasso.jar
JAVA_JAR=lasso.jar

SWIG_OUTPUTS=$(JAVA_PATH)$(JAVA_MODULE).java $(JAVA_MODULE)_wrap.c $(JAVA_MODULE).java.in
JAVA_CRUFT=$(JAVA_PATH)$(JAVA_MODULE).class $(JAVA_MODULE)_wrap.o \
$(JAVA_JAR) \
$(JAVA_PATH)$(JAVA_MODULE)JNI.java

# Sources file in order to beautifully (and so humanly) wrap lasso.
JAVA_SOURCE_FILES=$(NULL)

# Bytecode version of the java source files.
JAVA_CLASS_FILES=$(NULL)


SUBDIRS=

# The SWIG outputs are included in the distribution so SWIG is not
# required to use the Java interface
EXTRA_DIST= lasso-fragment.java \
            $(SWIG_OUTPUTS)

CLEANFILES=$(JAVA_CRUFT)
MAINTAINERCLEANFILES=$(SWIG_OUTPUTS)


$(JAVA_MODULE)_wrap.c $(JAVA_MODULE).java.in: $(srcdir)/../swig/Lasso.i
	here=`pwd`; \
	mkdir -p $(JAVA_PATH) \
	cd $(JAVA_PATH); \
	$(SWIG) -v -java -noproxy -module $(JAVA_MODULE) -package $(JAVA_PACKAGE) -o $(JAVA_MODULE)_wrap.c $$here/$<; \
	if test -r $(JAVA_MODULE)JNI.java; then \
	  echo "Fixing SWIG 1.3.15+ broken Java API"; \
	  rm -f $(JAVA_MODULE).java SWIGTYPE_*; \
	  sed -e 's/class $(JAVA_MODULE)JNI/public class $(JAVA_MODULE)/' $(JAVA_MODULE)JNI.java > $(JAVA_MODULE).java; \
	  sed -e 's/$(JAVA_MODULE)JNI/$(JAVA_MODULE)/g' $(JAVA_MODULE)_wrap.c > $(JAVA_MODULE)_wrap.c.new; \
	  rm -f $(JAVA_MODULE)_wrap.c $(JAVA_MODULE)JNI.java; \
	  mv $(JAVA_MODULE)_wrap.c.new $(JAVA_MODULE)_wrap.c; \
	fi; \
	mv $(JAVA_MODULE).java $(JAVA_MODULE).java.in

# FIXME There must be a better way to do this with SWIG
$(JAVA_PATH)$(JAVA_MODULE).java: $(JAVA_MODULE).java.in lasso-fragment.java
	sed -e 's/^}//' $(JAVA_MODULE).java.in > $(JAVA_PATH)$(JAVA_MODULE).java.tmp
	cat $(JAVA_PATH)$(JAVA_MODULE).java.tmp lasso-fragment.java > $@
	echo "}" >> $@
	rm -f $(JAVA_PATH)$(JAVA_MODULE).java.tmp


clean-local:
	rm -f *.class

all-local: $(JAVA_JAR)

$(JAVA_PATH)$(JAVA_MODULE).class: $(JAVA_PATH)$(JAVA_MODULE).java
	$(JAVAC) $(JAVAC_FLAGS) $(JAVA_PATH)$(JAVA_MODULE).java

$(JAVA_JAR): $(JAVA_PATH)$(JAVA_MODULE).class 
	rm -f $@
	jar cf $@ $(JAVA_PATH)$(JAVA_MODULE).class 

.deps/libjlasso_la-lasso_wrap.Plo:
	echo "#dummy" > .deps/libjlasso_la-lasso_wrap.Plo 

.deps/com/entrouvert/lasso/lasso.Po:
	mkdir -p .deps/com/entrouvert/lasso 
	echo "#dummy" > .deps/com/entrouvert/lasso/lasso.Po  
