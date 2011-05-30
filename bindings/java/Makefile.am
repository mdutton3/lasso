.NOTPARALLEL:

MAINTAINERCLEANFILES = Makefile.in
INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(SASL_CFLAGS)

CLASSPATH_ENV= CLASSPATH=.:$(CLASSPATH_JUNIT)
CLASSPATH=.:tests

if HAVE_AM_SILENT_RULES
AM_V_JAVAC = $(am__v_JAVAC_$(V))
am__v_JAVAC_ = $(am__v_JAVAC_$(AM_DEFAULT_VERBOSITY))
am__v_JAVAC_0 = @echo "  JAVAC    " $@;

AM_V_JAR = $(am__v_JAR_$(V))
am__v_JAR_ = $(am__v_JAR_$(AM_DEFAULT_VERBOSITY))
am__v_JAR_0 = @echo "  JAR    " $@;
endif

java_extension_LTLIBRARIES = libjnilasso.la
java_extensiondir = ${libdir}/java

if WSF_ENABLED
EXTRA_ARGS = --enable-id-wsf
endif

java_lasso_source_files := $(shell python $(top_srcdir)/bindings/bindings.py -l java-list --src-dir=$(top_srcdir)/lasso/ $(EXTRA_ARGS) )

lasso_jardir=$(prefix)/share/java
lasso_jar_DATA=lasso.jar
lasso_jar_class_files = $(java_lasso_source_files:.java=.class)

%.class: %.java
	$(AM_V_JAVAC) $(JAVAC) $(CLASSPATH_OPT) $(CLASSPATH) $(JAVAC_FLAGS) -d . $<

all_jar_class_files = $(shell find com/entrouvert/lasso -name '*.class' | sed 's%\$$%\\$$%g')

lasso.jar: $(java_lasso_source_files:.java=.class)
	$(AM_V_JAR) $(JAR) -cf $@ $(all_jar_class_files)

# Doc
apidir = $(docbasedir)/lasso/java-api

doc:
	-mkdir .doc
	-javadoc -link http://java.sun.com/j2se/1.4.2/docs/api -public -d .doc -sourcepath . -subpackages com.entrouvert.lasso	
	mv .doc doc


com_entrouvert_lasso_LassoJNI.h: com/entrouvert/lasso/LassoJNI.class  $(java_lasso_source_files:.java=.class)
	$(AM_V_GEN) $(JAVAH) $(JAVAH_FLAGS) -classpath . `echo $< | sed 'su/u.ug;su.classuu'`

libjnilasso_la_CFLAGS = -fno-strict-aliasing $(LASSO_CORE_CFLAGS) -I$(top_srcdir) -I$(top_builddir) $(AM_CFLAGS) @JAVA_INCLUDE@
libjnilasso_la_CFLAGS += -Wno-unused-parameter

libjnilasso_la_LDFLAGS = -export-dynamic -prefer-pic -module -avoid-version $(JNI_EXTRA_LDFLAGS)
libjnilasso_la_LIBADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS)
nodist_libjnilasso_la_SOURCES = com_entrouvert_lasso_LassoJNI.c 

BUILT_SOURCES = com_entrouvert_lasso_LassoJNI.c com_entrouvert_lasso_LassoJNI.h

BINDING_OPTION=#--enable-exception-docs

$(java_lasso_source_files)  com_entrouvert_lasso_LassoJNI.c: wrapper_top.c wrapper_bottom.c lang.py ../bindings.py
	$(AM_V_GEN) $(PYTHON) $(top_srcdir)/bindings/bindings.py $(BINDING_OPTION) -l java --src-dir=$(top_srcdir)/lasso/ $(EXTRA_ARGS) && cp $(srcdir)/GObject.java com/entrouvert/lasso


doc-publish: doc
	tar czf doc.tgz -C doc .
	scp doc.tgz bdauvergne@perso.entrouvert.org:
	ssh bdauvergne@perso.entrouvert.org tar czf -C public_html/java-binding-doc doc.tgz
	rm doc.tgz

MOSTLYCLEANFILES =  com_entrouvert_lasso_LassoJNI.c  com_entrouvert_lasso_LassoJNI.h \
		    com/entrouvert/lasso/* lasso.jar *.class $(TESTS) \
		    __init__.pyc lang.pyc



EXTRA_DIST = \
	GObject.java \
	LassoException_top.java \
	tests/BindingTests.java \
	tests/LoginTest.java \
	lang.py \
	__init__.py \
	wrapper_bottom.c \
	wrapper_top.c 

clean-local:
	-rm -rf com

# Some of the following classes are built only if junit is available
if JUNIT_ENABLED
test_source_files= tests/BindingTests.java tests/LoginTest.java 

$(test_source_files:.java=.class): CLASSPATH=.:$(CLASSPATH_JUNIT)

TESTS = AllJunitTests

AllJunitTests: JAVAFLAGS +="-Dsrcdir=$(srcdir)"

AllJunitTests: $(test_source_files:.java=.class) 	
	echo "#! /bin/sh" > $@
	echo "OBJDIR=`libtool --config | grep ^objdir | sed s/.*=//`" >> $@
	echo 'LD_LIBRARY_PATH=$$OBJDIR DYLD_LIBRARY_PATH=$$OBJDIR @JUNIT@ -Djava.library.path=$$OBJDIR BindingTests' >> $@
	echo 'LD_LIBRARY_PATH=$$OBJDIR DYLD_LIBRARY_PATH=$$OBJDIR @JUNIT@ -Djava.library.path=$$OBJDIR LoginTest' >> $@
	chmod +x $@
endif


