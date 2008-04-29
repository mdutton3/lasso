if JAVA_ENABLED
INCLUDES = -I$(top_srcdir) \
	-I$(top_builddir) \
	$(SASL_CFLAGS)

AM_JAVACFLAGS=-C
CLASSPATH_ENV= CLASSPATH=.:lasso.jar:/usr/share/java/junit.jar
JAVAROOT=.

java_extension_LTLIBRARIES = libjnilasso.la
java_extensiondir = ${libdir}/java

java_lasso_source_files = $(shell python $(top_srcdir)/bindings/bindings.py -l java-list --src-dir=$(top_srcdir)/lasso/)

lasso_jardir=$(prefix)/share/java
lasso_jar_DATA=lasso.jar
lasso_jar_class_files = $(java_lasso_source_files:.java=.class)

JAVAH=gcjh

$(lasso_jar_class_files): %.class: %.java
	$(JAVAC) -C -classpath . -d . $<

all_jar_class_files = $(shell find com/entrouvert/lasso -name '*.class' | sed 's%\$$%\\$$%g')

lasso.jar: $(all_jar_class_files)
	$(JAR) -cf $@ $(all_jar_class_files)

# Doc
apidir = $(docbasedir)/lasso/java-api

doc:
	-mkdir .doc
	-javadoc -link http://java.sun.com/j2se/1.4.2/docs/api -public -d .doc -sourcepath . -subpackages com.entrouvert.lasso	
	mv .doc doc


com_entrouvert_lasso_LassoJNI.h: $(lasso_jar_class_files)
	$(JAVAH) -jni -d . --classpath=. com.entrouvert.lasso.LassoJNI

libjnilasso_la_CFLAGS = $(LASSO_CORE_CFLAGS) -I$(top_srcdir) -I$(top_builddir)
libjnilasso_la_LDFLAGS = -export-dynamic -prefer-pic -module -avoid-version
libjnilasso_la_LIBADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS)
nodist_libjnilasso_la_SOURCES = com_entrouvert_lasso_LassoJNI.c 

BUILT_SOURCES = com_entrouvert_lasso_LassoJNI.c com_entrouvert_lasso_LassoJNI.h

$(java_lasso_source_files)  com_entrouvert_lasso_LassoJNI.c: ../lang_java_wrapper_top.c ../lang_java.py
	$(PYTHON) $(top_srcdir)/bindings/bindings.py -l java --src-dir=$(top_srcdir)/lasso/
	cp $(srcdir)/GObject.java com/entrouvert/lasso


doc-publish: doc
	tar czf doc.tgz -C doc .
	scp doc.tgz bdauvergne@perso.entrouvert.org:
	ssh bdauvergne@perso.entrouvert.org tar czf -C public_html/java-binding-doc doc.tgz
	rm doc.tgz

clean-local:
	-rm -f com_entrouvert_lasso_LassoJNI.c com/entrouvert/lasso/*.java com/entrouvert/lasso/*.class com_entrouvert_lasso_LassoJNI.h lasso.jar
	-rm -rf doc 
	-rm tests/*.class


check_JAVA = tests/BindingTests.java tests/LoginTest.java

endif

EXTRA_DIST = \
	GObject.java \
	LassoException_top.java

