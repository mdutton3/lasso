if JAVA_ENABLED
INCLUDES = -I$(top_srcdir) \
	-I$(top_builddir) \
	$(SASL_CFLAGS)

java_extension_LTLIBRARIES = libjnilasso.la
java_extensiondir = ${libdir}

nodist_java_extension_DATA = 

libjnilasso_la_CFLAGS = $(LASSO_CORE_CFLAGS) -I$(top_srcdir) -I$(top_builddir)
libjnilasso_la_LDFLAGS = -export-dynamic -prefer-pic -module -avoid-version
libjnilasso_la_LIBADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS)
nodist_libjnilasso_la_SOURCES = com_entrouvert_lasso_LassoJNI.c

BUILT_SOURCES = com_entrouvert_lasso_LassoJNI.c

%.class: %.java
	javac -d . -cp . $<

com_entrouvert_lasso_LassoJNI.h: com/entrouvert/lasso/LassoJNI.class
	javah -d . -jni --classpath=. com.entrouvert.lasso.LassoJNI

com/entrouvert/lasso/LassoJNI.java com/entrouvert/lasso/LassoConstants.java com_entrouvert_lasso_LassoJNI.c: ../lang_java_wrapper_top.c ../lang_java.py
	$(PYTHON) $(top_srcdir)/bindings/bindings.py -l java --src-dir=$(top_srcdir)/lasso/
	cp GObject.java com/entrouvert/lasso

doc/index.html:
	javadoc -link http://java.sun.com/j2se/1.4.2/docs/api -public -d doc -sourcepath . -subpackages com.entrouvert.lasso	

publish: doc/index.html
	tar czf doc.tgz -C doc .
	scp doc.tgz bdauvergne@perso.entrouvert.org:
	ssh bdauvergne@perso.entrouvert.org tar czf -C public_html/java-binding-doc doc.tgz
	rm doc.tgz

clean-local:
	-rm -f doc/* com_entrouvert_lasso_LassoJNI.c com/entrouvert/lasso/*.java com/entrouvert/lasso/*.class com_entrouvert_lasso_LassoJNI.h 

endif
