# Define java Package directory, the tailing '/' is mandatory.
JAVA_PATH = com/entrouvert/lasso/
JDK_INCLUDES = @JDK_INCLUDE@
CLASSPATH = .

javalibdir = $(prefix)/lib/java
javasharedir = $(prefix)/share/java

# Shared library.
if MINGW
javalib_LTLIBRARIES = jlasso.la
else
javalib_LTLIBRARIES = libjlasso.la
endif

jlasso_la_SOURCES =	lasso_wrap.c
jlasso_la_CFLAGS = $(JDK_INCLUDES) $(LASSO_CORE_CFLAGS) -I$(top_srcdir)
jlasso_la_LIBADD =	$(top_builddir)/lasso/liblasso.la $(LASSO_LIBS)
jlasso_la_LDFLAGS =	-no-undefined -avoid-version -module \
                        -Wl,--add-stdcall-alias 

libjlasso_la_SOURCES =	lasso_wrap.c
libjlasso_la_CFLAGS = $(JDK_INCLUDES) $(LASSO_CORE_CFLAGS) -I$(top_srcdir)
libjlasso_la_LIBADD =	$(top_builddir)/lasso/liblasso.la $(LASSO_LIBS)
libjlasso_la_LDFLAGS =	-no-undefined -avoid-version -module

javashare_DATA = lasso.jar

SWIG_OUTPUTS = lasso_wrap.c \
	Defederation.java Identity.java lassoConstants.java lasso.java \
	lassoJNI.java Lecp.java LibAssertion.java LibAuthnRequest.java \
	LibAuthnResponse.java LibFederationTerminationNotification.java \
	LibLogoutRequest.java LibLogoutResponse.java \
	LibRegisterNameIdentifierRequest.java \
	LibRegisterNameIdentifierResponse.java Login.java Logout.java \
	NameIdentifierMapping.java NameRegistration.java Node.java \
	ProviderIds.java Provider.java SamlpRequest.java \
	SamlpResponse.java Server.java Session.java SWIGTYPE_p_void.java


JAVA_CRUFT = $(JAVA_PATH)lasso.class lasso_wrap.o lasso.jar $(JAVA_PATH)lasso.java

# The SWIG outputs are included in the distribution so SWIG is not
# required to use the Java interface
EXTRA_DIST = $(SWIG_OUTPUTS)

CLEANFILES = $(JAVA_CRUFT)
MAINTAINERCLEANFILES = $(SWIG_OUTPUTS)


lasso_wrap.c lasso.java: $(top_srcdir)/swig/Lasso.i
	$(SWIG) -v -java -module lasso -package com.entrouvert.lasso -o lasso_wrap.c $<

# FIXME There must be a better way to do this with SWIG
$(JAVA_PATH)lasso.java: lasso.java
	mkdir -p $(JAVA_PATH)
	rm -f $(JAVA_PATH)/*
	cp $(srcdir)/*.java $(JAVA_PATH)

clean-local:
	rm -f *.class
	rm -rf com

all-local: lasso.jar

$(JAVA_PATH)lasso.class: $(JAVA_PATH)lasso.java
	$(JAVAC) $(JAVAC_FLAGS) $(JAVA_PATH)*.java

lasso.jar: $(JAVA_PATH)lasso.class 
	rm -f $@
	$(JAR) cf $@ $(JAVA_PATH)*.class 

