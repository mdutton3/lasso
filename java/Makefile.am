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
	Defederation.java                          Node.java \
	DiscoCredentials.java                      NodeList.java \
	DiscoDescription.java                      Provider.java \
	DiscoEncryptedResourceID.java              SamlAdvice.java \
	DiscoInsertEntry.java                      SamlAssertion.java \
	DiscoModify.java                           SamlAttributeDesignator.java \
	DowncastableNode.java                      SamlAttribute.java \
	Federation.java                            SamlAttributeStatement.java \
	Identity.java                              SamlAudienceRestrictionCondition.java \
	LassoHttpMethod.java                       SamlAuthenticationStatement.java \
	LassoLoginProtocolProfile.java             SamlAuthorityBinding.java \
	LassoMessageType.java                      SamlConditionAbstract.java \
	LassoProviderRole.java                     SamlConditions.java \
	LassoRequestType.java                      SamlNameIdentifier.java \
	LassoSignatureMethod.java                  SamlpRequestAbstract.java \
	Lecp.java                                  SamlpRequest.java \
	LibAssertion.java                          SamlpResponseAbstract.java \
	LibAuthnRequest.java                       SamlpResponse.java \
	LibAuthnResponse.java                      SamlpStatusCode.java \
	LibFederationTerminationNotification.java  SamlpStatus.java \
	LibLogoutRequest.java                      SamlStatementAbstract.java \
	LibLogoutResponse.java                     SamlSubjectConfirmation.java \
	LibRegisterNameIdentifierRequest.java      SamlSubject.java \
	LibRegisterNameIdentifierResponse.java     SamlSubjectLocality.java \
	LibRequestAuthnContext.java                SamlSubjectStatementAbstract.java \
	LibStatusResponse.java                     SamlSubjectStatement.java \
	Login.java                                 Server.java \
	Logout.java                                Session.java \
	NameIdentifierMapping.java                 StringList.java \
	NameRegistration.java
 
JAVA_CRUFT = $(JAVA_PATH)lasso.class lasso_wrap.o lasso.jar $(JAVA_PATH)lasso.java

# The SWIG outputs are included in the distribution so SWIG is not
# required to use the Java interface
EXTRA_DIST = $(SWIG_OUTPUTS)

CLEANFILES = $(JAVA_CRUFT)
MAINTAINERCLEANFILES = $(SWIG_OUTPUTS)


lasso_wrap.c lasso.java: $(top_srcdir)/swig/Lasso.i $(top_srcdir)/swig/Lasso-wsf.i \
		$(top_srcdir)/swig/inheritance.h
	$(SWIG) -v -java -module lasso -package com.entrouvert.lasso -o lasso_wrap.c \
		$(top_srcdir)/swig/Lasso.i

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

