# Define java Package directory, the tailing '/' is mandatory.
JAVA_PATH = com/entrouvert/lasso/
JDK_INCLUDES = @JDK_INCLUDE@ -I$(top_builddir)
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
	Defederation.java \
	DowncastableNode.java \
	Ecp.java \
	Federation.java \
	Identity.java \
	lasso.java \
	lassoConstants.java \
	lassoJNI.java \
	Lecp.java \
	LibAssertion.java \
	LibAuthnRequest.java \
	LibAuthnResponse.java \
	LibFederationTerminationNotification.java \
	LibLogoutRequest.java \
	LibLogoutResponse.java \
	LibRegisterNameIdentifierRequest.java \
	LibRegisterNameIdentifierResponse.java \
	LibRequestAuthnContext.java \
	LibStatusResponse.java \
	Login.java \
	Logout.java \
	MiscTextNode.java \
	NameIdentifierMapping.java \
	NameIdManagement.java \
	NameRegistration.java \
	Node.java \
	NodeList.java \
	Provider.java \
	Saml2Action.java \
	Saml2Advice.java \
	Saml2Assertion.java \
	Saml2Attribute.java \
	Saml2AttributeStatement.java \
	Saml2AudienceRestriction.java \
	Saml2AuthnContext.java \
	Saml2AuthnStatement.java \
	Saml2AuthzDecisionStatement.java \
	Saml2BaseIDAbstract.java \
	Saml2ConditionAbstract.java \
	Saml2Conditions.java \
	Saml2EncryptedElement.java \
	Saml2Evidence.java \
	Saml2KeyInfoConfirmationData.java \
	Saml2NameID.java \
	Saml2OneTimeUse.java \
	Saml2ProxyRestriction.java \
	Saml2StatementAbstract.java \
	Saml2Subject.java \
	Saml2SubjectConfirmation.java \
	Saml2SubjectConfirmationData.java \
	Saml2SubjectLocality.java \
	SamlAdvice.java \
	SamlAssertion.java \
	SamlAttribute.java \
	SamlAttributeDesignator.java \
	SamlAttributeStatement.java \
	SamlAttributeValue.java \
	SamlAudienceRestrictionCondition.java \
	SamlAuthenticationStatement.java \
	SamlAuthorityBinding.java \
	SamlConditionAbstract.java \
	SamlConditions.java \
	SamlNameIdentifier.java \
	SamlStatementAbstract.java \
	SamlSubject.java \
	SamlSubjectConfirmation.java \
	SamlSubjectLocality.java \
	SamlSubjectStatement.java \
	SamlSubjectStatementAbstract.java \
	Samlp2ArtifactResolve.java \
	Samlp2ArtifactResponse.java \
	Samlp2AssertionIDRequest.java \
	Samlp2AttributeQuery.java \
	Samlp2AuthnQuery.java \
	Samlp2AuthnRequest.java \
	Samlp2AuthzDecisionQuery.java \
	Samlp2Extensions.java \
	Samlp2IDPEntry.java \
	Samlp2IDPList.java \
	Samlp2LogoutRequest.java \
	Samlp2ManageNameIDRequest.java \
	Samlp2NameIDMappingRequest.java \
	Samlp2NameIDMappingResponse.java \
	Samlp2NameIDPolicy.java \
	Samlp2RequestAbstract.java \
	Samlp2RequestedAuthnContext.java \
	Samlp2Response.java \
	Samlp2Scoping.java \
	Samlp2Status.java \
	Samlp2StatusCode.java \
	Samlp2StatusDetail.java \
	Samlp2StatusResponse.java \
	Samlp2SubjectQueryAbstract.java \
	Samlp2Terminate.java \
	SamlpRequest.java \
	SamlpRequestAbstract.java \
	SamlpResponse.java \
	SamlpResponseAbstract.java \
	SamlpStatus.java \
	SamlpStatusCode.java \
	Server.java \
	Session.java \
	StringDict.java \
	StringList.java \
	SWIGTYPE_p_GHashTable.java \
	SWIGTYPE_p_void.java

if WSF_ENABLED
SWIG_WSF_OUTPUTS = Authentication.java \
	DataService.java \
	DiscoAuthenticateRequester.java \
	DiscoAuthenticateSessionContext.java \
	DiscoAuthorizeRequester.java \
	DiscoCredentials.java \
	DiscoDescription.java \
	DiscoEncryptedResourceID.java \
	DiscoEncryptResourceID.java \
	DiscoGenerateBearerToken.java \
	DiscoInsertEntry.java \
	DiscoModify.java \
	DiscoModifyResponse.java \
	DiscoOptions.java \
	DiscoQuery.java \
	DiscoQueryResponse.java \
	DiscoRemoveEntry.java \
	DiscoRequestedServiceType.java \
	DiscoResourceID.java \
	DiscoResourceOffering.java \
	DiscoSendSingleLogout.java \
	DiscoServiceInstance.java \
	Discovery.java \
	DstData.java \
	DstModification.java \
	DstModify.java \
	DstModifyResponse.java \
	DstNewData.java \
	DstQueryItem.java \
	DstQuery.java \
	DstQueryResponse.java \
	InteractionProfileService.java \
	IsHelp.java \
	IsInquiryElement.java \
	IsInquiry.java \
	IsInteractionRequest.java \
	IsInteractionResponse.java \
	IsInteractionStatement.java \
	IsItem.java \
	IsParameter.java \
	IsRedirectRequest.java \
	IsSelect.java \
	IsText.java \
	IsUserInteraction.java \
	lassoConstants.java \
	SaCredentials.java \
	SaSASLRequest.java \
	SaSASLResponse.java \
	SoapBindingCorrelation.java \
	SoapBody.java \
	SoapEnvelope.java \
	SoapHeader.java \
	SWIGTYPE_p_LassoSoapBindingProvider.java \
	UserAccount.java \
	UtilityStatus.java \
	WsfProfile.java \
	WsseSecurity.java
endif

JAVA_CRUFT = $(JAVA_PATH)lasso.class lasso_wrap.o lasso.jar $(JAVA_PATH)lasso.java

# The SWIG outputs are included in the distribution so SWIG is not
# required to use the Java interface
EXTRA_DIST = $(SWIG_OUTPUTS) $(SWIG_WSF_OUTPUTS)

CLEANFILES = $(JAVA_CRUFT)
MAINTAINERCLEANFILES = $(SWIG_OUTPUTS) $(SWIG_WSF_OUTPUTS)

SWIG_I_FILES=$(shell find $(top_srcdir)/swig/ -name '*.[ih]')
lasso_wrap.c lasso.java: $(SWIG_I_FILES)
	$(SWIG) -v -java -module lasso -package com.entrouvert.lasso -o lasso_wrap.c \
		$(top_srcdir)/swig/Lasso.i
	cp lasso_wrap.c lasso_wrap.c.bak
	sed -e 's/} DowncastableNode;/void *fix;} DowncastableNode;/' \
			< lasso_wrap.c.bak > lasso_wrap.c

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

