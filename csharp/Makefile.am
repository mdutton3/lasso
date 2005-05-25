INCLUDES = -I$(top_srcdir)

lib_LTLIBRARIES = liblassosharpglue.la

liblassosharpglue_la_SOURCES = \
	liblassosharpglue_wrap.c

liblassosharpglue_la_CFLAGS = \
	$(LASSO_CORE_CFLAGS) \
	-DSWIG_COBJECT_TYPES

liblassosharpglue_la_LIBADD = \
	$(top_builddir)/lasso/liblasso.la \
	$(LASSO_LIBS)

liblassosharpglue_la_LDFLAGS =	-no-undefined -module -avoid-version

liblassosharpglue_wrap.c: $(top_srcdir)/swig/Lasso.i $(top_srcdir)/swig/Lasso-wsf.i \
		$(top_srcdir)/swig/inheritance.h
	$(SWIG) -v -csharp -namespace lasso -module lasso \
		-o liblassosharpglue_wrap.c $(top_srcdir)/swig/Lasso.i
	cp liblassosharpglue_wrap.c liblassosharpglue_wrap.c.bak
	sed -e 's/(char \*) "\(.*\)"/strdup("\1")/' \
		< liblassosharpglue_wrap.c.bak > liblassosharpglue_wrap.c

dotnetlibdir = $(datadir)/dotnet/lasso/
dotnetlib_DATA = lasso.dll lasso.dll.config

lasso.dll: liblassosharpglue.la
	-$(LN_S) $(srcdir)/lasso-sharp.snk lasso-sharp-build.snk
	$(CSHARPCOMPILER) -out:lasso.dll -target:library $(srcdir)/*.cs
	rm -f lasso-sharp-build.snk

pkgconfig_DATA  = lasso-sharp.pc
pkgconfigdir    = $(libdir)/pkgconfig

install-data-local:
	-$(GACUTIL) -i lasso.dll -f -package lasso -gacdir $(libdir)

clean-local:
	-rm lasso.dll lasso-sharp.pc liblassosharpglue_wrap.c.bak

SWIG_FILES = liblassosharpglue_wrap.c \
	Defederation.cs CheckVersionMode.cs \
	DowncastableNode.cs \
	Federation.cs Identity.cs \
	lasso.cs lassoPINVOKE.cs Lecp.cs LibAssertion.cs \
	LibAuthnRequest.cs \
	LibAuthnResponse.cs LibFederationTerminationNotification.cs \
	LibLogoutRequest.cs LibLogoutResponse.cs LibRegisterNameIdentifierRequest.cs \
	LibRegisterNameIdentifierResponse.cs LibRequestAuthnContext.cs \
	LibStatusResponse.cs Login.cs Logout.cs NameIdentifierMapping.cs \
	NameRegistration.cs Node.cs NodeList.cs Provider.cs \
	SamlAdvice.cs SamlAssertion.cs SamlAttribute.cs SamlAttributeDesignator.cs \
	SamlAttributeStatement.cs SamlAttributeValue.cs SamlAudienceRestrictionCondition.cs \
	SamlAuthenticationStatement.cs SamlAuthorityBinding.cs SamlConditionAbstract.cs \
	SamlConditions.cs SamlNameIdentifier.cs SamlpRequestAbstract.cs SamlpRequest.cs \
	SamlpResponseAbstract.cs SamlpResponse.cs SamlpStatusCode.cs SamlpStatus.cs \
	SamlStatementAbstract.cs SamlSubjectConfirmation.cs SamlSubject.cs \
	SamlSubjectLocality.cs SamlSubjectStatementAbstract.cs SamlSubjectStatement.cs \
	Server.cs Session.cs StringList.cs SWIGTYPE_p_LassoMdProtocolType.cs \
	SWIGTYPE_p_LassoSignatureType.cs SWIGTYPE_p_void.cs \
	HttpMethod.cs ProviderRole.cs SignatureMethod.cs LoginProtocolProfile.cs \
	RequestType.cs

if WSF_ENABLED
SWIG_WSF_FILES = Authentication.cs \
	DiscoAuthenticateRequester.cs \
	DiscoAuthenticateSessionContext.cs \
	DiscoAuthorizeRequester.cs \
	DiscoCredentials.cs \
	DiscoDescription.cs \
	DiscoEncryptedResourceID.cs \
	DiscoEncryptResourceID.cs \
	DiscoGenerateBearerToken.cs \
	DiscoInsertEntry.cs \
	DiscoModify.cs \
	DiscoModifyResponse.cs \
	DiscoOptions.cs \
	DiscoQuery.cs \
	DiscoQueryResponse.cs \
	DiscoRemoveEntry.cs \
	DiscoRequestedServiceType.cs \
	DiscoResourceID.cs \
	DiscoResourceOffering.cs \
	DiscoSendSingleLogout.cs \
	DiscoServiceInstance.cs \
	Discovery.cs \
	DstData.cs \
	DstModification.cs \
	DstModify.cs \
	DstModifyResponse.cs \
	DstNewData.cs \
	DstQueryItem.cs \
	DstQuery.cs \
	DstQueryResponse.cs \
	InteractionProfileService.cs \
	IsHelp.cs \
	IsInquiryElement.cs \
	IsInquiry.cs \
	IsInteractionRequest.cs \
	IsInteractionResponse.cs \
	IsInteractionStatement.cs \
	IsItem.cs \
	IsParameter.cs \
	IsRedirectRequest.cs \
	IsSelect.cs \
	IsText.cs \
	IsUserInteraction.cs \
	lassoConstants.cs \
	ProfileService.cs \
	SaCredentials.cs \
	SaSASLRequest.cs \
	SaSASLResponse.cs \
	SoapBindingCorrelation.cs \
	SoapBody.cs \
	SoapEnvelope.cs \
	SoapHeader.cs \
	SWIGTYPE_p_LassoSoapBindingProvider.cs \
	UserAccount.cs \
	UtilityStatus.cs \
	WsfProfile.cs \
	WsseSecurity.cs
endif

EXTRA_DIST = lasso-sharp.pc.in lasso.dll.config AssemblyInfo.cs lasso-sharp.snk \
		$(SWIG_FILES) $(SWIG_WSF_FILES)

MAINTAINERCLEANFILES = $(SWIG_FILES) $(SWIG_WSF_FILES)

