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
	Credentials.cs Defederation.cs Description.cs DiscoModify.cs \
	DiscoModifyResponse.cs DiscoQuery.cs DiscoQueryResponse.cs \
	Discovery.cs DowncastableNode.cs DstModification.cs DstModify.cs \
	DstModifyResponse.cs DstQuery.cs DstQueryResponse.cs Federation.cs \
	Identity.cs InsertEntry.cs LassoHttpMethod.cs LassoLoginProtocolProfile.cs \
	LassoMessageType.cs LassoProviderRole.cs LassoRequestType.cs \
	LassoSignatureMethod.cs Lecp.cs LibAssertion.cs LibAuthnRequest.cs \
	LibAuthnResponse.cs LibFederationTerminationNotification.cs \
	LibLogoutRequest.cs LibLogoutResponse.cs \
	LibRegisterNameIdentifierRequest.cs \
	LibRegisterNameIdentifierResponse.cs LibStatusResponse.cs Login.cs \
	Logout.cs NameIdentifierMapping.cs NameRegistration.cs Node.cs \
	NodeList.cs Options.cs PPMsgContact.cs PersonalProfileService.cs \
	Provider.cs QueryItem.cs RemoveEntry.cs ResourceID.cs \
	ResourceOffering.cs SWIGTYPE_p_LassoDiscoEncryptedResourceID.cs \
	SWIGTYPE_p_LassoDiscoRequestedServiceType.cs \
	SWIGTYPE_p_LassoDstNewData.cs SWIGTYPE_p_LassoMdProtocolType.cs \
	SWIGTYPE_p_LassoSignatureType.cs SWIGTYPE_p_void.cs SamlAdvice.cs \
	SamlAssertion.cs SamlAttributeStatement.cs \
	SamlAuthenticationStatement.cs SamlConditions.cs \
	SamlNameIdentifier.cs SamlSubject.cs SamlSubjectConfirmation.cs \
	SamlSubjectLocality.cs SamlSubjectStatement.cs SamlpRequest.cs \
	SamlpResponse.cs SamlpStatus.cs SamlpStatusCode.cs Server.cs \
	ServiceInstance.cs Session.cs Status.cs StringList.cs \
	lassoPINVOKE.cs SamlpRequestAbstract.cs SamlpResponseAbstract.cs \
	LibRequestAuthnContext.cs lasso.cs SamlAttribute.cs \
	SamlSubjectStatementAbstract.cs SamlStatementAbstract.cs


EXTRA_DIST = lasso-sharp.pc.in lasso.dll.config AssemblyInfo.cs lasso-sharp.snk $(SWIG_FILES)

MAINTAINERCLEANFILES = $(SWIG_FILES)

