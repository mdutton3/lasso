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

liblassosharpglue_wrap.c: $(top_srcdir)/swig/Lasso.i $(top_srcdir)/swig/Lasso-wsf.i
	$(SWIG) -v -csharp -module lasso -o liblassosharpglue_wrap.c $(top_srcdir)/swig/Lasso.i
	cp liblassosharpglue_wrap.c liblassosharpglue_wrap.c.bak
	sed -e 's/(char \*) "\(.*\)"/malloc("\1")/' \
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
	Defederation.cs Identity.cs lasso.cs lassoHttpMethod.cs \
	lassoLoginProtocolProfile.cs lassoMessageType.cs lassoPINVOKE.cs \
	LassoProviderRole.cs lassoRequestType.cs lassoSignatureMethod.cs \
	Lecp.cs LibAssertion.cs LibAuthnRequest.cs LibAuthnResponse.cs \
	LibFederationTerminationNotification.cs LibLogoutRequest.cs \
	LibLogoutResponse.cs LibRegisterNameIdentifierRequest.cs \
	LibRegisterNameIdentifierResponse.cs Login.cs Logout.cs \
	NameIdentifierMapping.cs NameRegistration.cs Node.cs Provider.cs \
	ProviderIds.cs SamlpRequest.cs SamlpResponse.cs Server.cs \
	Session.cs SWIGTYPE_p_void.cs


EXTRA_DIST = lasso-sharp.pc.in lasso.dll.config AssemblyInfo.cs lasso-sharp.snk $(SWIG_FILES)

MAINTAINERCLEANFILES = $(SWIG_FILES)

