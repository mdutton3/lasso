INCLUDES = -I$(top_srcdir)

lib_LTLIBRARIES = liblassosharpglue.la

liblassosharpglue_la_SOURCES = \
	liblassosharpglue_wrap.c \
	$(top_srcdir)/swig/Lasso.c

liblassosharpglue_la_CFLAGS = \
	$(LASSO_CFLAGS) \
	-DSWIG_COBJECT_TYPES

liblassosharpglue_la_LIBADD = \
	$(top_builddir)/lasso/liblasso.la \
	$(LASSO_LIBS)

liblassosharpglue_la_LDFLAGS =	-no-undefined -module -avoid-version

liblassosharpglue_wrap.c: $(top_srcdir)/swig/Lasso.i
	$(SWIG) -v -csharp -package lasso -module lasso -o liblassosharpglue_wrap.c $<
	cp liblassosharpglue_wrap.c liblassosharpglue_wrap.c.bak
	sed -e 's/(char \*) "\(.*\)"/malloc("\1")/' \
		< liblassosharpglue_wrap.c.bak > liblassosharpglue_wrap.c

dotnetlibdir = $(datadir)/dotnet/lasso/
dotnetlib_DATA = lasso.dll lasso.dll.config

lasso.dll: liblassosharpglue.la
	$(CSHARPCOMPILER) -out:lasso.dll -target:library $(srcdir)/*.cs

pkgconfig_DATA  = lasso-sharp.pc
pkgconfigdir    = $(libdir)/pkgconfig

install-data-local:
	$(GACUTIL) -i lasso.dll -f -package lasso -gacdir $(libdir)

clean-local:
	-rm lasso.dll lasso-sharp.pc liblassosharpglue_wrap.c.bak

SWIG_FILES = liblassosharpglue_wrap.c \
	LassoAuthnRequest.cs LassoAuthnResponse.cs LassoIdentity.cs \
	LassoLecp.cs LassoLibAuthnRequest.cs LassoLibAuthnResponse.cs \
	LassoLogin.cs LassoLogout.cs LassoProfile.cs LassoRequest.cs \
	LassoResponse.cs LassoSamlpRequest.cs LassoSamlpResponse.cs \
	LassoServer.cs LassoSession.cs lasso.cs lassoPINVOKE.cs \
	SWIGTYPE_p_GHashTable.cs SWIGTYPE_p_GObject.cs SWIGTYPE_p_GPtrArray.cs \
	SWIGTYPE_p_LassoLibRequestAuthnContext.cs \
	SWIGTYPE_p_LassoLibScoping.cs SWIGTYPE_p_LassoNode.cs \
	SWIGTYPE_p_LassoProvider.cs SWIGTYPE_p_LassoSamlpRequestAbstract.cs \
	SWIGTYPE_p_LassoSamlpResponseAbstract.cs

EXTRA_DIST = lasso-sharp.pc.in lasso.dll.config AssemblyInfo.cs lasso-sharp.snk $(SWIG_FILES)

MAINTAINERCLEANFILES = $(SWIG_FILES)

