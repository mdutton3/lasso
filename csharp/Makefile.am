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
	$(SWIG) -v -csharp -module liblassosharpglue -o liblassosharpglue_wrap.c $<


dotnetlibdir = $(datadir)/dotnet/lasso/
dotnetlib_DATA = lasso.dll

lasso.dll: liblassosharpglue.la
	mcs /out:lasso.dll /target:library $(srcdir)/*.cs

clean-local:
	-rm lasso.dll

SWIG_FILES = liblassosharpglue_wrap.c \
	LassoAuthnRequest.cs LassoAuthnResponse.cs LassoIdentity.cs \
	LassoLecp.cs LassoLibAuthnRequest.cs LassoLibAuthnResponse.cs \
	LassoLogin.cs LassoLogout.cs LassoProfile.cs LassoRequest.cs \
	LassoResponse.cs LassoSamlpRequest.cs LassoSamlpResponse.cs \
	LassoServer.cs LassoSession.cs liblassosharpglue.cs \
	liblassosharpgluePINVOKE.cs SWIGTYPE_p_GHashTable.cs \
	SWIGTYPE_p_GObject.cs SWIGTYPE_p_GPtrArray.cs \
	SWIGTYPE_p_LassoLibRequestAuthnContext.cs \
	SWIGTYPE_p_LassoLibScoping.cs SWIGTYPE_p_LassoNode.cs \
	SWIGTYPE_p_LassoProvider.cs SWIGTYPE_p_LassoSamlpRequestAbstract.cs \
	SWIGTYPE_p_LassoSamlpResponseAbstract.cs

EXTRA_DIST = $(SWIG_FILES)

MAINTAINERCLEANFILES = $(SWIG_FILES)

