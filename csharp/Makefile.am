INCLUDES = -I$(top_srcdir)

lib_LTLIBRARIES = liblassosharpglue.la

liblassosharpglue_la_SOURCES = \
	liblassosharpglue_wrap.c

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
	lassoPINVOKE.cs        lasso.cs          Server.cs  \
	Defederation.cs        Request.cs        Session.cs \
	Identity.cs            Response.cs       AuthnRequest.cs \
	Lecp.cs                AuthnResponse.cs  Login.cs \
	Logout.cs              LogoutResponse.cs LogoutRequest.cs \
	FederationTerminationNotification.cs     Assertion.cs

EXTRA_DIST = lasso-sharp.pc.in lasso.dll.config AssemblyInfo.cs lasso-sharp.snk $(SWIG_FILES)

MAINTAINERCLEANFILES = $(SWIG_FILES)

