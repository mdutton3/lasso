INCLUDES = -I$(top_srcdir)

csharp_LTLIBRARIES = lassomod.la
csharpdir = /tmp

lassomod_la_SOURCES = lassomod_wrap.c \
			$(top_srcdir)/swig/Lasso.c

lassomod_la_CFLAGS =	$(LASSO_CFLAGS) \
			-DSWIG_COBJECT_TYPES

lassomod_la_LIBADD =	$(top_builddir)/lasso/liblasso.la \
			$(LASSO_LIBS)

lassomod_la_LDFLAGS =	-no-undefined -module -avoid-version

lassomod_wrap.c: $(top_srcdir)/swig/Lasso.i
	$(SWIG) -v -csharp -module lassomod -o lassomod_wrap.c $<

SWIG_OUTPUTS = lassomod_wrap.c SWIGTYPE*.cs lasso*.cs Lasso*.cs

MAINTAINERCLEANFILES = $(SWIG_OUTPUTS)

