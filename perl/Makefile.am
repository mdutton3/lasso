INCLUDES = -I$(top_srcdir)

noinst_DATA = lasso.pm

lasso_wrap.c lasso.pm: $(top_srcdir)/swig/Lasso.i $(top_srcdir)/swig/Lasso-wsf.i
	$(SWIG) -v -perl5 -module lasso -o lasso_wrap.c $(top_srcdir)/swig/Lasso.i

SWIG_OUTPUTS = lasso_wrap.c lasso.pm

# In distribution, swig generated files are present.
EXTRA_DIST = $(SWIG_OUTPUTS)

# Maintainer clean the swig generated files, because he/she maintains them.
MAINTAINERCLEANFILES = $(SWIG_OUTPUTS)
