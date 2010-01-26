MAINTAINERCLEANFILES = Makefile.in
MOSTLYCLEANFILES =

LASSO_XS_CFLAGS = -fno-strict-aliasing $(LASSO_CFLAGS) $(LASSO_CORE_CFLAGS) $(PERL_CFLAGS) $(AM_CFLAGS)

TESTS = test.sh

if PERL_ENABLED
INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(SASL_CFLAGS)

all: Lasso.so

EXTRA_DIST=gobject_handling.c glist_handling.c typemap.in typemap.out lang.py Makefile.PL LassoNode.xs __init__.py test.pl test.sh t

if WSF_ENABLED
EXTRA_ARGS = --enable-id-wsf
endif

Makefile.perl: $(srcdir)/Makefile.PL Lasso.xs Lasso.pm
	CFLAGS="$(LASSO_XS_CFLAGS)" TOP_SRCDIR="$(top_srcdir)" TOP_BUILDDIR="$(top_builddir)" \
	       SRCDIR="$(srcdir)" BUILDDIR=./ $(PERL) $(srcdir)/Makefile.PL PREFIX=$(prefix)

	-if [ "$(srcdir)" != "$(builddir)" ]; then cp -R $(srcdir)/t $(srcdir)/test.pl $(srcdir)/Makefile.PL $(srcdir)/LassoNode.xs $(builddir); fi

Lasso.xs Lasso.pm: lang.py typemap.in typemap.out
	$(PYTHON) $(top_srcdir)/bindings/bindings.py -l perl --src-dir=$(top_srcdir)/lasso/ $(EXTRA_ARGS)

Lasso.so: Lasso.xs Lasso.pm Makefile.perl gobject_handling.c LassoNode.xs glist_handling.c
	make -f Makefile.perl

CLEANFILES = Lasso.pm Lasso.xs Lasso.so Makefile.perl typemap Lasso.o Lasso.bs pm_to_blib Lasso.c blib

clean-local:
	-make -f Makefile.perl clean
	-if [ "$(srcdir)" != "$(builddir)" ]; then rm -rf `find -mindepth 1 -not -name Makefile`; fi

install-exec-local:
	make -f Makefile.perl install DESTDIR=$(DESTDIR) PREFIX=$(prefix)

endif
