MAINTAINERCLEANFILES = Makefile.in
MOSTLYCLEANFILES =

LASSO_XS_CFLAGS = -fno-strict-aliasing $(LASSO_CFLAGS) $(LASSO_CORE_CFLAGS) $(PERL_CFLAGS) $(AM_CFLAGS)

TESTS_ENVIRONMENT=TOP_SRCDIR=$(top_srcdir)
TESTS = test.sh

if PERL_ENABLED
INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(SASL_CFLAGS)

all: Lasso.so

TOCOPY=gobject_handling.c glist_handling.c ghashtable_handling.c Makefile.PL \
	LassoNode.xs test.pl t

EXTRA_DIST=$(TOCOPY) typemap-in typemap-out lang.py __init__.py test.sh

if WSF_ENABLED
EXTRA_ARGS = --enable-id-wsf
endif

# Copy if out of a build
Makefile.perl: $(srcdir)/Makefile.PL Lasso.xs Lasso.pm
	-if [ "$(srcdir)" != "$(builddir)" ]; then \
		for file in $(TOCOPY); do \
			cp -Rf $(srcdir)/$$file .; \
		done; \
		chmod -R u+rwX $(TOCOPY); \
	fi
	$(PERL) Makefile.PL PREFIX=$(prefix) CCFLAGS="$(LASSO_XS_CFLAGS)" INC="-I. -I$(top_srcdir)" LIBS="`$(top_builddir)/lasso-src-config --libs`"

Lasso.xs Lasso.pm: lang.py typemap-in typemap-out
	$(PYTHON) $(top_srcdir)/bindings/bindings.py -l perl --src-dir=$(top_srcdir)/lasso/ $(EXTRA_ARGS)

Lasso.so: Lasso.xs Lasso.pm Makefile.perl gobject_handling.c LassoNode.xs glist_handling.c
	make -f Makefile.perl

CLEANFILES = Lasso.pm Lasso.xs Lasso.so typemap Lasso.o Lasso.bs pm_to_blib Lasso.c blib

clean-local:
	-@make -f Makefile.perl clean
	-@rm -f Makefile.perl
	-if [ "$(srcdir)" != "$(builddir)" ]; then rm -rf `find -H -mindepth 1 -not -name Makefile` t; fi

install-exec-local:
	make -f Makefile.perl install DESTDIR=$(DESTDIR) PREFIX=$(prefix)

uninstall-local:
	@rm -rf `find $(DESTDIR)$(prefix) -name Lasso.pm -or -name Lasso.so -or -name Lasso.bs -or -name .packlist -or -name perllocal.pod`

endif
