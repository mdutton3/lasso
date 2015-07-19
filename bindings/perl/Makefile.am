if HAVE_AM_SILENT_RULES
AM_V_SUBMAKE = $(am__v_SUBMAKE_$(V))
am__v_SUBMAKE_ = $(am__v_SUBMAKE_$(AM_DEFAULT_VERBOSITY))
am__v_SUBMAKE_0 = @echo "  SUBMAKE    " $@; LOG=`mktemp tmp.XXXXXXXX`; (

AM_V_SUBMAKE_POSTFIX = $(am__v_SUBMAKE_POSTFIX_$(V))
am__v_SUBMAKE_POSTFIX_ = $(am__v_SUBMAKE_POSTFIX_$(AM_DEFAULT_VERBOSITY))
am__v_SUBMAKE_POSTFIX_0 = 2>&1 >$$LOG && rm $$LOG ) || ( cat $$LOG; rm $$LOG )
endif

MAINTAINERCLEANFILES = Makefile.in
DISTCLEANFILES = __init__.pyc lang.pyc Makefile.perl.old
CLEANFILES = Lasso.pm Lasso.xs Lasso.so typemap Lasso.o Lasso.bs pm_to_blib Lasso.c

LASSO_XS_CFLAGS = -fno-strict-aliasing $(LASSO_CFLAGS) $(LASSO_CORE_CFLAGS) $(PERL_CFLAGS) $(AM_CFLAGS) -Wno-unused-but-set-variable

TESTS_ENVIRONMENT=TOP_SRCDIR=$(top_srcdir)
TESTS = test.sh

if PERL_ENABLED
AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(SASL_CFLAGS)

all: blib/arch/auto/Lasso/Lasso.so Lasso.pm

TOCOPY=gobject_handling.c glist_handling.c ghashtable_handling.c Makefile.PL \
	LassoNode.xs test.pl t

EXTRA_DIST=$(TOCOPY) typemap-in typemap-out lang.py __init__.py test.sh

if WSF_ENABLED
EXTRA_ARGS = --enable-id-wsf
endif

# Copy if out of a build
Makefile.perl: $(srcdir)/Makefile.PL Lasso.xs Lasso.pm
	$(AM_V_GEN) if [ "$(srcdir)" != "$(builddir)" ]; then \
		for file in $(TOCOPY); do \
			if [ $(srcdir)/$$file -nt $$file ]; then cp -Rf $(srcdir)/$$file .; fi; \
		done; \
		chmod -R u+rwX $(TOCOPY); \
	fi;
	$(AM_V_SUBMAKE) $(PERL) Makefile.PL INSTALLDIRS=vendor CCFLAGS="$(LASSO_XS_CFLAGS)" INC="-I. -I$(top_srcdir) -I$(srcdir)" LIBS="`$(top_builddir)/lasso-src-config --libs`" OPTIMIZE="-g" $(AM_V_SUBMAKE_POSTFIX)

Lasso.xs Lasso.pm: lang.py typemap-in typemap-out
	$(AM_V_GEN) $(PYTHON) $(top_srcdir)/bindings/bindings.py -l perl --src-dir=$(top_srcdir)/lasso/ $(EXTRA_ARGS)

blib/arch/auto/Lasso/Lasso.so: Lasso.xs Lasso.pm Makefile.perl gobject_handling.c LassoNode.xs glist_handling.c
	$(AM_V_SUBMAKE) make -f Makefile.perl $(AM_V_SUBMAKE_POSTFIX)

distclean-local:
	-@if [ "$(srcdir)" != "$(builddir)" ]; then \
		rm -rf $(TOCOPY); \
	fi

clean-local:
	-@if [ -f Makefile.perl ]; then make -f Makefile.perl clean; fi; rm -f Makefile.perl

install-exec-local: Makefile.perl
	make -f Makefile.perl install DESTDIR=$(DESTDIR) PREFIX=$(prefix)

uninstall-local:
	-@rm -rf `find $(DESTDIR)$(prefix) -name Lasso.pm -or -name Lasso.so -or -name Lasso.bs -or -name .packlist -or -name perllocal.pod`

endif
