INCLUDES = -I$(top_srcdir)

AM_CPPFLAGS=@CPPFLAGS@ -I$(top_srcdir) -I$(top_builddir)/lasso @LASSO_CFLAGS@
AM_CFLAGS=@CFLAGS@ @LASSO_CORE_CFLAGS@
AM_STANDARD_CFLAGS=@LASSO_CORE_CFLAGS@

PERL=@PERL@

PERL_LASSO_PACKAGE=Lasso
PERL_MAKEFILE=Makefile.perl

PERL_CRUFT=pm_to_blib lasso.bs lasso_wrap.o $(PERL_MAKEFILE).old

fakedir=$(prefix)
fake_DATA=build-perl-stamp

SWIG_I_FILES=$(shell find $(top_srcdir)/swig/ -name '*.[ih]')
lasso_wrap.c lasso.pm: $(SWIG_I_FILES)
	$(SWIG) -v -perl5 -module lasso -o lasso_wrap.c $(top_srcdir)/swig/Lasso.i

$(PERL_MAKEFILE): lasso.pm
	test -e Makefile.PL || $(LN_S) $(srcdir)/Makefile.PL .
	test -e lasso_wrap.c || $(LN_S) $(srcdir)/lasso_wrap.c .
	test -e lasso.pm || $(LN_S) $(srcdir)/lasso.pm .
	VERSION=$(VERSION) CC=$(CC) CFLAGS="$(AM_CPPFLAGS) $(AM_CFLAGS) $(SWIG_OPTS) $(CPPFLAGS) $(AM_STANDARD_CFLAGS)" $(PERL) $(srcdir)/Makefile.PL DESTDIR=$(DESTDIR) PREFIX=$(prefix) $(MAKE_PL_OPTS)

-perl install-perl: $(PERL_MAKEFILE)
	target=`echo $@ | sed -e 's/-perl//'`; \
	$(MAKE) -f $(PERL_MAKEFILE) DESTDIR=$(DESTDIR) PREFIX=$(prefix) $$target

test-perl: $(PERL_MAKEFILE)
	$(RUN)$(MAKE) -f $(PERL_MAKEFILE) test

clean-perl realclean-perl:
	@target=`echo $@ | sed -e 's/-perl//'`; \
	if test -r $(PERL_MAKEFILE); then \
	  echo $(MAKE) -f $(PERL_MAKEFILE) $$target; \
	  $(MAKE) -f $(PERL_MAKEFILE) $$target; \
	fi

build-perl: -perl

build-perl-stamp: ../swig/Lasso.i
	$(MAKE) build-perl && touch build-perl-stamp



SWIG_OUTPUTS = lasso_wrap.c lasso.pm

# In distribution, swig generated files are present.
EXTRA_DIST = $(SWIG_OUTPUTS) Makefile.PL

# Maintainer clean the swig generated files, because he/she maintains them.
MAINTAINERCLEANFILES = $(SWIG_OUTPUTS)

clean-local:
	rm -rf blib $(PERL_MAKEFILE) $(PERL_MAKEFILE).old build-perl-stamp $(PERL_CRUFT)
	-test -L Makefile.PL && rm Makefile.PL
	-test -L lasso.pm && rm lasso.pm
	-test -L lasso_wrap.c && rm lasso_wrap.c


# perl module installation disabled since broken wrt to make distcheck
install-fakeDATA: install-perl

uninstall-local:
	find $(DESTDIR)$(prefix) -name lasso -type d | grep perl | xargs rm -rf
	find $(DESTDIR)$(prefix) -name lasso.pm -exec rm -f {} \;
	find $(DESTDIR)$(prefix) -name perllocal.pod -exec rm -f {} \;
	true

