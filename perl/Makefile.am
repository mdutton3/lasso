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

lasso_wrap.c lasso.pm: $(top_srcdir)/swig/Lasso.i $(top_srcdir)/swig/Lasso-wsf.i
	$(SWIG) -v -perl5 -module lasso -o lasso_wrap.c $(top_srcdir)/swig/Lasso.i

$(PERL_MAKEFILE): $(srcdir)/Makefile.PL lasso.pm
	VERSION=$(VERSION) CFLAGS="$(AM_CPPFLAGS) $(SWIG_OPTS) $(CPPFLAGS) $(AM_STANDARD_CFLAGS)" $(PERL) $(srcdir)/Makefile.PL $(MAKE_PL_OPTS)

-perl install-perl: $(PERL_MAKEFILE)
	@target=`echo $@ | sed -e 's/-perl//'`; \
	echo $(MAKE) -f $(PERL_MAKEFILE) $$target; \
	$(MAKE) -f $(PERL_MAKEFILE) $$target

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
EXTRA_DIST = $(SWIG_OUTPUTS)

# Maintainer clean the swig generated files, because he/she maintains them.
MAINTAINERCLEANFILES = $(SWIG_OUTPUTS)

clean-local:
	rm -rf blib $(PERL_MAKEFILE) $(PERL_MAKEFILE).old build-perl-stamp $(PERL_CRUFT)

# See this is the fake bit
install-fakeDATA: install-perl
