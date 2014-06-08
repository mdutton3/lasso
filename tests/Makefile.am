MAINTAINERCLEANFILES = Makefile.in

WSF_TESTS=

if WSF_ENABLED
WSF_TESTS+=idwsf2_tests.c
endif

if WITH_TESTS

TESTS = tests tests2
noinst_PROGRAMS = tests perfs tests2


INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-DTESTSDATADIR=\"$(srcdir)/data/\" \
	-DTESTSMETADATADIR=\"$(srcdir)/data/metadata/\" \
	$(LASSO_CFLAGS) \
	$(CHECK_CFLAGS)


tests_SOURCES = tests.c login_tests.c basic_tests.c non_regression_tests.c random_tests.c metadata_tests.c login_tests_saml2.c assertion_query_saml2.c $(WSF_TESTS)

tests_LDADD = \
	$(top_builddir)/lasso/liblasso.la \
	$(LASSO_LIBS) \
	$(CHECK_LIBS)
tests_LDFLAGS = -rpath `cd $(top_builddir)/lasso/.libs/; pwd` -static

tests2_SOURCES = tests2.c
tests2_LDADD = \
	$(top_builddir)/lasso/liblasso.la \
	$(LASSO_LIBS) \
	$(CHECK_LIBS)
tests2_LDFLAGS = -rpath `cd $(top_builddir)/lasso/.libs/; pwd`
tests2_CFLAGS = $(AM_CFLAGS) -DSRCDIR=\"$(srcdir)\"

perfs_SOURCES = perfs.c
perfs_LDADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS)
perfs_LDFLAGS = -rpath `cd $(top_builddir)/lasso/.libs/; pwd`

.PHONY: valgrind

LEAKCHECK = G_DEBUG=gc-friendly MALLOC_CHECK_=2 G_SLICE=always-malloc CK_FORK=no \
		valgrind --leak-check=full --log-file=valgrind.log \
		--suppressions=$(top_srcdir)/tests/valgrind/glib.supp \
		--suppressions=$(top_srcdir)/tests/valgrind/openssl.supp \
		--suppressions=$(top_srcdir)/tests/valgrind/lasso.supp \
		--num-callers=50

LEAKCHECK_REACHABLE = $(LEAKCHECK) --show-reachable=yes

LEAKCHECK_GENSUPPRESSIONS=$(LEAKCHECK) --gen-suppressions=all

MASSIF = G_DEBUG=gc-friendly MALLOC_CHECK_=2 G_SLICE=always-malloc CK_FORK=no \
		valgrind --tool=massif

leakcheck:
	$(LEAKCHECK) ./tests

leakcheck-reachable:
	$(LEAKCHECK_REACHABLE) ./tests

leakcheck-gensuppressions:
	$(LEAKCHECK_GENSUPPRESSIONS) ./tests

massif:
	$(MASSIF) ./tests

endif
EXTRA_DIST = valgrind tests.h $(tests_SOURCES)

SUBDIRS = data

CLEANFILES = result.xml

