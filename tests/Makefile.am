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
	-DTESTSMETADATADIR=\"$(srcdir)/metadata/\" \
	$(LASSO_CFLAGS) \
	$(CHECK_CFLAGS)


tests_SOURCES = tests.c login_tests.c basic_tests.c random_tests.c metadata_tests.c login_tests_saml2.c $(WSF_TESTS)

tests_LDADD = \
	$(top_builddir)/lasso/liblasso.la \
	$(LASSO_LIBS) \
	$(CHECK_LIBS)
tests_LDFLAGS = -rpath `cd $(top_builddir)/lasso/.libs/; pwd`

tests2_SOURCES = tests2.c
tests2_LDADD = \
	$(top_builddir)/lasso/liblasso.la \
	$(LASSO_LIBS) \
	$(CHECK_LIBS)
tests2_LDFLAGS = -rpath `cd $(top_builddir)/lasso/.libs/; pwd`
tests2_CFLAGS = -DSRCDIR=\"$(srcdir)\"

perfs_SOURCES = perfs.c
perfs_LDADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS)
perfs_LDFLAGS = -rpath `cd $(top_builddir)/lasso/.libs/; pwd`

endif
g
EXTRA_DIST = valgrind tests.h $(tests_SOURCES)

SUBDIRS = data metadata

CLEANFILES = result.xml

