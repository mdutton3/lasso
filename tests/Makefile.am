MAINTAINERCLEANFILES = Makefile.in
if WITH_TESTS

TESTS = tests
noinst_PROGRAMS = tests perfs

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	-DTESTSDATADIR=\"$(srcdir)/data/\" \
	-DTESTSMETADATADIR=\"$(srcdir)/metadata/\" \
	$(LASSO_CFLAGS) \
	$(CHECK_CFLAGS)

tests_SOURCES = tests.c login_tests.c basic_tests.c random_tests.c metadata_tests.c
tests_LDADD = \
	$(top_builddir)/lasso/liblasso.la \
	$(LASSO_LIBS) \
	$(CHECK_LIBS)
tests_LDFLAGS = -rpath $(top_srcdir)/lasso/.libs/

perfs_SOURCES = perfs.c
perfs_LDADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS)
perfs_LDFLAGS = -rpath $(top_srcdir)/lasso/.libs/

endif

EXTRA_DIST = tests.c login_tests.c basic_tests.c random_tests.c metadata_tests.c

SUBDIRS = data metadata

CLEANFILES = result.xml

