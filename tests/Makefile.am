if WITH_TESTS

TESTS = tests
noinst_PROGRAMS = tests perfs

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	-DTESTSDATADIR=\"$(srcdir)/data/\" \
	-DTESTSMETADATADIR=\"$(srcdir)/metadata/\" \
	$(LASSO_CFLAGS) \
	$(CHECK_CFLAGS)

tests_SOURCES = tests.c login_tests.c basic_tests.c random_tests.c metadata_tests.c
tests_LDADD = \
	$(top_builddir)/lasso/liblasso.la \
	$(LASSO_LIBS) \
	$(CHECK_LIBS)

perfs_SOURCES = perfs.c
perfs_LDADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS)

endif

EXTRA_DIST = tests.c login_tests.c basic_tests.c random_tests.c metadata_tests.c

SUBDIRS = data metadata

CLEANFILES = result.xml

