if WITH_TESTS

TESTS = tests
noinst_PROGRAMS = tests

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	-DTESTSDATADIR=\"$(srcdir)/data/\" \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	$(CHECK_CFLAGS)

tests_SOURCES = tests.c login_tests.c basic_tests.c
tests_LDADD = \
	$(top_builddir)/lasso/liblasso.la \
	$(LASSO_LIBS) \
	$(CHECK_LIBS)
endif

EXTRA_DIST = tests.c login_tests.c basic_tests.c

SUBDIRS = data

CLEANFILES = result.xml

