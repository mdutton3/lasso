if WITH_TESTS

TESTS = login_tests
noinst_PROGRAMS = login_tests

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	$(CHECK_CFLAGS)

login_tests_SOURCES = login_tests.c
login_tests_LDADD = \
	$(top_builddir)/lasso/liblasso.la \
	$(LASSO_LIBS) \
	$(CHECK_LIBS)
endif

EXTRA_DIST = login_tests.c

