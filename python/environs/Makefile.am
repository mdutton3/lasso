noinst_LIBRARIES = libenvirons.a

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	$(PY_CFLAGS) \
	$(NULL)


libenvirons_a_SOURCES = py_federation_termination.c py_login.c py_logout.c py_profile_context.c py_register_name_identifier.c py_server.c py_user.c

EXTRA_DIST = py_federation_termination.h py_login.h py_logout.h py_profile_context.h py_register_name_identifier.h py_server.h py_user.h

