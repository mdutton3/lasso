INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	$(PY_CFLAGS) \
	$(NULL)


ENVSOURCES = py_federation_termination.c py_lecp.c py_login.c py_logout.c py_profile.c py_register_name_identifier.c py_server.c py_session.c py_identity.c

if WITH_PYTHON
noinst_LIBRARIES = libenvirons.a
libenvirons_a_SOURCES = $(ENVSOURCES)
endif

EXTRA_DIST = $(ENVSOURCES) py_federation_termination.h py_lecp.h py_login.h py_logout.h py_profile.h py_register_name_identifier.h py_server.h py_session.h py_identity.h

