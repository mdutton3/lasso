SUBDIRS = elements

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	$(PY_CFLAGS) \
	$(NULL)

PROTSOURCES = \
	py_authn_request.c \
	py_authn_response.c \
	py_federation_termination_notification.c \
	py_logout_request.c \
	py_logout_response.c \
	py_name_identifier_mapping_request.c \
	py_name_identifier_mapping_response.c \
	py_register_name_identifier_request.c \
	py_register_name_identifier_response.c


if WITH_PYTHON
libprotocols_a_SOURCES = $(PROTSOURCES)
noinst_LIBRARIES = libprotocols.a
endif

EXTRA_DIST = \
	$(PROTSOURCES) \
	py_authn_request.h \
	py_authn_response.h \
	py_federation_termination_notification.h \
	py_logout_request.h \
	py_logout_response.h \
	py_name_identifier_mapping_request.h \
	py_name_identifier_mapping_response.h \
	py_register_name_identifier_request.h \
	py_register_name_identifier_response.h

