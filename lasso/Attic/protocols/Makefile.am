liblassoincludedir = $(includedir)/lasso/protocols

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(GLIB_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(XMLSEC1_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-protocols.la

liblasso_protocols_la_SOURCES = \
	single_sign_on_and_federation.c \
	logout.c \
	federation_termination_notification.c \
	register_name_identifier.c

liblassoinclude_HEADERS = \
	single_sign_on_and_federation.h \
	logout.h \
	federation_termination_notification.h \
	register_name_identifier.h \
	protocols.h
