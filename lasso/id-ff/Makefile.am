SUBDIRS = 

liblassoincludedir = $(includedir)/lasso/environs

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(GLIB_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(XMLSEC1_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-environs.la

liblasso_environs_la_SOURCES = \
	provider.c \
	server_environ.c \
	session_environ.c \
	user_environ.c \
	identity.c

liblassoinclude_HEADERS = \
	provider.h \
	server_environ.h \
	session_environ.h \
	user_environ.h \
	identity.h