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
	federation_termination.c \
	login.c \
	logout.c \
	profile_context.c \
	server.c \
	user.c

liblassoinclude_HEADERS = \
	federation_termination.h \
	login.h \
	logout.h \
	profile_context.h \
	server.h \
	user.h
