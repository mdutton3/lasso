SUBDIRS = 

liblassoincludedir = $(includedir)/lasso/environs

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-environs.la

liblasso_environs_la_SOURCES = \
	federation_termination.c \
	lecp.c \
	login.c \
	logout.c \
	name_identifier_mapping.c \
	profile_context.c \
	register_name_identifier.c \
	server.c \
	session.c \
	user.c

liblassoinclude_HEADERS = \
	federation_termination.h \
	lecp.h \
	login.h \
	logout.h \
	name_identifier_mapping.h \
	profile_context.h \
	register_name_identifier.h \
	server.h \
	session.h \
	user.h
