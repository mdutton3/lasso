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
	defederation.c \
	identity.c \
	lecp.c \
	login.c \
	logout.c \
	name_identifier_mapping.c \
	profile.c \
	register_name_identifier.c \
	server.c \
	session.c

liblassoinclude_HEADERS = \
	defederation.h \
	identity.h \
	lecp.h \
	login.h \
	logout.h \
	name_identifier_mapping.h \
	profile.h \
	register_name_identifier.h \
	server.h \
	session.h
