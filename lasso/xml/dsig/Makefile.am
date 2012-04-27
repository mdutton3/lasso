MAINTAINERCLEANFILES = Makefile.in
liblassoincludedir = $(includedir)/lasso/xml/dsig

INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-xml-dsig.la

liblasso_xml_dsig_la_SOURCES = \
	ds_key_info.c \
	ds_key_value.c \
	ds_rsa_key_value.c \
	ds_x509_data.c

liblassoinclude_HEADERS = \
	ds_key_info.h \
	ds_key_value.h \
	ds_rsa_key_value.h \
	ds_x509_data.h \
	strings.h \
	xml_dsig.h
