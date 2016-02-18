MAINTAINERCLEANFILES = Makefile.in

liblassoincludedir = $(includedir)/lasso/xml/ecp

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-xml-ecp.la

liblasso_xml_ecp_la_SOURCES = \
	ecp_request.c \
	ecp_response.c \
	ecp_relaystate.c

liblassoinclude_HEADERS = \
	ecp_request.h \
	ecp_response.h \
	ecp_relaystate.h
