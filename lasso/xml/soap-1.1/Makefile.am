MAINTAINERCLEANFILES = Makefile.in

liblassoincludedir = $(includedir)/lasso/xml/soap-1.1

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-xml-soap11.la

liblasso_xml_soap11_la_SOURCES = \
	soap_body.c \
	soap_detail.c \
	soap_fault.c \
	soap_envelope.c \
	soap_header.c

liblassoinclude_HEADERS = \
	soap_body.h \
	soap_detail.h \
	soap_fault.h \
	soap_envelope.h \
	soap_header.h \
	xml_soap11.h
