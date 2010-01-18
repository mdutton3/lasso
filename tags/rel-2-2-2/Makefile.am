if PHP4_ENABLED
    PHP4_SD = php
endif
if CSHARP_ENABLED
    CSHARP_SD = csharp
endif
if PERL_ENABLED
    PERL_SD = perl
endif

SUBDIRS		= lasso \
		  swig \
		  $(PHP4_SD) $(PERL_SD) \
		  tests \
		  win32 \
		  bindings \
		  docs

EXTRA_DIST	= COPYING lasso.pc.in lasso-src-config.in

MAINTAINERCLEANFILES = \
    Makefile.in \
    config.guess \
    config.sub \
    configure \
    install-sh \
    missing
 

pkgconfig_DATA	= lasso.pc
pkgconfigdir	= $(libdir)/pkgconfig

clean-local:
	-rm -f lasso.pc

