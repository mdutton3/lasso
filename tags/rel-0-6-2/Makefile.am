if PYTHON_ENABLED
    PYTHON_SD = python
endif
if JAVA_ENABLED
    JAVA_SD = java
endif
if PHP_ENABLED
    PHP_SD = php
endif
if CSHARP_ENABLED
    CSHARP_SD = csharp
endif
if PERL_ENABLED
    PERL_SD = perl
endif

SUBDIRS		= lasso \
		  swig \
		  $(PHP_SD) $(PYTHON_SD) $(JAVA_SD) $(CSHARP_SD) $(PERL_SD) \
		  tests \
		  win32 \
		  docs

ABS_BUILDDIR	= $(shell pwd)

EXTRA_DIST	= COPYING lasso.pc.in lasso-src-config.in

pkgconfig_DATA	= lasso.pc
pkgconfigdir	= $(libdir)/pkgconfig

clean-local:
	-rm -f lasso.pc

