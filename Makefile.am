if PYTHON_ENABLED
    PYTHON_SD = python
endif
if JAVA_ENABLED
    JAVA_SD = java
endif
if PHP4_ENABLED
    PHP4_SD = php
endif
if PHP5_ENABLED
    PHP5_SD = php5
endif
if CSHARP_ENABLED
    CSHARP_SD = csharp
endif
if PERL_ENABLED
    PERL_SD = perl
endif

SUBDIRS		= lasso \
		  swig \
		  $(PHP4_SD) $(PHP5_SD) $(PYTHON_SD) $(JAVA_SD) $(PERL_SD) \
		  tests \
		  win32 \
		  docs

ABS_BUILDDIR	= $(shell pwd)

EXTRA_DIST	= COPYING lasso.pc.in lasso-src-config.in

pkgconfig_DATA	= lasso.pc
pkgconfigdir	= $(libdir)/pkgconfig

clean-local:
	-rm -f lasso.pc

