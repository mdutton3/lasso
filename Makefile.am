if PYTHON_ENABLED
    PYTHON_SD = python
endif
if JAVA_ENABLED
    JAVA_SD = java
endif
if PHP_ENABLED
    PHP_SD = php
endif
if GTK_DOC_ENABLED
    GTK_DOC_SD = docs
endif

SUBDIRS		= lasso \
		  $(PHP_SD) $(PYTHON_SD) $(JAVA_SD) \
		  tests \
		  swig \
		  $(GTK_DOC_SD)

ABS_BUILDDIR	= $(shell pwd)

EXTRA_DIST	= COPYING lasso.pc.in

pkgconfig_DATA	= lasso.pc
pkgconfigdir	= $(libdir)/pkgconfig

clean-local:
	-rm -f lasso.pc

