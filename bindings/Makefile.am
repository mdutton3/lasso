MAINTAINERCLEANFILES = Makefile.in
SUBDIRS =
if PYTHON_ENABLED
SUBDIRS += python
endif
if PHP5_ENABLED
SUBDIRS += php5
endif
if JAVA_ENABLED
SUBDIRS += java
endif
if PERL_ENABLED
SUBDIRS += perl
endif

CLEANFILES = bindings.pyc lang_java.pyc lang_python.pyc lang_php5.pyc \
             utils.pyc lang_php5_helpers/__init__.pyc lang_php5_helpers/php_code.pyc \
              lang_php5_helpers/wrapper_header.pyc lang_php5_helpers/wrapper_source.pyc

EXTRA_DIST = bindings.py \
	overrides.xml \
	utils.py \
	utility-scripts/error-analyzer.pl \
	ghashtable.h \
	utils.c

