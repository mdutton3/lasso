MAINTAINERCLEANFILES = Makefile.in
if HAVE_INKSCAPE
if HAVE_XSLTPROC
SUBDIRS = figures
endif
endif

docdir = $(datadir)/doc/lasso

LASSOBOOK_FILES = book.rst common-knowledge.rst getting-lasso.rst \
		  integration.rst language-bindings.rst lasso-architecture.rst \
		  liberty-architecture.rst other-profiles.rst preface.rst \
		  single-sign-on.rst

SP_DOC_FILES = writing-a-c-sp.txt writing-a-php-sp.txt writing-a-java-sp.txt \
		  writing-a-saml2-php-sp.txt

SP_DOC_HTML = writing-a-c-sp.html writing-a-php-sp.html writing-a-java-sp.html \
		  writing-a-saml2-php-sp.html

if HAVE_REST2HTML
doc_DATA = $(SP_DOC_HTML) book.html
else
doc_DATA = $(SP_DOC_FILES) $(LASSOBOOK_FILES)
endif

%.html: %.txt
	$(REST2HTML) --stylesheet=default.css --link-stylesheet $? > $@

%.html: %.rst
	$(REST2HTML) $? > $@

CLEANFILES = $(SP_DOC_HTML) book.html
EXTRA_DIST = lasso-book.txt $(LASSOBOOK_FILES) $(SP_DOC_FILES) default.css

