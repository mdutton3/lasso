docdir = $(datadir)/doc/lasso

LASSOBOOK_FILES = book.rst common-knowledge.rst getting-lasso.rst \
		  integration.rst language-bindings.rst lasso-architecture.rst \
		  liberty-architecture.rst other-profiles.rst preface.rst \
		  single-sign-on.rst

if HAVE_REST2HTML
doc_DATA = writing-a-c-sp.html book.html
else
doc_DATA = writing-a-c-sp.txt $(LASSOBOOK_FILES)
endif

%.html: %.txt
	$(REST2HTML) $? > $@

%.html: %.rst
	$(REST2HTML) $? > $@

CLEANFILES = writing-a-c-sp.html book.html
EXTRA_DIST = lasso-book.txt writing-a-c-sp.txt $(LASSOBOOK_FILES)

