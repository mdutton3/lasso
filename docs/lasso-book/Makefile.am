docdir = $(datadir)/doc/lasso

if HAVE_REST2HTML
doc_DATA = writing-a-c-sp.html
else
doc_DATA = writing-a-c-sp.txt
endif

%.html: %.txt
	$(REST2HTML) $? > $@

CLEANFILES = writing-a-c-sp.html
EXTRA_DIST = lasso-book.txt writing-a-c-sp.txt

