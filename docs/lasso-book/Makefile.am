
if HAVE_REST2HTML
doc_DATA = writing-a-c-sp.html
else
doc_DATA = writing-a-c-sp.txt
endif

writing-a-c-sp.html: writing-a-c-sp.txt
	$(REST2HTML) writing-a-c-sp.txt > writing-a-c-sp.html

EXTRA_DIST = \
            lasso-book.txt writing-a-c-sp.txt

