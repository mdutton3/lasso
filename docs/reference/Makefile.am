MAINTAINERCLEANFILES = Makefile.in
EXTRA_DIST = \
	lasso-sections.txt \
	lasso.sgml \
	lasso.types.in \
	version.xml.in \
	style.css

if WSF_ENABLED
lasso.types: lasso.types.in
	sed -e 's/#WSF# //g' < $(srcdir)/lasso.types.in > lasso.types
else
lasso.types: lasso.types.in
	grep -v '#WSF#' $(srcdir)/lasso.types.in > lasso.types
endif

	

# We need to pre-process original source files
# because gtkdoc does not understand some C features
#
DOC_SOURCE_DIR = ./code
DOC_SOURCE_FILES = \
	$(shell find $(top_srcdir)/lasso -name '*.c' -print ) \
	$(shell find $(top_srcdir)/lasso -name '*.h' -print | grep -v private)

IGNORE_HFILES = lasso_config.h

# do nothing for all
all: docs

docs: sgml html clean-sources

html: sgml lasso.sgml lasso-index
	@echo '*** Building HTML ***'
	test -d html || mkdir html
	cd html && gtkdoc-mkhtml lasso ../build/lasso.sgml
	cp $(srcdir)/style.css html/

SCANOBJ_FILES = lasso.hierarchy	lasso.signals lasso.interfaces lasso.prerequisites lasso.args

#
# Prepeare sgml files from sources for each library. We are also
# doing some "magic" here by automatically adding links to XML DSig and 
# XML Enc specification, we also remove "Ptr" from the end of the link
# targets to make more references
#
sgml: templates
	@echo '*** Building SGML ***'
	cp $(srcdir)/*.sgml version.xml build/
	cd build && gtkdoc-mkdb --module=lasso \
		    --main-sgml-file=lasso.sgml \
		    --sgml-mode \
		    --output-format=xml \
		    --tmpl-dir=../tmpl/ \
		    --source-dir=../$(DOC_SOURCE_DIR)/lasso \
		    --output-dir=../sgml/
	(for i in `find sgml -name "*.sgml" -print` ; do \
	    cat $$i | \
		sed 's!\(&lt;dsig:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmldsig-core/#sec-\2\">\1\2\3</ulink>!g' | \
		sed 's!\(&lt;enc:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmlenc-core/#sec-\2\">\1\2\3</ulink>!g' | \
		sed 's!linkend=\"\(.*\)Ptr\"!linkend=\"\1\"!g' > \
		$$i.tmp; \
		mv -f $$i.tmp $$i; \
	done);
	rm -f build/sgml && $(LN_S) ../sgml build/sgml


# don't rebuild templates if tmpl is not in srcdir
templates: scan
	@echo '*** Building TMPL ***'
	if test $(top_builddir) = $(top_srcdir); then \
		(cd build && gtkdoc-mktmpl --module=lasso --output-dir=../tmpl/) ; \
	fi

# CFLAGS and LDFLAGS for compiling scan program.
GTKDOC_CFLAGS = 		\
	$(LASSO_CFLAGS) 	\
	-I$(top_builddir)       \
	-I$(top_srcdir)

GTKDOC_LIBS = 	\
	$(LASSO_LIBS) \
	$(top_builddir)/lasso/liblasso.la

GTKDOC_CC = $(LIBTOOL) --mode=compile $(CC)
GTKDOC_LD = $(LIBTOOL) --mode=link $(CC)

scan: doc_sources lasso.types
	test -d build || mkdir build
	@echo '*** Scan sources ***'
	cp $(srcdir)/lasso-sections.txt build/
	if grep -l '^..*$$' lasso.types > /dev/null ; then \
		CC="$(GTKDOC_CC)" LD="$(GTKDOC_LD)" CFLAGS="$(GTKDOC_CFLAGS)" LDFLAGS="$(GTKDOC_LIBS)" gtkdoc-scangobj $(SCANOBJ_OPTIONS) --module=lasso --types=lasso.types --output-dir=build/ ; \
	else \
		cd $(srcdir) ; \
		for i in $(SCANOBJ_FILES) ; do \
			test -f $$i || touch $$i ; \
		done \
	fi
	gtkdoc-scan --module=lasso \
		--source-dir=$(DOC_SOURCE_DIR)/lasso/ \
		--output-dir=build/ \
		--ignore-headers="$(IGNORE_HFILES)"

#
# Prepare source files by coping them to "code" folder and 
# removing LASSO_EXPORT* stuff that makes gtkdoc crazy
#
doc_sources: $(DOC_SOURCE_FILES)
	@echo '*** Prepare sources ***'
	(for i in $(DOC_SOURCE_FILES) ; do \
	    folder_name=`echo $$i | sed 's#$(top_srcdir)/##' | sed 's#/[^/]*$$##'`; \
	    file_name=`echo $$i | sed 's#.*/##'`; \
	    test -d $(DOC_SOURCE_DIR)/$$folder_name || mkdir -p $(DOC_SOURCE_DIR)/$$folder_name; \
	    cat $$i | \
		sed 's/#if.*//' | \
		sed 's/#el.*//' | \
		sed 's/#end.*//' | \
		sed 's/LASSO_EXPORT_VAR//' | \
		sed 's/LASSO_EXPORT//' > \
		$(DOC_SOURCE_DIR)/$$folder_name/$$file_name; \
	done);

#
# Create index for all functions. For macros and defines need to add -CAPS suffix
#
lasso-index: scan 
	@echo '*** Create functions index ***'
	grep -h '<NAME>.*</NAME>' build/lasso-*decl.txt | \
		grep -v '<NAME>extern</NAME>' | \
		sort -u | \
		sed 's#_#-#g' | \
		sed 's#<NAME>\([^-]*\)-\([^<]*\)</NAME>#<listitem><para><link linkend=\"\1-\2-CAPS\">\1-\2</link></para></listitem>#g' | \
		sed 's#<NAME>\([^<]*\)</NAME>#<listitem><para><link linkend=\"\1\">\1</link></para></listitem>#g' > \
		sgml/lasso-index.sgml

clean-local: clean-sources
	-rm -rf $(DOC_SOURCE_DIR)
	-rm -rf .libs
	-if test $(top_builddir) != $(top_srcdir); then rm -f tmpl/*.sgml ; fi
	-rm -rf sgml
	-rm -rf html
	-rm -rf build
	-rm -f $(SCANOBJ_FILES) index.sgml lasso-index.sgml
	-rm -rf  $(SCANOBJ_FILES) *.o *~ *.bak *.stamp
	-rm -f lasso.types
	-rm -rf tmpl

clean-sources:
	-rm -rf code

maintainer-clean-local: clean
	-rm -rf `find sgml -name "*.sgml" -print`

if GTK_DOC_ENABLED
dist-check-gtkdoc:
else
dist-check-gtkdoc:
	@echo "*** gtk-doc must be installed and enabled in order to make dist"
	@false
endif

dist-hook: dist-check-gtkdoc dist-hook-local
	mkdir $(distdir)/tmpl
	mkdir $(distdir)/html
	-cp $(srcdir)/tmpl/*.sgml $(distdir)/tmpl
	-cp $(srcdir)/html/* $(distdir)/html

.PHONY : dist-hook-local
