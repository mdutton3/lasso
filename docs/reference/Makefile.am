TOP=$(top_srcdir)
DOC_MAIN_SGML_FILE=lasso.sgml
SOURCE_DIR=$(TOP)/lasso
INCLUDE_DIR=$(TOP)/lasso

EXTRA_DIST = \
	lasso-sections.txt \
	lasso.sgml \
	lasso.types 

# Extra options to pass to gtkdoc-scangobj.
SCANOBJ_OPTIONS=

#
# We need to pre-process original source files
# because gtkdoc does not understand some C features
#
DOC_SOURCE_DIR=./code
DOC_SOURCE_FILES=\
	$(shell find $(SOURCE_DIR) -name '*.c' -print ) \
	$(shell find $(INCLUDE_DIR) -name '*.h' -print )

# do nothing for all
all: docs

docs: sgml html clean-sources

html: sgml $(DOC_MAIN_SGML_FILE) lasso-index
	@echo '*** Building HTML ***'
	test -d html || mkdir html
	cd html && gtkdoc-mkhtml lasso ../build/$(DOC_MAIN_SGML_FILE)

SCANOBJ_FILES = lasso.hierarchy	lasso.signals lasso.interfaces lasso.prerequisites lasso.args

#
# Prepeare sgml files from sources for each library. We are also
# doing some "magic" here by automatically adding links to XML DSig and 
# XML Enc specification, we also remove "Ptr" from the end of the link
# targets to make more references
#
sgml: templates
	@echo '*** Building SGML ***'
	cd build && gtkdoc-mkdb --module=lasso \
		    --main-sgml-file=$(DOC_MAIN_SGML_FILE) \
		    --tmpl-dir=../tmpl/ \
		    --source-dir=../$(DOC_SOURCE_DIR)/lasso \
		    --output-dir=../sgml/
	cp $(srcdir)/lasso.sgml build/
	(for i in `find sgml -name "*.sgml" -print` ; do \
	    cat $$i | \
		sed 's!\(&lt;dsig:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmldsig-core/#sec-\2\">\1\2\3</ulink>!g' | \
		sed 's!\(&lt;enc:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmlenc-core/#sec-\2\">\1\2\3</ulink>!g' | \
		sed 's!linkend=\"\(.*\)Ptr\"!linkend=\"\1\"!g' > \
		$$i.tmp; \
		mv -f $$i.tmp $$i; \
	done);
	rm -f build/sgml && $(LN_S) ../sgml build/sgml

templates: scan
	@echo '*** Building TMPL ***'
	cd build && gtkdoc-mktmpl --module=lasso --output-dir=../tmpl/

# CFLAGS and LDFLAGS for compiling scan program.
GTKDOC_CFLAGS = 		\
	$(LASSO_CFLAGS) 	\
	-I$(top_srcdir)

GTKDOC_LIBS = 	\
	$(LASSO_LIBS) \
	$(top_builddir)/lasso/liblasso.la

GTKDOC_CC=$(LIBTOOL) --mode=compile $(CC)
GTKDOC_LD=$(LIBTOOL) --mode=link $(CC)

scan: doc_sources
	test -d build || mkdir build
	@echo '*** Scan sources ***'
	cp $(srcdir)/lasso-sections.txt build/
	if grep -l '^..*$$' $(srcdir)/lasso.types > /dev/null ; then \
		CC="$(GTKDOC_CC)" LD="$(GTKDOC_LD)" CFLAGS="$(GTKDOC_CFLAGS)" LDFLAGS="$(GTKDOC_LIBS)" gtkdoc-scangobj $(SCANOBJ_OPTIONS) --module=lasso --types=$(srcdir)/lasso.types --output-dir=build/ ; \
	else \
		cd $(srcdir) ; \
		for i in $(SCANOBJ_FILES) ; do \
			test -f $$i || touch $$i ; \
		done \
	fi
	gtkdoc-scan --module=lasso --source-dir=$(DOC_SOURCE_DIR)/lasso/ --output-dir=build/


#
# Prepare source files by coping them to "code" folder and 
# removing LASSO_EXPORT* stuff that makes gtkdoc crazy
#
doc_sources: $(DOC_SOURCE_FILES)
	@echo '*** Prepare sources ***'
	(for i in $(DOC_SOURCE_FILES) ; do \
	    folder_name=`echo $$i | sed 's#$(TOP)/##' | sed 's#/[^/]*$$##'`; \
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

#dist-hook:
#	@cp -p $(srcdir)/html/*.html $(srcdir)/images/*.png $(srcdir)/*.sgml $(distdir)

clean-local: clean-sources
	-rm -rf $(DOC_SOURCE_DIR)
	-rm -rf .libs
	-rm -rf tmpl
	-rm -rf sgml
	-rm -rf html
	-rm -rf build
	-rm -f $(SCANOBJ_FILES) index.sgml lasso-index.sgml
	-rm -rf  $(SCANOBJ_FILES) *.o *~ *.bak *.stamp

clean-sources:
	-rm -rf code

maintainer-clean-local: clean
	-rm -rf `find sgml -name "*.sgml" -print`

