NULL=
TOP=$(top_srcdir)
MODULE=lasso
DOC_MAIN_SGML_FILE=$(MODULE).sgml
SOURCE_DIR=$(TOP)/lasso
INCLUDE_DIR=$(TOP)/lasso

EXTRA_DIST = \
	$(NULL)

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
all:

docs: sgml html clean-sources

html: sgml $(DOC_MAIN_SGML_FILE) lasso-index
	@echo '*** Building HTML ***'
	test -d $(srcdir)/html || mkdir $(srcdir)/html
	cd $(srcdir)/html && gtkdoc-mkhtml $(MODULE) ../$(DOC_MAIN_SGML_FILE)

SCANOBJ_FILES = 		\
	$(MODULE).hierarchy	\
	$(MODULE).signals 	\
	$(MODULE).interfaces 	\
	$(MODULE).prerequisites \
	$(MODULE).args

#
# Prepeare sgml files from sources for each library. We are also
# doing some "magic" here by automatically adding links to XML DSig and 
# XML Enc specification, we also remove "Ptr" from the end of the link
# targets to make more references
#
sgml: templates
	@echo '*** Building SGML ***'
	-@gtkdoc-mkdb --module=$(MODULE) \
		    --main-sgml-file=$(DOC_MAIN_SGML_FILE) \
		    --source-dir=$(DOC_SOURCE_DIR)/lasso
	-@(for i in `find sgml -name "*.sgml" -print` ; do \
	    cat $$i | \
		sed 's!\(&lt;dsig:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmldsig-core/#sec-\2\">\1\2\3</ulink>!g' | \
		sed 's!\(&lt;enc:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmlenc-core/#sec-\2\">\1\2\3</ulink>!g' | \
		sed 's!linkend=\"\(.*\)Ptr\"!linkend=\"\1\"!g' > \
		$$i.tmp; \
		mv -f $$i.tmp $$i; \
	done);

templates: scan
	@echo '*** Building TMPL ***'
	-@gtkdoc-mktmpl --module=$(MODULE)

# CFLAGS and LDFLAGS for compiling scan program.
GTKDOC_CFLAGS = 		\
	@CFLAGS@		\
	@GLIB_CFLAGS@ 		\
	@LIBXML_CFLAGS@ 	\
	@XMLSEC1_CFLAGS@ 	\
	-I$(top_srcdir)

GTKDOC_LIBS = 				\
	@LIBS@				\
	@GLIB_LIBS@ -lgobject-2.0 	\
	@LIBXML_LIBS@ 			\
	@XMLSEC1_LIBS@ 			\
	-L$(top_srcdir)/lasso -llasso

GTKDOC_CC=$(LIBTOOL) --mode=compile $(CC)
GTKDOC_LD=$(LIBTOOL) --mode=link $(CC)

scan: doc_sources
	@echo '*** Scan sources ***'
	if grep -l '^..*$$' $(MODULE).types > /dev/null ; then \
		CC="$(GTKDOC_CC)" LD="$(GTKDOC_LD)" CFLAGS="$(GTKDOC_CFLAGS)" LDFLAGS="$(GTKDOC_LIBS)" gtkdoc-scangobj $(SCANOBJ_OPTIONS) --module=$(MODULE) --output-dir=$(srcdir) ; \
	else \
		cd $(srcdir) ; \
		for i in $(SCANOBJ_FILES) ; do \
			test -f $$i || touch $$i ; \
		done \
	fi
	-@gtkdoc-scan --module=$(MODULE) \
		    --source-dir=$(DOC_SOURCE_DIR)/lasso/

$(MODULE)-decl.txt $(SCANOBJ_FILES): scan
	@true

#
# Prepare source files by coping them to "code" folder and 
# removing LASSO_EXPORT* stuff that makes gtkdoc crazy
#
doc_sources: $(DOC_SOURCE_FILES)
	@echo '*** Prepare sources ***'
	@(for i in $(DOC_SOURCE_FILES) ; do \
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
	@grep -h '<NAME>.*</NAME>' $(MODULE)-*decl.txt | \
		grep -v '<NAME>extern</NAME>' | \
		sort -u | \
		sed 's#_#-#g' | \
		sed 's#<NAME>\([^-]*\)-\([^<]*\)</NAME>#<listitem><para><link linkend=\"\1-\2-CAPS\">\1-\2</link></para></listitem>#g' | \
		sed 's#<NAME>\([^<]*\)</NAME>#<listitem><para><link linkend=\"\1\">\1</link></para></listitem>#g' > \
		lasso-index.sgml

#dist-hook:
#	@cp -p $(srcdir)/html/*.html $(srcdir)/images/*.png $(srcdir)/*.sgml $(distdir)

clean: clean-sources clean-local
	-@rm -rf $(DOC_SOURCE_DIR)
	-@rm -rf .libs
	-@rm -rf tmpl
	-@rm -rf sgml
	-@rm -rf html
	-@rm -f  lasso-decl-list.txt lasso-decl.txt lasso-undocumented.txt lasso-unused.txt
	-@rm -f $(SCANOBJ_FILES) index.sgml lasso-index.sgml

clean-sources:
	-@rm -rf code

clean-local:
	-@rm -rf  $(SCANOBJ_FILES) *.o *~ *.bak *.stamp

maintainer-clean-local: clean
	-@rm *.html *.txt
	-@rm -rf `find sgml -name "*.sgml" -print`
