MAINTAINERCLEANFILES = Makefile.in
figuresdir = $(datadir)/doc/lasso/figures

FIGURES_PNG_FILES = \
	sso-brws-art.png    sso-brws-art-1.png sso-brws-art-2.png \
	sso-brws-art-3.png  sso-brws-art-4.png sso-brws-art-5.png \
	sso-brws-post.png   sso-brws-post-1.png sso-brws-post-2.png \
	sso-brws-post-3.png sso-brws-post-4.png \
	slo-sp-soap.png     slo-sp-soap-1.png slo-sp-soap-2.png \
	slo-sp-soap-3.png   slo-sp-soap-4.png slo-sp-soap-5.png \
	slo-sp-soap-6.png

GENERATED_FIGURES_SVG_FILES = \
	sso-brws-art-1.svg sso-brws-art-2.svg sso-brws-art-3.svg \
	sso-brws-art-4.svg sso-brws-art-5.svg \
	sso-brws-post-1.svg sso-brws-post-2.svg sso-brws-post-3.svg \
	sso-brws-post-4.svg \
	slo-sp-soap-1.svg slo-sp-soap-2.svg slo-sp-soap-3.svg \
	slo-sp-soap-4.svg slo-sp-soap-5.svg slo-sp-soap-6.svg


figures_DATA = $(FIGURES_PNG_FILES)

CLEANFILES = $(FIGURES_PNG_FILES) $(GENERATED_FIGURES_SVG_FILES)

%.svg:
	$(XSLTPROC) --stringparam stepno `echo $@ | sed -e 's/[^0-9]//g'` \
		$(srcdir)/step.xsl $< > $@

%.png: %.svg
	$(INKSCAPE) -d 150 --export-png=$@ $<


sso-brws-art-1.svg: sso-brws-art.svg step.xsl
sso-brws-art-2.svg: sso-brws-art.svg step.xsl
sso-brws-art-3.svg: sso-brws-art.svg step.xsl
sso-brws-art-4.svg: sso-brws-art.svg step.xsl
sso-brws-art-5.svg: sso-brws-art.svg step.xsl

sso-brws-post-1.svg: sso-brws-post.svg step.xsl
sso-brws-post-2.svg: sso-brws-post.svg step.xsl
sso-brws-post-3.svg: sso-brws-post.svg step.xsl
sso-brws-post-4.svg: sso-brws-post.svg step.xsl

slo-sp-soap-1.svg: slo-sp-soap.svg step.xsl
slo-sp-soap-2.svg: slo-sp-soap.svg step.xsl
slo-sp-soap-3.svg: slo-sp-soap.svg step.xsl
slo-sp-soap-4.svg: slo-sp-soap.svg step.xsl
slo-sp-soap-5.svg: slo-sp-soap.svg step.xsl
slo-sp-soap-6.svg: slo-sp-soap.svg step.xsl

EXTRA_DIST = step.xsl sso-brws-art.svg sso-brws-post.svg slo-sp-soap.svg \
	$(FIGURES_PNG_FILES) $(GENERATED_FIGURES_SVG_FILES)
