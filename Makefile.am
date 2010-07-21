ACLOCAL_AMFLAGS = -I m4

SUBDIRS		= lasso \
		  tests \
		  win32 \
		  bindings \
		  docs

EXTRA_DIST	= COPYING lasso.pc.in lasso-src-config.in autogen.sh tools abi lasso.doap

MAINTAINERCLEANFILES = \
    Makefile.in \
    config.guess \
    config.sub \
    configure \
    install-sh \
    missing
 

pkgconfig_DATA	= lasso.pc
pkgconfigdir	= $(libdir)/pkgconfig

clean-local:
	-rm -f lasso.pc

dist-hook:
	-rm -rf `find $(distdir) -name .svn`

DISTCHECK_CONFIGURE_FLAGS=--enable-gtk-doc
