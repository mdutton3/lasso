dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.2)
AC_INIT(lasso/lasso.c)
AM_CONFIG_HEADER(config.h)
AC_CANONICAL_HOST

dnl ==========================================================================
dnl Version
dnl ==========================================================================
LASSO_PACKAGE=lasso
LASSO_VERSION_MAJOR=0
LASSO_VERSION_MINOR=2
LASSO_VERSION_SUBMINOR=0
LASSO_VERSION="$LASSO_VERSION_MAJOR.$LASSO_VERSION_MINOR.$LASSO_VERSION_SUBMINOR"
LASSO_VERSION_INFO=`echo $LASSO_VERSION | awk -F. '{ printf "%d:%d:%d", $1+$2, $3, $2 }'`
LASSO_VERSION_SAFE=`echo $LASSO_VERSION | sed 's/\./_/g'`

PACKAGE=$LASSO_PACKAGE
VERSION=$LASSO_VERSION

AC_SUBST(LASSO_VERSION)
AC_SUBST(LASSO_PACKAGE)
AC_SUBST(LASSO_VERSION_SAFE)
AC_SUBST(LASSO_VERSION_MAJOR)
AC_SUBST(LASSO_VERSION_MINOR)
AC_SUBST(LASSO_VERSION_SUBMINOR)
AC_SUBST(LASSO_VERSION_INFO)

AM_INIT_AUTOMAKE($PACKAGE, $VERSION, no-define)
AM_MAINTAINER_MODE
GLIB_FOUND="no"
XMLSEC1_FOUND="no"
LIBXML_FOUND="no"
LIBXML262_FOUND="no"
LIBXSLT_FOUND="no"
CWINDOWS="no"

dnl ==========================================================================
dnl Perform host specific configuration
dnl ==========================================================================
case "${host}" in
    *aix* )
	CFLAGS="${CFLAGS} -D_ALL_SOURCE"
	;;
    *-pc-*gw*)
        CC="gcc -mno-cygwin"
        CFLAGS="-I/usr/local/include -D_MSC_VER=1 -DIN_LASSO=1"
#        CFLAGS="-I/usr/local/include"
        LDFLAGS="-L/usr/local/lib" 
dnl        CFLAGS="${CFLAGS} -mno-cygwin"
dnl        LDFLAGS="${LDFLAGS} -mno-cygwin"
        GLIB_CFLAGS="-I/usr/local/include/glib-2.0 -I/usr/local/lib/glib-2.0/include"
        GLIB_LIBS="-lgobject-2.0 -lglib-2.0"
        GLIB_FOUND="yes"
        XMLSEC1_CFLAGS="-DXMLSEC_CRYPTO=\"openssl\" -DXMLSEC_LIBXML_260=1 -D__XMLSEC_FUNCTION__=__FUNCTION__ -DXMLSEC_NO_XKMS=1 -DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1 -DXMLSEC_CRYPTO_OPENSSL=1"
        XMLSEC1_LIBS="-lxmlsec-openssl -lxmlsec"
        XMLSEC1_FOUND="yes"
        LIBXML_CFLAGS="-I/usr/local/include/libxml2"
        LIBXML_LIBS="-lxml2"
        LIBXML_FOUND="yes"
        LIBXML262_FOUND="yes"
        LIBXSLT_CFLAGS=""
        LIBXSLT_LIBS="-lxslt"
        LIBXSLT_FOUND="yes"
        CWINDOWS="yes"
        ;;
esac

dnl
dnl Check the environment
dnl
AC_PROG_CC

#AC_DISABLE_SHARED
AC_PROG_LIBTOOL

AC_PROG_INSTALL
AC_STDC_HEADERS
AC_PATH_PROG(RM, rm, /bin/rm)
AC_PATH_PROG(CP, cp, /bin/cp)
AC_PATH_PROG(MV, mv, /bin/mv)
AC_PATH_PROG(TAR, tar, /bin/tar)
AC_PATH_PROG(HELP2MAN, help2man)
AC_PATH_PROG(MAN2HTML, man2html)

LIBTOOL_EXPORT_OPTIONS='-export-symbols-regex "^[^_].*"'

dnl Make sure we have an ANSI compiler
AM_C_PROTOTYPES
test "z$U" != "z" && AC_MSG_ERROR(Compiler not ANSI compliant)

dnl Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([stdio.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([ctype.h])
AC_CHECK_HEADERS([errno.h])
AC_CHECK_HEADERS([ansidecl.h])
AC_CHECK_HEADERS([time.h])
AC_CHECK_FUNCS(printf sprintf fprintf snprintf vfprintf vsprintf vsnprintf sscanf timegm)

dnl AC_LIB_LTDL

LASSO_DEFINES="-DLASSO_DEBUG"
dnl LASSO_DEFINES=""



dnl ==========================================================================
dnl Check for __FUNCTION__ or __func__
dnl ==========================================================================
dnl AC_MSG_CHECKING(for __FUNCTION__ or __func__)
dnl AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
dnl 	[[char *foo = __FUNCTION__;]])],
dnl 	[ac_function_exists=yes],
dnl 	[ac_function_exists=no])
dnl AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
dnl 	[[char *foo = __func__;]])],
dnl 	[ac_func_exists=yes],
dnl 	[ac_func_exists=no])
dnl if test "z$ac_function_exists" = "zyes" ; then
dnl 	AC_MSG_RESULT(__FUNCTION__)
dnl 	LASSO_DEFINES="$LASSO_DEFINES -D__LASSO_FUNCTION__=__FUNCTION__"
dnl elif test "z$ac_func_exists" = "zyes" ; then 
dnl 	AC_MSG_RESULT(__func__)
dnl 	LASSO_DEFINES="$LASSO_DEFINES -D__LASSO_FUNCTION__=__func__"
dnl else 
dnl 	AC_MSG_RESULT("no")
dnl fi

dnl ==========================================================================
dnl check do we have size_t and its size, 
dnl TODO: will need to replace this and the lassoSize define with 
dnl typedef on next ABI refresh
dnl ==========================================================================
AC_CHECK_SIZEOF(size_t)
if test "$ac_cv_sizeof_size_t" -ne "4" ; then
    LASSO_DEFINES="$LASSO_DEFINES -DLASSO_NO_SIZE_T"
fi


dnl ==========================================================================
dnl Check if pkg-config enabled and installed
dnl ==========================================================================
AC_ARG_ENABLE(sha1,   [  --enable-pkgconfig      enable pkgconfig for configuration (yes)])
if test "z$enable_pkgconfig" = "zno" ; then
    PKG_CONFIG_ENABLED=no
else
    AC_CHECK_PROG(PKG_CONFIG_ENABLED, pkg-config, yes, no)
    if test "z$PKG_CONFIG_ENABLED" = "zyes" ; then
	if ! pkg-config --atleast-pkgconfig-version 0.9 ; then
	    PKG_CONFIG_ENABLED=no
	fi
    fi
fi

PKG_CHECK_MODULES(LASSO, glib-2.0 gobject-2.0 libxml-2.0 libxslt xmlsec1 xmlsec1-openssl)
AC_SUBST(LASSO_LIBS)
AC_SUBST(LASSO_CFLAGS)
	

dnl find xmlsec crypto library (openssl) if not under Windows(c)
if test "z$CWINDOWS" = "zno" ; then
    if test "z$XMLSEC1_FOUND" = "zyes" ; then
        AC_MSG_CHECKING(for xmlsec1 OpenSSL crypto library)
        XMLSEC1_DEFAULT_CRYPTO_LIB=`$XMLSEC1_CONFIG --crypto`
        if test "$XMLSEC1_DEFAULT_CRYPTO_LIB" = "openssl" ; then
            prefix=`$XMLSEC1_CONFIG --prefix`
            if test -e $prefix/lib/libxmlsec1-openssl.so ; then
                AC_MSG_RESULT(yes)
            else
                AC_MSG_ERROR(Could not find xmlsec1 OpenSSL crypto library)
            fi
        else
            AC_MSG_ERROR(Bad default crypto library ($XMLSEC1_DEFAULT_CRYPTO_LIB) detected, must be OpenSSL)
        fi
    fi
fi

dnl ==========================================================================
dnl python
dnl ==========================================================================

AC_CHECK_PROG(python_val, python, true, false)
if $python_val; then
        AC_MSG_CHECKING(for Python development files)
        PY_PREFIX=`python -c 'import sys ; print sys.prefix'`
        PY_EXEC_PREFIX=`python -c 'import sys ; print sys.exec_prefix'`
        changequote(<<, >>)dnl
        PY_VERSION=`python -c 'import sys ; print sys.version[0:3]'`
        changequote([, ])dnl
        PYTHON_H=$PY_PREFIX/include/python$PY_VERSION/Python.h
        LIBPYTHON_SO=$PY_PREFIX/lib/libpython$PY_VERSION.so
	if test -f $PYTHON_H; then
                AC_MSG_RESULT(yes)
                PYTHON="python$PY_VERSION"
                PY_LIB_LOC="-L$PY_EXEC_PREFIX/lib/python$PY_VERSION/config"
                PY_CFLAGS="-I$PY_PREFIX/include/python$PY_VERSION"
                PY_MAKEFILE="$PY_EXEC_PREFIX/lib/python$PY_VERSION/config/Makefile"
                PY_OTHER_LIBS=`sed -n -e 's/^LIBS=\(.*\)/\1/p' $PY_MAKEFILE`
                PY_EXTRA_LIBS="$PY_LOCALMODLIBS $PY_BASEMODLIBS $PY_OTHER_LIBS"
                PY_DYNLOAD="$PY_EXEC_PREFIX/lib/python$PY_VERSION/lib-dynload"
                PY_LIB_A="$PY_EXEC_PREFIX/lib/python$PY_VERSION/config/libpython$PY_VERSION.a"
		PY_SITE_PACKAGES="$PY_EXEC_PREFIX/lib/python$PY_VERSION/site-packages"
                AC_SUBST(PYTHON)
                AC_SUBST(PY_LIB_LOC)
                AC_SUBST(PY_CFLAGS)
                AC_SUBST(PY_EXTRA_LIBS)
                AC_SUBST(PY_DYNLOAD)
                AC_SUBST(PY_LIB_A)
		AC_SUBST(PY_SITE_PACKAGES)
        else
                AC_MSG_RESULT("no")
	fi
fi


dnl ==========================================================================
dnl find gtk-doc
dnl ==========================================================================
AC_ARG_WITH(html-dir, [  --with-html-dir=PATH path to installed docs ])

if test "x$with_html_dir" = "x" ; then
  HTML_DIR='${datadir}/gtk-doc/html'
else
  HTML_DIR=$with_html_dir
fi

AC_SUBST(HTML_DIR)

gtk_doc_min_version=1.0
AC_MSG_CHECKING([gtk-doc version >= $gtk_doc_min_version])
if pkg-config --atleast-version=$gtk_doc_min_version gtk-doc; then
  AC_MSG_RESULT(yes)
  GTKDOC=true
else
  AC_MSG_RESULT(no)
  GTKDOC=false
fi

dnl Let people disable the gtk-doc stuff.
AC_ARG_ENABLE(gtk-doc, [  --enable-gtk-doc  Use gtk-doc to build documentation [default=auto]], enable_gtk_doc="$enableval", enable_gtk_doc=auto)

if test x$enable_gtk_doc = xauto ; then
  if test x$GTKDOC = xtrue ; then
    enable_gtk_doc=yes
  else
    enable_gtk_doc=no 
  fi
fi

AM_CONDITIONAL(ENABLE_GTK_DOC, test x$enable_gtk_doc = xyes)

dnl ==========================================================================
dnl Where do we want to install docs
dnl ==========================================================================
AC_MSG_CHECKING(for docs folder) 
AC_ARG_WITH(html-dir,           [  --with-html-dir=PATH    path to installed docs ])
if test "z$with_html_dir" != "z" ; then
    LASSO_DOCDIR=$with_html_dir
else
    LASSO_DOCDIR='$(datadir)/doc/lasso'
fi

AC_MSG_RESULT($LASSO_DOCDIR)
AC_SUBST(LASSO_DOCDIR)

dnl ==========================================================================
dnl Debug 
dnl ==========================================================================
AC_MSG_CHECKING(for debuging) 
AC_ARG_ENABLE(debuging,   [  --enable-debuging       enable debuging compilation flags (no)])
if test "z$enable_debuging" = "zyes" ; then
    CFLAGS="$CFLAGS -g"
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi    

dnl ==========================================================================
dnl Profiling 
dnl ==========================================================================
AC_MSG_CHECKING(for profiling) 
AC_ARG_ENABLE(profiling,   [  --enable-profiling      enable profiling compilation flags (no)])
if test "z$enable_profiling" = "zyes" ; then
    CFLAGS="$CFLAGS -pg"
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi 

dnl ==========================================================================
dnl Pedantic compilation
dnl ==========================================================================
AC_MSG_CHECKING(for pedantic) 
AC_ARG_ENABLE(pedantic,   [  --enable-pedantic       enable pedantic compilation flags (no)])
if test "z$enable_pedantic" = "zyes" ; then
    dnl CFLAGS="$CFLAGS -pedantic -Wall -ansi -W -Wunused -Wimplicit -Wreturn-type -Wswitch -Wcomment -Wtrigraphs -Wformat -Wchar-subscripts -Wuninitialized -Wparentheses -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Waggregate-return -Wstrict-prototypes -Wmissing-prototypes -Wnested-externs -Winline -Wredundant-decls"
    CFLAGS="$CFLAGS -O -pedantic -Wall -ansi -fno-inline -W -Wunused -Wimplicit -Wreturn-type -Wswitch -Wcomment -Wtrigraphs -Wformat -Wchar-subscripts -Wuninitialized -Wparentheses -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Waggregate-return -Wmissing-prototypes -Wnested-externs -Winline -Wredundant-decls"
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi    

dnl ==========================================================================
dnl Static linking
dnl ==========================================================================
LASSO_STATIC_BINARIES=""
AC_MSG_CHECKING(for static linking) 
AC_ARG_ENABLE(static_linking,   [  --enable-static-linking enable static linking (no)])
if test "z$enable_static_linking" = "zyes" ; then
    LASSO_STATIC_BINARIES="-static"
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi    
AC_SUBST(LASSO_STATIC_BINARIES)

dnl ==========================================================================
dnl Final steps: lasso config
dnl ==========================================================================
LASSO_CORE_CFLAGS="$LASSO_DEFINES -I${includedir}/lasso"
LASSO_CORE_LIBS="-llasso "
AC_SUBST(LASSO_CORE_CFLAGS)
AC_SUBST(LASSO_CORE_LIBS)

LASSO_CFLAGS="$LASSO_CORE_CFLAGS $LASSO_CFLAGS"
LASSO_LIBS="-L${libdir} $LASSO_LIBS"
AC_SUBST(LASSO_CFLAGS)
AC_SUBST(LASSO_LIBS)

AC_SUBST(LASSO_DEFINES)
AC_SUBST(LASSO_APP_DEFINES)
AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)

dnl ==========================================================================
dnl Producing DLL
dnl ==========================================================================
dnl if test "$CWINDOWS" = "yes" ; then
dnl     LINK="/usr/bin/dllwrap.exe --add-stdcall-alias -mwindows -s --driver-name \$(CCLD) \$(AM_CFLAGS) \$(CFLAGS) \$(LDFLAGS) \$(LASSO_CORE_CFLAGS) \$(GLIB_CFLAGS) \$(LIBXML_CFLAGS) \$(LIBXSLT_CFLAGS) \$(XMLSEC1_CFLAGS) \$(LASSO_CRYPTO_CFLAGS) -L\${libdir} \$(GLIB_LIBS) \$(LIBXML_LIBS) \$(LIBXSLT_LIBS) \$(XMLSEC1_LIBS) \$(LASSO_CRYPTO_LIBS) -o \$@"
dnl else
dnl     LINK="\$(LIBTOOL) --mode=link \$(CCLD) \$(AM_CFLAGS) \$(CFLAGS) \$(LDFLAGS) -o \$@"
dnl fi
dnl AC_SUBST(LINK)

dnl ==========================================================================
dnl Writing result files
dnl ==========================================================================
AC_OUTPUT([
lasso/version.h
Makefile
lasso/Makefile
lasso/xml/Makefile
lasso/protocols/Makefile
lasso/protocols/elements/Makefile
lasso/environs/Makefile
docs/Makefile
docs/reference/Makefile
python/Makefile
python/doc/Makefile
python/doc/tutorial/Makefile
python/environs/Makefile
python/examples/Makefile
python/protocols/Makefile
python/protocols/elements/Makefile
python/tests/Makefile
python/xml/Makefile
]
[lasso.pc:lasso.pc.in]
dnl [lasso-config:lasso-config.in]
dnl [lasso.spec:lasso.spec.in]
)
