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
CWINDOWS="no"

dnl ==========================================================================
dnl Perform host specific configuration
dnl ==========================================================================
case "${host}" in
    *aix* )
	CFLAGS="${CFLAGS} -D_ALL_SOURCE"
	;;
    *-pc-*gw*)
dnl     mno-cygwin to produce purely win32 DLL.
        CC="gcc -mno-cygwin"
dnl     _MSC_VER to emulate a MSVC compilation and active secret room with
dnl     correct dllexport/import export definitions.
dnl     IN_LASSO to active special import/export mechanisms.
dnl     G_OS_WIN32 is already defined, so we do not do it. With this
dnl     definition, Microsoft C library will be used (msvcrt.dll).
dnl     WIN32 and _WIN32 used to be sure. Some header test against it (ie:
dnl     jni.h), then it do not cost to add this def...
        CFLAGS="-I/usr/local/include -DWIN32 -D_WIN32 -D_MSC_VER -DIN_LASSO"
        LDFLAGS="-L/usr/local/lib"
        GLIB_CFLAGS="-I/usr/local/include/glib-2.0 -I/usr/local/lib/glib-2.0/include"
        GLIB_LIBS="-lgobject-2.0 -lglib-2.0"
        XMLSEC1_CFLAGS="-DXMLSEC_CRYPTO=\"openssl\" -DXMLSEC_LIBXML_260=1 -D__XMLSEC_FUNCTION__=__FUNCTION__ -DXMLSEC_NO_XKMS=1 -DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1 -DXMLSEC_CRYPTO_OPENSSL=1"
        XMLSEC1_LIBS="-lxmlsec-openssl -lxmlsec"
        LIBXML_CFLAGS="-I/usr/local/include/libxml2"
        LIBXML_LIBS="-lxml2"
        LIBXSLT_CFLAGS=""
        LIBXSLT_LIBS="-lxslt"
        CWINDOWS="yes"
        ;;
esac

dnl
dnl Check the environment
dnl
AC_PROG_CC
if test "x$GCC" = "xyes"; then
  if test -z "`echo "$CFLAGS" | grep "\-Wall" 2> /dev/null`" ; then
      CFLAGS="$CFLAGS -Wall -g"
  fi
fi
AC_HEADER_STDC

#AC_DISABLE_SHARED
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL
AC_PROG_INSTALL

LIBTOOL_EXPORT_OPTIONS='-export-symbols-regex "^[^_].*"'

dnl Make sure we have an ANSI compiler
AM_C_PROTOTYPES
test "z$U" != "z" && AC_MSG_ERROR(Compiler not ANSI compliant)

dnl AC_LIB_LTDL


dnl ==========================================================================
dnl check do we have size_t and its size, 
dnl TODO: will need to replace this and the lassoSize define with 
dnl typedef on next ABI refresh
dnl ==========================================================================
AC_CHECK_SIZEOF(size_t)
if test "$ac_cv_sizeof_size_t" -ne "4" ; then
    LASSO_DEFINES="$LASSO_DEFINES -DLASSO_NO_SIZE_T"
fi


if test "$CWINDOWS" = "no" ; then
    PKG_CHECK_MODULES(LASSO, glib-2.0 gobject-2.0 libxml-2.0 libxslt xmlsec1 xmlsec1-openssl)
fi
AC_SUBST(LASSO_LIBS)
AC_SUBST(LASSO_CFLAGS)
	

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
		python_val=false
                AC_MSG_RESULT(no)
	fi
fi

AC_ARG_ENABLE(python,
[  --enable-python         build the Python binding (default)],
[case "${enableval}" in
        yes) ;;
        no)  python_val=false;;
esac])

if test x$python_val = xtrue ; then
  enable_python=yes
else
  enable_python=no
fi

AM_CONDITIONAL(WITH_PYTHON, $python_val)


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
AC_ARG_ENABLE(gtk-doc, [  --enable-gtk-doc        Use gtk-doc to build documentation [[default=auto]]], enable_gtk_doc="$enableval", enable_gtk_doc=auto)

if test x$enable_gtk_doc = xauto ; then
  if test x$GTKDOC = xtrue ; then
    enable_gtk_doc=yes
  else
    enable_gtk_doc=no 
  fi
fi

AM_CONDITIONAL(ENABLE_GTK_DOC, test x$enable_gtk_doc = xyes)


dnl ==========================================================================
dnl Test suite (requires check)
dnl ==========================================================================
AC_ARG_ENABLE(tests,
[  --enable-tests          build the test suite (default)],
[case "${enableval}" in
        yes) tests_val=true;;
        no)  tests_val=false;;
esac], tests_val=true)

if $tests_val ; then
  AM_PATH_CHECK
fi

AM_CONDITIONAL(WITH_TESTS, $tests_val)



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
AC_MSG_CHECKING(for debugging) 
AC_ARG_ENABLE(debugging,   [  --enable-debugging      enable debuging messages (no)])
if test "z$enable_debugging" = "zyes" ; then
    enable_debugging=yes
    LASSO_DEFINES="$LASSO_DEFINES -DLASSO_DEBUG"
else
    enable_debugging=no
fi    
AC_MSG_RESULT($enable_debugging)

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
docs/tutorial/Makefile
python/Makefile
python/doc/Makefile
python/doc/tutorial/Makefile
python/environs/Makefile
python/examples/Makefile
python/protocols/Makefile
python/protocols/elements/Makefile
python/tests/Makefile
python/xml/Makefile
tests/Makefile
win32/Makefile
win32/nsis/Makefile
]
[lasso.pc:lasso.pc.in]
dnl [lasso-config:lasso-config.in]
dnl [lasso.spec:lasso.spec.in]
)
echo "

Configuration:

	Compiler:		${CC} 
	Install prefix:		${prefix}
	Debugging:		$enable_debugging

	Build Python binding:	${enable_python}

	Build C API reference:	${enable_gtk_doc}
"
