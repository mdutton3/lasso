dnl -*- Mode: sh -*-
dnl
dnl configure.ac - top level autoconf file for Lasso
dnl (Process this file with autoconf to produce a configure script.)
dnl
dnl $Id$
dnl
dnl 
dnl See COPYING at the top of this package for the
dnl full license terms.
dnl 
dnl 

dnl Declare package
AC_INIT([Liberty Alliance Single Sign On], 0.3.0, lasso-devel@lists.labs.libre-entreprise.org)
dnl Check if autoconf ver > 2.53
AC_PREREQ(2.53)
dnl Check existence of a relative pathed source file.
AC_CONFIG_SRCDIR(lasso/lasso.c)
dnl Copy stamp REVISIO-INFO in the configure script.
AC_REVISION($Revision$)

dnl Run many macros mostly needed by configure.ac.
AM_INIT_AUTOMAKE(lasso, 0.3.0)
dnl Create rules to automaticaly regenerate the config header.
AM_CONFIG_HEADER(lasso/lasso_config.h)
dnl Add --enable-maintainer-mode option to configure.
AM_MAINTAINER_MODE

dnl Perform only subset commands and variable relevant to the host type.
AC_CANONICAL_HOST
dnl ==========================================================================
dnl Perform host specific configuration
dnl ==========================================================================
MINGW=0
case "${host}" in
    *aix* )
	CFLAGS="${CFLAGS} -D_ALL_SOURCE"
	;;
    *-pc-mingw32)
        case "${build}" in
            *-pc-cygwin)
                CC="gcc -mno-cygwin"
                CFLAGS="${CFLAGS} -D_MSC_VER -DIN_LASSO -DMINGW -DWIN32 -D_WIN32 -I/usr/local/include"
                LDFLAGS="${LDFLAGS} -L/usr/local/lib"
                MINGW=1
                ;;
            dnl ==========================================================================
            dnl Workaround for non libtool standard library name specs.
            dnl ==========================================================================
        esac
dnl         if test -f "/cygdrive/c/windows/system/user32.dll"; then
dnl             dnl make symbolic link.
dnl             if test ! -f "/usr/local/lib/libuser32.dll"; then
dnl                 AC_MSG_WARN([Create workaround symbolic links: user32.dll])
dnl                 ln -s   /cygdrive/c/windows/system/user32.dll \
dnl                         /usr/local/lib/libuser32.dll
dnl             fi
dnl             if test ! -f "/usr/local/lib/libkernel32.dll"; then
dnl                 AC_MSG_WARN([Create workaround symbolic links: kernel32.dll])
dnl                 ln -s   /cygdrive/c/windows/system/kernel32.dll \
dnl                         /usr/local/lib/libkernel32.dll
dnl             fi
dnl         fi
        ;;
esac


dnl ==========================================================================
dnl Version
dnl ==========================================================================

changequote(<<, >>)dnl
VERSION_MAJOR=`echo $VERSION | sed -e 's/^\([^\.]*\)\.\([^\.]*\)\.\(.*\)$/\1/'`
VERSION_MINOR=`echo $VERSION | sed -e 's/^\([^\.]*\)\.\([^\.]*\)\.\(.*\)$/\2/'`
VERSION_RELEASE=`echo $VERSION | sed -e 's/^\([^\.]*\)\.\([^\.]*\)\.\(.*\)$/\3/'`
changequote([, ])dnl

version_decimal=`expr $VERSION_MAJOR \* 10000 + $VERSION_MINOR \* 100 + $VERSION_RELEASE`
windows_version=`echo $VERSION_MAJOR,$VERSION_MINOR,$VERSION_RELEASE,0`

dnl Add versionning & package defines to lasso_config.h
AC_DEFINE_UNQUOTED(LASSO_VERSION_MAJOR, $VERSION_MAJOR, [Major version number])
AC_DEFINE_UNQUOTED(LASSO_VERSION_MINOR, $VERSION_MINOR, [Minor version number])
AC_DEFINE_UNQUOTED(LASSO_VERSION_SUBMINOR, $VERSION_RELEASE, [Release version number])
AC_DEFINE_UNQUOTED(LASSO_VERSION_DECIMAL, $version_decimal, [Release version as a decimal])

dnl Dirty hack in order to have dynamic resource version numbering.
AC_DEFINE_UNQUOTED(LASSO_WINDOWS_VERSION, $windows_version, [Windows version of the lasso version])

# Libtool versioning
#
# CURRENT
#      The most recent interface number that this library implements.
# 
# REVISION
#      The implementation number of the CURRENT interface.
# 
# AGE
#      The difference between the newest and oldest interfaces that this
#      library implements.  In other words, the library implements all the
#      interface numbers in the range from number `CURRENT - AGE' to
#      `CURRENT'.
#
# Rules:
#  1. Start with version information of `0:0:0' for each libtool library.
#
#  2. Update the version information only immediately before a public
#     release of your software.  More frequent updates are unnecessary,
#     and only guarantee that the current interface number gets larger
#     faster.
#
#  3. If the library source code has changed at all since the last
#     update, then increment REVISION (`C:R:A' becomes `C:r+1:A').
#
#  4. If any interfaces have been added, removed, or changed since the
#     last update, increment CURRENT, and set REVISION to 0.
#
#  5. If any interfaces have been added since the last public release,
#     then increment AGE.
#
#  6. If any interfaces have been removed since the last public release,
#     then set AGE to 0.
#
# syntax: CURRENT[:REVISION[:AGE]]
current=`expr $VERSION_MAJOR + $VERSION_MINOR`
LASSO_VERSION_INFO="$current:$VERSION_RELEASE:$VERSION_MINOR"
AC_SUBST(LASSO_VERSION_INFO)
AC_MSG_RESULT([Setup version.])

# OSX Fink
if test -d /sw/bin ; then
  PATH=$PATH:/sw/bin
fi

dnl
dnl Check for programs
dnl
AC_PROG_CC_STDC
LT_AC_PROG_RC
AC_EXEEXT
AC_PROG_CC_C_O
AM_SANITY_CHECK
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_EGREP
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_LIBTOOL_WIN32_DLL
AM_PROG_LIBTOOL
AC_PROG_INSTALL
AC_SUBST(LIBTOOL_DEPS)

dnl Find tar command for make dist
AC_CHECK_PROGS(TAR, gnutar gtar tar)

dnl Find egrep command.
dnl AC_CHECK_PROGS(EGREP, egrep)

dnl Check existenz of binding programs
AC_CHECK_PROGS(JAVA, gij java)
AC_CHECK_PROGS(JAVAC, gcj javac)
AC_CHECK_PROGS(JAVAH, gcjh javah)
AC_CHECK_PROGS(JAR, fastjar jar)
AC_CHECK_PROGS(PYTHON, python)
AC_CHECK_PROGS(SWIG, swig)
AC_CHECK_PROGS(PKG_CONFIG, pkg-config)

LIBTOOL_EXPORT_OPTIONS='-export-symbols-regex "^[^_].*"'

dnl Make sure we have an ANSI compiler
AM_C_PROTOTYPES
test "z$U" != "z" && AC_MSG_ERROR(Compiler not ANSI compliant)


dnl ==========================================================================
dnl Swig
dnl ==========================================================================
SWIG_MIN_VERSION=1.3
AC_MSG_CHECKING(SWIG support)
if test "X$SWIG" != "X"; then
  SWIG_VERSION=`$SWIG -version 2>&1 |sed -ne 's/^SWIG Version //p'`
  SWIG_VERSION_DEC=`echo $SWIG_VERSION | $AWK -F. '{printf("%d\n", 10000*$1 + 100*$2 + $3)};'`

 if test $SWIG_VERSION_DEC -ge 010314; then
   SWIG_PYTHON_ARGS=-noproxy
 fi

  SWIG_MIN_VERSION_DEC=`echo $SWIG_MIN_VERSION | $AWK -F. '{printf("%d\n", 10000*$1 + 100*$2 + $3)};'`

  if test $SWIG_VERSION_DEC -ge $SWIG_MIN_VERSION_DEC; then
    AC_MSG_RESULT($SWIG_VERSION - OK)
  else
    AC_MSG_RESULT($SWIG_VERSION - too old to generate language interfaces)
    if test -r $srcdir/perl/CORE_wrap.c ; then
      AC_MSG_WARN(Pre-generated language interface files are present)
      AC_MSG_WARN(If you want to change the interfaces you will need)
      AC_MSG_WARN(SWIG version $SWIG_MIN_VERSION from http://www.swig.org/)
    else
      AC_MSG_WARN(There are no pre-generated language interface files)
      AC_MSG_WARN(Redland language interfaces will NOT build.)
      AC_MSG_WARN(If you want to build them you will need)
      AC_MSG_WARN(SWIG version $SWIG_MIN_VERSION from http://www.swig.org/)
      AC_MSG_WARN(Alternatively copy the pre-generated interface)
      AC_MSG_WARN(files from a released version)
    fi
  fi
else
  AC_MSG_RESULT(not present - using pre-generated interface files)
fi
AC_SUBST(SWIG_PYTHON_ARGS)

dnl Detect available languages binding.
languages=
languages_available=

dnl Java(tm)

AC_ARG_WITH(java, [  --with-java(=JAVA)      Enable the java interface], with_java="$withval", with_java="yes")
AC_MSG_CHECKING(Enable Java API)
if test "X$with_java" != Xno ; then
  if test "X$with_java" != Xyes; then
    JAVA=$with_java
  fi
  with_java=yes
fi

JAVAC_FLAGS=
JAVAH_FLAGS=
dnl need to change quotes to allow square brackets
changequote(<<, >>)dnl
JAVA_VERSION=`$JAVA -version 2>&1 | $SED -ne 's/java version "\([^"]*\)".*/\1/p' 2>/dev/null`
if test "X$JAVA_VERSION" = X; then
    JAVA_VERSION=`$JAVA --version 2>&1 | $SED -ne 's/gij (GNU libgcj) version \([^"]*\) (.*/\1/p' 2>/dev/null`
fi

changequote([, ])dnl
if test "X$JAVA_VERSION" != X; then
  languages_available="$languages_available java($JAVA_VERSION)"
  if test "x$with_java" = "xyes"; then
    languages="$languages java"
  fi
fi
AC_MSG_RESULT($with_java)
if test "X$JAVA" = "Xgij"; then
    JAVAC_FLAGS="-C"
    JAVAH_FLAGS="-jni"
fi
AC_SUBST(JAVA_VERSION)
AC_SUBST(JAVAC_FLAGS)
AC_SUBST(JAVAH_FLAGS)


dnl python
AC_ARG_WITH(python, [  --with-python(=PYTHON)  Enable the Python interface], with_python="$withval", with_python="yes")
AC_MSG_CHECKING(Enable Python API)
if test "X$with_python" != Xno; then
  if test "X$with_python" != Xyes; then
    PYTHON=$with_python
  fi
  with_python=yes
fi


dnl need to change quotes to allow square brackets
changequote(<<, >>)dnl
PYTHON_VERSION=`$PYTHON -c 'import sys; print sys.version[:3]' 2>/dev/null`
changequote([, ])dnl
if test "X$PYTHON_VERSION" != X; then
  if test $with_python = yes; then
        PY_PREFIX=`python -c 'import sys ; print sys.prefix'`
        PY_EXEC_PREFIX=`python -c 'import sys ; print sys.exec_prefix'`
        changequote(<<, >>)dnl
        PY_VERSION=`python -c 'import sys ; print sys.version[0:3]'`
        changequote([, ])dnl
        PYTHON_H=$PY_PREFIX/include/python$PY_VERSION/Python.h
        LIBPYTHON_SO=$PY_PREFIX/lib/libpython$PY_VERSION.so
	if test -f $PYTHON_H; then
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
                languages_available="$languages_available python($PYTHON_VERSION)"
                languages="$languages python"
        else
		with_python=false
	fi
    fi
fi
AC_MSG_RESULT($with_python)
AC_SUBST(PYTHON_VERSION)

SD_LANG="$languages"
AC_SUBST(SD_LANG)

dnl ==========================================================================
dnl Test suite (requires check)
dnl ==========================================================================
AC_ARG_ENABLE(tests,
[  --enable-tests          build the test suite (default)],
[case "${enableval}" in
        yes) tests_val=true;;
        no)  tests_val=false;;
esac], tests_val=true)
AC_DEFINE([CHECK_IS_XML], [], [Define if check available with XML support])
if $tests_val ; then
  AM_PATH_CHECK
  AC_CHECK_LIB(check, srunner_set_xml, [AC_DEFINE(CHECK_IS_XML)])
fi

AM_CONDITIONAL(WITH_TESTS, $tests_val)
if test "z$tests_val" = "ztrue"; then
    tests_val="yes"
else
    tests_val="no"
fi

dnl Final step, add missing programs.

AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)

dnl ==========================================================================
dnl User specific option.
dnl ==========================================================================
dnl Where do we want to install docs
AC_MSG_CHECKING(for docs folder) 
AC_ARG_WITH(html-dir, [  --with-html-dir=PATH    path to installed docs ])
if test "z$with_html_dir" != "z" ; then
    LASSO_DOCDIR=$with_html_dir
else
    LASSO_DOCDIR='$(datadir)/doc/lasso'
fi
AC_MSG_RESULT($LASSO_DOCDIR)
AC_SUBST(LASSO_DOCDIR)

AC_ARG_WITH(html-dir, [  --with-html-dir=PATH path to installed docs ])

if test "x$with_html_dir" = "x" ; then
  HTML_DIR='${datadir}/gtk-doc/html'
else
  HTML_DIR=$with_html_dir
fi
AC_SUBST(HTML_DIR)

dnl pkg-config path
AC_ARG_WITH(pkg-config-path, [  --with-pkg-config=PATH Set pkg-config metadata search path.],
            PKG_CONFIG_PATH="${withval}", PKG_CONFIG_PATH="")
if test "z$PKG_CONFIG_PATH" != "z"; then
    export PKG_CONFIG_PATH
fi

PKG_CHECK_MODULES(LASSO, glib-2.0 gobject-2.0 libxml-2.0 libxslt xmlsec1 xmlsec1-openssl)

dnl Let people disable the gtk-doc stuff.
AC_ARG_ENABLE(gtk-doc, [  --disable-gtk-doc        Disable documentation build], 
[case "${enableval}" in
        yes) enable_gtk_doc=true;;
        no)  enable_gtk_doc=false;;
esac], enable_gtk_doc=true)

if test "x$enable_gtk_doc" = "xtrue" ; then
    GTK_DOC_MIN_VERSION=1.0
    AC_MSG_CHECKING(gtk-doc support:)
    PKG_CHECK_MODULES(GTK_DOC, gtk-doc >= $GTK_DOC_MIN_VERSION, enable_gtk_doc="yes",
                      enable_gtk_doc="no")
fi

dnl ==========================================================================
dnl check do we have size_t and its size, 
dnl TODO: will need to replace this and the lassoSize define with 
dnl typedef on next ABI refresh
dnl ==========================================================================
AC_CHECK_SIZEOF(size_t)
if test "$ac_cv_sizeof_size_t" -ne "4" ; then
    LASSO_DEFINES="$LASSO_DEFINES -DLASSO_NO_SIZE_T"
fi

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(xmlsec/xmlsec.h xmlsec/crypto.h string.h libxml/uri.h glib/gprintf.h)


dnl Debug 
AC_MSG_CHECKING(for debugging) 
AC_ARG_ENABLE(debugging,   [  --enable-debugging      enable debuging messages (no)])
if test "z$enable_debugging" = "zyes" ; then
    enable_debugging=yes
    LASSO_DEFINES="$LASSO_DEFINES -DLASSO_DEBUG"
else
    enable_debugging=no
fi    
AC_MSG_RESULT($enable_debugging)

dnl Profiling 
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
if test $MINGW -eq 1; then 
LASSO_CORE_LIBS="-llasso-0"
else
LASSO_CORE_LIBS="-llasso "
fi
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
dnl if test "$MINGW" = "yes" ; then
dnl     LINK="/usr/bin/dllwrap.exe --add-stdcall-alias -mwindows -s --driver-name \$(CCLD) \$(AM_CFLAGS) \$(CFLAGS) \$(LDFLAGS) \$(LASSO_CORE_CFLAGS) \$(GLIB_CFLAGS) \$(LIBXML_CFLAGS) \$(LIBXSLT_CFLAGS) \$(XMLSEC1_CFLAGS) \$(LASSO_CRYPTO_CFLAGS) -L\${libdir} \$(GLIB_LIBS) \$(LIBXML_LIBS) \$(LIBXSLT_LIBS) \$(XMLSEC1_LIBS) \$(LASSO_CRYPTO_LIBS) -o \$@"
dnl else
dnl     LINK="\$(LIBTOOL) --mode=link \$(CCLD) \$(AM_CFLAGS) \$(CFLAGS) \$(LDFLAGS) -o \$@"
dnl fi
dnl AC_SUBST(LINK)


dnl Temporaly
AM_CONDITIONAL(MINGW, test $MINGW == 1)
AM_CONDITIONAL(WITH_PYTHON, test 1 -eq 0)


dnl ==========================================================================
dnl Writing result files
dnl ==========================================================================
AC_OUTPUT(
dnl [lasso/version.h]
[Makefile
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
java/Makefile]
dnl [java/coldfusion/Makefile]
[java/src/Makefile
java/src/c/Makefile]
[lasso.pc:lasso.pc.in]
dnl [lasso-config:lasso-config.in]
dnl [lasso.spec:lasso.spec.in]
)
AC_MSG_RESULT([
=============
Configuration
=============

Main
----

Compiler:
    ${CC} 

Install prefix:
    ${prefix}

Debugging:
    $enable_debugging

Optionals builds
----------------

Python binding:
    ${with_python}

Build Java binding:
    ${with_java}
        
C API references:
    ${enable_gtk_doc}

Tests suite:
    ${tests_val}
])
