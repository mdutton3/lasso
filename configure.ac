dnl -*- Mode: sh -*-
dnl
dnl configure.ac - top level autoconf file for Lasso
dnl (Process this file with autoconf to produce a configure script.)
dnl
dnl 
dnl See COPYING at the top of this package for the full license terms.
dnl 
dnl 

dnl Declare package and package version.
dnl (r-c).a.r
dnl - First number is the lowest supported API version number.
dnl - Second number is the number of supported API versions where API version >
dnl   first number.
dnl - Third number is the current API version implementation version number.
dnl See libtool explanations about current, age and release, later in this file.
AC_INIT([Liberty Alliance Single Sign On], 0.4.0, lasso-devel@lists.labs.libre-entreprise.org)
dnl Check if autoconf ver > 2.53
AC_PREREQ(2.53)
dnl Check existence of a relative pathed source file.
AC_CONFIG_SRCDIR(lasso/lasso.c)
dnl Copy stamp REVISIO-INFO in the configure script.
AC_REVISION($Revision$)

dnl Run many macros mostly needed by configure.ac.
AM_INIT_AUTOMAKE(lasso, 0.4.0)
dnl Create rules to automaticaly regenerate the config header.
AM_CONFIG_HEADER(lasso/lasso_config.h)
dnl Add --enable-maintainer-mode option to configure.
AM_MAINTAINER_MODE

dnl Perform only subset commands and variable relevant to the host type.
AC_CANONICAL_HOST
dnl ==========================================================================
dnl Perform host specific configuration
dnl ==========================================================================
NULL=
MINGW=0
dnl For java sun environment automagic include subdir guessing. (dirty ? No...)
SUN_EXTRA_INCLUDE=
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
        dnl FIXME: This is a guessing, no test yet under windows with sun JDK
        SUN_EXTRA_INCLUDE="/win32" 
        ;;
    *linux*)
        SUN_EXTRA_INCLUDE="/linux"
esac



# OSX Fink
if test -d /sw/bin ; then
  PATH=$PATH:/sw/bin
fi

dnl
dnl Check for programs
dnl
AC_PROG_CC
AC_HEADER_STDC
LT_AC_PROG_RC
AM_PROG_GCJ
AC_EXEEXT
AC_PROG_CC_C_O
AM_SANITY_CHECK
AC_PROG_AWK
AC_PROG_LN_S
AC_LIBTOOL_WIN32_DLL
AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

dnl Find tar command for make dist
AC_CHECK_PROGS(TAR, gnutar gtar tar)

dnl Check existence of binding programs
AC_CHECK_PROGS(JAVA, java)
AC_CHECK_PROGS(JAVAC, gcj javac)
AC_CHECK_PROGS(JAR, fastjar jar)
AC_CHECK_PROGS(PYTHON, python)
AC_CHECK_PROGS(PHP, php)
AC_PATH_PROGS(PHP_PATH, php)
AC_CHECK_PROG(PHP_CONFIG, php-config, php-config)
AC_CHECK_PROGS(SWIG, swig)

LIBTOOL_EXPORT_OPTIONS='-export-symbols-regex "^[^_].*"'

dnl Make sure we have an ANSI compiler
AM_C_PROTOTYPES
test "z$U" != "z" && AC_MSG_ERROR(Compiler not ANSI compliant)

dnl ==========================================================================
dnl Version Super.Size.Me.L
dnl ==========================================================================

changequote(<<, >>)dnl
VERSION_MAJOR=`echo $VERSION | $SED -e 's/^\([^\.]*\)\.\([^\.]*\)\.\(.*\)$/\1/'`
VERSION_MINOR=`echo $VERSION | $SED -e 's/^\([^\.]*\)\.\([^\.]*\)\.\(.*\)$/\2/'`
VERSION_RELEASE=`echo $VERSION | $SED -e 's/^\([^\.]*\)\.\([^\.]*\)\.\(.*\)$/\3/'`
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

dnl CURRENT, REVISION, AGE
dnl - library source changed -> increment REVISION
dnl - interfaces added/removed/changed -> increment CURRENT, REVISION = 0
dnl - interfaces added -> increment AGE
dnl - interfaces removed -> AGE = 0

# syntax: CURRENT[:REVISION[:AGE]]
# So if M=major, m=minor, r=release:
# c = M + a = M + m;
# m = a
# r = r
current=`expr $VERSION_MAJOR + $VERSION_MINOR`
LASSO_VERSION_INFO="1:0:0"
AC_SUBST(LASSO_VERSION_INFO)

dnl ==========================================================================
dnl Swig
dnl ==========================================================================
SWIG_MIN_VERSION=1.3
AC_MSG_CHECKING(SWIG support)
if test "X$SWIG" != "X"; then
  SWIG_VERSION=`$SWIG -version 2>&1 | $SED -ne 's/^SWIG Version //p'`
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
      AC_MSG_WARN(lasso language interfaces will NOT build.)
      AC_MSG_WARN(If you want to build them you will need)
      AC_MSG_WARN(SWIG version $SWIG_MIN_VERSION from http://www.swig.org/)
      AC_MSG_WARN(Alternatively copy the pre-generated interface)
      AC_MSG_WARN(files from a released version)
    fi
  fi
else
  AC_MSG_RESULT(not present - using pre-generated interface files)
  SWIG="echo"
fi
AC_SUBST(SWIG_PYTHON_ARGS)

dnl Detect available languages binding.
languages_available=

dnl ==========================================================================
dnl Java(tm) API
dnl ==========================================================================
dnl Check if java is explicitly disabled.
AC_ARG_ENABLE(java, [  --disable-java          disable the Java bindings],,
              enable_java="yes")
AC_ARG_WITH(java-home,
            [  --with-java-home=(JAVA_HOME)  set the full path to the java home directory.])
JAVAC_FLAGS=
JDK_INCLUDE=
SUN=no
if test "X$with_java_home" != X; then
    JDK_INCLUDE="$with_java_home/include"
fi

dnl If the java compiler seems to be a Sun JDK-like compile (Kaffe, Sun JDK...)
if test "x$JAVA" = "xjava" && test "x$JAVAC" = "xjavac"; then
    dnl If we have a java compiler
    dnl need to change quotes to allow square brackets
    changequote(<<, >>)dnl
    JAVA_VERSION=`$JAVA -version 2>&1 | $SED -ne 's/java version "\([^"]*\)".*/\1/p' 2>/dev/null`
    changequote([, ])dnl
    dnl If no java version found, perphas it is a kaffee environment...
    if test "x$JAVA_VERSION" = x; then
        JAVA_VERSION=`$JAVA -version 2>&1 | grep "Java Version" | $SED 's/^.*Java Version: //g'`
        dnl If the java environment is kaffe, specify the JDK_INCLUDE directory.
        if test "x$JAVA_VERSION" != x; then
            JDK_INCLUDE="/usr/lib/kaffe/include"
        fi
    else
        dnl We assume it is a SUN environment.
        SUN=yes
    fi
    if ! test -f "$JDK_INCLUDE/jni.h"; then
        JAVA_VERSION=""
    fi
fi

dnl If the java compiler is the GNU Java Compiler.
if test "x$JAVAC" = "xgcj"; then
    changequote(<<, >>)dnl
    JAVA_VERSION=`$JAVAC --version 2>&1 | $SED -ne 's/gcj (GCC) \([^"]*\) (.*/\1/p' 2>/dev/null`
    changequote([, ])dnl
    
    dnl Byte-compiled .class file
    JAVAC_FLAGS="-C"
    dnl JNI compatible header files. (not used with SWIG.)
    dnl JAVAH_FLAGS="-jni"
    dnl Checking for jni.h if gcj is the java interpreter.
    AC_CHECK_HEADERS([jni.h], [], [JAVA_VERSION=$(NULL)])
fi

dnl Now transform JDK_INCLUDE in CFLAG option if applicable.
if test "X$JDK_INCLUDE" != X; then
    dnl If it is a sun environment
    if test "x$SUN" = "xyes"; then
        JDK_INCLUDE="$JDK_INCLUDE -I$JDK_INCLUDE$SUN_EXTRA_INCLUDE"
    fi
    JDK_INCLUDE=-I$JDK_INCLUDE
fi

dnl If we found a java version information, we have java compilation environment.
if test "X$JAVA_VERSION" != X; then
  if test "X$JAR" != X; then
    languages_available="$languages_available $JAVA($JAVA_VERSION)"
  else
    enable_java=no
  fi
fi

dnl Conditional java sub dir test.
AM_CONDITIONAL([JAVA_ENABLED],[test "x$enable_java" = "xyes"])
AC_SUBST(JAVA_VERSION)
AC_SUBST(JAVAC_FLAGS)
AC_SUBST(JDK_INCLUDE)


dnl ==========================================================================
dnl Python API
dnl ==========================================================================
dnl Check if python is explicitly disabled.
AC_ARG_ENABLE(python, [  --disable-python        disable the Python bindings],,
              enable_python="yes")

dnl Check if user passed a specific python program.
AC_ARG_WITH(python,
            [  --with-python=(PYTHON)  set the full path to the python program to use.])
AC_MSG_CHECKING(for Python development files)

dnl specific program passed, set PYTHON to it.
if test "X$with_python" != X; then
    PYTHON=$with_python
fi


dnl need to change quotes to allow square brackets
changequote(<<, >>)dnl
PYTHON_VERSION=`$PYTHON -c 'import sys; print sys.version[:3]' 2>/dev/null`
changequote([, ])dnl

dnl Check if we were be able to extract a good version number.
if test "X$PYTHON_VERSION" != X; then
    PY_PREFIX=`$PYTHON -c 'import sys ; print sys.prefix'`
    PY_EXEC_PREFIX=`$PYTHON -c 'import sys ; print sys.exec_prefix'`
    changequote(<<, >>)dnl
    PY_VERSION=`$PYTHON -c 'import sys ; print sys.version[0:3]'`
    changequote([, ])dnl
    PYTHON_H=$PY_PREFIX/include/python$PY_VERSION/Python.h
    LIBPYTHON_SO=$PY_PREFIX/lib/libpython$PY_VERSION.so
    if test -f $PYTHON_H; then
            dnl Not useful unless we make a test on the python version.
            PYTHON="python$PY_VERSION"
            PY_CFLAGS="-I$PY_PREFIX/include/python$PY_VERSION"
            PY_MAKEFILE="$PY_EXEC_PREFIX/lib/python$PY_VERSION/config/Makefile"
            PY_OTHER_LIBS=`$SED -n -e 's/^LIBS=\(.*\)/\1/p' $PY_MAKEFILE`
            PY_EXTRA_LIBS="$PY_LOCALMODLIBS $PY_BASEMODLIBS $PY_OTHER_LIBS"
            PY_SITE_PACKAGES="\${prefix}/lib/python$PY_VERSION/site-packages"
            AC_SUBST(PYTHON)
            AC_SUBST(PY_LIB_LOC)
            AC_SUBST(PY_CFLAGS)
            AC_SUBST(PY_EXTRA_LIBS)
            AC_SUBST(PY_DYNLOAD)
            AC_SUBST(PY_LIB_A)
            AC_SUBST(PY_SITE_PACKAGES)
            languages_available="$languages_available python($PYTHON_VERSION)"
    else
            enable_python=no
    fi
else
	enable_python=no
fi
AM_CONDITIONAL([PYTHON_ENABLED],[test "x$enable_python" = "xyes"])
AC_MSG_RESULT($enable_python)
AC_SUBST(PYTHON_VERSION)

dnl Check if php is explicitly disabled.
AC_ARG_ENABLE(php, [  --disable-php           disable the PHP bindings],,
              enable_php="yes")

AC_ARG_WITH(php-config,
            [  --with-php-config(=PHP_CONFIG)      Specify full path to php-config.])
dnl Check if user passed a specific php-config program.
if test "X$with_php_config" != X ; then
    PHP_CONFIG=$with_php_config
fi

if test "X$PHP_CONFIG" != X ; then
  PHP_INCLUDES=`$PHP_CONFIG --includes`
  PHP_LDFLAGS=`$PHP_CONFIG --ldflags`
  PHP_LIBS=`$PHP_CONFIG --libs`
  PHP_UNPREFIXED_EXTENSION_DIR=`$PHP_CONFIG --extension-dir | $SED 's/\/usr//g'`
  PHP_PREFIX=`$PHP_CONFIG --prefix`
else
  # This allows 'make clean' in the php directory to work when
  # php isn't available
  PHP=:
  PHP_INCLUDES=
  PHP_LDFLAGS=
  PHP_LIBS=
  PHP_UNPREFIXED_EXTENSION_DIR=
  PHP_PREFIX=
fi
AC_SUBST(PHP_INCLUDES)
AC_SUBST(PHP_LDFLAGS)
AC_SUBST(PHP_LIBS)
AC_SUBST(PHP_UNPREFIXED_EXTENSION_DIR)
AC_SUBST(PHP_PREFIX)

dnl Check for expat
have_expat_include=no
AC_CHECK_LIB(expat, XML_ParserCreate, have_expat_lib=yes, have_expat_lib=no)
  
if test x$have_expat_lib = xno; then
    enable_php=no
fi

AC_MSG_CHECKING(for PHP development files)
PHP_VERSION=`$PHP_CONFIG --version 2>/dev/null`
dnl Check if we were be able to extract a good version number.
if test "X$PHP_VERSION" != X; then
    languages_available="$languages_available php($PHP_VERSION)"
else
    enable_php=no
fi
AC_MSG_RESULT($enable_php)
AM_CONDITIONAL([PHP_ENABLED], [test "x$enable_php" = "xyes"])
AC_SUBST(PHP_VERSION)



# -----------
# C# bindings
# -----------

AC_ARG_ENABLE(csharp, [  --disable-csharp        disable the C Sharp bindings],,
              enable_csharp="yes")

AC_ARG_WITH(cil-interpreter, [  --with-cil-interpreter=path     set location of CIL interpreter for CSharp],[CSHARPBIN="$withval"], [CSHARPBIN=])
AC_ARG_WITH(csharp-compiler, [  --with-csharp-compiler=path     set location of CSharp compiler],[CSHARPCOMPILERBIN="$withval"], [CSHARPCOMPILERBIN=])

if test -z "$CSHARPCOMPILERBIN" ; then
  case $host in
  *-*-cygwin* | *-*-mingw*)
    AC_CHECK_PROGS(CSHARPCOMPILER, mcs.bat cscc csc);;
  *)AC_CHECK_PROGS(CSHARPCOMPILER, mcs cscc);;
  esac
else
  CSHARPCOMPILER="$CSHARPCOMPILERBIN"
fi

CSHARPPATHSEPARATOR="/"
CSHARPCYGPATH_W=echo
if test -z "$CSHARPBIN" ; then
  languages_available="$languages_available C#($CSHARPCOMPILER)"
  CSHARPCILINTERPRETER=""
  if test "cscc" = "$CSHARPCOMPILER" ; then
    AC_CHECK_PROGS(CSHARPCILINTERPRETER, ilrun)
  else
    if test "mcs" = "$CSHARPCOMPILER"; then
      # Check that mcs is the C# compiler and not the Unix mcs utility by examining the output of 'mcs --version'
      # The Mono compiler should emit: Mono C# compiler version a.b.c.d
      csharp_version_raw=`(mcs --version) 2>/dev/null`
      csharp_version_searched=`(mcs --version | sed -n "/C#\|Mono/p") 2>/dev/null`
      CSHARPCOMPILER="";
      if test -n "$csharp_version_raw" ; then
        if test "$csharp_version_raw" = "$csharp_version_searched" ; then
          CSHARPCOMPILER="mcs"
        fi
      fi

      # mono interpreter (ver 0.26 doesn't seem to work on Windows platforms)
      case $host in
      *-*-cygwin* | *-*-mingw*)
        ;;
      *)AC_CHECK_PROGS(CSHARPCILINTERPRETER, mint);;
      esac
    else 
      if test "csc" = "$CSHARPCOMPILER"; then
          CSHARPPATHSEPARATOR="\\\\"
          CSHARPCYGPATH_W='cygpath -w'
      fi
    fi
  fi
else
  CSHARPCILINTERPRETER="$CSHARPBIN"
fi

# Cygwin requires the Windows standard (Pascal) calling convention as it is a Windows executable and not a Cygwin built executable
case $host in
*-*-cygwin* | *-*-mingw*)
    if test "$GCC" = yes; then
        CSHARPDYNAMICLINKING=" -Wl,--add-stdcall-alias"
    else
        CSHARPDYNAMICLINKING=""
    fi ;;
*)CSHARPDYNAMICLINKING="";;
esac

AC_CHECK_PROGS(GACUTIL, gacutil)

AC_SUBST(CSHARPCILINTERPRETER)
AC_SUBST(CSHARPCYGPATH_W)
AC_SUBST(CSHARPCOMPILER)
AC_SUBST(CSHARPDYNAMICLINKING)
AC_SUBST(CSHARPLIBRARYPREFIX) # Is this going to be used?
AC_SUBST(GACUTIL)

if test "X$CSHARPCOMPILER" = X; then
    enable_csharp=no 
fi
if test "X$GACUTIL" = X; then
    enable_csharp=no 
fi
AM_CONDITIONAL([CSHARP_ENABLED], [test "x$enable_csharp" = "xyes"])



dnl ==========================================================================
dnl Test suite (requires check)
dnl ==========================================================================
dnl Check if user disabled the tests.
AC_ARG_ENABLE(tests, [  --disable-tests         disable the test suite],,
              enable_tests="yes")
AC_DEFINE([CHECK_IS_XML], [], [Define if check available with XML support])
if test "x$enable_tests" = xyes ; then
  AM_PATH_CHECK
  AC_CHECK_LIB(check, srunner_set_xml, [AC_DEFINE(CHECK_IS_XML)])
fi

AM_CONDITIONAL(WITH_TESTS, [test "x$enable_tests" = "xyes"])

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

AC_CHECK_PROGS(REST2HTML, rest2html)

AM_CONDITIONAL(HAVE_REST2HTML, test -n "$ac_cv_prog_REST2HTML")


dnl pkg-config path
AC_ARG_WITH(pkg-config-path, [  --with-pkg-config-path=PATH set pkg-config metadata search path.],
            PKG_CONFIG_PATH="${withval}", PKG_CONFIG_PATH="")
if test "z$PKG_CONFIG_PATH" != "z"; then
    export PKG_CONFIG_PATH
fi

PKG_CHECK_MODULES(LASSO, glib-2.0 gobject-2.0 libxml-2.0 libxslt xmlsec1 xmlsec1-openssl openssl)

dnl Let people disable the gtk-doc stuff.
AC_ARG_ENABLE(gtk-doc, [  --disable-gtk-doc       disable documentation build],,
              enable_gtk_doc="yes")

if test "x$enable_gtk_doc" = "xyes" ; then
    GTK_DOC_MIN_VERSION=1.0
    AC_MSG_CHECKING(gtk-doc support:)
    PKG_CHECK_MODULES(GTK_DOC, gtk-doc >= $GTK_DOC_MIN_VERSION, enable_gtk_doc="yes",
                      enable_gtk_doc="no")
fi
dnl Conditional docs sub dir test.
AM_CONDITIONAL([GTK_DOC_ENABLED],[test "x$enable_gtk_doc" = "xyes"])


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
LASSO_CORE_CFLAGS="$LASSO_DEFINES" 
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

dnl Temporaly
AM_CONDITIONAL(MINGW, test $MINGW == 1)
AM_CONDITIONAL(WITH_PYTHON, test 1 -eq 0)


dnl ==========================================================================
dnl Writing result files
dnl ==========================================================================
AC_OUTPUT(
[Makefile
csharp/Makefile
csharp/lasso-sharp.pc
docs/Makefile
docs/lasso-book/Makefile
docs/reference/Makefile
docs/tutorial/Makefile
java/Makefile
lasso/Makefile
lasso/environs/Makefile
lasso/protocols/elements/Makefile
lasso/protocols/Makefile
lasso/xml/Makefile
php/Makefile
python/Makefile
swig/Makefile
tests/Makefile
tests/data/Makefile
tests/data/ca1-la/Makefile
tests/data/idp1-la/Makefile
tests/data/lecp1-la/Makefile
tests/data/sp1-la/Makefile
lasso.pc
win32/Makefile
win32/nsis/Makefile
])
languages_available=`echo $languages_available | sed -e "s/^ //" `
AC_MSG_RESULT(

=============
Configuration
=============

Main
----

Compiler:               ${CC} 
Install prefix:         ${prefix}
Debugging:              $enable_debugging

Optionals builds
----------------
  
Available languages:    ${languages_available}

C# binding:             ${enable_csharp}
Java binding:           ${enable_java}
PHP binding:            ${enable_php}
Python binding:         ${enable_python}

C API references:       ${enable_gtk_doc}
Tests suite:            ${enable_tests}
)
