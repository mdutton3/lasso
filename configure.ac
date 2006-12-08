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
AC_INIT([Liberty Alliance Single Sign On], 0.6.6, lasso-devel@lists.labs.libre-entreprise.org)
dnl Check if autoconf ver > 2.53
AC_PREREQ(2.53)
dnl Check existence of a relative pathed source file.
AC_CONFIG_SRCDIR(lasso/lasso.c)
dnl Copy stamp REVISIO-INFO in the configure script.
AC_REVISION($Revision$)

dnl Run many macros mostly needed by configure.ac.
AM_INIT_AUTOMAKE(lasso, 0.6.6)
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

### Sun Java environment needs to be told about platform...
SUN_EXTRA_INCLUDE=
case "${host}" in
    *-pc-mingw32)
        SUN_EXTRA_INCLUDE="win32" 
        ;;
    *-pc-cygwin)
        SUN_EXTRA_INCLUDE="win32" 
        ;;
    *linux*)
        SUN_EXTRA_INCLUDE="linux"
        ;;
esac

### adapting build environment for different platforms...
MINGW=0
DARWIN=0
case "${host}" in
    *aix*)
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
        esac
        ;;
    *-darwin*)
        DARWIN=1
        ;;
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
AC_CHECK_PROGS(PERL, perl)
AC_CHECK_PROGS(PHP4, php4 php)
AC_CHECK_PROGS(PHP5, php4 php)
AC_CHECK_PROGS(PHP4_CONFIG, php-config4 php-config)
AC_CHECK_PROGS(PHP5_CONFIG, php-config5 php-config)
AC_CHECK_PROGS(PYTHON, python)
AC_CHECK_PROGS(SWIG, swig)

dnl Make sure we have an ANSI compiler
AM_C_PROTOTYPES
test "z$U" != "z" && AC_MSG_ERROR(Compiler not ANSI compliant)

dnl Check for variadic macros
AC_CACHE_CHECK([for variadic cpp macros],
    [ac_cv_cpp_variadic_macros],
    [AC_TRY_COMPILE(
         [#include <stdio.h>
          #define a(b,c...) printf(b,##c)],
         [a("foo");a("%s","bar");a("%s%s","baz","quux");],
         ac_cv_cpp_variadic_macros=yes,
         ac_cv_cpp_variadic_macros=no)])
if test "x${ac_cv_cpp_variadic_macros}" != "xno"; then
    AC_DEFINE(HAVE_VARIADIC_MACROS, 1, Support for variadic macros)
fi


dnl ==========================================================================
dnl Version Super.Size.Me.L
dnl ==========================================================================

changequote(<<, >>)dnl
VERSION_MAJOR=`echo $VERSION | $SED -e 's/^\([^\.]*\)\.\([^\.]*\)\.\(.*\)$/\1/'`
VERSION_MINOR=`echo $VERSION | $SED -e 's/^\([^\.]*\)\.\([^\.]*\)\.\(.*\)$/\2/'`
VERSION_RELEASE=`echo $VERSION | $SED -e 's/^\([^\.]*\)\.\([^\.]*\)\.\(.*\)$/\3/'`
changequote([, ])dnl
VERSION_UNDERSCORED=`echo $VERSION | $SED -e 's/\./_/g'`
AC_SUBST(VERSION_UNDERSCORED)


dnl Add versionning & package defines to lasso_.h
AC_DEFINE_UNQUOTED(LASSO_VERSION_MAJOR, $VERSION_MAJOR, [Major version number])
AC_DEFINE_UNQUOTED(LASSO_VERSION_MINOR, $VERSION_MINOR, [Minor version number])
AC_DEFINE_UNQUOTED(LASSO_VERSION_SUBMINOR, $VERSION_RELEASE, [Release version number])

dnl Dirty hack in order to have dynamic resource version numbering.
WINDOWS_VERSION=`echo $VERSION_MAJOR,$VERSION_MINOR,$VERSION_RELEASE,0`
AC_SUBST(WINDOWS_VERSION)

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
LASSO_VERSION_INFO="6:0:3"
AC_SUBST(LASSO_VERSION_INFO)

dnl Compute the minimal supported ABI version for Win32 scripts and resources files.
minimal_version=`echo $LASSO_VERSION_INFO | $AWK -F: '{printf("%d\n",$1-$3)};'`
UPCASED_DLL_FILENAME="LIBLASSO-$minimal_version.DLL"
DLL_FILENAME="liblasso-$minimal_version.dll"
AC_SUBST(UPCASED_DLL_FILENAME)
AC_SUBST(DLL_FILENAME)

dnl ==========================================================================
dnl Swig
dnl ==========================================================================
SWIG_MIN_VERSION=1.3.27
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
    if test -r $srcdir/python/lasso_wrap.c ; then
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


# ------------
# JAVA binding
# ------------

dnl Check if java is explicitly disabled.
AC_ARG_ENABLE(java, [  --disable-java          disable the Java binding],,
              enable_java="yes")
AC_ARG_WITH(java-home,
            [  --with-java-home=(JAVA_HOME)  set the full path to the java home directory.])
JAVAC_FLAGS=
JDK_INCLUDE=
SUN=no
if test "X$with_java_home" != "X"; then
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
        if test "x$JAVA_VERSION" != "x"; then
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
    AC_CHECK_HEADERS([jni.h], [], [JAVA_VERSION=""])
fi

dnl Now transform JDK_INCLUDE in CFLAG option if applicable.
if test "X$JDK_INCLUDE" != "X"; then
    dnl If it is a sun environment
    if test "x$SUN" = "xyes"; then
        JDK_INCLUDE="$JDK_INCLUDE -I$JDK_INCLUDE/$SUN_EXTRA_INCLUDE"
    fi
    JDK_INCLUDE=-I$JDK_INCLUDE
fi

dnl If we found a java version information, we have java compilation environment.
if test "X$JAVA_VERSION" != "X" && test "X$JAR" != "X"; then
  languages_available="$languages_available $JAVA($JAVA_VERSION)"
else
  enable_java=no
  JAVA_VERSION=""
fi

dnl Conditional java sub dir test.
AM_CONDITIONAL([JAVA_ENABLED],[test "x$enable_java" = "xyes"])
AC_SUBST(JAVA_VERSION)
AC_SUBST(JAVAC_FLAGS)
AC_SUBST(JDK_INCLUDE)


# --------------
# Python binding
# --------------

dnl Check if python is explicitly disabled.
AC_ARG_ENABLE(python, [  --disable-python        disable the Python binding],,
              enable_python="yes")

dnl Check if user passed a specific python program.
AC_ARG_WITH(python,
            [  --with-python=(PYTHON)  set the full path to the python program to use.])

dnl specific program passed, set PYTHON to it.
if test "X$with_python" != "X"; then
    PYTHON=$with_python
fi


dnl need to change quotes to allow square brackets
changequote(<<, >>)dnl
PYTHON_VERSION=`$PYTHON -c 'import sys; print sys.version[:3]' 2>/dev/null`
changequote([, ])dnl

test "x$PYTHON" != "x" || AC_MSG_ERROR(Python must be installed to compile lasso)

AC_MSG_CHECKING(for Python development files)
dnl Check if we were be able to extract a good version number.
if test "X$PYTHON_VERSION" != "X"; then
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

# -----------
# PHP binding
# -----------

dnl Check if php is explicitly disabled.
AC_ARG_ENABLE(php4, [  --disable-php4         disable the PHP 4 binding],,
              enable_php4="yes")

AC_ARG_ENABLE(php4-force, [  --enable-php4-force    always enable of the PHP 4 binding (win32)],
              [ENABLE_PHP4_FORCE="yes"],
              [ENABLE_PHP4_FORCE="no"])

AC_ARG_WITH(php4-config,
            [  --with-php4-config=(PHP4_CONFIG)      Specify full path to php-config4.])

AC_ARG_WITH(php4-extension-dir,
            [  --with-php4-extension-dir=(PHP4_EXTENSION_DIR)      Specify full path to php 4 extension dir.],
            [PHP4_EXTENSION_DIR="$withval"],[PHP4_EXTENSION_DIR=])

dnl Check if user passed a specific php-config program.
if test "X$with_php4_config" != "X" ; then
    PHP4_CONFIG=$with_php4_config
fi

if test "X$PHP4_CONFIG" != "X" ; then
  PHP4_INCLUDES=`$PHP4_CONFIG --includes`
  PHP4_LDFLAGS=`$PHP4_CONFIG --ldflags`
  PHP4_LIBS=`$PHP4_CONFIG --libs`
  PHP4_UNPREFIXED_EXTENSION_DIR=`$PHP4_CONFIG --extension-dir | $SED 's/\/usr//g'`
  PHP4_PREFIX=`$PHP4_CONFIG --prefix`
else
  # We assume PHP are in /usr/local directory.
  if test $MINGW -eq 1; then 
    CFLAGS="$CFLAGS -DZTS -DZEND_WIN32 -DWIN32 -D_MBCS"
  fi
  PHP4_INCLUDES="-I/usr/local/include/php4 -I/usr/local/include/php4/main -I/usr/local/include/php4/Zend -I/usr/local/include/php4/TSRM -I/usr/local/include/php4/win32"
  PHP4_LDFLAGS=
  PHP4_LIBS=-lphp4ts -lxmlparse -lxmltok
  PHP4_UNPREFIXED_EXTENSION_DIR=
  PHP4_PREFIX=
fi
AC_SUBST(PHP4_INCLUDES)
AC_SUBST(PHP4_LDFLAGS)
AC_SUBST(PHP4_LIBS)
AC_SUBST(PHP4_UNPREFIXED_EXTENSION_DIR)
AC_SUBST(PHP4_EXTENSION_DIR)
AC_SUBST(PHP4_PREFIX)

dnl Check for expat
have_expat_include=no
if test $MINGW -eq 1; then 
    AC_CHECK_LIB(xmlparse, XML_ParserCreate, have_expat_lib=yes, have_expat_lib=no)
else
    AC_CHECK_LIB(expat, XML_ParserCreate, have_expat_lib=yes, have_expat_lib=no)
fi
  
if test x$have_expat_lib = xno; then
    enable_php4=no
fi

AC_MSG_CHECKING(for PHP 4 development files)
if $PHP4_CONFIG --version | grep -q 4 || test "x$ENABLE_PHP4_FORCE" == "xyes"
then
	PHP4_VERSION=`$PHP4_CONFIG --version 2> /dev/null`
	languages_available="$languages_available php4($PHP4_VERSION)"
else
	enable_php4=no
fi

AC_MSG_RESULT($enable_php4)
AM_CONDITIONAL([PHP4_ENABLED], [test "x$enable_php4" = "xyes"])
AC_SUBST(PHP4_VERSION)


### # ----------
### # C# binding (disabled for the moment)
### # ----------
### 
### AC_ARG_ENABLE(csharp, [  --disable-csharp        disable the C Sharp binding],,
###               enable_csharp="yes")
### 
### AC_ARG_WITH(cil-interpreter, [  --with-cil-interpreter=path     set location of CIL interpreter for CSharp],[CSHARPBIN="$withval"], [CSHARPBIN=])
### AC_ARG_WITH(csharp-compiler, [  --with-csharp-compiler=path     set location of CSharp compiler],[CSHARPCOMPILERBIN="$withval"], [CSHARPCOMPILERBIN=])
### 
### if test -z "$CSHARPCOMPILERBIN" ; then
###   case $host in
###   *-*-cygwin* | *-*-mingw*)
###     AC_CHECK_PROGS(CSHARPCOMPILER, mcs.bat cscc csc);;
###   *)AC_CHECK_PROGS(CSHARPCOMPILER, mcs cscc);;
###   esac
### else
###   CSHARPCOMPILER="$CSHARPCOMPILERBIN"
### fi
### 
### CSHARPPATHSEPARATOR="/"
### CSHARPCYGPATH_W=echo
### if test -z "$CSHARPBIN" ; then
###   #languages_available="$languages_available C#($CSHARPCOMPILER)"
###   CSHARPCILINTERPRETER=""
###   if test "cscc" = "$CSHARPCOMPILER" ; then
###     AC_CHECK_PROGS(CSHARPCILINTERPRETER, ilrun)
###   else
###     if test "mcs" = "$CSHARPCOMPILER"; then
###       # Check that mcs is the C# compiler and not the Unix mcs utility by examining the output of 'mcs --version'
###       # The Mono compiler should emit: Mono C# compiler version a.b.c.d
###       csharp_version_raw=`(mcs --version) 2>/dev/null`
###       csharp_version_searched=`(mcs --version | sed -n "/C#\|Mono/p") 2>/dev/null`
###       CSHARPCOMPILER="";
###       if test -n "$csharp_version_raw" ; then
###         if test "$csharp_version_raw" = "$csharp_version_searched" ; then
###           CSHARPCOMPILER="mcs"
###         fi
###       fi
### 
###       # mono interpreter (ver 0.26 doesn't seem to work on Windows platforms)
###       case $host in
###       *-*-cygwin* | *-*-mingw*)
###         ;;
###       *)AC_CHECK_PROGS(CSHARPCILINTERPRETER, mint);;
###       esac
###     else 
###       if test "csc" = "$CSHARPCOMPILER"; then
###           CSHARPPATHSEPARATOR="\\\\"
###           CSHARPCYGPATH_W='cygpath -w'
###       fi
###     fi
###   fi
### else
###   CSHARPCILINTERPRETER="$CSHARPBIN"
### fi

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


# ------------
# Perl binding
# ------------

AC_ARG_ENABLE(perl, [  --disable-perl          disable the Perl binding],,
              enable_perl="yes")

if test "X$PERL" != "X"; then
  PERLINSTALLSITEARCH=`$PERL -MConfig -e 'print $Config{installsitearch};'`
  PERLMAN3DIR=`$PERL -MConfig -e 'print $Config{man3dir};'`
else
  PERLINSTALLSITEARCH=none
  PERLMAN3DIR=none
fi
AC_SUBST(PERLINSTALLSITEARCH)
AC_SUBST(PERLMAN3DIR)

AC_MSG_CHECKING(for Perl API)
if test "X$enable_perl" != "Xno" ; then
  if test "X$enable_perl" != "Xyes"; then
    PERL=$enable_perl
  fi
  enable_perl=yes
fi

PERL_VERSION=`$PERL -MConfig -e 'print $Config{version}' 2>/dev/null`
if test "X$PERL_VERSION" != "X"; then
  languages_available="$languages_available perl($PERL_VERSION)"
  if test $enable_perl = yes; then
    languages="$languages perl"
  fi
fi
AM_CONDITIONAL([PERL_ENABLED],[test "x$enable_perl" = "xyes"])
AC_MSG_RESULT($enable_perl)
AC_SUBST(PERL_VERSION)


dnl Checks for zlib library (code adapted from libxml2 configure.in)
_cppflags="${CPPFLAGS}" 
_ldflags="${LDFLAGS}"

AC_ARG_WITH(zlib,
[  --with-zlib[[=DIR]]       use libz in DIR],[
  if test "$withval" != "no" -a "$withval" != "yes"; then
    Z_DIR=$withval
    CPPFLAGS="${CPPFLAGS} -I$withval/include"
    LDFLAGS="${LDFLAGS} -L$withval/lib"
  fi
]) 
AC_CHECK_HEADERS(zlib.h,
    AC_CHECK_LIB(z, gzread,[
        AC_DEFINE([HAVE_LIBZ], [], [Have compression library])
        if test "x${Z_DIR}" != "x"; then
            Z_CFLAGS="-I${Z_DIR}/include"
            Z_LIBS="-L${Z_DIR}/lib -lz"
            [case ${host} in
                *-*-solaris*)
                    Z_LIBS="-L${Z_DIR}/lib -R${Z_DIR}/lib -lz"
                    ;;
            esac]
        else
            Z_LIBS="-lz"
        fi]))

test "z$Z_LIBS" != "z" || AC_MSG_ERROR(missing zlib)

AC_SUBST(Z_CFLAGS)
AC_SUBST(Z_LIBS)

CPPFLAGS=${_cppflags}
LDFLAGS=${_ldflags}

dnl ==========================================================================
dnl Test suite (requires check)
dnl ==========================================================================
dnl Check if user disabled the tests.
AC_ARG_ENABLE(tests, [  --disable-tests         disable the test suite],,
              enable_tests="yes")
if test "x$enable_tests" = xyes ; then
  AC_CHECK_LIB(check, srunner_set_log, enable_tests="yes", enable_tests="no")
  CHECK_CFLAGS=""
  CHECK_LIBS="-lcheck"
  AC_SUBST(CHECK_CFLAGS)
  AC_SUBST(CHECK_LIBS)
  AC_CHECK_LIB(check, srunner_set_xml, [AC_DEFINE(CHECK_IS_XML, [], [Define if check available with XML support])])
fi

AM_CONDITIONAL(WITH_TESTS, [test "x$enable_tests" = "xyes"])

dnl Final step, add missing programs.
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)

dnl Check if wsf is explicitly disabled.
AC_ARG_ENABLE(wsf, [  --enable-wsf            enable experimental ID-WSF],
		enable_wsf="yes", enable_wsf="no")

AM_CONDITIONAL([WSF_ENABLED],[test "x$enable_wsf" = "xyes"])
LASSO_WSF_SUPPORT=0
if test "x$enable_wsf" = "xyes"; then
	AC_DEFINE(LASSO_WSF_ENABLED, [], [Define if ID-WSF support is enabled])
	LASSO_WSF_SUPPORT=1
	if grep -q 'WSF_SUPPORT.*0' $srcdir/*/lasso_wrap.c;
	then
		if test "x$SWIG" = "xecho"; then
			AC_MSG_WARN(Bindings were pre-generated without ID-WSF support)
			AC_MSG_ERROR(and you don't have SWIG to regenerate their files)
		fi
		echo "removing pre-generated language interface files"
		rm -f $srcdir/*/lasso_wrap.c $srcdir/csharp/liblassosharpglue_wrap.c
	fi
else
	if grep -q 'WSF_SUPPORT.*1' $srcdir/*/lasso_wrap.c;
	then
		if test "x$SWIG" = "xecho"; then
			AC_MSG_WARN(Bindings were pre-generated with ID-WSF support)
			AC_MSG_ERROR(and you don't have SWIG to regenerate their files)
		fi
		echo "removing pre-generated language interface files"
		rm -f $srcdir/*/lasso_wrap.c $srcdir/csharp/liblassosharpglue_wrap.c
	fi
fi
AC_SUBST(LASSO_WSF_SUPPORT)


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
AC_ARG_WITH(pkg-config, [  --with-pkg-config=PATH set pkg-config metadata search path.],
            PKG_CONFIG_PATH="${withval}", PKG_CONFIG_PATH="")
if test "z$PKG_CONFIG_PATH" != "z"; then
    export PKG_CONFIG_PATH
fi

PKG_CHECK_MODULES(LASSO, glib-2.0 >= 2.4.0 gobject-2.0 >= 2.4.0 libxml-2.0 libxslt xmlsec1 >= 1.2.6 xmlsec1-openssl >= 1.2.6 openssl)

AC_ARG_WITH(sasl2, [  --with-sasl2[=PFX]         Use Cyrus SASL library version 2 for WSF-Auth])
if test "x$enable_wsf" = "xyes"; then
	if test "$with_sasl2" != "no" && test "$with_sasl2" != "yes"
	then
		CPPFLAGS="$CPPFLAGS -I$with_sasl2/include"
		LDFLAGS="$LDFLAGS -L$with_sasl2/lib"
	fi
		
	saved_LIBS="$LIBS"
	AC_CHECK_LIB(sasl2, sasl_server_init,,
		AC_MSG_ERROR([libsasl must be installed for WSF support]),)
	LIBS="$saved_LIBS"
	LASSO_LIBS="$LASSO_LIBS -lsasl2"
fi

dnl Let people disable the gtk-doc stuff.
AC_ARG_ENABLE(gtk-doc, [  --disable-gtk-doc       disable documentation build],,
              enable_gtk_doc="yes")

if test "x$enable_gtk_doc" = "xyes" ; then
    GTK_DOC_MIN_VERSION=1.0
    PKG_CHECK_MODULES(GTK_DOC, gtk-doc >= $GTK_DOC_MIN_VERSION, enable_gtk_doc="yes",
                      enable_gtk_doc="no")
fi
dnl Conditional docs sub dir test.
AM_CONDITIONAL([GTK_DOC_ENABLED],[test "x$enable_gtk_doc" = "xyes"])


AC_CHECK_PROGS(REST2HTML, rest2html rst2html)
AM_CONDITIONAL(HAVE_REST2HTML, test -n "$ac_cv_prog_REST2HTML")

AC_CHECK_PROGS(XSLTPROC, xsltproc)
AM_CONDITIONAL(HAVE_XSLTPROC, test -n "$ac_cv_prog_XSLTPROC")

AC_CHECK_PROGS(INKSCAPE, inkscape)
AM_CONDITIONAL(HAVE_INKSCAPE, test -n "$ac_cv_prog_INKSCAPE")


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
LASSO_PUB_CFLAGS="$LASSO_DEFINES"
LASSO_CORE_CFLAGS="$LASSO_CFLAGS $LASSO_DEFINES $Z_CFLAGS -DLASSO_INTERNALS" 
if test $MINGW -eq 1; then 
  LASSO_CORE_LIBS="-llasso-0"
else
  LASSO_CORE_LIBS="-llasso "
fi
AC_SUBST(LASSO_CORE_CFLAGS)
AC_SUBST(LASSO_CORE_LIBS)

LASSO_CFLAGS="$LASSO_CFLAGS"
LASSO_LIBS="-L${libdir} $Z_LIBS $LASSO_LIBS"
AC_SUBST(LASSO_CFLAGS)
AC_SUBST(LASSO_LIBS)

AC_SUBST(LASSO_PUB_CFLAGS)
AC_SUBST(LASSO_DEFINES)
AC_SUBST(LASSO_APP_DEFINES)
AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)

dnl Dirty system often means dirty hacks...
AM_CONDITIONAL(MINGW, test $MINGW == 1)
AM_CONDITIONAL(DARWIN, test $DARWIN == 1)


dnl ==========================================================================
dnl Writing result files
dnl ==========================================================================
AC_CONFIG_FILES([lasso-src-config], [chmod +x lasso-src-config])
AC_OUTPUT(
[Makefile
docs/Makefile
docs/lasso-book/Makefile
docs/lasso-book/figures/Makefile
docs/reference/Makefile
docs/reference/version.xml
java/Makefile
lasso/Makefile
lasso/id-ff/Makefile
lasso/id-wsf/Makefile
lasso/saml-2.0/Makefile
lasso/xml/Makefile
lasso/xml/saml-2.0/Makefile
perl/Makefile
php/Makefile
python/Makefile
swig/Makefile
swig/wsf-support.i
swig/saml-2.0/Makefile
tests/Makefile
tests/data/Makefile
tests/data/ca1-la/Makefile
tests/data/idp1-la/Makefile
tests/data/lecp1-la/Makefile
tests/data/sp1-la/Makefile
lasso.pc
win32/Makefile
win32/lasso.rc
win32/msvc/Makefile
win32/msvc/lasso.dsp
win32/msvc/lasso_config.h
win32/msvc/java/Makefile
win32/msvc/php/Makefile
win32/msvc/python/Makefile
win32/nsis/Makefile
win32/nsis/jlasso-lite.nsi
win32/nsis/lasso-deps.nsi
win32/nsis/lasso-full.nsi
win32/nsis/lasso-lite.nsi
win32/nsis/python.nsi
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
Experimental ID-WSF:    $enable_wsf

Optionals builds
----------------
  
Available languages:    ${languages_available}

Java binding:           ${enable_java}
Perl binding:           ${enable_perl}
PHP 4 binding:          ${enable_php4}
Python binding:         ${enable_python}

C API references:       ${enable_gtk_doc}
Tests suite:            ${enable_tests}
)
