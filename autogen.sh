#!/bin/sh
#
# autogen.sh - Generates the initial makefiles from a pristine CVS tree
#
# $Id$
#
# USAGE: autogen.sh [configure options]
#
# If environment variable DRYRUN is set, no configuring will be done -
# (e.g. in bash)  DRYRUN=1 ./autogen.sh
# will not do any configuring but will emit the programs that would be run.
#
# This script is based on similar scripts used in various tools
# commonly made available via CVS and used with GNU automake.
# Try 'locate autogen.sh' on your system and see what you get.
#

PACKAGE=lasso

SRCDIR=`dirname $0`
test -z "$SRCDIR" && SRCDIR=. 

cd $SRCDIR
DIE=

if test "z$DRYRUN" != "z"; then
    DRYRUN=echo
fi

echo "- Define minimal version constants."
automake_min_vers=1.6
aclocal_min_vers=$automake_min_vers
autoconf_min_vers=2.53
libtoolize_min_vers=1.5
swig_min_vers=1.3
# For cygwin wrapper and perphas others ?
WANT_AUTOCONF_VER=$autoconf_min_vers
WANT_AUTOMAKE_VER=$automake_min_vers
WANT_LIBTOOL_VER=$libtoolize_min_vers
export WANT_AUTOCONF_VER WANT_AUTOMAKE_VER WANT_LIBTOOL_VER

echo "- Define autotools programs command line arguments."
echo " - Add missing required files to the package by symbolic links."
automake_args=--add-missing
autoconf_args=
aclocal_args=

echo - Store the used shell interpreter name.
program=`basename $0`

echo " - Define autotool program commands."
autoconf=autoconf
automake=automake
aclocal=aclocal

echo "- Check autoconf version."
if ($autoconf --version) < /dev/null > /dev/null 2>&1 ; then
    if ($autoconf --version | awk 'NR==1 { if( $3 >= '$autoconf_min_vers') \
			       exit 1; exit 0; }');
    then
       echo "$program: ERROR: \`$autoconf' is too old."
       echo "           (version $autoconf_min_vers or newer is required)"
       DIE="yes"
    fi
else
    echo
    echo "$program: ERROR: You must have \`$autoconf' installed to compile $PACKAGE."
    echo "           (version $autoconf_min_vers or newer is required)"
    DIE="yes"
fi

echo "- Check automake version."
if ($automake --version) < /dev/null > /dev/null 2>&1 ; then
  if ($automake --version | awk 'NR==1 { if( $4 >= '$automake_min_vers') \
			     exit 1; exit 0; }');
     then
     echo "$program: ERROR: \`$automake' is too old."
     echo "           (version $automake_min_vers or newer is required)"
     DIE="yes"
  fi
  if ($aclocal --version) < /dev/null > /dev/null 2>&1; then
    if ($aclocal --version | awk 'NR==1 { if( $4 >= '$aclocal_min_vers' ) \
						exit 1; exit 0; }' );
    then
      echo "$program: ERROR: \`$aclocal' is too old."
      echo "           (version $aclocal_min_vers or newer is required)"
      DIE="yes"
    fi
  else
    echo
    echo "$program: ERROR: Missing \`$aclocal'"
    echo "           The version of $automake installed doesn't appear recent enough."
    DIE="yes"
  fi
else
    echo
    echo "$program: ERROR: You must have \`$automake' installed to compile $PACKAGE."
    echo "           (version $automake_min_vers or newer is required)"
    DIE="yes"
fi

echo "- Check Libtoolize version."
if (libtoolize --version) < /dev/null > /dev/null 2>&1 ; then
    if (libtoolize --version | awk 'NR==1 { if( $4 >= '$libtoolize_min_vers') \
			       exit 1; exit 0; }');
    then
       echo "$program: ERROR: \`libtoolize' is too old."
       echo "           (version $libtoolize_min_vers or newer is required)"
       DIE="yes"
    fi
else
    echo
    echo "$program: ERROR: You must have \`libtoolize' installed to compile $PACKAGE."
    echo "           (version $libtoolize_min_vers or newer is required)"
    DIE="yes"
fi


echo "- Check swig version."
if (swig -help) </dev/null >/dev/null 2>&1; then 
  swig_version=`swig -version 2>&1 |sed -ne 's/^SWIG Version //p'`
  swig_version_dec=`echo $swig_version | awk -F. '{printf("%d\n", 10000*$1 + 100*$2 + $3)};'`
  swig_min_version_dec=`echo $swig_min_vers | awk -F. '{printf("%d\n", 10000*$1 + 100*$2 + $3)};'`

  if test $swig_version_dec -lt $swig_min_version_dec; then
    echo "$program: ERROR: \`swig' is too old."
    echo "           (version $swig_min_vers or newer is required)"
    DIE="yes"
  fi
else
    echo
    echo "$program: ERROR: You must have \`swig' installed to compile $PACKAGE."
    echo "           (version $swig_min_vers or newer is required)"
    DIE="yes"
fi

# - If something went wrong, exit with error code:1.
if test "z$DIE" != "z"; then
	exit 1
fi

echo - Check if we are in the top-level lasso directory.
test -f lasso/lasso.h  || {
        pwd
	echo "You must run this script in the top-level lasso directory"
	exit 1
}

if test -z "$*"; then
	echo "I am going to run ./configure with no arguments - if you wish "
        echo "to pass any to it, please specify them on the $0 command line."
fi

echo "- Clean up autotool distribution programs."
echo " - libtool stuff."
rm -f ltconfig ltmain.sh libtool
echo " - autoconf generated files"
rm -f configure
echo " - automake generated files"
rm -f missing depcomp
echo " - automake cache file."
rm -rf autom4te.cache

echo "- Auto generate autoconf configuration files."
for autoconfile in `find $SRCDIR -name configure.ac -print`
do 
  dir=`dirname $autoconfile`
  if test -f $dir/NO-AUTO-GEN; then
    echo $program: Skipping $dir -- flagged as no auto-gen
  else
    echo $program: Processing directory $dir
    ( cd $dir
      echo "$program: Running libtoolize --copy --automake"
      $DRYRUN rm -f ltmain.sh libtool
      $DRYRUN libtoolize --copy --automake

      aclocalinclude="$ACLOCAL_FLAGS"
      echo "$program: Running aclocal $aclocalinclude"
      $DRYRUN $aclocal $aclocal_args
      if grep "^AM_CONFIG_HEADER" configure.ac >/dev/null; then
	echo "$program: Running autoheader"
	$DRYRUN autoheader
      fi
      echo "$program: Running automake $am_opt"
      $DRYRUN $automake $automake_args $am_opt
      echo "$program: Running autoconf"
      $DRYRUN $autoconf $autoconf_args

    )
  fi
done

echo "- Clean up configuration cache."
rm -f config.cache


conf_flags="--enable-compile-warnings"

echo "- Set and export autotools environment variables."
AUTOMAKE=$automake
AUTOCONF=$autoconf
ACLOCAL=$aclocal
export AUTOMAKE AUTOCONF ACLOCAL

echo "$program: Running ./configure $conf_flags $@ ..."
if test "z$DRYRUN" = "z"; then
    $DRYRUN ./configure $conf_flags "$@" \
    && echo "Now type 'make' to compile lasso."
else
    $DRYRUN ./configure $conf_flags "$@"
fi

