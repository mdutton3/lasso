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
# This script is based on similar scripts used in various free software
# projects; notably the gnome-autogen.sh script used in many GNOME programs.
#

DIE=0

if test "z$DRYRUN" != "z"; then
    DRYRUN=echo
fi

# Not all echo versions allow -n, so we check what is possible. This test is
# based on the one in autoconf.
case `echo "testing\c"; echo 1,2,3`,`echo -n testing; echo 1,2,3` in
  *c*,-n*) ECHO_N= ;;
  *c*,*  ) ECHO_N=-n ;;
  *)       ECHO_N= ;;
esac

# some terminal codes ...
boldface="`tput bold 2>/dev/null`"
normal="`tput sgr0 2>/dev/null`"
printbold() {
    echo $ECHO_N "$boldface"
    echo "$@"
    echo $ECHO_N "$normal"
}    
printerr() {
    echo "$@" >&2
}

# Usage:
#     compare_versions MIN_VERSION ACTUAL_VERSION
# returns true if ACTUAL_VERSION >= MIN_VERSION
compare_versions() {
    ch_min_version=$1
    ch_actual_version=$2
    ch_status=0
    IFS="${IFS=         }"; ch_save_IFS="$IFS"; IFS="."
    set $ch_actual_version
    for ch_min in $ch_min_version; do
        ch_cur=`echo $1 | sed 's/[^0-9].*$//'`; shift # remove letter suffixes
        if [ -z "$ch_min" ]; then break; fi
        if [ -z "$ch_cur" ]; then ch_status=1; break; fi
        if [ $ch_cur -gt $ch_min ]; then break; fi
        if [ $ch_cur -lt $ch_min ]; then ch_status=1; break; fi
    done
    IFS="$ch_save_IFS"
    return $ch_status
}

# Usage:
#     version_check PACKAGE VARIABLE CHECKPROGS MIN_VERSION SOURCE
# checks to see if the package is available
version_check() {
    vc_package=$1
    vc_variable=$2
    vc_checkprogs=$3
    vc_min_version=$4
    vc_source=$5
    vc_status=1

    vc_checkprog=`eval echo "\\$$vc_variable"`
    if [ -n "$vc_checkprog" ]; then
	printbold "using $vc_checkprog for $vc_package"
	return 0
    fi

    printbold "checking for $vc_package >= $vc_min_version..."
    for vc_checkprog in $vc_checkprogs; do
	echo $ECHO_N "  testing $vc_checkprog... "
	if $vc_checkprog --version < /dev/null > /dev/null 2>&1 || \
		$vc_checkprog -version < /dev/null > /dev/null 2>&1 ; then
            if [ "$vc_package" = "swig" ]; then
                vc_actual_version=`$vc_checkprog -version 2>&1 | head -n 2 | \
                                  tail -1 | sed 's/^.*[      ]\([0-9.]*[a-z]*\).*$/\1/'`
            else
	        vc_actual_version=`$vc_checkprog --version | head -n 1 | \
                                  sed 's/^.*[ 	]\([0-9.]*[a-z]*\).*$/\1/'`
            fi
	    if compare_versions $vc_min_version $vc_actual_version; then
		echo "found $vc_actual_version"
		# set variable
		eval "$vc_variable=$vc_checkprog"
		vc_status=0
		break
	    else
		echo "too old (found version $vc_actual_version)"
	    fi
	else
	    echo "not found."
	fi
    done
    if [ "$vc_status" != 0 ]; then
	printerr "***Error***: You must have $vc_package >= $vc_min_version installed"
	printerr "  to build $PKG_NAME.  Download the appropriate package for"
	printerr "  from your distribution or get the source tarball at"
        printerr "    $vc_source"
	printerr
    fi
    return $vc_status
}

printbold "checking this is lasso top-level directory..."
test -f lasso/lasso.h  || {
	printerr "***Error***: You must run this script in lasso top-level directory"
	exit 1
}

REQUIRED_AUTOCONF_VERSION=2.53
REQUIRED_AUTOMAKE_VERSION=1.8
REQUIRED_LIBTOOL_VERSION=1.5
REQUIRED_SWIG_VERSION=1.3.22
REQUIRED_PKG_CONFIG_VERSION=0.14.0

# For cygwin wrapper and perphas others ?
WANT_AUTOCONF_VER=$REQUIRED_AUTOCONF_VERSION
WANT_AUTOMAKE_VER=$REQUIRED_AUTOMAKE_VERSION
WANT_LIBTOOL_VER=$REQUIRED_LIBTOOL_VERSION
export WANT_AUTOCONF_VER WANT_AUTOMAKE_VER WANT_LIBTOOL_VER

automake_args=--add-missing
autoconf_args=
aclocal_args="-I macros"

program=`basename $0`

WANT_AUTOCONF_2_5=1 # for Mandrake wrapper
export WANT_AUTOCONF_2_5
version_check autoconf AUTOCONF 'autoconf2.50 autoconf autoconf-2.53 autoconf253' $REQUIRED_AUTOCONF_VERSION \
    "http://ftp.gnu.org/pub/gnu/autoconf/autoconf-$REQUIRED_AUTOCONF_VERSION.tar.gz" || DIE=1
AUTOHEADER=`echo $AUTOCONF | sed s/autoconf/autoheader/`

case $REQUIRED_AUTOMAKE_VERSION in
    1.4*) automake_progs="automake-1.4" ;;
    1.5*) automake_progs="automake-1.5 automake-1.6 automake-1.7 automake-1.8 automake-1.9" ;;
    1.6*) automake_progs="automake-1.6 automake-1.7 automake-1.8 automake-1.9" ;;
    1.7*) automake_progs="automake-1.7 automake-1.8 automake-1.9" ;;
    1.8*) automake_progs="automake-1.8 automake-1.9" ;;
    1.9*) automake_progs="automake-1.9" ;;
esac

version_check automake AUTOMAKE "$automake_progs" $REQUIRED_AUTOMAKE_VERSION \
    "http://ftp.gnu.org/pub/gnu/automake/automake-$REQUIRED_AUTOMAKE_VERSION.tar.gz" || DIE=1
ACLOCAL=`echo $AUTOMAKE | sed s/automake/aclocal/`

version_check swig SWIG "swig-1.3 swig" $REQUIRED_SWIG_VERSION \
    "http://prdownloads.sourceforge.net/swig/swig-$REQUIRED_SWIG_VERSION.tar.gz" || DIE=1

version_check libtool LIBTOOLIZE libtoolize $REQUIRED_LIBTOOL_VERSION \
    "http://ftp.gnu.org/pub/gnu/libtool/libtool-$REQUIRED_LIBTOOL_VERSION.tar.gz" || DIE=1

version_check pkg-config PKG_CONFIG pkg-config $REQUIRED_PKG_CONFIG_VERSION \
    "'http://www.freedesktop.org/software/pkgconfig/releases/pkgconfig-$REQUIRED_PKG_CONFIG_VERSION.tar.gz" || DIE=1

# - If something went wrong, exit with error code:1.
if [ "$DIE" -eq 1 ]; then
    exit 1
fi

if test -z "$*"; then
    printerr "**Warning**: I am going to run \`configure' with no arguments."
    printerr "If you wish to pass any to it, please specify them on the"
    printerr \`$0\'" command line."
fi

# cleaning up some files
$DRYRUN rm -f ltconfig ltmain.sh libtool
$DRYRUN rm -f configure
$DRYRYN rm -f missing depcomp
$DRYRUN rm -rf autom4te.cache

printbold "Running $LIBTOOLIZE..."
$DRYRUN $LIBTOOLIZE --force --copy || exit 1

printbold "Running $ACLOCAL..."
$DRYRUN $ACLOCAL $aclocal_args || exit 1

printbold "Running $AUTOHEADER..."
$DRYRUN $AUTOHEADER || exit 1

printbold "Running $AUTOMAKE..."
$DRYRUN $AUTOMAKE $automake_args $am_opt

printbold "Running $AUTOCONF..."
$DRYRUN $AUTOCONF $autoconf_args

printbold "Cleaning up configuration cache..."
$DRYRUN rm -f config.cache

export AUTOMAKE AUTOCONF ACLOCAL

printbold Running ./configure $conf_flags "$@" ...
if test "z$DRYRUN" = "z"; then
    ./configure $conf_flags "$@" \
            && echo "Now type 'make' to compile lasso." || exit 1
else
    $DRYRUN ./configure $conf_flags "$@"
fi

