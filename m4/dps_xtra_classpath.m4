##### http://autoconf-archive.cryp.to/dps_xtra_classpath.html
#
# SYNOPSIS
#
#   DPS_XTRA_CLASSPATH(<classpath>,<class>,<jarfile>,<action-if-found>,<action-if-not-found>)
#
# DESCRIPTION
#
#   Set $1 to extra classpath components required for class $2 found in
#   a jar file in $3. If the class is found do $4 and otherwise do $5.
#   Uses DPS_JAVA_CHECK_CLASS for testing whether a class is avialable
#
# LAST MODIFICATION
#
#   2008-01-28
#
# COPYLEFT
#
#   Copyright (c) 2008 Duncan Simpson <dps@simpson.demon.co.uk>
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License as
#   published by the Free Software Foundation; either version 2 of the
#   License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#   General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, see <http://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright
#   owner gives unlimited permission to copy, distribute and modify the
#   configure scripts that are the output of Autoconf when processing
#   the Macro. You need not follow the terms of the GNU General Public
#   License when using or distributing such scripts, even though
#   portions of the text of the Macro appear in them. The GNU General
#   Public License (GPL) does govern all other use of the material that
#   constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the
#   Autoconf Macro released by the Autoconf Macro Archive. When you
#   make and distribute a modified version of the Autoconf Macro, you
#   may extend this special exception to the GPL to apply to your
#   modified version as well.

AC_DEFUN([DPS_XTRA_CLASSPATH],[
AC_CHECK_PROG(SED, sed)
DPS_JAVA_CHECK_CLASS([$2],[got="yes"],[got="no"])
cpxtra=""; saved_cp="${CLASSPATH}";
for jhome in `ls -dr /usr/share/java /usr/java/* /usr/local/java/* 2> /dev/null`; do
for jdir in lib jre/lib . ; do
for jfile in $3; do
if test "x$got" != "xyes" && test -f "$jhome/$jdir/$jfile"; then
CLASSPATH="${saved_cp}:$jhome/$jdir/$jfile"
DPS_JAVA_CHECK_CLASS([$2],[got="yes"; cpxtra="$jhome/$jdir/$jfile:"],[got="no"])
fi; done; done; done
if test "x${saved_cp}" != "x"; then
CLASSPATH="${saved_cp}"
else unset CLASSPATH; fi
if test "x$got" = "xyes"; then
$1="$cpxtra"
$4
true; else
$5
false; fi
])
