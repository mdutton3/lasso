# -*- coding: UTF-8 -*-


# Assertion functions.
# By: Frederic Peters <fpeters@entrouvert.com>
#     Emmanuel Raviart <eraviart@entrouvert.com>
#
# Copyright (C) 2004 Entr'ouvert
# http://www.entrouvert.org
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
#
# Original code taken from Python2.3 unittest module:
#
# Copyright (c) 1999, 2000, 2001 Steve Purcell
# This module is free software, and you may redistribute it and/or modify
# it under the same terms as Python itself, so long as this copyright message
# and disclaimer are retained in their original form.
#
# IN NO EVENT SHALL THE AUTHOR BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT,
# SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF
# THIS CODE, EVEN IF THE AUTHOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

# THE AUTHOR SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE.  THE CODE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS,
# AND THERE IS NO OBLIGATION WHATSOEVER TO PROVIDE MAINTENANCE,
# SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.


"""Assertion functions"""


import builtins


def fail(message = None):
    """Fail immediately, with the given message."""
    raise self.failureException, message


def failIf(expression, message = None):
    """Fail the test if the expression is true."""
    if expression:
        raise self.failureException, message


def failIfAlmostEqual(first, second, places = 7, message = None):
    """Fail if the two objects are equal as determined by their difference rounded to the given
    number of decimal places (default 7) and comparing to zero.

    Note that decimal places (from zero) is usually not the same as significant digits
    (measured from the most signficant digit).
    """
    if round(second - first, places) == 0:
        raise self.failureException, \
              (message or '%s == %s within %s places' % (`first`, `second`, `places`))


def failIfEqual(first, second, message = None):
    """Fail if the two objects are equal as determined by the '==' operator."""
    if first == second:
        raise self.failureException, (message or '%s == %s' % (`first`, `second`))


def failUnless(expression, message = None):
    """Fail the test unless the expression is true."""
    if not expression:
        raise self.failureException, message


def failUnlessAlmostEqual(first, second, places = 7, message = None):
    """Fail if the two objects are unequal as determined by their difference rounded to the given
    number of decimal places (default 7) and comparing to zero.

    Note that decimal places (from zero) is usually not the same as significant digits (measured
    from the most signficant digit).
    """
    if round(second - first, places) != 0:
        raise self.failureException, \
              (message or '%s != %s within %s places' % (`first`, `second`, `places` ))


def failUnlessEqual(first, second, message = None):
    """Fail if the two objects are unequal as determined by the '==' operator."""
    if not first == second:
        raise self.failureException, \
              (message or '%s != %s' % (`first`, `second`))


def failUnlessRaises(exceptionClass, callableObject, *arguments, **keywordArguments):
    """Fail unless an exception of class exceptionClass is thrown by callableObject when invoked
    with arguments arguments and keyword arguments keywordArguments. If a different type of
    exception is thrown, it will not be caught, and the test case will be deemed to have suffered
    an error, exactly as for an unexpected exception.
    """
    try:
        callableObject(*arguments, **keywordArguments)
    except exceptionClass:
        return
    else:
        if hasattr(exceptionClass, '__name__'):
            exceptionName = exceptionClass.__name__
        else:
            exceptionName = str(exceptionClass)
        raise self.failureException, exceptionName


allGlobals = globals()
for name in ('fail', 'failIf', 'failIfAlmostEqual', 'failIfEqual', 'failUnless',
             'failUnlessAlmostEqual', 'failUnlessRaises', 'failUnlessEqual'):
    builtins.set(name, allGlobals[name])
