#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# $Id$
#
# PyLasso - Python bindings for Lasso library
#
# Copyright (C) 2004 Entr'ouvert
# http://lasso.entrouvert.org
#
# Author: Valéry Febvre <vfebvre@easter-eggs.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

__doc__ = """Python bindings for Lasso Library

PyLasso is a set of Python bindings for Lasso Library.
"""

classifiers = """\
Development Status :: 2 - Pre-Alpha
Intended Audience :: Developers
License :: OSI Approved :: GNU General Public License (GPL)
Operating System :: POSIX
Programming Language :: C
Programming Language :: Python
Topic :: Software Development :: Libraries :: Python Modules
"""

from distutils.core import setup, Extension
import sys, commands

# check python version
if not hasattr(sys, 'version_info') or sys.version_info < (2,2):
    raise SystemExit, "PyLasso requires Python version 2.2 or above."

# sanity check for any arguments
if len(sys.argv) == 1:
    msg = 'Choose an action :\n' \
          '   1. Build module\n' \
          '   2. Build documentation\n' \
          '   3. Install\n' \
          '   4. Clean\n' \
          '   5. Exit\n' \
          'Your choice : '
    reply = raw_input(msg)
    choice = None
    if reply:
        choice = reply[0]
    if choice == '1':
        sys.argv.append('build')
    elif choice == '2':
        print commands.getoutput('doxygen doc/doxygen.conf')
        sys.exit(0)
    elif choice == '3':
        sys.argv.append('install')
    elif choice == '4':
        sys.argv.append('clean')
        sys.argv.append('-a')
    elif choice == '5':
        sys.exit(0)

# the crypto engine name : openssl, gnutls or nss
xmlsec1_crypto = "openssl"
if 'build' in sys.argv:
    msg = '\nChoose a crypto engine :\n' \
          '   1. OpenSSL\n' \
          '   2. GnuTLS\n' \
          '   3. NSS\n' \
          'Your choice : '
    reply = raw_input(msg)
    choice = None
    if reply:
        choice = reply[0]
    if choice == '1':
        xmlsec1_crypto = "openssl"
    elif choice == '2':
        xmlsec1_crypto = "gnutls"
    elif choice == '3':
        xmlsec1_crypto = "nss"

define_macros = []
include_dirs  = []
library_dirs  = []
libraries     = []

def extract_cflags(cflags):
    global define_macros, include_dirs
    list = cflags.split(' ')
    for flag in list:
        if flag == '':
            continue
        flag = flag.replace("\\\"", "")
        if flag[:2] == "-I":
            if flag[2:] not in include_dirs:
                include_dirs.append(flag[2:])
        elif flag[:2] == "-D":
            t = tuple(flag[2:].split('='))
            if t not in define_macros:
                define_macros.append(t)
        else:
            print "Warning : cflag %s skipped" % flag

def extract_libs(libs):
    global library_dirs, libraries
    list = libs.split(' ')
    for flag in list:
        if flag == '':
            continue
        if flag[:2] == "-l":
            if flag[2:] not in libraries:
                libraries.append(flag[2:])
        elif flag[:2] == "-L":
            if flag[2:] not in library_dirs:
                library_dirs.append(flag[2:])
        else:
            print "Warning : linker flag %s skipped" % flag

# GObject
gobject_cflags = commands.getoutput('pkg-config gobject-2.0 --cflags')
if gobject_cflags[:2] not in ["-I", "-D"]:
    print "Error : cannot get GObject pre-processor and compiler flags"

gobject_libs = commands.getoutput('pkg-config gobject-2.0 --libs')
if gobject_libs[:2] not in ["-l", "-L"]:
    print "Error : cannot get GObject linker flags"

# LibXML2
libxml2_cflags = commands.getoutput('pkg-config libxml-2.0 --cflags')
if libxml2_cflags[:2] not in ["-I", "-D"]:
    libxml2_cflags = commands.getoutput('xml2-config --cflags')
if libxml2_cflags[:2] not in ["-I", "-D"]:
    print "Error : cannot get LibXML2 pre-processor and compiler flags"

libxml2_libs = commands.getoutput('pkg-config libxml-2.0 --libs')
if libxml2_libs[:2] not in ["-l", "-L"]:
    libxml2_libs = commands.getoutput('xml2-config --libs')
if libxml2_libs[:2] not in ["-l", "-L"]:
    print "Error : cannot get LibXML2 linker flags"

# XMLSec1
cmd = 'pkg-config xmlsec1-%s --cflags' % xmlsec1_crypto
xmlsec1_cflags = commands.getoutput(cmd)
if xmlsec1_cflags[:2] not in ["-I", "-D"]:
    cmd = 'xmlsec1-config --cflags --crypto=%s' % xmlsec1_crypto
    xmlsec1_cflags = commands.getoutput(cmd)
if xmlsec1_cflags[:2] not in ["-I", "-D"]:
    print "Error : cannot get XMLSec1 pre-processor and compiler flags"

cmd = 'pkg-config xmlsec1-%s --libs' % xmlsec1_crypto
xmlsec1_libs = commands.getoutput(cmd)
if xmlsec1_libs[:2] not in ["-l", "-L"]:
    cmd = 'xmlsec1-config --libs --crypto=%s' % xmlsec1_crypto
    xmlsec1_libs = commands.getoutput(cmd)
if xmlsec1_libs[:2] not in ["-l", "-L"]:
    print "Error : cannot get XMLSec1 linker flags"

#print gobject_cflags
#print gobject_libs
#print libxml2_cflags
#print libxml2_libs
#print xmlsec1_cflags
#print xmlsec1_libs

extract_cflags(gobject_cflags)
extract_libs(gobject_libs)

extract_cflags(libxml2_cflags)
extract_libs(libxml2_libs)

extract_cflags(xmlsec1_cflags)
extract_libs(xmlsec1_libs)

# FIXME : cflags & libs for lasso
include_dirs.append('..')
library_dirs.append('../lasso/.libs')
#include_dirs.append('/usr/local/include')
#library_dirs.append('/usr/local/lib')
libraries.append('lasso')

em = Extension("lassomod",
               sources = ["py_lasso.c",
                          "xml/py_xml.c",
                          "xml/py_lib_authentication_statement.c",
                          "xml/py_lib_authn_request.c",
                          "xml/py_lib_federation_termination_notification.c",
                          "xml/py_lib_logout_request.c",
                          "xml/py_lib_logout_response.c",
                          "xml/py_lib_name_identifier_mapping_request.c",
                          "xml/py_lib_name_identifier_mapping_response.c",
                          "xml/py_lib_register_name_identifier_request.c",
                          "xml/py_saml_assertion.c",
                          "xml/py_saml_authentication_statement.c",
                          "xml/py_saml_name_identifier.c",
                          "xml/py_samlp_response.c",
			  "protocols/py_authn_request.c",
			  "protocols/py_authn_response.c",
                          "protocols/py_federation_termination_notification.c",
			  "protocols/py_logout_request.c",
                          "protocols/py_logout_response.c",
                          "protocols/py_name_identifier_mapping_request.c",
                          "protocols/py_name_identifier_mapping_response.c",
                          "protocols/py_register_name_identifier_request.c",
                          "protocols/py_register_name_identifier_response.c",
                          "protocols/elements/py_assertion.c",
                          "protocols/elements/py_authentication_statement.c",
                          "environs/py_federation_termination.c",
                          "environs/py_login.c",
                          "environs/py_logout.c",
                          "environs/py_register_name_identifier.c",
                          "environs/py_server.c",
                          "environs/py_user.c",
                          "lassomod.c",
                          "utils.c", "wrap_objs.c"],
               define_macros = define_macros,
               include_dirs  = include_dirs,
               library_dirs  = library_dirs,
               libraries     = libraries
               )

doclines = __doc__.split("\n")

setup(name = "pylasso",
      version = "0.0.1",
      description = doclines[0],
      long_description = "\n" . join(doclines[2:]),
      author = "Valery Febvre",
      author_email = "vfebvre@easter-eggs.com",
      license = "GNU GPL",
      platforms = ["any"],
      url = "http://lasso.entrouvert.org",
      ext_modules = [em],
      py_modules = ["lasso", "lasso_strings"]
)
