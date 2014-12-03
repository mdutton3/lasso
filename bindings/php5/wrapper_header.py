# Lasso - A free implementation of the Liberty Alliance specifications.
#
# Copyright (C) 2004-2007 Entr'ouvert
# http://lasso.entrouvert.org
#
# Authors: See AUTHORS file in top-level directory.
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
# along with this program; if not, see <http://www.gnu.org/licenses/>.
import six

class WrapperHeader:
    def __init__(self, binding_data, fd, functions_list):
        self.binding_data = binding_data
        self.fd = fd
        self.functions_list = functions_list

    def generate(self):
        self.generate_header()
        self.generate_functions_list()
        self.generate_footer()

    def generate_header(self):
        # FIXME: Get the current version and name
        six.print_('''\
/* this file has been generated automatically; do not edit */

#include "../../config.h"

#ifndef PHP_LASSO_H
#define PHP_LASSO_H 1

#define PHP_LASSO_EXTNAME "lasso"
#define PHP_LASSO_VERSION VERSION

#define PHP_LASSO_SERVER_RES_NAME "Lasso Server"

PHP_MINIT_FUNCTION(lasso);
PHP_MSHUTDOWN_FUNCTION(lasso);
''', file=self.fd)

    def generate_functions_list(self):
        for m in self.functions_list:
            six.print_('PHP_FUNCTION(%s);' % m, file=self.fd)
        six.print_('', file=self.fd)

    def generate_footer(self):
        six.print_('''\
extern zend_module_entry lasso_module_entry;
#define phpext_lasso_ptr &lasso_module_entry

#endif
''', file=self.fd)

