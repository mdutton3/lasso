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

import os
from wrapper_source import WrapperSource
from wrapper_header import WrapperHeader
from php_code import PhpCode

class Binding:
    def __init__(self, binding_data):
        self.binding_data = binding_data

    def generate(self):
        fd = open('_lasso.c', 'w')
        wrapper_source = WrapperSource(self.binding_data, fd)
        wrapper_source.generate()
        fd.close()

        fd = open('php_lasso.h', 'w')
        WrapperHeader(self.binding_data, fd, wrapper_source.functions_list).generate()
        fd.close()

        fd = open('lasso.php', 'w')
        PhpCode(self.binding_data, fd).generate()
        fd.close()

