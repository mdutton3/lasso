#! /usr/bin/env python
# -*- coding: UTF-8 -*-


# Python unit tests for Lasso library
# By: Frederic Peters <fpeters@entrouvert.com>
#     Emmanuel Raviart <eraviart@entrouvert.com>
#
# Copyright (C) 2004 Entr'ouvert
# http://lasso.entrouvert.org
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


import unittest
import sys

if not '..' in sys.path:
    sys.path.insert(0, '..')
if not '../.libs' in sys.path:
    sys.path.insert(0, '../.libs')

import lasso


class ErrorCheckingTestCase(unittest.TestCase):
    def test01(self):
        lasso.Login.new(None).msg_url

    def test02(self):
        lasso.Logout.new(None, lasso.providerTypeSp).msg_url

suite1 = unittest.makeSuite(ErrorCheckingTestCase, 'test')

allTests = unittest.TestSuite((suite1,))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity=2).run(allTests).wasSuccessful())

