# -*- coding: UTF-8 -*-


# Built-in variables access functions
# By: Emmanuel Raviart <eraviart@entrouvert.com>
#
# Copyright (C) 2004 Entr'ouvert
# http://www.entrouvert.org
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


"""Built-in variables access functions

Allow the declaration of global variables accessible from everywhere
(in opposition to global variables which are only easily accessible inside
the module they are declared in).
"""


import __builtin__


def delete(name):
    del __builtin__.__dict__[name]


def get(name, default = None):
    return __builtin__.__dict__.get(name, default)


def set(name, value):
    __builtin__.__dict__[name] = value
