#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# $Id$
#
# PyLasso - Python bindings for Lasso Library
#
# Copyright (C) 2003-2004 Easter-eggs, Valery Febvre
# http://lasso.labs.libre-entreprise.org
#
# Author: Valery Febvre <vfebvre@easter-eggs.com>
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

__docformat__ = "plaintext en"

import lassomod
from lasso_strings import *

class Error(Exception):
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return repr(self.msg)

def init():
    """
    """
    return lassomod.init()

def shutdown():
    """
    """
    return lassomod.shutdown()

class AuthnRequest:
    def __init__(self, providerID, nameIDPolicy, forceAuthn, isPassive,
                 protocolProfile, assertionConsumerServiceID, authnContextClassRefs,
                 authnContextStatementRefs, authnContextComparison, relayState,
                 proxyCount, idpList, consent, _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = lassomod.authn_request_build(providerID,
                                               nameIDPolicy,
                                               forceAuthn,
                                               isPassive,
                                               protocolProfile,
                                               assertionConsumerServiceID,
                                               authnContextClassRefs,
                                               authnContextStatementRefs,
                                               authnContextComparison,
                                               relayState,
                                               proxyCount,
                                               idpList,
                                               consent)
        if self._o is None: raise Error('lasso_authn_request_build() failed')
    def __isprivate(self, name):
        return name == '_o'
    def __getattr__(self, name):
        if self.__isprivate(name):
            return self.__dict__[name]
        if name[:2] == "__" and name[-2:] == "__" and name != "__members__":
            raise AttributeError, name
        ret = lassomod.authn_request_getattr(self, name)
        if ret is None:
            raise AttributeError, name
        if name == "request":
            ret = Node(_obj=ret)
        return ret

class Node:
    def __init__(self, _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        #self._o = lassomod.(size)
        if self._o is None: raise Error('lasso_node_new() failed')
    def dump(self, encoding, format):
        lassomod.node_dump(self, encoding, format)
    def destroy(self):
        lassomod.node_unref(self)
