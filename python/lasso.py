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
    Shutdown Lasso Library
    """
    return lassomod.shutdown()

def assertion_build(response, issuer):
    return Node(_obj=lassomod.assertion_build(response, issuer))

def assertion_add_authenticationStatement(assertion, statement):
    return lassomod.assertion_add_authenticationStatement(assertion, statement)

def authentication_statement_build(authenticationMethod, sessionIndex,
                                   reauthenticateOnOrAfter,
                                   nameIdentifier, nameQualifier,
                                   format, idp_nameIdentifier,
                                   idp_nameQualifier, idp_format,
                                   confirmationMethod):
    return Node(_obj=lassomod.authentication_statement_build(
        authenticationMethod, sessionIndex,
        reauthenticateOnOrAfter,
        nameIdentifier, nameQualifier,
        format, idp_nameIdentifier,
        idp_nameQualifier, idp_format,
        confirmationMethod))


class Node:
    def __init__(self, _obj=None):
        """
        """
##         if _obj != None:
##             self._o = _obj
##             return
##         #self._o = lassomod.(size)
##         if self._o is None: raise Error('lasso_node_new() failed')

    def dump(self, encoding = "utf8", format = 1):
        return lassomod.node_dump(self, encoding, format)

    def destroy(self):
        lassomod.node_unref(self)

    def get_attr_value(self, name):
        return lassomod.node_get_attr_value(self, name)

    def get_child(self, name):
        return Node(_obj=lassomod.node_get_child(self, name))

    def url_encode(self, sign_method, private_key_file):
        return lassomod.node_url_encode(self, sign_method, private_key_file)

    def verify_signature(self, certificate_file):
        return lassomod.node_verify_signature(self, certificate_file)


class AuthnRequest:
    def __init__(self, providerID, nameIDPolicy, forceAuthn, isPassive,
                 protocolProfile, assertionConsumerServiceID,
                 authnContextClassRefs, authnContextStatementRefs,
                 authnContextComparison, relayState, proxyCount, idpList,
                 consent, _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = lassomod.authn_request_create(providerID,
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
        if self._o is None: raise Error('lasso_authn_request_create() failed')

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
        if name == "node":
            ret = Node(_obj=ret)
        return ret


class AuthnResponse:
    def __init__(self, query, verify_signature, public_key_file,
                 private_key_file, certificate_file, is_authenticated,
                 _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = lassomod.authn_response_create(query,
                                                 verify_signature,
                                                 public_key_file,
                                                 private_key_file,
                                                 certificate_file,
                                                 is_authenticated)
        if self._o is None: raise Error('lasso_authn_response_create() failed')

    def __isprivate(self, name):
        return name == '_o'

    def __getattr__(self, name):
        if self.__isprivate(name):
            return self.__dict__[name]
        if name[:2] == "__" and name[-2:] == "__" and name != "__members__":
            raise AttributeError, name
        ret = lassomod.authn_response_getattr(self, name)
        if ret is None:
            raise AttributeError, name
        if name == "node":
            ret = Node(_obj=ret)
        return ret

    def init(self, providerID, authentication_result):
        return lassomod.authn_response_init(self, providerID,
                                            authentication_result)
    def add_assertion(self, assertion):
        return lassomod.authn_response_add_assertion(self, assertion)


class Request:
    def __init__(self, assertionArtifact, _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = lassomod.request_create(assertionArtifact)
        if self._o is None: raise Error('lasso_request_create() failed')

    def __isprivate(self, name):
        return name == '_o'

    def __getattr__(self, name):
        if self.__isprivate(name):
            return self.__dict__[name]
        if name[:2] == "__" and name[-2:] == "__" and name != "__members__":
            raise AttributeError, name
        ret = lassomod.request_getattr(self, name)
        if ret is None:
            raise AttributeError, name
        if name == "node":
            ret = Node(_obj=ret)
        return ret


class Response:
    def __init__(self,
                 serialized_request,
                 verify_signature,
                 public_key_file, private_key_file, certificate_file,
                 _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = lassomod.response_create(serialized_request,
                                           verify_signature,
                                           public_key_file, private_key_file, certificate_file)
        if self._o is None: raise Error('lasso_response_create() failed')

    def __isprivate(self, name):
        return name == '_o'

    def __getattr__(self, name):
        if self.__isprivate(name):
            return self.__dict__[name]
        if name[:2] == "__" and name[-2:] == "__" and name != "__members__":
            raise AttributeError, name
        ret = lassomod.response_getattr(self, name)
        if ret is None:
            raise AttributeError, name
        if name == "node":
            ret = Node(_obj=ret)
        elif name == "request_node":
            ret = Node(_obj=ret)
        return ret

    def init(self, authentication_result):
        return lassomod.response_init(self, authentication_result)

    def add_assertion(self, assertion):
        return lassomod.response_add_assertion(self, assertion)

class LogoutRequest(Node):
    def __init__(self,
                 providerID,
		 nameIdentifier, nameQualifier, format,
                 sessionIndex = None, relayState = None, consent = None,
                 _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = lassomod.logout_request(providerID,
                                          nameIdentifier,
                                          nameQualifier,
                                          format)
        if self._o is None: raise Error('lasso_logout_request() failed')

        if sessionIndex:
            lassomod.logout_request_set_sessionIndex(self, sessionIndex)

        if relayState:
            lassomod.logout_request_set_relayState(self, relayState)

        if consent:
            lassomod.logout_request_set_consent(self, consent)

    def __isprivate(self, name):
        return name == '_o'

    def __getattr__(self, name):
        if self.__isprivate(name):
            return self.__dict__[name]
        if name[:2] == "__" and name[-2:] == "__" and name != "__members__":
            raise AttributeError, name
        ret = lassomod.logout_request_getattr(self, name)
        if ret is None:
            raise AttributeError, name
        if name == "node":
            ret = Node(_obj=ret)
        return ret


class LogoutResponse(Node):
    def __init__(self,
                 providerID,
                 statusCodeValue,
                 request,
                 _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = lassomod.logout_response(providerID,
                                           statusCodeValue,
                                           request)
        if self._o is None: raise Error('lasso_logout_response() failed')

    def __isprivate(self, name):
        return name == '_o'

    def __getattr__(self, name):
        if self.__isprivate(name):
            return self.__dict__[name]
        if name[:2] == "__" and name[-2:] == "__" and name != "__members__":
            raise AttributeError, name
        ret = lassomod.logout_response_getattr(self, name)
        if ret is None:
            raise AttributeError, name
        if name == "node":
            ret = Node(_obj=ret)
        return ret   


class RegisterNameIdentifierRequest(Node):
    def __init__(self,
                 providerID,
                 idpNameIdentifier, idpNameQualifier, idpFormat,
                 spNameIdentifier,  spNameQualifier,  spFormat,
                 oldNameIdentifier, oldNameQualifier, oldFormat,
                 relayState = None,
		 _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = lassomod.register_name_identifier_request(providerID,
                                                            idpNameIdentifier, idpNameQualifier, idpFormat,
                                                            spNameIdentifier,  spNameQualifier,  spFormat,
                                                            oldNameIdentifier, oldNameQualifier, oldFormat)
        if self._o is None: raise Error('lasso_register_name_identifier_request() failed')

        if relayState:
            lassomod.register_name_identifier_request_set_relayState(self, relayState)

    def __isprivate(self, name):
        return name == '_o'

    def __getattr__(self, name):
        if self.__isprivate(name):
            return self.__dict__[name]
        if name[:2] == "__" and name[-2:] == "__" and name != "__members__":
            raise AttributeError, name
        ret = lassomod.register_name_identifier_request_getattr(self, name)
        if ret is None:
            raise AttributeError, name
        if name == "node":
            ret = Node(_obj=ret)
        return ret

    def changeAttributeNamesIdentifiers(self):
        lassomod.register_name_identifier_request_change_attribute_names_identifiers(self);

class RegisterNameIdentifierResponse(Node):
    def __init__(self,
                 providerID,
                 statusCodeValue,
                 request,
                 _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = lassomod.register_name_identifier_response(providerID,
                                           statusCodeValue,
                                           request)
        if self._o is None: raise Error('lasso_register_name_identifier_response() failed')

    def __isprivate(self, name):
        return name == '_o'

    def __getattr__(self, name):
        if self.__isprivate(name):
            return self.__dict__[name]
        if name[:2] == "__" and name[-2:] == "__" and name != "__members__":
            raise AttributeError, name
        ret = lassomod.register_name_identifier_response_getattr(self, name)
        if ret is None:
            raise AttributeError, name
        if name == "node":
            ret = Node(_obj=ret)
        return ret

class FederationTerminationNotification(Node):
    def __init__(self,
                 providerID,
                 nameIdentifier, nameQualifier, format,
                 consent = None,
		 _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = lassomod.federation_termination_notification(providerID,
                                                               nameIdentifier, nameQualifier, format)
        if self._o is None: raise Error('lasso_federation_termination_notification() failed')

        if consent:
            lassomod.federation_termination_notification_set_consent(self, consent)

    def __isprivate(self, name):
        return name == '_o'

    def __getattr__(self, name):
        if self.__isprivate(name):
            return self.__dict__[name]
        if name[:2] == "__" and name[-2:] == "__" and name != "__members__":
            raise AttributeError, name
        ret = lassomod.federation_termination_notification_getattr(self, name)
        if ret is None:
            raise AttributeError, name
        if name == "node":
            ret = Node(_obj=ret)
        return ret


class NameIdentifierMappingRequest(Node):
    def __init__(self,
                 providerID,
                 nameIdentifier, nameQualifier, format,
                 consent = None,
		 _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = lassomod.name_identifier_mapping_request(providerID,
                                                           nameIdentifier, nameQualifier, format)
        if self._o is None: raise Error('lasso_name_identifier_mapping_request() failed')

        if consent:
            lassomod.name_identifier_mapping_request_set_consent(self, consent)

    def __isprivate(self, name):
        return name == '_o'

    def __getattr__(self, name):
        if self.__isprivate(name):
            return self.__dict__[name]
        if name[:2] == "__" and name[-2:] == "__" and name != "__members__":
            raise AttributeError, name
        ret = lassomod.name_identifier_mapping_request_getattr(self, name)
        if ret is None:
            raise AttributeError, name
        if name == "node":
            ret = Node(_obj=ret)
        return ret

class NameIdentifierMappingResponse(Node):
    def __init__(self,
                 providerID,
                 statusCodeValue,
                 request,
                 _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = lassomod.name_identifier_mapping_response(providerID,
                                           statusCodeValue,
                                           request)
        if self._o is None: raise Error('lasso_name_identifier_mapping_response() failed')

    def __isprivate(self, name):
        return name == '_o'

    def __getattr__(self, name):
        if self.__isprivate(name):
            return self.__dict__[name]
        if name[:2] == "__" and name[-2:] == "__" and name != "__members__":
            raise AttributeError, name
        ret = lassomod.name_identifier_mapping_response_getattr(self, name)
        if ret is None:
            raise AttributeError, name
        if name == "node":
            ret = Node(_obj=ret)
        return ret
