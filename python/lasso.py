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

################################################################################
# xml : low level classes
################################################################################

class Node:
    def __init__(self, _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
##         #self._o = lassomod.(size)
##         if self._o is None: raise Error('lasso_node_new() failed')

    def dump(self, encoding="utf8", format=1):
        return lassomod.node_dump(self, encoding, format)

    def destroy(self):
        lassomod.node_unref(self)

    def get_attr_value(self, name):
        return lassomod.node_get_attr_value(self, name)

    def get_child(self, name):
        obj = lassomod.node_get_child(self, name)
        if obj:
            return Node(_obj=obj)
        return None

    def get_content(self):
        return lassomod.node_get_content(self)

    def url_encode(self, sign_method, private_key_file):
        return lassomod.node_url_encode(self, sign_method, private_key_file)

    def soap_envelop(self):
        return lassomod.node_soap_envelop(self)

    def verify_signature(self, certificate_file):
        return lassomod.node_verify_signature(self, certificate_file)


class SamlAssertion(Node):
    def __init__(self, _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.saml_assertion_new()
        if _obj is None: raise Error('lasso_saml_assertion_new() failed')
        Node.__init__(self, _obj=_obj)

    def add_authenticationStatement(self, authenticationStatement):
        lassomod.saml_assertion_add_authenticationStatement(self,
                                                            authenticationStatement)


class SamlAuthenticationStatement(Node):
    def __init__(self, _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.saml_authentication_statement_new()
        if _obj is None: raise Error('lasso_saml_authentication_statement_new() failed')
        Node.__init__(self, _obj=_obj)


class LibAuthenticationStatement(SamlAuthenticationStatement):
    def __init__(self, _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.lib_authentication_statement_new()
        if _obj is None: raise Error('lasso_saml_authentication_statement_new() failed')
        SamlAuthenticationStatement.__init__(self, _obj=_obj)
    def set_sessionIndex(self, sessionIndex):
        lassomod.lib_authentication_statement_set_sessionIndex(self, sessionIndex)


class LibAuthnRequest(Node):
    def __init__(self, _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.lib_authn_request_new()
        if _obj is None: raise Error('lasso_lib_authn_request_new() failed')
        Node.__init__(self, _obj=_obj)
        
    def set_forceAuthn(self, forceAuthn):
        lassomod.lib_authn_request_set_forceAuthn(self, forceAuthn)

    def set_isPassive(self, isPassive):
        lassomod.lib_authn_request_set_isPassive(self, isPassive)

    def set_nameIDPolicy(self, nameIDPolicy):
        lassomod.lib_authn_request_set_nameIDPolicy(self, nameIDPolicy)

    def set_protocolProfile(self, protocolProfile):
        lassomod.lib_authn_request_set_protocolProfile(self, protocolProfile)

    def set_relayState(self, relayState):
        lassomod.lib_authn_request_set_relayState(self, relayState)


class LibFederationTerminationNotification(Node):
    def __init__(self, _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.lib_federation_termination_notification_new()
        if _obj is None:
            raise Error('lasso_lib_federation_termination_notification_new() failed')
        Node.__init__(self, _obj=_obj)

    def set_consent(self, consent):
        lassomod.lib_federation_termination_notification_set_consent(self, consent)


class LibLogoutRequest(Node):
    def __init__(self, _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.lib_logout_request_new()
        if _obj is None: raise Error('lasso_lib_logout_request_new() failed')
        Node.__init__(self, _obj=_obj)

    def set_consent(self, consent):
        lassomod.lib_logout_request_set_consent(self, consent)

    def set_nameIdentifier(self, nameIdentifier):
        lassomod.lib_logout_request_set_nameIdentifier(self, nameIdentifier)

    def set_providerID(self, providerID):
        lassomod.lib_logout_request_set_providerID(self, providerID)

    def set_relayState(self, relayState):
        lassomod.lib_logout_request_set_relayState(self, relayState)

    def set_sessionIndex(self, sessionIndex):
        lassomod.lib_logout_request_set_sessionIndex(self, sessionIndex)


class LibLogoutResponse(Node):
    def __init__(self, _obj = None):
        if _obj!=None:
            self._o = _obj
            return

        _obj = lassomod.lib_logout_response_new()
        if _obj is None: raise Error('lasso_lib_logout_response_new() failed')
        Node.__init__(self, _obj = _obj)
        

class LibNameIdentifierMappingRequest(Node):
    def __init__(self, _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.lib_name_identifier_mapping_request_new()
        if _obj is None:
            raise Error('lasso_lib_name_identifier_mapping_request_new() failed')
        Node.__init__(self, _obj=_obj)

    def set_consent(self, consent):
        lassomod.lib_name_identifier_mapping_request_set_consent(self, consent)

class LibNameIdentifierMappingResponse(Node):
    def __init__(self, _obj = None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.lib_name_identifier_mapping_response_new()
        if _obj is None:
            raise Error('lasso_lib_name_identifier_mapping_response_new() failed')
        Node.__init__(self, _obj=_obj)


class SamlNameIdentifier(Node):
    def __init__(self, _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.saml_name_identifier_new()
        if _obj is None: raise Error('lasso_saml_authentication_statement_new() failed')
        Node.__init__(self, _obj=_obj)

    def set_format(self, format):
        lassomod.saml_name_identifier_set_format(self, format)
    
    def set_nameQualifier(self, nameQualifier):
        lassomod.saml_name_identifier_set_nameQualifier(self, nameQualifier)

################################################################################
# protocols : high level classes
################################################################################

def authn_request_get_protocolProfile(query):
    return lassomod.authn_request_get_protocolProfile(query)
class AuthnRequest(LibAuthnRequest):
    def __init__(self, providerID, _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.authn_request_new(providerID)
        if _obj is None: raise Error('lasso_authn_request_new() failed')
        LibAuthnRequest.__init__(self, _obj=_obj)
    
    def set_requestAuthnContext(self, authnContextClassRefs=None,
                                authnContextStatementRefs=None,
                                authnContextComparison=None):
        lassomod.authn_request_set_requestAuthnContext(self,
                                                       authnContextClassRefs,
                                                       authnContextStatementRefs,
                                                       authnContextComparison)

    def set_scoping(self, proxyCount):
        lassomod.authn_request_set_scoping(self, proxyCount)


class AuthnResponse(Node):
    def __init__(self, _obj):
        """
        """
        self._o = _obj
        Node.__init__(self, _obj=_obj)

    def new_from_dump(cls, buffer):
        obj = lassomod.authn_response_new_from_dump(buffer)
        return AuthnResponse(obj)
    new_from_dump = classmethod(new_from_dump)

    def new_from_request_query(cls, query, providerID):
        obj = lassomod.authn_response_new_from_request_query(query, providerID)
        return AuthnResponse(obj)
    new_from_request_query = classmethod(new_from_request_query)

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
        if name == "request":
            ret = AuthnRequest(None, _obj=ret)
        return ret

    def add_assertion(self, assertion, private_key_file, certificate_file):
        lassomod.authn_response_add_assertion(self, assertion,
                                              private_key_file,
                                              certificate_file)

    def must_authenticate(self, is_authenticated):
        return lassomod.authn_response_must_authenticate(self,
                                                         is_authenticated)

    def process_authentication_result(self, authentication_result):
        lassomod.authn_response_process_authentication_result(self,
                                                              authentication_result)

    def verify_signature(self, public_key_file, private_key_file):
        return lassomod.authn_response_verify_signature(self, public_key_file,
                                                        private_key_file)


class FederationTerminationNotification(LibFederationTerminationNotification):
    def __init__(self, obj):
        """
        """
        self._o = obj
        LibFederationTerminationNotification.__init__(self, _obj=self._o)

    def new(cls, providerID, nameIdentifier, nameQualifier, format):
        obj = lassomod.federation_termination_notification_new(providerID, nameIdentifier, nameQualifier, format)
        return FederationTerminationNotification(obj)
    new = classmethod(new)

    def new_from_soap(cls, envelope):
        obj = lassomod.federation_termination_notification_new_from_soap(envelope)
        return FederationTerminationNotification(obj)
    new_from_soap = classmethod(new_from_soap)

    def new_from_query(cls, query):
        obj = lassomod.federation_termination_notification_new_from_query(query)
        return FederationTerminationNotification(obj)
    new_from_query = classmethod(new_from_query)

class LogoutRequest(LibLogoutRequest):
    def __init__(self, _obj):
        """
        """
        self._o = _obj
        LibLogoutRequest.__init__(self, _obj = self._o)
        
    def new(cls, providerID, nameIdentifier, nameQualifier, format):
        obj = lassomod.logout_request_new(providerID, nameIdentifier, nameQualifier, format)
        return LogoutRequest(obj)
    new = classmethod(new)

    def new_from_soap(cls, envelope):
        obj = lassomod.logout_request_new_from_soap(envelope)
        return LogoutRequest(obj)
    new_from_soap = classmethod(new_from_soap)

    def new_from_query(cls, query):
        obj = lassomod.logout_request_new_from_query(query)
        return LogoutRequest(obj)
    new_from_query = classmethod(new_from_query)


class LogoutResponse(LibLogoutResponse):
    def __init__(self, _obj):
        """
        """
        self._o = _obj
        LibLogoutResponse.__init__(self, _obj = self._o)

    def new_from_request_soap(cls, envelope, providerID, status_code_value):
        obj = lassomod.logout_response_new_from_request_soap(envelope, providerID, status_code_value)
        return LogoutResponse(obj)
    new_from_request_soap = classmethod(new_from_request_soap)

    def new_from_soap(cls, envelope):
        obj = lassomod.logout_response_new_from_soap(envelope)
        return LogoutResponse(obj)
    new_from_soap = classmethod(new_from_soap)

    def new_from_dump(cls, dump):
        obj = lassomod.logout_response_new_from_dump(dump)
        return LogoutResponse(obj)
    new_from_dump = classmethod(new_from_dump)

    def new_from_request_query(cls, query, providerID, status_code_value):
        obj = lassomod.logout_response_new_from_request_query(query, providerID, status_code_value)
        return LogoutResponse(obj);
    new_from_request_query = classmethod(new_from_request_query)

    def new_from_query(cls, query):
        obj = lassomod.logout_response_new_from_query(query)
        return LogoutResponse(obj);
    new_from_query = classmethod(new_from_query)


class NameIdentifierMappingRequest(LibNameIdentifierMappingRequest):
    def __init__(self, _obj):
        """
        """
        self._o = _obj
        LibNameIdentifierMappingRequest.__init__(self, _obj = self._o)

    def new(cls, providerID, nameIdentifier, nameQualifier, format):
        obj = lassomod.name_identifier_mapping_request_new(providerID, nameIdentifier, nameQualifier, format)
        return NameIdentifierMappingRequest(obj)
    new = classmethod(new)

    def new_from_soap(cls, envelope):
        obj = lassomod.name_identifier_mapping_request_new_from_soap(envelope)
        return NameIdentifierMappingRequest(obj)
    new_from_soap = classmethod(new_from_soap)

    def new_from_query(cls, query):
        obj = lassomod.name_identifier_mapping_request_new_from_query(query)
        return NameIdentifierMappingRequest(obj)
    new_from_query = classmethod(new_from_query)


class NameIdentifierMappingResponse(LibNameIdentifierMappingResponse):
    def __init__(self, _obj):
        """
        """
        self._o = _obj
        LibNameIdentifierMappingResponse.__init__(self, _obj = self._o)

    def new_from_request_soap(cls, envelope, providerID, status_code_value):
        obj = lassomod.name_identifier_mapping_response_new_from_request_soap(envelope, providerID, status_code_value)
        return NameIdentifierMappingResponse(obj)
    new_from_request_soap = classmethod(new_from_request_soap)

    def new_from_soap(cls, envelope):
        obj = lassomod.name_identifier_mapping_response_new_from_soap(envelope)
        return NameIdentifierMappingResponse(obj)
    new_from_soap = classmethod(new_from_soap)

    def new_from_dump(cls, dump):
        obj = lassomod.name_identifier_mapping_response_new_from_dump(dump)
        return NameIdentifierMappingResponse(obj)
    new_from_dump = classmethod(new_from_dump)

    def new_from_request_query(cls, query, providerID, status_code_value):
        obj = lassomod.name_identifier_mapping_response_new_from_request_query(query, providerID, status_code_value)
        return NameIdentifierMappingResponse(obj);
    new_from_request_query = classmethod(new_from_request_query)

    def new_from_query(cls, query):
        obj = lassomod.name_identifier_mapping_response_new_from_query(query)
        return NameIdentifierMappingResponse(obj);
    new_from_query = classmethod(new_from_query)


class RegisterNameIdentifierRequest(Node):
    def __init__(_obj):
        """
        """
        self._o = obj
        LibRegisterNameIdentifierRequest.__init__(self, _obj = self._o)

    def new(cls, providerID, nameIdentifier, nameQualifier, format):
        obj = lassomod.register_name_identifier_new(providerID, nameIdentifier, nameQualifier, format)
        return RegisterNameIdentifierRequest(obj)
    new = classmethod(new)

    def new_from_soap(cls, envelope):
        obj = lassomod.register_name_identifier_new_from_soap(envelope)
        return RegisterNameIdentifierRequest(obj)
    new_from_soap = classmethod(new_from_soap)

    def new_from_query(cls, query):
        obj = lassomod.register_name_identifier_new_from_query(query)
        return RegisterNameIdentifierRequest(obj)
    new_from_query = classmethod(new_from_query)

    def url_encode(self):
        pass

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
        _obj = lassomod.register_name_identifier_response_new(providerID,
                                                              statusCodeValue,
                                                              request)
        if _obj is None:
            raise Error('lasso_register_name_identifier_response_new() failed')
        Node.__init__(self, _obj=_obj)

################################################################################
# elements
################################################################################

class Assertion(SamlAssertion):
    def __init__(self, issuer, requestID, _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.assertion_new(issuer, requestID)
        if _obj is None: raise Error('lasso_assertion_new() failed')
        SamlAssertion.__init__(self, _obj=_obj)


class AuthenticationStatement(Node):
    def __init__(self,
                 authenticationMethod,
                 reauthenticateOnOrAfter,
                 nameIdentifier,
                 nameQualifier,
                 format,
                 idp_nameIdentifier,
                 idp_nameQualifier,
                 idp_format,
                 _obj=None):
        """
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.authentication_statement_new(authenticationMethod,
                                                     reauthenticateOnOrAfter,
                                                     nameIdentifier,
                                                     nameQualifier,
                                                     format,
                                                     idp_nameIdentifier,
                                                     idp_nameQualifier,
                                                     idp_format)
        if _obj is None:
            raise Error('lasso_authentication_statement_new() failed')
        Node.__init__(self, _obj=_obj)
