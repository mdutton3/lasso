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
    Init Lasso Library.
    """
    return lassomod.init()

def shutdown():
    """
    Shutdown Lasso Library.
    """
    return lassomod.shutdown()

################################################################################
# xml : low level classes
################################################################################
# Export types
NodeExportTypeXml    = 1
NodeExportTypeBase64 = 2
NodeExportTypeQuery  = 3
NodeExportTypeSoap   = 4

class Node:
    """\brief The base class of the Lasso hierarchy.

    Node is the base class for all Lasso classes.
    """

    def __init__(self, _obj=None):
        """
        The constructor
        """
        if _obj != None:
            self._o = _obj
            return
        
    def destroy(self):
        """
        Destroys the node.
        """
        lassomod.node_destroy(self)

    def dump(self, encoding="utf8", format=0):
        """
        Dumps the node. All datas in object are dumped in an XML format.

        \param encoding the name of the encoding to use or None.
        \param format is formatting allowed?
        \return an XML dump of the node
        """
        return lassomod.node_dump(self, encoding, format)

    def export(self):
        """
        Exports the node.

        \return an XML dump of the node (UTF-8 encoded)
        """
        return lassomod.node_export(self)

    def export_to_base64(self):
        """
        Like export() method except that result is Base64 encoded.

        \return a Base64 encoded export of the node
        """
        return lassomod.node_export_to_base64(self)

    def export_to_query(self, sign_method=0, private_key_file=None):
        """
        URL-encodes and signes the node.
        If private_key_file is None, query won't be signed.

        \param sign_method the Signature transform method
        \param private_key_file a private key
        \return a query
        """
        return lassomod.node_export_to_query(self, sign_method, private_key_file)

    def export_to_soap(self):
        """
        Like export() method except that result is SOAP enveloped.

        \return a SOAP enveloped export of the node
        """
        return lassomod.node_export_to_soap(self)

    def get_attr_value(self, name):
        """
        Gets the value of an attribute associated to node.
        
        \param name an attribut name
        \return the attribut value or None if not found.
        """
        return lassomod.node_get_attr_value(self, name)

    def get_child(self, name, href=None):
        """
        Gets child of node having given \a name and namespace \a href.

        \param name the child name
        \param href the namespace
        \return a child node
        """
        obj = lassomod.node_get_child(self, name, href)
        if obj:
            return Node(_obj=obj)
        return None

    def get_content(self):
        """
        Read the value of node, this can be either the text carried directly by
        this node if it's a TEXT node or the aggregate string of the values carried
        by this node child's (TEXT and ENTITY_REF). Entity references are
        substituted.

        \return a string or None if no content is available.
        """
        return lassomod.node_get_content(self)

    def verify_signature(self, certificate_file):
        """
        Verifys the node signature.

        \param certificate_file a certificate
        \return 1 if signature is valid, 0 if invalid. -1 if an error occurs.
        """
        return lassomod.node_verify_signature(self, certificate_file)


class SamlAssertion(Node):
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj=None):
        """
        The constructor
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.saml_assertion_new()
        if _obj is None: raise Error('lasso_saml_assertion_new() failed')
        Node.__init__(self, _obj=_obj)

    def add_authenticationStatement(self, authenticationStatement):
        """
        bla bla
        """
        lassomod.saml_assertion_add_authenticationStatement(self,
                                                            authenticationStatement)

    def set_signature(self, sign_method, private_key_file, certificate_file):
        lassomod.saml_assertion_set_signature(self, sign_method,
                                              private_key_file, certificate_file)


class SamlAuthenticationStatement(Node):
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj=None):
        """
        The constructor
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.saml_authentication_statement_new()
        if _obj is None: raise Error('lasso_saml_authentication_statement_new() failed')
        Node.__init__(self, _obj=_obj)


class SamlNameIdentifier(Node):
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj=None):
        """
        The constructor
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.saml_name_identifier_new()
        if _obj is None: raise Error('lasso_saml_name_identifier_new() failed')
        Node.__init__(self, _obj=_obj)

    def set_format(self, format):
        lassomod.saml_name_identifier_set_format(self, format)
    
    def set_nameQualifier(self, nameQualifier):
        lassomod.saml_name_identifier_set_nameQualifier(self, nameQualifier)


class SamlpResponse(Node):
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj=None):
        """
        The constructor
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.samlp_response_new()
        if _obj is None: raise Error('lasso_samlp_response_new() failed')
        Node.__init__(self, _obj=_obj)

    def add_assertion(self, assertion):
        lassomod.samlp_response_add_assertion(self, assertion)


class LibAuthenticationStatement(SamlAuthenticationStatement):
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj=None):
        """
        The constructor
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
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj=None):
        """
        The constructor
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
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj=None):
        """
        The constructor
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
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj=None):
        """
        The constructor
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
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj = None):
        if _obj!=None:
            self._o = _obj
            return

        _obj = lassomod.lib_logout_response_new()
        if _obj is None: raise Error('lasso_lib_logout_response_new() failed')
        Node.__init__(self, _obj = _obj)
        

class LibNameIdentifierMappingRequest(Node):
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj=None):
        """
        The constructor
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
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj = None):
        """
        The constructor
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.lib_name_identifier_mapping_response_new()
        if _obj is None:
            raise Error('lasso_lib_name_identifier_mapping_response_new() failed')
        Node.__init__(self, _obj=_obj)


class LibRegisterNameIdentifierRequest(Node):
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj=None):
        """
        The constructor
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.lib_register_name_identifier_request_new()
        if _obj is None:
            raise Error('lasso_lib_register_name_identifier_request_new() failed')
        Node.__init__(self, _obj=_obj)


class LibRegisterNameIdentifierResponse(Node):
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj = None):
        """
        The constructor
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.lib_register_name_identifier_response_new()
        if _obj is None:
            raise Error('lasso_lib_register_name_identifier_response_new() failed')
        Node.__init__(self, _obj=_obj)

################################################################################
# protocols : middle level classes
################################################################################

def authn_request_get_protocolProfile(query):
    return lassomod.authn_request_get_protocolProfile(query)
class AuthnRequest(LibAuthnRequest):
    """\brief Blabla

    Bla bla
    """
    def __init__(self, providerID, _obj=None):
        """
        The constructor
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


class AuthnResponse(SamlpResponse):
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj):
        """
        The constructor
        """
        self._o = _obj
        SamlpResponse.__init__(self, _obj=_obj)

    def new_from_export(cls, buffer, type=0):
        obj = lassomod.authn_response_new_from_export(buffer, type)
        return AuthnResponse(obj)
    new_from_export = classmethod(new_from_export)


class FederationTerminationNotification(LibFederationTerminationNotification):
    """\brief Blabla

    Bla bla
    """
    def __init__(self, obj):
        """
        The constructor
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
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj):
        """
        The constructor
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
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj):
        """
        The constructor
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
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj):
        """
        The constructor
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
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj):
        """
        The constructor
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


class RegisterNameIdentifierRequest(LibRegisterNameIdentifierRequest):
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj):
        """
        The constructor
        """
        self._o = _obj
        LibRegisterNameIdentifierRequest.__init__(self, _obj = self._o)

    def new(cls, providerID,
            idpNameIdentifier, idpNameQualifier, idpFormat,
            spNameIdentifier, spNameQualifier, spFormat,
            oldNameIdentifier, oldNameQualifier, oldFormat):
        obj = lassomod.register_name_identifier_request_new(providerID,
                                                            idpNameIdentifier, idpNameQualifier, idpFormat,
                                                            spNameIdentifier, spNameQualifier, spFormat,
                                                            oldNameIdentifier, oldNameQualifier, oldFormat)
        return RegisterNameIdentifierRequest(obj)
    new = classmethod(new)

    def new_from_soap(cls, envelope):
        obj = lassomod.register_name_identifier_request_new_from_soap(envelope)
        return RegisterNameIdentifierRequest(obj)
    new_from_soap = classmethod(new_from_soap)

    def new_from_query(cls, query):
        obj = lassomod.register_name_identifier_request_new_from_query(query)
        return RegisterNameIdentifierRequest(obj)
    new_from_query = classmethod(new_from_query)

    def rename_attributes_for_encoded_query(self):
        lassomod.register_name_identifier_request_rename_attributes_for_query(self)


class RegisterNameIdentifierResponse(LibRegisterNameIdentifierResponse):
    """\brief Blabla

    Bla bla
    """
    def __init__(self, _obj):
        """
        The constructor
        """
        self._o = _obj
        LibRegisterNameIdentifierResponse.__init__(self, _obj = self._o)

    def new_from_request_soap(cls, envelope, providerID, status_code_value):
        obj = lassomod.register_name_identifier_response_new_from_request_soap(envelope, providerID, status_code_value)
        return RegisterNameIdentifierResponse(obj)
    new_from_request_soap = classmethod(new_from_request_soap)

    def new_from_soap(cls, envelope):
        obj = lassomod.register_name_identifier_response_new_from_soap(envelope)
        return RegisterNameIdentifierResponse(obj)
    new_from_soap = classmethod(new_from_soap)

    def new_from_dump(cls, dump):
        obj = lassomod.register_name_identifier_response_new_from_dump(dump)
        return RegisterNameIdentifierResponse(obj)
    new_from_dump = classmethod(new_from_dump)

    def new_from_request_query(cls, query, providerID, status_code_value):
        obj = lassomod.register_name_identifier_response_new_from_request_query(query, providerID, status_code_value)
        return RegisterNameIdentifierResponse(obj);
    new_from_request_query = classmethod(new_from_request_query)

    def new_from_query(cls, query):
        obj = lassomod.register_name_identifier_response_new_from_query(query)
        return RegisterNameIdentifierResponse(obj);
    new_from_query = classmethod(new_from_query)

################################################################################
# elements
################################################################################

class Assertion(SamlAssertion):
    """\brief Blabla

    Bla bla
    """
    def __init__(self, issuer, requestID, _obj=None):
        """
        The constructor
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = lassomod.assertion_new(issuer, requestID)
        if _obj is None: raise Error('lasso_assertion_new() failed')
        SamlAssertion.__init__(self, _obj=_obj)


class AuthenticationStatement(Node):
    """\brief Blabla

    Bla bla
    """
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
        The constructor
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

################################################################################
# environs : high level classes
################################################################################
SignatureMethodRsaSha1 = 1
SignatureMethodDsaSha1 = 2

HttpMethodGet      = 1
HttpMethodPost     = 2
HttpMethodRedirect = 3
HttpMethodSoap     = 4

MessageTypeNone          = 0
MessageTypeAuthnRequest  = 1
MessageTypeAuthnResponse = 2
MessageTypeRequest       = 3
MessageTypeResponse      = 4
MessageTypeArtifact      = 5

class Server:
    """\brief Short desc

    Long desc
    """
    def __init__(self, _obj):
        """
        The constructor
        """
        self._o = _obj

    def new(cls, metadata, public_key, private_key, certificate, signature_method):
        obj = lassomod.server_new(metadata, public_key, private_key,
                                  certificate, signature_method)
        return Server(obj)
    new = classmethod(new)

    def add_provider(self, metadata, public_key=None, certificate=None):
        lassomod.server_add_provider(self, metadata,
                                     public_key, certificate)


class Login:
    """\brief Short desc

    Long desc
    """

    def __init__(self, _obj):
	"""
	The constructor
	"""
	self._o = _obj
        
    def __isprivate(self, name):
        return name == '_o'

    def __getattr__(self, name):
        if self.__isprivate(name):
            return self.__dict__[name]
        if name[:2] == "__" and name[-2:] == "__" and name != "__members__":
            raise AttributeError, name
        ret = lassomod.login_getattr(self, name)
        if ret is None:
            raise AttributeError, name
        if name == "request":
            if lassomod.login_getattr(self, "request_type") == MessageTypeAuthnRequest:
                ret = AuthnRequest(None, _obj=ret)
            # TODO
        if name == "response":
            ret = Node(_obj=ret)
        return ret

    def new(cls, server, user=None):
	obj = lassomod.login_new(server, user)
	return Login(obj)
    new = classmethod(new)

    def new_from_dump(cls, server, user, dump):
	obj = lassomod.login_new_from_dump(server, user, dump)
	return Login(obj)
    new_from_dump = classmethod(new_from_dump)

    def build_artifact_msg(self, authentication_result, authenticationMethod,
                           reauthenticateOnOrAfter, method):
        return lassomod.login_build_artifact_msg(self, authentication_result,
                                                 authenticationMethod,
                                                 reauthenticateOnOrAfter,
                                                 method)

    def build_authn_request_msg(self):
        return lassomod.login_build_authn_request_msg(self)

    def build_authn_response_msg(self, authentication_result, authenticationMethod,
                                 reauthenticateOnOrAfter):
        return lassomod.login_build_authn_response_msg(self, authentication_result,
                                                       authenticationMethod,
                                                       reauthenticateOnOrAfter)

    def build_request_msg(self):
        return lassomod.login_build_request_msg(self)

    def dump(self):
        return lassomod.login_dump(self)

    def handle_authn_response_msg(self, authn_response_msg):
        return lassomod.login_handle_authn_response_msg(self, authn_response_msg)

    def handle_request_msg(self, request_msg):
        return lassomod.login_handle_request_msg(self, request_msg)

    def init_authn_request(self, remote_providerID):
        return lassomod.login_init_authn_request(self, remote_providerID)

    def init_from_authn_request_msg(self, authn_request_msg, authn_request_method):
        return lassomod.login_init_from_authn_request_msg(self, authn_request_msg,
                                                          authn_request_method)

    def init_request(self, response_msg, response_method, remote_providerID):
        return lassomod.login_init_request(self, response_msg,
                                           response_method, remote_providerID)

    def must_authenticate(self):
        return lassomod.login_must_authenticate(self)


class Logout:
    """\brief Short desc

    Long desc
    """

    def __init__(self, _obj):
	"""
	The constructor
	"""
	self._o = _obj

    def new(cls, server, user=None):
	obj = lassomod.logout_new(server, user)
	return Logout(obj)
    new = classmethod(new)

    def build_request_msg(self):
	return lassomod.logout_build_request_msg(self)

    def build_response_msg(self):
	return lassomod.logout_build_response_msg(self)

    def init_request(self, remote_providerID):
	return lassomod.logout_init_request(self, remote_providerID);

    def handle_request(self, request_msg, request_method):
	return lassomod.logout_handle_request(self, request_msg, request_method);

    def handle_response(self, response_msg, response_method):
	return lassomod.logout_handle_response(self, response_msg, response_method);
