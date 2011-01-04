#! /usr/bin/env python
# -*- coding: UTF-8 -*-
#
# $Id: idwsf2_tests.py 3254 2007-06-05 21:23:57Z dlaniel $
#
# Python unit tests for Lasso library
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


import os
import unittest
import sys
from StringIO import StringIO
import logging

logging.basicConfig()

if not '..' in sys.path:
    sys.path.insert(0, '..')
if not '../.libs' in sys.path:
    sys.path.insert(0, '../.libs')

import lasso

try:
    import lxml.etree as ET
except ImportError:
    try:
        import elementtree.ElementTree as ET
    except ImportError:
        import xml.etree.ElementTree as ET

try:
    dataDir
except NameError:
    dataDir = os.path.join(os.environ['TOP_SRCDIR'], 'tests', 'data')

idpSoapEndpoint = 'http://idp1/soapEndpoint'
spSoapEndpoint = 'http://sp1/soapEndpoint'
spInteractionUrl = 'http://sp1/askMeAQuestion'

class IdWsf2TestCase(unittest.TestCase):
    def getWspServer(self):
        wsp_metadata = os.path.join(dataDir, 'sp5-saml2/metadata.xml')
        wsp_private_key = os.path.join(dataDir, 'sp5-saml2/private-key.pem')
        idp_metadata = os.path.join(dataDir, 'idp5-saml2/metadata.xml')

        server = lasso.Server(wsp_metadata, wsp_private_key, None, None)
        server.role = lasso.PROVIDER_ROLE_SP
        server.addProvider(lasso.PROVIDER_ROLE_IDP, idp_metadata, None, None)
        server.setEncryptionPrivateKey(wsp_private_key);

        return server;

    def getWscServer(self):
        wsc_metadata = os.path.join(dataDir, 'sp6-saml2/metadata.xml')
        wsc_private_key = os.path.join(dataDir, 'sp6-saml2/private-key.pem')
        idp_metadata = os.path.join(dataDir, 'idp5-saml2/metadata.xml')

        server = lasso.Server(wsc_metadata, wsc_private_key, None, None)
        server.role = lasso.PROVIDER_ROLE_SP
        server.addProvider(lasso.PROVIDER_ROLE_IDP, idp_metadata, None, None)

        return server;

    def getIdpServer(self):
        if hasattr(self, 'idp_server_dump') and self.idp_server_dump is not None:
            server = lasso.Server.newFromDump(self.idp_server_dump)
            server.role = lasso.PROVIDER_ROLE_IDP
        else:
            idp_metadata = os.path.join(dataDir, 'idp5-saml2/metadata.xml')
            idp_private_key = os.path.join(dataDir, 'idp5-saml2/private-key.pem')
            wsp_metadata = os.path.join(dataDir, 'sp5-saml2/metadata.xml')
            wsc_metadata = os.path.join(dataDir, 'sp6-saml2/metadata.xml')

            server = lasso.Server(idp_metadata, idp_private_key, None, None)
            server.role = lasso.PROVIDER_ROLE_IDP
            server.addProvider(lasso.PROVIDER_ROLE_SP, wsp_metadata, None, None)
            server.getProvider(server.providerIds[0]).setEncryptionMode(lasso.ENCRYPTION_MODE_NAMEID);
            server.addProvider(lasso.PROVIDER_ROLE_SP, wsc_metadata, None, None)
            self.idp_server_dump = server.dump()

        return server

    def query(self, wsc, idp, idp_identity_dump, wsc_session_dump, uid, federations, services_map, service_associations, provider_ids = None, service_types = None, options = None, actions = None):
        session = lasso.Session.newFromDump(wsc_session_dump)
        assertion = session.getAssertion(idp.providerId)
        self.failUnless(assertion is not None)
        epr = assertion.idwsf2GetDiscoveryBootstrapEpr()
        self.failUnless(epr is not None)
        wsc_disco = lasso.IdWsf2Discovery(wsc)
        wsc_disco.setEpr(epr)
        wsc_disco.initQuery()
        wsc_disco.addRequestedService(service_types = service_types, provider_ids = provider_ids, options = options, actions = actions)
        wsc_disco.buildRequestMsg()
        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.setIdentityFromDump(idp_identity_dump)
        idp_disco.processRequestMsg(wsc_disco.msgBody)
        f = self.nid2tuple(idp_disco.getNameIdentifier())
        uid = federations[f]
        for id in service_associations[uid]:
            idp_disco.addServiceMetadata(services_map[id])
        idp_disco.validateRequest()
        idp_disco.buildResponseMsg()
        wsc_disco.processResponseMsg(idp_disco.msgBody)
        return wsc_disco.endpointReferences



    def metadataRegister(self, wsp, idp, session_dump, abstract = None, address = None, provider_id = None, service_types = None, services_map = None):
        session = lasso.Session.newFromDump(session_dump)
        assertion = session.getAssertion(idp.providerId)
        self.failUnless(assertion is not None)
        epr = assertion.idwsf2GetDiscoveryBootstrapEpr()
        self.failUnless(epr is not None)
        wsp_disco = lasso.IdWsf2Discovery(wsp)
        wsp_disco.setEpr(epr)
        abstract = 'Personal Profile service'
        self.failUnless(abstract is not None)
        self.failUnless(address is not None)
        self.failUnless(service_types is not None)
        self.failUnless(isinstance(services_map, dict))
        wsp_disco.initMetadataRegister()
        if not provider_id:
            provider_id = wsp.providerId
        wsp_disco.addSimpleServiceMetadata(
                service_types = service_types,
                abstract = abstract, provider_id = provider_id,
                address = address, 
                security_mechanisms = (lasso.SECURITY_MECH_BEARER,))
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processRequestMsg(wsp_disco.msgBody)
        idp_disco.checkSecurityMechanism()
        idp_disco.validateRequest()
        self.failUnlessEqual(len(idp_disco.metadatas), 1)
        # add metadatas to directory
        sender = idp_disco.getSoapEnvelopeRequest().sb2GetProviderId()
        self.failUnless(sender is not None)
        metadatas = services_map.get(sender, [])
        for metadata in idp_disco.metadatas:
            services_map[metadata.svcMDID] = metadata
            metadatas.append(metadata.svcMDID)
        services_map[sender] = metadatas
        idp_disco.buildResponseMsg()
        wsp_disco.processResponseMsg(idp_disco.msgBody)
        self.failUnlessEqual(len(wsp_disco.metadatas), 1)
        self.failUnlessEqual(wsp_disco.metadatas[0].svcMDID, wsp_disco.response.svcMDID[0])
        return wsp_disco.metadatas[0].svcMDID

    def nid2tuple(self, nid):
        return (nid.nameQualifier, nid.format, nid.sPNameQualifier, nid.content)

    def addAssociation(self, wsp, idp, session_dump, svcmdid, service_maps, federations, service_associations):
        self.failUnless(isinstance(service_associations, dict))
        self.failUnless(isinstance(service_maps, dict))
        # Get the bootstrap
        session = lasso.Session.newFromDump(session_dump)
        assertion = session.getAssertion(idp.providerId)
        self.failUnless(assertion is not None)
        epr = assertion.idwsf2GetDiscoveryBootstrapEpr()
        self.failUnless(epr is not None)
        wsp_disco = lasso.IdWsf2Discovery(wsp)
        wsp_disco.setEpr(epr)
        wsp_disco.initMetadataAssociationAdd()
        wsp_disco.svcmdids = (svcmdid,)
        wsp_disco.buildRequestMsg()
        # Handle request
        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processRequestMsg(wsp_disco.msgBody)
        idp_disco.checkSecurityMechanism()
        self.failUnlessEqual(idp_disco.svcmdids, (svcmdid,))
        sender = idp_disco.getSoapEnvelopeRequest().sb2GetProviderId()
        name_identifier = idp_disco.getNameIdentifier()
        f = self.nid2tuple(name_identifier)
        uid = federations[f]
        l = service_associations.get(uid, [])
        for id in idp_disco.svcmdids:
            # check it exists
            self.failUnless(service_maps.get(id) is not None)
            # create association
            if id not in l:
                l.append(id)
        service_associations[uid] = l
        idp_disco.validateRequest()
        idp_disco.buildResponseMsg()
        wsp_disco.processResponseMsg(idp_disco.msgBody)

    def login(self, sp, idp, user_id, federations, sp_identity_dump=None, sp_session_dump=None,
            idp_identity_dump=None, idp_session_dump=None):
        sp_login = lasso.Login(sp)
        idp_provider_id = 'http://idp5/metadata'
        sp_login.initAuthnRequest(idp_provider_id, lasso.HTTP_METHOD_REDIRECT)
        sp_login.request.nameIDPolicy.format = lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT
        sp_login.request.nameIDPolicy.allowCreate = True
        sp_login.buildAuthnRequestMsg()

        idp_login = lasso.Login(idp)
        query = sp_login.msgUrl.split('?')[1]
        if idp_identity_dump is not None:
            idp_login.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_login.setSessionFromDump(idp_session_dump)
        idp_login.processAuthnRequestMsg(query)
        idp_login.validateRequestMsg(True, True)
        idp_login.buildAssertion(lasso.SAML_AUTHENTICATION_METHOD_PASSWORD, None, None, None, None)
        if idp_login.assertion.subject.encryptedId:
            f = self.nid2tuple(idp_login.assertion.subject.encryptedId.originalData)
        else:
            f = self.nid2tuple(idp_login.assertion.subject.nameId)
        federations[f] = user_id
        l = federations.get(user_id, [])
        l.append(f)
        federations[user_id] = l
        idp_login.idwsf2AddDiscoveryBootstrapEpr(url = idpSoapEndpoint, abstract = 'Discovery Service', security_mechanisms = (lasso.SECURITY_MECH_BEARER,))
        idp_login.buildArtifactMsg(lasso.HTTP_METHOD_ARTIFACT_GET)
        artifact_message = idp_login.artifactMessage

        if idp_login.isIdentityDirty:
            idp_identity_dump = idp_login.identity.dump()
        if idp_login.isSessionDirty:
            idp_session_dump = idp_login.session.dump()

        sp_login = lasso.Login(sp)
        query = idp_login.msgUrl.split('?')[1]
        query = query.replace("%3D", "=")
        sp_login.initRequest(query, lasso.HTTP_METHOD_ARTIFACT_GET)
        sp_login.buildRequestMsg()

        idp_login = lasso.Login(idp)
        idp_login.processRequestMsg(sp_login.msgBody)
        idp_login.artifactMessage = artifact_message
        idp_login.buildResponseMsg(None)

        sp_login.processResponseMsg(idp_login.msgBody)
        sp_login.acceptSso()
        if sp_login.isIdentityDirty:
            sp_identity_dump = sp_login.identity.dump()
        if sp_login.isSessionDirty:
            sp_session_dump = sp_login.session.dump()

        return sp_identity_dump, sp_session_dump, idp_identity_dump, idp_session_dump, sp_login.idwsf2GetDiscoveryBootstrapEpr()


class MetadataTestCase(IdWsf2TestCase):
    def test01(self):
        """Test metadata registration on the IdP"""
        idp = self.getIdpServer()
        wsp = self.getWspServer()
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump, dst_epr = self.login(wsp, idp, 1, {})

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        wsp_disco.setEpr(dst_epr)

        abstract = 'Personal Profile service'
        wsp_disco.initMetadataRegister()
        self.failUnless(wsp_disco.request is not None)
        wsp_disco.addSimpleServiceMetadata(service_types = 
                (lasso.PP11_HREF,), abstract = abstract,
                provider_id = wsp.providerId, address = spSoapEndpoint,
                security_mechanisms = (lasso.SECURITY_MECH_BEARER,))
        self.failUnlessEqual(len(wsp_disco.metadatas), 1)
        metadata = wsp_disco.metadatas[0]
        self.failUnlessEqual(metadata.abstract, abstract)
        self.failUnlessEqual(metadata.providerId, wsp.providerId)
        self.failUnlessEqual(len(metadata.serviceContext), 1)
        self.failUnlessEqual(len(metadata.serviceContext[0].serviceType), 1)
        self.failUnlessEqual(metadata.serviceContext[0].serviceType[0],
                lasso.PP11_HREF)
        self.failUnlessEqual(len(metadata.serviceContext[0].endpointContext), 1)
        self.failUnlessEqual(
                len(metadata.serviceContext[0].endpointContext[0].address),
                1)
        self.failUnlessEqual(metadata.serviceContext[0].endpointContext[0].address[0],
                spSoapEndpoint)
        self.failUnlessEqual(
                len(metadata.serviceContext[0].endpointContext[0].securityMechId),
                1)
        self.failUnlessEqual(
                metadata.serviceContext[0].endpointContext[0].securityMechId[0],
                lasso.SECURITY_MECH_BEARER)
        self.failUnless(metadata.svcMDID is None)
        wsp_disco.buildRequestMsg()
        self.failUnlessEqual(wsp_disco.msgUrl, idpSoapEndpoint)
        self.failUnless(wsp_disco.msgBody is not None)

        idp_disco = lasso.IdWsf2Discovery(idp)
        self.failUnless(idp_disco is not None)
        idp_disco.processRequestMsg(wsp_disco.msgBody)
        self.failUnless(idp_disco.request is not None)
        self.failUnlessEqual(len(idp_disco.request.svcMD), 1)
        self.failUnless(idp_disco.request.svcMD[0].svcMDID is None)
        try:
            idp_disco.checkSecurityMechanism()
        except lasso.Error, e:
            self.fail(e)
        try:
            idp_disco.validateRequest()
        except lasso.Error, e:
            self.fail(e)
        self.failUnless(idp_disco.response is not None)
        self.failUnlessEqual(len(idp_disco.metadatas), 1)
        metadata = idp_disco.metadatas[0]
        self.failUnlessEqual(metadata.abstract, abstract)
        self.failUnlessEqual(metadata.providerId, wsp.providerId)
        self.failUnlessEqual(len(metadata.serviceContext), 1)
        self.failUnlessEqual(len(metadata.serviceContext[0].serviceType), 1)
        self.failUnlessEqual(metadata.serviceContext[0].serviceType[0],
                lasso.PP11_HREF)
        self.failUnlessEqual(len(metadata.serviceContext[0].endpointContext), 1)
        self.failUnlessEqual(
                len(metadata.serviceContext[0].endpointContext[0].address),
                1)
        self.failUnlessEqual(metadata.serviceContext[0].endpointContext[0].address[0],
                spSoapEndpoint)
        self.failUnlessEqual(
                len(metadata.serviceContext[0].endpointContext[0].securityMechId),
                1)
        self.failUnlessEqual(
                metadata.serviceContext[0].endpointContext[0].securityMechId[0],
                lasso.SECURITY_MECH_BEARER)
        idp_disco.buildResponseMsg()
        self.failUnless(metadata.svcMDID is not None)
        self.failUnless(idp_disco.msgUrl is None)
        self.failUnless(idp_disco.msgBody is not None)

        wsp_disco.processResponseMsg(idp_disco.msgBody)

        self.failUnless(len(wsp_disco.metadatas) == 1, 'missing svcMDID')
        self.failUnless(wsp_disco.metadatas[0].svcMDID, 'missing svcMDID')

    def test02(self):
        "Test failure by IdP for register request"
        idp = self.getIdpServer()
        wsp = self.getWspServer()
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump, dst_epr = self.login(wsp, idp, 1, {})

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        wsp_disco.setEpr(dst_epr)

        abstract = 'Personal Profile service'
        wsp_disco.initMetadataRegister()
        self.failUnless(wsp_disco.request is not None)
        wsp_disco.addSimpleServiceMetadata(service_types = 
                (lasso.PP11_HREF,), abstract = abstract,
                provider_id = wsp.providerId, address = spSoapEndpoint,
                security_mechanisms= (lasso.SECURITY_MECH_BEARER,))
        self.failUnlessEqual(len(wsp_disco.metadatas), 1)
        metadata = wsp_disco.metadatas[0]
        self.failUnlessEqual(metadata.abstract, abstract)
        self.failUnlessEqual(metadata.providerId, wsp.providerId)
        self.failUnlessEqual(len(metadata.serviceContext[0].serviceType), 1)
        self.failUnlessEqual(metadata.serviceContext[0].serviceType[0],
                lasso.PP11_HREF)
        self.failUnlessEqual(len(metadata.serviceContext[0].endpointContext), 1)
        self.failUnlessEqual(
                len(metadata.serviceContext[0].endpointContext[0].address),
                1)
        self.failUnlessEqual(metadata.serviceContext[0].endpointContext[0].address[0],
                spSoapEndpoint)
        self.failUnlessEqual(
                len(metadata.serviceContext[0].endpointContext[0].securityMechId),
                1)
        self.failUnlessEqual(
                metadata.serviceContext[0].endpointContext[0].securityMechId[0],
                lasso.SECURITY_MECH_BEARER)
        self.failUnless(metadata.svcMDID is None)
        wsp_disco.buildRequestMsg()
        self.failUnlessEqual(wsp_disco.msgUrl, idpSoapEndpoint)
        self.failUnless(wsp_disco.msgBody is not None)

        idp_disco = lasso.IdWsf2Discovery(idp)
        self.failUnless(idp_disco is not None)
        try:
            idp_disco.processRequestMsg(wsp_disco.msgBody)
        except lasso.Error, e:
            self.fail(e)
        self.failUnless(idp_disco.request is not None)
        try:
            idp_disco.checkSecurityMechanism()
        except lasso.Error, e:
            self.fail(e)
        try:
            idp_disco.failRequest(lasso.IDWSF2_DISCOVERY_STATUS_CODE_FAILED, lasso.IDWSF2_DISCOVERY_STATUS_CODE_FORBIDDEN)
        except lasso.Error, e:
            self.fail(e)
        self.failUnless(idp_disco.response is not None)
        self.failUnless(idp_disco.response.status is not None)
        self.failUnless(idp_disco.response.status.code is not lasso.IDWSF2_DISCOVERY_STATUS_CODE_FAILED)
        self.failUnlessEqual(len(idp_disco.response.status.status), 1)
        self.failUnless(idp_disco.response.status.status[0].code is not lasso.IDWSF2_DISCOVERY_STATUS_CODE_FORBIDDEN)
        idp_disco.buildResponseMsg()
        self.failUnless(idp_disco.msgUrl is None)
        self.failUnless(idp_disco.msgBody is not None)

        try:
            wsp_disco.processResponseMsg(idp_disco.msgBody)
        except lasso.Idwsf2DiscoveryForbiddenError:
            pass
        except lasso.Error, e:
            self.fail(e)

    def test03(self):
        """Test metadata register with redirection"""
        idp = self.getIdpServer()
        wsp = self.getWspServer()
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump, dst_epr = self.login(wsp, idp, 1, {})

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        wsp_disco.setEpr(dst_epr)

        abstract = 'Personal Profile service'
        wsp_disco.initMetadataRegister()
        soap_envelope = wsp_disco.getSoapEnvelopeRequest()
        soap_envelope.setSb2UserInteractionHint(lasso.IDWSF2_SB2_USER_INTERACTION_HINT_INTERACT_IF_NEEDED)
        self.failUnless(isinstance(soap_envelope.header, lasso.SoapHeader))
        self.failUnless(len(soap_envelope.header.other) > 0)
        self.failUnlessEqual(soap_envelope.getSb2UserInteractionHint(), lasso.IDWSF2_SB2_USER_INTERACTION_HINT_INTERACT_IF_NEEDED)
        self.failUnless(wsp_disco.request is not None)
        wsp_disco.addSimpleServiceMetadata(service_types = 
                (lasso.PP11_HREF,), abstract = abstract,
                provider_id = wsp.providerId, address = spSoapEndpoint,
                security_mechanisms = (lasso.SECURITY_MECH_BEARER,))
        self.failUnlessEqual(len(wsp_disco.metadatas), 1)
        metadata = wsp_disco.metadatas[0]
        self.failUnlessEqual(metadata.abstract, abstract)
        self.failUnlessEqual(metadata.providerId, wsp.providerId)
        self.failUnlessEqual(len(metadata.serviceContext), 1)
        self.failUnlessEqual(len(metadata.serviceContext[0].serviceType), 1)
        self.failUnlessEqual(metadata.serviceContext[0].serviceType[0],
                lasso.PP11_HREF)
        self.failUnlessEqual(len(metadata.serviceContext[0].endpointContext), 1)
        self.failUnlessEqual(
                len(metadata.serviceContext[0].endpointContext[0].address),
                1)
        self.failUnlessEqual(metadata.serviceContext[0].endpointContext[0].address[0],
                spSoapEndpoint)
        self.failUnlessEqual(
                len(metadata.serviceContext[0].endpointContext[0].securityMechId),
                1)
        self.failUnlessEqual(
                metadata.serviceContext[0].endpointContext[0].securityMechId[0],
                lasso.SECURITY_MECH_BEARER)
        self.failUnless(metadata.svcMDID is None)
        wsp_disco.buildRequestMsg()
        self.failUnlessEqual(wsp_disco.msgUrl, idpSoapEndpoint)
        self.failUnless(wsp_disco.msgBody is not None)

        idp_disco = lasso.IdWsf2Discovery(idp)
        self.failUnless(idp_disco is not None)
        idp_disco.processRequestMsg(wsp_disco.msgBody)
        self.failUnless(idp_disco.request is not None)
        self.failUnlessEqual(len(idp_disco.request.svcMD), 1)
        self.failUnless(idp_disco.request.svcMD[0].svcMDID is None)
        soap_envelope = idp_disco.getSoapEnvelopeRequest()
        self.failUnless(soap_envelope is not None)
        self.failUnless(soap_envelope.getMessageId() is not None)
        try:
            idp_disco.checkSecurityMechanism()
        except lasso.Error, e:
            self.fail(e)
        # redirect
        interactionUrl = spInteractionUrl
        idp_disco.redirectUserForInteraction(interactionUrl, False)
        response = idp_disco.response
        self.failUnless(isinstance(response, lasso.SoapFault))
        self.failUnless(response.detail is not None)
        self.failUnlessEqual(len(response.detail.any), 1)
        self.failUnless(isinstance(response.detail.any[0], lasso.IdWsf2Sb2RedirectRequest))
        self.failUnless(response.detail.any[0].redirectURL.startswith(interactionUrl + '?transactionID='))
        try:
            idp_disco.buildResponseMsg()
        except lasso.Error, e:
            self.fail(e)
        self.failUnless(idp_disco.msgBody is not None)


        self.failUnless(idp_disco.msgUrl is None)
        self.failUnless(idp_disco.msgBody is not None)

        try:
            wsp_disco.processResponseMsg(idp_disco.msgBody)
        except lasso.WsfprofileRedirectRequestError:
            pass
        except lasso.Error, e:
            self.fail(e)
        response_envelope = wsp_disco.getSoapEnvelopeResponse()
        self.failUnless(response_envelope.sb2GetRedirectRequestUrl().startswith(interactionUrl + '?transactionID='))
        # Here keep information about the request associated to ID: response_envelope.getMessageId().content
        wsp_disco_dump = wsp_disco.dump()
        wsp_disco = lasso.Node.newFromDump(wsp_disco_dump)
        wsp_disco.server = wsp
        request_envelope = wsp_disco.getSoapEnvelopeRequest()
        self.failUnless(request_envelope is not None)
        relates_to = request_envelope.getRelatesTo(True)
        self.failUnless(relates_to is not None)
        response_message_id = response_envelope.getMessageId().content
        relates_to.content = response_message_id
        wsp_disco.buildRequestMsg()
        # now redo as for test01 after request building
        self.failUnlessEqual(wsp_disco.msgUrl, idpSoapEndpoint)
        self.failUnless(wsp_disco.msgBody is not None)

        idp_disco = lasso.IdWsf2Discovery(idp)
        self.failUnless(idp_disco is not None)
        idp_disco.processRequestMsg(wsp_disco.msgBody)
        self.failUnless(idp_disco.request is not None)
        self.failUnlessEqual(len(idp_disco.request.svcMD), 1)
        self.failUnless(idp_disco.request.svcMD[0].svcMDID is None)
        try:
            idp_disco.checkSecurityMechanism()
        except lasso.Error, e:
            self.fail(e)
        try:
            idp_disco.validateRequest()
        except lasso.Error, e:
            self.fail(e)
        self.failUnless(idp_disco.response is not None)
        self.failUnlessEqual(len(idp_disco.metadatas), 1)
        metadata = idp_disco.metadatas[0]
        self.failUnlessEqual(metadata.abstract, abstract)
        self.failUnlessEqual(metadata.providerId, wsp.providerId)
        self.failUnlessEqual(len(metadata.serviceContext), 1)
        self.failUnlessEqual(len(metadata.serviceContext[0].serviceType), 1)
        self.failUnlessEqual(metadata.serviceContext[0].serviceType[0],
                lasso.PP11_HREF)
        self.failUnlessEqual(len(metadata.serviceContext[0].endpointContext), 1)
        self.failUnlessEqual(
                len(metadata.serviceContext[0].endpointContext[0].address),
                1)
        self.failUnlessEqual(metadata.serviceContext[0].endpointContext[0].address[0],
                spSoapEndpoint)
        self.failUnlessEqual(
                len(metadata.serviceContext[0].endpointContext[0].securityMechId),
                1)
        self.failUnlessEqual(
                metadata.serviceContext[0].endpointContext[0].securityMechId[0],
                lasso.SECURITY_MECH_BEARER)
        idp_disco.buildResponseMsg()
        self.failUnless(metadata.svcMDID is not None)
        self.failUnless(idp_disco.msgUrl is None)
        self.failUnless(idp_disco.msgBody is not None)

        wsp_disco.processResponseMsg(idp_disco.msgBody)

        self.failUnless(len(wsp_disco.metadatas) == 1, 'missing svcMDID')
        self.failUnless(wsp_disco.metadatas[0].svcMDID, 'missing svcMDID')

    def test04(self):
        """Test metadata query"""
        idp = self.getIdpServer()
        wsp = self.getWspServer()
        federations = {}
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump, dst_epr = self.login(wsp, idp, 1, federations)
        service_map = {}
        self.metadataRegister(wsp, idp, wsp_session_dump, service_types =
            (lasso.PP11_HREF,), address = spSoapEndpoint,
            abstract = 'My first PP service', services_map = service_map)
        self.metadataRegister(wsp, idp, wsp_session_dump, service_types =
            (lasso.PP11_HREF,), address = spSoapEndpoint+'2',
            abstract = 'My second PP service', services_map = service_map)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump, dst_epr = self.login(wsp, idp, 1, federations)
        wsp_disco = lasso.IdWsf2Discovery(wsp)
        wsp_disco.setEpr(dst_epr)
        wsp_disco.initMetadataQuery()
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processRequestMsg(wsp_disco.msgBody)
        idp_disco.checkSecurityMechanism()
        self.failUnlessEqual(idp_disco.svcmdids, ())
        sender = idp_disco.getSoapEnvelopeRequest().sb2GetProviderId()
        for svcMDID in service_map.get(sender, []):
            idp_disco.addServiceMetadata(service_map.get(svcMDID))
        idp_disco.validateRequest()
        idp_disco.buildResponseMsg()
        wsp_disco.processResponseMsg(idp_disco.msgBody)
        self.failUnless(len(wsp_disco.metadatas), 2)

    def test05(self):
        """Test metadata delete"""
        idp = self.getIdpServer()
        wsp = self.getWspServer()
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump, dst_epr = self.login(wsp, idp, 1, {})
        service_map = {}
        self.metadataRegister(wsp, idp, wsp_session_dump, service_types =
            (lasso.PP11_HREF,), address = spSoapEndpoint,
            abstract = 'My first PP service', services_map = service_map)
        self.metadataRegister(wsp, idp, wsp_session_dump, service_types =
            (lasso.PP11_HREF,), address = spSoapEndpoint+'2',
            abstract = 'My second PP service', services_map = service_map)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump, dst_epr = self.login(wsp, idp, 1, {})

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        wsp_disco.setEpr(dst_epr)
        wsp_disco.initMetadataDelete()
        svcmdids = tuple(service_map[wsp.providerId])
        wsp_disco.setSvcmdids(svcmdids)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processRequestMsg(wsp_disco.msgBody)
        idp_disco.checkSecurityMechanism()
        self.failUnlessEqual(idp_disco.svcmdids, svcmdids)
        sender = idp_disco.getSoapEnvelopeRequest().sb2GetProviderId()
        self.failUnlessEqual(sender, wsp.providerId)
        idp_disco.validateRequest()
        idp_disco.buildResponseMsg()
        wsp_disco.processResponseMsg(idp_disco.msgBody)

class MetadataAssociationTestCase(IdWsf2TestCase):
    def test01(self):
        """Metadata association add"""
        idp = self.getIdpServer()
        wsp = self.getWspServer()
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump, dst_epr = self.login(wsp, idp, 1, {})
        service_map = {}
        svcMDID = self.metadataRegister(wsp, idp, wsp_session_dump, service_types =
            (lasso.PP11_HREF,), address = spSoapEndpoint,
            abstract = 'My first PP service', services_map = service_map)
        # Make the request
        wsp_disco = lasso.IdWsf2Discovery(wsp)
        wsp_disco.setEpr(dst_epr)
        wsp_disco.initMetadataAssociationAdd()
        wsp_disco.svcmdids = (svcMDID,)
        wsp_disco.buildRequestMsg()
        # Receive it
        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processRequestMsg(wsp_disco.msgBody)
        idp_disco.checkSecurityMechanism()
        self.failUnlessEqual(idp_disco.svcmdids, (svcMDID,))
        sender = idp_disco.getSoapEnvelopeRequest().sb2GetProviderId()
        name_identifier = idp_disco.getNameIdentifier()
        # Store the association
        self.failUnless(sender is not None)
        self.failUnless(name_identifier is not None)
        idp_disco.validateRequest()
        idp_disco.buildResponseMsg()
        wsp_disco.processResponseMsg(idp_disco.msgBody)

    def test02(self):
        """Metadata association query"""
        idp = self.getIdpServer()
        wsp = self.getWspServer()
        wsc = self.getWscServer()
        # Register the service, add an association
        federations = {}
        wsp_identity_dump, wsp_session_dump, \
                idp_identity_dump, idp_session_dump, \
                wsp_dst_epr = self.login(wsp, idp, 1, federations)
        service_maps = {}
        svcMDID = self.metadataRegister(wsp, idp, wsp_session_dump,
                service_types = (lasso.PP11_HREF,), address = spSoapEndpoint,
            abstract = 'My first PP service', services_map = service_maps)
        service_associations = {}
        self.addAssociation(wsp, idp, wsp_session_dump, svcMDID, service_maps,
                federations, service_associations)
        # Start a query
        wsp_disco = lasso.IdWsf2Discovery(wsp)
        wsp_disco.setEpr(wsp_dst_epr)
        wsp_disco.initMetadataAssociationQuery()
        wsp_disco.buildRequestMsg()
        #
        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processRequestMsg(wsp_disco.msgBody)
        idp_disco.checkSecurityMechanism()
        self.failUnlessEqual(idp_disco.svcmdids, ())
        f = self.nid2tuple(idp_disco.getNameIdentifier())
        uid = federations[f]
        result = []
        for svcmdid in service_associations[uid]:
            result.append(svcmdid)
        idp_disco.svcmdids = tuple(result)
        idp_disco.validateRequest()
        idp_disco.buildResponseMsg()
        wsp_disco.processResponseMsg(idp_disco.msgBody)
        self.failUnlessEqual(wsp_disco.svcmdids, (svcMDID,))

    def test03(self):
        """Metadata association delete"""
        pass

class QueryTestCase(IdWsf2TestCase):
    def test01(self):
        """Discovery Service Query"""
        idp = self.getIdpServer()
        wsp = self.getWspServer()
        wsc = self.getWscServer()
        federations = {}
        # Register the service, add an association
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump, wsp_dst_epr = self.login(wsp, idp, 1, federations)
        service_maps = {}
        svcMDID = self.metadataRegister(wsp, idp, wsp_session_dump, service_types =
            (lasso.PP11_HREF,), address = spSoapEndpoint,
            abstract = 'My first PP service', services_map = service_maps)
        service_associations = {}
        self.addAssociation(wsp, idp, wsp_session_dump, svcMDID, service_maps, federations, service_associations)
        # Try to find the service
        wsc_identity_dump, wsc_session_dump, idp_identity_dump, idp_session_dump, wsc_dst_epr = self.login(wsc, idp, 1, federations, idp_identity_dump = idp_identity_dump, idp_session_dump = idp_session_dump)
        wsc_disco = lasso.IdWsf2Discovery(wsc)
        wsc_disco.setEpr(wsc_dst_epr)
        wsc_disco.initQuery()
        wsc_disco.addRequestedService(service_types = (lasso.PP11_HREF,))
        wsc_disco.buildRequestMsg()
        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.setIdentityFromDump(idp_identity_dump)
        idp_disco.processRequestMsg(wsc_disco.msgBody)
        f = self.nid2tuple(idp_disco.getNameIdentifier())
        uid = federations[f]
        for id in service_associations[uid]:
            idp_disco.addServiceMetadata(service_maps[id])
        idp_disco.validateRequest()
        idp_disco.buildResponseMsg()
        wsc_disco.processResponseMsg(idp_disco.msgBody)
        self.failUnlessEqual(len(wsc_disco.endpointReferences), 1)

class DstTestCase(IdWsf2TestCase):
    def test01(self):
        """Data Service Template Query"""
        content = '<pp:PP xmlns:pp="%s">Coin</pp:PP>' % lasso.PP11_HREF
        idp = self.getIdpServer()
        wsp = self.getWspServer()
        wsc = self.getWscServer()
        federations = {}
        # Register the service, add an association
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, \
            idp_session_dump, wsp_dst_epr = self.login(wsp, idp, 1,
                    federations)
        service_maps = {}
        svcMDID = self.metadataRegister(wsp, idp, wsp_session_dump,
                service_types = (lasso.PP11_HREF,), address =
                spSoapEndpoint, abstract = 'My first PP service',
                services_map = service_maps)
        service_associations = {}
        self.addAssociation(wsp, idp, wsp_session_dump, svcMDID,
                service_maps, federations, service_associations)
        wsc_identity_dump, wsc_session_dump, idp_identity_dump, \
        idp_session_dump, wsc_dst_epr = self.login(wsc, idp, 1, federations,
                idp_identity_dump = idp_identity_dump, idp_session_dump =
                idp_session_dump)
        eprs = self.query(wsc, idp, idp_identity_dump, wsc_session_dump, 1,
                federations, service_maps, service_associations,
                service_types = (lasso.PP11_HREF,))
        self.failUnless(len(eprs), 1)
        lasso.registerIdwsf2DstService(lasso.PP11_PREFIX, lasso.PP11_HREF)
        wsc_dst = lasso.IdWsf2DataService(wsc)
        wsc_dst.setEpr(eprs[0])
        wsc_dst.initQuery()
        wsc_dst.setServiceType(lasso.PP11_PREFIX, lasso.PP11_HREF)
        wsc_dst.addQueryItem('/%s:PP' % lasso.PP11_PREFIX, 'xxx')
        wsc_dst.buildRequestMsg()
        wsp_dst = lasso.IdWsf2DataService(wsp)
        wsp_dst.processRequestMsg(wsc_dst.msgBody)
        self.failUnlessEqual(wsp_dst.requestType, lasso.IDWSF2_DATA_SERVICE_REQUEST_TYPE_QUERY)
        wsp_dst.checkSecurityMechanism()
        data = ET.parse(StringIO(content))
        for item in wsp_dst.items:
            result = data.xpath(item.select, namespaces = { lasso.PP11_PREFIX: lasso.PP11_HREF })
            for found in result:
                wsp_dst.setQueryItemResult(item.itemId, ET.tostring(found), True)
        wsp_dst.setServiceType(lasso.PP11_PREFIX, lasso.PP11_HREF)
        wsp_dst.validateRequest()
        wsp_dst.buildResponseMsg()
        wsc_dst.processResponseMsg(wsp_dst.msgBody)


metadataSuite = unittest.makeSuite(MetadataTestCase, 'test')
metadataAssociationSuite = unittest.makeSuite(MetadataAssociationTestCase, 'test')
querySuite = unittest.makeSuite(QueryTestCase, 'test')
dstSuite = unittest.makeSuite(DstTestCase, 'test')


allTests = unittest.TestSuite((metadataSuite,
    metadataAssociationSuite,querySuite,dstSuite)) 

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity = 2).run(allTests).wasSuccessful())

