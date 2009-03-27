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

if not '..' in sys.path:
    sys.path.insert(0, '..')
if not '../.libs' in sys.path:
    sys.path.insert(0, '../.libs')

import lasso


try:
    dataDir
except NameError:
    dataDir = '../../../tests/data'


class IdWsf2TestCase(unittest.TestCase):
    def getWspServer(self):
        wsp_metadata = os.path.join(dataDir, 'sp5-saml2/metadata.xml')
        wsp_private_key = os.path.join(dataDir, 'sp5-saml2/private-key.pem')
        idp_metadata = os.path.join(dataDir, 'idp5-saml2/metadata.xml')

        server = lasso.Server(wsp_metadata, wsp_private_key, None, None)
        server.addProvider(lasso.PROVIDER_ROLE_IDP, idp_metadata, None, None)
        server.setEncryptionPrivateKey(wsp_private_key);

        return server;

    def getWscServer(self):
        wsc_metadata = os.path.join(dataDir, 'sp6-saml2/metadata.xml')
        wsc_private_key = os.path.join(dataDir, 'sp6-saml2/private-key.pem')
        idp_metadata = os.path.join(dataDir, 'idp5-saml2/metadata.xml')

        server = lasso.Server(wsc_metadata, wsc_private_key, None, None)
        server.addProvider(lasso.PROVIDER_ROLE_IDP, idp_metadata, None, None)

        return server;

    def getIdpServer(self):
        if hasattr(self, 'idp_server_dump') and self.idp_server_dump is not None:
            server = lasso.Server.newFromDump(self.idp_server_dump)
        else:
            idp_metadata = os.path.join(dataDir, 'idp5-saml2/metadata.xml')
            idp_private_key = os.path.join(dataDir, 'idp5-saml2/private-key.pem')
            wsp_metadata = os.path.join(dataDir, 'sp5-saml2/metadata.xml')
            wsc_metadata = os.path.join(dataDir, 'sp6-saml2/metadata.xml')

            server = lasso.Server(idp_metadata, idp_private_key, None, None)
            server.addProvider(lasso.PROVIDER_ROLE_SP, wsp_metadata, None, None)
            server.getProvider(server.providerIds[0]).setEncryptionMode(lasso.ENCRYPTION_MODE_NAMEID);
            server.addProvider(lasso.PROVIDER_ROLE_SP, wsc_metadata, None, None)
            self.idp_server_dump = server.dump()

        return server

    def idpRegisterSelf(self, idp_server):
        disco = lasso.IdWsf2Discovery(idp_server)
        service_type = lasso.IDWSF2_DISCO_HREF
        abstract = 'Disco service'
        soapEndpoint = 'http://idp1/soapEndpoint'
        disco.metadataRegisterSelf(service_type, abstract, soapEndpoint)

        return idp_server

    def metadataRegister(self, wsp, idp):
        wsp_disco = lasso.IdWsf2Discovery(wsp)
        abstract = 'Personal Profile service'
        soapEndpoint = 'http://idp1/soapEndpoint'
        wsp_disco.initMetadataRegister(
                'urn:liberty:id-sis-pp:2005-05', abstract, wsp.providerIds[0], soapEndpoint)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataRegisterMsg(wsp_disco.msgBody)
        idp_disco.buildResponseMsg()

        wsp_disco.processMetadataRegisterResponseMsg(idp_disco.msgBody)
        return idp, wsp_disco.svcMDID

    def login(self, sp, idp, sp_identity_dump=None, sp_session_dump=None,
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

        return sp_identity_dump, sp_session_dump, idp_identity_dump, idp_session_dump


class IdpSelfRegistrationTestCase(IdWsf2TestCase):
    def test01(self):
        """Register IdP as Dicovery Service and get a random svcMDID"""

        disco = lasso.IdWsf2Discovery(self.getIdpServer())

        service_type = lasso.IDWSF2_DISCO_HREF
        abstract = 'Disco service'
        soapEndpoint = 'http://idp1/soapEndpoint'

        svcMDID = disco.metadataRegisterSelf(service_type, abstract, soapEndpoint)
        # In real use, store the server dump here

        self.failUnless(svcMDID, 'missing svcMDID')

    def test02(self):
        """Register IdP as Dicovery Service with a given svcMDID"""

        disco = lasso.IdWsf2Discovery(self.getIdpServer())

        service_type = lasso.IDWSF2_DISCO_HREF
        abstract = 'Disco service'
        soapEndpoint = 'http://idp1/soapEndpoint'
        mySvcMDID = 'RaNdOm StRiNg'

        svcMDID = disco.metadataRegisterSelf(service_type, abstract, soapEndpoint, mySvcMDID)
        # In real use, store the server dump here

        self.failUnless(svcMDID, 'missing svcMDID')
        self.failUnlessEqual(svcMDID, mySvcMDID, 'wrong svcMDID')

    def test03(self):
        """Register IdP as Dicovery Service with wrong parameters"""

        disco = lasso.IdWsf2Discovery(self.getIdpServer())

        service_type = ''
        abstract = ''
        soapEndpoint = ''

        svcMDID = disco.metadataRegisterSelf(service_type, abstract, soapEndpoint)

        self.failIf(svcMDID, 'svcMDID should not be set')


class MetadataRegisterTestCase(IdWsf2TestCase):
    def test01(self):
        """Init metadata registration request"""

        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        wsp_disco = lasso.IdWsf2Discovery(wsp)

        abstract = 'Personal Profile service'
        soapEndpoint = 'http://idp1/soapEndpoint'
        try:
            wsp_disco.initMetadataRegister(
                'urn:liberty:id-sis-pp:2005-05', abstract, wsp.providerIds[0], soapEndpoint)
        except lasso.Error, e:
            self.fail(e)


    def test02(self):
        """Build metadata registration request"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        wsp_disco = lasso.IdWsf2Discovery(wsp)

        abstract = 'Personal Profile service'
        soapEndpoint = 'http://idp1/soapEndpoint'
        wsp_disco.initMetadataRegister(
                'urn:liberty:id-sis-pp:2005-05', abstract, wsp.providerIds[0], soapEndpoint)
        wsp_disco.buildRequestMsg()

        self.failUnless(wsp_disco.msgBody, 'missing soap request')

    def test03(self):
        """Check metadata registration request type"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        wsp_disco = lasso.IdWsf2Discovery(wsp)

        abstract = 'Personal Profile service'
        soapEndpoint = 'http://idp1/soapEndpoint'
        wsp_disco.initMetadataRegister(
                'urn:liberty:id-sis-pp:2005-05', abstract, wsp.providerIds[0], soapEndpoint)
        wsp_disco.buildRequestMsg()

        request_type = lasso.getRequestTypeFromSoapMsg(wsp_disco.msgBody)
        self.failUnlessEqual(request_type, lasso.REQUEST_TYPE_IDWSF2_DISCO_SVCMD_REGISTER,
            'wrong request type in metadata_register : %s' % request_type)

    def test04(self):
        """Process metadata registration request"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        wsp_disco = lasso.IdWsf2Discovery(wsp)

        abstract = 'Personal Profile service'
        soapEndpoint = 'http://idp1/soapEndpoint'
        wsp_disco.initMetadataRegister(
                'urn:liberty:id-sis-pp:2005-05', abstract, wsp.providerIds[0], soapEndpoint)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        try:
            idp_disco.processMetadataRegisterMsg(wsp_disco.msgBody)
        except lasso.Error, e:
            self.fail(e)

    def test05(self):
        """Check metadata registration on the Discovery service"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        wsp_disco = lasso.IdWsf2Discovery(wsp)

        abstract = 'Personal Profile service'
        soapEndpoint = 'http://idp1/soapEndpoint'
        wsp_disco.initMetadataRegister(
                'urn:liberty:id-sis-pp:2005-05', abstract, wsp.providerIds[0], soapEndpoint)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataRegisterMsg(wsp_disco.msgBody)

        self.failUnless(idp_disco.metadata.dump(), 'missing registered metadata')

    def test06(self):
        """Build metadata registration response"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        wsp_disco = lasso.IdWsf2Discovery(wsp)

        abstract = 'Personal Profile service'
        soapEndpoint = 'http://idp1/soapEndpoint'
        wsp_disco.initMetadataRegister(
                'urn:liberty:id-sis-pp:2005-05', abstract, wsp.providerIds[0], soapEndpoint)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataRegisterMsg(wsp_disco.msgBody)
        idp_disco.buildResponseMsg()

        self.failUnless(idp_disco.msgBody, 'missing soap answer')

    def test07(self):
        """Process metadata registration response"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        wsp_disco = lasso.IdWsf2Discovery(wsp)

        abstract = 'Personal Profile service'
        soapEndpoint = 'http://idp1/soapEndpoint'
        wsp_disco.initMetadataRegister(
                'urn:liberty:id-sis-pp:2005-05', abstract, wsp.providerIds[0], soapEndpoint)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataRegisterMsg(wsp_disco.msgBody)
        idp_disco.buildResponseMsg()

        try:
            wsp_disco.processMetadataRegisterResponseMsg(idp_disco.msgBody)
        except lasso.Error, e:
            self.fail(e)

    def test08(self):
        """Check metadata registration on the WSP"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        wsp_disco = lasso.IdWsf2Discovery(wsp)

        abstract = 'Personal Profile service'
        soapEndpoint = 'http://idp1/soapEndpoint'
        wsp_disco.initMetadataRegister(
                'urn:liberty:id-sis-pp:2005-05', abstract, wsp.providerIds[0], soapEndpoint)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataRegisterMsg(wsp_disco.msgBody)
        idp_disco.buildResponseMsg()

        wsp_disco.processMetadataRegisterResponseMsg(idp_disco.msgBody)

        self.failUnless(wsp_disco.svcMDID, 'missing svcMDID')

class MetadataAssociationAddTestCase(IdWsf2TestCase):
    def test01(self):
        """Init metadata association add request"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)

        try:
            wsp_disco.initMetadataAssociationAdd(svcMDID)
        except lasso.Error, e:
            self.fail(e)

    def test02(self):
        """Init metadata association add request without login"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)

        try:
            wsp_disco.initMetadataAssociationAdd(svcMDID)
        except lasso.Error, e:
            if e[0] != lasso.PROFILE_ERROR_SESSION_NOT_FOUND:
                self.fail(e)
        else:
            self.fail('Should have a "session not found" exception')

    def test03(self):
        """Init metadata association add request - msgUrl construction"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)

        self.failUnless(wsp_disco.msgUrl, 'missing msgUrl')

    def test04(self):
        """Build metadata association add request"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        self.failUnless(wsp_disco.msgBody, 'missing msgBody')

    def test05(self):
        """Process metadata association add request"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)

        try:
            idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        except lasso.Error, e:
            self.fail(e)

    def test06(self):
        """Register metadata association"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        try:
            idp_disco.registerMetadata()
        except lasso.Error, e:
            self.fail(e)

    def test07(self):
        """Check metadata association registration"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)
        idp_disco.registerMetadata()

        self.failUnless(idp_disco.isIdentityDirty, 'identity has not changed, it should contain a svcMDID')
        self.failUnless(idp_disco.identity.dump() != idp_identity_dump,
            'identity dump has not changed, it should contain a svcMDID')

    def test08(self):
        """Build metadata association add response"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        idp_disco.registerMetadata()
        if idp_disco.isIdentityDirty:
            idp_identity_dump = idp_disco.identity.dump()
        if idp_disco.isSessionDirty:
            idp_session_dump = idp_disco.session.dump()

        idp_disco.buildResponseMsg()

        self.failUnless(idp_disco.msgBody)

    def test09(self):
        """Process metadata association add response"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        idp_disco.registerMetadata()
        if idp_disco.isIdentityDirty:
            idp_identity_dump = idp_disco.identity.dump()
        if idp_disco.isSessionDirty:
            idp_session_dump = idp_disco.session.dump()
        idp_disco.buildResponseMsg()

        try:
            wsp_disco.processMetadataAssociationAddResponseMsg(idp_disco.msgBody)
        except lasso.Error, e:
            self.fail(e)


class DiscoveryQueryTestCase(IdWsf2TestCase):
    def test01(self):
        """Init discovery query"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        idp_disco.registerMetadata()
        if idp_disco.isIdentityDirty:
            idp_identity_dump = idp_disco.identity.dump()
        if idp_disco.isSessionDirty:
            idp_session_dump = idp_disco.session.dump()
        idp_disco.buildResponseMsg()

        wsp_disco.processMetadataAssociationAddResponseMsg(idp_disco.msgBody)

        wsc = self.getWscServer()
        wsc_identity_dump, wsc_session_dump, idp_identity_dump, idp_session_dump = \
            self.login(wsc, idp, None, None, idp_identity_dump, idp_session_dump)

        wsc_disco = lasso.IdWsf2Discovery(wsc)
        if wsc_identity_dump is not None:
            wsc_disco.setIdentityFromDump(wsc_identity_dump)
        if wsc_session_dump is not None:
            wsc_disco.setSessionFromDump(wsc_session_dump)

        try:
            wsc_disco.initQuery()
        except lasso.Error, e:
            self.fail(e)

    def test02(self):
        """Init discovery query without login"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        idp_disco.registerMetadata()
        if idp_disco.isIdentityDirty:
            idp_identity_dump = idp_disco.identity.dump()
        if idp_disco.isSessionDirty:
            idp_session_dump = idp_disco.session.dump()
        idp_disco.buildResponseMsg()

        wsp_disco.processMetadataAssociationAddResponseMsg(idp_disco.msgBody)

        wsc = self.getWscServer()

        wsc_disco = lasso.IdWsf2Discovery(wsc)

        try:
            wsc_disco.initQuery()
        except lasso.Error, e:
            if e[0] != lasso.PROFILE_ERROR_SESSION_NOT_FOUND:
                self.fail(e)
        else:
            self.fail('Should have a "session not found" exception')

    def test03(self):
        """Init discovery query - check msg url"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        idp_disco.registerMetadata()
        if idp_disco.isIdentityDirty:
            idp_identity_dump = idp_disco.identity.dump()
        if idp_disco.isSessionDirty:
            idp_session_dump = idp_disco.session.dump()
        idp_disco.buildResponseMsg()

        wsp_disco.processMetadataAssociationAddResponseMsg(idp_disco.msgBody)

        wsc = self.getWscServer()
        wsc_identity_dump, wsc_session_dump, idp_identity_dump, idp_session_dump = \
            self.login(wsc, idp, None, None, idp_identity_dump, idp_session_dump)

        wsc_disco = lasso.IdWsf2Discovery(wsc)
        if wsc_identity_dump is not None:
            wsc_disco.setIdentityFromDump(wsc_identity_dump)
        if wsc_session_dump is not None:
            wsc_disco.setSessionFromDump(wsc_session_dump)

        wsc_disco.initQuery()

        self.failUnless(wsc_disco.msgUrl, 'missing msgUrl')

    def test04(self):
        """Add requested service type to discovery query"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        idp_disco.registerMetadata()
        if idp_disco.isIdentityDirty:
            idp_identity_dump = idp_disco.identity.dump()
        if idp_disco.isSessionDirty:
            idp_session_dump = idp_disco.session.dump()
        idp_disco.buildResponseMsg()

        wsp_disco.processMetadataAssociationAddResponseMsg(idp_disco.msgBody)

        wsc = self.getWscServer()
        wsc_identity_dump, wsc_session_dump, idp_identity_dump, idp_session_dump = \
            self.login(wsc, idp, None, None, idp_identity_dump, idp_session_dump)

        wsc_disco = lasso.IdWsf2Discovery(wsc)
        if wsc_identity_dump is not None:
            wsc_disco.setIdentityFromDump(wsc_identity_dump)
        if wsc_session_dump is not None:
            wsc_disco.setSessionFromDump(wsc_session_dump)

        wsc_disco.initQuery()

        try:
            wsc_disco.addRequestedServiceType('urn:liberty:id-sis-pp:2005-05')
        except lasso.Error, e:
            self.fail(e)

    def test05(self):
        """Build discovery query"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        idp_disco.registerMetadata()
        if idp_disco.isIdentityDirty:
            idp_identity_dump = idp_disco.identity.dump()
        if idp_disco.isSessionDirty:
            idp_session_dump = idp_disco.session.dump()
        idp_disco.buildResponseMsg()

        wsp_disco.processMetadataAssociationAddResponseMsg(idp_disco.msgBody)

        wsc = self.getWscServer()
        wsc_identity_dump, wsc_session_dump, idp_identity_dump, idp_session_dump = \
            self.login(wsc, idp, None, None, idp_identity_dump, idp_session_dump)

        wsc_disco = lasso.IdWsf2Discovery(wsc)
        if wsc_identity_dump is not None:
            wsc_disco.setIdentityFromDump(wsc_identity_dump)
        if wsc_session_dump is not None:
            wsc_disco.setSessionFromDump(wsc_session_dump)

        wsc_disco.initQuery()
        wsc_disco.addRequestedServiceType('urn:liberty:id-sis-pp:2005-05')
        wsc_disco.buildRequestMsg()

        self.failUnless(wsc_disco.msgBody)

    def test06(self):
        """Process discovery query"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        idp_disco.registerMetadata()
        if idp_disco.isIdentityDirty:
            idp_identity_dump = idp_disco.identity.dump()
        if idp_disco.isSessionDirty:
            idp_session_dump = idp_disco.session.dump()
        idp_disco.buildResponseMsg()

        wsp_disco.processMetadataAssociationAddResponseMsg(idp_disco.msgBody)

        wsc = self.getWscServer()
        wsc_identity_dump, wsc_session_dump, idp_identity_dump, idp_session_dump = \
            self.login(wsc, idp, None, None, idp_identity_dump, idp_session_dump)

        wsc_disco = lasso.IdWsf2Discovery(wsc)
        if wsc_identity_dump is not None:
            wsc_disco.setIdentityFromDump(wsc_identity_dump)
        if wsc_session_dump is not None:
            wsc_disco.setSessionFromDump(wsc_session_dump)

        wsc_disco.initQuery()
        wsc_disco.addRequestedServiceType('urn:liberty:id-sis-pp:2005-05')
        wsc_disco.buildRequestMsg()

        try:
            idp_disco.processQueryMsg(wsc_disco.msgBody)
        except lasso.Error, e:
            self.fail(e)

    def test07(self):
        """Process discovery query and check name identifier"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        idp_disco.registerMetadata()
        if idp_disco.isIdentityDirty:
            idp_identity_dump = idp_disco.identity.dump()
        if idp_disco.isSessionDirty:
            idp_session_dump = idp_disco.session.dump()
        idp_disco.buildResponseMsg()

        wsp_disco.processMetadataAssociationAddResponseMsg(idp_disco.msgBody)

        wsc = self.getWscServer()
        wsc_identity_dump, wsc_session_dump, idp_identity_dump, idp_session_dump = \
            self.login(wsc, idp, None, None, idp_identity_dump, idp_session_dump)

        wsc_disco = lasso.IdWsf2Discovery(wsc)
        if wsc_identity_dump is not None:
            wsc_disco.setIdentityFromDump(wsc_identity_dump)
        if wsc_session_dump is not None:
            wsc_disco.setSessionFromDump(wsc_session_dump)

        wsc_disco.initQuery()
        wsc_disco.addRequestedServiceType('urn:liberty:id-sis-pp:2005-05')
        wsc_disco.buildRequestMsg()

        idp_disco.processQueryMsg(wsc_disco.msgBody)

    def test08(self):
        """Build discovery query response EPRs"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        idp_disco.registerMetadata()
        if idp_disco.isIdentityDirty:
            idp_identity_dump = idp_disco.identity.dump()
        if idp_disco.isSessionDirty:
            idp_session_dump = idp_disco.session.dump()
        idp_disco.buildResponseMsg()

        wsp_disco.processMetadataAssociationAddResponseMsg(idp_disco.msgBody)

        wsc = self.getWscServer()
        wsc_identity_dump, wsc_session_dump, idp_identity_dump, idp_session_dump = \
            self.login(wsc, idp, None, None, idp_identity_dump, idp_session_dump)

        wsc_disco = lasso.IdWsf2Discovery(wsc)
        if wsc_identity_dump is not None:
            wsc_disco.setIdentityFromDump(wsc_identity_dump)
        if wsc_session_dump is not None:
            wsc_disco.setSessionFromDump(wsc_session_dump)

        wsc_disco.initQuery()
        wsc_disco.addRequestedServiceType('urn:liberty:id-sis-pp:2005-05')
        wsc_disco.buildRequestMsg()

        idp_disco.processQueryMsg(wsc_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        try:
            idp_disco.buildQueryResponseEprs()
        except lasso.Error, e:
            self.fail(e)

    def test09(self):
        """Build discovery query response"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        idp_disco.registerMetadata()
        if idp_disco.isIdentityDirty:
            idp_identity_dump = idp_disco.identity.dump()
        if idp_disco.isSessionDirty:
            idp_session_dump = idp_disco.session.dump()
        idp_disco.buildResponseMsg()

        wsp_disco.processMetadataAssociationAddResponseMsg(idp_disco.msgBody)

        wsc = self.getWscServer()
        wsc_identity_dump, wsc_session_dump, idp_identity_dump, idp_session_dump = \
            self.login(wsc, idp, None, None, idp_identity_dump, idp_session_dump)

        wsc_disco = lasso.IdWsf2Discovery(wsc)
        if wsc_identity_dump is not None:
            wsc_disco.setIdentityFromDump(wsc_identity_dump)
        if wsc_session_dump is not None:
            wsc_disco.setSessionFromDump(wsc_session_dump)

        wsc_disco.initQuery()
        wsc_disco.addRequestedServiceType('urn:liberty:id-sis-pp:2005-05')
        wsc_disco.buildRequestMsg()

        idp_disco.processQueryMsg(wsc_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)
        idp_disco.buildQueryResponseEprs()
        idp_disco.buildResponseMsg()

        self.failUnless(idp_disco.msgBody, 'missing msgBody')

    def test10(self):
        """Process discovery query response"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        idp_disco.registerMetadata()
        if idp_disco.isIdentityDirty:
            idp_identity_dump = idp_disco.identity.dump()
        if idp_disco.isSessionDirty:
            idp_session_dump = idp_disco.session.dump()
        idp_disco.buildResponseMsg()

        wsp_disco.processMetadataAssociationAddResponseMsg(idp_disco.msgBody)

        wsc = self.getWscServer()
        wsc_identity_dump, wsc_session_dump, idp_identity_dump, idp_session_dump = \
            self.login(wsc, idp, None, None, idp_identity_dump, idp_session_dump)

        wsc_disco = lasso.IdWsf2Discovery(wsc)
        if wsc_identity_dump is not None:
            wsc_disco.setIdentityFromDump(wsc_identity_dump)
        if wsc_session_dump is not None:
            wsc_disco.setSessionFromDump(wsc_session_dump)

        wsc_disco.initQuery()
        wsc_disco.addRequestedServiceType('urn:liberty:id-sis-pp:2005-05')
        wsc_disco.buildRequestMsg()

        idp_disco.processQueryMsg(wsc_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)
        idp_disco.buildQueryResponseEprs()
        idp_disco.buildResponseMsg()

        try:
            wsc_disco.processQueryResponseMsg(idp_disco.msgBody)
        except lasso.Error, e:
            self.fail(e)

    def test11(self):
        """Check discovery query result"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        idp_disco.registerMetadata()
        if idp_disco.isIdentityDirty:
            idp_identity_dump = idp_disco.identity.dump()
        if idp_disco.isSessionDirty:
            idp_session_dump = idp_disco.session.dump()
        idp_disco.buildResponseMsg()

        wsp_disco.processMetadataAssociationAddResponseMsg(idp_disco.msgBody)

        wsc = self.getWscServer()
        wsc_identity_dump, wsc_session_dump, idp_identity_dump, idp_session_dump = \
            self.login(wsc, idp, None, None, idp_identity_dump, idp_session_dump)

        wsc_disco = lasso.IdWsf2Discovery(wsc)
        if wsc_identity_dump is not None:
            wsc_disco.setIdentityFromDump(wsc_identity_dump)
        if wsc_session_dump is not None:
            wsc_disco.setSessionFromDump(wsc_session_dump)

        wsc_disco.initQuery()
        wsc_disco.addRequestedServiceType('urn:liberty:id-sis-pp:2005-05')
        wsc_disco.buildRequestMsg()

        idp_disco.processQueryMsg(wsc_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)
        idp_disco.buildQueryResponseEprs()
        idp_disco.buildResponseMsg()

        wsc_disco.processQueryResponseMsg(idp_disco.msgBody)

        self.failUnless(wsc_disco.getService(), 'missing service after discovery query')


class DataServiceQueryTestCase(IdWsf2TestCase):
    def getProfileService(self):
        """Check discovery query result"""
        idp = self.getIdpServer()
        idp = self.idpRegisterSelf(idp)
        wsp = self.getWspServer()
        idp, svcMDID = self.metadataRegister(wsp, idp)
        wsp_identity_dump, wsp_session_dump, idp_identity_dump, idp_session_dump = self.login(wsp, idp)

        wsp_disco = lasso.IdWsf2Discovery(wsp)
        if wsp_identity_dump is not None:
            wsp_disco.setIdentityFromDump(wsp_identity_dump)
        if wsp_session_dump is not None:
            wsp_disco.setSessionFromDump(wsp_session_dump)
        wsp_disco.initMetadataAssociationAdd(svcMDID)
        wsp_disco.buildRequestMsg()

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataAssociationAddMsg(wsp_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)

        idp_disco.registerMetadata()
        if idp_disco.isIdentityDirty:
            idp_identity_dump = idp_disco.identity.dump()
        if idp_disco.isSessionDirty:
            idp_session_dump = idp_disco.session.dump()
        idp_disco.buildResponseMsg()

        wsp_disco.processMetadataAssociationAddResponseMsg(idp_disco.msgBody)

        wsc = self.getWscServer()
        wsc_identity_dump, wsc_session_dump, idp_identity_dump, idp_session_dump = \
            self.login(wsc, idp, None, None, idp_identity_dump, idp_session_dump)

        wsc_disco = lasso.IdWsf2Discovery(wsc)
        if wsc_identity_dump is not None:
            wsc_disco.setIdentityFromDump(wsc_identity_dump)
        if wsc_session_dump is not None:
            wsc_disco.setSessionFromDump(wsc_session_dump)

        wsc_disco.initQuery()
        wsc_disco.addRequestedServiceType('urn:liberty:id-sis-pp:2005-05')
        wsc_disco.buildRequestMsg()

        idp_disco.processQueryMsg(wsc_disco.msgBody)
        if idp_identity_dump is not None:
            idp_disco.setIdentityFromDump(idp_identity_dump)
        if idp_session_dump is not None:
            idp_disco.setSessionFromDump(idp_session_dump)
        idp_disco.buildQueryResponseEprs()
        idp_disco.buildResponseMsg()

        wsc_disco.processQueryResponseMsg(idp_disco.msgBody)

        return wsc_disco.getService(), wsp

    def test01(self):
        """Data service init query"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')

        try:
            service.initQuery()
        except lasso.Error, e:
            self.fail(e)

    def test02(self):
        """Data service init query - msgUrl construction"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()

        self.failUnless(service.msgUrl, 'missing msgUrl')

    def test03(self):
        """Data service add query item"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()

        try:
            service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        except lasso.Error, e:
            self.fail(e)

    def test04(self):
        """Data service build query"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.buildRequestMsg()

        self.failUnless(service.msgBody, 'missing msgBody')

    def test05(self):
        """Data service build query with multiple items"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('not existing attribute', 'not existing attribute')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        self.failUnless(service.msgBody, 'missing msgBody')

    def test06(self):
        """Data service process query"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('not existing attribute', 'not existing attribute')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)

        try:
            wsp_service.processQueryMsg(service.msgBody)
        except lasso.Error, e:
            self.fail(e)

    def test07(self):
        """Data service check service type"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('not existing attribute', 'not existing attribute')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        self.failUnless(wsp_service.type, 'service type is not set')
        self.failUnless(wsp_service.type == 'urn:liberty:id-sis-pp:2005-05', 'wrong service type')

    def test08(self):
        """Data service get query items"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('not existing attribute', 'not existing attribute')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        self.failUnless(wsp_service.queryItems, 'queryItems list is None or empty')

    def test09(self):
        """Data service check query items"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('not existing attribute', 'not existing attribute')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        items = [ '/pp2:PP/pp2:InformalName', 'not existing attribute', '/pp2:PP/pp2:MsgContact' ]
        for i in range(3):
            self.failUnless(wsp_service.queryItems[i] == items[i],
                "query items don't match : %s != %s" % (wsp_service.queryItems[i], items[i]))

    def test10(self):
        """Data service check name identifier"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

    def test11(self):
        """Data service parse query items - success"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        wsp_service.data = """<PP xmlns="urn:liberty:id-sis-pp:2005-05">
                <InformalName>User name</InformalName>
                <MsgContact>
                    <MsgAccount>Email account</MsgAccount>
                    <MsgProvider>Email server</MsgProvider>
                </MsgContact>
            </PP>"""

        try:
            wsp_service.parseQueryItems()
        except lasso.Error, e:
            self.fail(e)

    def test12(self):
        """Data service parse query items - failure - no item"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        wsp_service.data = """<PP xmlns="urn:liberty:id-sis-pp:2005-05">
                <InformalName>User name</InformalName>
                <MsgContact>
                    <MsgAccount>Email account</MsgAccount>
                    <MsgProvider>Email server</MsgProvider>
                </MsgContact>
            </PP>"""

        try:
            wsp_service.parseQueryItems()
        except lasso.Error, e:
            if e[0] != lasso.DST_ERROR_QUERY_FAILED:
                self.fail(e)
        else:
             self.fail('query items parsing should have failed because no item was requested')

    def test13(self):
        """Data service parse query items - failure - wrong item"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('not existing attribute', 'not existing attribute')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        wsp_service.data = """<PP xmlns="urn:liberty:id-sis-pp:2005-05">
                <InformalName>User name</InformalName>
                <MsgContact>
                    <MsgAccount>Email account</MsgAccount>
                    <MsgProvider>Email server</MsgProvider>
                </MsgContact>
            </PP>"""

        try:
            wsp_service.parseQueryItems()
        except lasso.Error, e:
            if e[0] != lasso.DST_ERROR_QUERY_FAILED:
                self.fail(e)
        else:
             self.fail('query items parsing should have failed because a wrong query item was requested')

    def test14(self):
        """Data service parse query items - failure - no data"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        try:
            wsp_service.parseQueryItems()
        except lasso.Error, e:
            if e[0] != lasso.DST_ERROR_MISSING_SERVICE_DATA:
                self.fail(e)
        else:
             self.fail('query items parsing should have failed because no data was provided')


    def test15(self):
        """Data service parse query items - partial failure"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        wsp_service.data = """<PP xmlns="urn:liberty:id-sis-pp:2005-05">
                <InformalName>User name</InformalName>
            </PP>"""

        # No exception should be raised here but one will be raised on the WSC
        # when parsing response status
        try:
            wsp_service.parseQueryItems()
        except lasso.Error, e:
            self.fail(e)

    def test16(self):
        """Data service build query response"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        wsp_service.data = """<PP xmlns="urn:liberty:id-sis-pp:2005-05">
                <InformalName>User name</InformalName>
                <MsgContact>
                    <MsgAccount>Email account</MsgAccount>
                    <MsgProvider>Email server</MsgProvider>
                </MsgContact>
            </PP>"""

        wsp_service.parseQueryItems()
        wsp_service.buildResponseMsg()

        self.failUnless(wsp_service.msgBody, 'missing msgBody')

    def test17(self):
        """Data service process query response - success"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        wsp_service.data = """<PP xmlns="urn:liberty:id-sis-pp:2005-05">
                <InformalName>User name</InformalName>
                <MsgContact>
                    <MsgAccount>Email account</MsgAccount>
                    <MsgProvider>Email server</MsgProvider>
                </MsgContact>
            </PP>"""

        wsp_service.parseQueryItems()
        wsp_service.buildResponseMsg()

        try:
            service.processQueryResponseMsg(wsp_service.msgBody)
        except lasso.Error, e:
            self.fail(e)

    def test18(self):
        """Data service process query response - failure"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('not existing attribute', 'not existing attribute')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        wsp_service.data = """<PP xmlns="urn:liberty:id-sis-pp:2005-05">
                <InformalName>User name</InformalName>
                <MsgContact>
                    <MsgAccount>Email account</MsgAccount>
                    <MsgProvider>Email server</MsgProvider>
                </MsgContact>
            </PP>"""

        try:
            wsp_service.parseQueryItems()
        except lasso.Error, e:
            pass
        wsp_service.buildResponseMsg()

        try:
            service.processQueryResponseMsg(wsp_service.msgBody)
        except lasso.Error, e:
            if e[0] != lasso.DST_ERROR_QUERY_FAILED:
                self.fail(e)
        else:
             self.fail('response should have a "failed" status because a wrong query item was requested')

    def test19(self):
        """Data service process query response - partial failure"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('not existing attribute', 'not existing attribute')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        wsp_service.data = """<PP xmlns="urn:liberty:id-sis-pp:2005-05">
                <InformalName>User name</InformalName>
                <MsgContact>
                    <MsgAccount>Email account</MsgAccount>
                    <MsgProvider>Email server</MsgProvider>
                </MsgContact>
            </PP>"""

        wsp_service.parseQueryItems()
        wsp_service.buildResponseMsg()

        try:
            service.processQueryResponseMsg(wsp_service.msgBody)
        except lasso.Error, e:
            if e[0] != lasso.DST_ERROR_QUERY_PARTIALLY_FAILED:
                self.fail(e)
        else:
             self.fail('response should have a "partially failed" status because a wrong query item was requested')

    def test20(self):
        """Data service get first attribute"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        wsp_service.data = """<PP xmlns="urn:liberty:id-sis-pp:2005-05">
                <InformalName>User name</InformalName>
                <MsgContact>
                    <MsgAccount>Email account</MsgAccount>
                    <MsgProvider>Email server</MsgProvider>
                </MsgContact>
            </PP>"""

        wsp_service.parseQueryItems()
        wsp_service.buildResponseMsg()

        service.processQueryResponseMsg(wsp_service.msgBody)
        informal_name = service.getAttributeNode()

        self.failUnlessEqual(informal_name, """<pp2:InformalName xmlns="urn:liberty:id-sis-pp:2005-05" xmlns:pp2="urn:liberty:id-sis-pp:2005-05">User name</pp2:InformalName>""", 'first attribute node is wrong')

    def test21(self):
        """Data service get attribute string"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        wsp_service.data = """<PP xmlns="urn:liberty:id-sis-pp:2005-05">
                <InformalName>User name</InformalName>
                <MsgContact>
                    <MsgAccount>Email account</MsgAccount>
                    <MsgProvider>Email server</MsgProvider>
                </MsgContact>
            </PP>"""

        wsp_service.parseQueryItems()
        wsp_service.buildResponseMsg()

        service.processQueryResponseMsg(wsp_service.msgBody)
        informal_name = service.getAttributeString('name')

        self.failUnlessEqual(informal_name, 'User name', 'attribute string is wrong')

    def test22(self):
        """Data service get attribute node"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        wsp_service.data = """<PP xmlns="urn:liberty:id-sis-pp:2005-05">
                <InformalName>User name</InformalName>
                <MsgContact>
                    <MsgAccount>Email account</MsgAccount>
                    <MsgProvider>Email server</MsgProvider>
                </MsgContact>
            </PP>"""

        wsp_service.parseQueryItems()
        wsp_service.buildResponseMsg()

        service.processQueryResponseMsg(wsp_service.msgBody)
        email = service.getAttributeNode('email')

        expected_result = """<pp2:MsgContact xmlns="urn:liberty:id-sis-pp:2005-05" xmlns:pp2="urn:liberty:id-sis-pp:2005-05">.*?<pp2:MsgAccount>Email account</pp2:MsgAccount>.*?<pp2:MsgProvider>Email server</pp2:MsgProvider>.*?</pp2:MsgContact>"""

        import re
        result = re.findall(expected_result, email, re.DOTALL)

        self.failUnless(len(result) == 1, 'attribute node is wrong')

    def test23(self):
        """Data service get attribute node - partial failure"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('not existing attribute', 'not existing attribute')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        wsp_service.data = """<PP xmlns="urn:liberty:id-sis-pp:2005-05">
                <InformalName>User name</InformalName>
                <MsgContact>
                    <MsgAccount>Email account</MsgAccount>
                    <MsgProvider>Email server</MsgProvider>
                </MsgContact>
            </PP>"""

        wsp_service.parseQueryItems()
        wsp_service.buildResponseMsg()

        try:
            service.processQueryResponseMsg(wsp_service.msgBody)
        except lasso.Error, e:
            if e[0] == lasso.DST_ERROR_QUERY_PARTIALLY_FAILED:
                pass
        informal_name = service.getAttributeString('name')
        email = service.getAttributeNode('email')

        self.failUnlessEqual(informal_name, 'User name', 'attribute string is wrong')
        self.failUnlessEqual(email, None, 'attribute node should be None')

    def test24(self):
        """Data service redirect request"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('not existing attribute', 'not existing attribute')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        if '/pp2:PP/pp2:MsgContact' in wsp_service.queryItems:
            wsp_service.initRedirectUserForConsent('http://sp5/consent');
        wsp_service.buildResponseMsg()

        try:
            service.processQueryResponseMsg(wsp_service.msgBody)
        except lasso.Error, e:
            if e[0] != lasso.SOAP_FAULT_REDIRECT_REQUEST:
                self.fail(e)
        else:
            self.fail('a "soap fault redirect request" exception should have been raised')

    def test25(self):
        """Data service redirect request - check redirectUrl"""
        service, wsp = self.getProfileService()
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:InformalName', 'name')
        service.addQueryItem('not existing attribute', 'not existing attribute')
        service.addQueryItem('/pp2:PP/pp2:MsgContact', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        if '/pp2:PP/pp2:MsgContact' in wsp_service.queryItems:
            wsp_service.initRedirectUserForConsent('http://sp5/consent');
        wsp_service.buildResponseMsg()

        try:
            service.processQueryResponseMsg(wsp_service.msgBody)
        except lasso.Error, e:
            if e[0] == lasso.SOAP_FAULT_REDIRECT_REQUEST:
                pass

        self.failUnlessEqual(service.redirectUrl, 'http://sp5/consent', 'redirectUrl is not set or wrong')

    def test26(self):
        """Data service get multiple attribute nodes with the same name"""
        lasso.registerIdWsf2DstService('pp2', 'urn:liberty:id-sis-pp:2005-05')
        service, wsp = self.getProfileService()
        service.initQuery()
        service.addQueryItem('/pp2:PP/pp2:MsgContact/pp2:MsgAccount', 'email')
        service.buildRequestMsg()

        wsp_service = lasso.IdWsf2DataService(wsp)
        wsp_service.processQueryMsg(service.msgBody)

        email1 = 'Email account 1'
        email2 = 'Email account 2'
        wsp_service.data = """<PP xmlns="urn:liberty:id-sis-pp:2005-05">
                <MsgContact>
                    <MsgAccount>%s</MsgAccount>
                </MsgContact>
                <MsgContact>
                    <MsgAccount>%s</MsgAccount>
                </MsgContact>
            </PP>""" % (email1, email2)

        wsp_service.parseQueryItems()
        wsp_service.buildResponseMsg()

        service.processQueryResponseMsg(wsp_service.msgBody)

        email_nodes = service.getAttributeNodes('email')
        self.failUnless(email_nodes[0] ==
            '<pp2:MsgAccount xmlns="urn:liberty:id-sis-pp:2005-05" xmlns:pp2="urn:liberty:id-sis-pp:2005-05">%s</pp2:MsgAccount>' % email1)
        self.failUnless(email_nodes[1] ==
            '<pp2:MsgAccount xmlns="urn:liberty:id-sis-pp:2005-05" xmlns:pp2="urn:liberty:id-sis-pp:2005-05">%s</pp2:MsgAccount>' % email2)

        email_strings = service.getAttributeStrings('email')
        self.failUnless(email_strings[0] == email1)
        self.failUnless(email_strings[1] == email2)


idpSelfRegistrationSuite = unittest.makeSuite(IdpSelfRegistrationTestCase, 'test')
metadataRegisterSuite = unittest.makeSuite(MetadataRegisterTestCase, 'test')
metadataAssociationAddSuite = unittest.makeSuite(MetadataAssociationAddTestCase, 'test')
discoveryQuerySuite = unittest.makeSuite(DiscoveryQueryTestCase, 'test')
dataServiceQuerySuite = unittest.makeSuite(DataServiceQueryTestCase, 'test')

allTests = unittest.TestSuite((idpSelfRegistrationSuite, metadataRegisterSuite,
    metadataAssociationAddSuite, discoveryQuerySuite, dataServiceQuerySuite))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity = 2).run(allTests).wasSuccessful())

