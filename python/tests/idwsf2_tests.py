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
    dataDir = '../../tests/data'


class IdpSelfRegistrationTestCase(unittest.TestCase):
    def getIdpServer(self):
        idp_metadata = os.path.join(dataDir, 'idp5-saml2/metadata.xml')
        idp_private_key = os.path.join(dataDir, 'idp5-saml2/private-key.pem')

        server = lasso.Server(idp_metadata, idp_private_key, None, None)
        
        return server

    def test01(self):
        """Register IdP as Dicovery Service and get a random svcMDID"""

        disco = lasso.IdWsf2Discovery(self.getIdpServer())

        service_type = lasso.IDWSF2_DISCO_HREF
        abstract = 'Disco service'
        soapEndpoint = 'http://idp1/soapEndpoint'

        svcMDID = disco.metadataRegisterSelf(service_type, abstract, soapEndpoint)

        self.failUnless(svcMDID, 'missing svcMDID')

    def test02(self):
        """Register IdP as Dicovery Service with a given svcMDID"""

        disco = lasso.IdWsf2Discovery(self.getIdpServer())

        service_type = lasso.IDWSF2_DISCO_HREF
        abstract = 'Disco service'
        soapEndpoint = 'http://idp1/soapEndpoint'
        mySvcMDID = 'RaNdOm StRiNg'

        svcMDID = disco.metadataRegisterSelf(service_type, abstract, soapEndpoint, mySvcMDID)

        self.failUnless(svcMDID, 'missing svcMDID')
        self.failUnlessEqual(svcMDID, mySvcMDID, 'wrong svcMDID')

    def test03(self):
        """Register IdP as Dicovery Service with wrong parameters"""

        disco = lasso.IdWsf2Discovery(self.getIdpServer())

        service_type = None
        abstract = 'Disco service'
        soapEndpoint = 'http://idp1/soapEndpoint'

        svcMDID = disco.metadataRegisterSelf(service_type, abstract, soapEndpoint)

        self.failUnless(svcMDID is None, 'svcMDID should not be set')


class MetadataRegisterTestCase(unittest.TestCase):
    def getWspServer(self):
        wsp_metadata = os.path.join(dataDir, 'sp5-saml2/metadata.xml')
        wsp_private_key = os.path.join(dataDir, 'sp5-saml2/private-key.xml')
        idp_metadata = os.path.join(dataDir, 'idp5-saml2/metadata.xml')

        server = lasso.Server(wsp_metadata, wsp_private_key, None, None)
        server.addProvider(lasso.PROVIDER_ROLE_IDP, idp_metadata, None, None)

        return server;

    def getWscServer(self):
        wsc_metadata = os.path.join(dataDir, 'sp6-saml2/metadata.xml')
        wsc_private_key = os.path.join(dataDir, 'sp6-saml2/private-key.xml')
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
            server.addProvider(lasso.PROVIDER_ROLE_SP, wsc_metadata, None, None)
            self.idp_server_dump = server.dump()
        
        return server

    def idpRegisterSelf(self, idp_server):
        disco = lasso.IdWsf2Discovery(idp_server)

        service_type = lasso.IDWSF2_DISCO_HREF
        abstract = 'Disco service'
        soapEndpoint = 'http://idp1/soapEndpoint'

        svcMDID = disco.metadataRegisterSelf(service_type, abstract, soapEndpoint)

        self.idp_server_dump = idp_server.dump()

    def test01(self):
        """Register service metadatas"""

        idp = self.getIdpServer()
        self.idpRegisterSelf(idp)
        idp = self.getIdpServer()
        
        wsp = self.getWspServer()

        disco = lasso.IdWsf2Discovery(wsp)

        abstract = 'Personal Profile service'
        soapEndpoint = 'http://idp1/soapEndpoint'
        try:
            disco.initMetadataRegister(
                'urn:liberty:id-sis-pp:2005-05', abstract, wsp.providerIds[0], soapEndpoint)
        except lasso.Error, e:
            self.fail(e)

        disco.buildRequestMsg()

        # FIXME : set msgUrl
#        self.failUnless(disco.msgUrl, 'msgUrl should be set')

        soap_msg = disco.msgBody
        self.failUnless(soap_msg, 'missing soap message')

        request_type = lasso.getRequestTypeFromSoapMsg(soap_msg)
        self.failUnlessEqual(request_type, lasso.REQUEST_TYPE_IDWSF2_DISCO_SVCMD_REGISTER,
            'wrong request type in metadata_register : %s' % request_type)

        idp_disco = lasso.IdWsf2Discovery(idp)
        idp_disco.processMetadataRegisterMsg(soap_msg)
        self.idp_server_dump = idp.dump()

        self.failUnless(idp_disco.metadata.dump(), 'missing registered metadata')

        idp_disco.buildResponseMsg()
        soap_answer = idp_disco.msgBody

        self.failUnless(soap_answer, 'missing soap answer')

        disco.processMetadataRegisterResponseMsg(soap_answer)

        svcMDID = disco.svcMDID
        self.failUnless(svcMDID, 'missing svcMDID')

        #self.services[service_type] = svcMDID


idpSelfRegistrationSuite = unittest.makeSuite(IdpSelfRegistrationTestCase, 'test')
metadataRegisterSuite = unittest.makeSuite(MetadataRegisterTestCase, 'test')

allTests = unittest.TestSuite((idpSelfRegistrationSuite, metadataRegisterSuite))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity = 2).run(allTests).wasSuccessful())

