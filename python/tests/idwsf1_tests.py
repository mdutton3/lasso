#! /usr/bin/env python
# -*- coding: UTF-8 -*-
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

wsp_metadata = os.path.join(dataDir, 'sp1-la/metadata.xml')
wsp_private_key = os.path.join(dataDir, 'sp1-la/private-key-raw.pem')
wsp_public_key = os.path.join(dataDir, 'sp1-la/public-key.pem')
wsc_metadata = os.path.join(dataDir, 'sp2-la/metadata.xml')
wsc_private_key = os.path.join(dataDir, 'sp2-la/private-key-raw.pem')
wsc_public_key = os.path.join(dataDir, 'sp2-la/public-key.pem')
idp_metadata = os.path.join(dataDir, 'idp1-la/metadata.xml')
idp_private_key = os.path.join(dataDir, 'idp1-la/private-key-raw.pem')
idp_public_key = os.path.join(dataDir, 'idp1-la/public-key.pem')

abstract_description = "Personal Profile Resource"
resource_id = "http://idp/user/resources/1"

class IdWsf1TestCase(unittest.TestCase):
    def get_wsp_server(self):
        server = lasso.Server(wsp_metadata, wsp_private_key, None, None)
        server.addProvider(lasso.PROVIDER_ROLE_IDP, idp_metadata, idp_public_key, None)
        return server

    def get_wsc_server(self):
        server = lasso.Server(wsc_metadata, wsc_private_key, None, None)
        server.addProvider(lasso.PROVIDER_ROLE_IDP, idp_metadata, idp_public_key, None)
        return server

    def get_idp_server(self):
        server = lasso.Server(idp_metadata, idp_private_key, None, None)
        server.addProvider(lasso.PROVIDER_ROLE_SP, wsp_metadata, wsp_public_key, None)
        server.addProvider(lasso.PROVIDER_ROLE_SP, wsc_metadata, wsc_public_key, None)
        return server

    def add_services(self, idp):
        # Add Discovery service
        disco_description = lasso.DiscoDescription.newWithBriefSoapHttpDescription(
                              lasso.SECURITY_MECH_NULL,
                              "http://idp/discovery/soapEndpoint",
                              "Discovery SOAP Endpoint description");
        disco_service_instance = lasso.DiscoServiceInstance(
                              lasso.DISCO_HREF,
                              "http://idp/providerId",
                              disco_description);
        idp.addService(disco_service_instance);

        # Add Personal Profile service
        pp_description = lasso.DiscoDescription.newWithBriefSoapHttpDescription(
                            lasso.SECURITY_MECH_NULL,
                            "http://idp/pp/soapEndpoint",
                            "Discovery SOAP Endpoint description");
        pp_service_instance = lasso.DiscoServiceInstance(
                                lasso.PP_HREF,
                                "http://idp/providerId",
                                pp_description);
        idp.addService(pp_service_instance);
        return idp

    def login(self, sp, idp):
        sp_login = lasso.Login(sp)
        sp_login.initAuthnRequest(sp.providerIds[0], lasso.HTTP_METHOD_POST)
        sp_login.request.nameIdPolicy = lasso.LIB_NAMEID_POLICY_TYPE_FEDERATED
        sp_login.request.protocolProfile = lasso.LIB_PROTOCOL_PROFILE_BRWS_POST
        sp_login.buildAuthnRequestMsg()
        
        idp_login = lasso.Login(idp)
        idp_login.processAuthnRequestMsg(sp_login.msgBody)
        idp_login.validateRequestMsg(True, True)

        # Set a resource offering in the assertion
        discovery_resource_id = "http://idp/discovery/resources/1"
        idp_login.setResourceId(discovery_resource_id)
        idp_login.buildAssertion(lasso.SAML_AUTHENTICATION_METHOD_PASSWORD, None, None, None, None)
        idp_login.buildAuthnResponseMsg()

        sp_login = lasso.Login(sp)
        sp_login.processAuthnResponseMsg(idp_login.msgBody)
        sp_login.acceptSso()

        return sp_login.identity.dump(), sp_login.session.dump(), idp_login.identity.dump(), idp_login.session.dump()

    def get_pp_service(self):
        self.wsc = self.get_wsc_server()
        self.idp = self.get_idp_server()
        self.idp = self.add_services(self.idp)

        # Login from WSC
        sp_identity_dump, sp_session_dump, idp_identity_dump, idp_session_dump = self.login(self.wsc, self.idp)
        
        # Init discovery query
        wsc_disco = lasso.Discovery(self.wsc)
        wsc_disco.setSessionFromDump(sp_session_dump)
        wsc_disco.initQuery()
        wsc_disco.addRequestedServiceType(lasso.PP_HREF)
        wsc_disco.buildRequestMsg();

        # Process query
        idp_disco = lasso.Discovery(self.idp)
        idp_disco.processQueryMsg(wsc_disco.msgBody)
        idp_disco.setIdentityFromDump(idp_identity_dump)

        # Build resource offering
        service_instance = lasso.DiscoServiceInstance(
                lasso.PP_HREF,
                self.idp.providerId,
                lasso.DiscoDescription_newWithBriefSoapHttpDescription(
                    lasso.SECURITY_MECH_NULL,
                    'http://idp/pp/soapEndpoint'))
        resource_offering = lasso.DiscoResourceOffering(service_instance);
        resource_offering.resourceId = lasso.DiscoResourceID(resource_id)
        resource_offering.abstract = abstract_description
        idp_disco.identity.addResourceOffering(resource_offering)
        idp_disco.buildResponseMsg()

        # Process response
        wsc_disco.processQueryResponseMsg(idp_disco.msgBody);
        return wsc_disco.getService()

    def test01(self):
        '''Test a discovery query'''
        service = self.get_pp_service()
        # Check service attributes
        self.failUnless(service.resourceId is not None)
        self.failUnless(service.resourceId.content == resource_id)
        self.failUnless(service.providerId == self.wsc.providerIds[0])
        self.failUnless(service.abstractDescription == abstract_description)

    def test02(self):
        '''Test a data service query'''
        wsc_service = self.get_pp_service()
        wsc_service.initQuery('/pp:PP/pp:InformalName', 'name')
        wsc_service.buildRequestMsg()
        self.failUnless(lasso.getRequestTypeFromSoapMsg(wsc_service.msgBody)
                        == lasso.REQUEST_TYPE_DST_QUERY)

        self.wsp = self.get_wsp_server()
        wsp_service = lasso.DataService(self.wsp)
        wsp_service.processQueryMsg(wsc_service.msgBody)
        wsp_service.resourceData = '''
        <PP xmlns="urn:liberty:id-sis-pp:2003-08">
                <InformalName>Damien</InformalName>
        </PP>'''
        wsp_service.buildResponseMsg()

        wsc_service.processQueryResponseMsg(wsp_service.msgBody)
        self.failUnless(wsc_service.getAnswer('/pp:PP/pp:InformalName') ==
                '<InformalName xmlns="urn:liberty:id-sis-pp:2003-08">Damien</InformalName>')

    def test03(self):
        '''Test a data service modify'''
        wsc_service = self.get_pp_service()

        xpath = '/pp:PP/pp:InformalName'
        old_data = '''
            <PP xmlns="urn:liberty:id-sis-pp:2003-08">
                <InformalName>Damien</InformalName>
            </PP>'''
        new_data = '<InformalName>Alain</InformalName>'

        new_full_data = '''<PP xmlns="urn:liberty:id-sis-pp:2003-08">
                <pp:InformalName xmlns:pp="urn:liberty:id-sis-pp:2003-08">Alain</pp:InformalName>
            </PP>'''

        wsc_service.initModify(xpath, new_data)
        wsc_service.buildRequestMsg()
        self.failUnless(lasso.getRequestTypeFromSoapMsg(wsc_service.msgBody)
                        == lasso.REQUEST_TYPE_DST_MODIFY)

        self.wsp = self.get_wsp_server()
        wsp_service = lasso.DataService(self.wsp)
        wsp_service.processModifyMsg(wsc_service.msgBody)
        wsp_service.resourceData = old_data
        wsp_service.buildModifyResponseMsg()
        # Save the new wsp_service.resourceData here

        self.failUnless(wsp_service.resourceData == new_full_data)

        wsc_service.processModifyResponseMsg(wsp_service.msgBody)

    def test10(self):
        '''Test a data service modify - root element'''
        wsc_service = self.get_pp_service()

        xpath = '/pp:PP'
        old_data = '''
            <PP xmlns="urn:liberty:id-sis-pp:2003-08">
                <InformalName>Damien</InformalName>
            </PP>'''
        new_data = '''<PP xmlns="urn:liberty:id-sis-pp:2003-08">
                <InformalName>Alain</InformalName>
            </PP>'''

        new_full_data = '''<PP xmlns="urn:liberty:id-sis-pp:2003-08">
                <InformalName>Alain</InformalName>
            </PP>'''

        wsc_service.initModify(xpath, new_data)
        wsc_service.buildRequestMsg()
 
        self.failUnless(lasso.getRequestTypeFromSoapMsg(wsc_service.msgBody)
                        == lasso.REQUEST_TYPE_DST_MODIFY)

        self.wsp = self.get_wsp_server()
        wsp_service = lasso.DataService(self.wsp)
        wsp_service.processModifyMsg(wsc_service.msgBody)
        wsp_service.resourceData = old_data
        wsp_service.buildModifyResponseMsg()
        # Save the new wsp_service.resourceData here

        self.failUnless(wsp_service.resourceData == new_full_data)

        wsc_service.processModifyResponseMsg(wsp_service.msgBody)
        

idWsf1Suite = unittest.makeSuite(IdWsf1TestCase, 'test')

allTests = unittest.TestSuite((idWsf1Suite))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity = 2).run(allTests).wasSuccessful())
