# -*- coding: UTF-8 -*-


# Python Lasso Simulator
#
# Copyright (C) 2004 Entr'ouvert
# http://lasso.entrouvert.org
# 
# Author: Emmanuel Raviart <eraviart@entrouvert.com>
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
# FIXME: Replace principal with client in most methods.
# FIXME: Rename webUser to userAccount.


import lasso

from Provider import Provider
from websimulator import *


class IdentityProvider(Provider):
    soapResponseMsgs = None

    def __init__(self, test, internet, url):
        Provider.__init__(self, test, internet, url)
        self.soapResponseMsgs = {}

    def singleSignOn(self, httpRequest):
        server = self.getServer()
        login = lasso.Login.new(server)
        identityDump = self.getIdentityDump(httpRequest.client)
        if identityDump is not None:
            login.set_identity_from_dump(identityDump)
        sessionDump = self.getSessionDump(httpRequest.client)
        if sessionDump is not None:
            login.set_session_from_dump(sessionDump)
        authnRequestQuery = self.extractQueryFromUrl(httpRequest.url)
        login.init_from_authn_request_msg(authnRequestQuery, lasso.httpMethodRedirect)

        self.failUnless(login.must_authenticate()) # FIXME: To improve.
        webSession = self.getWebSession(httpRequest.client)
        if webSession is None:
            webSession = self.createWebSession(httpRequest.client)
        webSession.loginDump = login.dump()

        # A real identity provider using a HTML form to ask user's login & password would store
        # idpLoginDump in a session variable and display the HTML login form.
        webUserId = httpRequest.client.keyring.get(self.url, None)
        userAuthenticated = webUserId in self.webUsers
        if userAuthenticated:
            webSession.webUserId = webUserId
        authenticationMethod = lasso.samlAuthenticationMethodPassword # FIXME

        server = self.getServer()
        webSession = self.getWebSession(httpRequest.client)
        loginDump = webSession.loginDump
        del webSession.loginDump
        login = lasso.Login.new_from_dump(server, loginDump)
        # Set identity & session in login, because loginDump doesn't contain them.
        identityDump = self.getIdentityDump(httpRequest.client)
        if identityDump is not None:
            login.set_identity_from_dump(identityDump)
        sessionDump = self.getSessionDump(httpRequest.client)
        if sessionDump is not None:
            login.set_session_from_dump(sessionDump)
        self.failUnlessEqual(login.protocolProfile, lasso.loginProtocolProfileBrwsArt) # FIXME
        login.build_artifact_msg(
            userAuthenticated, authenticationMethod, "FIXME: reauthenticateOnOrAfter",
            lasso.httpMethodRedirect)
        webUser = self.getWebUserFromWebSession(webSession)
        if login.is_identity_dirty():
            identityDump = login.get_identity().dump()
            self.failUnless(identityDump)
            webUser.identityDump = identityDump
        self.failUnless(login.is_session_dirty())
        sessionDump = login.get_session().dump()
        self.failUnless(sessionDump)
        webSession.sessionDump = sessionDump
        nameIdentifier = login.nameIdentifier
        self.failUnless(nameIdentifier)
        self.webUserIdsByNameIdentifier[nameIdentifier] = webUser.uniqueId
        self.webSessionIdsByNameIdentifier[nameIdentifier] = webSession.uniqueId
        artifact = login.assertionArtifact
        self.failUnless(artifact)
        soapResponseMsg = login.response_dump
        self.failUnless(soapResponseMsg)
        self.soapResponseMsgs[artifact] = soapResponseMsg
        responseUrl = login.msg_url
        self.failUnless(responseUrl)
        return httpRequest.client.redirect(responseUrl)
        
    def soapEndpoint(self, httpRequest):
        soapRequestMsg = httpRequest.body
        requestType = lasso.get_request_type_from_soap_msg(soapRequestMsg)
        if requestType == lasso.requestTypeLogin:
            server = self.getServer()
            login = lasso.Login.new(server)
            login.process_request_msg(soapRequestMsg)
            artifact = login.assertionArtifact
            self.failUnless(artifact)
            soapResponseMsg = self.soapResponseMsgs.get(artifact, None)
            if soapResponseMsg is None:
                raise Exception("FIXME: Handle the case when artifact is wrong")
            return HttpResponse(200, body = soapResponseMsg)
        elif requestType == lasso.requestTypeLogout:
            server = self.getServer()
            logout = lasso.Logout.new(server, lasso.providerTypeIdp)
            logout.process_request_msg(soapRequestMsg, lasso.httpMethodSoap)
            nameIdentifier = logout.nameIdentifier
            self.failUnless(nameIdentifier)

            # Retrieve session dump and identity dump using name identifier.
            webSession = self.getWebSessionFromNameIdentifier(nameIdentifier)
            if webSession is None:
                raise Exception("FIXME: Handle the case when there is no web session")
            sessionDump = webSession.sessionDump
            if sessionDump is None:
                raise Exception(
                    "FIXME: Handle the case when there is no session dump in web session")
            logout.set_session_from_dump(sessionDump)
            webUser = self.getWebUserFromNameIdentifier(nameIdentifier)
            if webUser is None:
                raise Exception("FIXME: Handle the case when there is no web user")
            identityDump = webUser.identityDump
            if identityDump is None:
                raise Exception(
                    "FIXME: Handle the case when there is no identity dump in web user")
            logout.set_identity_from_dump(identityDump)

            logout.validate_request()
            self.failIf(logout.is_identity_dirty())
            identity = logout.get_identity()
            self.failUnless(identity)
            identityDump = identity.dump()
            self.failUnless(identityDump)
            self.failUnless(logout.is_session_dirty())
            session = logout.get_session()
            if session is None:
                del webSession.sessionDump
            else:
                sessionDump = session.dump()
                self.failUnless(sessionDump)
                webSession.sessionDump = sessionDump
            nameIdentifier = logout.nameIdentifier
            self.failUnless(nameIdentifier)
            del self.webSessionIdsByNameIdentifier[nameIdentifier]

            # Tell each other service provider to logout the user.
            otherProviderId = logout.get_next_providerID()
            while otherProviderId is not None:
                logout.init_request(otherProviderId)
                logout.build_request_msg()

                soapEndpoint = logout.msg_url
                self.failUnless(soapEndpoint)
                soapRequestMsg = logout.msg_body
                self.failUnless(soapRequestMsg)
                httpResponse = HttpRequest(self, "POST", soapEndpoint, body = soapRequestMsg).ask()
                self.failUnlessEqual(httpResponse.statusCode, 200)
                logout.process_response_msg(httpResponse.body, lasso.httpMethodSoap)

                otherProviderId = logout.get_next_providerID()

            logout.build_response_msg()
            soapResponseMsg = logout.msg_body
            self.failUnless(soapResponseMsg)
            return HttpResponse(200, body = soapResponseMsg)
        else:
            raise Exception("Unknown request type: %s" % requestType)
