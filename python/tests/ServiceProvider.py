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


class ServiceProvider(Provider):
    idpSite = None # The identity provider, this service provider will use to authenticate users.

    def assertionConsumer(self, httpRequest):
        server = self.getServer()
        login = lasso.Login.new(server)
        responseQuery = self.extractQueryFromUrl(httpRequest.url)
        login.init_request(responseQuery, lasso.httpMethodRedirect)
        login.build_request_msg()

        soapEndpoint = login.msg_url
        self.failUnless(soapEndpoint)
        soapRequestMsg = login.msg_body
        self.failUnless(soapRequestMsg)
        httpResponse = HttpRequest(self, 'POST', soapEndpoint, body = soapRequestMsg).ask()
        self.failUnlessEqual(httpResponse.statusCode, 200)
        try:
            login.process_response_msg(httpResponse.body)
        except lasso.Error, error:
            if error.code == -7: # FIXME: This will change, he said.
                return HttpResponse(
                    401, 'Access Unauthorized: User authentication failed on identity provider.')
            else:
                raise
        nameIdentifier = login.nameIdentifier
        self.failUnless(nameIdentifier)

        # Retrieve session dump, using name identifier or else try to use the client web session.
        # If session dump exists, give it to Lasso, so that it updates it.
        webSession = self.getWebSessionFromNameIdentifier(nameIdentifier)
        if webSession is None:
            webSession = self.getWebSession(httpRequest.client)
        if webSession is not None:
            sessionDump = webSession.sessionDump
            if sessionDump is not None:
                login.set_session_from_dump(sessionDump)
        # Retrieve identity dump, using name identifier or else try to retrieve him from web
        # session. If identity dump exists, give it to Lasso, so that it updates it.
        webUser = self.getWebUserFromNameIdentifier(nameIdentifier)
        if webUser is None:
            webUser = self.getWebUserFromWebSession(webSession)
        if webUser is not None:
            identityDump = webUser.identityDump
            if identityDump is not None:
                login.set_identity_from_dump(identityDump)

        login.accept_sso()
        if webUser is not None and identityDump is None:
            self.failUnless(login.is_identity_dirty())
        identity = login.get_identity()
        self.failUnless(identity)
        identityDump = identity.dump()
        self.failUnless(identityDump)
        self.failUnless(login.is_session_dirty())
        session = login.get_session()
        self.failUnless(session)
        sessionDump = session.dump()
        self.failUnless(sessionDump)

        # User is now authenticated.

        # If there was no web session yet, create it. Idem for the web user account.
        if webSession is None:
            webSession = self.createWebSession(httpRequest.client)
        if webUser is None:
            # A real service provider would ask user to login locally to create federation. Or it
            # would ask user informations to create a local account.
            webUserId = httpRequest.client.keyring.get(self.url, None)
            userAuthenticated = webUserId in self.webUsers
            if not userAuthenticated:
                return HttpResponse(401, 'Access Unauthorized: User has no account.')
            webSession.webUserId = webUserId
            webUser = self.webUsers[webUserId]

        # Store the updated identity dump and session dump.
        if login.is_identity_dirty():
            webUser.identityDump = identityDump
        webSession.sessionDump = sessionDump
        self.webUserIdsByNameIdentifier[nameIdentifier] = webUser.uniqueId
        self.webSessionIdsByNameIdentifier[nameIdentifier] = webSession.uniqueId

        return HttpResponse(200)

    def loginUsingRedirect(self, httpRequest):
        server = self.getServer()
        login = lasso.Login.new(server)
        login.init_authn_request(self.idpSite.providerId)
        self.failUnlessEqual(login.request_type, lasso.messageTypeAuthnRequest)
        login.request.set_isPassive(False)
        login.request.set_nameIDPolicy(lasso.libNameIDPolicyTypeFederated)
        login.request.set_consent(lasso.libConsentObtained)
        relayState = 'fake'
        login.request.set_relayState(relayState)
        login.build_authn_request_msg()
        authnRequestUrl = login.msg_url
        self.failUnless(authnRequestUrl)
        return httpRequest.client.redirect(authnRequestUrl)

    def logoutUsingSoap(self, httpRequest):
        webSession = self.getWebSession(httpRequest.client)
        if webSession is None:
            return HttpResponse(401, 'Access Unauthorized: User has no session opened.')
        webUser = self.getWebUserFromWebSession(webSession)
        if webUser is None:
            return HttpResponse(401, 'Access Unauthorized: User is not logged in.')

        server = self.getServer()
        logout = lasso.Logout.new(server, lasso.providerTypeSp)
        identityDump = self.getIdentityDump(httpRequest.client)
        if identityDump is not None:
            logout.set_identity_from_dump(identityDump)
        sessionDump = self.getSessionDump(httpRequest.client)
        if sessionDump is not None:
            logout.set_session_from_dump(sessionDump)
        logout.init_request()
        logout.build_request_msg()

        soapEndpoint = logout.msg_url
        self.failUnless(soapEndpoint)
        soapRequestMsg = logout.msg_body
        self.failUnless(soapRequestMsg)
        httpResponse = HttpRequest(self, 'POST', soapEndpoint, body = soapRequestMsg).ask()
        self.failUnlessEqual(httpResponse.statusCode, 200)

        logout.process_response_msg(httpResponse.body, lasso.httpMethodSoap)
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

        return HttpResponse(200)
