# -*- coding: UTF-8 -*-


# Lasso Simulator
# By: Emmanuel Raviart <eraviart@entrouvert.com>
#
# Copyright (C) 2004 Entr'ouvert
# http://lasso.entrouvert.org
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


import lasso

from Provider import Provider
from websimulator import *


class ServiceProvider(Provider):
    idpSite = None # The identity provider, this service provider will use to authenticate users.

    def assertionConsumer(self, handler):
        lassoServer = self.getLassoServer()
        login = lasso.Login.new(lassoServer)

        if handler.httpRequest.method == 'GET':
            login.init_request(handler.httpRequest.query, lasso.httpMethodRedirect)
            login.build_request_msg()

            soapEndpoint = login.msg_url
            failUnless(soapEndpoint)
            soapRequestMsg = login.msg_body
            failUnless(soapRequestMsg)
            httpResponse = self.sendHttpRequest(
                'POST', soapEndpoint, headers = {'Content-Type': 'text/xml'},
                body = soapRequestMsg)
            failUnlessEqual(httpResponse.statusCode, 200)
            try:
                login.process_response_msg(httpResponse.body)
            except lasso.Error, error:
                if error.code == -7: # FIXME: This will change, he said.
                    return handler.respond(
                        401,
                        'Access Unauthorized: User authentication failed on identity provider.')
                else:
                    raise
        elif handler.httpRequest.method == 'POST':
            authnResponseMsg = handler.httpRequest.getFormField('LARES', None)
            failUnless(authnResponseMsg)
            # FIXME: Should we do an init before process_authn_response_msg?
            try:
                login.process_authn_response_msg(authnResponseMsg)
            except lasso.Error, error:
                if error.code == -7: # FIXME: This will change, he said.
                    return handler.respond(
                        401,
                        'Access Unauthorized: User authentication failed on identity provider.')
                else:
                    raise
        else:
            return handler.respond(
                400,
                'Bad Request: Method %s not handled by assertionConsumer'
                    % handler.httpRequest.method)

        nameIdentifier = login.nameIdentifier
        failUnless(nameIdentifier)

        # Retrieve session dump, using name identifier or else try to use the client web session.
        # If session dump exists, give it to Lasso, so that it updates it.
        session = self.getSessionFromNameIdentifier(nameIdentifier)
        if session is None:
            session = handler.session
        if session is not None and session.lassoSessionDump is not None:
            login.set_session_from_dump(session.lassoSessionDump)
        # Retrieve identity dump, using name identifier or else try to retrieve him from web
        # session. If identity dump exists, give it to Lasso, so that it updates it.
        user = self.getUserFromNameIdentifier(nameIdentifier)
        if user is None:
            user = handler.user
        if user is not None and user.lassoIdentityDump is not None:
            login.set_identity_from_dump(user.lassoIdentityDump)

        login.accept_sso()
        if user is not None and user.lassoIdentityDump is None:
            failUnless(login.is_identity_dirty())
        lassoIdentity = login.get_identity()
        failUnless(lassoIdentity)
        lassoIdentityDump = lassoIdentity.dump()
        failUnless(lassoIdentityDump)
        failUnless(login.is_session_dirty())
        lassoSession = login.get_session()
        failUnless(lassoSession)
        lassoSessionDump = lassoSession.dump()
        failUnless(lassoSessionDump)

        # User is now authenticated.

        # If there was no web session yet, create it. Idem for the web user account.
        if session is None:
            session = handler.createSession()
        if user is None:
            # A real service provider would ask user to login locally to create federation. Or it
            # would ask user informations to create a local account.
            userId = handler.httpRequest.client.keyring.get(self.url, None)
            userAuthenticated = userId in self.users
            if not userAuthenticated:
                return handler.respond(401, 'Access Unauthorized: User has no account.')
            user = self.users[userId]

        session.userId = user.uniqueId

        # Store the updated identity dump and session dump.
        if login.is_identity_dirty():
            user.lassoIdentityDump = lassoIdentityDump
        session.lassoSessionDump = lassoSessionDump

        self.userIdsByNameIdentifier[nameIdentifier] = user.uniqueId
        self.sessionTokensByNameIdentifier[nameIdentifier] = session.token

        return handler.respond()

    def login(self, handler):
        libertyEnabled = handler.httpRequest.headers.get('Liberty-Enabled', None)
        userAgent = handler.httpRequest.headers.get('User-Agent', None)
        # FIXME: Lasso should have a function to compute useLecp.
        # Or this should be done in lasso.Login.new(lassoServer, libertyEnabled, userAgent)
        useLecp = False
        if libertyEnabled:
            useLecp = 'urn:liberty:iff:2003-08' in libertyEnabled
            if not useLecp:
                return handler.respond(501, 'Unsupported Liberty Version.')
        elif userAgent:
            useLecp = 'urn:liberty:iff:2003-08' in userAgent
            if not useLecp and "LIBV=" in userAgent:
                return handler.respond(501, 'Unsupported Liberty Version.')
        else:
            useLecp = False

        forceAuthn = handler.httpRequest.getQueryBoolean('forceAuthn', False)
        isPassive = handler.httpRequest.getQueryBoolean('isPassive', False)
        lassoServer = self.getLassoServer()
        if useLecp:
            lecp = lasso.Lecp.new(lassoServer)
            lecp.init_authn_request()
            failUnlessEqual(lecp.request_type, lasso.messageTypeAuthnRequest)

            # FIXME: This protocol profile should be set by default by Lasso.
            lecp.request.set_protocolProfile(lasso.libProtocolProfileBrwsPost)

            # Same treatement as for non LECP login.
            if forceAuthn:
                lecp.request.set_forceAuthn(forceAuthn)
            if not isPassive:
                lecp.request.set_isPassive(isPassive)
            lecp.request.set_nameIDPolicy(lasso.libNameIDPolicyTypeFederated)
            lecp.request.set_consent(lasso.libConsentObtained)
            relayState = 'fake'
            lecp.request.set_relayState(relayState)

            lecp.build_authn_request_envelope_msg()
            authnRequestEnvelopeMsg = lecp.msg_body
            failUnless(authnRequestEnvelopeMsg)
            # FIXME: Lasso should set a lecp.msg_content_type to
            # "application/vnd.liberty-request+xml". This should also be done for SOAP, etc, with
            # other profiles.
            # contentType = lecp.msg_content_type
            # failUnlessEqual(contentType, 'application/vnd.liberty-request+xml')
            contentType = 'application/vnd.liberty-request+xml'
            return handler.respond(
                headers = {
                    'Content-Type': contentType,
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache',
                    },
                body = authnRequestEnvelopeMsg)
        else:
            login = lasso.Login.new(lassoServer)
            login.init_authn_request()
            failUnlessEqual(login.request_type, lasso.messageTypeAuthnRequest)
            if forceAuthn:
                login.request.set_forceAuthn(forceAuthn)
            if not isPassive:
                login.request.set_isPassive(isPassive)
            login.request.set_nameIDPolicy(lasso.libNameIDPolicyTypeFederated)
            login.request.set_consent(lasso.libConsentObtained)
            relayState = 'fake'
            login.request.set_relayState(relayState)
            login.build_authn_request_msg(self.idpSite.providerId)
            authnRequestUrl = login.msg_url
            failUnless(authnRequestUrl)
            return handler.respondRedirectTemporarily(authnRequestUrl)

    def logoutUsingSoap(self, handler):
        session = handler.session
        if session is None:
            return handler.respond(401, 'Access Unauthorized: User has no session opened.')
        user = handler.user
        if user is None:
            return handler.respond(401, 'Access Unauthorized: User is not logged in.')

        lassoServer = self.getLassoServer()
        logout = lasso.Logout.new(lassoServer, lasso.providerTypeSp)
        if user.lassoIdentityDump is not None:
            logout.set_identity_from_dump(user.lassoIdentityDump)
        if session.lassoSessionDump is not None:
            logout.set_session_from_dump(session.lassoSessionDump)
        logout.init_request()
        logout.build_request_msg()

        soapEndpoint = logout.msg_url
        failUnless(soapEndpoint)
        soapRequestMsg = logout.msg_body
        failUnless(soapRequestMsg)
        httpResponse = self.sendHttpRequest(
            'POST', soapEndpoint, headers = {'Content-Type': 'text/xml'}, body = soapRequestMsg)
        failUnlessEqual(httpResponse.statusCode, 200)

        logout.process_response_msg(httpResponse.body, lasso.httpMethodSoap)
        failIf(logout.is_identity_dirty())
        identity = logout.get_identity()
        failUnless(identity)
        lassoIdentityDump = identity.dump()
        failUnless(lassoIdentityDump)
        failUnless(logout.is_session_dirty())
        lassoSession = logout.get_session()
        if lassoSession is None:
            # The user is no more authenticated on any identity provider. Log him out.
            del session.lassoSessionDump
            del session.userId
            # We also delete the session, but it is not mandantory, since the user is logged out
            # anyway.
            del self.sessions[session.token] 
        else:
            # The user is still logged in on some other identity providers.
            lassoSessionDump = lassoSession.dump()
            failUnless(lassoSessionDump)
            session.lassoSessionDump = lassoSessionDump
        nameIdentifier = logout.nameIdentifier
        failUnless(nameIdentifier)
        del self.sessionTokensByNameIdentifier[nameIdentifier]

        return handler.respond()
