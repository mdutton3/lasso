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


class IdentityProvider(Provider):
    soapResponseMsgs = None

    def __init__(self, internet, url):
        Provider.__init__(self, internet, url)
        self.soapResponseMsgs = {}

    def singleSignOn(self, handler):
        lassoServer = self.getLassoServer()
        if handler.httpRequest.method == 'GET':
            # Single sign-on using HTTP redirect.
            login = lasso.Login.new(lassoServer)
            session = handler.session
            user = None
            if session is not None:
                if session.lassoSessionDump is not None:
                    login.set_session_from_dump(session.lassoSessionDump)
                user = self.getUserFromSession(session)
                if user is not None and user.lassoIdentityDump is not None:
                    login.set_identity_from_dump(user.lassoIdentityDump)
            login.init_from_authn_request_msg(handler.httpRequest.query, lasso.httpMethodRedirect)

            if not login.must_authenticate():
                userAuthenticated = user is not None
                authenticationMethod = lasso.samlAuthenticationMethodPassword # FIXME
                return self.singleSignOn_part2(
                    handler, login, session, user, userAuthenticated, authenticationMethod)

            if session is None:
                session = self.createSession(handler.httpRequest.client)
            session.loginDump = login.dump()

            # A real identity provider using a HTML form to ask user's login & password would store
            # idpLoginDump in a session variable and display the HTML login form.
            userId = handler.httpRequest.client.keyring.get(self.url, None)
            userAuthenticated = userId in self.users
            if userAuthenticated:
                session.userId = userId
            authenticationMethod = lasso.samlAuthenticationMethodPassword # FIXME

            lassoServer = self.getLassoServer()
            session = handler.session
            loginDump = session.loginDump
            del session.loginDump
            login = lasso.Login.new_from_dump(lassoServer, loginDump)
            # Set identity & session in login, because loginDump doesn't contain them.
            if session.lassoSessionDump is not None:
                login.set_session_from_dump(session.lassoSessionDump)
            user = self.getUserFromSession(session)
            if user is not None and user.lassoIdentityDump is not None:
                login.set_identity_from_dump(user.lassoIdentityDump)

            return self.singleSignOn_part2(
                handler, login, session, user, userAuthenticated, authenticationMethod)
        elif handler.httpRequest.method == 'POST' \
               and handler.httpRequest.headers.get('Content-Type', None) == 'text/xml':
            # SOAP request => LECP single sign-on.
            lecp = lasso.Lecp.new(lassoServer)
            session = handler.session
            user = None
            if session is not None:
                if session.lassoSessionDump is not None:
                    lecp.set_session_from_dump(session.lassoSessionDump)
                user = self.getUserFromSession(session)
                if user is not None and user.lassoIdentityDump is not None:
                    lecp.set_identity_from_dump(user.lassoIdentityDump)
            lecp.init_from_authn_request_msg(handler.httpRequest.body, lasso.httpMethodSoap)
            # FIXME: lecp.must_authenticate() should always return False.
            # The other solution is that we are able to not call lecp.must_authenticate()
            # failIf(lecp.must_authenticate())
            userAuthenticated = user is not None
            authenticationMethod = lasso.samlAuthenticationMethodPassword # FIXME
            # FIXME: It is very very strange that we don't provide userAuthenticated,
            # authenticationMethod, reauthenticateOnOrAfter' to lecp before or when build response.
            lecp.build_authn_response_envelope_msg(
                userAuthenticated, authenticationMethod, 'FIXME: reauthenticateOnOrAfter')
            soapResponseMsg = lecp.msg_body
            failUnless(soapResponseMsg)
            # FIXME: Lasso should set a lecp.msg_content_type to
            # "application/vnd.liberty-response+xml". This should also be done for SOAP, etc, with
            # other profiles.
            # contentType = lecp.msg_content_type
            # failUnlessEqual(contentType, 'application/vnd.liberty-response+xml')
            contentType = 'application/vnd.liberty-response+xml'
            return handler.respond(
                headers = {
                    'Content-Type': contentType,
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache',
                    },
                body = soapResponseMsg)
        else:
            return handler.respond(
                400,
                'Bad Request: Method %s not handled by singleSignOn' % handler.httpRequest.method)

    def singleSignOn_part2(self, handler, login, session, user, userAuthenticated,
                           authenticationMethod):
        failUnlessEqual(login.protocolProfile, lasso.loginProtocolProfileBrwsArt) # FIXME
        login.build_artifact_msg(
            userAuthenticated, authenticationMethod, 'FIXME: reauthenticateOnOrAfter',
            lasso.httpMethodRedirect)
        if userAuthenticated:
            if login.is_identity_dirty():
                lassoIdentityDump = login.get_identity().dump()
                failUnless(lassoIdentityDump)
                user.lassoIdentityDump = lassoIdentityDump
            failUnless(login.is_session_dirty())
            lassoSessionDump = login.get_session().dump()
            failUnless(lassoSessionDump)
            session.lassoSessionDump = lassoSessionDump
            nameIdentifier = login.nameIdentifier
            failUnless(nameIdentifier)
            self.userIdsByNameIdentifier[nameIdentifier] = user.uniqueId
            self.sessionTokensByNameIdentifier[nameIdentifier] = session.token
        else:
            failIf(login.is_identity_dirty())
            failIf(login.is_session_dirty())
        artifact = login.assertionArtifact
        failUnless(artifact)
        soapResponseMsg = login.response_dump
        failUnless(soapResponseMsg)
        self.soapResponseMsgs[artifact] = soapResponseMsg
        responseUrl = login.msg_url
        failUnless(responseUrl)
        return handler.respondRedirectTemporarily(responseUrl)
        
    def soapEndpoint(self, handler):
        soapRequestMsg = handler.httpRequest.body
        requestType = lasso.get_request_type_from_soap_msg(soapRequestMsg)
        if requestType == lasso.requestTypeLogin:
            lassoServer = self.getLassoServer()
            login = lasso.Login.new(lassoServer)
            login.process_request_msg(soapRequestMsg)
            artifact = login.assertionArtifact
            failUnless(artifact)
            soapResponseMsg = self.soapResponseMsgs.get(artifact, None)
            if soapResponseMsg is None:
                raise Exception('FIXME: Handle the case when artifact is wrong')
            return handler.respond(
                headers = {'Content-Type': 'text/xml'}, body = soapResponseMsg)
        elif requestType == lasso.requestTypeLogout:
            lassoServer = self.getLassoServer()
            logout = lasso.Logout.new(lassoServer, lasso.providerTypeIdp)
            logout.process_request_msg(soapRequestMsg, lasso.httpMethodSoap)
            nameIdentifier = logout.nameIdentifier
            failUnless(nameIdentifier)

            # Retrieve session dump and identity dump using name identifier.
            session = self.getSessionFromNameIdentifier(nameIdentifier)
            if session is None:
                raise Exception('FIXME: Handle the case when there is no web session')
            lassoSessionDump = session.lassoSessionDump
            if lassoSessionDump is None:
                raise Exception(
                    'FIXME: Handle the case when there is no session dump in web session')
            logout.set_session_from_dump(lassoSessionDump)
            user = self.getUserFromNameIdentifier(nameIdentifier)
            if user is None:
                raise Exception('FIXME: Handle the case when there is no web user')
            lassoIdentityDump = user.lassoIdentityDump
            if lassoIdentityDump is None:
                raise Exception(
                    'FIXME: Handle the case when there is no identity dump in web user')
            logout.set_identity_from_dump(lassoIdentityDump)

            logout.validate_request()
            failIf(logout.is_identity_dirty())
            lassoIdentity = logout.get_identity()
            failUnless(lassoIdentity)
            lassoIdentityDump = lassoIdentity.dump()
            failUnless(lassoIdentityDump)
            failUnless(logout.is_session_dirty())

            # Log the user out.
            # It is done before logout from other service providers, since we don't want to
            # accept passive login connections inbetween.
            del session.lassoSessionDump
            del session.userId
            # We also delete the session, but it is not mandantory, since the user is logged out
            # anyway.
            del self.sessions[session.token] 
            nameIdentifier = logout.nameIdentifier
            failUnless(nameIdentifier)
            del self.sessionTokensByNameIdentifier[nameIdentifier]

            # Tell each other service provider to logout the user.
            otherProviderId = logout.get_next_providerID()
            while otherProviderId is not None:
                logout.init_request(otherProviderId)
                logout.build_request_msg()

                soapEndpoint = logout.msg_url
                failUnless(soapEndpoint)
                soapRequestMsg = logout.msg_body
                failUnless(soapRequestMsg)
                httpResponse = sendHttpRequest(
                    'POST', soapEndpoint, headers = {'Content-Type': 'text/xml'},
                    body = soapRequestMsg)
                failUnlessEqual(httpResponse.statusCode, 200)
                logout.process_response_msg(httpResponse.body, lasso.httpMethodSoap)

                otherProviderId = logout.get_next_providerID()

            logout.build_response_msg()
            soapResponseMsg = logout.msg_body
            failUnless(soapResponseMsg)
            return handler.respond(
                headers = {'Content-Type': 'text/xml'}, body = soapResponseMsg)
        else:
            raise Exception('Unknown request type: %s' % requestType)
