#! /usr/bin/env python
# -*- coding: UTF-8 -*-


# PyLasso -- Python bindings for Lasso library
#
# Copyright (C) 2004 Entr'ouvert
# http://lasso.entrouvert.org
# 
# Authors: Nicolas Clapies <nclapies@entrouvert.com>
#          Valery Febvre <vfebvre@easter-eggs.com>
#          Emmanuel Raviart <eraviart@entrouvert.com>
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


import unittest
import sys

sys.path.insert(0, '..')
sys.path.insert(0, '../.libs')


import lasso


# FIXME: Replace principal with client in most methods.
# FIXME: Rename webUser to userAccount.


class HttpRequest(object):
    client = None # Principal or web site sending the request.
    body = None
    header = None
    method = None # "GET" or "POST" or "PUT" or...
    url = None

    def __init__(self, client, method, url, body = None):
        self.client = client
        self.method = method
        self.url = url
        if body:
            self.body = body

    def ask(self):
        webSite = self.client.internet.getWebSite(self.url)
        return webSite.doHttpRequest(self)


class HttpResponse(object):
    body = None
    header = None
    statusCode = None # 200 or...
    statusMessage = None

    def __init__(self, statusCode, statusMessage = None, body = None):
        self.statusCode = statusCode
        if statusMessage:
            self.statusMessage = statusMessage
        if body:
            self.body = body


class Internet(object):
    webSites = None

    def __init__(self):
        self.webSites = {}

    def addWebSite(self, webSite):
        self.webSites[webSite.url] = webSite

    def getWebSite(self, url):
        for webSiteUrl, webSite in self.webSites.iteritems():
            if url.startswith(webSiteUrl):
                return webSite
        raise Exception("Unknown web site: %s" % url)


class WebClient(object):
    internet = None
    keyring = None
    webSessionIds = None # Simulate the cookies, stored in user's navigator, and containing the
                         # IDs of sessions already opened by the user.

    def __init__(self, internet):
        self.internet = internet
        self.keyring = {}
        self.webSessionIds = {}

    def redirect(self, url):
        webSite = self.internet.getWebSite(url)
        return webSite.doHttpRequest(HttpRequest(self, "GET", url))


class Principal(WebClient):
    """Simulation of a user and its web navigator"""

    name = None # The user name

    def __init__(self, internet, name):
        WebClient.__init__(self, internet)
        self.name = name


class Simulation(object):
    test = None # The testing instance

    def __init__(self, test):
        self.test = test

    def fail(self, msg = None):
        return self.test.fail(msg)

    def failIf(self, expr, msg = None):
        return self.test.failIf(expr, msg)

    def failIfAlmostEqual(self, first, second, places = 7, msg = None):
        return self.test.failIfAlmostEqual(first, second, places, msg)

    def failIfEqual(self, first, second, msg = None):
        return self.test.failIfEqual(first, second, msg)

    def failUnless(self, expr, msg = None):
        return self.test.failUnless(expr, msg)

    def failUnlessAlmostEqual(self, first, second, places = 7, msg = None):
        return self.test.failUnlessAlmostEqual(first, second, places, msg)

    def failUnlessRaises(self, excClass, callableObj, *args, **kwargs):
        return self.test.failUnlessRaises(self, excClass, callableObj, *args, **kwargs)

    def failUnlessEqual(self, first, second, msg = None):
        return self.test.failUnlessEqual(first, second, msg)


class WebSession(object):
    """Simulation of session of a web site"""

    expirationTime = None # A sample session variable
    loginDump = None # Used only by some identity providers
    uniqueId = None # The session number
    sessionDump = None
    webUserId = None # ID of logged user. 

    def __init__(self, uniqueId):
        self.uniqueId = uniqueId


class WebUser(object):
    """Simulation of user of a web site"""

    identityDump = None
    language = 'fr' # A sample user variable
    uniqueId = None # The user name is used as an ID in this simulation.

    def __init__(self, uniqueId):
        self.uniqueId = uniqueId


class WebSite(WebClient, Simulation):
    """Simulation of a web site"""

    lastWebSessionId = 0
    providerId = None # The Liberty providerID of this web site
    serverDump = None
    url = None # The main URL of web site
    webUserIdsByNameIdentifier = None
    webUsers = None
    webSessionIdsByNameIdentifier = None
    webSessions = None

    def __init__(self, test, internet, url):
        Simulation.__init__(self, test)
        WebClient.__init__(self, internet)
        self.url = url
        self.webUserIdsByNameIdentifier = {}
        self.webUsers = {}
        self.webSessionIdsByNameIdentifier = {}
        self.webSessions = {}
        self.internet.addWebSite(self)

    def addWebUser(self, name):
        self.webUsers[name] = WebUser(name)

    def createWebSession(self, client):
        self.lastWebSessionId += 1
        webSession = WebSession(self.lastWebSessionId)
        self.webSessions[self.lastWebSessionId] = webSession
        client.webSessionIds[self.url] = self.lastWebSessionId
        return webSession

    def doHttpRequest(self, httpRequest):
        url = httpRequest.url
        if url.startswith(self.url):
            url = url[len(self.url):]
        methodName = url.split("?", 1)[0].replace("/", "")
        method = getattr(self, methodName)
        return method(httpRequest)

    def extractQueryFromUrl(self, url):
        return url.split("?", 1)[1]

    def getIdentityDump(self, principal):
        webSession = self.getWebSession(principal)
        webUser = self.getWebUserFromWebSession(webSession)
        if webUser is None:
            return None
        return webUser.identityDump

    def getServer(self):
        return lasso.Server.new_from_dump(self.serverDump)

    def getSessionDump(self, principal):
        webSession = self.getWebSession(principal)
        if webSession is None:
            return None
        return webSession.sessionDump

    def getWebSession(self, principal):
        webSessionId = principal.webSessionIds.get(self.url, None)
        if webSessionId is None:
            # The user has no web session opened on this site.
            return None
        return self.webSessions.get(webSessionId, None)

    def getWebSessionFromNameIdentifier(self, nameIdentifier):
        webSessionId = self.webSessionIdsByNameIdentifier.get(nameIdentifier, None)
        if webSessionId is None:
            # The user has no federation on this site or has no authentication assertion for this
            # federation.
            return None
        return self.webSessions.get(webSessionId, None)

    def getWebUserFromNameIdentifier(self, nameIdentifier):
        webUserId = self.webUserIdsByNameIdentifier.get(nameIdentifier, None)
        if webUserId is None:
            # The user has no federation on this site.
            return None
        return self.webUsers.get(webUserId, None)

    def getWebUserFromWebSession(self, webSession):
        if webSession is None:
            return None
        webUserId = webSession.webUserId
        if webUserId is None:
            # The user has no account on this site.
            return None
        return self.webUsers.get(webUserId, None)


class IdpSite(WebSite):
    soapResponseMsgs = None

    def __init__(self, test, internet, url):
        WebSite.__init__(self, test, internet, url)
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


class SpSite(WebSite):
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
        httpResponse = HttpRequest(self, "POST", soapEndpoint, body = soapRequestMsg).ask()
        self.failUnlessEqual(httpResponse.statusCode, 200)
        login.process_response_msg(httpResponse.body)
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
                login.set_identity_from_dump(sessionDump)

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
        nameIdentifier = login.nameIdentifier
        self.failUnless(nameIdentifier)

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
                return HttpResponse(401, "Access Unauthorized: User has no account.")
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
        relayState = "fake"
        login.request.set_relayState(relayState)
        login.build_authn_request_msg()
        authnRequestUrl = login.msg_url
        self.failUnless(authnRequestUrl)
        return httpRequest.client.redirect(authnRequestUrl)

    def logoutUsingSoap(self, httpRequest):
        webSession = self.getWebSession(httpRequest.client)
        if webSession is None:
            return HttpResponse(401, "Access Unauthorized: User has no session opened.")
        webUser = self.getWebUserFromWebSession(webSession)
        if webUser is None:
            return HttpResponse(401, "Access Unauthorized: User is not logged in.")

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
        httpResponse = HttpRequest(self, "POST", soapEndpoint, body = soapRequestMsg).ask()
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


class TestCase(unittest.TestCase):
    def generateIdpSite(self, internet):
        site = IdpSite(self, internet, "https://identity-provider/")
        site.providerId = "https://identity-provider/metadata"

        server = lasso.Server.new(
            "../../examples/data/idp-metadata.xml",
            "../../examples/data/idp-public-key.pem",
            "../../examples/data/idp-private-key.pem",
            "../../examples/data/idp-crt.pem",
            lasso.signatureMethodRsaSha1)
        server.add_provider(
            "../../examples/data/sp-metadata.xml",
            "../../examples/data/sp-public-key.pem",
            "../../examples/data/ca-crt.pem")
        site.serverDump = server.dump()
        self.failUnless(site.serverDump)
        server.destroy()

        site.addWebUser('Chantereau')
        site.addWebUser('Clapies')
        site.addWebUser('Febvre')
        site.addWebUser('Nowicki')
        return site

    def generateSpSite(self, internet):
        site = SpSite(self, internet, "https://service-provider/")
        site.providerId = "https://service-provider/metadata"

        server = lasso.Server.new(
            "../../examples/data/sp-metadata.xml",
            "../../examples/data/sp-public-key.pem",
            "../../examples/data/sp-private-key.pem",
            "../../examples/data/sp-crt.pem",
            lasso.signatureMethodRsaSha1)
        server.add_provider(
            "../../examples/data/idp-metadata.xml",
            "../../examples/data/idp-public-key.pem",
            "../../examples/data/ca-crt.pem")
        site.serverDump = server.dump()
        self.failUnless(site.serverDump)
        server.destroy()

        site.addWebUser('Nicolas')
        site.addWebUser('Romain')
        site.addWebUser('Valery')
        return site

    def setUp(self):
        pass

    def tearDown(self):
        pass


class LoginTestCase(TestCase):
    def test01_generateServers(self):
        """Service provider initiated login using HTTP redirect"""

        internet = Internet()
        idpSite = self.generateIdpSite(internet)
        spSite = self.generateSpSite(internet)
        spSite.idpSite = idpSite
        principal = Principal(internet, "Romain Chantereau")
        principal.keyring[idpSite.url] = "Chantereau"
        principal.keyring[spSite.url] = "Romain"
        httpResponse = spSite.doHttpRequest(HttpRequest(principal, "GET", "/loginUsingRedirect"))
        self.failUnlessEqual(httpResponse.statusCode, 200)
        httpResponse = spSite.doHttpRequest(HttpRequest(principal, "GET", "/logoutUsingSoap"))
        self.failUnlessEqual(httpResponse.statusCode, 200)

##     def test02_spLogin(self):
##         """Service provider initiated login using HTTP redirect"""

##         spLogin = self.spLoginForRedirect()
##         # A real service provider would issue a HTTPS redirect to spLogin.msg_url.

##         # Identity provider single sign-on, for a user having no federation.
##         authnRequestQuery = spLogin.msg_url.split("?", 1)[1]
##         idpLogin = self.idpSingleSignOnForRedirect(authnRequestQuery, None, None)
##         self.failUnless(idpLogin.must_authenticate())
##         idpLoginDump = idpLogin.dump()
##         # A real identity provider using a HTML form to ask user's login & password would store
##         # idpLoginDump in a session variable and display the HTML login form.

##         userAuthenticated = True
##         authenticationMethod = lasso.samlAuthenticationMethodPassword
##         idpServer = self.generateIdpServer()
##         idpLogin = lasso.Login.new_from_dump(idpServer, idpLoginDump)
##         #FIXME: set user and session from dump, because the logindump doesn't contain them.
##         self.failUnlessEqual(idpLogin.protocolProfile, lasso.loginProtocolProfileBrwsArt)
##         idpLogin = self.idpSingleSignOn_part2ForArtifactRedirect(
##             idpLogin, userAuthenticated, authenticationMethod)
##         # The user had no Liberty federation before, so identity must be dirty.
##         self.failUnless(idpLogin.is_identity_dirty())
##         idpIdentityDump = idpLogin.get_identity().dump()
##         idpSessionDump = idpLogin.get_session().dump()
##         nameIdentifier = idpLogin.nameIdentifier
##         artifact = idpLogin.assertionArtifact
##         soapResponseMsg = idpLogin.response_dump
##         # A real identity provider would store idpIdentityDump in user record and store
##         # idpSessionDump in session variables or user record.
##         # It would then index its user record and its session using nameIdentifier.
##         # It would also store soapResponseMsg and index it using artifact.
##         # It would optionally create a web session (using cookie, ...).
##         # And finally, it would issue a HTTPS redirect to idpLogin.msg_url.

##         # Service provider assertion consumer.
##         responseQuery = idpLogin.msg_url.split("?", 1)[1]
##         spLogin = self.spAssertionConsumerForRedirect(responseQuery)
##         # A real service provider would issue a SOAP HTTPS request containing spLogin.msg_body to
##         # spLogin.msg_url.

##         # Identity provider SOAP endpoint.
##         idpLogin = self.idpSoapEndpointForLogin(spLogin.msg_body)
##         # A real identity provider would retrieve soapResponseMsg using spLogin.assertionArtifact
##         # and return it as SOAP response.
##         self.failUnlessEqual(idpLogin.assertionArtifact, artifact)

##         # Service provider assertion consumer (part 2: process SOAP response).
##         spLogin = self.spAssertionConsumer_part2(spLogin, soapResponseMsg)
##         # A real service provider would search for a user record and a session indexed by
##         # spLogin.nameIdentifier.
##         # In this case, we assume that the user has no Liberty federation yet => no identity dump
##         # and no session dump. 
##         self.failUnlessEqual(spLogin.nameIdentifier, nameIdentifier)
##         spLogin = self.spAssertionConsumer_part3(spLogin, None, None)
##         self.failUnless(spLogin.is_identity_dirty())
##         spIdentityDump = spLogin.get_identity().dump()
##         spSession = spLogin.get_session()
##         spSessionDump = spSession.dump()
##         authenticationMethod = spSession.get_authentication_method()
##         self.failUnlessEqual(authenticationMethod, lasso.samlAuthenticationMethodPassword)
##         # A real service provider would store spIdentityDump in user record and spSessionDump
##         # in session variables or user record.
##         # It would then index its user record and its session using nameIdentifier.
##         # It would create a web session (using cookie, ...).
##         # And finally, it would display a page saying that Liberty authentication has succeeded.

##         # Service provider logout using SOAP.
##         spLogout = self.spLogoutForSoap(spIdentityDump, spSessionDump)
##         # A real service provider would issue a SOAP HTTPS request containing spLogout.msg_body to
##         # spLogout.msg_url.

##         # Identity provider SOAP endpoint.
##         idpLogout = self.idpSoapEndpointForLogout(spLogout.msg_body)
##         self.failUnlessEqual(idpLogout.nameIdentifier, nameIdentifier)
##         # A real identity provider would retrieve the user record and the session indexed by
##         # idpLogout.nameIdentifier.
        
##         idpLogout = self.idpSoapEndpointForLogout_part2(idpLogout, idpIdentityDump, idpSessionDump)
##         # A real identity provider would store idpIdentityDump in user record and store or delete
##         # idpSessionDump in session variables or user record.
##         # It would then remove the nameIdentifier index to the user record and the session.
##         # And finally, it would return idpLogout.msg_body as SOAP response.

##         # Service provider logout (part 2: process SOAP response).
##         spLogout = self.spLogoutForSoap_part2(spLogout, idpLogout.msg_body)
##         self.failIf(spLogout.is_identity_dirty())
##         spIdentityDump = spLogout.get_identity().dump()
##         spSession = spLogout.get_session()
##         # In this case, spSession should be None, but Lasso doesn't implement it yet.
##         # self.failIf(spSession)
##         #
##         # A real service provider would store spIdentityDump in user record and store or delete
##         # spSessionDump in session variables or user record.
##         # It would then remove the idpLogout.nameIdentifier index to the user record and the
##         # session.
##         # And finally, it would display a page saying that Liberty logout has succeeded.

##     def test03(self):
##         """Identity provider single sign-on when identity and session already exist."""
##         idpServer = self.generateIdpServer()
##         idpLogin = lasso.Login.new(idpServer)
##         idpIdentityDump = """\
## <LassoIdentity><LassoFederations><LassoFederation RemoteProviderID="https://service-provider:2003/liberty-alliance/metadata"><LassoLocalNameIdentifier><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">NjMxMEMzRTlEMDA4NTNEMEZGNDI1MEM0QzY4NUNBNzY=</saml:NameIdentifier></LassoLocalNameIdentifier></LassoFederation></LassoFederations></LassoIdentity>
## """.strip()
##         idpLogin.set_identity_from_dump(idpIdentityDump)
##         idpSessionDump = """
## <LassoSession><LassoAssertions><LassoAssertion RemoteProviderID="https://service-provider:2003/liberty-alliance/metadata"><lib:Assertion xmlns:lib="urn:liberty:iff:2003-08" AssertionID="Q0QxQzNFRTVGRTZEM0M0RjY2MTZDNTEwOUY4MDQzRTI=" MajorVersion="1" MinorVersion="2" IssueInstance="2004-08-02T18:51:43Z" Issuer="https://identity-provider:1998/liberty-alliance/metadata" InResponseTo="OEQ0OEUzODhGRTdGMEVFMzQ5Q0Q0QzYzQjk4MjUwNjQ="><lib:AuthenticationStatement xmlns:lib="urn:liberty:iff:2003-08" AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="2004-08-02T18:51:43Z" ReauthenticateOnOrAfter="FIXME: reauthenticateOnOrAfter"><lib:Subject xmlns:lib="urn:liberty:iff:2003-08"><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">NjMxMEMzRTlEMDA4NTNEMEZGNDI1MEM0QzY4NUNBNzY=</saml:NameIdentifier><lib:IDPProvidedNameIdentifier xmlns:lib="urn:liberty:iff:2003-08" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">NjMxMEMzRTlEMDA4NTNEMEZGNDI1MEM0QzY4NUNBNzY=</lib:IDPProvidedNameIdentifier><saml:SubjectConfirmation xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"><saml:SubjectConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:SubjectConfirmationMethod></saml:SubjectConfirmation></lib:Subject></lib:AuthenticationStatement><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
## <SignedInfo>
## <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
## <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
## <Reference>
## <Transforms>
## <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
## </Transforms>
## <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
## <DigestValue>ZRe7eb5JuhgL6W/Le1oMezbEHnA=</DigestValue>
## </Reference>
## </SignedInfo>
## <SignatureValue>CYOtlOvHtpkQsLA87GrtHs1WuoPVXHiPkVsmce2X1+PUslYpKLKp3cuNTVo1Z7+k
## Iku+DThYC9EvR7gprVQW2Y3CpCPanWs2A6j21SrlfqGFffpUtOFuiv3L1rfGKjPJ
## eMWehfc/SEi3+/JT22RejeYrSA61YLwsfItB7Ie4L0TRuZuxxu++CsidIEu2iv7l
## fI79SMn5hF7j/oFU9IODFhCArNLgBiOxA9rnRNvXwRFFmRN3qvdEuXuAZBthRhoa
## BRcL2T7tLxIVV+8y1fUjkliV1QgvOeus9g1bib1FLHdzHZ6KNGLPkZiXuM7ZPT1B
## G8WStJalTeH81AE7Ol4pcg==</SignatureValue>
## <KeyInfo>
## <X509Data>
## <X509Certificate>MIIDKTCCAhECAQEwDQYJKoZIhvcNAQEEBQAwWzELMAkGA1UEBhMCSVQxDzANBgNV
## BAcTBlBvbXBlaTEQMA4GA1UEChMHVmVzdXZpbzEpMCcGA1UEAxMgVmVzdXZpbyBM
## aWJlcnR5IEFsbGlhbmNlIFJvb3QgQ0EwHhcNMDQwNDIwMTQwMzQ1WhcNMDUwNDIw
## MTQwMzQ1WjBaMQswCQYDVQQGEwJJVDEPMA0GA1UEBxMGUG9tcGVpMR4wHAYDVQQK
## ExVJZGVudGl0eSBQcm92aWRlciBJbmMxGjAYBgNVBAMTEWlkZW50aXR5LXByb3Zp
## ZGVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4SGH3FPnhpQ8rCED
## RmC+NEkJQ6ZrG1jRL1kNx3wNu1xRZgFPiEDFnu9p/muVQkRAzK4txgC5i0ymwgRZ
## uan2yFrdq7Kpc9r0cM1S/q63aQeOMXQszz6G0NIY9DOzdrdlTc2uToBpIPA4a/Tf
## NWpMFZ7zGB9ThJ4+S5MAIA6y3SRWYHOqdlwjo/R0P4C3y8wIClgI0ZTdS6/Rkr59
## XC4WRocMzGCSsk+1F1tAZoR77ummLcY4nFkbtawyeRXEUpSpDaxgVEEmvH+/Kqx5
## NhVzeCZkm8szOzMea+QT4Uh3F7GVwY/7+JV23eCGyr2n3EhXgCqw0nnGSGR7vrNl
## Ue1oswIDAQABMA0GCSqGSIb3DQEBBAUAA4IBAQAFyYC/V49X7ZNLpYI8jx1TE9X3
## J4c47cCLaxslrhi0/X6nCOEcBckXtbL+ZhIiHfI6PWizHMjTCEkJOYMVOsXyWN73
## XdzfIZVrThQRsYvQZqUH8cZZH3fFg/RyEM3fzlFDsuIxfg7+NIDNmSFbt/YdFL0T
## 3sB7jYSkKr4buX9ZewdOfRxwN4MZIE32SoBo+UOgNrMM2hcQTStBK09vzJiWQE/4
## aWbZJT9jtBPGWTsMS8g1x9WAmJHV2BpUiSfY39895a5T7kbbqZ3rp7DM9dgLjdXC
## jFL7NhzvY02aBTLhm22YOLYnlycKm64NGne+siooDCi5tel2/vcx+e+btX9x</X509Certificate>
## </X509Data>
## </KeyInfo>
## </Signature></lib:Assertion></LassoAssertion></LassoAssertions></LassoSession>
## """.strip()
##         # " <-- Trick for Emacs Python mode.
##         idpLogin.set_session_from_dump(idpSessionDump)
##         authnRequestQuery = """NameIDPolicy=federated&IsPassive=false&ProviderID=https%3A%2F%2Fservice-provider%3A2003%2Fliberty-alliance%2Fmetadata&consent=urn%3Aliberty%3Aconsent%3Aobtained&IssueInstance=2004-08-02T20%3A33%3A58Z&MinorVersion=2&MajorVersion=1&RequestID=ODVGNkUyMzY5N0MzOTY4QzZGOUYyNzEwRTJGMUNCQTI%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=fnSL5Mgp%2BV%2FtdUuYQJmFKvFY8eEco6sypmejvP4sD0v5ApywV94mUo6BxE29o1KW%0AGFXiMG7puhTwRSlKDo1vlh5iHNqVfjKcbx2XhfoDfplqLir102dyHxB5GedEQvqw%0AbTFtFrB6SnHi5facrYHCn7b58CxAWv9XW4DIfcVCOSma2OOBCm%2FzzCSiZpOtbRk9%0AveQzace41tDW0XLlbRdWpvwsma0yaYSkqYvTV3hmvgkWS5x9lzcm97oME4ywzwbU%0AJAyG8BkqMFoG7FPjwzR8qh7%2FWi%2BCzxxqfczxSGkUZUmsQdxyxazjhDpt1X8i5fan%0AnaF1vWF3GmS6G4t7mrkItA%3D%3D"""
##         method = lasso.httpMethodRedirect
##         idpLogin.init_from_authn_request_msg(authnRequestQuery, method)
##         self.failIf(idpLogin.must_authenticate())
##         userAuthenticated = True
##         authenticationMethod = lasso.samlAuthenticationMethodPassword
##         self.failUnlessEqual(idpLogin.protocolProfile, lasso.loginProtocolProfileBrwsArt)
##         idpLogin.build_artifact_msg(
##             userAuthenticated, authenticationMethod, "FIXME: reauthenticateOnOrAfter",
##             lasso.httpMethodRedirect)
##         self.failUnless(idpLogin.msg_url)
##         self.failUnless(idpLogin.assertionArtifact)
##         self.failUnless(idpLogin.response_dump)
##         self.failUnless(idpLogin.nameIdentifier)

##     def test04(self):
##         """Identity provider logout."""
##         idpServer = self.generateIdpServer()
##         soapRequestMessage = """\
## <soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"><soap-env:Body xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"><lib:LogoutRequest xmlns:lib="urn:liberty:iff:2003-08" RequestID="RDIwMUYzM0Q1MzdFMjMzQzk0NTM4QUNEQUQ0MURBMEE=" MajorVersion="1" MinorVersion="2" IssueInstance="2004-08-03T11:56:15Z"><lib:ProviderID>https://service-provider:2003/liberty-alliance/metadata</lib:ProviderID><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">QkM3M0M4MTYxREQzNEYwNEI4M0I4MUVERDUyQUUyMjA=</saml:NameIdentifier><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
## <SignedInfo>
## <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
## <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
## <Reference>
## <Transforms>
## <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
## </Transforms>
## <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
## <DigestValue>NlVszQnxIyPU7zbJYadQmTnFAsI=</DigestValue>
## </Reference>
## </SignedInfo>
## <SignatureValue>h0lB2hBstgxlNYnVQ4xzmXIi2APqNxKEEfUqYm3NeGmddbazg0/Y/SdcqLlto9fy
## ML34w/TJG7DnCdeUQVxdxhzmJlv3X2U5qDAYh6gX4g36wJCntderC5LtNkZhhTWt
## m9NWGszFhCm9nSaGATdj4JGqJNc+LUIt3EvXHDIqQ/LU2g3hxZQ4Hs5Fg9yqRS98
## 5CWPtckYcGPcG8kFuTKNos2F4KQPyXJRX0KF+9FbkBX0RsblstzL0CiFUlor4m+R
## ejvMcEt/nGCGj7F5mRPYcW3ZxTw4J2wAqS52Tu41fyeKw5SHIJQNmwV25P/hINim
## hd2ybn/G3vK2If0+rUjA8Q==</SignatureValue>
## <KeyInfo>
## <X509Data>
## <X509Certificate>MIIDJzCCAg8CAQIwDQYJKoZIhvcNAQEEBQAwWzELMAkGA1UEBhMCSVQxDzANBgNV
## BAcTBlBvbXBlaTEQMA4GA1UEChMHVmVzdXZpbzEpMCcGA1UEAxMgVmVzdXZpbyBM
## aWJlcnR5IEFsbGlhbmNlIFJvb3QgQ0EwHhcNMDQwNDIwMTQyMDMxWhcNMDUwNDIw
## MTQyMDMxWjBYMQswCQYDVQQGEwJJVDEPMA0GA1UEBxMGUG9tcGVpMR0wGwYDVQQK
## ExRTZXJ2aWNlIFByb3ZpZGVyIEluYzEZMBcGA1UEAxMQc2VydmljZS1wcm92aWRl
## cjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALIjOIroSVwUaMOyFlGL
## p6oCDkI14ssZRec/l2Z+p89kwVF+vkyhE7LHkaIgE1RnmPhcudzMCNFc6okpHdtV
## yU+GTSXhRN7/BGYBoDpfNpTMP0aUpw/BQOhL+zeb0nSsSf7ejNeKyvR+q5ia+3N4
## dm9vgUPWZk0iN0URMSRxzIA3nEsR+B9JV7BFFyfbBxwLR4Aht667cuSeFnAUnynp
## JiHiKF/r5yXk+EKK++8NpjflpJnFVT1mSfj+6iYutiOrgUKgCANsaXr0WomR4oKg
## kqzP2DLDwnwi73vUAW4y9CBNk7nDtZJFhUxKa63i1HgHCKNvHfVjvKPz844PnLw/
## CWMCAwEAATANBgkqhkiG9w0BAQQFAAOCAQEAOfAVexQY2ImgBWjcAkGAYfLwMZ2k
## 8jtQGRgbPuD1DBQ+oZm+Ykuw30orVAo8/S5PcSNdRawOVoTY60oRupGBctoqSzmp
## SiBkWOwb4wBZOHfSNRFDS83N0ewHk4FFY6t5NPlhUORC07xl4GaVUb5LjyDKMh2j
## RtLaR85lCV8xVvM+jdBzBM2FxOQ0WdhphMjO4gj5ene791iT4PpA69o7wuZ9g728
## CGb/HRUx5EPgbIy52G224ITlQWadD1Z6y4PFTowDjkaRVerjUVRJZ/a5QVNsI4Du
## /z71zAbdg4NfTfXjAXHRhEGappHVBROAQFchQ0oKhCTkICN4TUSuodgy/A==</X509Certificate>
## </X509Data>
## </KeyInfo>
## </Signature></lib:LogoutRequest></soap-env:Body></soap-env:Envelope>
## """.strip()
##         # " <-- Trick for Emacs Python mode.
##         requestType = lasso.get_request_type_from_soap_msg(soapRequestMessage)
##         self.failUnlessEqual(requestType, lasso.requestTypeLogout)
##         idpLogout = lasso.Logout.new(idpServer, lasso.providerTypeIdp)
##         idpLogout.process_request_msg(soapRequestMessage, lasso.httpMethodSoap)
##         self.failUnless(idpLogout.nameIdentifier)
##         idpIdentityDump = """\
## <LassoIdentity><LassoFederations><LassoFederation RemoteProviderID="https://service-provider:2003/liberty-alliance/metadata"><LassoLocalNameIdentifier><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">QkM3M0M4MTYxREQzNEYwNEI4M0I4MUVERDUyQUUyMjA=</saml:NameIdentifier></LassoLocalNameIdentifier></LassoFederation></LassoFederations></LassoIdentity>
## """.strip()
##         idpLogout.set_identity_from_dump(idpIdentityDump)
##         self.failUnlessEqual(idpLogout.get_identity().dump(), idpIdentityDump)
##         idpSessionDump = """
## <LassoSession><LassoAssertions><LassoAssertion RemoteProviderID="https://service-provider:2003/liberty-alliance/metadata"><lib:Assertion xmlns:lib="urn:liberty:iff:2003-08" AssertionID="QUVENUJCNzRFOUQ3MEZFNEYzNUUwQTA5OTRGMEYzMDg=" MajorVersion="1" MinorVersion="2" IssueInstance="2004-08-03T11:55:55Z" Issuer="https://identity-provider:1998/liberty-alliance/metadata" InResponseTo="N0VEQzE0QUE1NTYwQTAzRjk4Njk3Q0JCRUU0RUZCQkY="><lib:AuthenticationStatement xmlns:lib="urn:liberty:iff:2003-08" AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="2004-08-03T11:55:55Z" ReauthenticateOnOrAfter="FIXME: reauthenticateOnOrAfter"><lib:Subject xmlns:lib="urn:liberty:iff:2003-08"><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">QkM3M0M4MTYxREQzNEYwNEI4M0I4MUVERDUyQUUyMjA=</saml:NameIdentifier><lib:IDPProvidedNameIdentifier xmlns:lib="urn:liberty:iff:2003-08" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">QkM3M0M4MTYxREQzNEYwNEI4M0I4MUVERDUyQUUyMjA=</lib:IDPProvidedNameIdentifier><saml:SubjectConfirmation xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"><saml:SubjectConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:SubjectConfirmationMethod></saml:SubjectConfirmation></lib:Subject></lib:AuthenticationStatement><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
## <SignedInfo>
## <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
## <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
## <Reference>
## <Transforms>
## <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
## </Transforms>
## <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
## <DigestValue>TqCKQTLsexix/tIqEabjBPcYby8=</DigestValue>
## </Reference>
## </SignedInfo>
## <SignatureValue>l96xDhc0/nevhvx79eyYvGknXDJMcykiomKOLMiL0FcxOglaKi/aNOGNA5VdT0mh
## EdlAynOOVy9xXphy9kLyXXSMcYV5UMeqCIi0ro5cvMP1xBfEqBHAHaYQR+TXbGdn
## bPCkIvGwzLDVr8bvwWnPjHqaXffswlfzjrDYq726Sx37s3UBgcViEVG0HTGe2X+f
## Kx2iahOjVLvR9bBWOdsiKNisK3GtZPGFmxIXALg8oZnwJA4JKodzh+o1synKoLn3
## 2WigVh7r43LISSkCHx1C7qIK2zFz8YtPtaHa4xfMWT6QwZRngsXRcUcUibWZyoYt
## 950ly3lp1XkexL0uRXPvKw==</SignatureValue>
## <KeyInfo>
## <X509Data>
## <X509Certificate>MIIDKTCCAhECAQEwDQYJKoZIhvcNAQEEBQAwWzELMAkGA1UEBhMCSVQxDzANBgNV
## BAcTBlBvbXBlaTEQMA4GA1UEChMHVmVzdXZpbzEpMCcGA1UEAxMgVmVzdXZpbyBM
## aWJlcnR5IEFsbGlhbmNlIFJvb3QgQ0EwHhcNMDQwNDIwMTQwMzQ1WhcNMDUwNDIw
## MTQwMzQ1WjBaMQswCQYDVQQGEwJJVDEPMA0GA1UEBxMGUG9tcGVpMR4wHAYDVQQK
## ExVJZGVudGl0eSBQcm92aWRlciBJbmMxGjAYBgNVBAMTEWlkZW50aXR5LXByb3Zp
## ZGVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4SGH3FPnhpQ8rCED
## RmC+NEkJQ6ZrG1jRL1kNx3wNu1xRZgFPiEDFnu9p/muVQkRAzK4txgC5i0ymwgRZ
## uan2yFrdq7Kpc9r0cM1S/q63aQeOMXQszz6G0NIY9DOzdrdlTc2uToBpIPA4a/Tf
## NWpMFZ7zGB9ThJ4+S5MAIA6y3SRWYHOqdlwjo/R0P4C3y8wIClgI0ZTdS6/Rkr59
## XC4WRocMzGCSsk+1F1tAZoR77ummLcY4nFkbtawyeRXEUpSpDaxgVEEmvH+/Kqx5
## NhVzeCZkm8szOzMea+QT4Uh3F7GVwY/7+JV23eCGyr2n3EhXgCqw0nnGSGR7vrNl
## Ue1oswIDAQABMA0GCSqGSIb3DQEBBAUAA4IBAQAFyYC/V49X7ZNLpYI8jx1TE9X3
## J4c47cCLaxslrhi0/X6nCOEcBckXtbL+ZhIiHfI6PWizHMjTCEkJOYMVOsXyWN73
## XdzfIZVrThQRsYvQZqUH8cZZH3fFg/RyEM3fzlFDsuIxfg7+NIDNmSFbt/YdFL0T
## 3sB7jYSkKr4buX9ZewdOfRxwN4MZIE32SoBo+UOgNrMM2hcQTStBK09vzJiWQE/4
## aWbZJT9jtBPGWTsMS8g1x9WAmJHV2BpUiSfY39895a5T7kbbqZ3rp7DM9dgLjdXC
## jFL7NhzvY02aBTLhm22YOLYnlycKm64NGne+siooDCi5tel2/vcx+e+btX9x</X509Certificate>
## </X509Data>
## </KeyInfo>
## </Signature></lib:Assertion></LassoAssertion></LassoAssertions></LassoSession>
## """.strip()
##         # " <-- Trick for Emacs Python mode.
##         idpLogout.set_session_from_dump(idpSessionDump)
##         self.failUnlessEqual(idpLogout.get_session().dump(), idpSessionDump)
##         idpLogout.validate_request()
##         self.failIf(idpLogout.is_identity_dirty())
##         self.failUnless(idpLogout.is_session_dirty())
##         idpSessionDump = idpLogout.get_session().dump()
##         self.failUnless(idpSessionDump)
##         self.failIf(idpLogout.get_next_providerID())
##         idpLogout.build_response_msg()
##         soapResponseMsg = idpLogout.msg_body
##         self.failUnless(soapResponseMsg)

##     def test05(self):
##         """Service provider logout."""
##         spServer = self.getServer()
##         spLogout = lasso.Logout.new(spServer, lasso.providerTypeSp)

##         spIdentityDump = """\
## <LassoIdentity><LassoFederations><LassoFederation RemoteProviderID="https://identity-provider:1998/liberty-alliance/metadata"><LassoRemoteNameIdentifier><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">RTE5REZDN0UyMEJEQzA0MDQxRjM3NThCQkFCNERCODQ=</saml:NameIdentifier></LassoRemoteNameIdentifier><LassoLocalNameIdentifier><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">RTE5REZDN0UyMEJEQzA0MDQxRjM3NThCQkFCNERCODQ=</saml:NameIdentifier></LassoLocalNameIdentifier></LassoFederation></LassoFederations></LassoIdentity>
## """.strip()
##         spLogout.set_identity_from_dump(spIdentityDump)

##         spSessionDump = """\
## <LassoSession><LassoAssertions><LassoAssertion RemoteProviderID="https://identity-provider:1998/liberty-alliance/metadata"><lib:Assertion xmlns:lib="urn:liberty:iff:2003-08" AssertionID="QzQ3NkVCMEIzNTY0RDNBOUVEQkNDN0RCQjA1MjlFRTA=" MajorVersion="1" MinorVersion="2" IssueInstance="2004-08-04T00:03:08Z" Issuer="https://identity-provider:1998/liberty-alliance/metadata" InResponseTo="M0M3Q0RBREE4QjQ1OTAwOTk2QTlFN0RFRUU0NTNGNUM="><lib:AuthenticationStatement xmlns:lib="urn:liberty:iff:2003-08" AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="2004-08-04T00:03:08Z" ReauthenticateOnOrAfter="FIXME: reauthenticateOnOrAfter"><lib:Subject xmlns:lib="urn:liberty:iff:2003-08"><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">RTE5REZDN0UyMEJEQzA0MDQxRjM3NThCQkFCNERCODQ=</saml:NameIdentifier><lib:IDPProvidedNameIdentifier xmlns:lib="urn:liberty:iff:2003-08" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">RTE5REZDN0UyMEJEQzA0MDQxRjM3NThCQkFCNERCODQ=</lib:IDPProvidedNameIdentifier><saml:SubjectConfirmation xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"><saml:SubjectConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:SubjectConfirmationMethod></saml:SubjectConfirmation></lib:Subject></lib:AuthenticationStatement><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
## <SignedInfo>
## <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
## <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
## <Reference>
## <Transforms>
## <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
## </Transforms>
## <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
## <DigestValue>8BSywvR2YB/euz8CCEhElQRSiZA=</DigestValue>
## </Reference>
## </SignedInfo>
## <SignatureValue>Vg0BM0Z15mFsRxEOhy9oCfXuK/NgQPrgJc2Kf3tE9g/uTnNFGq0YNB5KSlonJLUr
## 0cZ8D18XlTJrZp22vPCUO44hvL5DDWGTctqJbl+TV3D8qzFlfe8XOPBy3cUSXcYo
## E4qR44SnA9iZeRH0t4c3+8lY+BeXoqcglBrpE86B5Ftfb7wvLY0m8fdzPSJneSqq
## Z41uh4Wtegq4bqIkUev0nrY1wKHJjkfpKNmcirGTNm0gm8c/Ki9UCgI9g4cknj+F
## /UR8LQH/H8u2YSp3w5wiWfcmEfjfoVqa8YoiwWAoRgkKRVwER6iXYdqJ9vF0GFN/
## Bm7OmEnDwF3bc/fruca4Pg==</SignatureValue>
## <KeyInfo>
## <X509Data>
## <X509Certificate>MIIDKTCCAhECAQEwDQYJKoZIhvcNAQEEBQAwWzELMAkGA1UEBhMCSVQxDzANBgNV
## BAcTBlBvbXBlaTEQMA4GA1UEChMHVmVzdXZpbzEpMCcGA1UEAxMgVmVzdXZpbyBM
## aWJlcnR5IEFsbGlhbmNlIFJvb3QgQ0EwHhcNMDQwNDIwMTQwMzQ1WhcNMDUwNDIw
## MTQwMzQ1WjBaMQswCQYDVQQGEwJJVDEPMA0GA1UEBxMGUG9tcGVpMR4wHAYDVQQK
## ExVJZGVudGl0eSBQcm92aWRlciBJbmMxGjAYBgNVBAMTEWlkZW50aXR5LXByb3Zp
## ZGVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4SGH3FPnhpQ8rCED
## RmC+NEkJQ6ZrG1jRL1kNx3wNu1xRZgFPiEDFnu9p/muVQkRAzK4txgC5i0ymwgRZ
## uan2yFrdq7Kpc9r0cM1S/q63aQeOMXQszz6G0NIY9DOzdrdlTc2uToBpIPA4a/Tf
## NWpMFZ7zGB9ThJ4+S5MAIA6y3SRWYHOqdlwjo/R0P4C3y8wIClgI0ZTdS6/Rkr59
## XC4WRocMzGCSsk+1F1tAZoR77ummLcY4nFkbtawyeRXEUpSpDaxgVEEmvH+/Kqx5
## NhVzeCZkm8szOzMea+QT4Uh3F7GVwY/7+JV23eCGyr2n3EhXgCqw0nnGSGR7vrNl
## Ue1oswIDAQABMA0GCSqGSIb3DQEBBAUAA4IBAQAFyYC/V49X7ZNLpYI8jx1TE9X3
## J4c47cCLaxslrhi0/X6nCOEcBckXtbL+ZhIiHfI6PWizHMjTCEkJOYMVOsXyWN73
## XdzfIZVrThQRsYvQZqUH8cZZH3fFg/RyEM3fzlFDsuIxfg7+NIDNmSFbt/YdFL0T
## 3sB7jYSkKr4buX9ZewdOfRxwN4MZIE32SoBo+UOgNrMM2hcQTStBK09vzJiWQE/4
## aWbZJT9jtBPGWTsMS8g1x9WAmJHV2BpUiSfY39895a5T7kbbqZ3rp7DM9dgLjdXC
## jFL7NhzvY02aBTLhm22YOLYnlycKm64NGne+siooDCi5tel2/vcx+e+btX9x</X509Certificate>
## </X509Data>
## </KeyInfo>
## </Signature></lib:Assertion></LassoAssertion></LassoAssertions></LassoSession>
## """.strip()
##         # " <-- Trick for Emacs Python mode.
##         spLogout.set_session_from_dump(spSessionDump)

##         spLogout.init_request()
##         spLogout.build_request_msg()
##         self.failUnless(spLogout.msg_url)
##         self.failUnless(spLogout.msg_body)
##         self.failUnless(spLogout.nameIdentifier)

##         soapResponseMessage = """\
## <soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"><soap-env:Body xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"><lib:LogoutResponse xmlns:lib="urn:liberty:iff:2003-08" ResponseID="NjcyNDYxQ0FCRTQwMUE0NjE4MzlFQjFDOTI2MTc3NjE=" MajorVersion="1" MinorVersion="2" IssueInstance="2004-08-04T00:03:20Z" InResponseTo="MzNCOTRBMjRCMDExN0MxODc1MUI5NjMwQjlCMTg1NzM=" Recipient="https://service-provider:2003/liberty-alliance/metadata"><lib:ProviderID>https://identity-provider:1998/liberty-alliance/metadata</lib:ProviderID><samlp:Status xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"><samlp:StatusCode xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" Value="Samlp:Success"/></samlp:Status></lib:LogoutResponse></soap-env:Body></soap-env:Envelope>
## """.strip()
##         spLogout.process_response_msg(soapResponseMessage, lasso.httpMethodSoap)
##         self.failIf(spLogout.is_identity_dirty())
##         self.failUnless(spLogout.is_session_dirty())
##         spSessionDump = spLogout.get_session().dump()
##         # self.failIf(spSessionDump)

##     def test06(self):
##         """Service provider LECP login."""

##         # LECP has asked service provider for login.
##         spServer = self.getServer()

##         # FIXME: Why doesn't lasso.Lecp.new have spServer as argument?
##         # spLecp = lasso.Lecp.new(spServer)
##         spLecp = lasso.Lecp.new()
##         spLecp.init_authn_request_envelope(sp, )
##         lasso_lecp_init_authn_request_envelope(sp_lecp, spserver, authnRequest);
##         lasso_lecp_build_authn_request_envelope_msg(sp_lecp);
##         msg = g_strdup(sp_lecp->msg_body);
##         lasso_lecp_destroy(sp_lecp);


suite1 = unittest.makeSuite(LoginTestCase, 'test')

allTests = unittest.TestSuite((suite1,))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity=2).run(allTests).wasSuccessful())

