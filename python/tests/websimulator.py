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
