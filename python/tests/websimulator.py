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


# FIXME: Replace principal with client in most methods.
# FIXME: Rename user to userAccount.


import abstractweb


class HttpRequest(abstractweb.HttpRequestMixin, object):
    client = None # Principal or web site sending the request.
    body = None
    form = None
    headers = None
    method = None # 'GET' or 'POST' or 'PUT' or...
    url = None

    def __init__(self, client, method, url, headers = None, body = None, form = None):
        self.client = client
        self.method = method
        self.url = url
        if headers:
            self.headers = headers
        if body:
            self.body = body
        if form:
            self.form = form

    def getFormField(self, name, default = None):
        if self.form is not None:
            return self.form.get(name, default)
        return default

    def getPath(self):
        return self.pathAndQuery.split('?', 1)[0]

    def getPathAndQuery(self):
        urlWithoutScheme = self.url[self.url.find('://') + 3:]
        if '/' in urlWithoutScheme:
            pathAndQuery = urlWithoutScheme[urlWithoutScheme.find('/'):]
        else:
            pathAndQuery = ''
        return pathAndQuery

    def getQuery(self):
        splitedUrl = self.pathAndQuery.split('?', 1)
        if len(splitedUrl) > 1:
            return splitedUrl[1]
        else:
            return ''

    def getScheme(self):
        return self.url.split(':', 1)[0].lower()

    def hasFormField(self, name):
        if self.form is None:
            return False
        return name in self.form

    def send(self):
        webSite = self.client.internet.getWebSite(self.url)
        return webSite.handleHttpRequest(self)

    path = property(getPath)
    pathAndQuery = property(getPathAndQuery)
    query = property(getQuery)
    scheme = property(getScheme)


class HttpResponse(abstractweb.HttpResponseMixin, object):
    def send(self, httpRequestHandler):
        return self


class HttpRequestHandler(abstractweb.HttpRequestHandlerMixin, object):
    HttpResponse = HttpResponse # Class

    def __init__(self, site, httpRequest):
        self.site = site
        self.httpRequest = httpRequest

    def getSession(self):
        return self.site.getSessionFromPrincipal(self.httpRequest.client)
        
    def respondRedirectTemporarily(self, url):
        return self.httpRequest.client.redirect(url)

    session = property(getSession)


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
        raise Exception('Unknown web site: %s' % url)


class WebClient(object):
    internet = None
    keyring = None
    httpRequestHeaders = {
        'User-Agent': 'LassoSimulator/0.0.0',
        'Accept': 'text/xml,application/xml,application/xhtml+xml,text/html',
        }
    sessionTokens = None # Simulate the cookies, stored in user's navigator, and containing the
                         # IDs of sessions already opened by the user.

    def __init__(self, internet):
        self.internet = internet
        self.keyring = {}
        self.sessionTokens = {}

    def redirect(self, url):
        return self.sendHttpRequest('GET', url)

    def sendHttpRequest(self, method, url, headers = None, body = None, form = None):
        if headers:
            httpRequestHeaders = self.httpRequestHeaders.copy()
            for name, value in headers.iteritems():
                httpRequestHeaders[name] = value
        else:
            httpRequestHeaders = self.httpRequestHeaders
        return HttpRequest(
            self, method, url, headers = httpRequestHeaders, body = body, form = form).send()

    def sendHttpRequestToSite(self, webSite, method, path, headers = None, body = None,
                              form = None):
        url = webSite.url
        if path:
            if path[0] == '/':
                while url[-1] == '/':
                    url = url[:-1]
            elif url[-1] != '/':
                url += '/'
            url += path
        return self.sendHttpRequest(method, url, headers = headers, body = body, form = form)


class Principal(WebClient):
    """Simulation of a user and its web navigator"""

    name = None # The user name

    def __init__(self, internet, name):
        WebClient.__init__(self, internet)
        self.name = name


class WebSession(abstractweb.WebSessionMixin, object):
    """Simulation of session of a web site"""

    expirationTime = None # A sample session variable
    isDirty = True
    lassoSessionDump = None
    loginDump = None # Used only by some identity providers
    userId = None # ID of logged user. 

    def __init__(self, token):
        self.token = token

    def save(self):
        pass


class WebSite(abstractweb.WebSiteMixin, WebClient):
    """Simulation of a web site"""

    httpResponseHeaders = {
        'Server': 'Lasso Simulator Web Server',
        }
    lastSessionToken = 0
    providerId = None # The Liberty providerID of this web site
    url = None # The main URL of web site
    users = None
    sessions = None

    def __init__(self, internet, url):
        WebClient.__init__(self, internet)
        self.url = url
        self.userIdsByNameIdentifier = {}
        self.users = {}
        self.sessionTokensByNameIdentifier = {}
        self.sessions = {}
        self.internet.addWebSite(self)

    def addUser(self, name):
        self.users[name] = WebUser(name)

    def createSession(self, client):
        self.lastSessionToken += 1
        session = WebSession(self.lastSessionToken)
        self.sessions[self.lastSessionToken] = session
        client.sessionTokens[self.url] = self.lastSessionToken
        return session

    def getIdentityDump(self, principal):
        session = self.getSessionFromPrincipal(principal)
        user = self.getUserFromSession(session)
        if user is None:
            return None
        return user.lassoIdentityDump

    def getLassoSessionDump(self, principal):
        session = self.getSessionFromPrincipal(principal)
        if session is None:
            return None
        return session.lassoSessionDump

    def getSessionFromNameIdentifier(self, nameIdentifier):
        sessionToken = self.sessionTokensByNameIdentifier.get(nameIdentifier, None)
        if sessionToken is None:
            # The user has no federation on this site or has no authentication assertion for this
            # federation.
            return None
        return self.sessions.get(sessionToken, None)

    def getSessionFromPrincipal(self, principal):
        sessionToken = principal.sessionTokens.get(self.url, None)
        return self.getSessionFromToken(sessionToken)

    def getSessionFromToken(self, sessionToken):
        if sessionToken is None:
            # The user has no web session opened on this site.
            return None
        return self.sessions.get(sessionToken, None)

    def getUserFromNameIdentifier(self, nameIdentifier):
        userId = self.userIdsByNameIdentifier.get(nameIdentifier, None)
        if userId is None:
            # The user has no federation on this site.
            return None
        return self.users.get(userId, None)

    def getUserFromSession(self, session):
        if session is None:
            return None
        userId = session.userId
        if userId is None:
            # The user has no account on this site.
            return None
        return self.users.get(userId, None)

    def handleHttpRequest(self, httpRequest):
        httpRequestHandler = HttpRequestHandler(self, httpRequest)
        return self.handleHttpRequestHandler(httpRequestHandler)

    def handleHttpRequestHandler(self, httpRequestHandler):
        methodName = httpRequestHandler.httpRequest.path.replace('/', '')
        try:
            method = getattr(self, methodName)
        except AttributeError:
            return httpRequestHandler.respond(
                404, 'Path "%s" Not Found.' % httpRequestHandler.httpRequest.path)
        return method(httpRequestHandler)


class WebUser(abstractweb.WebUserMixin, object):
    """Simulation of user of a web site"""

    isDirty = True
    lassoIdentityDump = None
    language = 'fr' # A sample user variable
    uniqueId = None # The user name is used as an ID in this simulation.

    def __init__(self, uniqueId):
        self.uniqueId = uniqueId

    def save(self):
        pass
