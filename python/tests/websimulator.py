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

    def createSession(self):
        session = abstractweb.HttpRequestHandlerMixin.createSession(self)
        self.httpRequest.client.sessionTokens[self.site.url] = session.token
        return session

    def respondRedirectTemporarily(self, url):
        scheme = url.split('://')[0].lower()
        if scheme not in ('http', 'https'):
            # The url doesn't include host name => add it.
            path = url
            url = self.site.url
            if path:
                if path[0] == '/':
                    while url[-1] == '/':
                        url = url[:-1]
                elif url[-1] != '/':
                    url += '/'
                url += path
        return self.httpRequest.client.redirect(url)


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


class WebClient(abstractweb.WebClientMixin, object):
    internet = None
    keyring = None
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
    lassoLoginDump = None # Used only by some identity providers
    lassoSessionDump = None


class WebUser(abstractweb.WebUserMixin, object):
    """Simulation of user of a web site"""

    lassoIdentityDump = None
    language = 'fr' # A sample user variable


class WebSite(abstractweb.WebSiteMixin, WebClient):
    """Simulation of a web site"""

    instantAuthentication = True # Authentication doesn't use a HTML form.
    url = None # The main URL of web site
    WebSession = WebSession
    WebUser = WebUser

    def __init__(self, internet, url):
        WebClient.__init__(self, internet)
        abstractweb.WebSiteMixin.__init__(self)
        self.url = url
        self.internet.addWebSite(self)

    def authenticate(self, handler, callback, *arguments, **keywordArguments):
        userId = handler.httpRequest.client.keyring.get(self.url, None)
        userAuthenticated = userId in self.users

        import lasso
        authenticationMethod = lasso.samlAuthenticationMethodPassword # FIXME
        if userAuthenticated:
            session = handler.session
            if session is None:
                session = handler.createSession()
            user = handler.user
            if user is None:
                user = handler.createUser()
            session.userId = user.uniqueId
            user.sessionToken = session.token
        return callback(handler, userAuthenticated, authenticationMethod, *arguments,
                        **keywordArguments)

    def handleHttpRequest(self, httpRequest):
        httpRequestHandler = HttpRequestHandler(self, httpRequest)

        # Retrieve session and user.
        sessionToken = httpRequest.client.sessionTokens.get(self.url, None)
        if sessionToken is not None:
            session = self.sessions.get(sessionToken)
            if session is not None:
                httpRequestHandler.session = session
                if session.userId is not None:
                    httpRequestHandler.user = self.users.get(session.userId, None)

        return self.handleHttpRequestHandler(httpRequestHandler)
