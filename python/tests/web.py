# -*- coding: UTF-8 -*-


# HTTP Client and Server Enhanced Classes
# By: Frederic Peters <fpeters@entrouvert.com>
#     Emmanuel Raviart <eraviart@entrouvert.com>
#
# Copyright (C) 2004 Entr'ouvert
# http://www.entrouvert.org
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.


"""HTTP client and server enhanced classes

Features:
- HTTPS using OpenSSL;
- web sessions (with or without cookie);
- user authentication (support of basic HTTP-authentication, X.509v3 certificate authentication,
  HTML based authentication, etc).
"""


import urlparse

from OpenSSL import SSL

import abstractweb
import http


class ReceivedHttpResponse(object):
    body = None
    headers = None
    statusCode = None # 200 or...
    statusMessage = None

    def __init__(self, statusCode = 200, statusMessage = None, headers = None, body = None):
        if statusCode:
            self.statusCode = statusCode
        if statusMessage:
            self.statusMessage = statusMessage
        if headers:
            self.headers = headers
        if body:
            self.body = body
    

class WebClient(abstractweb.WebClientMixin, object):
    certificateAbsolutePath = None
    privateKeyAbsolutePath = None
    peerCaCertificateAbsolutePath = None

    def sendHttpRequest(self, method, url, headers = None, body = None):
        parsedUrl =  urlparse.urlparse(url)
        addressingScheme, hostName, path = parsedUrl[:3]
        if addressingScheme == 'https':
            connection = http.HttpsConnection(
                hostName, None, self.privateKeyAbsolutePath, self.certificateAbsolutePath,
                self.peerCaCertificateAbsolutePath)
        else:
            connection = httplib.HTTPConnection(hostName)
        if headers:
            httpRequestHeaders = self.httpRequestHeaders.copy()
            for name, value in headers.iteritems():
                httpRequestHeaders[name] = value
        else:
            httpRequestHeaders = self.httpRequestHeaders
        failUnless('Content-Type' in httpRequestHeaders)
        try:
            connection.request('POST', path, body, httpRequestHeaders)
        except SSL.Error, error:
            if error.args and error.args[0] and error.args[0][0] \
                   and error.args[0][0][0] == 'SSL routines':
                logger.debug('SSL Error in sendHttpRequest. Error = %s' % repr(error))
            raise
        response = connection.getresponse()
        try:
            body = response.read()
        except SSL.SysCallError, error:
            logger.debug('No SOAP answer in sendHttpRequest. Error = %s' % repr(error))
            raise
        httpResponse = ReceivedHttpResponse(response.status, response.reason, response.msg, body)
        return httpResponse


class WebSession(abstractweb.WebSessionMixin, object):
    """Simulation of session of a web site"""

    expirationTime = None # A sample session variable
    lassoLoginDump = None # Used only by some identity providers
    lassoSessionDump = None
    publishToken = False


class WebUser(abstractweb.WebUserMixin, object):
    """Simulation of user of a web site"""

    lassoIdentityDump = None
    language = 'fr' # A sample user variable
    password = None


class WebSite(abstractweb.WebSiteMixin, WebClient):
    instantAuthentication = True # Authentication doesn't use a HTML form.
    url = None # The main URL of web site
    WebSession = WebSession
    WebUser = WebUser

    def __init__(self, url):
        WebClient.__init__(self)
        abstractweb.WebSiteMixin.__init__(self)
        self.url = url

    def authenticate(self, handler, callback, *arguments, **keywordArguments):
        user = handler.user
        if user is None:
            failUnless(handler.useHttpAuthentication)
            return handler.outputErrorUnauthorized(handler.httpRequest.path)
        else:
            # The user is already authenticated using HTTP authentication.
            userAuthenticated = True

        import lasso
        authenticationMethod = lasso.samlAuthenticationMethodPassword # FIXME
        if userAuthenticated:
            session = handler.session
            if session is None:
                session = handler.createSession()
            # No need to publish token, because we are using HTTP authentication.
            if session.publishToken:
                del session.publishToken
            user = handler.user
            if user is None:
                user = handler.createUser()
            session.userId = user.uniqueId
            user.sessionToken = session.token
        return callback(handler, userAuthenticated, authenticationMethod, *arguments,
                        **keywordArguments)

    def authenticateLoginPasswordUser(self, login, password):
        # We should check login & password and return the user if one matches or None otherwise.
        # FIXME: Check password also.
        return self.users.get(login)
