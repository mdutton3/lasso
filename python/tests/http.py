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


import BaseHTTPServer
import Cookie
import cStringIO
import gzip
import httplib
import os
import socket
import SocketServer
import sys
import time

try:
    from OpenSSL import SSL
except ImportError:
    SSL = None

import abstractweb


try:
    logger
except NameError:
    logger = None
if logger is None:
    import logging as logger


class BaseHTTPSRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def setup(self):
        """
        We need to use socket._fileobject Because SSL.Connection
        doesn't have a 'dup'. Not exactly sure WHY this is, but
        this is backed up by comments in socket.py and SSL/connection.c
        """

        self.connection = self.request # for doPOST
        self.rfile = socket._fileobject(self.request, 'rb', self.rbufsize)
        self.wfile = socket._fileobject(self.request, 'wb', self.wbufsize)


class BaseHTTPSServer(SocketServer.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, privateKeyFilePath,
                 certificateFilePath, peerCaCertificateFile = None,
                 certificateChainFilePath = None, verifyClient = None):
        SocketServer.BaseServer.__init__(self, server_address, RequestHandlerClass)
        self.verifyClient = verifyClient

        ctx = SSL.Context(SSL.SSLv23_METHOD)
        nVerify = SSL.VERIFY_NONE
        ctx.set_options(SSL.OP_NO_SSLv2)

        ctx.use_privatekey_file(privateKeyFilePath)
        ctx.use_certificate_file(certificateFilePath)
        if peerCaCertificateFile:
            ctx.load_verify_locations(peerCaCertificateFile)
        if certificateChainFilePath:
            ctx.use_certificate_chain_file(certificateChainFilePath)
        if verifyClient == 'require':
            nVerify |= SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT
        elif verifyClient in ('optional', 'optional_on_ca'):
            nVerify |= SSL.VERIFY_PEER
        ctx.set_verify(nVerify, self.verifyCallback)

        self.socket = SSL.Connection(ctx, socket.socket(self.address_family, self.socket_type))
        self.server_bind()
        self.server_activate()

    def verifyCallback(self, connection, x509Object, errorNumber, errorDepth, returnCode):
        logger.info('http.HttpsConnection(%s, %s, %s, %s, %s, %s)' % (
            self, connection, x509Object, errorNumber, errorDepth, returnCode))
        return returnCode

    #~ def server_bind(self):
        #~ """Override server_bind to store the server name."""

        #~ SocketServer.TCPServer.server_bind(self)
        #~ host, port = self.socket.getsockname()[:2]
        #~ self.server_name = socket.getfqdn(host)
        #~ self.server_port = port


class HttpRequest(abstractweb.HttpRequestMixin, object):
    handler = None

    def __init__(self, handler):
        self.handler = handler

    def getHeaders(self):
        return self.handler.headers

    def getMethod(self):
        return self.handler.command

    def getPath(self):
        return self.pathAndQuery.split('?', 1)[0]

    def getPathAndQuery(self):
        return self.handler.path

    def getQuery(self):
        splitedPathAndQuery = self.pathAndQuery.split('?', 1)
        if len(splitedPathAndQuery) > 1:
            return splitedPathAndQuery[1]
        else:
            return ''

    def getScheme(self):
        return self.handler.scheme

    def getUrl(self):
        return "%s://%s%s" % (self.scheme, self.headers.get('Host'), self.pathAndQuery)

    headers = property(getHeaders)
    method = property(getMethod)
    path = property(getPath)
    pathAndQuery = property(getPathAndQuery)
    query = property(getQuery)
    scheme = property(getScheme)
    url = property(getUrl)


class HttpResponse(abstractweb.HttpResponseMixin, object):
    def send(self, httpRequestHandler):
        statusCode = self.statusCode
        if statusCode == 404:
            return self.send404(httpRequestHandler)
        assert statusCode in (200, 207)
        if self.headers is None:
            headers = {}
        else:
            headers = self.headers.copy()
        if time.time() > httpRequestHandler.socketCreationTime + 300:
            headers['Connection'] = 'close'
        elif not httpRequestHandler.close_connection:
            headers['Connection'] = 'Keep-Alive'
        # TODO: Could also output Content-MD5.
        lastModified = headers.get('Last-Modified')
        ifModifiedSince = httpRequestHandler.httpRequest.headers.get('If-Modified-Since')
        if lastModified and ifModifiedSince:
            # We don't want to use bandwith if the file was not modified.
            try:
                lastModifiedTime = time.strptime(lastModified[:25], '%a, %d %b %Y %H:%M:%S')
                ifModifiedSinceTime = time.strptime(ifModifiedSince[:25], '%a, %d %b %Y %H:%M:%S')
                if lastModifiedTime[:8] <= ifModifiedSinceTime[:8]:
                    httpRequestHandler.send_response(304, 'Not Modified.')
                    for key in ('Connection', 'Content-Location'):
                        if key in headers:
                            httpRequestHandler.send_header(key, headers[key])
                    httpRequestHandler.setCookie()
                    httpRequestHandler.end_headers()
                    return
            except (ValueError, KeyError):
                pass
        data = self.body
        if data is None:
            data = ''
        if isinstance(data, basestring):
            dataFile = None
            dataSize = len(data)
        else:
            dataFile = data
            data = ''
            if hasattr(dataFile, 'fileno'):
                dataSize = os.fstat(dataFile.fileno())[6]
            else:
                # For StringIO and cStringIO classes.
                dataSize = len(dataFile.getvalue())
        if dataFile is not None:
            assert not data
            data = dataFile.read(1048576) # Read first MB chunk
        contentType = headers.get('Content-Type')
        if contentType and contentType.split(';')[0] == 'text/html' and data.startswith('<?xml'):
            # Internet Explorer 6 renders the page differently when they start with <?xml...>, so
            # skip it.
            i = data.find('\n')
            if i > 0:
                data = data[i + 1:]
            else:
                i = data.find('>')
                if i > 0:
                    data = data[i + 1:]
            dataSize -= i + 1
        # Compress data if possible and if data is not too big.
        acceptEncoding = httpRequestHandler.httpRequest.headers.get('Accept-Encoding', '')
        if 0 < dataSize < 1048576 and 'gzip' in acceptEncoding \
               and 'gzip;q=0' not in acceptEncoding:
            # Since dataSize < 1 MB, the data is fully contained in string.
            zbuf = cStringIO.StringIO()
            zfile = gzip.GzipFile(mode = 'wb',  fileobj = zbuf)
            zfile.write(data)
            zfile.close()
            data = zbuf.getvalue()
            dataSize = len(data)
            headers['Content-Encoding'] = 'gzip'
        headers['Content-Length'] = '%d' % dataSize
        statusMessages = {
            200: 'OK',
            207: 'Multi-Status',
            }
        assert statusCode in statusMessages, 'Unknown status code %d.' % statusCode
        if httpRequestHandler.httpAuthenticationLogoutTrick and statusCode == 200:
            statusCode = 401
            statusMessage = 'Access Unauthorized'
            headers['WWW-Authenticate'] = 'Basic realm="%s"' % httpRequestHandler.realm
        else:
            statusMessage = statusMessages[statusCode]
        httpRequestHandler.send_response(statusCode, statusMessage)
        for key, value in headers.items():
            httpRequestHandler.send_header(key, value)
        httpRequestHandler.setCookie()
        httpRequestHandler.end_headers()
        if httpRequestHandler.httpRequest.method != 'HEAD' and dataSize > 0:
            outputFile = httpRequestHandler.wfile
            if data:
                outputFile.write(data)
            if dataFile is not None:
                while True:
                    chunk = dataFile.read(1048576) # 1 MB chunk
                    if not chunk:
                        break
                    outputFile.write(chunk)

    def send404(self, httpRequestHandler):
        logger.info(self.statusMessage)
        data = '<html><body>%s</body></html>' % self.statusMessage
        return httpRequestHandler.send_error(
            self.statusCode, self.statusMessage, data, setCookie = True)


class HttpRequestHandlerMixin(abstractweb.HttpRequestHandlerMixin):
    canUseCookie = False
#    command = None # Strange
    cookie = None
    httpAuthenticationLogoutTrick = False
    HttpResponse = HttpResponse # Class
    socketCreationTime = None
    protocol_version = 'HTTP/1.1'
    realm = 'HttpRequestHandlerMixin Web Site'
#    requestline = None # Strange
#    request_version = None # Strange
    server_version = 'HttpRequestHandlerMixin/1.0'
    site = None # Class variable
    testCookieSupport = False

    def createSession(self):
        session = abstractweb.HttpRequestHandlerMixin.createSession(self)
        if self.canUseCookie:
            self.testCookieSupport = True
        return session

    def handle(self):
        """Handle multiple requests if necessary."""
        self.httpRequest = HttpRequest(self)
        self.socketCreationTime = time.time()
        try:
            try:
                self.close_connection = True
                self.handle_one_request()
                while not self.close_connection:
                    self.handle_one_request()
            except socket.timeout:
                pass
            except KeyboardInterrupt:
                raise
            except SSL.ZeroReturnError:
                pass
            except SSL.Error, exception:
                raise str((exception, exception[0]))
                if exception[0] == ('PEM routines', 'PEM_read_bio', 'no start line'):
                    pass
                else:
                    self.outputUnknownException()
            except:
                self.outputUnknownException()
        finally:
            del self.socketCreationTime

    def handle_one_request(self):
        """Handle a single HTTP request."""
        self.raw_requestline = self.rfile.readline()
        if not self.raw_requestline:
            self.close_connection = 1
            return
        if not self.parse_request(): # An error code has been sent, just exit
            return
        logger.info(self.raw_requestline.strip())
        logger.debug(str(self.headers))

        # Retrieve the session and user, if possible.

        session = None
        sessionToken = None
        user = None

        # Handle X.509 certificate authentication.
        if hasattr(self.connection, 'get_peer_certificate'):
            clientCertificate = self.connection.get_peer_certificate()
            if clientCertificate:
                user = self.site.authenticateX509User(clientCertificate)
                if user is None:
                    logger.info('Unknown certificate (serial number = %s)'
                                % clientCertificate.get_serial_number())
                else:
                    sessionToken = user.sessionToken
                    if sessionToken is not None:
                        session = self.site.sessions.get(sessionToken)
                        if session is None:
                            sessionToken = None
                            del user.sessionToken
                        else:
                            # For security reasons, we want to minimize the publication of
                            # session token (it is better not to store it in a cookie or in
                            # URLs). The client need to send the certificate each time, for the
                            # session to continue.
                            if session.publishToken:
                                del session.publishToken

        # Handle HTTP authentication.
        authorization = self.httpRequest.headers.get('authorization')
        if self.httpRequest.hasQueryField('login') and not authorization \
               and rootDataHolder.getConfigBoolean('yep:useHttpAuthentication', default = False):
            # Ask for HTTP authentication.
            return self.outputErrorUnauthorized(httpPath)
        if self.httpRequest.hasQueryField('logout') and authorization:
            # Since HTTP authentication provides no way to logout,  we send a status
            # Unauthorized to force the user to press the cancel button. But instead of
            # sending an error page immediately, we send the real page, so the user will see
            # the page instead of an error message.
            authorization = None
            self.httpAuthenticationLogoutTrick = True
        if authorization:
            try:
                authenticationScheme, credentials = authorization.split(None, 1)
            except ValueError:
                return self.outputErrorUnauthorized(httpPath)
            authenticationScheme = authenticationScheme.lower()
            if authenticationScheme == 'basic':
                loginAndPassword = base64.decodestring(credentials)
                try:
                    login, password = loginAndPassword.split(':', 1)
                except:
                    login = loginAndPassword
                    password = ''
                logger.debug('Basic authentication: login = "%s" / password = "%s"' % (
                    login, password))
                if password:
                    user = self.site.authenticateLoginPasswordUser(login, password)
                    if user is None:
                        logger.info('Unknown user (login = "%s" / password = "%s")' % (
                            login, password))
                        return self.outputErrorUnauthorized(httpPath)
                    else:
                        sessionToken = user.sessionToken
                        if sessionToken is not None:
                            session = self.site.sessions.get(sessionToken)
                            if session is None:
                                sessionToken = None
                                del user.sessionToken
                            else:
                                # For security reasons, we want to minimize the publication of
                                # session token (it is better not to store it in a cookie or in
                                # URLs). The client need to send the certificate each time, for the
                                # session to continue.
                                if session.publishToken:
                                    del session.publishToken
                elif login:
                    # No password was given. Assume login contains a session token.
                    # TODO: sanity chek on login
                    sessionToken = login
                    session = self.site.sessions.get(sessionToken)
                    if session is not None and session.userId is not None:
                        user = self.site.users.get(session.userId)
                        if user is not None and user.sessionToken != session.token:
                            # Sanity check.
                            user.sessionToken = session.token
            else:
                logger.info('Unknown authentication scheme = %s' % authenticationScheme)
                return self.outputErrorUnauthorized(httpPath)

        # Handle use of cookies, session and user.
        cookie = None
        cookieContent = {}
        if self.httpRequest.headers.has_key('Cookie'):
            logger.debug('Cookie received:')
            cookie = Cookie.SimpleCookie(
                self.httpRequest.headers['Cookie'])
            for k, v in cookie.items():
                cookieContent[k] = v.value
                logger.debug('  %s = %s' % (k, cookieContent[k]))
        self.cookie = cookie

        sessionToken = None
        sessionTokenInCookie = False
        if self.httpRequest.hasQueryField('sessionToken'):
            sessionToken = self.httpRequest.getQueryField('sessionToken')
            if not sessionToken:
                sessionToken = None
            if session is not None and sessionToken != session.token:
                sessionToken = None
        if cookieContent.has_key('sessionToken'):
            cookieSessionToken = cookieContent['sessionToken']
            if cookieSessionToken:
                if session is None or cookieSessionToken == session.token:
                    if sessionToken is None:
                        sessionToken = cookieSessionToken
                    if cookieSessionToken == sessionToken:
                        sessionTokenInCookie = True
        canUseCookie = True
        if session is None and sessionToken is not None:
            session = self.site.sessions.get(sessionToken)
            if session is None:
                sessionToken = None
                sessionTokenInCookie = False
            else:
                if user is None:
                    if session.userId is not None:
                        user = self.site.users.get(session.userId)
                        if user is not None and user.sessionToken != sessionToken:
                            # Sanity check.
                            user.sessionToken = sessionToken
                else:
                    # The user has been authenticated (using HTTP or X.509 authentication), but the
                    # associated session didn't exist (or was too old, or...). So, update
                    # its sessionToken.
                    user.sessionToken = sessionToken
                    # For security reasons, we want to minimize the publication of session
                    # token (it is better not to store it in a cookie or in URLs).
                    if session.publishToken:
                        del session.publishToken
        self.canUseCookie = canUseCookie
        if session is None and user is not None:
            # The user has been authenticated (using HTTP or X.509 authentication), but the session
            # doesn't exist yet (or was too old, or...). Create a new session.
            session = self.createSession()
            # For security reasons, we want to minimize the publication of session
            # token (it is better not to store it in a cookie or in URLs).
            # session.publishToken = False # False is the default value.
            session.userId = user.uniqueId
            user.sessionToken = session.token
        else:
            self.session = session
        if session is not None:
            if not sessionTokenInCookie:
                # The sessionToken is valid but is not stored in the cookie. So, don't try to
                # use cookie.
                canUseCookie = False
            logger.debug('Session: %s' % session.simpleLabel)
        self.user = user
        if user is not None:
            logger.debug('User: %s' % user.simpleLabel)

        # Now, the HTTP request handler has done everything it could done. Transfer the processing
        # to the site.

        try:
            self.site.handleHttpRequestHandler(self)
        except IOError:
            logger.exception('An exception occured:')
            path = self.path.split('?')[0]
            return self.outputErrorNotFound(path)

    def log_message(self, format, *arguments):
        """Override BaseHTTPServer.HttpRequestHandler method to use logger.

        Do not use. Use logger instead.
        """

        logger.info('%s - - [%s] %s' % (
            self.address_string(), self.log_date_time_string(), format % arguments))

##     def outputAlert(self, data, title = None, url = None):
##         import html
##         if title is None:
##             title = N_('Alert')
##         # FIXME: Handle XSLT template.
##         if url:
##             buttonsBar = html.div(class_ = 'buttons-bar')
##             actionButtonsBar = html.span(class_ = 'action-buttons-bar')
##             buttonsBar.append(actionButtonsBar)
##             actionButtonsBar.append(html.a(_('OK'), class_ = 'button', href = url))
##         else:
##             buttonsBar = None
##         layout = html.html(
##             html.head(html.title(_(title))),
##             html.body(
##                 html.p(_(data), class_ = 'alert'),
##                 buttonsBar,
##                 ),
##             )
##         self.outputData(layout.serialize(), contentLocation = None, mimeType = 'text/html')

##     def outputData(self, data, contentLocation = None, headers = None, mimeType = None,
##                    modificationTime = None, successCode = 200):
##         # Session and user must be saved before responding. Otherwise, when the server is
##         # multitasked or multithreaded, it may receive a new HTTP request before the session is
##         # saved.
##         if self.session is not None and self.session.isDirty:
##             self.session.save()
##         if self.user is not None and self.user.isDirty:
##             self.user.save()

##         if isinstance(data, basestring):
##             dataFile = None
##             dataSize = len(data)
##         else:
##             dataFile = data
##             data = ''
##             if hasattr(dataFile, 'fileno'):
##                 dataSize = os.fstat(dataFile.fileno())[6]
##             else:
##                 # For StringIO and cStringIO classes.
##                 dataSize = len(dataFile.getvalue())

##         if headers is None:
##             headers = {}
##         if time.time() > self.socketCreationTime + 300:
##             headers['Connection'] = 'close'
##         elif not self.close_connection:
##             headers['Connection'] = 'Keep-Alive'
##         if contentLocation is not None:
##             headers['Content-Location'] = contentLocation
##         if mimeType:
##             headers['Content-Type'] = '%s; charset=utf-8' % mimeType
##         if modificationTime:
##             headers['Last-Modified'] = time.strftime('%a, %d %b %Y %H:%M:%S GMT', modificationTime)
##         # TODO: Could also output Content-MD5.
##         ifModifiedSince = self.headers.get('If-Modified-Since')
##         if modificationTime and ifModifiedSince:
##             # We don't want to use bandwith if the file was not modified.
##             try:
##                 ifModifiedSinceTime = time.strptime(ifModifiedSince[:25], '%a, %d %b %Y %H:%M:%S')
##                 if modificationTime[:8] <= ifModifiedSinceTime[:8]:
##                     self.send_response(304, 'Not Modified.')
##                     for key in ('Connection', 'Content-Location'):
##                         if key in headers:
##                             self.send_header(key, headers[key])
##                     self.setCookie()
##                     self.end_headers()
##                     return
##             except (ValueError, KeyError):
##                 pass
##         if dataFile is not None:
##             assert not data
##             data = dataFile.read(1048576) # Read first MB chunk
##         if mimeType == 'text/html' and data.startswith('<?xml'):
##             # Internet Explorer 6 renders the page differently when they start with <?xml...>, so
##             # skip it.
##             i = data.find('\n')
##             if i > 0:
##                 data = data[i + 1:]
##             else:
##                 i = data.find('>')
##                 if i > 0:
##                     data = data[i + 1:]
##             dataSize -= i + 1
##         # Compress data if possible and if data is not too big.
##         acceptEncoding = self.headers.get('Accept-Encoding', '')
##         if 0 < dataSize < 1048576 and 'gzip' in acceptEncoding \
##                and 'gzip;q=0' not in acceptEncoding:
##             # Since dataSize < 1 MB, the data is fully contained in string.
##             zbuf = cStringIO.StringIO()
##             zfile = gzip.GzipFile(mode = 'wb',  fileobj = zbuf)
##             zfile.write(data)
##             zfile.close()
##             data = zbuf.getvalue()
##             dataSize = len(data)
##             headers['Content-Encoding'] = 'gzip'
##         headers['Content-Length'] = '%d' % dataSize
##         successMessages = {
##             200: 'OK',
##             207: 'Multi-Status',
##             }
##         assert successCode in successMessages, 'Unknown success code %d.' % successCode
##         if self.httpAuthenticationLogoutTrick and successCode == 200:
##             successCode = 401
##             successMessage = 'Access Unauthorized'
##             headers['WWW-Authenticate'] = 'Basic realm="%s"' % self.realm
##         else:
##             successMessage = successMessages[successCode]
##         self.send_response(successCode, successMessage)
##         for key, value in headers.items():
##             self.send_header(key, value)
##         self.setCookie()
##         self.end_headers()
##         if self.httpRequest.method != 'HEAD' and dataSize > 0:
##             outputFile = self.wfile
##             if data:
##                 outputFile.write(data)
##             if dataFile is not None:
##                 while True:
##                     chunk = dataFile.read(1048576) # 1 MB chunk
##                     if not chunk:
##                         break
##                     outputFile.write(chunk)
##         return

##     def outputErrorAccessForbidden(self, filePath):
##         if filePath is None:
##             message = 'Access Forbidden'
##         else:
##             message = 'Access to "%s" Forbidden.' % filePath
##         logger.info(message)
##         data = '<html><body>%s</body></html>' % message
##         return self.send_error(403, message, data, setCookie = True)

##     def outputErrorBadRequest(self, reason):
##         if reason:
##             message = 'Bad Request: %s' % reason
##         else:
##             message = 'Bad Request'
##         logger.info(message)
##         data = '<html><body>%s</body></html>' % message
##         return self.send_error(400, message, data)

    def outputErrorInternalServer(self):
        message = 'Internal Server Error'
        logger.info(message)
        data = '<html><body>%s</body></html>' % message
        return self.send_error(500, message, data)

##     def outputErrorMethodNotAllowed(self, reason):
##         if reason:
##             message = 'Method Not Allowed: %s' % reason
##         else:
##             message = 'Method Not Allowed'
##         logger.info(message)
##         data = '<html><body>%s</body></html>' % message
##         # This error doesn't need a pretty interface.
##         # FIXME: Add an 'Allow' header containing a list of valid methods for the requested
##         # resource.
##         return self.send_error(405, message, data)

##     def outputErrorNotFound(self, filePath):
##         if filePath is None:
##             message = 'Not Found'
##         else:
##             message = 'Path "%s" Not Found.' % filePath
##         logger.info(message)
##         data = '<html><body>%s</body></html>' % message
##         return self.send_error(404, message, data, setCookie = True)

##     def outputErrorUnauthorized(self, filePath):
##         if filePath is None:
##             message = 'Access Unauthorized'
##         else:
##             message = 'Access to "%s" Unauthorized.' % filePath
##         logger.info(message)
##         data = '<html><body>%s</body></html>' % message
##         headers = {}
##         return self.send_error(401, message, data, headers, setCookie = True)

##     def outputInformationContinue(self):
##         message = 'Continue'
##         logger.debug(message)
##         self.send_response(100, message)

##     def outputSuccessCreated(self, filePath):
##         if filePath is None:
##             message = 'Created'
##         else:
##             message = 'File "%s" Created.' % filePath
##         logger.debug(message)
##         data = '<html><body>%s</body></html>' % message
##         self.send_response(201, message)
##         if time.time() > self.socketCreationTime + 300:
##             self.send_header('Connection', 'close')
##         elif not self.close_connection:
##             self.send_header('Connection', 'Keep-Alive')
##         self.send_header('Content-Type', 'text/html; charset=utf-8')
##         self.send_header('Content-Length', '%d' % len(data))
##         self.setCookie()
##         self.end_headers()
##         if self.httpRequest.method != 'HEAD':
##             self.wfile.write(data)

##     def outputSuccessNoContent(self):
##         message = 'No Content'
##         logger.debug(message)
##         self.send_response(204, message)
##         if time.time() > self.socketCreationTime + 300:
##             self.send_header('Connection', 'close')
##         elif not self.close_connection:
##             self.send_header('Connection', 'Keep-Alive')
##         self.setCookie()
##         self.end_headers()

    def outputUnknownException(self):
        import traceback, cStringIO
        f = cStringIO.StringIO()
        traceback.print_exc(file = f)
        exceptionTraceback = f.getvalue()
        exceptionType, exception = sys.exc_info()[:2]
        logger.debug("""\
An exception "%(exception)s" of class "%(exceptionType)s" occurred.

%(traceback)s
""" % {
            'exception': exception,
            'exceptionType': exceptionType,
            'traceback': exceptionTraceback,
            })
        return self.outputErrorInternalServer()

    def respondRedirectTemporarily(self, url):
        # Session and user must be saved before responding. Otherwise, when the server is
        # multitasked or multithreaded, it may receive a new HTTP request before the session is
        # saved.
        if self.session is not None and self.session.isDirty:
            self.session.save()
        if self.user is not None and self.user.isDirty:
            self.user.save()

        message = 'Moved Temporarily to "%s".' % url
        logger.debug(message)
        data = '<html><body>%s</body></html>' % message
        self.send_response(302, message)
        self.send_header('Location', url)
        if time.time() > self.socketCreationTime + 300:
            self.send_header('Connection', 'close')
        elif not self.close_connection:
            self.send_header('Connection', 'Keep-Alive')
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', '%d' % len(data))
        self.setCookie()
        self.end_headers()
        if self.httpRequest.method != 'HEAD':
            self.wfile.write(data)

    def send_error(self, code, message = None, data = None, headers = None, setCookie = False):
        # Session and user must be saved before responding. Otherwise, when the server is
        # multitasked or multithreaded, it may receive a new HTTP request before the session is
        # saved.
        if self.session is not None and self.session.isDirty:
            self.session.save()
        if self.user is not None and self.user.isDirty:
            self.user.save()

        shortMessage, longMessage = self.responses.get(code, ('???', '???'))
        if message is None:
            message = shortMessage
        if not data:
            explain = longMessage
            data = self.error_message_format % {
                'code': code,
                'message': message,
                'explain': longMessage,
                }
        self.send_response(code, message)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', '%d' % len(data))
        self.send_header('Connection', 'close')
        if headers is not None:
            for name, value in headers.items():
                self.send_header(name, value)
        if setCookie:
            self.setCookie()
        self.end_headers()
        if self.httpRequest.method != 'HEAD' and code >= 200 and code not in (204, 304):
            self.wfile.write(data)

    def setCookie(self):
        if not self.canUseCookie:
            return
        oldCookie = self.cookie
        cookie = Cookie.SimpleCookie()
        cookieContent = {}
        session = self.session
        if session is not None and session.publishToken:
            cookieContent['sessionToken'] = session.token
        for key, value in cookieContent.items():
            cookie[key] = value
            cookie[key]['path'] = '/'
        if not cookieContent:
            if oldCookie:
                for key, morsel in oldCookie.items():
                    cookie[key] = ''
                    cookie[key]['max-age'] = 0
                    cookie[key]['path'] = '/'
            else:
                cookie = None
        if cookie is not None:
            # Is new cookie different from previous one?
            sameCookie = False
            if oldCookie is not None and cookie.keys() == oldCookie.keys():
                for key, morsel in cookie.items():
                    oldMorsel = oldCookie[key]
                    if morsel.value != oldMorsel.value:
                        break
                else:
                    sameCookie = True
            if not sameCookie:
                for morsel in cookie.values():
                    self.send_header(
                        'Set-Cookie', morsel.output(header = '')[1:])
                self.cookie = cookie


class HttpRequestHandler(HttpRequestHandlerMixin, BaseHTTPServer.BaseHTTPRequestHandler):
    scheme = 'http'


class HttpsConnection(httplib.HTTPConnection):
    certificateFile = None
    default_port = httplib.HTTPS_PORT
    peerCaCertificateFile = None
    privateKeyFile = None

    def __init__(self, host, port = None, privateKeyFile = None, certificateFile = None,
                 peerCaCertificateFile = None, strict = None):
        httplib.HTTPConnection.__init__(self, host, port, strict)
        self.privateKeyFile = privateKeyFile
        self.certificateFile = certificateFile
        self.peerCaCertificateFile = peerCaCertificateFile

    def connect(self):
        """Connect to a host on a given (SSL) port."""

        context = SSL.Context(SSL.SSLv23_METHOD)
        # Demand a certificate.
        context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, self.verifyCallback)
        if self.privateKeyFile:
            context.use_privatekey_file(self.privateKeyFile)
        if self.certificateFile:
            context.use_certificate_file(self.certificateFile)
        if self.peerCaCertificateFile:
            context.load_verify_locations(self.peerCaCertificateFile)

        # Strange hack, that is derivated from httplib.HTTPSConnection, but that I (Emmanuel) don't
        # really understand...
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sslSocket = SSL.Connection(context, sock)
        sslSocket.connect((self.host, self.port))
        self.sock = httplib.FakeSocket(sslSocket, sslSocket)

    def verifyCallback(self, connection, x509Object, errorNumber, errorDepth, returnCode):
        logger.debug('http.HttpsConnection(%s, %s, %s, %s, %s, %s)' % (
            self, connection, x509Object, errorNumber, errorDepth, returnCode))
        # FIXME: What should be done?
        return returnCode


class HttpsRequestHandler(HttpRequestHandlerMixin, BaseHTTPSRequestHandler):
    scheme = 'https'


# We use ForkingMixIn instead of ThreadingMixIn because the Python binding for
# libxml2 limits the number of registered xpath functions to 10. Even if we use
# only one xpathContext, this would limit the number of threads to 10, wich is
# not enough for a web server.

class HttpServer(SocketServer.ForkingMixIn, BaseHTTPServer.HTTPServer):
    pass

class HttpsServer(SocketServer.ForkingMixIn, BaseHTTPSServer):
    pass
