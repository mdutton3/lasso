# -*- coding: UTF-8 -*-


# Abstract web classes for HTTP clients and servers or simulators
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


"""Abstract web classes for HTTP clients and servers or simulators"""


class HttpRequestMixin:
    headers = None
    method = None # 'GET' or 'POST' or 'PUT' or...
    url = None
    path = None
    pathAndQuery = None
    query = None
    scheme = None # 'http' or 'https'

    def getFormField(self, name, default = 'none'):
        raise NotImplementedError

    def getQueryBoolean(self, name, default = 'none'):
        try:
            fieldValue = self.getQueryField(name)
        except KeyError:
            if default == 'none':
                raise
            return default
        return fieldValue.lower not in ('', '0', 'false')

    def getQueryField(self, name, default = 'none'):
        if self.query:
            for field in self.query.split('&'):
                fieldName, fieldValue = field.split('=')
                if name == fieldName:
                    return fieldValue
        if default == 'none':
            raise KeyError(name)
        return default


class HttpResponseMixin:
    body = None
    defaultStatusMessages = {
        '100': 'Continue',
        '101': 'Switching Protocols',
        '200': 'OK',
        '201': 'Created',
        '202': 'Accepted',
        '203': 'Non-Authoritative Information',
        '204': 'No Content',
        '205': 'Reset Content',
        '206': 'Partial Content',
        '300': 'Multiple Choices',
        '301': 'Moved Permanently',
        '302': 'Found',
        '303': 'See Other',
        '304': 'Not Modified',
        '305': 'Use Proxy',
        '307': 'Temporary Redirect',
        '400': 'Bad Request',
        '401': 'Unauthorized',
        '402': 'Payment Required',
        '403': 'Forbidden',
        '404': 'Not Found',
        '405': 'Method Not Allowed',
        '406': 'Not Acceptable',
        '407': 'Proxy Authentication Required',
        '408': 'Request Time-out',
        '409': 'Conflict',
        '410': 'Gone',
        '411': 'Length Required',
        '412': 'Precondition Failed',
        '413': 'Request Entity Too Large',
        '414': 'Request-URI Too Large',
        '415': 'Unsupported Media Type',
        '416': 'Requested range not satisfiable',
        '417': 'Expectation Failed',
        '500': 'Internal Server Error',
        '501': 'Not Implemented',
        '502': 'Bad Gateway',
        '503': 'Service Unavailable',
        '504': 'Gateway Time-out',
        '505': 'HTTP Version not supported',
        }
    headers = None
    statusCode = None # 200 or...
    statusMessage = None

    def __init__(self, httpRequestHandler, statusCode, statusMessage = None, headers = None,
                 body = None):
        self.statusCode = statusCode
        if statusMessage:
            self.statusMessage = statusMessage
        else:
            self.statusMessage = self.defaultStatusMessages.get(statusCode)
        httpResponseHeaders = httpRequestHandler.webServer.httpResponseHeaders
        if headers:
            httpResponseHeaders = httpResponseHeaders.copy()
            for name, value in headers.iteritems():
                httpResponseHeaders[name] = value
        if httpResponseHeaders:
            self.headers = httpResponseHeaders
        if body:
            self.body = body

    def send(self, httpRequestHandler):
        raise NotImplementedError


class HttpRequestHandlerMixin:
    httpRequest = None
    HttpResponse = None # Class
    httpResponse = None
    session = None
    user = None
    webServer = None # The web server, which can then redirect to several virtual hosts

    def respond(self, statusCode = 200, statusMessage = None, headers = None, body = None):
        # Session must be saved before responding. Otherwise, when the server is multitasked or
        # multithreaded, it may receive a new HTTP request before the session is saved.
        if self.session is not None and self.session.isDirty:
            self.session.save()

        self.httpResponse = self.HttpResponse(
            self, statusCode, statusMessage = statusMessage, headers = headers, body = body)

        # Session must be saved before responding. Otherwise, when the server is multitasked or
        # multithreaded, it may receive a new HTTP request before the session is saved.
        # FIXME: For some status codes, session must not be saved. See outputXXX methods in http.
        if self.session is not None and self.session.isDirty:
            self.session.save()

        return self.httpResponse.send(self)

    def respondRedirectTemporarily(self, url):
        raise NotImplementedError
