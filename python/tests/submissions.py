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


"""Wrapper for HTML form submissions, simulating Web Forms 2 behaviour

See http://whatwg.org/specs/web-forms/2004-06-27-call-for-comments/#x-www-form-xml
"""


import cgi


class AbstractSubmission(object):
    httpRequestHandler = None
    length = None
    mimeType = None

    def __init__(self, httpRequestHandler, contentLength):
        assert httpRequestHandler
        self.httpRequestHandler = httpRequestHandler
        assert isinstance(contentLength, int)
        self.length = contentLength

    def getField(self, name, index = 0, default = None):
        # Return either a string or a sequence of strings.
        fieldList = self.getFieldList(name, index)
        if not fieldList:
            return default
        elif len(fieldList) == 1:
            return fieldList[0]
        else:
            return fieldList

    def getFieldList(self, name, index = 0):
        # Return a sequence of strings.
        raise NotImplementedError

    def getFile(self, name, index = 0, default = None):
        # Return either an instance of FileUpload or a sequence of FileUpload instances.
        fileList = self.getFileList(name, index)
        if not fileList:
            return default
        elif len(fileList) == 1:
            return fileList[0]
        else:
            return fileList

    def getFileList(self, name, index = 0):
        # Return a sequence of FileUpload instances.
        raise NotImplementedError

##     def getRepeat(self, template):
##         raise NotImplementedError

    def hasField(self, name, index = 0):
        raise NotImplementedError

    def hasFile(self, name, index = 0):
        raise NotImplementedError

    def readFile(self):
        raise NotImplementedError


class FakeSubmission(AbstractSubmission):
    _fields = None

    def __init__(self, fields = None, query = None):
        self._fields = {}
        if fields:
            for name, value in fields.items():
                self._fields[name] = [value]
        if query:
            for name, value in cgi.parse_qsl(query, keep_blank_values = True):
                if name in self._fields:
                    self._fields[name].append(value)
                else:
                    self._fields[name] = [value]

    def getFieldList(self, name, index = 0):
        if index == 0 and name in self._fields:
            return self._fields[name]
        return []

    def getFileList(self, name, index = 0):
        return []

    def hasField(self, name, index = 0):
        return index == 0 and name in self._fields

    def hasFile(self, name, index = 0):
        return False

    def readFile(self):
        return None


class FieldStorageSubmission(AbstractSubmission):
    """Submission wrapper for all encoding types handled by module 'cgi':
    'application/x-www-form-urlencoded', 'multipart/form-data'...

    This submission method discards the control index and repetition block parts of the form data
    set. So, for these encoding types, control index is always 0.
    """
    
    fieldStorage = None

    def __init__(self, httpRequestHandler, contentType, contentLength, contentTypeHeader):
        super(FieldStorageSubmission, self).__init__(httpRequestHandler, contentLength)
        assert contentType
        self.mimeType = contentType
        # The use of environ seems to be required by cgi.FieldStorage.
        # It also needs to add "content-type" in headers.
        fakeHeaders = {}
        for key, value in httpRequestHandler.headers.items():
            fakeHeaders[key] = value
        environ = {
            "CONTENT_TYPE": contentTypeHeader,
            "REQUEST_METHOD": httpRequestHandler.command,
            }
        if not "content-type" in fakeHeaders:
            fakeHeaders["content-type"] = environ["CONTENT_TYPE"]
        if contentLength:
            environ["CONTENT_LENGTH"] = str(contentLength)
        splitedPath = httpRequestHandler.path.split("?")
        if len(splitedPath) >= 2:
            httpQuery = splitedPath[1]
            if httpQuery:
                environ["QUERY_STRING"] = httpQuery
        self.fieldStorage = cgi.FieldStorage(
            environ = environ,
            fp = httpRequestHandler.rfile,
            headers = fakeHeaders,
            keep_blank_values = True)

    def getFieldList(self, name, index = 0):
        if index > 0:
            return []
        return [item.value
                for item in self.fieldStorage.list
                if item.name == name and item.filename is None]

    def getFileList(self, name, index = 0):
        if index > 0:
            return []
        return [FileUpload(item.filename, item.type, item.file)
                for item in self.fieldStorage.list
                if item.name == name and item.filename is not None]

    def hasField(self, name, index = 0):
        if index == 0:
            for item in self.fieldStorage.list:
                if item.name == name and item.filename is None:
                    return True
        return False

    def hasFile(self, name, index = 0):
        if index == 0:
            for item in self.fieldStorage.list:
                if item.name == name and item.filename is not None:
                    return True
        return False

    def readFile(self):
        return None


class FileUpload(object):
    file = None
    filename = None # Optional
    mimeType = None # Optional: MIME type with optional parameters.

    def __init__(self, filename, mimeType, file):
        if filename is not None:
            self.filename = filename
        if mimeType is not None:
            self.mimeType = mimeType
        assert file is not None
        self.file = file


class FileUploadSubmission(AbstractSubmission):
    """Submission for exactly one file

    If the enctype attribute is not specified in the form (or is set to the empty string), and the
    form consists of exactly one file upload control with exactly one file selected, then the user
    agent use this submission method.
    Also used for HTTP PUT...

    Note: FileUploadSubmission contains all the FileUpload interface, so that it can be used as a
    FileUpload.
    """

    file = None
    filename = None # Always None

    def __init__(self, httpRequestHandler, contentType, contentLength):
        super(FileUploadSubmission, self).__init__(httpRequestHandler, contentLength)
        assert contentType
        self.mimeType = contentType
        self.file = httpRequestHandler.rfile

    def getFieldList(self, name, index = 0):
        return []

    def getFileList(self, name, index = 0):
        return []

    def hasField(self, name, index = 0):
        return False

    def hasFile(self, name, index = 0):
        return False

    def readFile(self):
        if self.length == 0:
            return None
        return self.file.read(self.length)


class XmlFormSubmission(AbstractSubmission):
    """Submission for encoding type 'application/x-www-form+xml'"""

    file = None
    mimeType = "application/x-www-form+xml"
    
    def __init__(self, httpRequestHandler, contentType, contentLength):
        super(XmlFormSubmission, self).__init__(httpRequestHandler, contentLength)
        assert contentType == self.mimeType
        self.file = httpRequestHandler.rfile

    def getFieldList(self, name, index = 0):
        raise NotImplementedError

    def getFileList(self, name, index = 0):
        return NotImplementedError

    def hasField(self, name, index = 0):
        raise NotImplementedError

    def hasFile(self, name, index = 0):
        raise NotImplementedError

    def readFile(self):
        return None


def readSubmission(httpRequestHandler):
    # Get query, headers and form variables.
    if httpRequestHandler.headers.typeheader is None:
        if httpRequestHandler.command in ("GET", "HEAD", "POST"):
            contentTypeHeader = "application/x-www-form-urlencoded"
        else:
            contentTypeHeader = httpRequestHandler.headers.type
    else:
        contentTypeHeader = httpRequestHandler.headers.typeheader
    contentType, contentTypeOptions = cgi.parse_header(contentTypeHeader)
    contentLength = httpRequestHandler.headers.get("content-length")
    try:
        contentLength = int(contentLength)
    except (TypeError, ValueError):
        contentLength = 0
    if contentType == "application/x-www-form+xml":
        submission = XmlFormSubmission(httpRequestHandler, contentType, contentLength)
    elif contentType in ("application/x-www-form-urlencoded", "multipart/form-data"):
        submission = FieldStorageSubmission(
            httpRequestHandler, contentType, contentLength, contentTypeHeader)
    else:
        submission = FileUploadSubmission(httpRequestHandler, contentType, contentLength)
    return submission
