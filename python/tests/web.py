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


import abstractweb


class WebSite(abstractweb.WebSiteMixin, WebClient):
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
        FIXME: TODO.

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
