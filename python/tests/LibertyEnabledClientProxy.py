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

from websimulator import *


class LibertyEnabledClientProxy(WebClient):
    # A service provider MAY provide a list of identity providers it recognizes by including the
    # <lib:IDPList> element in the <lib:AuthnRequestEnvelope>. The format and processing rules for
    # the identity provider list MUST be as defined in [LibertyProtSchema].

    # The identity provider list can be used by the LECP to create a user identifier to be
    # presented to the Principal. For example, the LECP could compare the list of the Principal's
    # known identities (and the identities of the identity provider that provides those identities)
    # against the list provided by the service provider and then only display the intersection.

    # If the service provider does not support the LECP-advertised Liberty version, the service
    # provider MUST return to the LECP an HTTP 501 response with the reason phrase "Unsupported
    # Liberty Version."
    #
    # The responses in step 3 and step 6 SHOULD NOT be cached. To this end service providers and
    # identity providers SHOULD place both "Cache-Control: no-cache" and "Pragma: no-cache" on
    # their responses to ensure that the LECP and any intervening proxies will not cache the
    # response.

    # If the LECP discovers a syntax error due to the service provider or cannot proceed any
    # further for other reasons (for example, cannot resolve identity provider, cannot reach the
    # identity provider, etc.), the LECP MUST return to the service provider a <lib:AuthnResponse>
    # with a <samlp:Status> indicating the desired error element as defined in
    # [LibertyProtSchema]. The <lib:AuthnResponse> containing the error status MUST be sent using
    # a POST to the service provider's assertion consumer service URL obtained from the
    # <lib:AssertionConsumerServiceURL> element of the <lib:AuthnRequestEnvelope>. The POST MUST
    # be a form that contains the field LARES with the value being the <lib:AuthnResponse>
    # protocol message as defined in [LibertyProtSchema], containing the <samlp:Status>. The
    # <lib:AuthnResponse> MUST be encoded by applying a base64 transformation (refer to
    # [RFC2045]) to the <lib:AuthnResponse> and all its elements.

    httpRequestHeaders = WebClient.httpRequestHeaders.copy()
    httpRequestHeaders.update({
        # FIXME: Is this the correct syntax for several URLs in LIBV?
        'Liberty-Enabled': 'LIBV=urn:liberty:iff:2003-08,http://projectliberty.org/specs/v1',
        'Liberty-Agent': 'LassoSimulator/0.0.0',
        # FIXME: As an alternative to 'Liberty-Enabled' header, a user agent may use:
        # 'User-Agent': ' '.join((
        #     httpRequestHeaders['User-Agent'],
        #     'LIBV=urn:liberty:iff:2003-08,http://projectliberty.org/specs/v1'))
        'Accept': ','.join((httpRequestHeaders['Accept'], 'application/vnd.liberty-request+xml'))
        })
    idpSite = None # The identity provider, this LECP will use to authenticate users.
    lassoServerDump = None
    principal = None

    def __init__(self, internet):
        WebClient.__init__(self, internet)

    def getLassoServer(self):
        return lasso.Server.new_from_dump(self.lassoServerDump)

    def getSessionTokens(self):
        # LECP is a proxy, not au principal, so it doesn't have its own sessionTokens.
        if self.principal is None:
            return {}
        return self.principal.sessionTokens

    def login(self, principal, site, path):
        self.principal = principal

        httpResponse = self.sendHttpRequestToSite(site, 'GET', path)
        failUnlessEqual(
            httpResponse.headers['Content-Type'], 'application/vnd.liberty-request+xml')
        lassoServer = self.getLassoServer()
        lecp = lasso.Lecp.new(lassoServer)
        authnRequestEnvelope = httpResponse.body
        lecp.process_authn_request_envelope_msg(authnRequestEnvelope)
        # FIXME: The service provider could return an IDPList in authnRequestEnvelope, so that
        # we verify that self.idpSingleSignOnServiceUrl belongs to one of them
        lecp.build_authn_request_msg(self.idpSite.providerId)
        failUnless(lecp.msg_url)
        failUnless(lecp.msg_body)
        httpResponse = self.sendHttpRequest(
            'POST', lecp.msg_url, headers = {'Content-Type': 'text/xml'},
            body = lecp.msg_body)
        failUnlessEqual(
            httpResponse.headers.get('Content-Type', None), 'application/vnd.liberty-response+xml')
        lecp.process_authn_response_envelope_msg(httpResponse.body)
        lecp.build_authn_response_msg()
        failUnless(lecp.msg_url)
        failUnless(lecp.msg_body)

        del self.principal

        # FIXME: Should we use 'multipart/form-data' for forms?
        return self.sendHttpRequest(
            'POST', lecp.msg_url, headers = {'Content-Type': 'multipart/form-data'},
            form = {'LARES': lecp.msg_body})

    def setKeyring(self, keyring):
        # LECP is a proxy, not au principal, so it doesn't have its own keyring.
        pass

    def setSessionTokens(self, sessionTokens):
        # LECP is a proxy, not au principal, so it doesn't have its own sessionTokens.
        pass

    sessionTokens = property(getSessionTokens, setSessionTokens)
