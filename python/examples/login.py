#! /usr/bin/env python
# -*- coding: utf-8 -*-

import sys
sys.path.insert(0, '../')
import string

import lasso

lasso.init()

####################
# Service provider #
####################
server = lasso.Server.new("../../examples/sp.xml",
                          "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
                          lasso.SignatureMethodRsaSha1)

server.add_provider("../../examples/idp.xml", None, None)

# create AuthnRequest
splogin = lasso.Login.new(server, None)
ret = splogin.init_authn_request("https://identity-provider:2003/liberty-alliance/metadata")
splogin.request.set_isPassive(0)
splogin.request.set_forceAuthn(1)
#splogin.request.set_nameIDPolicy(lasso.LibNameIDPolicyTypeFederated)
splogin.request.set_relayState("fake")
splogin.request.set_protocolProfile(lasso.libProtocolProfileBrwsArt)

print "Request type =", splogin.request_type
print splogin.request.dump()

splogin.build_authn_request_msg()
print "message url =", splogin.msg_url

#####################
# Identity provider #
#####################
server = lasso.Server.new("../../examples/idp.xml",
                          None, "../../examples/rsakey.pem", "../../examples/rootcert.pem",
                          lasso.SignatureMethodRsaSha1)

server.add_provider("../../examples/sp.xml",
                    "../../examples/rsapub.pem", "../../examples/rsacert.pem")

# create AuthnResponse OR artifact (depending ProtocolProfile)
idplogin = lasso.Login.new(server, None)

# get query part in msg_url
authn_request_msg = string.split(splogin.msg_url, '?')[1]
ret = idplogin.init_from_authn_request_msg(authn_request_msg,
                                           lasso.HttpMethodRedirect);

print "ProtocolProfile =", idplogin.protocolProfile

must_authenticate = idplogin.must_authenticate()
print "User must be authenticated =", idplogin.protocolProfile

if idplogin.protocolProfile == 1:
    ret = idplogin.build_artifact_msg(1,
                                      lasso.samlAuthenticationMethodPassword,
                                      "",
                                      lasso.HttpMethodRedirect)
    print "ret = %d, msg_url = %s" % (ret, idplogin.msg_url)
