#! /usr/bin/env python
# -*- coding: utf-8 -*-

import sys
sys.path.insert(0, '../')
import lasso

lasso.init()

####################
# Service provider #
####################
server = lasso.Server.new("../../examples/sp.xml",
                          "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
                          lasso.SignatureMethodRsaSha1)

server.add_provider("../../examples/idp.xml", None, None)

# creation d'une AuthnRequest
splogin = lasso.Login.new(server, None)
ret = splogin.init_authn_request("https://identity-provider:2003/liberty-alliance/metadata")
splogin.request.set_isPassive(0)
splogin.request.set_forceAuthn(1)
#splogin.request.set_nameIDPolicy(lasso.LibNameIDPolicyTypeFederated)
splogin.request.set_relayState("fake")
splogin.request.set_protocolProfile(lasso.libProtocolProfileBrwsArt)

print "Request type =", splogin.request_type
print splogin.request.dump()

print splogin.build_authn_request_msg()
print "message url =", splogin.msg_url
