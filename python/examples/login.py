#! /usr/bin/env python
# -*- coding: utf-8 -*-

import sys
sys.path.insert(0, '../')
import string

import lasso

####################
# Service provider #
####################
server = lasso.Server.new("../../examples/sp.xml",
                          "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
                          lasso.SIGNATURE_METHOD_RSA_SHA1)

server.add_provider("../../examples/idp.xml", None, None)
server_dump = server.dump()
server.destroy()

# create AuthnRequest
server = lasso.Server.new_from_dump(server_dump)
splogin = lasso.Login.new(server)
ret = splogin.init_authn_request("https://identity-provider:2003/liberty-alliance/metadata")
splogin.request.set_isPassive(0)
splogin.request.set_forceAuthn(1)
splogin.request.set_nameIDPolicy(lasso.libNameIDPolicyTypeFederated)
splogin.request.set_relayState("fake")
splogin.request.set_consent(lasso.LIB_CONSENT_OBTAINED)
splogin.request.set_protocolProfile(lasso.LIB_PROTOCOL_PROFILE_BRWS_ART)

splogin.build_authn_request_msg()
print "message url =", splogin.msg_url

#####################
# Identity provider #
#####################
server = lasso.Server.new("../../examples/idp.xml",
                          None, "../../examples/rsakey.pem", "../../examples/rootcert.pem",
                          lasso.SIGNATURE_METHOD_RSA_SHA1)

server.add_provider("../../examples/sp.xml",
                    "../../examples/rsapub.pem", "../../examples/rsacert.pem")

# create AuthnResponse OR artifact (depending ProtocolProfile)
idplogin = lasso.Login.new(server)

# get query part in msg_url
authn_request_msg = string.split(splogin.msg_url, '?')[1]
ret = idplogin.init_from_authn_request_msg(authn_request_msg,
                                           lasso.HTTP_METHOD_REDIRECT)

print "ProtocolProfile =", idplogin.protocolProfile

must_authenticate = idplogin.must_authenticate()
print "User must be authenticated =", must_authenticate

if idplogin.protocolProfile == lasso.LOGIN_PROTOCOL_PROFILE_BRWS_ART:
    ret = idplogin.build_artifact_msg(1,
                                      lasso.SAML_AUTHENTICATION_METHOD_PASSWORD,
                                      "",
                                      lasso.HTTP_METHOD_REDIRECT)
    print "ret = %d, msg_url = %s" % (ret, idplogin.msg_url)
    sess = idplogin.get_session()
    print sess.providerIDs

####################
# Service provider #
####################
server = lasso.Server.new("../../examples/sp.xml",
                          "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
                          lasso.SIGNATURE_METHOD_RSA_SHA1)

server.add_provider("../../examples/idp.xml", None, None)

# create Request OR finish (if an authnResponse was received)
splogin = lasso.Login.new(server)

response_msg = string.split(idplogin.msg_url, '?')[1]
ret = splogin.init_request(response_msg,
                           lasso.HTTP_METHOD_REDIRECT)

ret = splogin.build_request_msg()
print "ret = %d, msg_url = %s, msg_body = %s" % (ret, splogin.msg_url, splogin.msg_body)

#####################
# Identity provider #
#####################
server = lasso.Server.new("../../examples/idp.xml",
                          None, "../../examples/rsakey.pem", "../../examples/rootcert.pem",
                          lasso.SIGNATURE_METHOD_RSA_SHA1)

server.add_provider("../../examples/sp.xml",
                    "../../examples/rsapub.pem", "../../examples/rsacert.pem")

# create Response
idplogin = lasso.Login.new(server)

ret = idplogin.process_request_msg(splogin.msg_body)
print "samlp:AssertionArtifact = %s" % idplogin.assertionArtifact
