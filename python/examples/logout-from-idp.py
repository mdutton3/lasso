#! /usr/bin/env python
# -*- coding: utf-8 -*-

import sys
sys.path.insert(0, '../')
import lasso

lasso.init()

# server :
server = lasso.Server.new("../../examples/idp.xml",
    "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
    lasso.signatureMethodRsaSha1)
server.add_provider("../../examples/sp1.xml", None, None)
server.add_provider("../../examples/sp2.xml", None, None)
server.add_provider("../../examples/sp3.xml", None, None)

# user :

sp1_identity = """<LassoIdentity RemoteProviderID="https://service-provider1:2003/liberty-alliance/metadata"><LassoRemoteNameIdentifier><NameIdentifier NameQualifier="https://identity-provider:2003/liberty-alliance/metadata" Format="federated">111111111111111111111111</NameIdentifier></LassoRemoteNameIdentifier><LassoLocalNameIdentifier><NameIdentifier NameQualifier="https://identity-provider:2003/liberty-alliance/metadata" Format="federated">222222222222222222222222</NameIdentifier></LassoLocalNameIdentifier></LassoIdentity>"""
sp1_assertion = """<LassoAssertion RemoteProviderID="https://service-provider1:2003/liberty-alliance/metadata"><Assertion AssertionID="1234567890"></Assertion></LassoAssertion>"""

sp2_identity = """<LassoIdentity RemoteProviderID="https://service-provider2:2003/liberty-alliance/metadata"><LassoRemoteNameIdentifier><NameIdentifier NameQualifier="https://identity-provider:2003/liberty-alliance/metadata" Format="federated">222222222222222222222</NameIdentifier></LassoRemoteNameIdentifier></LassoIdentity>"""
sp2_assertion = """<LassoAssertion RemoteProviderID="https://service-provider2:2003/liberty-alliance/metadata"><Assertion AssertionID="1234567890"></Assertion></LassoAssertion>"""

user_dump = """<LassoUser><LassoAssertions>%s%s</LassoAssertions><LassoIdentities>%s%s</LassoIdentities></LassoUser>""" % (
    sp1_assertion, sp2_assertion, sp1_identity, sp2_identity)
user = lasso.User.new_from_dump(user_dump);


print user.dump()

# requests :
logout = lasso.Logout.new(server, user, lasso.providerTypeIdp);
next_provider_id = user.get_next_assertion_remote_providerID();
while(next_provider_id):
    assertion = user.get_assertion(next_provider_id)

    logout.init_request(next_provider_id)
    logout.build_request_msg();

    # send the request with logout.msg_url and logout.msg_body
    print 'url : ', logout.msg_url
    print 'body : ', logout.msg_body

    # use the fake response :
    lasso_logout_process_response_msg()

    next_provider_id = user.get_next_assertion_remote_providerID()

print "End of logout ..."
print "Dump of user environ :"
print user.dump()

user.destroy()

logout.destroy()
