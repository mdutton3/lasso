#! /usr/bin/env python

import sys
sys.path.insert(0, '../')
import lasso

lasso.init()

spserver = lasso.Server.new("../../examples/sp.xml",
			    "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
			    lasso.signatureMethodRsaSha1)

spserver.add_provider("../../examples/idp.xml", None, None)
spserver.add_provider("../../examples/idp2.xml", None, None)

spuser_dump = "<LassoUser><LassoAssertions><LassoAssertion RemoteProviderID=\"https://identity-provider:2003/liberty-alliance/metadata\"><Assertion AssertionID=\"CD8SCD7SC6SDCD5CDSDCD88SDCDSD\"></Assertion></LassoAssertion></LassoAssertions><LassoIdentities><LassoIdentity RemoteProviderID=\"https://identity-provider:2003/liberty-alliance/metadata\"><LassoLocalNameIdentifier><NameIdentifier NameQualifier=\"qualifier.com\" Format=\"federated\">11111111111111111111111111</NameIdentifier></LassoLocalNameIdentifier></LassoIdentity><LassoIdentity RemoteProviderID=\"https://identity-provider2:2003/liberty-alliance/metadata\"><LassoLocalNameIdentifier><NameIdentifier NameQualifier=\"qualifier.com\" Format=\"federated\">22222222222222222222222222</NameIdentifier></LassoLocalNameIdentifier></LassoIdentity></LassoIdentities></LassoUser>"

spuser = lasso.User.new_from_dump(spuser_dump)

# LogoutRequest :
splogout = lasso.Logout.new(spserver, spuser, lasso.providerTypeSp)
splogout.init_request()
splogout.build_request_msg()

request_msg = splogout.msg_body
msg_url  = splogout.msg_url
msg_body = splogout.msg_body

splogout.destroy()

print 'request url : ', msg_url
print 'request body : ', msg_body

request_type = lasso.get_request_type_from_soap_msg(msg_body)
if request_type == lasso.requestTypeLogout:
    print "it's a LogoutRequest !"


# LogoutResponse :
idpserver = lasso.Server.new("../../examples/idp.xml",
			    "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
			    lasso.signatureMethodRsaSha1)
idpserver.add_provider("../../examples/sp.xml", None, None)

idpuser_dump = "<LassoUser><LassoAssertions></LassoAssertions><LassoIdentities></LassoIdentities></LassoUser>"
idpuser = lasso.User.new_from_dump(idpuser_dump)

idplogout = lasso.Logout.new(idpserver, idpuser, lasso.providerTypeIdp)
idplogout.process_request_msg(request_msg, lasso.httpMethodSoap)
idplogout.build_response_msg()

msg_url  = idplogout.msg_url
msg_body = idplogout.msg_body
print 'body : ', idplogout.msg_body

# process the response :
splogout = lasso.Logout.new(spserver, spuser, lasso.providerTypeSp)
splogout.process_response_msg(msg_body, lasso.httpMethodSoap)

lasso.shutdown()
