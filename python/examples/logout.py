#! /usr/bin/env python

import sys
sys.path.insert(0, '../')
import lasso

lasso.init()

spserver = lasso.Server.new("../../examples/sp.xml",
			    "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
			    lasso.signatureMethodRsaSha1)

spserver.add_provider("../../examples/idp.xml", None, None)

spuser_dump = "<LassoUser><LassoIdentities><LassoIdentity RemoteProviderID=\"https://identity-provider:2003/liberty-alliance/metadata\"><LassoLocalNameIdentifier><NameIdentifier NameQualifier=\"qualifier.com\" Format=\"federated\">LLLLLLLLLLLLLLLLLLLLLLLLL</NameIdentifier></LassoLocalNameIdentifier></LassoIdentity></LassoIdentities></LassoUser>"

spuser = lasso.User.new_from_dump(spuser_dump)

# LogoutRequest :
splogout = lasso.Logout.new(spserver, spuser, lasso.providerTypeSp)
splogout.init_request("https://identity-provider:2003/liberty-alliance/metadata")
splogout.build_request_msg()

request_msg = splogout.msg_body
print 'request url : ', splogout.msg_url
print 'request body : ', splogout.msg_body


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
print 'url : ', idplogout.msg_url
print 'body : ', idplogout.msg_body

lasso.shutdown()
