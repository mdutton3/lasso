#! /usr/bin/env python

import sys
sys.path.insert(0, '../')
import lasso

lasso.init()

# servers :
spserver = lasso.Server.new("../../examples/sp.xml",
    "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
    lasso.signatureMethodRsaSha1)

spserver.add_provider("../../examples/idp.xml", None, None)

idpserver = lasso.Server.new("../../examples/idp.xml",
    "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
    lasso.signatureMethodRsaSha1)

spserver.add_provider("../../examples/sp.xml", None, None)

# users :
spuser_dump = "<LassoUser><LassoIdentities><LassoIdentity RemoteProviderID=\"https://identity-provider:2003/liberty-alliance/metadata\"><LassoRemoteNameIdentifier><NameIdentifier NameQualifier=\"qualifier.com\" Format=\"federated\">LLLLLLLLLLLLLLLLLLLLLLLLL</NameIdentifier></LassoRemoteNameIdentifier></LassoIdentity></LassoIdentities></LassoUser>"

spuser = lasso.User.new_from_dump(spuser_dump)

idpuser_dump = "<LassoUser><LassoIdentities><LassoIdentity RemoteProviderID=\"https://service-provider:2003/liberty-alliance/metadata\"><LassoLocalNameIdentifier><NameIdentifier NameQualifier=\"qualifier.com\" Format=\"federated\">LLLLLLLLLLLLLLLLLLLLLLLLL</NameIdentifier></LassoLocalNameIdentifier></LassoIdentity></LassoIdentities></LassoUser>"

idpuser = lasso.User.new_from_dump(idpuser_dump)


# sp register name identifier :
print 'new registration'
spregistration = lasso.RegisterNameIdentifier.new(spserver, spuser, lasso.providerTypeSp)
spregistration.init_request("https://identity-provider:2003/liberty-alliance/metadata")
#spregistration.build_request_msg()
print 'url : ', spregistration.msg_url
print 'body : ', spregistration.msg_body


print 'End of registration'

lasso.shutdown()
