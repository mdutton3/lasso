#! /usr/bin/env python

import sys
sys.path.insert(0, '../')
import lasso


spuser_dump = "<LassoUser><LassoIdentities><LassoIdentity RemoteProviderID=\"https://identity-provider:2003/liberty-alliance/metadata\"><LassoRemoteNameIdentifier><NameIdentifier NameQualifier=\"qualifier.com\" Format=\"federated\">1111111111111111111111111</NameIdentifier></LassoRemoteNameIdentifier></LassoIdentity></LassoIdentities></LassoUser>"

idpuser_dump = "<LassoUser><LassoIdentities><LassoIdentity RemoteProviderID=\"https://service-provider:2003/liberty-alliance/metadata\"><LassoLocalNameIdentifier><NameIdentifier NameQualifier=\"qualifier.com\" Format=\"federated\">1111111111111111111111111</NameIdentifier></LassoLocalNameIdentifier></LassoIdentity></LassoIdentities></LassoUser>"


# SP :
spserver = lasso.Server.new("../../examples/sp.xml",
                            "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
                            lasso.signatureMethodRsaSha1)
spserver.add_provider("../../examples/idp.xml", None, None)

spuser = lasso.User.new_from_dump(spuser_dump)

spdefederation = lasso.FederationTermination.new(spserver, lasso.providerTypeSp)
spdefederation.set_user_from_dump(spuser_dump)
spdefederation.init_notification()
spdefederation.build_notification_msg()
print 'url : ', spdefederation.msg_url
print 'body : ', spdefederation.msg_body

notification_msg = spdefederation.msg_body


# IDP :
idpserver = lasso.Server.new("../../examples/idp.xml",
                            "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
                            lasso.signatureMethodRsaSha1)
idpserver.add_provider("../../examples/sp.xml", None, None)

idpuser = lasso.User.new_from_dump(idpuser_dump)

idpdefederation = lasso.FederationTermination.new(idpserver, lasso.providerTypeIdp)
idpdefederation.load_notification_msg(notification_msg, lasso.httpMethodSoap)
print 'NameIdentifier :', idpdefederation.nameIdentifier

idpdefederation.set_user_from_dump(idpuser_dump);
idpdefederation.process_notification()

print 'End of federation termination notification'

lasso.shutdown()
