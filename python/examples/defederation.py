#! /usr/bin/env python

import sys
sys.path.insert(0, '../')
import lasso


spidentity_dump = "<LassoIdentity><LassoFederations><LassoFederation RemoteProviderID=\"https://identity-provider:2003/liberty-alliance/metadata\"><LassoRemoteNameIdentifier><NameIdentifier NameQualifier=\"qualifier.com\" Format=\"federated\">1111111111111111111111111</NameIdentifier></LassoRemoteNameIdentifier></LassoFederation></LassoFederations></LassoIdentity>"

idpidentity_dump = "<LassoIdentity><LassoFederations><LassoFederation RemoteProviderID=\"https://service-provider:2003/liberty-alliance/metadata\"><LassoLocalNameIdentifier><NameIdentifier NameQualifier=\"qualifier.com\" Format=\"federated\">1111111111111111111111111</NameIdentifier></LassoLocalNameIdentifier></LassoFederation></LassoFederations></LassoIdentity>"


# SP :
spserver = lasso.Server.new("../../examples/sp.xml",
                            "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
                            lasso.signatureMethodRsaSha1)
spserver.add_provider("../../examples/idp.xml", None, None)

spdefederation = lasso.FederationTermination.new(spserver, lasso.providerTypeSp)
spdefederation.set_identity_from_dump(spidentity_dump)
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

idpdefederation = lasso.FederationTermination.new(idpserver, lasso.providerTypeIdp)
idpdefederation.process_notification_msg(notification_msg, lasso.httpMethodSoap)
print 'NameIdentifier :', idpdefederation.nameIdentifier

idpdefederation.set_identity_from_dump(idpidentity_dump);
idpdefederation.validate_notification()

print 'End of federation termination notification'

lasso.shutdown()
