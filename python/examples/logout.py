#! /usr/bin/env python

import sys
sys.path.insert(0, '../')
import lasso

lasso.init()

# SP1 server and user :
sp1server = lasso.Server.new("../../examples/sp1.xml",
    "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
    lasso.signatureMethodRsaSha1)
sp1server.add_provider("../../examples/idp.xml", None, None)

sp1user_dump = "<LassoUser><LassoAssertions><LassoAssertion RemoteProviderID=\"https://identity-provider:2003/liberty-alliance/metadata\"><Assertion AssertionID=\"C9DS8CD7CSD6CDSCKDKCS\"></Assertion></LassoAssertion></LassoAssertions><LassoIdentities><LassoIdentity RemoteProviderID=\"https://identity-provider:2003/liberty-alliance/metadata\"><LassoRemoteNameIdentifier><NameIdentifier NameQualifier=\"qualifier.com\" Format=\"federated\">11111111111111111111111111</NameIdentifier></LassoRemoteNameIdentifier></LassoIdentity></LassoIdentities></LassoUser>"

# SP2 server and user :
sp2server = lasso.Server.new("../../examples/sp2.xml",
    "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
    lasso.signatureMethodRsaSha1)
sp2server.add_provider("../../examples/idp.xml", None, None)

sp2user_dump = "<LassoUser><LassoAssertions><LassoAssertion RemoteProviderID=\"https://identity-provider:2003/liberty-alliance/metadata\"><Assertion AssertionID=\"4IK43JCJSDCSDKCSCSDL\"></Assertion></LassoAssertion></LassoAssertions><LassoIdentities><LassoIdentity RemoteProviderID=\"https://identity-provider:2003/liberty-alliance/metadata\"><LassoRemoteNameIdentifier><NameIdentifier NameQualifier=\"qualifier.com\" Format=\"federated\">222222222222222222222222</NameIdentifier></LassoRemoteNameIdentifier></LassoIdentity></LassoIdentities></LassoUser>"

# IDP server and user :
idpserver = lasso.Server.new("../../examples/idp.xml",
    "../../examples/rsapub.pem", "../../examples/rsakey.pem", "../../examples/rsacert.pem",
    lasso.signatureMethodRsaSha1)
idpserver.add_provider("../../examples/sp1.xml", None, None)
idpserver.add_provider("../../examples/sp2.xml", None, None)
idpserver.add_provider("../../examples/sp3.xml", None, None)

idpuser_dump = "<LassoUser><LassoAssertions><LassoAssertion RemoteProviderID=\"https://service-provider1:2003/liberty-alliance/metadata\"><Assertion AssertionID=\"C9DS8CD7CSD6CDSCKDKCS\"></Assertion></LassoAssertion><LassoAssertion RemoteProviderID=\"https://service-provider2:2003/liberty-alliance/metadata\"><Assertion AssertionID=\"4IK43JCJSDCSDKCSCSDL\"></Assertion></LassoAssertion></LassoAssertions><LassoIdentities><LassoIdentity RemoteProviderID=\"https://service-provider1:2003/liberty-alliance/metadata\"><LassoLocalNameIdentifier><NameIdentifier NameQualifier=\"qualifier.com\" Format=\"federated\">11111111111111111111111111</NameIdentifier></LassoLocalNameIdentifier></LassoIdentity><LassoIdentity RemoteProviderID=\"https://service-provider2:2003/liberty-alliance/metadata\"><LassoLocalNameIdentifier><NameIdentifier NameQualifier=\"qualifier.com\" Format=\"federated\">222222222222222222222222</NameIdentifier></LassoLocalNameIdentifier></LassoIdentity></LassoIdentities></LassoUser>"



# SP1 build a request :
sp1user = lasso.User.new_from_dump(sp1user_dump)

sp1logout = lasso.Logout.new(sp1server, lasso.providerTypeSp)

sp1logout.load_user_dump(sp1user_dump)

sp1logout.init_request()

request = sp1logout.request
request.set_relayState("http://relaystate.com")

sp1logout.build_request_msg()

msg_url  = sp1logout.msg_url
msg_body = sp1logout.msg_body

sp1logout.destroy()

# IDP process request and return a response :
idpuser = lasso.User.new_from_dump(idpuser_dump)
idplogout = lasso.Logout.new(idpserver, lasso.providerTypeIdp)

if lasso.get_request_type_from_soap_msg(msg_body)==lasso.requestTypeLogout:
    print "it's a logout request !"

#fake response, only for test !
response_msg_body = "<Envelope><LogoutResponse><ProviderID>https://service-provider2:2003/liberty-alliance/metadata</ProviderID><Status><StatusCode Value=\"Samlp:Success\"></StatusCode></Status></LogoutResponse></Envelope>"

idplogout.load_request_msg(msg_body, lasso.httpMethodSoap)
nameIdentifier = idplogout.nameIdentifier
print "get the user dump from NameIdentifier : ", nameIdentifier
idplogout.load_user_dump(idpuser_dump)
idplogout.process_request()

print "RelayState :", idplogout.msg_relayState

next_provider_id = idplogout.get_next_providerID()
while next_provider_id:
    idplogout.init_request(next_provider_id)
    idplogout.build_request_msg()

    print "send soap msg to url", idplogout.msg_url
    # remote SP send back a LogoutResponse, process it.
    idplogout.process_response_msg(response_msg_body, lasso.httpMethodSoap)

    next_provider_id = idplogout.get_next_providerID()

idplogout.build_response_msg()

print "End of logout"
