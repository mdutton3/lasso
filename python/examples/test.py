#! /usr/bin/env python

import sys
sys.path.insert(0, '../')
import lasso

lasso.init()

# creation d'une AuthnRequest
req = lasso.AuthnRequest("providerid.com",
                         "federated",
                         0,
                         1,
                         "pp", # None
                         "3",
                         ["test"],
                         None,
                         lasso.libAuthnContextComparisonExact, # None
                         "encoded_RelayState", # None
                         0,
                         None,
                         "obtained")

req.node.dump("iso-8859-1", 1)

query = req.node.url_encode(1, "../../examples/rsakey.pem")

print query

# creation d'une AuthnResponse
res = lasso.AuthnResponse(query, 1,
                          "../../examples/rsapub.pem",
                          "../../examples/rsakey.pem",
                          "../../examples/rsacert.pem", 0)

res.init("toto", 1)

assertion = lasso.assertion_build(res, "http://idprovider.com")
authentication_statement = lasso.authentication_statement_build("password",
                                                                "3",
                                                                "tralala",
                                                                "dslqkjfslfj",
                                                                "http://service-provider.com",
                                                                "federated",
                                                                "wxkfjesmqfj",
                                                                "http://idp-provider.com",
                                                                "federated",
                                                                "bearer")
lasso.assertion_add_authenticationStatement(assertion, authentication_statement);
res.add_assertion(assertion)
res.node.dump("iso-8859-1", 1)

# Verification de l'assertion de l'AuthnResponse
#assertion.verify_signature("../../examples/rootcert.pem")
res.node.get_child("Assertion").verify_signature("../../examples/rootcert.pem")

# recuperation du StatusCode
status = res.node.get_child("Status")
status_code = status.get_child("StatusCode")
print status_code.get_attr_value("Value")

#req.node.destroy()

#lasso.shutdown()
