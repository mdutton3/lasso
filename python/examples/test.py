#! /usr/bin/env python

import sys
sys.path.insert(0, '../')
import lasso

print lasso.init()

req = lasso.AuthnRequest("providerid.com",
                         "federated",
                         0,
                         1,
                         "pp", # None
                         "3",
                         ["test"],
                         None,
                         lasso.LibAuthnContextComparisonExact, # None
                         "encoded_RelayState", # None
                         0,
                         None,
                         "obtained")

req.node.dump("iso-8859-1", 1)

query = req.node.url_encode(1, "../../examples/rsakey.pem")

print query

res = lasso.AuthnResponse(query, 1,
                          "../../examples/rsapub.pem",
                          "../../examples/rsakey2.pem",
                          "../../examples/rsacert.pem", 0)

res.init("toto", 1)

assertion = lasso.assertion_build(res, "http://idprovider.com")
authentication_statement = lasso.authentication_statement_build("password",
                                                                "3",
                                                                "tralalal",
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
#req.node.destroy()

#print lasso.shutdown()
