#! /usr/bin/env python
# -*- coding: utf-8 -*-

import sys
sys.path.insert(0, '../')
import lasso

lasso.init()

# creation d'une AuthnRequest
req = lasso.AuthnRequest("http://providerid.com")
req.set_forceAuthn(0)
req.set_isPassive(0)
req.set_protocolProfile(lasso.libProtocolProfilePost)
req.set_requestAuthnContext(["test"],
                            None,
                            lasso.libAuthnContextComparisonExact)
req.set_scoping(proxyCount=1)

# admiration du resultat
req.dump()

# url encodage + signature
query = req.url_encode(1, "../../examples/rsakey.pem")

print query
req.destroy()

# creation de la response AuthnResponse OU Response
# en fonction de la valeur de ProtocolProfile
protocolProfile = lasso.authn_request_get_protocolProfile(query)
if protocolProfile == lasso.libProtocolProfilePost:
    # partie IDP
    res = lasso.AuthnResponse(query, "http://providerid.com")
    # verification de la signature de la query
    print res.verify_signature("../../examples/rsapub.pem",
                               "../../examples/rsakey.pem")
    print res.must_authenticate(is_authenticated=0)
    res.process_authentication_result(0)
    # creation de l'assertion
    assertion = lasso.Assertion("issuer", res.requestID)
    authentication_statement = lasso.AuthenticationStatement("password",
                                                             "3",
                                                             "tralala",
                                                             "dslqkjfslfj",
                                                             "http://service-provider.com",
                                                             "federated",
                                                             "wxkfjesmqfj",
                                                             "http://idp-provider.com",
                                                             "federated",
                                                             "bearer")
    assertion.add_authenticationStatement(authentication_statement)
    # ajout de l'assertion
    res.add_assertion(assertion, "../../examples/rsakey.pem",
                      "../../examples/rsacert.pem")
    # dump pour envoi au SP
    dump_response = res.dump()

    # partie SP
    # Verification de la signature de l'assertion
    print res.get_child("Assertion").verify_signature("../../examples/rootcert.pem")
    # recuperation du StatusCode
    status_code = res.get_child("StatusCode")
    # recuperation de la valeur de l'attribut "Value"
    print status_code.get_attr_value("Value")
    res.destroy()
else:
    print "La Response (par artifact) n'est pas encore implementée"

lasso.shutdown()
