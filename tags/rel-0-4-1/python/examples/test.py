#! /usr/bin/env python
# -*- coding: utf-8 -*-

import sys
sys.path.insert(0, '../')
import lasso

# creation d'une AuthnRequest
req = lasso.AuthnRequest("http://providerid.com")
req.set_forceAuthn(0)
req.set_isPassive(1)
req.set_protocolProfile(lasso.libProtocolProfilePost)
req.set_requestAuthnContext(["test1", "test2"],
                            None,
                            lasso.libAuthnContextComparisonExact)
req.set_scoping(proxyCount=1)

# url encodage de la request (+ signature)
query = req.export_to_query(1, "../../examples/rsakey.pem")
req.destroy()

# creation de la response AuthnResponse OU Response
# en fonction de la valeur de ProtocolProfile
protocolProfile = lasso.authn_request_get_protocolProfile(query)
if protocolProfile == lasso.libProtocolProfilePost:
    # partie IDP
    res = lasso.AuthnResponse.new_from_request_query(query, "http://providerid.com")
    # verification de la signature de la query
    print "Query signature check:", res.verify_signature("../../examples/rsapub.pem",
                                                         "../../examples/rsakey.pem")
    must_authenticate = res.must_authenticate(is_authenticated=0)
    print "Must authenticate?   :", must_authenticate

    if must_authenticate:
        # dump (sauvegarde avant authentification)
        dump_response = res.dump()
        res.destroy()
        
        # reconstruction de la reponse apres authentification du Principal
        res = lasso.AuthnResponse.new_from_dump(dump_response)
        res.process_authentication_result(1)

        # if NameIDPolicy omitted or none and federation KO
        #    statusCode = lib:FederationDoesNotExist
        
        # creation de l'assertion
        assertion = lasso.Assertion("issuer", res.get_attr_value("InResponseTo"))
        authentication_statement = lasso.AuthenticationStatement("password",
                                                                 "tralala",
                                                                 "dslqkjfslfj",
                                                                 "http://service-provider.com",
                                                                 "federated",
                                                                 "wxkfjesmqfj",
                                                                 "http://idp-provider.com",
                                                                 "federated")
        assertion.add_authenticationStatement(authentication_statement)
        assertion.set_signature(1, "../../examples/rsakey.pem",
                                "../../examples/rsacert.pem");
        # ajout de l'assertion
        res.add_assertion(assertion)

    # export de la response (base64 encodÃ©e) pr envoi au SP
    res_b64 = res.export_to_base64()
    res.destroy()
else:
    print "La Response (par artifact) n'est pas encore implementée"
    lasso.shutdown()
    sys.exit(0)

# partie SP
# reconstruction de la reponse
res = lasso.AuthnResponse.new_from_export(res_b64, type=1)
# Verification de la signature de l'assertion
assertion = res.get_child("Assertion")
if assertion:
    print "Assertion signature check: ", res.get_child("Assertion").verify_signature("../../examples/rootcert.pem")
# recuperation du StatusCode
status_code = res.get_child("StatusCode")
# recuperation de la valeur de l'attribut "Value"
print "Resultat de la demande d'authentification:", status_code.get_attr_value("Value")
res.destroy()

lasso.shutdown()
