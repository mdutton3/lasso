#! /usr/bin/env python

import sys
sys.path.insert(0, '../')
import lasso

lasso.init()

# creation d'une AuthnRequest
req = lasso.AuthnRequest("http://providerid.com")
req.set_requestAuthnContext(["test"],
                            None,
                            lasso.libAuthnContextComparisonExact)
req.set_scoping(1)

req.dump()

query = req.url_encode(1, "../../examples/rsakey.pem")

print query

req.destroy()

#lasso.shutdown()
