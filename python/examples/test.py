#! /usr/bin/env python

import sys
sys.path.insert(0, '../')
import lasso

print lasso.init()

req = lasso.AuthnRequest("providerid.com",
                         "federated",
                         "false",
                         "true",
                         "", # None
                         "3",
                         None,
                         None,
                         "", # None
                         "", # None
                         0,
                         None,
                         "obtained")

req.request.dump("iso-8859-1", 1)

#req.dump("iso-8859-1", 1)
#req.destroy()

#print lasso.shutdown()
