#! /usr/bin/env python

import sys
sys.path.insert(0, '../')
import lasso

lasso.init()

## print 
## print 'Build LogoutRequest ...'
## req = lasso.LogoutRequest.new("http://providerid.com", "CDSC7SCD6SSDJCSCKSDKCDSCLSD", "http://qualifier.com", "federated")
## soap = req.soap_envelop()
## req2 = lasso.LogoutRequest.new_from_soap(soap)

## print
## print 'Rebuild LogoutRequest from soap message ...'
## req2.dump()
## query = req2.url_encode(1, 'rsakey.pem')
## print 'query : ', query

notification = lasso.FederationTerminationNotification.new("http://providerid.com",
                                                           "CDSC7SCD65SCDSDCCDS", "http://qualifier.com", "federated")

query = notification.url_encode(0, './rsakey.pem')
print query

notification2 = lasso.FederationTerminationNotification.new_from_query(query)
print notification2.dump()

soap = notification.soap_envelop()

notification3 = lasso.FederationTerminationNotification.new_from_soap(soap)
print notification3.dump()

lasso.shutdown()
