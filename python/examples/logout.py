#! /usr/bin/env python

import sys
sys.path.insert(0, '../')
import lasso

lasso.init()

print 
print 'Build LogoutRequest ...'
req = lasso.LogoutRequest.new("http://providerid.com", "CDSC7SCD6SSDJCSCKSDKCDSCLSD", "http://qualifier.com", "federated")
soap = req.soap_envelop()
req2 = lasso.LogoutRequest.new_from_soap(soap)

print
print 'Rebuild LogoutRequest from soap message ...'
req2.dump()
query = req2.url_encode(1, 'rsakey.pem')
print 'query : ', query

print
print 'Rebuild LogoutRequest from query ...'
req3 = lasso.LogoutRequest.new_from_query(query)
req3.dump()

print
print 'Build the LogoutResponse from the request soap ...'
res = lasso.LogoutResponse.new_from_request_soap(soap, "http://providerid.com", "success")
soap = res.dump()

print
print 'Build LogoutResponse from soap response dump'
res2 = lasso.LogoutResponse.new_from_soap(soap)
print res2.dump()

print
print 'Build LogoutResponse from response dump'
dump = res.dump()
res3 = lasso.LogoutResponse.new_from_dump(dump)

print
print 'Build LogoutResponse from request query'
res4 = lasso.LogoutResponse.new_from_request_query(query, "http://providerid.com", "success")
res4.dump()

print
print 'Rebuild LogoutResponse from response query'
query = res4.url_encode(1, 'rsakey.pem')
res5 = lasso.LogoutResponse.new_from_query(query)
print res5.dump()


lasso.shutdown()
