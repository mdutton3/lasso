#! /usr/bin/env python

import sys
sys.path.insert(0, '../')
import lasso

lasso.init()

req = lasso.NameIdentifierMappingRequest.new("http://providerid.com",
                                             "CDSC7SCD65SCDSDCCDS", "http://qualifier.com", "federated")
print 'dump req : ', req.dump()

query = req.url_encode(1, './rsakey.pem')
print 'req url encoded : ', query

soap = req.soap_envelop()
print 'req soap envelopped : ', soap

req = lasso.NameIdentifierMappingRequest.new_from_query(query)
print 'dump req2 from query : ', req.dump()

req = lasso.NameIdentifierMappingRequest.new_from_soap(soap)
print 'dump req3 from soap : ', req.dump()

res = lasso.NameIdentifierMappingResponse.new_from_request_soap(soap, "http://providerid.com", "success")
print 'dump res from request soap : ', res.dump()

query = res.url_encode(1, 'rsakey.pem')
soap  = res.soap_envelop() 

#res = lasso.NameIdentifierMappingResponse.new_from_request_query(query, "http://providerid.com", "success")
#print 'dump res from request query : ', res.dump()

res = lasso.NameIdentifierMappingResponse.new_from_soap(soap)
print 'dump res from request soap : ', res.dump()

res = lasso.NameIdentifierMappingResponse.new_from_query(query)
print 'dump res from request query : ', res.dump()
