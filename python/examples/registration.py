#! /usr/bin/env python

import sys
sys.path.insert(0, '../')
import lasso

lasso.init()

req = lasso.RegisterNameIdentifierRequest.new("http://providerid.com",
                                              "CD8SC7DSDC56D5CSDCD5CSDCS", "http://qualifier.com", "federated",
                                              "CD8CSDCS633CDCDCSDCDSCSDC", "http://qualifier.com", "federated",
                                              "CDS9CDS8C7CDC3I2KCDSCDCSD", "http://qualifier.com", "federated")
print '----------------------- Requets dump -----------------------', req.dump()

req.rename_attributes_for_encoded_query()
print '----------------------- Requets dump after renaming attributes -----------------------'
print req.dump()


query = req.url_encode(1, 'rsakey.pem')
print '----------------------- Request encoded url query -----------------------'
print query

soap = req.soap_envelop()
print '----------------------- Request SOAP envelopped -----------------------'
print soap


res = lasso.RegisterNameIdentifierResponse.new_from_request_soap(soap, "http://providerid.com", "success")
print '----------------------- Response from Request SOAP  -----------------------'
print res.dump()

res2 = lasso.RegisterNameIdentifierResponse.new_from_request_query(query, "http://providerid.com", "success")
print '----------------------- Response from Request QUERY  -----------------------'
print res.dump()

query = res.url_encode(1, 'rsakey.pem')

res3 = lasso.RegisterNameIdentifierResponse.new_from_query(query)
print '----------------------- Response from QUERY  -----------------------'
print res.dump()


soap = res.soap_envelop()
res3 = lasso.RegisterNameIdentifierResponse.new_from_soap(soap)
print '----------------------- Response from SOAP  -----------------------'
print res.dump()



lasso.shutdown()
