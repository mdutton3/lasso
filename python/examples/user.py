#! /usr/bin/env python

import sys
sys.path.insert(0, '../')
import lasso

lasso.init()


lasso_assertions = """<LassoAssertions><LassoAssertion RemoteProviderID="https://service-provider1:2003/liberty-alliance/metadata"><Assertion AssertionID="1234567890"></Assertion></LassoAssertion><LassoAssertion RemoteProviderID="https://service-provider2:2003/liberty-alliance/metadata"><Assertion AssertionID="1234567890"></Assertion></LassoAssertion><LassoAssertion RemoteProviderID="https://service-provider3:2003/liberty-alliance/metadata"><Assertion AssertionID="1234567890"></Assertion></LassoAssertion></LassoAssertions>"""

lasso_identities = """<LassoIdentities><LassoIdentity RemoteProviderID="https://service-provider1:2003/liberty-alliance/metadata"><LassoRemoteNameIdentifier><NameIdentifier>111111111111111111111111111111</NameIdentifier></LassoRemoteNameIdentifier></LassoIdentity></LassoIdentities>"""


user_dump = "<LassoUser>%s%s</LassoUser>" % (lasso_assertions, lasso_identities)

user = lasso.User.new_from_dump(user_dump);

print "Dump of user environ : %s\n" % user.dump()

next_provider_id = user.get_next_providerID()
while(next_provider_id):
    print "Next provider id : ", next_provider_id
    assertion = user.get_assertion(next_provider_id)
    print "his Assertion : ", assertion.dump()
    print "Remove his assertion from user ..."
    user.remove_assertion(next_provider_id)

    next_provider_id = user.get_next_providerID()

print "All assertions deleted\n"

print "Dump of user environ :"
print user.dump()

user2 = lasso.User.new_from_dump(user.dump());

assertion = lasso.Assertion("http://nowhere.com", "CD8CS7C6CS6CD6C6SC6SSDC6CS6D")
user.add_assertion("https://service-provider1:2003/liberty-alliance/metadata", assertion)

user.destroy()
