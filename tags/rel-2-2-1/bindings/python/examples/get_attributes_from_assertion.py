# Example SP Python code to get attributes from an assertion

for attribute in assertion.attributeStatement[0].attribute:
    if attribute.name == lasso.SAML2_ATTRIBUTE_NAME_EPR:
        continue
    print 'attribute : ' + attribute.name
    for value in attribute.attributeValue:
        print '  value : ' + value.any[0].content
