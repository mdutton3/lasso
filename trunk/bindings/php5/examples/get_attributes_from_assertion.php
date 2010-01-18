/* Example SP PHP5 code to get attributes from an assertion */

foreach ($assertion->attributeStatement[0]->attribute as $attribute) {
    if ($attribute->name == LASSO_SAML2_ATTRIBUTE_NAME_EPR) {
        continue;
    }
    echo 'attribute : ' . $attribute->name . "\n";
    foreach ($attribute->attributeValue as $value) {
        echo '  value : ' . $value->any[0]->content . "\n";
    }
}
