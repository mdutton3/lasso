--TEST--
Check Lasso Server 
--SKIPIF--
<?php if (!extension_loaded("lasso")) print "skip"; ?>
--FILE--
<?php
	lasso_init();
    $server = lasso_server_new("../examples/sp.xml",
    "../examples/rsapub.pem",
    "../examples/rsakey.pem",
    "../examples/sacert.pem", lassoSignatureMethodRsaSha1);
    var_dump($server);

    lasso_server_add_provider($server, "../examples/idp.xml", "", "");

    $dump = lasso_server_dump($server);

    print $dump . "\n";

	$new_server = lasso_server_new_from_dump($dump);

	var_dump($new_server);

	lasso_server_destroy($server);

	var_dump($server);

    lasso_shutdown();

?>
--EXPECT--
DEBUG: lasso_init
DEBUG: lasso_server_new
resource(4) of type (LASSO Server Resource)
DEBUG: lasso_server_add_provider
DEBUG: lasso_server_dump
<LassoServer SignatureMethod="1" ProviderID="https://service-provider:2003/liberty-alliance/metadata" PrivateKey="../examples/rsakey.pem" Certificate="../examples/sacert.pem" PublicKey="../examples/rsapub.pem"><EntityDescriptor xmlns="urn:liberty:metadata:2003-08" ProviderID="https://service-provider:2003/liberty-alliance/metadata">
 <SPDescriptor>

  <FederationTerminationServiceURL>https://service-provider:2003/liberty-alliance/singleLogout</FederationTerminationServiceURL>
  <FederationTerminationProtocolProfile>http://projectliberty.org/profiles/slo-idp-soap</FederationTerminationProtocolProfile>

  <SingleLogoutServiceURL>https://service-provider:2003/liberty-alliance/singleLogout</SingleLogoutServiceURL>
  <SingleLogoutProtocolProfile>http://projectliberty.org/profiles/slo-idp-soap</SingleLogoutProtocolProfile>
  <RegisterNameIdentifierProtocolProfile>http://projectliberty.org/profiles/rni-sp-soap</RegisterNameIdentifierProtocolProfile>
  <RegisterNameIdentifierServiceURL>https://service-provider:2003/liberty-alliance/registerNameIdentifier</RegisterNameIdentifierServiceURL>
  <SoapEndpoint>https://service-provider:2003/liberty-alliance/soapEndpoint</SoapEndpoint>
  <AssertionConsumerServiceURL id="AssertionConsumerServiceURL1" isDefault="true">https://service-provider:2003/liberty-alliance/assertionConsumer</AssertionConsumerServiceURL>
  <AuthnRequestsSigned>true</AuthnRequestsSigned>
</SPDescriptor>
</EntityDescriptor><LassoProviders><LassoProvider PublicKey="" CaCertificate=""><EntityDescriptor xmlns="urn:liberty:metadata:2003-08" ProviderID="https://identity-provider:2003/liberty-alliance/metadata">
 <IDPDescriptor>
  <FederationTerminationServiceURL>https://identity-provider:2003/liberty-alliance/federationTermination</FederationTerminationServiceURL>
  <FederationTerminationNotificationProtocolProfile>http://projectliberty.org/profiles/slo-idp-soap</FederationTerminationNotificationProtocolProfile>
  <SingleSignOnProtocolProfile>http://projectliberty.org/profiles/sso-get</SingleSignOnProtocolProfile>
  <SingleSignOnServiceURL>http://identity-provider:2002/sso</SingleSignOnServiceURL>
  <SingleLogoutServiceURL>https://identity-provider:2003/liberty-alliance/singleLogout</SingleLogoutServiceURL>
  <SingleLogoutProtocolProfile>http://projectliberty.org/profiles/slo-idp-soap</SingleLogoutProtocolProfile>
  <RegisterNameIdentifierProtocolProfile>http://projectliberty.org/profiles/rni-idp-soap</RegisterNameIdentifierProtocolProfile>
  <RegisterNameIdentifierServiceURL>https://identity-provider:2003/liberty-alliance/registerNameIdentifier</RegisterNameIdentifierServiceURL>
  <SoapEndpoint>https://identity-provider:2003/liberty-alliance/soapEndpoint</SoapEndpoint>
</IDPDescriptor>
</EntityDescriptor></LassoProvider></LassoProviders></LassoServer>
DEBUG: lasso_server_new_from_dump
resource(5) of type (LASSO Server Resource)
DEBUG: lasso_server_destroy
resource(4) of type (Unknown)
DEBUG: lasso_shutdown
