#!/usr/bin/php
<?php
  if(!extension_loaded('lasso')) {
	    dl('lasso.' . PHP_SHLIB_SUFFIX);
  }

  $module = 'lasso';
  $functions = get_extension_funcs($module);
  echo "Functions available in the lasso extension:<br>\n";
  foreach($functions as $func) { 
	echo $func."<br>\n";
  }

  
  echo "\n";

  lasso_init();


  print lasso_version() . "\n";

  $identity = lasso_identity_new();

  var_dump($identity);

  $dump = lasso_identity_dump($identity);

  var_dump($identity); 

  $server = lasso_server_new("./sp.xml", "./rsapub.pem", "./rsakey.pem", "./rsacert.pem", lassoSignatureMethodRsaSha1);
  lasso_server_add_provider($server, "./idp.xml", "", "");
  
  var_dump($server);

  $dump = lasso_server_dump($server);

  print $dump;

  lasso_server_destroy($server);

  var_dump($server);

  $new_server = lasso_server_new_from_dump($dump);

  var_dump($new_server);

  $spsession = lasso_login_new($new_server);

  var_dump($spsession);

  lasso_login_init_authn_request($spsession, 
  "https://identity-provider:2003/liberty-alliance/metadata");



  $profile = lasso_cast_to_profile($spsession);

  var_dump($profile);

  $node = lasso_profile_get_request($profile);

  var_dump($node);

  $lib_authn_request = lasso_cast_to_lib_authn_request($node);

  var_dump($lib_authn_request);

  lasso_lib_authn_request_set_consent($lib_authn_request, lassoLibConsentObtained);
  lasso_lib_authn_request_set_ispassive($lib_authn_request, FALSE);
  lasso_lib_authn_request_set_forceauthn($lib_authn_request, TRUE);
  lasso_lib_authn_request_set_nameidpolicy($lib_authn_request, lassoLibNameIDPolicyTypeFederated);
  lasso_lib_authn_request_set_relaystate($lib_authn_request, "fake");
  lasso_lib_authn_request_set_protocolprofile($lib_authn_request, lassoLibProtocolProfileBrwsArt);
  
  lasso_login_build_authn_request_msg($spsession, lassoHttpMethodRedirect);

  $ret = lasso_login_init_authn_request($spsession, "https://identity-provider:1998/liberty-alliance/metadata");
  if (!$ret) {
	print("lasso_login_init_authn_request failed");
  }

  /* $dump = lasso_user_dump($user);
  print ($dump);

  $identity = lasso_identity_new("http://remote-provider-id.com");

  var_dump($identity);

  lasso_login_destroy($spsession); */

  lasso_shutdown();

?>
