#!/usr/bin/php
<?php
  if(!extension_loaded('lasso')) {
	    dl('lasso.' . PHP_SHLIB_SUFFIX);
  }

  lasso_init();

  print "Lasso version : " . lasso_version() . "\n";

  $server = lasso_server_new(
	"./sp.xml", 
  	"./rsapub.pem", 
  	"./rsakey.pem", 
  	"./rsacert.pem", lassoSignatureMethodRsaSha1);

  lasso_server_add_provider($server, "./idp.xml", "", "");

  $splogin = lasso_login_new($server);

  # Create AuthnRequest

  lasso_login_init_authn_request($splogin, "https://identity-provider:2003/liberty-alliance/metadata");
  
  $profile = lasso_cast_to_profile($splogin);
  
  $node = lasso_profile_get_request($profile);

  $lib_authn_request = lasso_cast_to_lib_authn_request($node);

  lasso_lib_authn_request_set_ispassive($lib_authn_request, FALSE);
  lasso_lib_authn_request_set_forceauthn($lib_authn_request, TRUE);
  lasso_lib_authn_request_set_nameidpolicy($lib_authn_request, lassoLibNameIDPolicyTypeFederated);
  lasso_lib_authn_request_set_relaystate($lib_authn_request, "fake");
  lasso_lib_authn_request_set_protocolprofile($lib_authn_request, lassoLibProtocolProfileBrwsArt);

  lasso_login_build_authn_request_msg($splogin);

  print "msg_url : " . lasso_profile_get_msg_url($profile) . "\n";
  print "msg_body : " . lasso_profile_get_msg_body($profile) . "\n";

  lasso_shutdown();
?>
