#!/usr/bin/php
<?php
  
 if(!extension_loaded('lasso')) {
	    dl('lasso.' . PHP_SHLIB_SUFFIX);
  }

  /*
   *
   */
  
  lasso_init();

  $server = lasso_server_new("./sp.xml", "./rsapub.pem", 
  "./rsakey.pem", "./rsacert.pem", lassoSignatureMethodRsaSha1);
  lasso_server_add_provider($server, "./idp.xml", "", "");

  $login = lasso_login_new($server);
  
  lasso_login_init_authn_request($login, 
  "https://identity-provider:2003/liberty-alliance/metadata");

  $profile = lasso_cast_to_profile($login);
  lasso_profile_get_request($profile);

  $profile2 = lasso_cast_to_profile($login);
  lasso_profile_get_request($profile2);
  
  lasso_shutdown();
?>
