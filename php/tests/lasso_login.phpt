--TEST--
Check Lasso Login 
--SKIPIF--
<?php if (!extension_loaded("lasso")) print "skip"; ?>
--FILE--
<?php
	lasso_init();
	$server = lasso_server_new("../examples/sp.xml",
    "../examples/rsapub.pem",
    "../examples/rsakey.pem",
    "../examples/sacert.pem", lassoSignatureMethodRsaSha1);
	$login = lasso_login_new($server);
	var_dump($login);
	lasso_login_destroy($login);
	var_dump($login);

    lasso_shutdown();
?>
--EXPECT--
DEBUG: lasso_init
DEBUG: lasso_server_new
DEBUG: lasso_login_new
resource(5) of type (LASSO Login Resource)
DEBUG: lasso_login_destroy
resource(5) of type (Unknown)
DEBUG: lasso_shutdown
