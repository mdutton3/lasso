--TEST--
Check for lasso presence
--SKIPIF--
<?php if (!extension_loaded("lasso")) print "skip"; ?>
--FILE--
<?php 
echo "lasso extension is available";
?>
--EXPECT--
lasso extension is available
