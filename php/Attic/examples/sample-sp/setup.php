<?php
/*  
 *
 * Service Provider Example -- Installation Script
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Christophe Nowicki <cnowicki@easter-eggs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

 if(!extension_loaded('lasso')) {
	$ret = @dl('lasso.' . PHP_SHLIB_SUFFIX);
	if ($ret == FALSE)
	{
		print "<p align='center'><b>The Lasso Extension is not available</b><br>";
		print "Please check your PHP extensions<br>";
		print "You can get more informations about <b>Lasso</b> at <br>";
		print "<a href='http://lasso.entrouvert.org/'>http://lasso.entrouvert.org/</a></p>";
		exit();
	}
 }

	require_once 'DB.php';

	$config = unserialize(file_get_contents('config.inc'));

	switch($_POST['action'])
	{
	  case 'setup' :
		print "<b>Lasso Service Provider Setup</b><br>";

		unset($_POST['action']);

		$diff = array_diff($_POST, $config);

		foreach($diff as $key => $value) {
		  $config[$key] = $value;
		}
		
		print "Check Data base : ";

		$db = &DB::connect($config['dsn']);
		
		if (DB::isError($db)) {
		  die("Failed (" . $db->getMessage() . ")");
		}
		else 
		  print "OK";
		 
		print "<br>Create sequence 'user_id_seq' : ";
		
		$query = "DROP SEQUENCE user_id_seq";
		$res =& $db->query($query);
		
		$query = "CREATE SEQUENCE user_id_seq";
		$res =& $db->query($query);
		if (DB::isError($res)) 
		  die($res->getMessage());
		
		print "OK";

		print "<br>Create table 'users' : ";
		$query = "DROP TABLE users CASCADE";
		$res =& $db->query($query);

		$query = "CREATE TABLE users (
		  user_id         varchar(100) primary key,
		  identity_dump   text,
		  first_name   	  varchar(50),
		  last_name   	  varchar(50),
		  created		  timestamp)";
		$res =& $db->query($query);
		if (DB::isError($res)) 
		  die($res->getMessage());

		print "OK";

		print "<br>Create table 'nameidentifiers' : ";

		$query = "DROP TABLE nameidentifiers CASCADE";
		$res =& $db->query($query);

		$query = "CREATE TABLE nameidentifiers (
		  name_identifier varchar(100) primary key,
		  user_id         varchar(100),
		  FOREIGN KEY (user_id) REFERENCES users (user_id))";
		$res =& $db->query($query);
		if (DB::isError($res)) 
		  die($res->getMessage()); 

		print "OK";
		
		$db->disconnect();
		
		$keys = array_keys($config);
		$files = preg_grep("/(sp|idp)/", $keys);

		foreach($files as $file)
		{
		  print "<br>Check file " . $config[$file] . " : ";
		  if (!file_exists($config[$file]))
		  {
			die("Failed (file does not exist)");
		  }
		  else
			print "OK";
		}

		lasso_init();

		print "<br>Create Server : ";

		$server = lasso_server_new(
		  	$config['sp-metadata'], $config['sp-public_key'],
			$config['sp-private_key'], $config['sp-ca'], lassoSignatureMethodRsaSha1);

		if (empty($server))
		{
		  print "Failed";
		  break;
		} 
		else
		  print "OK";

		print "<br>Add provider : ";

		$ret = lasso_server_add_provider($server, 
		$config['idp-metadata'], $config['idp-public_key'], $config['idp-ca']);

		/*if ($ret != TRUE)
		{
		  print "Failed";
		  break;
		} 
		else */
		  print "OK";

		print "<br>Write XML Server Dump : ";

		$dump = lasso_server_dump($server);
		
		if (($fd = fopen($config['server_dump_filename'], "w")))
		{
		  fwrite($fd, $dump);
		  fclose($fd);
		  print "OK";
		}
		else
		  print "Failed";

		lasso_shutdown();

		# Save configuration file
		$config_ser = serialize($config);
		if (($fd = fopen("config.inc", "w")))
		{
		  fwrite($fd, $config_ser);
		  fclose($fd);
		}

		break;
	  default:
?>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
<title>Setup script for Lasso (Liberty Alliance Single Sign On)</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-15" />
</head>
<body>
<form name='frm' action='<?php echo $PHP_SELF ?>' method='POST'>
<table>
<caption>Lasso Service Provider Setup</caption>
<tr>
  <td>DSN:</td><td><input type='text' name='dsn' value='<?php echo $config['dsn']; ?>' maxlength='100'></td>
</tr>
<tr>
  <td>Server XML Dump:</td><td><input type='text' name='server_dump_filename' value='<?php echo $config['server_dump_filename']; ?>' maxlength='100'></td>
</tr>
<tr>
  <td><input type='hidden' name='action' value='setup'></td>
  <td><input type='submit' value='setup'></td>
</tr>
</table>
</form>
</body>
</html>
<?php
  }
?>
