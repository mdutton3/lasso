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
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<?php
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

	# default config
	if (!file_exists('config.inc'))
	{
	  $cwd = getcwd();
	  $config = array(
	  'dsn' => "pgsql://sp:sp@localhost/sp",
	  'server_dump_filename' => "lasso_server_dump.xml",
	  'sp-metadata' => "/home/cnowicki/mcvs/lasso/tests/data/sp1-la/metadata.xml",
	  'sp-public_key' => "/home/cnowicki/mcvs/lasso/tests/data/sp1-la/public-key.pem",
	  'sp-private_key' => "/home/cnowicki/mcvs/lasso/tests/data/sp1-la/private-key-raw.pem",
	  'sp-ca' => "/home/cnowicki/mcvs/lasso/tests/data/sp1-la/certificate.pem",
	  'idp-metadata' => "/home/cnowicki/mcvs/lasso/tests/data/idp1-la/metadata.xml",
	  'idp-public_key' => "/home/cnowicki/mcvs/lasso/tests/data/idp1-la/public-key.pem",
	  'idp-ca' => "/home/cnowicki/mcvs/lasso/tests/data/ca1-la/certificate.pem",
	  );

	  $config_ser = serialize($config);

	  if (($fd = fopen("config.inc", "w")))
		{
		  fwrite($fd, $config_ser);
		  fclose($fd);
		}
	  else
		die("Could not write default config file");
	}
	else 
	{
	  $config = unserialize(file_get_contents('config.inc'));
	}

	if ($_POST['action'] == 'setup') 
	{
		ob_start();
		
		$setup = FALSE;
		
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
		  last_login	  timestamp,
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

		$server = new LassoServer($config['sp-metadata'], 
		  $config['sp-public_key'], $config['sp-private_key'], 
		  $config['sp-ca'], lassoSignatureMethodRsaSha1);

		if (empty($server))
		{
		  die("Failed");
		} 
		else
		  print "OK";

		print "<br>Add provider : ";

		$ret = $server->addProvider($config['idp-metadata'], 
		  $config['idp-public_key'], $config['idp-ca']);

		/*if ($ret != TRUE)
		{
		  print "Failed";
		  break;
		} 
		else */
		  print "OK";

		print "<br>Write XML Server Dump : ";

		$dump = $server->dump();
		
		if (($fd = fopen($config['server_dump_filename'], "w")))
		{
		  fwrite($fd, $dump);
		  fclose($fd);
		  print "OK";
		}
		else
		  die("Failed");

		lasso_shutdown();

		print "<br>Save configuration file : ";

		# Save configuration file
		$config_ser = serialize($config);
		if (($fd = fopen("config.inc", "w")))
		{
		  fwrite($fd, $config_ser);
		  fclose($fd);
		  print "OK";
		} 
		else
		{
		  print("Failed");
		  break;
		}
		$setup = TRUE;
	}
		ob_start();
?>
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
<title>Setup script for Lasso (Liberty Alliance Single Sign On)</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-15" />
<?php
  if ($setup == TRUE) {
?>
<meta http-equiv="Refresh" CONTENT="3; URL=index.php">
<?php } ?>
</head>
<body>
<?php
  ob_end_flush();
  ob_end_flush();
  ?>
</body>
</html>
<?php
  	if (empty($setup))
	{
?>

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
  <td colspan='3' align='center'>Database Configuration</td>
</tr>
<tr>
  <td>DSN (Data Source Name) :</td><td><input type='text' name='dsn' size='50' value='<?php echo $config['dsn']; ?>' maxlength='100'></td><td><a href='http://pear.php.net/manual/en/package.database.db.intro-dsn.php' target='_new'>Help</a></td>
</tr>
<tr>
  <td>Server XML Dump:</td><td><input type='text' name='server_dump_filename' size='50' value='<?php echo $config['server_dump_filename']; ?>' maxlength='100'></td><td>&nbsp;</td>

</tr>
<tr>
  <td colspan='3' align='center'>Service Provider</td>
</tr>

<tr>
  <td>Metadata</td><td><input type='text' name='sp-metadata' size='50' value='<?php echo $config['sp-metadata']; ?>'></td><td>&nbsp;</td>

</tr>

<tr>
  <td>Public Key</td><td><input type='text' name='sp-public_key' size='50' value='<?php echo $config['sp-public_key']; ?>'></td><td>&nbsp;</td>

</tr>

<tr>
  <td>Private Key</td><td><input type='text' name='sp-private_key' size='50' value='<?php echo $config['sp-private_key']; ?>'></td><td>&nbsp;</td>

</tr>

<tr>
  <td>Certificate</td><td><input type='text' name='sp-ca' size='50' value='<?php echo $config['sp-ca']; ?>'></td><td>&nbsp;</td>

</tr>

<tr>
  <td colspan='3' align='center'>Identity Provider</td>
</tr>

<tr>
  <td>Metadata</td><td><input type='text' name='idp-metadata' size='50' value='<?php echo $config['idp-metadata']; ?>'></td><td>&nbsp;</td>

</tr>
<tr>
  <td>Public Key</td><td><input type='text' name='idp-public_key' size='50' value='<?php echo $config['idp-public_key']; ?>'></td><td>&nbsp;</td>

</tr>
<tr>
  <td>Certificate</td><td><input type='text' name='idp-ca' size='50' value='<?php echo $config['idp-ca']; ?>'></td><td>&nbsp;</td>
</tr>

<tr>
  <td colspan='3'>&nbsp;</td>
</tr>

<tr>
  <td align='center' colspan='3'><input type='submit' value='setup'></td>
</tr>
</table>
<input type='hidden' name='action' value='setup'>
</form>
</body>
</html>
<?php
  }
?>
