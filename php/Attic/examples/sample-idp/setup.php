<?php
/*  
 * Identity Provider Example -- Setup
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

   /*
    * This callback function is called by array_walk and 
	* add an service provider to the identity provider.
    */
   function add_service_provider(&$item, $key, $server)
   {
	  print "<br>$key : ";

	  $ret = $server->addProvider($item['metadata'], $item['public_key'], $item['ca']);
	  
	  /*if ($ret != TRUE)
	  {
		print "Failed";
		break;
	  } 
	  else */
		print "OK";
   }

   function write_config_inc($config)
   {
	 $config_ser = serialize($config);
	  $filename = "config.inc";
	 
	 if ($fd = fopen($filename, "w"))
	  {
  		fwrite($fd, $config_ser);
		fclose($fd);
		return TRUE;
	  }
	  return FALSE;
   }
   
	require_once 'DB.php';

	# default config
	if (!file_exists('config.inc'))
	{
	  $cwd = getcwd();
	  $config = array(
		'dsn' => "pgsql://idp:idp@localhost/idp",
		'server_dump_filename' => "lasso_server_dump.xml",
		'idp-metadata' => "/home/cnowicki/mcvs/lasso/tests/data/idp1-la/metadata.xml",
		'idp-public_key' => "/home/cnowicki/mcvs/lasso/tests/data/idp1-la/public-key.pem",
		'idp-private_key' => "/home/cnowicki/mcvs/lasso/tests/data/idp1-la/private-key-raw.pem",
		'idp-ca' => "/home/cnowicki/mcvs/lasso/tests/data/idp1-la/certificate.pem",
		'sp' => array(
		  'sp1' => array(
			'metadata' => "/home/cnowicki/mcvs/lasso/tests/data/sp1-la/metadata.xml",
			'public_key' => "/home/cnowicki/mcvs/lasso/tests/data/sp1-la/public-key.pem",
			'ca' => "/home/cnowicki/mcvs/lasso/tests/data/ca1-la/certificate.pem"),
		  'sp2' => array(
			'metadata' => "/home/cnowicki/mcvs/lasso/tests/data/sp2-la/metadata.xml",
			'public_key' => "/home/cnowicki/mcvs/lasso/tests/data/sp2-la/public-key.pem",
			'ca' => "/home/cnowicki/mcvs/lasso/tests/data/ca1-la/certificate.pem")
		));

	  $config_ser = serialize($config);

	  if (!write_config_inc($config))
		die("Could not write default config file");
	}
	else 
	{
	  $config = unserialize(file_get_contents('config.inc'));
	}

	$keys = array_keys($_POST);

	$to_del = preg_grep('/delete_(\w)/', $keys);

	if (!empty($to_del)) 
	{
	  $keys = array_values($to_del);
	  foreach($keys as $key)
	  {
		$name = substr($key, 7);
		unset($config['sp'][$name]);
		write_config_inc($config);
	  }
	}
	
	$to_update = preg_grep('/update_(\w)/', $keys);
	
	if (!empty($to_update)) 
	{
	  $keys = array_values($to_update);
	  foreach($keys as $key)
	  {
		$name = substr($key, 7);
		$config['sp'][$name]['metadata'] = $_POST['sp^'.$name.'^metadata'];
		$config['sp'][$name]['public_key'] = $_POST['sp^'.$name.'^public_key'];
		$config['sp'][$name]['ca'] = $_POST['sp^'.$name.'^ca'];
		write_config_inc($config);
	  }
	}

	
	if (array_key_exists('new', $_POST))
	{
	  $form = array('sp' => 'Name', 
		'metadata' => 'Metadata', 
		'public_key' => 'Public Key', 
		'ca' => 'Certificate');
	  
	  foreach ($form as $input => $name)
		if (empty($_POST[$input]))
		  die("Field <b>$name</b> is empty"); 
	
	  $config['sp'][$_POST['sp']] = array(
		'metadata' => $_POST['metadata'], 
		'public_key' => $_POST['public_key'],
		'ca' => $_POST['ca']);

	  write_config_inc($config);
	}

	if (array_key_exists('setup', $_POST))
	{
		ob_start();
		
		$setup = FALSE;
		
		print "<b>Lasso Identity Provider Setup</b><br>";

		unset($_POST['setup'], $_POST['metadata'], $_POST['public_key'], $_POST['ca'], $_POST['sp']);

		$sps = array_values(preg_grep("/sp\^/", array_keys($_POST)));


		$_POST['sp'] = array();

		foreach ($sps as $sp) {
		  list($null, $name, $type) = split("\^", $sp, 3);
		  $_POST['sp'][$name][$type] = $_POST[$sp];
		  unset($_POST[$sp]);
		}
		
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
		  username		  varchar(255) unique,
		  password		  varchar(255),
		  user_dump       text,
		  session_dump    text)";
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

		print "<br>Create table 'assertions' : ";
		$query = "DROP TABLE assertions CASCADE";
		$res =& $db->query($query);

		$query = "CREATE TABLE assertions (
		  assertion        text,
		  response_dump    text,
		  created          timestamp)";

		$res =& $db->query($query);
		if (DB::isError($res)) 
		  die($res->getMessage());

		print "OK";

		$db->disconnect();

		// Check if IdP files does exists
	
		$keys = array_keys($config);
		$files = preg_grep("/idp/", $keys);
		
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

		
		foreach($config['sp'] as $key)
		{
		  foreach ($key as $file) 
		  {
			print "<br>Check file " . $file . " : ";
			if (!file_exists($file))
			{
			  die("Failed (file does not exist)");
			}
			else
			  print "OK";

		  }
		}
		
		lasso_init();

		print "<br>Create Server : ";

		$server = new LassoServer($config['idp-metadata'], 
		  $config['idp-public_key'], $config['idp-private_key'], 
		  $config['idp-ca'], lassoSignatureMethodRsaSha1);

		if (empty($server))
		{
		  die("Failed");
		} 
		else
		  print "OK";


		print "<br>Add Service Provider(s) :";
		
		array_walk($config['sp'], 'add_service_provider', $server);

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
<script language="JavaScript" type="text/javascript">
<!-- 

  function openpopup(popurl)
  {
	var winpops=window.open(popurl,"","width=745,height=600")
  }
//-->
</script>
</head>
<body>
<form name='frm' action='<?php echo $PHP_SELF ?>' method='POST'>

<p align='center'>Lasso Identity Provider Setup</p>
<p>
<table>
<caption>Database Configuration</caption>
<tr>
  <td>DSN (Data Source Name) :</td><td><input type='text' name='dsn' size='50' value='<?php echo $config['dsn']; ?>' maxlength='100'></td><td><a href='http://pear.php.net/manual/en/package.database.db.intro-dsn.php' target='_new'>Help</a></td>
</tr>
<tr>
  <td>Server XML Dump:</td><td><input type='text' name='server_dump_filename' size='50' value='<?php echo $config['server_dump_filename']; ?>' maxlength='100'></td><td>&nbsp;</td>
</tr>
</table>
</p>
<hr>
<p>
<table>
<caption>Identity Provider</caption>

<tr>
  <td>Metadata</td><td><input type='text' name='idp-metadata' size='50' value='<?php echo $config['idp-metadata']; ?>'></td><td>&nbsp;</td>
</tr>

<tr>
  <td>Public Key</td><td><input type='text' name='idp-public_key' size='50' value='<?php echo $config['idp-public_key']; ?>'></td><td>&nbsp;</td>
</tr>

<tr>
  <td>Private Key</td><td><input type='text' name='idp-private_key' size='50' value='<?php echo $config['idp-private_key']; ?>'></td><td>&nbsp;</td>
</tr>

<tr>
  <td>Certificate</td><td><input type='text' name='idp-ca' size='50' value='<?php echo $config['idp-ca']; ?>'></td><td>&nbsp;</td>
</tr>
</table>
</p>

<hr>
<?php
  foreach ($config['sp'] as $sp => $name) 
  {
?>
<table>
<caption>Service Provider <b><?php echo $sp ?></caption>

<tr>
  <td>Metadata</td><td><input type='text' name='sp^<?php echo $sp; ?>^metadata' size='50' value='<?php echo $config['sp'][$sp]['metadata']; ?>'></td>
  <td><a href="javascript:openpopup('edit_metadata.php?filename=<?php echo $config['sp'][$sp]['metadata']; ?>')">Edit Metadata</a></td>
</tr>
<tr>
  <td>Public Key</td><td><input type='text' name='sp^<?php echo $sp; ?>^public_key' size='50' value='<?php echo $config['sp'][$sp]['public_key']; ?>'></td><td>&nbsp;</td>

</tr>
<tr>
  <td>Certificate</td><td><input type='text' name='sp^<?php echo $sp; ?>^ca' size='50' value='<?php echo $config['sp'][$sp]['ca']; ?>'></td><td>&nbsp;</td>
</tr>

<tr>
  <td colspan='3' align='center'>
	<input type='submit' name='update_<?php echo $sp; ?>' value='save / update'>
	<input type='submit' name='delete_<?php echo $sp; ?>' value='delete'>
  </td>
</tr>
</table>

<?php
  }
?>
</p>

<p>
<table>
<caption>Add a new Service Provider</caption>

<tr>
  <td>Name</td><td><input type='text' name='sp' size='50'></td><td>&nbsp;</td>
</tr>

<tr>
  <td>Metadata</td><td><input type='text' name='metadata' size='50'></td>
  <td><a href="javascript:openpopup('create_metadata.php')">Create Metadata</a></td>
</tr>

<tr>
  <td>Public Key</td><td><input type='text' name='public_key' size='50'></td><td>&nbsp;</td>
</tr>

<tr>
  <td>Certificate</td><td><input type='text' name='ca' size='50'></td><td>&nbsp;</td>
</tr>

<tr>
  <td colspan='3' align='center'>
	<input type='submit' name='new' value='save / update'>
  </td>
</tr>
</fieldset>
</table>
</p>
<hr>
<p>
  <input type='submit' name='setup' value='setup'>
</p>
</form>
<br>
<p>Copyright &copy; 2004 Entr'ouvert</p>
</body>
</html>
<?php
  }
?>
