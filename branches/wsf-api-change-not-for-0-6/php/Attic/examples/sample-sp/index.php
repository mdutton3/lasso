<?php
/*  
 * Service Provider Example -- Index File
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

 require_once 'DB.php';
 require_once 'session.php';

 if(!extension_loaded('lasso')) {
	$ret = @dl('lasso.' . PHP_SHLIB_SUFFIX);
	if ($ret == FALSE)
	{
?>
<p align='center'><b>The Lasso Extension is not available</b><br>
Please check your PHP extensions<br>
You can get more informations about <b>Lasso</b> at <br>
<a href='http://lasso.entrouvert.org/'>http://lasso.entrouvert.org/</a></p>
<?php
	exit();
	}
 }

 if (!file_exists('config.inc'))
  {
?>
<p align='center'><b>Service Provider Configuration file is not available</b><br>
Please run the setup script :<br>
<a href='setup.php'>Lasso Service Provider Setup</a><br>
You can get more informations about <b>Lasso</b> at <br>
<a href='http://lasso.entrouvert.org/'>http://lasso.entrouvert.org/</a></p>
<?php
  exit();
  }

 $config = unserialize(file_get_contents('config.inc'));

 // connect to the data base
 $db = &DB::connect($config['dsn']);
 if (DB::isError($db)) 
	die($db->getMessage());

 // session handler
 session_set_save_handler("open_session", "close_session", 
 "read_session", "write_session", "destroy_session", "gc_session");

  session_start();


  lasso_init();

  $server_dump = file_get_contents($config['server_dump_filename']);
  $server = LassoServer::newFromDump($server_dump);
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" 
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
<title>Lasso Service Provider Example</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-15" />
</head>

<body>
<p align='center'>
<b>Service Provider Administration</b><br>
<a href="setup.php">Setup</a><br>
<a href="admin_user.php">Users Management</a><br>
<a href="view_session.php">View Online Users</a>
<?php if ($config['log_handler'] == 'sql') { ?>
  <br><a href="log_view.php">View log</a>
<?php } ?>
</p>
<p align='center'>
  <b>Serice Provider Fonctionnality</b>
<table align='center'>
<?php
  if (!isset($_SESSION["nameidentifier"])) {  
  ?>
<tr>
  <td colspan="2">Single SignOn using an Identity Provider</td>
</tr>
<tr>
  <td colspan="2">&nbsp;</td>
</tr>
<tr>
  <td>Provider</td>
  <td>Profile</td>
</tr>
<tr>
  <td><?php echo $config['providerID']; ?></td>
  <td><a href="login.php?profile=post">post</a> | <a href="login.php?profile=artifact">artifact</a></td>
</tr>
<?php } else { 
        // User is federated with an Service Provider
	if (isset($_SESSION['identity_dump']))
	{
		$login = new LassoLogin($server);
		$login->setIdentityFromDump($_SESSION['identity_dump']);
		if (!empty($_SESSION['session_dump']))
			$login->setSessionFromDump($_SESSION['session_dump']);
		$identity = $login->identity;
		$providerIDs = $identity->providerIds;

		if ($providerIDs->length())
		{
?>
<tr>
	<td align='center' colspan='2'>Cancel a Federation with :</td>
</tr>
<tr>
	<td align='center'>Identity Provider</td><td align='center'>Profile</td>
</tr>
<?php
			for($i = 0; $i <  $providerIDs->length() ; $i++)
			{
				$providerID = $providerIDs->getItem($i);
?>
<tr>
	<td align='center'><?php echo $providerID; ?></td>
	<td align='center'>
		<a href="cancel_federation.php?profile=redirect&with=<?php echo $providerID; ?>">Redirect</a> |
		<a href="cancel_federation.php?profile=soap&with=<?php echo $providerID; ?>">SOAP</a>
	</td>
</tr>
<tr>
	<td colspan='2'>&nbsp;</td>
</tr>
<?php
			}
		}
	}
?>
<tr>
  <td>Single Logout using </td><td><a href="logout.php?profile=soap">SOAP</a></td>
</tr>
<?php } ?>
</table>
</p>

<p align='center'>
<table align='center'>
<caption><b>Status</b></caption>
<tr>
  <?php 
	if (!isset($_SESSION["nameidentifier"]))
	{
	  echo "<td>User is <b>not</b> logged in!</td>";
	}
	else 
	{ 
	  ?>
	<td colspan='2' align="center">User <b>is</b> logged in!</td>
</tr>
<tr>
	<td><b>Name Identifier:</b></td><td><?php echo $_SESSION["nameidentifier"]; ?></td>
</tr>
<tr>
	<td><b>UserID:</b></td><td><?php echo $_SESSION["user_id"]; ?></td>
</tr>
<?php
 
  $query = "SELECT * FROM users WHERE user_id='". $_SESSION["user_id"] ."'"; 

  $res =& $db->query($query);
  if (DB::isError($res)) 
	die($res->getMessage());

  list($user_id, $identity_dump, $first_name, $last_name, $last_login, $created) = $res->fetchRow();
  ?>
<tr>
	<td><b>Last Name:</b></td><td><?php echo $last_name; ?></td>
</tr>
<tr>
	<td><b>First Name:</b></td><td><?php echo $first_name; ?></td>
</tr>
<tr>
	<td><b>PHP Session ID:</b></td><td><?php echo session_id(); ?></td>
</tr>
<tr>
	<td><b>Account Created:</b></td><td><?php echo $created; ?></td>
</tr>
<tr>
	<td><b>Last Login:</b></td><td><?php echo $last_login; ?></td>
  <?php 
	} 
	?>
</tr>
</table>
</p>
<br>
<p align='center'>Copyright &copy; 2004, 2005 Entr'ouvert</p>
</body>
</html>
<?php
	lasso_shutdown();
?>
