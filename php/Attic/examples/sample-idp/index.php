<?php
/*  
 * Identity Provider Example -- Index File
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
<p align='center'><b>Identity Provider Configuration file is not available</b><br>
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

 // Create Lasso Server
 $server_dump = file_get_contents($config['server_dump_filename']);
 $server = LassoServer::newFromDump($server_dump);
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" 
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
<title>Lasso Identity Provider Example</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-15" />
</head>

<body>
<p align='center'>
  <b>Identity Provider Administration</b><br>
  <a href="setup.php">Setup</a><br>
  <a href="admin_user.php">Users Management</a><br>
  <a href="view_session.php">View Online Users</a>
<?php if ($config['log_handler'] == 'sql') { ?>
  <br><a href="log_view.php">View log</a>
<?php } ?>
</p>
<p align='center'>
  <b>Identity Provider Fonctionnality</b>
</p>
<?php
  if (!isset($_SESSION["user_id"])) {  
  ?>
<p align='center'>
  <a href="login.php">Local Login</a></p>
<?php 
  } 
  else
  { 
	if (isset($_SESSION['identity_dump']))
	{
		$login = new LassoLogin($server);
		$login->setIdentityFromDump($_SESSION['identity_dump']);
		if (!empty($_SESSION['session_dump']))
			$login->setSessionFromDump($_SESSION['sesion_dump']);
		$identity = $login->identity;
		$providerIDs = $identity->providerIds;

		if ($providerIDs->length())
		{
?>
<p align='center'>Cancel a Federation with :</p>
<p align='center'>
<table align='center'>
<thead>
<tr>
	<td align='center'>Service Provider</td>
	<td align='center'>Profile</td>
</tr>
</thead>
<tbody>
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
<?php
			}
?>
</tbody>
</table>
</p>
<?php
		}
		else
		{
?>
<p align='center'>Your are not Federated with an Service Provider.</p>
<?php
		}
	}
?>
<p align='center'>
<a href="logout.php">Local Logout</a></p>
<?php } ?>

<p align='center'>
<table align='center'>
<caption><b>Status</b></caption>
<tr>
  <?php 
	if (!isset($_SESSION["user_id"]))
	{
	  echo "<td>User is <b>not</b> logged in!</td>";
	}
	else 
	{ 
	  ?>
	<td colspan='2' align="center">User <b>is</b> logged in!</td>
</tr>
<tr>
	<td><b>UserID:</b></td><td><?php echo $_SESSION["user_id"]; ?></td>
</tr>
<tr>
	<td><b>User Name:</b></td><td><?php echo $_SESSION["username"]; ?></td>
</tr>
<tr>
	<td><b>PHP Session ID:</b></td><td><?php echo session_id(); ?></td>
</tr>
<?php
  }
?>
</table>

<br>
<p align='center'>Copyright &copy; 2004 Entr'ouvert</p>

</body>

</html>
<?php
	lasso_shutdown();
?>
