<?php
/*  
 * Service Provider Example -- Configuration File
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
 
 include 'config.php.inc';

 require_once 'DB.php';

 session_start($SID);

 lasso_init();
 
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
<title>Lasso Service Provider Example</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-15" />
</head>

<body>
<p>
<table border="1" frame="above">
<tr>
  <td><b>Service Provider Administration</b></td>
</tr>
<?php
  if (!file_exists($server_dump_filename)) {
?>
<tr>
  <td><a href="setup.php">Setup</a></td>
</tr>
</table>
<?php 
} else {
?>
<tr>
  <td><a href="admin_user.php">Users Management</a></td>
</tr>
<tr>
  <td><a href="admin_fed.php">Federation Administration</a></td>
</tr>
<tr>
  <td><b>Serice Provider Fonctionnality</b></td>
</tr>
<?php
  if (!isset($_SESSION["nameidentifier"])) {  
  ?>
<tr>
  <td><a href="login.php">Login!</a></td>
</tr>
<?php } else { ?>
<tr>
  <td><a href="logout.php?SID=<?php echo $SID ?>">Logout!</a></td>
</tr>
<?php } ?>
</table>
</p>
<p>
<table border="1" frame="above">
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
  $db = &DB::connect($dsn);

  if (DB::isError($db)) 
	die($db->getMessage());

  $query = "SELECT * FROM users WHERE user_id='". $_SESSION["user_id"] ."'"; 

  $res =& $db->query($query);
  if (DB::isError($res)) 
	print $res->getMessage(). "\n";

  list($user_id, $identity_dump, $first_name, $last_name, $created, $last_login) = $res->fetchRow();

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
	$db->disconnect();
	} 
	?>
</tr>
</table>
</p>
<?php
}
?>
<p>Lasso Version : <?php echo lasso_version(); ?></p>

<br>
<p>Copyright &copy; 2004 Entr'ouvert</p>

</body>

</html>
<?php
	lasso_shutdown();
  ?>
