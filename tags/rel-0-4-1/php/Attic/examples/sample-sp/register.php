<?php
/*  
 * Service Provider Example -- Register Form
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

  $config = unserialize(file_get_contents('config.inc'));
  
  require_once 'DB.php';
  
  if (!empty($_GET['SID'])) 
	session_start($_GET['SID']);
  else
	session_start();

  if (!isset($_SESSION["nameidentifier"])) {
	print "User is not logged in";
	exit(0);
	}

	switch($_POST['action']) {
	  case "submit":
		$db = &DB::connect($config['dsn']);

		if (DB::isError($db)) 
		  die($db->getMessage());

		$query = "UPDATE users SET first_name='" . $_POST['first_name'] . "',last_name='". $_POST['last_name'] ."' WHERE user_id='".$_SESSION["user_id"]."'";
		$res =& $db->query($query);
		if (DB::isError($res)) 
		  print $res->getMessage(). "\n";

		$url = "index.php";
		header("Request-URI: $url");
		header("Content-Location: $url");
		header("Location: $url");
		break;
	  default:
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
<title>Lasso Service Provider Example : Registration Form</title>
</head>

<body>
<form name='frm' action="<?php echo $PHP_SELF; ?>" method='post'>
<table align="center">
<caption>Registration Form</caption>
<tr>
  <td>First Name:</td><td><input type='text' name="first_name" maxlength='50'></td>
</tr>
<tr>
  <td>Last Name:</td><td><input type='text' name="last_name" maxlength='50'></td>
</tr>
<tr>
	<td>&nbsp;</td><td><input type='submit' value="Ok"></td>
</tr>
</table>
<input type='hidden' name='action' value='submit'>
</form>

</body>
</html>
<?php
}
?>
