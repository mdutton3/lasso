<?php
/*  
 * Identity Provider Example -- User Administration 
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

  require_once 'Log.php';
  require_once 'DB.php';

  $config = unserialize(file_get_contents('config.inc'));
	
  $number_of_users = 5; 
  
  $db = &DB::connect($config['dsn']);

  if (DB::isError($db)) 
     die("Could not connect to the database");

  // create logger 
  $conf['db'] = $db;
  $logger = &Log::factory($config['log_handler'], 'log', $_SERVER['PHP_SELF'], $conf);

  // Show XML dump
  if (!empty($_GET['dump']) && !empty($_GET['type'])) 
  {
  	$query = "SELECT " . ($_GET['type'] == 'identity' ? 'identity' : 'session') . 
	$query .= "_dump FROM users WHERE user_id=".$db->quoteSmart($_GET['dump']);
	$res =& $db->query($query);
	if (DB::isError($res)) 
	  die($res->getMessage());
	  
	$row = $res->fetchRow();
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<body onLoad="window.focus();">
<table>
<caption><?php echo ($_GET['type'] == 'identity' ? 'Identity' : 'Session'); ?> Dump</caption>
<tr>
  <td>
  <textarea rows="15" cols="50"><?php echo htmlentities($row[0], ENT_QUOTES); ?></textarea>
  </td>
</tr>
<tr>
<td align="center"><a href="javascript:window.close(self)">Close</a></td>
</tr>
</table>
</body>
</html>
<?php	
	exit;
	}
  
  if (!empty($_GET['del'])) {

	$query = "DELETE FROM nameidentifiers WHERE user_id=".$db->quoteSmart($_GET['del']);
   	$res =& $db->query($query);
	if (DB::isError($res)) 
	  die($res->getMessage());

	$query = "DELETE FROM users WHERE user_id=".$db->quoteSmart($_GET['del']);
   	$res =& $db->query($query);
	if (DB::isError($res)) 
	  die($res->getMessage());

	}
	
  lasso_init();

  // Create Lasso Server
  $server_dump = file_get_contents($config['server_dump_filename']);
  $server = LassoServer::newFromDump($server_dump);

  // Lasso User
  $login = new LassoLogin($server);
  
  // Count users
  $query = "SELECT COUNT(*) FROM users";
  $res =& $db->query($query);
  if (DB::isError($res)) 
  	die($res->getMessage());
 
  $row = $res->fetchRow();
  $count = $row[0];

  
  $startUser = ((empty($_GET['startUser'])) ? 0 : $_GET['startUser']);
	
  $query = "SELECT * FROM users";

  if (!isset($_GET['show_all']))
  	$query .= " OFFSET $startUser LIMIT " . ($startUser + $number_of_users);
  $res =& $db->query($query);
  
  if (DB::isError($db)) 
  	die($db->getMessage());
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
<title>Lasso Service Provider Example : Users Management</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-15" />
<script language="JavaScript" type="text/javascript">
<!-- 

  function openpopup(popurl)
  {
	var winpops=window.open(popurl,"","width=400,height=300")
  }

  function ToggleAll() 
  {
	for (var i = 0; i < document.frm.elements.length; i++)
	{
	  if(document.frm.elements[i].type == 'checkbox')
		document.frm.elements[i].checked = !(document.frm.elements[i].checked);
	}
  }

//-->
</script>
</head>

<body>
<form name='frm' method=>
<table border="1" align="center">
<caption>Users</caption>
<?php
  $num_col = $res->numCols();
  $tableinfo = $db->tableInfo($res);
?>
<thead>
<tr>
  <td colspan='<?php echo $num_col + 1; ?>'>
	 
	<?php 
	  if ($startUser)
		echo "<a href=$PHP_SELF?startUser=" . ($startUser - $number_of_users) . ">Previous</a>";
	  else
		echo "Previous" 
	?> 
	| 
	<?php 
	  if ((($count - $startUser) >  $number_of_users)  && !isset($_GET['show_all']))
		echo "<a href=$PHP_SELF?startUser=" . ($startUser + $number_of_users) . ">Next</a>";
	  else
		echo "Next" 
	?>
	<?php
	  for ($i = 0; $i < $count; $i += $number_of_users)
		if ($i == $startUser)
		  echo "| " . ( $i / $number_of_users);
		else
		  echo "| <a href=\"$PHP_SELF?startUser=$i\">" . ( $i / $number_of_users) . "</a>";
	?>
	|
	<?php if (isset($_GET['show_all'])) { ?>
	<a href="<?php echo $PHP_SELF."?startUser=0"; ?>">Paginate</a> 
	<?php } else { ?>
	<a href="<?php echo $PHP_SELF."?show_all=1"; ?>">Show All</a> 
	<?php } ?>
	| <a href="javascript:void(0)" onClick="ToggleAll();">Toggle All</a></td>
  <td align='right'><a href="javascript:openpopup('user_add.php')">add user</a></td>
</tr>
<tr align="center">
<td>&nbsp;</td>
<?php
  for ($i = 0; $i < $num_col; $i++) {
	echo "<td><b>" . $tableinfo[$i]['name'] ."</b></td>";
  }
?>
<td>&nbsp;</td>
</tr>
</thead>
<tbody>
<?php
  while ($row =& $res->fetchRow()) {
?>
<tr align="center">
<td rowspan="2">
  <input type='checkbox' name='uid' value='<?php $row[0]; ?>'>
</td>
<?php
  for ($i = 0; $i < $num_col; $i++)
  {
	?>
	<td>
	<?php 
        // show row content
	  switch ($tableinfo[$i]['name']) 
	  {
		case "identity_dump":
            $identity_dump = $row[$i];
            if (empty($row[$i]))
                echo "&nbsp;";
            else
                echo "<a href=javascript:openpopup('". $PHP_SELF . '?dump=' . $row[0] . "&type=identity')>view</a>";
		  break;
	    case "session_dump":
            $session_dump = $row[$i];
            if (empty($row[$i]))
                echo "&nbsp;";
            else
                echo "<a href=javascript:openpopup('". $PHP_SELF . '?dump=' . $row[0] . "&type=session')>view</a>";
		  break;
		default:
		  echo (empty($row[$i])) ? "&nbsp;" : $row[$i];
	  }
	  ?>
	</td>
	<?php
  }
  ?>
  <td rowspan="2">
    <a href="<?php echo $PHP_SELF . '?del=' . $row[0]; ?>">delete</a>
    <a href="javascript:openpopup('user_edit.php?user_id=<?php echo ?>')">edit</a>
  </td>
</tr>
<tr>
    <td colspan="<?php echo $num_col; ?>" align='center'> 
    <?php
        // get all federations for this user
        if (!empty($session_dump) && !empty($identity_dump))
        {
            $login->setSessionFromDump($session_dump);
            $login->setIdentityFromDump($identity_dump);

            $identity = $login->identity;
            $providerIDs = $identity->providerIDs;
?>
<table width="100%">
<?php
            for($i = count($providerIDs); $i > 0; $i--)
            {
?>
<tr>
    <td align='center'><?php echo print $providerIDs[$i - 1]; ?></td>
    <td align='right'><a href="">cancel federation</a></td>
</tr>
<?php
            }
?>
</table>
<?php
        }
        else
            echo "Not Federated with an Service Provider.";
    ?>
    </td>
</tr>
<?php
}
?>
</tbody>
<tfoot>
<tr>
  <td colspan="<?php echo $num_col + 1; ?>">&nbsp;</td>
  <td>Total: <?php echo $count; ?> Users</td>
</tr>
</tfoot>
</table>
</form>

<br>
<p align='center'><a href='index.php'>Index</a>
</p>

<br>
<p>Copyright &copy; 2004 Entr'ouvert</p>

</body>

</html>
<?php
    lasso_shutdown();
    $db->disconnect();
?>
