<?php
/*  
 * Service Provider Example -- User Administration 
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

  require_once 'Log.php';
  require_once 'DB.php';
  
  // connect to the data base
  $db = &DB::connect($config['dsn']);
  if (DB::isError($db)) 
	die($db->getMessage());

  // create logger 
  $conf['db'] = $db;
  $logger = &Log::factory($config['log_handler'], 'log', $_SERVER['PHP_SELF'], $conf);


  if (!empty($_GET['dump'])) {
  	$query = "SELECT identity_dump FROM users WHERE user_id=".$db->quoteSmart($_GET['dump']);
	$res =& $db->query($query);
	if (DB::isError($res)) 
	  print $res->getMessage(). "\n";
	$row = $res->fetchRow();
	
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<body>
<table>
<caption>Identity Dump</caption>
<tr>
<td>
<textarea rows="15" cols="50">
<?php
  echo htmlentities($row[0], ENT_QUOTES);
?>
</textarea>
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

  if (!empty($_GET['del'])) 
  {

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
  
  $query = "SELECT * FROM users";
  $res =& $db->query($query);
  if (DB::isError($res)) 
  	print $res->getMessage(). "\n";
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
<title>Lasso Service Provider Example : Users Management</title>
<script type="text/javascript">

  function openpopup(popurl){
	var winpops=window.open(popurl,"","width=400,height=300")
  }

</script>
</head>
<body>

<table border="1" align="center">
<caption>Users</caption>
<?php
  $num_col = $res->numCols();
  $tableinfo = $db->tableInfo($res);
?>
<thead>
<tr align="center"><?php
  for ($i = 0; $i < $num_col; $i++) {
	echo "<td><b>" . $tableinfo[$i]['name'] ."</b></td>";
  }
?><td>&nbsp;</td>
</tr>
</thead>
<tbody>
<?php
  while ($row =& $res->fetchRow()) {
?>
<tr align="center">
<?php
  for ($i = 0; $i < $num_col; $i++)
  {
	?>
	<td>
	<?php 
	  switch ($tableinfo[$i]['name']) 
	  {
		case "identity_dump":
  		  echo "<a href=javascript:openpopup('". $PHP_SELF . '?dump=' . $row[0] . "')>view</a>";
		  $identity_dump = $row[$i];
		  break;
		  
		default:
		  echo (empty($row[$i])) ? "&nbsp;" : $row[$i];
	  }
	  ?>
	</td>
	<?php
  }
  ?>
  <td rowspan='2'><a href="<?php echo $PHP_SELF . '?del=' . $row[0]; ?>">delete</a></td>
</tr>
<tr>
	<td colspan='<?php echo $num_col; ?>' align='center'>
<?
	// get all federations for this user
        if (!empty($identity_dump))
        {
            $login->setIdentityFromDump($identity_dump);
            $identity = $login->identity;
            $providerIDs = $identity->providerIds;
	    
	    for($i = 0; $i <  $providerIDs->length() ; $i++)
	    {
		if ($i)
			echo "<br>";
		echo  $providerIDs->getItem($i);
	    }
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
<td colspan="<?php echo $num_col; ?>">&nbsp;</td>
<td>Total: <?php echo $res->numRows();?> Users</td>
</tr>
</tfoot>
</table>

<br>
<p align='center'><a href='index.php'>Index</a>
</p>

<br>
<p>Copyright &copy; 2004 Entr'ouvert</p>

</body>

</html>
<?php
  $db->disconnect();
  lasso_shutdown();
?>
