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

  require_once 'DB.php';


  $db = &DB::connect($config['dsn']);

  if (DB::isError($db)) 
	  die($db->getMessage());

  if (!empty($_GET['dump'])) {
  	$query = "SELECT identity_dump FROM users WHERE user_id='" . $_GET['dump'] . "'";
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

  if (!empty($_GET['del'])) {

	$query = "DELETE FROM nameidentifiers WHERE user_id='" . $_GET['del'] . "'" ;
   	$res =& $db->query($query);
	if (DB::isError($res)) 
	  print $res->getMessage(). "\n";

	$query = "DELETE FROM users WHERE user_id='" . $_GET['del'] . "'" ;
   	$res =& $db->query($query);
	if (DB::isError($res)) 
	  print $res->getMessage(). "\n";

	}
	

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
	echo "<td>" . $tableinfo[$i]['name'] ."</td>";
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
		  break;
		  
		default:
		  echo (empty($row[$i])) ? "&nbsp;" : $row[$i];
	  }
	  ?>
	</td>
	<?php
  }
  ?>
  <td>
  <a href="<?php echo $PHP_SELF . '?del=' . $row[0]; ?>">delete</a>
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

</body>

</html>
<?php
  $db->disconnect();
?>
