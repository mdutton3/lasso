<?php
/*  
 * Identity Provider Example -- View log
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

  require_once 'HTML/QuickForm.php';
  require_once 'DB.php';  

   $config = unserialize(file_get_contents('config.inc'));

   // connect to the data base
   $db = &DB::connect($config['dsn']);
   if (DB::isError($db)) 
	die("Could not connect to the database");

   if ($config['log_handler'] != 'sql')
	die("Unsupported log handler");

   $number_of_msg = 8; 
   
   // Count log messages
   $query = "SELECT COUNT(*) FROM log";
   $res =& $db->query($query);
   if (DB::isError($res)) 
  	die($res->getMessage());
 
   $row = $res->fetchRow();
   $count = $row[0];

   $startMsg = ((empty($_GET['startMsg'])) ? 0 : $_GET['startMsg']);
   
   $query = "SELECT * FROM log ORDER BY id DESC";
   if (!isset($_GET['show_all']))
  	$query .= " OFFSET $startMsg LIMIT " . ($startMsg + $number_of_msg);


   $res =& $db->query($query);
   if (DB::isError($res)) 
  	die($res->getMessage());

   $numRows = $res->numRows();

?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
<head>
  <title>Lasso Identity Provider Example : View Logs</title>
</head>
<body>
<br>
<table border='1' width='100%'>
<caption>Logged events</caption>
<thead>
<tr>
	<td colspan='4'>
	<?php 
	  if ($startMsg)
		echo "<a href=$PHP_SELF?startMsg=" . ($startMsg - $number_of_msg) . ">Previous</a>";
	  else
		echo "Previous" 
	?> 
	| 
	<?php 
	  if ((($count - $startMsg) >  $number_of_users)  && !isset($_GET['show_all']))
		echo "<a href=\"" . $PHP_SELF . "?startMsg=" . ($startMsg + $number_of_msg) . "\">Next</a>";
	  else
		echo "Next";

	if (isset($_GET['show_all']))
		echo "| <a href=\"" . $PHP_SELF ."?startMsg=0\">Paginate</a>"; 
	else
	{
	  for ($i = 0; $i < $count; $i += $number_of_msg)
		if ($i == $startMsg)
		  echo "| " . ( $i / $number_of_msg);
		else
		  echo "| <a href=\"$PHP_SELF?startMsg=$i\">" . ( $i / $number_of_msg) . "</a>";
          if ($count > $number_of_msg)
		echo "| <a href=\"$PHP_SELF?show_all=1\">Show All</a>"; 
	}
	?>
	</td>
</tr>
<tr>
	<td align='center'>date</td>
	<td align='center'>filename</td>
	<td align='center'>priority</td>
	<td align='center'>message</td>
</tr>
</thead>
<tbody>
<?php
	if ($numRows)
	{
		$num_col = $res->numCols();
		$tableinfo = $db->tableInfo($res);

		$desc = array("emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug");

		while($row = $res->fetchRow())
		{
			echo "<tr>";
			for ($i = 0; $i < $num_col; $i++)
			{
				switch ($tableinfo[$i]['name']) 
				{
					case "id":
						break;
					case "priority":
						echo "<td align='center'>" . $desc[$row[$i]] . "</td>";
						break;
					case "message":
						echo "<td>" . $row[$i] . "</td>";
						break;
					default:
						echo "<td align='center'>" . $row[$i] . "</td>";
				}
			}
			echo "</tr>";
		}
	}
?>
<tr>
</tr>
</tbody>
<tfoot>
<tr>
	<td colspan='4'>&nbsp;</td>
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

