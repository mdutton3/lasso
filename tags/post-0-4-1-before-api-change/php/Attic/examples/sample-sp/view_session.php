<?php
/*  
 * Service Provider Example -- Online User Viewer
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
 
 $db = &DB::connect($config['dsn']);

 if (DB::isError($db)) 
	die($db->getMessage());
	
 $query = "SELECT * FROM sessions";

 $res =& $db->query($query);
 if (DB::isError($res)) 
	die($res->getMessage());

 $numRows = $res->numRows();
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" 
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
<title>Lasso Service Provider Example : View Online Users</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-15" />
</head>
<body>

<p align='center'>
<table align='center' width='95%'>
<caption>Online Users</caption>
<thead>
<tr>
	<td>&nbsp;</td>
</tr>
</thead>
<tbody>

</tbody>
<tfoot>
<tr>
	<td>&nbsp;</td>
</tr>
</tfoot>
</table>
</p>

<br>
<p align='center'><a href='index.php'>Index</a>
</p>
<br>
<p align='center'>Copyright &copy; 2004 Entr'ouvert</p>

</body>
</html>
