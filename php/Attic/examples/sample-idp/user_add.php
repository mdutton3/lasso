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

  require_once 'HTML/QuickForm.php';
  require_once 'DB.php';  

  $form = new HTML_QuickForm('frm');

  $form->addElement('header', null, 'Add New User');
  $form->addElement('text', 'username', 'Username:', array('size' => 50, 'maxlength' => 255));
  $form->addElement('text', 'password', 'Password:', array('size' => 50, 'maxlength' => 255));
  $form->addElement('submit', null, 'Create');

  $form->addRule('username', 'Please enter the Username', 'required', null, 'client');
  $form->addRule('password', 'Please enter the Password', 'required', null, 'client');

  if ($form->validate()) 
  {
	  $config = unserialize(file_get_contents('config.inc'));
	
	  $db = &DB::connect($config['dsn']);
	  if (DB::isError($db)) 
	  die($db->getMessage());

	  $query = "INSERT INTO users (user_id, username, password) VALUES(nextval('user_id_seq'),'";
	  $query .= $form->exportValue('username') . "','" . $form->exportValue('password') . "')";

	  $res =& $db->query($query);
	  if (DB::isError($res)) 
		die("username exist!");
	  $db->disconnect();
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
<script type="text/javascript">
<!--
  function reload_and_close()
  {
	opener.document.location.reload();
	window.close();
  }

// -->
</script>
</head>
<body onLoad="reload_and_close();">
</body>
</html>
<?php
	}
	else
	{
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
  <title>Add User</title>
</head>
<body onLoad="window.focus();">
<?php
  $form->display();
?>
<br>
<p>Copyright &copy; 2004 Entr'ouvert</p>
</body>
</html>
<?php
  }
?>
