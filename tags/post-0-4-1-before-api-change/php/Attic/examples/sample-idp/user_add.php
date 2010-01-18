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

  require_once 'HTML/QuickForm.php';
  require_once 'Log.php';  
  require_once 'DB.php';  
  require_once 'session.php';

   $config = unserialize(file_get_contents('config.inc'));

   // connect to the data base
   $db = &DB::connect($config['dsn']);
   if (DB::isError($db)) 
	die("Could not connect to the database");

   // session handler
   session_set_save_handler("open_session", "close_session", 
   "read_session", "write_session", "destroy_session", "gc_session");
	
  // create logger 
  $conf['db'] = $db;
  $logger = &Log::factory($config['log_handler'], 'log', $_SERVER['PHP_SELF'], $conf);

  $form = new HTML_QuickForm('frm');

  $form->addElement('header', null, 'Add New User');
  $form->addElement('text', 'username', 'Username:', array('size' => 50, 'maxlength' => 255));
  $form->addElement('text', 'password', 'Password:', array('size' => 50, 'maxlength' => 255));
  $form->addElement('submit', null, 'Create');

  $form->addRule('username', 'Please enter the Username', 'required', null, 'client');
  $form->addRule('password', 'Please enter the Password', 'required', null, 'client');

  if ($form->validate()) 
  {
	
	  $query = "INSERT INTO users (user_id, username, password, created) VALUES(nextval('user_id_seq'),";
	  $query .= $db->quoteSmart($form->exportValue('username')) . ",";
	  $query .= $db->quoteSmart($form->exportValue('password')) . ", NOW())";

	  $res =& $db->query($query);
	  if (DB::isError($res)) 
	  { 
		$logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_ERR);
		$logger->log("DB Error :" . $res->getDebugInfo(), PEAR_LOG_DEBUG);
		die("username exist!");
	  }
	  
    	  $logger->log("Create User '" . $form->exportValue('username') . "'", PEAR_LOG_NOTICE);
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
