<?php
/*  
 * Identity Provider Example -- Local Login
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

  require_once 'HTML/QuickForm.php';
  require_once 'DB.php';

  
  $form = new HTML_QuickForm('frm');

  $form->addElement('header', null, 'Login on the Lasso Identity Provider Example');
  
  $form->addElement('text', 'username', 'Username:', array('size' => 50, 'maxlength' => 255));
  $form->addElement('password', 'password', 'Password:', array('size' => 50, 'maxlength' => 255));
  $form->addElement('submit', null, 'Ok');

  $form->addRule('username', 'Please enter the Username', 'required', null, 'client');
  $form->addRule('password', 'Please enter the Password', 'required', null, 'client');

  if ($form->validate())
  {
  	$config = unserialize(file_get_contents('config.inc'));
	
   	$db = &DB::connect($config['dsn']);

	if (DB::isError($db)) 
	  die($db->getMessage());

	  $query = "SELECT user_id FROM users WHERE username=" . $db->quoteSmart($form->exportValue('username'));
	  $query .= " AND password=" . $db->quoteSmart($form->exportValue('password'));;

	  $res =& $db->query($query);
	  if (DB::isError($res)) 
		die($res->getMessage());

	  $db->disconnect();
	
	  if ($res->numRows()) 
	  {
		$row = $res->fetchRow();
		session_start();
		$_SESSION['user_id'] = $row[0];
		$_SESSION['username'] = $form->exportValue('username');

		$url = 'index.php';
		header("Request-URI: $url");
		header("Content-Location: $url");
		header("Location: $url");
		exit;
	  }
  }
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<body>
<?php
  $form->display();
?>
</body>
</html>
