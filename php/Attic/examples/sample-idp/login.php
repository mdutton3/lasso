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

  require_once 'HTML/QuickForm.php';
  require_once 'Log.php';
  require_once 'DB.php';
  require_once 'session.php';

  $config = unserialize(file_get_contents('config.inc'));
   
   // connect to the data base
   $db = &DB::connect($config['dsn']);
   if (DB::isError($db)) 
	die("Could not connect to the database");

  // create logger 
  $conf['db'] = $db;
  $logger = &Log::factory($config['log_handler'], 'log', $_SERVER['PHP_SELF'], $conf);

  // session handler
  session_set_save_handler("open_session", "close_session", 
  "read_session", "write_session", "destroy_session", "gc_session");

  session_start();

  /*
   * 
   */
  function sendHTTPBasicAuth()
  {
    global $logger;
    
    header('WWW-Authenticate: Basic realm="Lasso Identity Provider One"');
    header('HTTP/1.0 401 Unauthorized');
    echo "Acces Denied";
    $logger->log("User from '" . $_SERVER['REMOTE_ADDR'] . "' pressed the cancel button during HTTP basic authentication request", PEAR_LOG_NOTICE);
  }


  /*
   * This function authentificate the user against the Users Database
   */
  function authentificateUser($db, $username, $password)
  {
    global $logger;

	$query = "SELECT user_id FROM users WHERE username=".$db->quoteSmart($username);
	$query .= " AND password=".$db->quoteSmart($password);

	$res =& $db->query($query);
	if (DB::isError($res)) 
    {
        $logger->log("DB Error :" . $db->getMessage(), PEAR_LOG_CRIT);
        $logger->log("DB Error :" . $db->getDebugInfo(), PEAR_LOG_DEBUG);
        die("Internal Server Error");
    } 

  	if ($res->numRows()) 
	{
	  $row = $res->fetchRow();
	  return ($row[0]);
	}
	return (0);
  }

  if ($config['auth_type'] == 'auth_basic')
  {
    if (!isset($_SERVER['PHP_AUTH_USER']))
    {
        sendHTTPBasicAuth();
        exit;
    }
    else
    {
        // Check Login and Password
        if (!($user_id = authentificateUser($db, $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])))
        {
            $logger->log("Authentication failure with login '".$form->exportValue('username')." password '". $form->exportValue('password') ."' IP " . $_SERVER['REMOTE_ADDR'], PEAR_LOG_WARNING);
            sendHTTPBasicAuth();
            exit;
        }
        else
        {
		$_SESSION['user_id'] = $user_id;
		$_SESSION['username'] = $_SERVER['PHP_AUTH_USER'];
	    
		$logger->log("User '".$_SERVER['PHP_AUTH_USER']."' ($user_id) authenticated, local session started", PEAR_LOG_NOTICE);


            /* TODO : load identity and session dump 
            $query = "SELECT identity_dump,session_dump FROM users WHERE identity_dump";
            $query .= " IS NOT NULL AND session_dump IS NOT NULL AND user_id='$user_id'";

            $res =& $db->query($query);

            if (DB::isError($res)) 
                die($res->getMessage());

            if ($res->numRows()) 
            {
                $row = $res->fetchRow();
    
                $_SESSION['identity_dump'] = $row[0];
                $_SESSION['session_dump'] = $row[1];
            } */
            
            $url = 'index.php';
            header("Request-URI: $url");
            header("Content-Location: $url");
            header("Location: $url\r\n\r\n");
            exit;
        }
    }
  }
  else if ($config['auth_type'] == 'auth_form')
  {
  
  $form = new HTML_QuickForm('frm');

  $form->addElement('header', null, 'Login on the Lasso Identity Provider Example');
  
  $form->addElement('text', 'username', 'Username:', array('size' => 50, 'maxlength' => 255));
  $form->addElement('password', 'password', 'Password:', array('size' => 50, 'maxlength' => 255));
  $form->addElement('submit', null, 'Ok');

  $form->addRule('username', 'Please enter the Username', 'required', null, 'client');
  $form->addRule('password', 'Please enter the Password', 'required', null, 'client');

  if ($form->validate())
  {
      if (($user_id = authentificateUser($db, $form->exportValue('username'), $form->exportValue('password'))))
      {
		$_SESSION['user_id'] = $user_id;
		$_SESSION['username'] = $form->exportValue('username');

		$logger->log("User '".$form->exportValue('username')."'($user_id) authenticated, local session started", PEAR_LOG_NOTICE);

		$url = 'index.php';
		header("Request-URI: $url");
		header("Content-Location: $url");
		header("Location: $url\r\n\r\n");
        exit;
	  }
      else
        $logger->log("Authentication failure with login '".$form->exportValue('username')." password '". $form->exportValue('password') ."' IP '" . $_SERVER['REMOTE_ADDR']."'", PEAR_LOG_WARNING);
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
<?php
    }
    else
    {
        $logger->log("Unknown authentification type '". $config['auth_type'] ."', check IdP setup", PEAR_LOG_ALERT);
        die('Unknown authentification type'); 
    }
?>
