<?php
/*  
 * Identity Provider Example -- Single Sing On
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
  
    lasso_init();

    // Create Lasso Server
    $server_dump = file_get_contents($config['server_dump_filename']);
    $server = LassoServer::newFromDump($server_dump);

    // HTTP Basic Authentification
    if ($config['auth_type'] == 'auth_basic')
    {
        if (!isset($_SERVER['PHP_AUTH_USER']))
        {
            sendHTTPBasicAuth();
            exit;
        }
        else
        {
		$login = new LassoLogin($server);

		// init login
		updateDumpsFromSession($login);
		initFromAuthnRequest($login);


		// User must *NOT* Authenticate with the IdP 
		if (!$login->mustAuthenticate()) 
		{
			$user_id = authentificateUser($db, $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']);
			if (!$user_id) 
			{
				$logger->log("User must not authenticate, username and password are not available", PEAR_LOG_CRIT);
				die("Unknown User");
			}
                    
			$array = getIdentityDumpAndSessionDumpFromUserID($db, $user_id);
			if (empty($array))
			{
				$logger->log("User must no authenticate, but I don't find session and identity 
				dump in the database", PEAR_LOG_CRIT);
				die("Could not get Identity and Session Dump");
			}

			$login->setIdentityFromDump($array['identity_dump']);
			if (!empty($array['session_dump']))
			{
				$logger->log("Update Session from dump for User '$user_id'", PEAR_LOG_CRIT);
				$login->setSessionFromDump($array['session_dump']);
			}
	  
			doneSingleSignOn($db, $login, $user_id);
			exit;
		}

            // Check Login and Password
            if (!($user_id = authentificateUser($db, $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])))
            {
                sendHTTPBasicAuth();
                exit;
            }
            else
            {
                $array = getIdentityDumpAndSessionDumpFromUserID($db, $user_id);
                $is_first_sso = (isset($array['identity_dump']) ? FALSE : TRUE);

                if (!$is_first_sso)
		{
			$login->setIdentityFromDump($array['identity_dump']); 
			$logger->log("Update Identity dump for user '$user_id' :" . $array['identity_dump'], PEAR_LOG_DEBUG);
		}

		if (!empty($array['session_dump']))
		{
			$login->setSessionFromDump($array['session_dump']);
			$logger->log("Update Session dump for user '$user_id' :" . $array['session_dump'], PEAR_LOG_DEBUG);
		}

                doneSingleSignOn($db, $login, $user_id, $is_first_sso);
            }
        }
        exit;
  }

  // HTML Form Authentification
  
  // Create the form
  $form = new HTML_QuickForm('frm');
  
  $form->addElement('header', null, 'Single Sing On Login');
  
  $form->addElement('text', 'username', 'Username:', array('size' => 50, 'maxlength' => 255));
  $form->addElement('password', 'password', 'Password:', array('size' => 50, 'maxlength' => 255));
  $form->addElement('submit', null, 'Ok');

  $form->addRule('username', 'Please enter the Username', 'required', null, 'client');
  $form->addRule('password', 'Please enter the Password', 'required', null, 'client');

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
   * Update Identity dump
   */
   function updateIdentityDump($db, $user_id, $identity_dump)
   {
        global $logger;
       
       	$query = "UPDATE users SET identity_dump=".$db->quoteSmart($identity_dump);
	$query .= " WHERE user_id='$user_id'";

	$res =& $db->query($query);
	if (DB::isError($res)) 
        {
            $logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
            $logger->log("DB Error :" . $db->getDebugInfo(), PEAR_LOG_DEBUG);
            die("Internal Server Error");
        }
        $logger->log("Update user '$user_id' identity dump in the database : $identity_dump", PEAR_LOG_DEBUG);
   }

   /*
   * Update Session dump
   */
   function updateSessionDump($db, $user_id, $session_dump)
   {
        global $logger;

	$query = "UPDATE users SET session_dump=".$db->quoteSmart($session_dump);
	$query .= " WHERE user_id='$user_id'";

	$res =& $db->query($query);
        if (DB::isError($res)) 
        {
            $logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
            $logger->log("DB Error :" . $res->getDebugInfo(), PEAR_LOG_DEBUG);
            die("Internal Server Error");
        }
        $logger->log("Update user '$user_id' Session dump in the database : $session_dump", PEAR_LOG_DEBUG);
   }

   /*
    * Save the Assertion Artifact in the database
    */
   function saveAssertionArtifact($db, $artifact, $assertion)
   {
	global $logger;
	/* 
	var_dump($assertion);
	if ($assertion->_cPtr == NULL)
		print "null"; */
	$assertion_dump = $assertion->dump();

	if (empty($assertion_dump))
	{
		$logger->log("assertion dump is empty", PEAR_LOG_ALERT);
		die("assertion dump is empty");
	}

	// Save assertion 
      	$query = "INSERT INTO assertions (assertion, response_dump, created) VALUES ";
	$query .= "('".$artifact."',".$db->quoteSmart($assertion_dump).", NOW())";

	$res =& $db->query($query);
	if (DB::isError($res)) 
	{
		$logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
		$logger->log("DB Error :" . $db->getDebugInfo(), PEAR_LOG_DEBUG);
		die("Internal Server Error");
	}
   }

  /*
   * Update Session and Identity Dump from PHP Session variables
   */
  function updateDumpsFromSession(&$login)
  {
	global $logger;

	// Get session and identity dump if there are available
	if (!empty($_SESSION['session_dump']))
	{
	  $login->setSessionFromDump($_SESSION['session_dump']);
          $logger->log("Update user's session dump", PEAR_LOG_DEBUG);
	}

	if (!empty($_SESSION['identity_dump']))
	{
	  $login->setIdentityFromDump($_SESSION['identity_dump']);
          $logger->log("Update user's identity dump", PEAR_LOG_DEBUG);
	}
  }

  /*
   * Init Lasso login from AuthnRequestMsg
   */
  function initFromAuthnRequest(&$login)
  {
	global $logger;

	switch ($_SERVER['REQUEST_METHOD'])
	{
	  case 'GET':
		$login->initFromAuthnRequestMsg($_SERVER['QUERY_STRING'], lassoHttpMethodRedirect);
		$logger->log("initFromAuthnRequest with method GET : " . $_SERVER['QUERY_STRING'], PEAR_LOG_DEBUG);
		break;
	  case 'POST':
		if (empty($_POST['LAREQ']))
		{
			$logger->log("POST LARQ value is empty");
			die("POST LARQ value is empty");
		}
                $login->initFromAuthnRequestMsg($_POST['LAREQ'], lassoHttpMethodPost);
		$logger->log("initFromAuthnRequest with method POST", PEAR_LOG_DEBUG);
		break;
	  default:
		$logger->log("initFromAuthnRequest with called an unknown method", PEAR_LOG_CRIT);
		die("Unknown request method"); 
	}
  }
  
  /*
   * This function authentificate the user against the Postgres Database
   */
  function authentificateUser($db, $username, $password)
  {
	global $logger;
	
	$query = "SELECT user_id FROM users WHERE username=".$db->quoteSmart($username);
	$query .= " AND password=".$db->quoteSmart($password);

	$res =& $db->query($query);
	if (DB::isError($res)) 
	{
	  $logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
          $logger->log("DB Error :" . $res->getDebugInfo(), PEAR_LOG_DEBUG);
	  die($res->getMessage());
	}

  	if ($res->numRows()) 
	{
	  $row = $res->fetchRow();
	  return ($row[0]);
	}
	return (0);
  }

  /*
   * Get UserID from the NameIdentifier
   * return user_id or 0 if not found
   */
  function getUserIDFromNameIdentifier($db, $nameidentifier)
  {
	$query = "SELECT user_id FROM nameidentifiers WHERE name_identifier='$nameidentifier'";
	  
	$res =& $db->query($query);
       	if (DB::isError($res)) 
	{
		$logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
	      	$logger->log("DB Error :" . $res->getDebugInfo(), PEAR_LOG_DEBUG);
		die($res->getMessage());
	}
		
	// UserID not found
	if (!$res->numRows()) 
		return (0);
	  
	$row = $res->fetchRow();
	return ($row[0]);
  }

  /*
   * 
   */
   function getIdentityDumpAndSessionDumpFromUserID($db, $user_id)
   {
	$query = "SELECT identity_dump,session_dump FROM users WHERE user_id='$user_id'";

	$res =& $db->query($query);
	if (DB::isError($res)) 
		die($res->getMessage());

      	if ($res->numRows()) 
	{
		$row =& $res->fetchRow();
		$ret = array("identity_dump" => $row[0], "session_dump" => $row[1]);
		return ($ret);
	} 
   }


  /*
   * 
   */
  function doneSingleSignOn($db, &$login, $user_id)
  {
	global $logger;

      	$authenticationMethod = 
	  (($_SERVER["HTTPS"] == 'on') ? lassoSamlAuthenticationMethodSecureRemotePassword : lassoSamlAuthenticationMethodPassword);

	  // reauth in session_cache_expire, default is 180 minutes
	  $reauthenticateOnOrAfter = strftime("%Y-%m-%dT%H:%M:%SZ", time() + session_cache_expire() * 60);

	  if ($login->protocolProfile == lassoLoginProtocolProfileBrwsArt)
		  $login->buildArtifactMsg(TRUE, // User is authenticated 
			$authenticationMethod, $reauthenticateOnOrAfter, lassoHttpMethodRedirect); 
	  else if ($login->protocolProfile == lassoLoginProtocolProfileBrwsPost)
		  die("TODO : Post\n"); // TODO
	  else
	  {
		$logger->log("Unknown protocol profile", PEAR_LOG_CRIT);
		die("Unknown protocol profile\n"); 
	  }

	  $query = "SELECT * FROM nameidentifiers WHERE name_identifier='";
	  $query .= $login->nameIdentifier."' AND user_id='$user_id'";

	  $res =& $db->query($query);
	  if (DB::isError($res)) 
	  {
      		$logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
    		$logger->log("DB Error :" . $res->getDebugInfo(), PEAR_LOG_DEBUG);
      		die($res->getMessage());
	  }  

	  if (!$res->numRows()) 
	  {
		// register new name_identifier 
		$query = "INSERT INTO nameidentifiers (name_identifier, user_id) ";
		$query .= "VALUES ('" . $login->nameIdentifier . "','$user_id')";
	  
		$res =& $db->query($query);
		if (DB::isError($res)) 
		{
			$logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
			$logger->log("DB Error :" . $res->getDebugInfo(), PEAR_LOG_DEBUG);
			die($res->getMessage());
		}  
    		$logger->log("Register Name Identifier '" . $login->nameIdentifier ."' for User '$user_id'", PEAR_LOG_INFO);
	  }

	  $identity = $login->identity;
	  // do we need to update identity dump?
	  if ($login->isIdentityDirty)
		updateIdentityDump($db, $user_id, $identity->dump());

	  $session = $login->session;
	  // do we need to update session dump?
	  if ($login->isSessionDirty)
		updateSessionDump($db, $user_id, $session->dump());

	  if (empty($login->assertionArtifact))
	  {
    		$logger->log("Assertion Artifact is empty", PEAR_LOG_CRIT);
		die("assertion Artifact is empty");
	  }

    	  $logger->log("Assertion Artifact is '" . $login->assertionArtifact . "'", PEAR_LOG_DEBUG);

	  saveAssertionArtifact($db, $login->assertionArtifact, $login->assertion);


	  // Save PHP Session ID in the sso_session table
	  $query = "INSERT INTO sso_sessions(name_identifier, session_id, ip)";
	  $query .= " VALUES('" . $login->nameIdentifier . "','" . session_id() . "','";
	  $query .= ip2long($_SERVER['REMOTE_ADDR']) . "')";

	  $res =& $db->query($query);
	  if (DB::isError($res)) 
	  {
		$logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
	    	$logger->log("DB Error :" . $res->getDebugInfo(), PEAR_LOG_DEBUG);
	      	die($res->getMessage());
	  }

	  unset($_SESSION['login_dump']); // delete login_dump 
	  $_SESSION['identity_dump'] = $identity->dump();
	  $_SESSION['session_dump'] = $session->dump();

          $logger->log("New Single Sign On Session started for user '$user_id'", PEAR_LOG_INFO);

	  switch($login->protocolProfile)
	  {
		case lassoLoginProtocolProfileBrwsArt:
		  	$url = $login->msgUrl;

			header("Request-URI: $url");
			header("Content-Location: $url");
			header("Location: $url\n\n");
			lasso_shutdown();
			exit;
		case lassoLoginProtocolProfileBrwsPost:
		  // TODO : lassoLoginProtocolProfileBrwsPost
		default:
			$logger->log("Unknown Login Protocol Profile :" . $login->protocolProfile, PEAR_LOG_CRIT);
			die("Unknown Login Protocol Profile");
	  }
  }

  // validate login
  if ($form->validate())
  {
	if (empty($_SESSION['login_dump']))
	{
		$logger->log("Login dump is not registred in the session", PEAR_LOG_ERR);
		die("Login dump is not registred");
	}

	$login = LassoLogin::newFromDump($server, $_SESSION['login_dump']);

	if (($user_id = authentificateUser($db, $form->exportValue('username'), 
	  $form->exportValue('password')))) 
	{
		$array = getIdentityDumpAndSessionDumpFromUserID($db, $user_id);
		$is_first_sso = (isset($array['identity_dump']) ? FALSE : TRUE);
	
		if (!empty($array['identity_dump']))
		{
			$logger->log("Update Identity dump for user '$user_id' from the database", PEAR_LOG_INFO);
			$login->setIdentityFromDump($array['identity_dump']);
		}

		if (!empty($array['identity_dump']))
		{
			$logger->log("Update Identity dump for user '$user_id' from the database", PEAR_LOG_INFO);
			$login->setIdentityFromDump($array['identity_dump']);
		}

			
		if (!empty($array['session_dump']))
		{
			$logger->log("Update Session dump for user '$user_id' from the database", PEAR_LOG_INFO);
			$login->setSessionFromDump($array['session_dump']);
		}

		doneSingleSignOn($db, $login, $user_id);
		exit;
	}
	else
		$logger->log("Authentication failure with login '". $form->exportValue('username')." 
		password '". $form->exportValue('password') ."' IP '" . $_SERVER['REMOTE_ADDR']."'", PEAR_LOG_WARNING);
  }
  else
  {
  	$login = new LassoLogin($server);

	// init login
	updateDumpsFromSession($login);
	initFromAuthnRequest($login);
	
	// User must NOT Authenticate with the IdP 
	if (!$login->mustAuthenticate()) 
	{
		$user_id = getUserIDFromNameIdentifier($db, $login->nameIdentifier);
	  
		if (!$user_id) 
		{
			$logger->log("Could not get UserID from Name Identifier '" . $login->nameIdentifier . "'", PEAR_LOG_ERR);
			die("Internal Server Error");
		}
		doneSingleSignOn($db, $login, $user_id);
		exit;
	}
	else
	{
		// register login dump in this session, 
		// we can not transfert xml dump with hidden input 
		$_SESSION['login_dump'] = $login->dump();
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
