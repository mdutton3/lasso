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
  require_once 'DB.php';
 
  $config = unserialize(file_get_contents('config.inc'));

  session_start();
  
  lasso_init();

  // Create Lasso Server
  $server_dump = file_get_contents($config['server_dump_filename']);
  $server = LassoServer::newFromDump($server_dump);

  // Create the form
  $form = new HTML_QuickForm('frm');
  
  $form->addElement('header', null, 'Single Sing On Login');
  
  $form->addElement('text', 'username', 'Username:', array('size' => 50, 'maxlength' => 255));
  $form->addElement('password', 'password', 'Password:', array('size' => 50, 'maxlength' => 255));
  $form->addElement('submit', null, 'Ok');

  $form->addRule('username', 'Please enter the Username', 'required', null, 'client');
  $form->addRule('password', 'Please enter the Password', 'required', null, 'client');

  /*
   * This function authentificate the user against the Postgres Database
   */
  function authentificateUser($db, $username, $password)
  {
	$query = "SELECT user_id FROM users WHERE username=".$db->quoteSmart($username);
	$query .= " AND password=".$db->quoteSmart($password);

	$res =& $db->query($query);
	if (DB::isError($res)) 
	  die($res->getMessage());

  	if ($res->numRows()) 
	{
	  $row = $res->fetchRow();
	  return ($row[0]);
	}
	return (0);
  }

  /*
   * 
   */
  function doneSingleSignOn($db, $login, $user_id, $is_first_sso)
  {
	  $authenticationMethod = 
	  (($_SERVER["HTTPS"] == 'on') ? lassoSamlAuthenticationMethodSecureRemotePassword : lassoSamlAuthenticationMethodPassword);

	  // reauth in session_cache_expire, default is 180 minutes
	  $reauthenticateOnOrAfter = strftime("%Y-%m-%dT%H:%M:%SZ", time() + session_cache_expire() * 60);

	  /* FIXME : there is a segfault when I use a switch statement 
	  switch($login->protocolProfile)
	  {
		case lassoLoginProtocolProfileBrwsArt:
		  $login->buildArtifactMsg(TRUE, // User is authenticated 
			$authenticationMethod, $reauthenticateOnOrAfter, lassoHttpMethodRedirect); 
			break;
		case lassoLoginProtocolProfileBrwsPost:
		  die("TODO : Post\n"); 
		default:
		  die("Unknown protocol profile\n"); 
	  } */
	  
	  if ($login->protocolProfile == lassoLoginProtocolProfileBrwsArt)
		  $login->buildArtifactMsg(TRUE, // User is authenticated 
			$authenticationMethod, $reauthenticateOnOrAfter, lassoHttpMethodRedirect); 
	  else if ($login->protocolProfile == lassoLoginProtocolProfileBrwsPost)
		  die("TODO : Post\n"); // TODO
	  else
		  die("Unknown protocol profile\n"); 

	  if ($is_first_sso)
	  {
		// name_identifier
		$query = "INSERT INTO nameidentifiers (name_identifier, user_id) ";
	  	$query .= "VALUES ('" . $login->nameIdentifier . "','$user_id')";

		$res =& $db->query($query);
		if (DB::isError($res)) 
		  die($res->getMessage());
	  }

	  $identity = $login->identity;
	  // do we need to update identity dump?
	  if ($login->isIdentityDirty)
	  {
		$query = "UPDATE users SET identity_dump=".$db->quoteSmart($identity->dump());
		$query .= " WHERE user_id='$user_id'";

		$res =& $db->query($query);
		if (DB::isError($res)) 
		  die($res->getMessage());
	  }

	  $session = $login->session;
	  // do we need to update session dump?
	  if ($login->isSessionDirty)
	  {
		$query = "UPDATE users SET session_dump=".$db->quoteSmart($identity->dump());
		$query .= " WHERE user_id='$user_id'";

		$res =& $db->query($query);
		if (DB::isError($res)) 
		  die($res->getMessage());
	  }

	  if (empty($login->assertionArtifact))
		die("assertion Artifact is empty");

	  $assertion = $login->assertion;
	  $assertion_dump = $assertion->dump();

	  if (empty($assertion_dump))
		die("assertion dump is empty");
		
	  // Save assertion 
	  $query = 	"INSERT INTO assertions (assertion, response_dump, created) VALUES ";
	  $query .= "('".$login->assertionArtifact."',".$db->quoteSmart($assertion_dump).", NOW())";

	  $res =& $db->query($query);
  	  if (DB::isError($res)) 
		die($res->getMessage());

	  $_SESSION['login_dump'] = ''; // delete login_dump 
	  $_SESSION['identity_dump'] = $session->dump();
	  $_SESSION['session_dump'] = $session->dump();

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
		  die("TODO : lassoLoginProtocolProfileBrwsPost");
		  break;
		default:
		  die("Unknown Login Protocol Profile");
	  }
  }

  // validate login
  if ($form->validate())
  {
	if (empty($_SESSION['login_dump']))
	  die("Login dump is not registred");

	// conect to the data base
	$db = &DB::connect($config['dsn']);
	if (DB::isError($db)) 
	  die($db->getMessage());

	$login = LassoLogin::newfromdump($server, $_SESSION['login_dump']);

	if (($user_id = authentificateUser($db, $form->exportValue('username'), 
	  $form->exportValue('password')))) 
	{
	  // User is authentificated
	  $query = "SELECT identity_dump,session_dump FROM users WHERE identity_dump";
	  $query .= " IS NOT NULL AND session_dump IS NOT NULL AND user_id='$user_id'";

	  $res =& $db->query($query);
	  if (DB::isError($res)) 
		die($res->getMessage());

	  $is_first_sso = FALSE;
	  if ($res->numRows()) 
	  {
		$row =& $res->fetchRow();
		$login->setIdentityFromDump($row[0]);
		$login->setSessionFromDump($row[1]);
	  } 
	  else
		$is_first_sso = TRUE;

	  doneSingleSignOn($db, $login, $user_id, $is_first_sso);
	  $db->disconnect();
	  exit;
	}
  }
  else
  {
  	$login = new LassoLogin($server);

	// Get session and identity dump if there are available
	if (!empty($_SESSION['session_dump']))
	  $login->setSessionFromDump($_SESSION['session_dump']);

	if (!empty($_SESSION['identity_dump']))
	  $login->setIdentityFromDump($_SESSION['identity_dump']);
	
	switch ($_SERVER['REQUEST_METHOD'])
	{
	  case 'GET':
		$login->initFromAuthnRequestMsg($_SERVER['QUERY_STRING'], lassoHttpMethodRedirect);
		break;
	  case 'POST':
		die("methode POST not implemented"); // TODO
		break;
	  default:
		die("Unknown request method"); 
	}
	
	// User must NOT Authenticate with the IdP 
	if (!$login->mustAuthenticate()) 
	{
	  // conect to the data base
	  $db = &DB::connect($config['dsn']);
	  if (DB::isError($db)) 
		die($db->getMessage());

	  $query = "SELECT user_id FROM nameidentifiers WHERE name_identifier='";
	  $query .= $login->nameIdentifier . "'";
	  
	  $res =& $db->query($query);
	  if (DB::isError($res)) 
  		die($res->getMessage());
		
	  if (!$res->numRows()) 
		die("Unknown User");
	  
	  $row = $res->fetchRow();
	  $user_id = $row[0];

	  doneSingleSignOn($db, $user_id);
	  $db->disconnect();
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
