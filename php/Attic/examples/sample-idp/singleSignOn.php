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

  // Create the form
  $form = new HTML_QuickForm('frm');
  
  $form->addElement('header', null, 'Single Sing On Login');
  
  $form->addElement('text', 'username', 'Username:', array('size' => 50, 'maxlength' => 255));
  $form->addElement('password', 'password', 'Password:', array('size' => 50, 'maxlength' => 255));
  $form->addElement('submit', null, 'Ok');

  $form->addRule('username', 'Please enter the Username', 'required', null, 'client');
  $form->addRule('password', 'Please enter the Password', 'required', null, 'client');

  function singleSignOn_done($config, $db, $user_id = 0) 
  {
	  $server_dump = file_get_contents($config['server_dump_filename']);
	  
	  lasso_init();
	  
	  $server = LassoServer::newFromDump($server_dump);
	  $login = LassoLogin::newFromDump($server, $_SESSION['login_dump']);

	  $authenticationMethod = 
	  (($_SERVER["HTTPS"] == 'on') ? lassoSamlAuthenticationMethodSecureRemotePassword : lassoSamlAuthenticationMethodPassword);

	  // reauth in session_cache_expire default is 180 minutes
	  $reauthenticateOnOrAfter = strftime("%Y-%m-%dT%H:%M:%SZ", time() + session_cache_expire() * 60);
	  
      if ($login->protocolProfile == lassoLoginProtocolProfileBrwsArt)
	  {
		$login->buildArtifactMsg(
		  TRUE, // User is authenticated 
		  $authenticationMethod,
		  $reauthenticateOnOrAfter,
		  lassoHttpMethodRedirect);
	  }
	  else if ($login->protocolProfile == lassoLoginProtocolProfileBrwsPost)
	  {
		// TODO
		print "TODO : Post\n";
		exit();
	  }
	  else
		die("Unknown protocol profile for login:" . $login->protocolProfile);
	
	  if (empty($user_id))
	  {
		// Get user_id
		$query = "SELECT user_id FROM nameidentifiers WHERE name_identifier='";
		$query .= $login->nameIdentifier . "'";

		$res =& $db->query($query);
		if (DB::isError($res)) 
		  die($res->getMessage());

		$row = $res->fetchRow();
		$user_id = $row[0];
	  } 
	  else
	  {
		$query = "INSERT INTO nameidentifiers (name_identifier, user_id) ";
	  	$query .= "VALUES ('" . $login->nameIdentifier . "','$user_id')";
  		$res =& $db->query($query);
		if (DB::isError($res)) 
		die($res->getMessage());
		$name_identifier = $login->nameIdentifier;
	  }

	  if ($login->isIdentityDirty)
	  {
		$identity = $login->identity;
		$query = "UPDATE users SET user_dump=".$db->quoteSmart($identity->dump());
		$query .= " WHERE user_id='$user_id'";

		$res =& $db->query($query);
		if (DB::isError($res)) 
		  die($res->getMessage());
	  } 

	  // Update identity dump
	  $identity = $login->identity;
	  $query = "UPDATE users SET user_dump=".$db->quoteSmart($identity->dump())." WHERE user_id='$user_id'";
	  
	  $res =& $db->query($query);
  	  if (DB::isError($res)) 
		die($res->getMessage());
	 
	  // Update session dump
	  $session = $login->session;
	  $query = "UPDATE users SET session_dump=".$db->quoteSmart($session->dump())." WHERE user_id='$user_id'";

	  $res =& $db->query($query);
  	  if (DB::isError($res)) 
		die($res->getMessage());

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

	  $_SESSION['login_dump'] = $login->dump();
	  $_SESSION['session_dump'] = $session->dump();

	  if ($login->protocolProfile == lassoLoginProtocolProfileBrwsArt)
	  {
		$url = $login->msgUrl;

		header("Request-URI: $url");
		header("Content-Location: $url");
		header("Location: $url");
	  }
	  else if ($login->protocolProfile == lassoLoginProtocolProfileBrwsPost)
	  {
	  }

	  lasso_shutdown();
  }

  if (!$form->validate())
  {
	// Check for AuthnRequest
	if (empty($_POST) && empty($_GET))
	{
	  die("Unknow login methode!");
	}

	lasso_init();
  
	$server_dump = file_get_contents($config['server_dump_filename']);

	$server = LassoServer::newfromdump($server_dump);

	if (!empty($_SESSION['login_dump']))
	  $login = LassoLogin::newFromDump($server, $_SESSION['login_dump']);
	else
	  $login = new LassoLogin($server);

	if (!empty($_SESSION['session_dump']))
	  $login->setSessionFromDump($_SESSION['session_dump']);
	
	if ($_SERVER['REQUEST_METHOD'] = 'GET')
	  $login->initFromAuthnRequestMsg($_SERVER['QUERY_STRING'], lassoHttpMethodRedirect);
	else
	{
	  // TODO
	  exit;
	}

	// User must NOT Authenticate with the IdP 
	if (!$login->mustAuthenticate()) 
	{
	  $db = &DB::connect($config['dsn']);
	  if (DB::isError($db)) 
		die($db->getMessage());

	  singleSignOn_done($config, $db);
	  $db->disconnect();
	  exit;
	}

	$login_dump = $login->dump();
	$session = $login->session;
	$_SESSION['login_dump'] = $login->dump();
	$_SESSION['session_dump'] = $session->dump();

	lasso_shutdown();
  }
  
 
  if (isset($_SESSION['login_dump']) && $form->validate())
  {
	$db = &DB::connect($config['dsn']);

	if (DB::isError($db)) 
	  die($db->getMessage());

	$query = "SELECT user_id FROM users WHERE username=" . $db->quoteSmart($form->exportValue('username'));
	$query .= " AND password=" . $db->quoteSmart($form->exportValue('password'));;

	$res =& $db->query($query);
	if (DB::isError($res)) 
	  die($res->getMessage());

	if ($res->numRows()) 
	{
	  $row = $res->fetchRow();
	  $user_id = $row[0];
	  singleSignOn_done($config, $db, $user_id);
	  $db->disconnect();
	  exit();
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
