<?php
/*  
 * Service Provider Example -- AssertionConsumer
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
  

  if (!$_GET['SAMLart']) {
  	exit(1);
  }
  
  session_start();

  lasso_init();

  $server_dump = file_get_contents($config['server_dump_filename']);

  $server = LassoServer::newfromdump($server_dump);

  $login = new LassoLogin($server);

  $login->initRequest($_SERVER['QUERY_STRING'], lassoHttpMethodRedirect);
  $login->buildRequestMsg();

  $url = parse_url($login->msgUrl);

  $soap = sprintf(
	"POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: %d\r\nContent-Type: text/xml\r\n\r\n%s\r\n",
  $url['path'], $url['host'], $url['port'], strlen($login->msgBody), $login->msgBody);

  # PHP 4.3.0 with OpenSSL support required
  $fp = fsockopen("ssl://" . $url['host'], $url['port'], $errno, $errstr, 30) or die($errstr ($errno));
  fwrite($fp, $soap);
  $ret = fgets($fp);

  if (!preg_match("/^HTTP\/1\\.. 200/i", $ret)) {
	die("Wrong artifact");
  }

  while (!feof($fp)) {
  	$reponse .= @fread($fp, 8192);
  }

  fclose($fp);

  list($header, $body) = preg_split("/(\r\n\r\n|\n\n)/", $reponse, 2);

  $login->processResponseMsg($body); 

  $db = &DB::connect($config['dsn']);

  if (DB::isError($db)) 
	  die($db->getMessage());

  $query = "SELECT user_id FROM nameidentifiers WHERE name_identifier='" . $login->nameIdentifier . "'"; 
  $res =& $db->query($query);

  if (DB::isError($res)) 
	  die($res->getMessage());

  if ($res->numRows() > 0)
  {
	// User already exist in the database
	$row =& $res->fetchRow();
    $user_id = $row[0];

	# Get Identity Dump from the data base
	$query = "SELECT identity_dump FROM users WHERE user_id='$user_id'";
	$res =& $db->query($query);

	if (DB::isError($db)) 
	  die($db->getMessage());

	$row =& $res->fetchRow();

	$login->setIdentityFromDump($row[0]);

	$res->free();
  	
	$login->acceptSso();
	
	$session = $login->session; 
  
	$_SESSION["nameidentifier"] = $login->nameIdentifier;
	$_SESSION["session_dump"] = $session->dump();
	$_SESSION["user_id"] = $user_id;

	$url = "index.php?SID=". $SID;
  }
  else 
  {
    // New User
	$login->acceptSso();

	$identity = $login->identity;
	$identity_dump = $identity->dump();

	$session = $login->session;

	// Insert into users 
	$identity_dump_quoted = $db->quoteSmart($identity_dump);
	$query = "INSERT INTO users (user_id,identity_dump,created) VALUES(nextval('user_id_seq'), $identity_dump_quoted, NOW())";
	$res =& $db->query($query);
	if (DB::isError($res)) 
		print $res->getMessage(). "\n";

	// Get UserID
	$query = "SELECT last_value FROM user_id_seq";
	$res =& $db->query($query);
	if (DB::isError($res)) 
		print $res->getMessage(). "\n";
	$row = $res->fetchRow();
	$user_id = $row[0];

	// Insert into nameidentifiers
	$query = "INSERT INTO nameidentifiers VALUES('".$login->nameIdentifier."', '$user_id')";
	$res =& $db->query($query);
	if (DB::isError($res)) 
		print $res->getMessage(). "\n";
	

	$_SESSION["nameidentifier"] = $login->nameIdentifier;
	$_SESSION["session_dump"] = $session->dump();
	$_SESSION["user_id"] = $user_id;

	$url = "register.php?SID=". $SID;
  }
  
  // Update last_login
  $query = "UPDATE users SET last_login=NOW() WHERE user_id='$user_id'";
  $res =& $db->query($query);
  if (DB::isError($res)) 
	print $res->getMessage(). "\n";

  $db->disconnect();
	
  lasso_shutdown();

  header("Request-URI: $url");
  header("Content-Location: $url");
  header("Location: $url");
  exit();
?>
