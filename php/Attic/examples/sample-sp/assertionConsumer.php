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

  require_once 'Log.php';
  require_once 'DB.php';


  $config = unserialize(file_get_contents('config.inc'));

  if (!$_GET['SAMLart']) {
  	exit(1);
  }

  $db = &DB::connect($config['dsn']);

  if (DB::isError($db)) 
	  die($db->getMessage());

  // create logger 
  $conf['db'] = $db;
  $logger = &Log::factory($config['log_handler'], 'log', $_SERVER['PHP_SELF'], $conf);
 
  session_start();

  lasso_init();

  $server_dump = file_get_contents($config['server_dump_filename']);

  $server = LassoServer::newFromDump($server_dump);

  $login = new LassoLogin($server);

  $logger->log('Request from ' . $_SERVER['REMOTE_ADDR'], PEAR_LOG_INFO);
  $login->initRequest($_SERVER['QUERY_STRING'], lassoHttpMethodRedirect);
  $login->buildRequestMsg();

  $url = parse_url($login->msgUrl);

  $soap = sprintf(
	"POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: %d\r\nContent-Type: text/xml\r\n\r\n%s\r\n",
  $url['path'], $url['host'], $url['port'], strlen($login->msgBody), $login->msgBody);

  $logger->log('Send SOAP Request to '. $url['host'] . ":" .$url['port']. $url['path'], PEAR_LOG_INFO);
  $logger->log('SOAP Request : ' . $soap, PEAR_LOG_DEBUG);

  # PHP 4.3.0 with OpenSSL support required
  $fp = fsockopen("ssl://" . $url['host'], $url['port'], $errno, $errstr, 30) or die($errstr ($errno));
  socket_set_timeout($fp, 10);
  fwrite($fp, $soap);

  // header
  do $header .= fread($fp, 1); while (!preg_match('/\\r\\n\\r\\n$/',$header));

  // chunked encoding
  if (preg_match('/Transfer\\-Encoding:\\s+chunked\\r\\n/',$header))
  {
	do {
	  $byte = '';
	  $chunk_size = '';
	  
	  do {
		$chunk_size .= $byte;
		$byte = fread($fp, 1);
	  } while ($byte != "\\r");     
	  
	  fread($fp, 1);    
	  $chunk_size = hexdec($chunk_size); 
  	  $response .= fread($fp, $chunk_size);
	  fread($fp, 2);          
  	} while ($chunk_size);        
  }
  else
  {
	if (preg_match('/Content\\-Length:\\s+([0-9]+)\\r\\n/', $header, $matches))
	  $response = @fread($fp, $matches[1]);
	else 
	  while (!feof($fp)) $response .= fread($fp, 1024);
  }
  fclose($fp);

  $logger->log('SOAP Response Header : ' . $header, PEAR_LOG_DEBUG);
  $logger->log('SOAP Response Body : ' . $response, PEAR_LOG_DEBUG);

  if (!preg_match("/^HTTP\/1\\.. 200/i", $header)) {
        $logger->log("Wrong Artifact send by " . $_SERVER['REMOTE_ADDR'], PEAR_LOG_ERR);
	die("Wrong Artifact");
  }

  $login->processResponseMsg($response); 
 
  $query = "SELECT user_id FROM nameidentifiers WHERE name_identifier='" . $login->nameIdentifier . "'"; 
  $res =& $db->query($query);

  $logger->log("Name Identifier : " . $login->nameIdentifier,  PEAR_LOG_DEBUG);

  if (DB::isError($res)) 
  {
	$logger->log("DB Error :" . $db->getMessage(), PEAR_LOG_CRIT);
        $logger->log("DB Error :" . $db->getDebugInfo(), PEAR_LOG_DEBUG);
	die($db->getMessage());
  }

  if ($res->numRows() > 0)
  {
	// User already exist in the database
	$row =& $res->fetchRow();
	$user_id = $row[0];

	# Get Identity Dump from the data base
	$query = "SELECT identity_dump FROM users WHERE user_id='$user_id'";
	$res =& $db->query($query);

	if (DB::isError($db)) 
	{
		$logger->log("DB Error :" . $db->getMessage(), PEAR_LOG_CRIT);
		$logger->log("DB Error :" . $db->getDebugInfo(), PEAR_LOG_DEBUG);
		die($db->getMessage());
	}

	$row =& $res->fetchRow();

	$login->setIdentityFromDump($row[0]);

	$res->free();
  	
	$login->acceptSso();
	
	$session = $login->session; 
  
        $_SESSION['nameidentifier'] = $login->nameIdentifier;
        $_SESSION['session_dump'] = $session->dump();
        $_SESSION['user_id'] = $user_id;

	$url = "index.php";

        $logger->log("New session started for user '$user_id'", PEAR_LOG_INFO);
  }
  else 
  {
    // New User
	$login->acceptSso();

	$identity = $login->identity;
	$identity_dump = $identity->dump();

	$session = $login->session;

	// Insert into users 
	$query = "INSERT INTO users (user_id,identity_dump,created) VALUES(nextval('user_id_seq'),";
	$query .= $db->quoteSmart($identity_dump) . ", NOW())";

	$res =& $db->query($query);
	if (DB::isError($res)) 
	{
		$logger->log("DB Error :" . $db->getMessage(), PEAR_LOG_CRIT);
		$logger->log("DB Error :" . $db->getDebugInfo(), PEAR_LOG_DEBUG);
		die($db->getMessage());
	}


	// Get UserID
	$query = "SELECT last_value FROM user_id_seq";
	$res =& $db->query($query);
	if (DB::isError($res)) 
	{
		$logger->log("DB Error :" . $db->getMessage(), PEAR_LOG_CRIT);
		$logger->log("DB Error :" . $db->getDebugInfo(), PEAR_LOG_DEBUG);
		die($db->getMessage());
	}
	$row = $res->fetchRow();
	$user_id = $row[0];

        $logger->log("New user($user_id) created", PEAR_LOG_NOTICE);

	// Insert into nameidentifiers
	$query = "INSERT INTO nameidentifiers VALUES('".$login->nameIdentifier."', '$user_id')";
	$res =& $db->query($query);
	if (DB::isError($res)) 
	{
		$logger->log("DB Error :" . $db->getMessage(), PEAR_LOG_CRIT);
		$logger->log("DB Error :" . $db->getDebugInfo(), PEAR_LOG_DEBUG);
		die($db->getMessage());
	}

	
	$_SESSION['nameidentifier'] = $login->nameIdentifier;
        $_SESSION['session_dump'] = $session->dump();
        $_SESSION['user_id'] = $user_id;

        $logger->log("New session started for user '$user_id', redirect to the registration form", PEAR_LOG_INFO);

	$url = "register.php";
  }
  
  // Update last_login
  $query = "UPDATE users SET last_login=NOW() WHERE user_id='$user_id'";
  $res =& $db->query($query);
  if (DB::isError($res)) 
  {
  	$logger->log("DB Error :" . $db->getMessage(), PEAR_LOG_CRIT);
	$logger->log("DB Error :" . $db->getDebugInfo(), PEAR_LOG_DEBUG);
	die($db->getMessage());
  }
  $logger->log("Update last login for user '$user_id'", PEAR_LOG_INFO);

  header("Request-URI: $url");
  header("Content-Location: $url");
  header("Location: $url\n\n");
  $db->disconnect(); 
  lasso_shutdown();
  exit();
?>
