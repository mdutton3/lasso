<?php
/*  
 * Identity Provider Example -- SOAP Endpoint
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
  require_once 'session.php';

  $config = unserialize(file_get_contents('config.inc'));
   
  $server_dump = file_get_contents($config['server_dump_filename']);

  header("Content-Type: text/xml\r\n");
  
  // connect to the data base
  $db = &DB::connect($config['dsn']);
  if (DB::isError($db)) 
  {
    header("HTTP/1.0 500 Internal Server Error");
    exit;
  }

  // create logger 
  $conf['db'] = $db;
  $logger = &Log::factory($config['log_handler'], 'log', $_SERVER['PHP_SELF'], $conf);

  // shutdown function
  function close_logger()
  {
	global $logger;
	$logger->close();
  }
  register_shutdown_function("close_logger");

  // session handler
  session_set_save_handler("open_session", "close_session", 
   "read_session", "write_session", "destroy_session", "gc_session");

  session_start();

  if (empty($HTTP_RAW_POST_DATA))
  {
   $logger->log("HTTP_RAW_POST_DATA is empty", PEAR_LOG_WARNING);
   die("HTTP_RAW_POST_DATA is empty!"); 
  }

  lasso_init();

  $requestype = lasso_getRequestTypeFromSoapMsg($HTTP_RAW_POST_DATA);
  $server = LassoServer::newFromDump($server_dump);

  switch ($requestype) 
  {
	// Login
	case lassoRequestTypeLogin:
	  $logger->log("SOAP Login Request from " . $_SERVER['REMOTE_ADDR'], PEAR_LOG_INFO);

	  $login = new LassoLogin($server);
	  $login->processRequestMsg($HTTP_RAW_POST_DATA);
	  $artifact = $login->assertionArtifact;
	
	  $query = "SELECT response_dump FROM assertions WHERE assertion='" . $artifact . "'";

	  $res =& $db->query($query);
	  if (DB::isError($res)) 
	  {
		header("HTTP/1.0 500 Internal Server Error");
		$logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
		$logger->log("DB Error :" . $res->getDebugInfo(), PEAR_LOG_DEBUG);
		exit;
	  }

	  // Good Artifact, send reponse_dump
	  if ($res->numRows()) 
	  {
		$row = $res->fetchRow();
		
		$logger->log("Good artifact send by " . $_SERVER['REMOTE_ADDR'], PEAR_LOG_INFO);        
		
		// Delete assertion from the database
		$query = "DELETE FROM assertions WHERE assertion='" . $artifact . "'";
		$res =& $db->query($query);
		if (DB::isError($res)) 
		{
		      	header("HTTP/1.0 500 Internal Server Error");
			$logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
			$logger->log("DB Error :" . $res->getDebugInfo(), PEAR_LOG_DEBUG);
			exit;
		}
		$logger->log("Delete assertion '$artifact'", PEAR_LOG_DEBUG);
        
		$login->setAssertionFromDump($row[0]);
		$login->buildResponseMsg();
		header("Content-Length: " . strlen($login->msgBody) . "\r\n");
		echo $login->msgBody;
		exit;
	  }
	  else
	  {
		// Wrong Artifact
		header("HTTP/1.0 403 Forbidden");
		header("Content-Length: 0\r\n");
		$logger->log("Wrong artifact send by " . $_SERVER['REMOTE_ADDR'], PEAR_LOG_WARNING);        
		exit;
	  }
	  break;
	case lassoRequestTypeLogout:
		$logger->info("SOAP Logout Request from " . $_SERVER['REMOTE_ADDR']);

		// Logout
		$logout = new LassoLogout($server, lassoProviderTypeIdp);
		$logout->processRequestMsg($HTTP_RAW_POST_DATA, lassoHttpMethodSoap);
		$nameIdentifier = $logout->nameIdentifier; 

		// name identifier is empty, wrong request
		if (empty($nameIdentifier))
		{
			header("HTTP/1.0 500 Internal Server Error");
			$logger->err("Name Identifier is empty");
			exit;
		}
      
		$logger->log("Name Identifier '$nameIdentifier'", PEAR_LOG_DEBUG);

		$query = "SELECT user_id FROM nameidentifiers WHERE name_identifier='$nameIdentifier'";

		$res =& $db->query($query);
		if (DB::isError($res)) 
		{
			header("HTTP/1.0 500 Internal Server Error");
			$logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
			$logger->log("DB Error :" . $res->getDebugInfo(), PEAR_LOG_DEBUG);
			exit;
		}
	  
		if (!$res->numRows()) 
		{
			header("HTTP/1.0 500 Internal Server Error");
			$logger->log("Could not find user_id matching nameidentifier '$nameIdentifier'", PEAR_LOG_ERR);
			exit;
		}
		
		$row = $res->fetchRow();
		$user_id = $row[0];

		$logger->log("Name Identifier '$nameIdentifier' match UserID '$user_id'", PEAR_LOG_DEBUG);

		$query = "SELECT identity_dump,session_dump FROM users WHERE user_id='$user_id'";
	
	      	$res =& $db->query($query);
		if (DB::isError($res)) 
		{
			header("HTTP/1.0 500 Internal Server Error");
			$logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
			$logger->log("DB Error :" . $res->getDebugInfo(), PEAR_LOG_DEBUG);
			exit;
		} 
	  
		if (!$res->numRows()) 
		{
			header("HTTP/1.0 500 Internal Server Error");
			$logger->log("Could not fetch identity and session dump for user '$user_id'", PEAR_LOG_ERR);
			exit;
		}
	  
		$row = $res->fetchRow();
		$user_dump = $row[0];
		$session_dump = $row[1];

		if (!empty($session_dump))
		{
			$logout->setSessionFromDump($session_dump);
			$logger->log("Update session from dump", PEAR_LOG_DEBUG);
		}
		$logout->setIdentityFromDump($user_dump);

		// TODO : handle bad validate request
		$logout->validateRequest();

		if ($logout->isIdentityDirty)
		{
			$identity = $logout->identity;
			$query = "UPDATE users SET identity_dump=".$db->quoteSmart($identity->dump());
			$query .= " WHERE user_id='$user_id'";

			$res =& $db->query($query);
			if (DB::isError($res)) 
			{
				header("HTTP/1.0 500 Internal Server Error");
				$logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
				$logger->log("DB Error :" . $res->getDebugInfo(), PEAR_LOG_DEBUG);
				exit;
			}
			$logger->log("Update identity dump for user '$user_id'", PEAR_LOG_DEBUG);
		} 

		if ($logout->isSessionDirty)
		{
			$session = $logout->session;
			$query = "UPDATE users SET session_dump=";
			$query .= (($session == NULL) ? "''" : $db->quoteSmart($session->dump()));
			$query .= " WHERE user_id='$user_id'"; 

			$res =& $db->query($query);
			if (DB::isError($res)) 
			{
				header("HTTP/1.0 500 Internal Server Error");
				$logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
				$logger->log("DB Error :" . $res->getDebugInfo(), PEAR_LOG_DEBUG);
				exit;
			}
			if ($session)
				$logger->log("Update session dump for user '$user_id'", PEAR_LOG_DEBUG);
			else
				$logger->log("Delete session dump for user '$user_id'", PEAR_LOG_DEBUG);
		} 

	  
		// TODO : try multiple sp logout
		while(($providerID = $logout->getNextProviderId()))
		{
			$logout->initRequest($providerID, lassoHttpMethodAny); // FIXME
			$logout->buildRequestMsg();
			$url = parse_url($logout->msgUrl);
		
			$logger->log("Send SOAP Logout Request to '$providerID' for user '$user_id'", PEAR_LOG_INFO);
        
			$soap = sprintf("POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: %d\r\nContent-Type: text/xml\r\n\r\n%s\r\n",
			$url['path'], $url['host'], $url['port'], strlen($logout->msgBody), $logout->msgBody);

			$logger->log('Send SOAP Request to '. $url['host'] . ":" .$url['port']. $url['path'], PEAR_LOG_INFO);
			$logger->log('SOAP Request : ' . $soap, PEAR_LOG_DEBUG);

			$fp = fsockopen("ssl://" . $url['host'], $url['port'], $errno, $errstr, 30);
			if (!$fp)
			{
				$logger->log("Could not send SOAP Logout Request to '$providerID' 
				for user '$user_id' : $errstr ($errno)", PEAR_LOG_WARN);
				continue;
			}
			fwrite($fp, $soap);

			read_http_response($fp, $header, $response);
		
			$logger->log('SOAP Response Header : ' . $header, PEAR_LOG_DEBUG);
			$logger->log('SOAP Response Body : ' . $response, PEAR_LOG_DEBUG);

			if (!preg_match("/^HTTP\/1\\.. 200/i", $header)) 
			{
				$logger->log("Logout faild for user '$user_id' on '$providerID'", PEAR_LOG_WARN);
				continue;
			}
			$logout->processResponseMsg($response, lassoHttpMethodSoap);
		} 

		$logout->buildResponseMsg();

                // Get PHP session ID
		$query = "SELECT session_id FROM sso_sessions WHERE name_identifier='$nameIdentifier'";
		$res =& $db->query($query);
		if (DB::isError($res)) 
		{
			header("HTTP/1.0 500 Internal Server Error");
			$logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
			$logger->log("DB Error :" . $res->getDebugInfo(), PEAR_LOG_DEBUG);
			exit;
		}
		$row = $res->fetchRow();
		$session_id = $row[0];
		
		$logger->log("Name Identifier '$nameIdentifier' match PHP Session ID '$session_id'", PEAR_LOG_DEBUG);
		
		// Delete SSO Session from table 'sso_sessions'
		$query = "DELETE FROM sso_sessions WHERE name_identifier='$nameIdentifier'";
		$res =& $db->query($query);
		if (DB::isError($res)) 
		{
			header("HTTP/1.0 500 Internal Server Error");
			$logger->log("DB Error :" . $res->getMessage(), PEAR_LOG_CRIT);
			$logger->log("DB Error :" . $res->getDebugInfo(), PEAR_LOG_DEBUG);
			exit;
		}
	 	
		$logger->log("Destroy PHP Session '$session_id'", PEAR_LOG_DEBUG);
		$logger->log("User '$user_id' is logged out", PEAR_LOG_INFO);

		// Destroy The PHP Session
		session_id($session_id);
		$_SESSION = array();
		session_destroy();

		header("Content-Length: " . strlen($logout->msgBody) . "\r\n");
		echo $logout->msgBody;
		break;
	case lassoRequestTypeDefederation:
		$logger->info("SOAP Defederation Request from " . $_SERVER['REMOTE_ADDR']);

		$defederation = new LassoDefederation($server, lassoProviderTypeSp);
		$defederation->processNotificationMsg($HTTP_RAW_POST_DATA, lassoHttpMethodSoap);

		$nameIdentifier = $defederation->nameIdentifier; 
		if (empty($nameIdentifier))
		{
			header("HTTP/1.0 500 Internal Server Error");
			$logger->err("Name Identifier is empty");
			exit;
		}

		$query = "SELECT user_id FROM nameidentifiers WHERE name_identifier='$nameIdentifier'";
		$res =& $db->query($query);
		if (DB::isError($res)) 
		{
			header("HTTP/1.0 500 Internal Server Error");
			$logger->crit("DB Error :" . $res->getMessage());
			$logger->debug("DB Error :" . $res->getDebugInfo());
			exit;
		}
		if (!$res->numRows())
		{
			header("HTTP/1.0 500 Internal Server Error");
			$logger->err("Name identifier '$nameIdentifier' doesn't correspond to any user");
			exit;
		}

		$row = $res->fetchRow();
		$user_id = $row[0];
		$logger->debug("UserID is '$user_id");
		
		$query = "SELECT identity_dump,session_dump FROM users WHERE user_id='$user_id'";
		$res =& $db->query($query);
		
		if (DB::isError($res)) 
		{
			header("HTTP/1.0 500 Internal Server Error");
			$logger->crit("DB Error :" . $res->getMessage());
			$logger->debug("DB Error :" . $res->getDebugInfo());
			exit;
		}
		
		if (!$res->numRows())
		{
			header("HTTP/1.0 500 Internal Server Error");
			$logger->err("User is not federated.");
			exit;
		}
		$row = $res->fetchRow();
		$identity_dump = $row[0];
		$session_dump = $row[1];

		$defederation->setIdentityFromDump($identity_dump);
		if (!empty($session_dump))
			$defederation->setSessionFromDump($identity_dump);

		$defederation->validateNotification();

		if (empty($defederation->msgUrl)):
			header("HTTP/1.0 204 No Content");
		else
		{
		  	$url = $defederation->msgUrl;

			header("Request-URI: $url");
			header("Content-Location: $url");
			header("Location: $url\n\n");
		}
		break;

	default:
		header("HTTP/1.0 500 Internal Server Error");
		$logger->crit("Unknown or unsupported SOAP request");
  }
  
  lasso_shutdown();
?>
