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
	case lassoRequestTypeLogout:
		$logger->info("SOAP Logout Request from " . $_SERVER['REMOTE_ADDR']);

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
		
		$query = "SELECT identity_dump FROM users WHERE user_id='$user_id'";
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

		$defederation->setIdentityFromDump($identity_dump);

		// TODO : Get Session

		$defederation->validateNotification();

		$identity = $defederation->identity;

		if (!isset($identity->dump))
		{
			$identity_dump = $identity->dump;
		}
		
		break;
	default:
		header("HTTP/1.0 500 Internal Server Error");
		$logger->crit("Unknown or unsupported SOAP request");
  }

?>
