<?php
/*  
 * Service Provider Example -- Logout
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

    // connect to the data base
    $db = &DB::connect($config['dsn']);
    if (DB::isError($db)) 
	die($db->getMessage());
	
    // create logger 
    $conf['db'] = $db;
    $logger = &Log::factory($config['log_handler'], 'log', $_SERVER['PHP_SELF'], $conf);

    // session handler
    session_set_save_handler("open_session", "close_session", 
    "read_session", "write_session", "destroy_session", "gc_session");

    session_start();

  if (!isset($_SESSION["nameidentifier"])) {
        $logger->log("Not logged in user '" . $_SERVER['REMOTE_ADDR'] , "', try to register.", PEAR_LOG_WARN);
	exit(0);
  }

  lasso_init();
  
  $server_dump = file_get_contents($config['server_dump_filename']);
  
  $server = LassoServer::newFromDump($server_dump);
  
  $logout = new LassoLogout($server, lassoProviderTypeSp);
  
  $query = "SELECT identity_dump FROM users WHERE user_id='";
  $query .= $_SESSION['user_id']."'";

  $res =& $db->query($query);
  
  if (DB::isError($res)) 
  {
        $logger->log("DB Error :" . $db->getMessage(), PEAR_LOG_CRIT);
        $logger->log("DB Error :" . $db->getDebugInfo(), PEAR_LOG_DEBUG);
	die($db->getMessage());
  }
 
  $row = $res->fetchRow();
  
  $logout->setIdentityFromDump($row[0]);
  $logout->setSessionFromDump($_SESSION['session_dump']);

  $logout->initRequest();
  $logout->buildRequestMsg();

  $url = parse_url($logout->msgUrl);

  $soap = sprintf(
	"POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: %d\r\nContent-Type: text/xml\r\n\r\n%s\r\n",
  $url['path'], $url['host'], $url['port'], 
  strlen($logout->msgBody), $logout->msgBody);

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
	  $response = fread($fp, $matches[1]);
	else 
	  while (!feof($fp)) $response .= fread($fp, 1024);
  }
  fclose($fp);
  
  $logger->log('SOAP Response Header : ' . $header, PEAR_LOG_DEBUG);
  $logger->log('SOAP Response Body : ' . $response, PEAR_LOG_DEBUG);

  if (!preg_match("/^HTTP\/1\\.. 200/i", $header)) {
        $logger->log("User is already logged out" . $_SERVER['REMOTE_ADDR'], PEAR_LOG_WARN);	
	die("User is already logged out");
  }

  # Destroy The PHP Session
  $_SESSION = array();
  $logger->log("Destroy session '".session_id()."' for user '".$_SESSION['username']."'", PEAR_LOG_INFO);	
  session_destroy();

  lasso_shutdown();

  $url = "index.php";
  
  header("Request-URI: $url");
  header("Content-Location: $url");
  header("Location: $url\n\r\n");
  exit;
?>
