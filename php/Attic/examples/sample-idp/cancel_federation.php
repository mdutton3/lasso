<?php
/*  
 * Identity Provider Example -- Cancel Federation with an Service Provider 
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

 $methodes = array('redirect' => lassoHttpMethodRedirect, 'soap' => lassoHttpMethodSoap);

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

 if (empty($_GET['profile']))
 {
	$logger->err("Cancel Federation called without profile.");
	die("Cancel Federation called without profile.");
 }

 if (empty($_GET['with']))
 {
	$logger->err("Cancel Federation called without providerID.");
	die("Cancel Federation called without providerID.");
 }

 session_start();

 lasso_init();

 if (empty($_SESSION['user_id']))
 {
	$logger->err("UserID is empty, user is not logged in.");
	die("UserID is empty, user is not logged in.");
 }
 
 if (empty($_SESSION['identity_dump']))
 {
	$logger->err("Identity Dump is empty, user is not federated.");
	die("Identity Dump is empty, user is not federated.");
 }

 if (!in_array($_GET['profile'], array_keys($methodes)))
 {
	die("Unknown defederation profile : " . $_GET['profile']);
	$logger->err("Unknown defederation profile : " . $_GET['profile']);
 }
 
 $user_id = $_SESSION['user_id'];
 
 $server_dump = file_get_contents($config['server_dump_filename']);
 $server = LassoServer::newFromDump($server_dump);

 $defederation = new LassoDefederation($server, lassoProviderTypeIdp);
 $defederation->setIdentityFromDump($_SESSION['identity_dump']);

 if (!empty($_SESSION['session_dump']))
	$defederation->setSessionFromDump($_SESSION['session_dump']);

 $logger->debug("Create Cancel Federation Notification for User '" . $_SESSION["user_id"] .
 "' with Service Provider '" . $_GET['with']. "'");
 
 $defederation->initNotification($_GET['with'], $methodes[$_GET['profile']]);
 
 $defederation->buildNotificationMsg();
 $nameIdentifier = $defederation->nameIdentifier;
 if (empty($nameIdentifier))
 {
 	$loggery>err("Name Identifier is empty.");
	die("Name Identifier is empty.");
 }

 $identity = $defederation->identity;
 if (isset($defederation->identity))
 {
	// Update identity dump
	$identity_dump = $identity->dump();
	$_SESSION['identity_dump'] = $identity_dump;
	$query = "UPDATE users SET identity_dump=".$db->quoteSmart($identity_dump);
 }
 else	// Delete identity and session dumps
	$query = "UPDATE users SET identity_dump=''";
 $query .= " WHERE user_id='$user_id'";

 $res =& $db->query($query);
 if (DB::isError($res)) 
 {
	$logger->crit("DB Error :" . $res->getMessage());
	$logger->debug("DB Error :" . $res->getDebugInfo());
	die("Internal Server Error");
 }
 $logger->debug("Update user '$user_id' identity dump in the database");

 // Update session dump, if available
 if (!empty($_SESSION['sesion_dump']) && $defederation->isSessionDirty)
 {
	$session = $defederation->session;
	$session_dump = $session->dump();
	$_SESSION['session_dump'] = $session_dump;
			
	$query = "UPDATE users SET session_dump=".$db->quoteSmart($session_dump);
	$query .= " WHERE user_id='$user_id'";

	$res =& $db->query($query);
	if (DB::isError($res)) 
	{
		$logger->crit("DB Error :" . $res->getMessage());
		$logger->debug("DB Error :" . $res->getDebugInfo());
		die("Internal Server Error");
	}
	$logger->debug("Update user '$user_id' session dump in the database");
}

// Delete Name Identifier
$query = "DELETE FROM nameidentifiers WHERE user_id='$user_id' ";
$query .= "AND name_identifier='$nameIdentifier'";

$res =& $db->query($query);
if (DB::isError($res)) 
{
	$logger->crit("DB Error :" . $res->getMessage());
	$logger->debug("DB Error :" . $res->getDebugInfo());
	die("Internal Server Error");
}

$logger->info("Delete Name Identifier '$nameIdentifier' for User '$user_id'");

switch($_GET['profile'])
{
	case 'redirect':
		$url = $defederation->msgUrl;
	        $logger->info("Redirect user to $url");
		
		header("Request-URI: $url");
		header("Content-Location: $url");
		header("Location: $url\r\n\r\n");
		break;
	case 'soap':
		$url = parse_url($defederation->msgUrl);
		$soap = sprintf(
		"POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: %d\r\nContent-Type: text/xml\r\n\r\n%s\r\n",
		$url['path'], $url['host'], $url['port'], strlen($defederation->msgBody), $defederation->msgBody);
		
		$logger->info('Send SOAP Request to '. $url['host'] . ":" .$url['port']. $url['path']);
		$logger->debug('SOAP Request : ' . $soap);

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

		// TODO : check reponse status


		break;
 }

?>

<?php
	lasso_shutdown();
?>
