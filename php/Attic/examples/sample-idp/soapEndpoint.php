<?php
/*  
 *
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
  require_once 'DB.php';

  header("Content-Type: text/xml\r\n");

  if (empty($HTTP_RAW_POST_DATA))
   die("HTTP_RAW_POST_DATA is empty!"); 

  $config = unserialize(file_get_contents('config.inc'));
   
  $server_dump = file_get_contents($config['server_dump_filename']);

  lasso_init();

  $requestype = lasso_getRequestTypeFromSoapMsg($HTTP_RAW_POST_DATA);
  $server = LassoServer::newfromdump($server_dump);

  $db = &DB::connect($config['dsn']);

  if (DB::isError($db)) 
  	die($db->getMessage());
  
  switch ($requestype) 
  {
	// Login
	case lassoRequestTypeLogin:
	  $login = new LassoLogin($server);
	  $login->processRequestMsg($HTTP_RAW_POST_DATA);
	  $artifact = $login->assertionArtifact;
	
	  $query = "SELECT response_dump FROM assertions WHERE assertion='";
	  $query .= $artifact ."'";

	  $res =& $db->query($query);
	  if (DB::isError($res)) 
	  {
		header("HTTP/1.0 500 Internal Server Error");
		die($res->getMessage());
	  }

	  // Good Artifact, send reponse_dump
	  if ($res->numRows()) 
	  {
		$row = $res->fetchRow();
		
		$query = "DELETE FROM assertions WHERE assertion='" . $artifact . "'";
		
		$res =& $db->query($query);
		if (DB::isError($res)) 
		{
		  header("HTTP/1.0 500 Internal Server Error");
		  die($res->getMessage()); 
		}
		$login->setAssertionFromDump($row[0]);
		$login->buildResponseMsg();
		header("Content-Length: " . strlen($login->msgBody) . "\r\n");
		echo $login->msgBody;
	  }
	  else
	  {
		// Wrong Artifact
		header("HTTP/1.0 403 Forbidden");
		header("Content-Length: 0\r\n");
		exit;
	  }
	  break;
	case lassoRequestTypeLogout:
	  // Logout
	  $logout = new LassoLogout($server, lassoProviderTypeIdp);
	  $logout->processRequestMsg($HTTP_RAW_POST_DATA, lassoHttpMethodSoap);
	  $nameIdentifier = $logout->nameIdentifier; 
	  
	  // name identifier is empty, wrong request
	  if (empty($nameIdentifier))
	  {
		header("HTTP/1.0 500 Internal Server Error");
		exit;
	  }

	  $query = "SELECT user_id FROM nameidentifiers WHERE name_identifier='";
	  $query .= $nameIdentifier . "'";

	  $res =& $db->query($query);
	  if (DB::isError($res)) 
		die($res->getMessage());
	  
	  if (!$res->numRows()) 
	  {
		header("HTTP/1.0 500 Internal Server Error");
		exit;
	  }
		
	  $row = $res->fetchRow();
	  $user_id = $row[0];

	  $query = "SELECT identity_dump,session_dump FROM users WHERE user_id='$user_id'";

	  $res =& $db->query($query);
	  if (DB::isError($res)) 
		die($res->getMessage());
	  
	  if (!$res->numRows()) 
	  {
		header("HTTP/1.0 500 Internal Server Error");
		exit;
	  }
	  
	  $row = $res->fetchRow();
	  $user_dump = $row[0];
	  $session_dump = $row[1];

	  $logout->setSessionFromDump($session_dump);
	  $logout->setIdentityFromDump($user_dump);

	  // TODO : handle exception
	  if ($logout->validateRequest())
	  {
		// validate request failed
		header("HTTP/1.0 500 Internal Server Error");
		exit;
	  }

	  if ($logout->isIdentityDirty)
	  {
		$identity = $logout->identity;
		$query = "UPDATE users SET identity_dump=".$db->quoteSmart($identity->dump());
		$query .= " WHERE identity_id='$user_id'";

		$res =& $db->query($query);
		if (DB::isError($res)) 
		  die($res->getMessage());
	  } 
	  
	  // TODO : try multiple sp logout
	  while(($providerID = $logout->getNextProviderId()))
	  {
		$logout->initRequest($providerID, lassoHttpMethodAny); // FIXME
		$logout->buildRequestMsg();
		$url = parse_url($logout->msgUrl);
		
		$soap = sprintf("POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: %d\r\nContent-Type: text/xml\r\n\r\n%s\r\n",
		  $url['path'], $url['host'], $url['port'], strlen($logout->msgBody), $logout->msgBody);

		$fp = fsockopen("ssl://" . $url['host'], $url['port'], $errno, $errstr, 30);
		if (!$fp)
		{
		  header("HTTP/1.0 500 Internal Server Error");
		  die($errstr ($errno));
		}
		fwrite($fp, $soap);
		$ret = fgets($fp);

		if (!preg_match("/^HTTP\/1\\.. 200/i", $ret)) 
		{
		  header("HTTP/1.0 500 Internal Server Error");
		  die("Logout failed with : " . $providerID);
		}
		
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

		$logout->processResponseMsg($response, lassoHttpMethodSoap);
	  } 
	  
	  $logout->buildResponseMsg();
	  header("Content-Length: " . strlen($logout->msgBody) . "\r\n");
	  echo $logout->msgBody;
	  break;
	case lassoRequestTypeDefederation:
	  break;
	default:
	  header("HTTP/1.0 500 Internal Server Error");
  }
  
  lasso_shutdown();
?>
