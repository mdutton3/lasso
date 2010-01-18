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
		die($res->getMessage());

	  // Good Artifact, send reponse_dump
	  if ($res->numRows()) 
	  {
		$row = $res->fetchRow();
		
		$query = "DELETE FROM assertions WHERE assertion='" . $artifact . "'";
		
		$res =& $db->query($query);
		if (DB::isError($res)) 
		  die($res->getMessage()); 
		header("Content-Length: " . strlen($row[0]) . "\r\n");
		echo $row[0];
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
	  break;
	case lassoRequestTypeDefederation:
	  break;
	default:
	  die("Unkown request type!");
  }
  
  lasso_shutdown();
?>
