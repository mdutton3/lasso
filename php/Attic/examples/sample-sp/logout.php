<?php
/*  
 * Service Provider Example -- Logout
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

  if (!empty($_GET['SID'])) 
	session_start($_GET['SID']);
  else
	session_start();

  if (!isset($_SESSION["nameidentifier"])) {
	print "User is not logged in";
	exit(0);
	}

  lasso_init();
  
  $db = &DB::connect($config['dsn']);

  if (DB::isError($db)) 
	die($db->getMessage());

  $server_dump = file_get_contents($config['server_dump_filename']);
  
  $server = LassoServer::newfromdump($server_dump);
  
  $logout = new LassoLogout($server, lassoProviderTypeSp);
  
  $query = "SELECT identity_dump FROM users WHERE user_id='";
  $query .= $_SESSION['user_id']."'";

  $res =& $db->query($query);
  
  if (DB::isError($res)) 
	print $res->getMessage(). "\n";
 
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

  # PHP 4.3.0 with OpenSSL support required
  $fp = fsockopen("ssl://" . $url['host'], $url['port'], $errno, $errstr, 30) or die($errstr ($errno));
 
  fwrite($fp, $soap);
  $ret = fgets($fp);

  if (!preg_match("/^HTTP\/1\\.. 200/i", $ret)) {
	die("User is already logged out");
  }

  while (!feof($fp)) {
  	$reponse .= @fread($fp, 8192);
  }

  fclose($fp);

  # Destroy The PHP Session
  $_SESSION = array();

  session_destroy();
  
  $db->disconnect();
  lasso_shutdown();

  $url = "index.php";
  
  header("Request-URI: $url");
  header("Content-Location: $url");
  header("Location: $url");
?>
