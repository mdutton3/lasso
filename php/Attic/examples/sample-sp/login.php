<?php
/*  
 * Service Provider Example -- Simple Sing On 
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

  // connect to the data base
  $db = &DB::connect($config['dsn']);
  if (DB::isError($db)) 
	die($db->getMessage());

  // session handler
  session_set_save_handler("open_session", "close_session", 
  "read_session", "write_session", "destroy_session", "gc_session");

  session_start();

  lasso_init();

  $server_dump = file_get_contents($config['server_dump_filename']);

  $server = LassoServer::newFromdump($server_dump);

  $login = new LassoLogin($server);

  if ($_GET['profile'] == 'post')
	$login->initauthnrequest(lassoHttpMethodPost);
  elseif ($_GET['profile'] == 'artifact')
	$login->initauthnrequest(lassoHttpMethodRedirect);
  else
	die('Unknown Single Sign ON Profile');

  $request = $login->authnRequest;
  $request->isPassive = FALSE;
  $request->nameIdPolicy = lassoLibNameIDPolicyTypeFederated;
  $request->consent = lassoLibConsentObtained;

  $login->buildAuthnRequestMsg($config['providerID']);

  $url = $login->msgUrl;
  $msg = $login->msgBody;
  switch ($_GET['profile'])
  {
	case 'post':
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
	"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
 <head>
  <title>Authentication Request</title>
 </head>
  <body onLoad="document.forms[0].submit()">
  <form action="<?php echo $url; ?>" method="post">
   <p>You should be automaticaly redirected to an authentication server.</p>
   <p>If this page is still visible after a few seconds, press the <em>Send</em> button below.</p>
   <input type="hidden" name="LAREQ" value="<?php echo $msg; ?>" />
   <input type="submit" name="SendButton" value="Send" />
  </form>
 </body>
</html>
<?
		break;
  	case 'artifact' :
		header("Request-URI: $url");
		header("Content-Location: $url");
		header("Location: $url\r\n\r\n");
		break;
  }
?>
