<?php
/*  
 *
 * Identity Provider Example -- Setup
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
 
  if (empty($_POST) && empty($_GET))
  {
	die("Unknow login methode!");
  }
  $methode = empty($_POST) ? 'GET' : 'POST'; 

  $config = unserialize(file_get_contents('config.inc'));

  lasso_init();

  $server_dump = file_get_contents($config['server_dump_filename']);

  $server = LassoServer::newfromdump($server_dump);

  $login = new LassoLogin($server);

  if ($methode = 'GET')
  {
	print $_SERVER['QUERY_STRING'];
	$login->initFromAuthnRequestMsg($_SERVER['QUERY_STRING'], lassoHttpMethodRedirect);
	print "ici";
  } 
  else
  {
	// TODO
  }


  //echo $methode;
  //echo $_SERVER['QUERY_STRING'];
?>
