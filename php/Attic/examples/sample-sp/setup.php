<?php
/*  
 *
 * Service Provider Example -- Installation Script
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

  	include "config.php.inc";

	require_once 'DB.php';

	print "Setup script for L.A.S.S.O (Liberty Alliance Single Sign On)\n";

	lasso_init();
	print "$server_dump_filename: ";


	# Create XML Server Dump
	if (file_exists($server_dump_filename))
	{
	  print "file already exists.\n";
	} 
	else 
	{
	  $server = lasso_server_new(
	  "/home/cnowicki/mcvs/lasso/tests/data/sp1-la/metadata.xml", 
	  "/home/cnowicki/mcvs/lasso/tests/data/sp1-la/public-key.pem",
      "/home/cnowicki/mcvs/lasso/tests/data/sp1-la/private-key-raw.pem",
      "/home/cnowicki/mcvs/lasso/tests/data/sp1-la/certificate.pem",
	  lassoSignatureMethodRsaSha1);

	  lasso_server_add_provider($server, 
	  "/home/cnowicki/mcvs/lasso/tests/data/idp1-la/metadata.xml", 
	  "/home/cnowicki/mcvs/lasso/tests/data/idp1-la/public-key.pem",
	  "/home/cnowicki/mcvs/lasso/tests/data/ca1-la/certificate.pem"
      );

	  $dump = lasso_server_dump($server);
	  $fd = fopen($server_dump_filename, "w");
	  fwrite($fd, $dump);
	  print "wrote.\n";
	  fclose($fd);
	}

	print "Create User Database.\n";
	print "DSN : $dsn\n";

	$options = array(
    	'debug'       => 2,
	);
	
	$db = &DB::connect($dsn, $options);
	if (DB::isError($db)) {
     	die($db->getMessage());
    }

	
	# Drop user_id_seq
	print "DROP user_id_seq.\n";
	$query = "DROP SEQUENCE user_id_seq";
	$res =& $db->query($query);
	if (DB::isError($res)) 
		die($res->getMessage());

	
	# Create user_id_seq
	print "Create user_id_seq Sequence.\n";
	$query = "CREATE SEQUENCE user_id_seq";
	$res =& $db->query($query);
	if (DB::isError($res)) 
		die($res->getMessage());

	/* print "DROP users.\n";
	$query = "DROP TABLE users CASCADE";
	$res =& $db->query($query);
	if (DB::isError($res)) 
		die($res->getMessage()); */

	# Create local data base
	print "Create users Table.\n";
	$query = "CREATE TABLE users (
      user_id         varchar(100) primary key,
      identity_dump   text,
      first_name   	  varchar(50),
      last_name   	  varchar(50),
	  created		  timestamp)";
	$res =& $db->query($query);
	if (DB::isError($res)) 
		die($res->getMessage());
		
	/* print "DROP nameidentifiers.\n";
	$query = "DROP TABLE nameidentifiers"; 

	$res =& $db->query($query); */
	
	if (DB::isError($res)) 
		die($res->getMessage());
	
	print "Create nameidentifiers Table.\n";
	$query = "CREATE TABLE nameidentifiers (
      name_identifier varchar(100) primary key,
      user_id         varchar(100),
      FOREIGN KEY (user_id) REFERENCES users (user_id))";
	$res =& $db->query($query);
	if (DB::isError($res)) 
		die($res->getMessage());

	
	$db->disconnect();

	lasso_shutdown();
?>
