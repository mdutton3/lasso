<?php
/*  
 * Service Provider Example -- AssertionConsumer
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
  
  session_start();

  if (!isset($_SESSION["nameidentifier"])) {
	print "User is not logged in";
	exit(0);
	}

  lasso_init();

  $server_dump = file_get_contents($server_dump_filename);
  
  $server = lasso_server_new_from_dump($server_dump);

  $logout = lasso_logout_new($server, lassoProviderTypeSp);

  // $profile = lasso_cast_to_profile($logout);

  lasso_shutdown();
?>
