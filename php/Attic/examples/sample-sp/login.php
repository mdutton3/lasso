<?php
/*  
 *
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

  include "config.php.inc";  

  lasso_init();

  $server_dump = file_get_contents($server_dump_filename);

  $server = lasso_server_new_from_dump($server_dump);

  $login = lasso_login_new($server);

  lasso_login_init_authn_request($login);

  $profile = lasso_cast_to_profile($login);

  $node = lasso_profile_get_request($profile);

  $lib_authn_request = lasso_cast_to_lib_authn_request($node);

  // lasso_lib_authn_request_set_forceauthn($lib_authn_request, TRUE);
  lasso_lib_authn_request_set_ispassive($lib_authn_request, FALSE);
  lasso_lib_authn_request_set_nameidpolicy($lib_authn_request, lassoLibNameIDPolicyTypeFederated);
  lasso_lib_authn_request_set_consent($lib_authn_request, lassoLibConsentObtained); 

  lasso_login_build_authn_request_msg($login, "https://idp1/metadata");

  
  $url = lasso_profile_get_msg_url($profile);

  header("Request-URI: $url");
  header("Content-Location: $url");
  header("Location: $url");
  exit();
?>
