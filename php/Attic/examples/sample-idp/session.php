<?php
/*  
 * Pear::DB session handler 
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


function open_session ($save_path, $session_name) {
  return(true);
}

function close_session() {
  global $db;
  $db->disconnect();
  return(true);
}

function read_session ($id) {
 global $db;
 
 $query = "SELECT * FROM sessions WHERE id='$id'";
 $res =& $db->query($query);
 if (DB::isError($res)) 
 {
   exit;
   die($res->getMessage());
 } 

 if ($res->numRows() == 1)
 {
   $row = $res->fetchRow();
   return ($row[2]);
 } else {
   return("");
 }
}

function write_session ($id, $sess_data) {
 global $db;

 $query = "DELETE FROM sessions WHERE id='$id'";
 $res =& $db->query($query);
 if (DB::isError($res)) 
  	die($res->getMessage());

 $query = "INSERT INTO sessions(id, lastupdate, data) VALUES('$id', NOW(),";
 $query .= $db->quoteSmart($sess_data).")";
 $res =& $db->query($query);
 if (DB::isError($res)) 
  	die($res->getMessage());
}

function destroy_session ($id) {
 global $db;

 $query = "DELETE FROM sessions WHERE id='$id'";
 $res =& $db->query($query);
 if (DB::isError($res)) 
   die($res->getMessage());

 return true;
}

function gc_session ($maxlifetime) {
  return true;
}

?>
