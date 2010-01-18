<?php
/*  
 * Service Provider Example -- Misc functions
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

function read_http_response($fp, &$header, &$response)
{
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
}
