/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#include <glib-object.h>

#include <libxml/xpath.h>

#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

xmlChar * lasso_build_unique_id(guint8 size);

xmlChar * lasso_doc_get_node_content(xmlDocPtr doc, const xmlChar *name);

xmlChar * lasso_g_ptr_array_index(GPtrArray *a, guint i);

xmlChar * lasso_get_current_time(void);

GData   * lasso_query_to_dict(const xmlChar *query);

xmlChar * lasso_str_escape(xmlChar *str);

xmlDocPtr lasso_str_sign(xmlChar *str,
			 xmlSecTransformId signMethodId,
			 const char* key_file);

xmlChar * lasso_str_unescape(xmlChar *str);

int       lasso_str_verify(xmlChar *str,
			   const xmlChar *sender_public_key_file,
			   const xmlChar *recipient_private_key_file);
