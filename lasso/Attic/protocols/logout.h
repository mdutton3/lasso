/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#ifndef __LOGOUT_H__
#define __LOGOUT_H__

#include <lasso/protocols/protocols.h>

typedef struct _lassoLogoutRequest lassoLogoutRequest;

struct _lassoLogoutRequest{
  LassoNode  *node;
};

typedef struct _lassoLogoutResponse lassoLogoutResponse;

struct _lassoLogoutResponse{
  LassoNode  *node;
  LassoNode  *request_node;
  xmlChar    *request_query;
};

lassoLogoutRequest * lasso_logout_request_create(const xmlChar *providerID,
						 xmlChar       *nameIdentifier,
						 const xmlChar *nameQualifier,
						 const xmlChar *format,
						 const xmlChar *sessionIndex,
						 const xmlChar *relayState,
						 const xmlChar *consent);

lassoLogoutResponse * lasso_logout_response_create(xmlChar *query);

#endif /* __LOGOUT_H__ */
