/* -*- Mode: c; c-basic-offset: 8 -*-
 *
 * $Id: Lasso-wsf-disco.i,v 1.7 2006/12/20 23:41:44 fpeters Exp $
 *
 * SWIG bindings for Lasso Library
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: See AUTHORS file in top-level directory.
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


/* WSF prefix & href */
#ifndef SWIGPHP4
%rename(IDWSF2_DISCO_HREF) LASSO_IDWSF2_DISCO_HREF;
%rename(IDWSF2_DISCO_PREFIX) LASSO_IDWSF2_DISCO_PREFIX;
#endif
#define LASSO_IDWSF2_DISCO_HREF   "urn:liberty:disco:2006-08"
#define LASSO_IDWSF2_DISCO_PREFIX "disco"


/***********************************************************************
 ***********************************************************************
 * XML Elements in Discovery Namespace
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * disco:Query
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Idwsf2DiscoQuery) LassoIdwsf2DiscoQuery;
#endif
typedef struct {
	/* Attributes */

	char *id;
} LassoIdwsf2DiscoQuery;
%extend LassoIdwsf2DiscoQuery {

	/* Constructor, Destructor & Static Methods */

	LassoIdwsf2DiscoQuery();

	~LassoIdwsf2DiscoQuery();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoIdwsf2DiscoQuery lasso_idwsf2_disco_query_new
#define delete_LassoIdwsf2DiscoQuery(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIdwsf2DiscoQuery_dump(self) lasso_node_dump(LASSO_NODE(self))

%}
