/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
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

#ifndef SWIG_PHP_RENAMES
%rename(Samlp2Scoping) LassoSamlp2Scoping;
#endif
typedef struct {
#ifndef SWIG_PHP_RENAMES
	%rename(requesterID) RequesterID;
#endif
	char *RequesterID;
#ifndef SWIG_PHP_RENAMES
	%rename(proxyCount) ProxyCount;
#endif
	char *ProxyCount;
} LassoSamlp2Scoping;
%extend LassoSamlp2Scoping {

#ifndef SWIG_PHP_RENAMES
	%rename(iDPList) IDPList;
#endif
	%newobject IDPList_get;
	LassoSamlp2IDPList *IDPList;


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2Scoping();
	~LassoSamlp2Scoping();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* IDPList */

#define LassoSamlp2Scoping_get_IDPList(self) get_node((self)->IDPList)
#define LassoSamlp2Scoping_IDPList_get(self) get_node((self)->IDPList)
#define LassoSamlp2Scoping_set_IDPList(self,value) set_node((gpointer*)&(self)->IDPList, (value))
#define LassoSamlp2Scoping_IDPList_set(self,value) set_node((gpointer*)&(self)->IDPList, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2Scoping lasso_samlp2_scoping_new
#define delete_LassoSamlp2Scoping(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2Scoping_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

