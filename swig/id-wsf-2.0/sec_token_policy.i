/* $Id: sec_token_policy.i,v 1.0 2005/10/14 15:17:55 fpeters Exp $ 
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

#ifndef SWIGPHP4
%rename(IdWsf2SecTokenPolicy) LassoIdWsf2SecTokenPolicy;
#endif
typedef struct {
	char *validUntil;
	char *issueTo;
	char *type;
	gboolean wantDSEPR;
} LassoIdWsf2SecTokenPolicy;
%extend LassoIdWsf2SecTokenPolicy {

	%newobject *any_get;
	LassoNode *any;

	/* any attribute */
	%immutable attributes;
	%newobject attributes_get;
	LassoStringDict *attributes;

	/* Constructor, Destructor & Static Methods */
	LassoIdWsf2SecTokenPolicy();
	~LassoIdWsf2SecTokenPolicy();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* any */

#define LassoIdWsf2SecTokenPolicy_get_any(self) get_node((self)->any)
#define LassoIdWsf2SecTokenPolicy_any_get(self) get_node((self)->any)
#define LassoIdWsf2SecTokenPolicy_set_any(self,value) set_node((gpointer*)&(self)->any, (value))
#define LassoIdWsf2SecTokenPolicy_any_set(self,value) set_node((gpointer*)&(self)->any, (value))
                    

/* any attribute */
LassoStringDict* LassoIdWsf2SecTokenPolicy_attributes_get(LassoIdWsf2SecTokenPolicy *self);
#define LassoIdWsf2SecTokenPolicy_get_attributes LassoIdWsf2SecTokenPolicy_attributes_get
LassoStringDict* LassoIdWsf2SecTokenPolicy_attributes_get(LassoIdWsf2SecTokenPolicy *self) {
        return self->attributes;
}
/* TODO: implement attributes_set */


/* Constructors, destructors & static methods implementations */

#define new_LassoIdWsf2SecTokenPolicy lasso_idwsf2_sec_token_policy_new
#define delete_LassoIdWsf2SecTokenPolicy(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIdWsf2SecTokenPolicy_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

