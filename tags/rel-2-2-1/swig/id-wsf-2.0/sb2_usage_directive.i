/* $Id: sb2_usage_directive.i,v 1.0 2005/10/14 15:17:55 fpeters Exp $ 
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
%rename(IdWsf2Sb2UsageDirective) LassoIdWsf2Sb2UsageDirective;
#endif
typedef struct {
	char *ref;
} LassoIdWsf2Sb2UsageDirective;
%extend LassoIdWsf2Sb2UsageDirective {

	/* any attribute */
	%immutable attributes;
	%newobject attributes_get;
	LassoStringDict *attributes;

	/* Constructor, Destructor & Static Methods */
	LassoIdWsf2Sb2UsageDirective();
	~LassoIdWsf2Sb2UsageDirective();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* any attribute */
LassoStringDict* LassoIdWsf2Sb2UsageDirective_attributes_get(LassoIdWsf2Sb2UsageDirective *self);
#define LassoIdWsf2Sb2UsageDirective_get_attributes LassoIdWsf2Sb2UsageDirective_attributes_get
LassoStringDict* LassoIdWsf2Sb2UsageDirective_attributes_get(LassoIdWsf2Sb2UsageDirective *self) {
        return self->attributes;
}
/* TODO: implement attributes_set */


/* Constructors, destructors & static methods implementations */

#define new_LassoIdWsf2Sb2UsageDirective lasso_idwsf2_sb2_usage_directive_new
#define delete_LassoIdWsf2Sb2UsageDirective(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIdWsf2Sb2UsageDirective_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

