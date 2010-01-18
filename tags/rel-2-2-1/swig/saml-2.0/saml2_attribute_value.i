/* $Id: saml2_attribute_value.i 3378 2007-08-13 10:43:37Z dlaniel $ 
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
%rename(Saml2AttributeValue) LassoSaml2AttributeValue;
#endif
typedef struct {
} LassoSaml2AttributeValue;
%extend LassoSaml2AttributeValue {

	/* Attribute */
	%newobject any_get;
	LassoNodeList *any;

	/* Constructor, Destructor & Static Methods */
	LassoSaml2AttributeValue();
	~LassoSaml2AttributeValue();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Attributes */

#define LassoSaml2AttributeValue_get_any(self) get_node_list((self)->any)
#define LassoSaml2AttributeValue_any_get(self) get_node_list((self)->any)
#define LassoSaml2AttributeValue_set_any(self,value) set_node_list(&(self)->any, (value))
#define LassoSaml2AttributeValue_any_set(self,value) set_node_list(&(self)->any, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2AttributeValue lasso_saml2_attribute_value_new
#define delete_LassoSaml2AttributeValue(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2AttributeValue_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

