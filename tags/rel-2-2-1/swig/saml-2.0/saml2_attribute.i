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
%rename(Saml2Attribute) LassoSaml2Attribute;
#endif
typedef struct {
#ifndef SWIG_PHP_RENAMES
	%rename(name) Name;
#endif
	char *Name;

#ifndef SWIG_PHP_RENAMES
	%rename(nameFormat) NameFormat;
#endif
	char *NameFormat;

#ifndef SWIG_PHP_RENAMES
	%rename(friendlyName) FriendlyName;
#endif
	char *FriendlyName;

} LassoSaml2Attribute;
%extend LassoSaml2Attribute {

	/* Attribute */
#ifndef SWIG_PHP_RENAMES
	%rename(attributeValue) AttributeValue;
#endif
	%newobject AttributeValue_get;
	LassoNodeList *AttributeValue;

	/* Constructor, Destructor & Static Methods */
	LassoSaml2Attribute();
	~LassoSaml2Attribute();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Attributes */

#define LassoSaml2Attribute_get_AttributeValue(self) get_node_list((self)->AttributeValue)
#define LassoSaml2Attribute_AttributeValue_get(self) get_node_list((self)->AttributeValue)
#define LassoSaml2Attribute_set_AttributeValue(self,value) set_node_list(&(self)->AttributeValue, (value))
#define LassoSaml2Attribute_AttributeValue_set(self,value) set_node_list(&(self)->AttributeValue, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2Attribute lasso_saml2_attribute_new
#define delete_LassoSaml2Attribute(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2Attribute_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

