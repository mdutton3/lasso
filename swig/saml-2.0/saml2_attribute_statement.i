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
%rename(Saml2AttributeStatement) LassoSaml2AttributeStatement;
#endif
typedef struct {
} LassoSaml2AttributeStatement;
%extend LassoSaml2AttributeStatement {

#ifndef SWIG_PHP_RENAMES
	%rename(attribute) Attribute;
#endif
	%newobject Attribute_get;
	LassoNodeList *Attribute;

#ifndef SWIG_PHP_RENAMES
	%rename(encryptedAttribute) EncryptedAttribute;
#endif
	%newobject EncryptedAttribute_get;
	LassoNodeList *EncryptedAttribute;

	/* inherited from Saml2StatementAbstract */

	/* Constructor, Destructor & Static Methods */
	LassoSaml2AttributeStatement();
	~LassoSaml2AttributeStatement();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Attribute */

#define LassoSaml2AttributeStatement_get_Attribute(self) get_node((self)->Attribute)
#define LassoSaml2AttributeStatement_Attribute_get(self) get_node((self)->Attribute)
#define LassoSaml2AttributeStatement_set_Attribute(self,value) set_node((gpointer*)&(self)->Attribute, (value))
#define LassoSaml2AttributeStatement_Attribute_set(self,value) set_node((gpointer*)&(self)->Attribute, (value))
                    

/* EncryptedAttribute */

#define LassoSaml2AttributeStatement_get_EncryptedAttribute(self) get_node((self)->EncryptedAttribute)
#define LassoSaml2AttributeStatement_EncryptedAttribute_get(self) get_node((self)->EncryptedAttribute)
#define LassoSaml2AttributeStatement_set_EncryptedAttribute(self,value) set_node((gpointer*)&(self)->EncryptedAttribute, (value))
#define LassoSaml2AttributeStatement_EncryptedAttribute_set(self,value) set_node((gpointer*)&(self)->EncryptedAttribute, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2AttributeStatement lasso_saml2_attribute_statement_new
#define delete_LassoSaml2AttributeStatement(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2AttributeStatement_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

