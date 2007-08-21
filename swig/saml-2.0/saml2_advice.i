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
%rename(Saml2Advice) LassoSaml2Advice;
#endif
typedef struct {
} LassoSaml2Advice;
%extend LassoSaml2Advice {

#ifndef SWIG_PHP_RENAMES
	%rename(assertionIDRef) AssertionIDRef;
#endif
	%newobject AssertionIDRef_get;
	LassoNodeList *AssertionIDRef;

#ifndef SWIG_PHP_RENAMES
	%rename(assertionURIRef) AssertionURIRef;
#endif
	%newobject AssertionURIRef_get;
	LassoStringList *AssertionURIRef;

#ifndef SWIG_PHP_RENAMES
	%rename(assertion) Assertion;
#endif
	%newobject Assertion_get;
	LassoNodeList *Assertion;

#ifndef SWIG_PHP_RENAMES
	%rename(encryptedAssertion) EncryptedAssertion;
#endif
	%newobject EncryptedAssertion_get;
	LassoNodeList *EncryptedAssertion;


	/* Constructor, Destructor & Static Methods */
	LassoSaml2Advice();
	~LassoSaml2Advice();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* AssertionIDRef */

#define LassoSaml2Advice_get_AssertionIDRef(self) get_node_list((self)->AssertionIDRef)
#define LassoSaml2Advice_AssertionIDRef_get(self) get_node_list((self)->AssertionIDRef)
#define LassoSaml2Advice_set_AssertionIDRef(self,value) set_node_list(&(self)->AssertionIDRef, (value))
#define LassoSaml2Advice_AssertionIDRef_set(self,value) set_node_list(&(self)->AssertionIDRef, (value))
                    

/* AssertionURIRef */

#define LassoSaml2Advice_get_AssertionURIRef(self) get_string_list((self)->AssertionURIRef)
#define LassoSaml2Advice_AssertionURIRef_get(self) get_string_list((self)->AssertionURIRef)
#define LassoSaml2Advice_set_AssertionURIRef(self,value) set_string_list(&(self)->AssertionURIRef, (value))
#define LassoSaml2Advice_AssertionURIRef_set(self,value) set_string_list(&(self)->AssertionURIRef, (value))
                    

/* Assertion */

#define LassoSaml2Advice_get_Assertion(self) get_node_list((self)->Assertion)
#define LassoSaml2Advice_Assertion_get(self) get_node_list((self)->Assertion)
#define LassoSaml2Advice_set_Assertion(self,value) set_node_list(&(self)->Assertion, (value))
#define LassoSaml2Advice_Assertion_set(self,value) set_node_list(&(self)->Assertion, (value))
                    

/* EncryptedAssertion */

#define LassoSaml2Advice_get_EncryptedAssertion(self) get_node_list((self)->EncryptedAssertion)
#define LassoSaml2Advice_EncryptedAssertion_get(self) get_node_list((self)->EncryptedAssertion)
#define LassoSaml2Advice_set_EncryptedAssertion(self,value) set_node_list(&(self)->EncryptedAssertion, (value))
#define LassoSaml2Advice_EncryptedAssertion_set(self,value) set_node_list(&(self)->EncryptedAssertion, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2Advice lasso_saml2_advice_new
#define delete_LassoSaml2Advice(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2Advice_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

