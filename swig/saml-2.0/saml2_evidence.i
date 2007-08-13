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
%rename(Saml2Evidence) LassoSaml2Evidence;
#endif
typedef struct {
} LassoSaml2Evidence;
%extend LassoSaml2Evidence {

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
	LassoSaml2Evidence();
	~LassoSaml2Evidence();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* AssertionIDRef */

#define LassoSaml2Evidence_get_AssertionIDRef(self) get_node((self)->AssertionIDRef)
#define LassoSaml2Evidence_AssertionIDRef_get(self) get_node((self)->AssertionIDRef)
#define LassoSaml2Evidence_set_AssertionIDRef(self,value) set_node((gpointer*)&(self)->AssertionIDRef, (value))
#define LassoSaml2Evidence_AssertionIDRef_set(self,value) set_node((gpointer*)&(self)->AssertionIDRef, (value))
                    

/* AssertionURIRef */

#define LassoSaml2Evidence_get_AssertionURIRef(self) get_node((self)->AssertionURIRef)
#define LassoSaml2Evidence_AssertionURIRef_get(self) get_node((self)->AssertionURIRef)
#define LassoSaml2Evidence_set_AssertionURIRef(self,value) set_node((gpointer*)&(self)->AssertionURIRef, (value))
#define LassoSaml2Evidence_AssertionURIRef_set(self,value) set_node((gpointer*)&(self)->AssertionURIRef, (value))
                    

/* Assertion */

#define LassoSaml2Evidence_get_Assertion(self) get_node((self)->Assertion)
#define LassoSaml2Evidence_Assertion_get(self) get_node((self)->Assertion)
#define LassoSaml2Evidence_set_Assertion(self,value) set_node((gpointer*)&(self)->Assertion, (value))
#define LassoSaml2Evidence_Assertion_set(self,value) set_node((gpointer*)&(self)->Assertion, (value))
                    

/* EncryptedAssertion */

#define LassoSaml2Evidence_get_EncryptedAssertion(self) get_node((self)->EncryptedAssertion)
#define LassoSaml2Evidence_EncryptedAssertion_get(self) get_node((self)->EncryptedAssertion)
#define LassoSaml2Evidence_set_EncryptedAssertion(self,value) set_node((gpointer*)&(self)->EncryptedAssertion, (value))
#define LassoSaml2Evidence_EncryptedAssertion_set(self,value) set_node((gpointer*)&(self)->EncryptedAssertion, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2Evidence lasso_saml2_evidence_new
#define delete_LassoSaml2Evidence(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2Evidence_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

