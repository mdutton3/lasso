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
%rename(Saml2Assertion) LassoSaml2Assertion;
#endif
typedef struct {
#ifndef SWIG_PHP_RENAMES
	%rename(version) Version;
#endif
	char *Version;
#ifndef SWIG_PHP_RENAMES
	%rename(iD) ID;
#endif
	char *ID;
#ifndef SWIG_PHP_RENAMES
	%rename(issueInstant) IssueInstant;
#endif
	char *IssueInstant;
} LassoSaml2Assertion;
%extend LassoSaml2Assertion {

#ifndef SWIG_PHP_RENAMES
	%rename(issuer) Issuer;
#endif
	%newobject Issuer_get;
	LassoSaml2NameID *Issuer;

#ifndef SWIG_PHP_RENAMES
	%rename(subject) Subject;
#endif
	%newobject Subject_get;
	LassoSaml2Subject *Subject;

#ifndef SWIG_PHP_RENAMES
	%rename(conditions) Conditions;
#endif
	%newobject Conditions_get;
	LassoSaml2Conditions *Conditions;

#ifndef SWIG_PHP_RENAMES
	%rename(advice) Advice;
#endif
	%newobject Advice_get;
	LassoSaml2Advice *Advice;

#ifndef SWIG_PHP_RENAMES
	%rename(statement) Statement;
#endif
	%newobject Statement_get;
	LassoNodeList *Statement;

#ifndef SWIG_PHP_RENAMES
	%rename(authnStatement) AuthnStatement;
#endif
	%newobject AuthnStatement_get;
	LassoNodeList *AuthnStatement;

#ifndef SWIG_PHP_RENAMES
	%rename(authzDecisionStatement) AuthzDecisionStatement;
#endif
	%newobject AuthzDecisionStatement_get;
	LassoNodeList *AuthzDecisionStatement;

#ifndef SWIG_PHP_RENAMES
	%rename(attributeStatement) AttributeStatement;
#endif
	%newobject AttributeStatement_get;
	LassoNodeList *AttributeStatement;


	/* Constructor, Destructor & Static Methods */
	LassoSaml2Assertion();
	~LassoSaml2Assertion();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Issuer */

#define LassoSaml2Assertion_get_Issuer(self) get_node((self)->Issuer)
#define LassoSaml2Assertion_Issuer_get(self) get_node((self)->Issuer)
#define LassoSaml2Assertion_set_Issuer(self,value) set_node((gpointer*)&(self)->Issuer, (value))
#define LassoSaml2Assertion_Issuer_set(self,value) set_node((gpointer*)&(self)->Issuer, (value))
                    

/* Subject */

#define LassoSaml2Assertion_get_Subject(self) get_node((self)->Subject)
#define LassoSaml2Assertion_Subject_get(self) get_node((self)->Subject)
#define LassoSaml2Assertion_set_Subject(self,value) set_node((gpointer*)&(self)->Subject, (value))
#define LassoSaml2Assertion_Subject_set(self,value) set_node((gpointer*)&(self)->Subject, (value))
                    

/* Conditions */

#define LassoSaml2Assertion_get_Conditions(self) get_node((self)->Conditions)
#define LassoSaml2Assertion_Conditions_get(self) get_node((self)->Conditions)
#define LassoSaml2Assertion_set_Conditions(self,value) set_node((gpointer*)&(self)->Conditions, (value))
#define LassoSaml2Assertion_Conditions_set(self,value) set_node((gpointer*)&(self)->Conditions, (value))
                    

/* Advice */

#define LassoSaml2Assertion_get_Advice(self) get_node((self)->Advice)
#define LassoSaml2Assertion_Advice_get(self) get_node((self)->Advice)
#define LassoSaml2Assertion_set_Advice(self,value) set_node((gpointer*)&(self)->Advice, (value))
#define LassoSaml2Assertion_Advice_set(self,value) set_node((gpointer*)&(self)->Advice, (value))
                    

/* Statement */

#define LassoSaml2Assertion_get_Statement(self) get_node_list((self)->Statement)
#define LassoSaml2Assertion_Statement_get(self) get_node_list((self)->Statement)
#define LassoSaml2Assertion_set_Statement(self,value) set_node_list(&(self)->Statement, (value))
#define LassoSaml2Assertion_Statement_set(self,value) set_node_list(&(self)->Statement, (value))
                    

/* AuthnStatement */

#define LassoSaml2Assertion_get_AuthnStatement(self) get_node_list((self)->AuthnStatement)
#define LassoSaml2Assertion_AuthnStatement_get(self) get_node_list((self)->AuthnStatement)
#define LassoSaml2Assertion_set_AuthnStatement(self,value) set_node_list(&(self)->AuthnStatement, (value))
#define LassoSaml2Assertion_AuthnStatement_set(self,value) set_node_list(&(self)->AuthnStatement, (value))
                    

/* AuthzDecisionStatement */

#define LassoSaml2Assertion_get_AuthzDecisionStatement(self) get_node_list((self)->AuthzDecisionStatement)
#define LassoSaml2Assertion_AuthzDecisionStatement_get(self) get_node_list((self)->AuthzDecisionStatement)
#define LassoSaml2Assertion_set_AuthzDecisionStatement(self,value) set_node_list(&(self)->AuthzDecisionStatement, (value))
#define LassoSaml2Assertion_AuthzDecisionStatement_set(self,value) set_node_list(&(self)->AuthzDecisionStatement, (value))
                    

/* AttributeStatement */

#define LassoSaml2Assertion_get_AttributeStatement(self) get_node_list((self)->AttributeStatement)
#define LassoSaml2Assertion_AttributeStatement_get(self) get_node_list((self)->AttributeStatement)
#define LassoSaml2Assertion_set_AttributeStatement(self,value) set_node_list(&(self)->AttributeStatement, (value))
#define LassoSaml2Assertion_AttributeStatement_set(self,value) set_node_list(&(self)->AttributeStatement, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2Assertion lasso_saml2_assertion_new
#define delete_LassoSaml2Assertion(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2Assertion_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

