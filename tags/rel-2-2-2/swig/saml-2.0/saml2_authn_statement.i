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
%rename(Saml2AuthnStatement) LassoSaml2AuthnStatement;
#endif
typedef struct {
#ifndef SWIG_PHP_RENAMES
	%rename(authnInstant) AuthnInstant;
#endif
	char *AuthnInstant;
#ifndef SWIG_PHP_RENAMES
	%rename(sessionIndex) SessionIndex;
#endif
	char *SessionIndex;
#ifndef SWIG_PHP_RENAMES
	%rename(sessionNotOnOrAfter) SessionNotOnOrAfter;
#endif
	char *SessionNotOnOrAfter;
} LassoSaml2AuthnStatement;
%extend LassoSaml2AuthnStatement {

#ifndef SWIG_PHP_RENAMES
	%rename(subjectLocality) SubjectLocality;
#endif
	%newobject SubjectLocality_get;
	LassoSaml2SubjectLocality *SubjectLocality;

#ifndef SWIG_PHP_RENAMES
	%rename(authnContext) AuthnContext;
#endif
	%newobject AuthnContext_get;
	LassoSaml2AuthnContext *AuthnContext;

	/* inherited from Saml2StatementAbstract */

	/* Constructor, Destructor & Static Methods */
	LassoSaml2AuthnStatement();
	~LassoSaml2AuthnStatement();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* SubjectLocality */

#define LassoSaml2AuthnStatement_get_SubjectLocality(self) get_node((self)->SubjectLocality)
#define LassoSaml2AuthnStatement_SubjectLocality_get(self) get_node((self)->SubjectLocality)
#define LassoSaml2AuthnStatement_set_SubjectLocality(self,value) set_node((gpointer*)&(self)->SubjectLocality, (value))
#define LassoSaml2AuthnStatement_SubjectLocality_set(self,value) set_node((gpointer*)&(self)->SubjectLocality, (value))
                    

/* AuthnContext */

#define LassoSaml2AuthnStatement_get_AuthnContext(self) get_node((self)->AuthnContext)
#define LassoSaml2AuthnStatement_AuthnContext_get(self) get_node((self)->AuthnContext)
#define LassoSaml2AuthnStatement_set_AuthnContext(self,value) set_node((gpointer*)&(self)->AuthnContext, (value))
#define LassoSaml2AuthnStatement_AuthnContext_set(self,value) set_node((gpointer*)&(self)->AuthnContext, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2AuthnStatement lasso_saml2_authn_statement_new
#define delete_LassoSaml2AuthnStatement(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2AuthnStatement_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

