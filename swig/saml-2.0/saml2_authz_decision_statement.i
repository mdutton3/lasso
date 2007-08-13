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
%rename(Saml2AuthzDecisionStatement) LassoSaml2AuthzDecisionStatement;
#endif
typedef struct {
#ifndef SWIG_PHP_RENAMES
	%rename(resource) Resource;
#endif
	char *Resource;
#ifndef SWIG_PHP_RENAMES
	%rename(decision) Decision;
#endif
	char *Decision;
} LassoSaml2AuthzDecisionStatement;
%extend LassoSaml2AuthzDecisionStatement {

#ifndef SWIG_PHP_RENAMES
	%rename(action) Action;
#endif
	%newobject Action_get;
	LassoSaml2Action *Action;

#ifndef SWIG_PHP_RENAMES
	%rename(evidence) Evidence;
#endif
	%newobject Evidence_get;
	LassoSaml2Evidence *Evidence;

	/* inherited from Saml2StatementAbstract */

	/* Constructor, Destructor & Static Methods */
	LassoSaml2AuthzDecisionStatement();
	~LassoSaml2AuthzDecisionStatement();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Action */

#define LassoSaml2AuthzDecisionStatement_get_Action(self) get_node((self)->Action)
#define LassoSaml2AuthzDecisionStatement_Action_get(self) get_node((self)->Action)
#define LassoSaml2AuthzDecisionStatement_set_Action(self,value) set_node((gpointer*)&(self)->Action, (value))
#define LassoSaml2AuthzDecisionStatement_Action_set(self,value) set_node((gpointer*)&(self)->Action, (value))
                    

/* Evidence */

#define LassoSaml2AuthzDecisionStatement_get_Evidence(self) get_node((self)->Evidence)
#define LassoSaml2AuthzDecisionStatement_Evidence_get(self) get_node((self)->Evidence)
#define LassoSaml2AuthzDecisionStatement_set_Evidence(self,value) set_node((gpointer*)&(self)->Evidence, (value))
#define LassoSaml2AuthzDecisionStatement_Evidence_set(self,value) set_node((gpointer*)&(self)->Evidence, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2AuthzDecisionStatement lasso_saml2_authz_decision_statement_new
#define delete_LassoSaml2AuthzDecisionStatement(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2AuthzDecisionStatement_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

