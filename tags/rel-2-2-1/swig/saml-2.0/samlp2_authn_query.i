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
%rename(Samlp2AuthnQuery) LassoSamlp2AuthnQuery;
#endif
typedef struct {
#ifndef SWIG_PHP_RENAMES
	%rename(sessionIndex) SessionIndex;
#endif
	char *SessionIndex;
} LassoSamlp2AuthnQuery;
%extend LassoSamlp2AuthnQuery {

#ifndef SWIG_PHP_RENAMES
	%rename(requestedAuthnContext) RequestedAuthnContext;
#endif
	%newobject RequestedAuthnContext_get;
	LassoSamlp2RequestedAuthnContext *RequestedAuthnContext;

	/* inherited from Samlp2SubjectQueryAbstract */
#ifndef SWIG_PHP_RENAMES
	%rename(subject) Subject;
#endif
	%newobject *Subject_get;
	LassoSaml2Subject *Subject;

	/* inherited from Samlp2RequestAbstract */
#ifndef SWIG_PHP_RENAMES
	%rename(issuer) Issuer;
#endif
	%newobject *Issuer_get;
	LassoSaml2NameID *Issuer;

#ifndef SWIG_PHP_RENAMES
	%rename(extensions) Extensions;
#endif
	%newobject *Extensions_get;
	LassoSamlp2Extensions *Extensions;

#ifndef SWIG_PHP_RENAMES
	%rename(iD) ID;
#endif
	char *ID;
#ifndef SWIG_PHP_RENAMES
	%rename(version) Version;
#endif
	char *Version;
#ifndef SWIG_PHP_RENAMES
	%rename(issueInstant) IssueInstant;
#endif
	char *IssueInstant;
#ifndef SWIG_PHP_RENAMES
	%rename(destination) Destination;
#endif
	char *Destination;
#ifndef SWIG_PHP_RENAMES
	%rename(consent) Consent;
#endif
	char *Consent;

	/* Constructor, Destructor & Static Methods */
	LassoSamlp2AuthnQuery();
	~LassoSamlp2AuthnQuery();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* RequestedAuthnContext */

#define LassoSamlp2AuthnQuery_get_RequestedAuthnContext(self) get_node((self)->RequestedAuthnContext)
#define LassoSamlp2AuthnQuery_RequestedAuthnContext_get(self) get_node((self)->RequestedAuthnContext)
#define LassoSamlp2AuthnQuery_set_RequestedAuthnContext(self,value) set_node((gpointer*)&(self)->RequestedAuthnContext, (value))
#define LassoSamlp2AuthnQuery_RequestedAuthnContext_set(self,value) set_node((gpointer*)&(self)->RequestedAuthnContext, (value))
                    

/* inherited from SubjectQueryAbstract */

/* Subject */

#define LassoSamlp2AuthnQuery_get_Subject(self) get_node(LASSO_SAMLP2_SUBJECT_QUERY_ABSTRACT(self)->Subject)
#define LassoSamlp2AuthnQuery_Subject_get(self) get_node(LASSO_SAMLP2_SUBJECT_QUERY_ABSTRACT(self)->Subject)
#define LassoSamlp2AuthnQuery_set_Subject(self,value) set_node((gpointer*)&LASSO_SAMLP2_SUBJECT_QUERY_ABSTRACT(self)->Subject, (value))
#define LassoSamlp2AuthnQuery_Subject_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_SUBJECT_QUERY_ABSTRACT(self)->Subject, (value))
                    

/* inherited from RequestAbstract */

/* Issuer */

#define LassoSamlp2AuthnQuery_get_Issuer(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer)
#define LassoSamlp2AuthnQuery_Issuer_get(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer)
#define LassoSamlp2AuthnQuery_set_Issuer(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer, (value))
#define LassoSamlp2AuthnQuery_Issuer_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer, (value))
                    

/* Extensions */

#define LassoSamlp2AuthnQuery_get_Extensions(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions)
#define LassoSamlp2AuthnQuery_Extensions_get(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions)
#define LassoSamlp2AuthnQuery_set_Extensions(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions, (value))
#define LassoSamlp2AuthnQuery_Extensions_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions, (value))
                    

/* ID */

#define LassoSamlp2AuthnQuery_get_ID(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID
#define LassoSamlp2AuthnQuery_ID_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID

#define LassoSamlp2AuthnQuery_set_ID(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID, (value))
#define LassoSamlp2AuthnQuery_ID_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID, (value))

/* Version */

#define LassoSamlp2AuthnQuery_get_Version(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version
#define LassoSamlp2AuthnQuery_Version_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version

#define LassoSamlp2AuthnQuery_set_Version(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version, (value))
#define LassoSamlp2AuthnQuery_Version_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version, (value))

/* IssueInstant */

#define LassoSamlp2AuthnQuery_get_IssueInstant(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant
#define LassoSamlp2AuthnQuery_IssueInstant_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant

#define LassoSamlp2AuthnQuery_set_IssueInstant(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant, (value))
#define LassoSamlp2AuthnQuery_IssueInstant_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant, (value))

/* Destination */

#define LassoSamlp2AuthnQuery_get_Destination(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination
#define LassoSamlp2AuthnQuery_Destination_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination

#define LassoSamlp2AuthnQuery_set_Destination(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination, (value))
#define LassoSamlp2AuthnQuery_Destination_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination, (value))

/* Consent */

#define LassoSamlp2AuthnQuery_get_Consent(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent
#define LassoSamlp2AuthnQuery_Consent_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent

#define LassoSamlp2AuthnQuery_set_Consent(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent, (value))
#define LassoSamlp2AuthnQuery_Consent_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent, (value))


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2AuthnQuery lasso_samlp2_authn_query_new
#define delete_LassoSamlp2AuthnQuery(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2AuthnQuery_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

