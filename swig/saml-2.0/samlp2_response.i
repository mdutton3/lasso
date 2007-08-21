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
%rename(Samlp2Response) LassoSamlp2Response;
#endif
typedef struct {
} LassoSamlp2Response;
%extend LassoSamlp2Response {

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

	/* inherited from Samlp2StatusResponse */
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
	%rename(status) Status;
#endif
	%newobject *Status_get;
	LassoSamlp2Status *Status;

#ifndef SWIG_PHP_RENAMES
	%rename(iD) ID;
#endif
	char *ID;
#ifndef SWIG_PHP_RENAMES
	%rename(inResponseTo) InResponseTo;
#endif
	char *InResponseTo;
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
	LassoSamlp2Response();
	~LassoSamlp2Response();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Assertion */

#define LassoSamlp2Response_get_Assertion(self) get_node_list((self)->Assertion)
#define LassoSamlp2Response_Assertion_get(self) get_node_list((self)->Assertion)
#define LassoSamlp2Response_set_Assertion(self,value) set_node_list((gpointer*)&(self)->Assertion, (value))
#define LassoSamlp2Response_Assertion_set(self,value) set_node_list((gpointer*)&(self)->Assertion, (value))
                    

/* EncryptedAssertion */

#define LassoSamlp2Response_get_EncryptedAssertion(self) get_node_list((self)->EncryptedAssertion)
#define LassoSamlp2Response_EncryptedAssertion_get(self) get_node_list((self)->EncryptedAssertion)
#define LassoSamlp2Response_set_EncryptedAssertion(self,value) set_node_list((gpointer*)&(self)->EncryptedAssertion, (value))
#define LassoSamlp2Response_EncryptedAssertion_set(self,value) set_node_list((gpointer*)&(self)->EncryptedAssertion, (value))
                    

/* inherited from StatusResponse */

/* Issuer */

#define LassoSamlp2Response_get_Issuer(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Issuer)
#define LassoSamlp2Response_Issuer_get(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Issuer)
#define LassoSamlp2Response_set_Issuer(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Issuer, (value))
#define LassoSamlp2Response_Issuer_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Issuer, (value))
                    

/* Extensions */

#define LassoSamlp2Response_get_Extensions(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Extensions)
#define LassoSamlp2Response_Extensions_get(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Extensions)
#define LassoSamlp2Response_set_Extensions(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Extensions, (value))
#define LassoSamlp2Response_Extensions_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Extensions, (value))
                    

/* Status */

#define LassoSamlp2Response_get_Status(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Status)
#define LassoSamlp2Response_Status_get(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Status)
#define LassoSamlp2Response_set_Status(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Status, (value))
#define LassoSamlp2Response_Status_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Status, (value))
                    

/* ID */

#define LassoSamlp2Response_get_ID(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->ID
#define LassoSamlp2Response_ID_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->ID

#define LassoSamlp2Response_set_ID(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->ID, (value))
#define LassoSamlp2Response_ID_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->ID, (value))

/* InResponseTo */

#define LassoSamlp2Response_get_InResponseTo(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->InResponseTo
#define LassoSamlp2Response_InResponseTo_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->InResponseTo

#define LassoSamlp2Response_set_InResponseTo(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->InResponseTo, (value))
#define LassoSamlp2Response_InResponseTo_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->InResponseTo, (value))

/* Version */

#define LassoSamlp2Response_get_Version(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Version
#define LassoSamlp2Response_Version_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Version

#define LassoSamlp2Response_set_Version(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Version, (value))
#define LassoSamlp2Response_Version_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Version, (value))

/* IssueInstant */

#define LassoSamlp2Response_get_IssueInstant(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->IssueInstant
#define LassoSamlp2Response_IssueInstant_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->IssueInstant

#define LassoSamlp2Response_set_IssueInstant(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->IssueInstant, (value))
#define LassoSamlp2Response_IssueInstant_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->IssueInstant, (value))

/* Destination */

#define LassoSamlp2Response_get_Destination(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Destination
#define LassoSamlp2Response_Destination_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Destination

#define LassoSamlp2Response_set_Destination(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Destination, (value))
#define LassoSamlp2Response_Destination_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Destination, (value))

/* Consent */

#define LassoSamlp2Response_get_Consent(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Consent
#define LassoSamlp2Response_Consent_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Consent

#define LassoSamlp2Response_set_Consent(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Consent, (value))
#define LassoSamlp2Response_Consent_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Consent, (value))


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2Response lasso_samlp2_response_new
#define delete_LassoSamlp2Response(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2Response_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

