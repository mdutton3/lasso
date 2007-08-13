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
%rename(Samlp2StatusResponse) LassoSamlp2StatusResponse;
#endif
typedef struct {
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
} LassoSamlp2StatusResponse;
%extend LassoSamlp2StatusResponse {

#ifndef SWIG_PHP_RENAMES
	%rename(issuer) Issuer;
#endif
	%newobject Issuer_get;
	LassoSaml2NameID *Issuer;

#ifndef SWIG_PHP_RENAMES
	%rename(extensions) Extensions;
#endif
	%newobject Extensions_get;
	LassoSamlp2Extensions *Extensions;

#ifndef SWIG_PHP_RENAMES
	%rename(status) Status;
#endif
	%newobject Status_get;
	LassoSamlp2Status *Status;


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2StatusResponse();
	~LassoSamlp2StatusResponse();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Issuer */

#define LassoSamlp2StatusResponse_get_Issuer(self) get_node((self)->Issuer)
#define LassoSamlp2StatusResponse_Issuer_get(self) get_node((self)->Issuer)
#define LassoSamlp2StatusResponse_set_Issuer(self,value) set_node((gpointer*)&(self)->Issuer, (value))
#define LassoSamlp2StatusResponse_Issuer_set(self,value) set_node((gpointer*)&(self)->Issuer, (value))
                    

/* Extensions */

#define LassoSamlp2StatusResponse_get_Extensions(self) get_node((self)->Extensions)
#define LassoSamlp2StatusResponse_Extensions_get(self) get_node((self)->Extensions)
#define LassoSamlp2StatusResponse_set_Extensions(self,value) set_node((gpointer*)&(self)->Extensions, (value))
#define LassoSamlp2StatusResponse_Extensions_set(self,value) set_node((gpointer*)&(self)->Extensions, (value))
                    

/* Status */

#define LassoSamlp2StatusResponse_get_Status(self) get_node((self)->Status)
#define LassoSamlp2StatusResponse_Status_get(self) get_node((self)->Status)
#define LassoSamlp2StatusResponse_set_Status(self,value) set_node((gpointer*)&(self)->Status, (value))
#define LassoSamlp2StatusResponse_Status_set(self,value) set_node((gpointer*)&(self)->Status, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2StatusResponse lasso_samlp2_status_response_new
#define delete_LassoSamlp2StatusResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2StatusResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

