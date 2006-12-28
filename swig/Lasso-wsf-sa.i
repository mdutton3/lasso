/* -*- Mode: c; c-basic-offset: 8 -*-
 *
 * $Id$
 *
 * SWIG bindings for Lasso Library
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

%{
#include <lasso/xml/sa_credentials.h>
#include <lasso/xml/sa_sasl_request.h>
#include <lasso/xml/sa_sasl_response.h>
%}

/* SASL mechanisms */
#ifndef SWIGPHP4
%rename(SASL_MECH_ANONYMOUS) LASSO_SASL_MECH_ANONYMOUS;
%rename(SASL_MECH_PLAIN) LASSO_SASL_MECH_PLAIN;
%rename(SASL_MECH_CRAM_MD5) LASSO_SASL_MECH_CRAM_MD5;
#endif
#define LASSO_SASL_MECH_ANONYMOUS "ANONYMOUS"
#define LASSO_SASL_MECH_PLAIN     "PLAIN"
#define LASSO_SASL_MECH_CRAM_MD5  "CRAM-MD5"

/* SASL result codes: */
#define SASL_CONTINUE    1   /* another step is needed in authentication */
#define SASL_OK          0   /* successful result */
#define SASL_FAIL       -1   /* generic failure */
#define SASL_NOMEM      -2   /* memory shortage failure */
#define SASL_BUFOVER    -3   /* overflowed buffer */
#define SASL_NOMECH     -4   /* mechanism not supported */
#define SASL_BADPROT    -5   /* bad protocol / cancel */
#define SASL_NOTDONE    -6   /* can't request info until later in exchange */
#define SASL_BADPARAM   -7   /* invalid parameter supplied */
#define SASL_TRYAGAIN   -8   /* transient failure (e.g., weak key) */
#define SASL_BADMAC	-9   /* integrity check failed */
#define SASL_NOTINIT    -12  /* SASL library not initialized */
			     /* -- client only codes -- */
#define SASL_INTERACT    2   /* needs user interaction */
#define SASL_BADSERV    -10  /* server failed mutual authentication step */
#define SASL_WRONGMECH  -11  /* mechanism doesn't support requested feature */
			     /* -- server only codes -- */
#define SASL_BADAUTH    -13  /* authentication failure */
#define SASL_NOAUTHZ    -14  /* authorization failure */
#define SASL_TOOWEAK    -15  /* mechanism too weak for this user */
#define SASL_ENCRYPT    -16  /* encryption needed to use mechanism */
#define SASL_TRANS      -17  /* One time use of a plaintext password will
				enable requested mechanism for user */
#define SASL_EXPIRED    -18  /* passphrase expired, has to be reset */
#define SASL_DISABLED   -19  /* account disabled */
#define SASL_NOUSER     -20  /* user not found */
#define SASL_BADVERS    -23  /* version mismatch with plug-in */
#define SASL_UNAVAIL    -24  /* remote authentication server unavailable */
#define SASL_NOVERIFY   -26  /* user exists, but no verifier for user */
			     /* -- codes for password setting -- */
#define SASL_PWLOCK     -21  /* passphrase locked */
#define SASL_NOCHANGE   -22  /* requested change was not needed */
#define SASL_WEAKPASS   -27  /* passphrase is too weak for security policy */
#define SASL_NOUSERPASS -28  /* user supplied passwords not permitted */

/* WSF prefix & href */
#ifndef SWIGPHP4
%rename(SA_HREF) LASSO_SA_HREF;
%rename(SA_PREFIX) LASSO_SA_PREFIX;
#endif
#define LASSO_SA_HREF "urn:liberty:sa:2004-04"
#define LASSO_SA_PREFIX "sa"

/* WSF status code */
#ifndef SWIGPHP4
%rename(SA_STATUS_CODE_CONTINUE) LASSO_SA_STATUS_CODE_CONTINUE;
%rename(SA_STATUS_CODE_ABORT) LASSO_SA_STATUS_CODE_ABORT;
%rename(SA_STATUS_CODE_OK) LASSO_SA_STATUS_CODE_OK;
#endif
#define LASSO_SA_STATUS_CODE_CONTINUE "continue"
#define LASSO_SA_STATUS_CODE_ABORT "abort"
#define LASSO_SA_STATUS_CODE_OK "OK"



/***********************************************************************
 ***********************************************************************
 * XML Elements in Sa Namespace
 ***********************************************************************
 ***********************************************************************/

/***********************************************************************
 * sa:SaCredentials
 ***********************************************************************/

#ifndef SWIGPHP4
%rename(SaCredentials) LassoSaCredentials;
#endif
typedef struct {
	/* Attributes */

} LassoSaCredentials;
%extend LassoSaCredentials {
	/* Attributes */
#ifndef SWIGPHP4
	%rename(any) any;
#endif
	%newobject any_get;
	LassoNodeList *any;

	/* Constructor, Destructor & Static Methods */

	LassoSaCredentials();

	~LassoSaCredentials();

	int addAssertion(LassoSamlAssertion *assertion);

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */
/* any */
#define LassoSaCredentials_get_any(self) get_node_list((self)->any)
#define LassoSaCredentials_any_get(self) get_node_list((self)->any)
#define LassoSaCredentials_set_any(self, value) set_node_list(&(self)->any, (value))
#define LassoSaCredentials_any_set(self, value) set_node_list(&(self)->any, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoSaCredentials lasso_sa_credentials_new
#define delete_LassoSaCredentials(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaCredentials_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Implementation of methods */
#define LassoSaCredentials_addAssertion lasso_sa_credentials_add_assertion

%}


/***********************************************************************
 * sa:SaSASLRequest
 ***********************************************************************/

#ifndef SWIGPHP4
%rename(SaSASLRequest) LassoSaSASLRequest;
#endif
typedef struct {
	/* Attributes */

	char *mechanism;
	
	char *authzID;

	char *advisoryAuthnID;

	char *id;

} LassoSaSASLRequest;
%extend LassoSaSASLRequest {
	/* Attributes */
#ifndef SWIGPHP4
	%rename(data) Data;
#endif
	%newobject Data_get;
	LassoNodeList *Data;

#ifndef SWIGPHP4
	%rename(requestAuthnContext) RequestAuthnContext;
#endif
	%newobject RequestAuthnContext_get;
	LassoNodeList *RequestAuthnContext;

	/* Constructor, Destructor & Static Methods */

	LassoSaSASLRequest(char *mechanism);

	~LassoSaSASLRequest();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */
/* Data */
#define LassoSaSASLRequest_get_Data(self) get_node_list((self)->Data)
#define LassoSaSASLRequest_Data_get(self) get_node_list((self)->Data)
#define LassoSaSASLRequest_set_Data(self, value) set_node_list(&(self)->Data, (value))
#define LassoSaSASLRequest_Data_set(self, value) set_node_list(&(self)->Data, (value))

/* RequestAuthnContext */
#define LassoSaSASLRequest_get_RequestAuthnContext(self) get_node((self)->RequestAuthnContext)
#define LassoSaSASLRequest_RequestAuthnContext_get(self) get_node((self)->RequestAuthnContext)
#define LassoSaSASLRequest_set_RequestAuthnContext(self, value) set_node((gpointer *) &(self)->RequestAuthnContext, (value))
#define LassoSaSASLRequest_RequestAuthnContext_set(self, value) set_node((gpointer *) &(self)->RequestAuthnContext, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoSaSASLRequest lasso_sa_sasl_request_new
#define delete_LassoSaSASLRequest(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaSASLRequest_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

/***********************************************************************
 * sa:SaSASLResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SaSASLResponse) LassoSaSASLResponse;
#endif
typedef struct {
	/* Attributes */

	char *serverMechanism;

	char *id;

} LassoSaSASLResponse;
%extend LassoSaSASLResponse {
	/* Attributes */
#ifndef SWIGPHP4
	%rename(data) Data;
#endif
	%newobject Data_get;
	LassoNodeList *Data;

#ifndef SWIGPHP4
	%rename(credentials) Credentials;
#endif
	%newobject Credentials_get;
	LassoNodeList *Credentials;

#ifndef SWIGPHP4
	%rename(resourceOffering) ResourceOffering;
#endif
	%newobject ResourceOffering_get;
	LassoNodeList *ResourceOffering;

#ifndef SWIGPHP4
	%rename(passwordTransforms) PasswordTransforms;
#endif
	%newobject PasswordTransforms_get;
	LassoNodeList *PasswordTransforms;

#ifndef SWIGPHP4
	%rename(status) Status;
#endif
	%newobject Status_get;
	LassoUtilityStatus *Status;

	/* Constructor, Destructor & Static Methods */

	LassoSaSASLResponse(LassoUtilityStatus *status);

	~LassoSaSASLResponse();

	int addCredentials(LassoSaCredentials *credentials);

	int addResourceOffering(LassoDiscoResourceOffering *resourceOffering);

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

}

%{

/* Attributes Implementations */
/* Data */
#define LassoSaSASLResponse_get_Data(self) get_node_list((self)->Data)
#define LassoSaSASLResponse_Data_get(self) get_node_list((self)->Data)
#define LassoSaSASLResponse_set_Data(self, value) set_node_list(&(self)->Data, (value))
#define LassoSaSASLResponse_Data_set(self, value) set_node_list(&(self)->Data, (value))

/* Credentials */
#define LassoSaSASLResponse_get_Credentials(self) get_node_list((self)->Credentials)
#define LassoSaSASLResponse_Credentials_get(self) get_node_list((self)->Credentials)
#define LassoSaSASLResponse_set_Credentials(self, value) set_node_list(&(self)->Credentials, (value))
#define LassoSaSASLResponse_Credentials_set(self, value) set_node_list(&(self)->Credentials, (value))

/* ResourceOffering */
#define LassoSaSASLResponse_get_ResourceOffering(self) get_node_list((self)->ResourceOffering)
#define LassoSaSASLResponse_ResourceOffering_get(self) get_node_list((self)->ResourceOffering)
#define LassoSaSASLResponse_set_ResourceOffering(self, value) set_node_list(&(self)->ResourceOffering, (value))
#define LassoSaSASLResponse_ResourceOffering_set(self, value) set_node_list(&(self)->ResourceOffering, (value))

/* PasswordTransforms */
#define LassoSaSASLResponse_get_PasswordTransforms(self) get_node_list((self)->PasswordTransforms)
#define LassoSaSASLResponse_PasswordTransforms_get(self) get_node_list((self)->PasswordTransforms)
#define LassoSaSASLResponse_set_PasswordTransforms(self, value) set_node_list(&(self)->PasswordTransforms, (value))
#define LassoSaSASLResponse_PasswordTransforms_set(self, value) set_node_list(&(self)->PasswordTransforms, (value))

/* ResourceOffering */
#define LassoSaSASLResponse_get_ResourceOffering(self) get_node_list((self)->ResourceOffering)
#define LassoSaSASLResponse_ResourceOffering_get(self) get_node_list((self)->ResourceOffering)
#define LassoSaSASLResponse_set_ResourceOffering(self, value) set_node_list(&(self)->ResourceOffering, (value))
#define LassoSaSASLResponse_ResourceOffering_set(self, value) set_node_list(&(self)->ResourceOffering, (value))

/* Status */
#define LassoSaSASLResponse_get_Status(self) get_node((self)->Status)
#define LassoSaSASLResponse_Status_get(self) get_node((self)->Status)
#define LassoSaSASLResponse_set_Status(self, value) set_node((gpointer *) &(self)->Status, (value))
#define LassoSaSASLResponse_Status_set(self, value) set_node((gpointer *) &(self)->Status, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoSaSASLResponse lasso_sa_sasl_response_new
#define delete_LassoSaSASLResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaSASLResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Implementations of methods */
#define LassoSaSASLResponse_addCredentials lasso_sa_sasl_response_add_credentials
#define LassoSaSASLResponse_addResourceOffering lasso_sa_sasl_response_add_resource_offering

%}
