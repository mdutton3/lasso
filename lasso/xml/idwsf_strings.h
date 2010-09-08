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
 *
 */

/*
 * This header file copy part of the SOAP 1.1 specification you can found there:
 * http://www.w3.org/TR/soap12-part1/
 * whom copyright is:
 * Copyright © 2007 W3C® (MIT, ERCIM, Keio), All Rights Reserved. W3C liability, trademark and
 * document use rules apply.
 */


/**
 * SECTION:idwsf-strings
 * @short_description: Useful string constants
 *
 **/

#ifndef __LASSO_IDWSF_STRINGS_H__
#define __LASSO_IDWSF_STRINGS_H__

/*****************************************************************************/
/* Liberty Alliance ID-WSF                                                   */
/*****************************************************************************/

/* Liberty Security Mechanisms - 1st version */
#define LASSO_SECURITY_MECH_NULL   "urn:liberty:security:2003-08:null:null"

#define LASSO_SECURITY_MECH_X509   "urn:liberty:security:2005-02:null:X509"
#define LASSO_SECURITY_MECH_SAML   "urn:liberty:security:2005-02:null:SAML"
#define LASSO_SECURITY_MECH_BEARER "urn:liberty:security:2005-02:null:Bearer"

#define LASSO_SECURITY_MECH_TLS        "urn:liberty:security:2003-08:TLS:null"
#define LASSO_SECURITY_MECH_TLS_X509   "urn:liberty:security:2005-02:TLS:X509"
#define LASSO_SECURITY_MECH_TLS_SAML   "urn:liberty:security:2005-02:TLS:SAML"
#define LASSO_SECURITY_MECH_TLS_BEARER "urn:liberty:security:2005-02:TLS:Bearer"

#define LASSO_SECURITY_MECH_CLIENT_TLS        "urn:liberty:security:2003-08:ClientTLS:null"
#define LASSO_SECURITY_MECH_CLIENT_TLS_X509   "urn:liberty:security:2005-02:ClientTLS:X509"
#define LASSO_SECURITY_MECH_CLIENT_TLS_SAML   "urn:liberty:security:2005-02:ClientTLS:SAML"
#define LASSO_SECURITY_MECH_CLIENT_TLS_BEARER "urn:liberty:security:2005-02:ClientTLS:Bearer"


/* Liberty Security Mechanisms - latest version */

#define LASSO_SECURITY11_MECH_X509   "urn:liberty:security:2005-02:null:X509"
#define LASSO_SECURITY11_MECH_SAML   "urn:liberty:security:2005-02:null:SAML"
#define LASSO_SECURITY11_MECH_BEARER "urn:liberty:security:2005-02:null:Bearer"

#define LASSO_SECURITY11_MECH_TLS_X509   "urn:liberty:security:2005-02:TLS:X509"
#define LASSO_SECURITY11_MECH_TLS_SAML   "urn:liberty:security:2005-02:TLS:SAML"
#define LASSO_SECURITY11_MECH_TLS_BEARER "urn:liberty:security:2005-02:TLS:Bearer"

/* liberty wsf prefix & href */
/**
 * LASSO_DISCO_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_DISCO_HREF          "urn:liberty:disco:2003-08"
/**
 * LASSO_DISCO_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_DISCO_PREFIX        "disco"

/**
 * LASSO_EP_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_EP_HREF   "urn:liberty:id-sis-ep:2003-08"
/**
 * LASSO_EP_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_EP_PREFIX "ep"

/**
 * LASSO_PP10_HREF:
 *
 * Namespace for ID-SIS Personal Profile
 *
 */
#define LASSO_PP10_HREF   "urn:liberty:id-sis-pp:2003-08"
/**
 * LASSO_PP10_PREFIX:
 *
 * Preferred prefix for namespace of ID-SIS Personal Profile
 *
 */
#define LASSO_PP10_PREFIX "pp10"

/**
 * LASSO_PP11_HREF:
 *
 * Namespace for ID-SIS Personal Profile
 *
 */
#define LASSO_PP11_HREF   "urn:liberty:id-sis-pp:2005-05"
/**
 * LASSO_PP11_PREFIX:
 *
 * Preferred prefix for namespace of ID-SIS Personal Profile
 *
 */
#define LASSO_PP11_PREFIX "pp11"

/**
 * LASSO_IS_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IS_HREF "urn:liberty:is:2003-08"
/**
 * LASSO_IS_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IS_PREFIX "is"

/**
 * LASSO_SA_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_SA_HREF "urn:liberty:sa:2004-04"
/**
 * LASSO_SA_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_SA_PREFIX "sa"

/**
 * LASSO_SEC_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_SEC_HREF "urn:liberty:sec:2003-08"
/**
 * LASSO_SEC_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_SEC_PREFIX "sec"

#define LASSO_SA_SASL_SERVICE_NAME "idwsf"

/* Interaction Service (interact attribute of is:UserInteraction element ) */
#define LASSO_IS_INTERACT_ATTR_INTERACT_IF_NEEDED "is:interactIfNeeded"
#define LASSO_IS_INTERACT_ATTR_DO_NOT_INTERACT "is:doNotInteract"
#define LASSO_IS_INTERACT_ATTR_DO_NOT_INTERACT_FOR_DATA "is:doNotInteractForData"

/* status code */
#define LASSO_DISCO_STATUS_CODE_OK "OK"
#define LASSO_DISCO_STATUS_CODE_DISCO_OK "disco:OK"
#define LASSO_DISCO_STATUS_CODE_FAILED "Failed"
#define LASSO_DISCO_STATUS_CODE_REMOVE_ENTRY "RemoveEntry"
#define LASSO_DISCO_STATUS_CODE_FORBIDDEN "Forbidden"
#define LASSO_DISCO_STATUS_CODE_NO_RESULTS "NoResults"
#define LASSO_DISCO_STATUS_CODE_DIRECTIVES "Directive"

#define LASSO_DST_STATUS_CODE_OK "OK"
#define LASSO_DST_STATUS_CODE_FAILED "Failed"
#define LASSO_DST_STATUS_CODE_PARTIAL "Partial"
#define LASSO_DST_STATUS_CODE_ACTION_NOT_AUTHORIZED "ActionNotAuthorized"
#define LASSO_DST_STATUS_CODE_ACTION_NOT_SUPPORTED "ActionNotSupported"
#define LASSO_DST_STATUS_CODE_ALL_RETURNED "AllReturned"
#define LASSO_DST_STATUS_CODE_CHANGE_HISTORY_NOT_SUPPORTED "ChangeHistoryNotSupported"
#define LASSO_DST_STATUS_CODE_CHANGED_SINCE_RETURNS_ALL "ChangedSinceReturnsAll"
#define LASSO_DST_STATUS_CODE_DATA_TOO_LONG "DataTooLong"
#define LASSO_DST_STATUS_CODE_EXISTS_ALREADY "ExistsAlready"
#define LASSO_DST_STATUS_CODE_EXTENSION_NOT_SUPPORTED "ExtensionNotSupported"
#define LASSO_DST_STATUS_CODE_INVALID_DATA "InvalidData"
#define LASSO_DST_STATUS_CODE_INVALID_RESOURCE_ID "InvalidResourceID"
#define LASSO_DST_STATUS_CODE_INVALID_SELECT "InvalidSelect"
#define LASSO_DST_STATUS_CODE_MISSING_NEW_DATA_ELEMENT "MissingNewDataElement"
#define LASSO_DST_STATUS_CODE_MISSING_RESOURCE_ID_ELEMENT "MissingResourceIDElement"
#define LASSO_DST_STATUS_CODE_MISSING_SELECT "MissingSelect"
#define LASSO_DST_STATUS_CODE_MODIFIED_SINCE "ModifiedSince"
#define LASSO_DST_STATUS_CODE_NO_MORE_ELEMENTS "NoMoreElements"
#define LASSO_DST_STATUS_CODE_NO_MULTIPLE_ALLOWED "NoMultipleAllowed"
#define LASSO_DST_STATUS_CODE_NO_MULTIPLE_RESOURCES "NoMultipleResources"
#define LASSO_DST_STATUS_CODE_TIME_OUT "TimeOut"
#define LASSO_DST_STATUS_CODE_UNEXPECTED_ERROR "UnexpectedError"

#define LASSO_SA_STATUS_CODE_OK "OK"
#define LASSO_SA_STATUS_CODE_CONTINUE "continue"
#define LASSO_SA_STATUS_CODE_ABORT "abort"

/*****************************************************************************/
/* SOAP BINDING                                                              */
/*****************************************************************************/

/**
 * LASSO_SOAP_BINDING_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_SOAP_BINDING_HREF          "urn:liberty:sb:2003-08"
/**
 * LASSO_SOAP_BINDING_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_SOAP_BINDING_PREFIX        "sb"

/**
 * LASSO_SOAP_BINDING_EXT_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_SOAP_BINDING_EXT_HREF "urn:liberty:sb:2004-04"
/**
 * LASSO_SOAP_BINDING_EXT_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_SOAP_BINDING_EXT_PREFIX "sbe"

#define LASSO_SOAP_BINDING_PROCESS_CONTEXT_PRINCIPAL_OFFLINE \
	"urn:liberty:sb:2003-08:ProcessingContext:PrincipalOffline"
#define LASSO_SOAP_BINDING_PROCESS_CONTEXT_PRINCIPAL_ONLINE \
	"urn:liberty:sb:2003-08:ProcessingContext:PrincipalOnline"
#define LASSO_SOAP_BINDING_PROCESS_CONTEXT_SIMULATE \
	"urn:liberty:sb:2003-08:ProcessingContext:Simulate"

#define LASSO_SOAP_FAULT_STRING_SERVER "Server Error"
#define LASSO_SOAP_FAULT_STRING_IDENTITY_NOT_FOUND "Identity not found"


/*****************************************************************************/
/* WS-*                                                                      */
/*****************************************************************************/

/**
 * LASSO_WSSE_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_WSSE_HREF "http://schemas.xmlsoap.org/ws/2002/07/secext"
/**
 * LASSO_WSSE_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_WSSE_PREFIX "wsse"

/**
 * LASSO_WSSE1_HREF:
 *
 * Namespace for WS-Security 1.0
 *
 */
#define LASSO_WSSE1_HREF \
	"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
/**
 * LASSO_WSSE1_PREFIX:
 *
 * Preferred prefix for namespace of WS-Security 1.0
 *
 */
#define LASSO_WSSE1_PREFIX "wsse"

/**
 * LASSO_WSSE11_HREF:
 *
 * Namespace for WS-Security 1.1
 */
#define LASSO_WSSE11_HREF \
	"http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"

/* LASSO_WSSE11_PREFIX:
 *
 * Preferred prefix for namespace of WS-Security 1.1
 *
 */
#define LASSO_WSSE11_PREFIX "wsse"

/**
 * LASSO_WSSE_SECEXT_FAULT_CODE_UNSUPPORTED_SECURITY_TOKEN:
 *
 * Fault code for WS-Security tokens handling
 */
#define LASSO_WSSE_SECEXT_FAULT_CODE_UNSUPPORTED_SECURITY_TOKEN \
	"wsse:UnsupportedSecurityToken"

/**
 * LASSO_WSSE_SECEXT_FAULT_CODE_UNSUPPORTED_ALGORITHM:
 *
 * Fault code for WS-Security tokens handling
 */
#define LASSO_WSSE_SECEXT_FAULT_CODE_UNSUPPORTED_ALGORITHM \
	"wsse:UnsupportedAlgorithm"

/**
 * LASSO_WSSE_SECEXT_FAULT_CODE_INVALID_SECURITY:
 *
 * Fault code for WS-Security tokens handling
 */
#define LASSO_WSSE_SECEXT_FAULT_CODE_INVALID_SECURITY \
	"wsse:InvalidSecurity"

/**
 * LASSO_WSSE_SECEXT_FAULT_CODE_INVALID_SECURITY_TOKEN:
 *
 * Fault code for WS-Security tokens handling
 */
#define LASSO_WSSE_SECEXT_FAULT_CODE_INVALID_SECURITY_TOKEN \
	"wsse:InvalidSecurityToken"

/**
 * LASSO_WSSE_SECEXT_FAULT_CODE_FAILED_AUTHENTICATION:
 *
 * Fault code for WS-Security tokens handling
 */
#define LASSO_WSSE_SECEXT_FAULT_CODE_FAILED_AUTHENTICATION \
	"wsse:FailedAuthentication"

/**
 * LASSO_WSSE_SECEXT_FAULT_CODE_FAILED_CHECK:
 *
 * Fault code for WS-Security tokens handling
 */
#define LASSO_WSSE_SECEXT_FAULT_CODE_FAILED_CHECK \
	"wsse:FailedCheck"

/**
 * LASSO_WSSE_SECEXT_FAULT_CODE_SECURITY_TOKEN_UNAVAILABLE:
 *
 * Fault code for WS-Security tokens handling
 */
#define LASSO_WSSE_SECEXT_FAULT_CODE_SECURITY_TOKEN_UNAVAILABLE \
	"wsse:SecurityTokenUnavailable"

/* 
 * Username token profile 
 */

/**
 * LASSO_WSSE_USERNAME_TOKEN_PROFILE_HREF:
 */
#define LASSO_WSSE_USERNAME_TOKEN_PROFILE_HREF \
	"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0"

/**
 * LASSO_WSSE_USERNAME_TOKEN_PROFILE_PASSWORD_DIGEST:
 *
 * Identifier for a UsernameToken of type PasswordDigest
 */
#define LASSO_WSSE_USERNAME_TOKEN_PROFILE_PASSWORD_DIGEST \
	LASSO_WSSE_USERNAME_TOKEN_PROFILE_HREF "#PasswordDigest"

/**
 * LASSO_WSSE_USERNAME_TOKEN_PROFILE_PASSWORD_TEXT:
 *
 * Identifier for a UsernameToken of type PasswordText
 */
#define LASSO_WSSE_USERNAME_TOKEN_PROFILE_PASSWORD_TEXT \
	LASSO_WSSE_USERNAME_TOKEN_PROFILE_HREF "#PasswordText"

/* WS-Addressing */
/**
 * LASSO_WSA_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_WSA_HREF "http://www.w3.org/2005/08/addressing"
/**
 * LASSO_WSA_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_WSA_PREFIX "wsa"

/**
 * LASSO_WSA_ELEMENT_MESSAGE_ID:
 *
 * Name of the element representing SOAP MessageID in the WS-Addressing specification.
 */
#define LASSO_WSA_ELEMENT_MESSAGE_ID "MessageID"
/**
 * LASSO_WSA_ELEMENT_RELATES_TO:
 *
 * Name of the element representing SOAP messages inter-relationships in the WS-Addressing
 * specification.
 */
#define LASSO_WSA_ELEMENT_RELATES_TO "RelatesTo"

/* WS-Utility */
/**
 * LASSO_WSU_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_WSU_HREF \
	"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
/**
 * LASSO_WSU_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_WSU_PREFIX "wsu"

#endif /* __LASSO_IDWSF_STRINGS_H__ */

