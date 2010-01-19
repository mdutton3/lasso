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
#define LASSO_SECURITY_MECH_SAML2   "urn:liberty:security:2006-08:null:SAMLV2"
#define LASSO_SECURITY_MECH_BEARER "urn:liberty:security:2005-02:null:Bearer"

#define LASSO_SECURITY_MECH_TLS        "urn:liberty:security:2003-08:TLS:null"
#define LASSO_SECURITY_MECH_TLS_X509   "urn:liberty:security:2005-02:TLS:X509"
#define LASSO_SECURITY_MECH_TLS_SAML   "urn:liberty:security:2005-02:TLS:SAML"
#define LASSO_SECURITY_MECH_TLS_SAML2   "urn:liberty:security:2006-08:TLS:SAMLV2"
#define LASSO_SECURITY_MECH_TLS_BEARER "urn:liberty:security:2005-02:TLS:Bearer"

#define LASSO_SECURITY_MECH_CLIENT_TLS        "urn:liberty:security:2003-08:ClientTLS:null"
#define LASSO_SECURITY_MECH_CLIENT_TLS_X509   "urn:liberty:security:2005-02:ClientTLS:X509"
#define LASSO_SECURITY_MECH_CLIENT_TLS_SAML   "urn:liberty:security:2005-02:ClientTLS:SAML"
#define LASSO_SECURITY_MECH_CLIENT_TLS_SAML2   "urn:liberty:security:2006-08:ClientTLS:SAMLV2"
#define LASSO_SECURITY_MECH_CLIENT_TLS_BEARER "urn:liberty:security:2005-02:ClientTLS:Bearer"
#define LASSO_SECURITY_MECH_CLIENT_TLS_PEER_SAML2 "urn:liberty:security:2006-08:ClientTLS:peerSAMLV2"


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
 * LASSO_PP_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_PP_HREF   "urn:liberty:id-sis-pp:2003-08"
/**
 * LASSO_PP_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_PP_PREFIX "pp"

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
/* ID-WSF 2.0 Status Codes                                                   */
/*****************************************************************************/
/**
 * LASSO_IDWSF2_DISCOVERY_STATUS_CODE_OK:
 *
 *  message processing succeeded
 */
#define LASSO_IDWSF2_DISCOVERY_STATUS_CODE_OK "OK"
/**
 * LASSO_IDWSF2_DISCOVERY_STATUS_CODE_FAILED:
 *
 *  general failure code
 */
#define LASSO_IDWSF2_DISCOVERY_STATUS_CODE_FAILED "Failed"
/**
 * LASSO_IDWSF2_DISCOVERY_STATUS_CODE_FORBIDDEN:
 *
 *  the request was denied based on policy
 */
#define LASSO_IDWSF2_DISCOVERY_STATUS_CODE_FORBIDDEN "Forbidden"
/**
 * LASSO_IDWSF2_DISCOVERY_STATUS_CODE_DUPLICATE:
 *
 *  the request was denied because it would result in duplicate data in the service
 */
#define LASSO_IDWSF2_DISCOVERY_STATUS_CODE_DUPLICATE "Duplicate"
/**
 * LASSO_IDWSF2_DISCOVERY_STATUS_CODE_LOGICAL_DUPLICATE:
 *
 *  the request was denied because it would result in logically duplicate data in the service
 */
#define LASSO_IDWSF2_DISCOVERY_STATUS_CODE_LOGICAL_DUPLICATE "LogicalDuplicate"
/**
 * LASSO_IDWSF2_DISCOVERY_STATUS_CODE_NO_RESULTS:
 *
 *  the query had no matching results
 */
#define LASSO_IDWSF2_DISCOVERY_STATUS_CODE_NO_RESULTS "NoResults"
/**
 * LASSO_IDWSF2_DISCOVERY_STATUS_CODE_NOT_FOUND:
 *
 *  the specified item(s) were not found
 */
#define LASSO_IDWSF2_DISCOVERY_STATUS_CODE_NOT_FOUND "NotFound"

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

/**
 * LASSO_IDWSF2_SB2_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_SB2_HREF "urn:liberty:sb:2006-08"
/**
 * LASSO_IDWSF2_SB2_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_SB2_PREFIX "sb"

/**
 * LASSO_IDWSF2_SBF_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_SBF_HREF "urn:liberty:sb"
/**
 * LASSO_IDWSF2_SBF_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_SBF_PREFIX "sbf"

#define LASSO_SOAP_BINDING_PROCESS_CONTEXT_PRINCIPAL_OFFLINE \
	"urn:liberty:sb:2003-08:ProcessingContext:PrincipalOffline"
#define LASSO_SOAP_BINDING_PROCESS_CONTEXT_PRINCIPAL_ONLINE \
	"urn:liberty:sb:2003-08:ProcessingContext:PrincipalOnline"
#define LASSO_SOAP_BINDING_PROCESS_CONTEXT_SIMULATE \
	"urn:liberty:sb:2003-08:ProcessingContext:Simulate"

#define LASSO_SOAP_FAULT_STRING_SERVER "Server Error"
#define LASSO_SOAP_FAULT_STRING_IDENTITY_NOT_FOUND "Identity not found"


/*****************************************************************************/
/* ID-WSF 2.0                                                                */
/*****************************************************************************/

/**
 * LASSO_IDWSF2_DISCO_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_DISCO_HREF   "urn:liberty:disco:2006-08"
/**
 * LASSO_IDWSF2_DISCO_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_DISCO_PREFIX "disco"

/**
 * LASSO_IDWSF2_DST_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_DST_HREF "urn:liberty:dst:2006-08"
/**
 * LASSO_IDWSF2_DST_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_DST_PREFIX "dst"

/**
 * LASSO_IDWSF2_DSTREF_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_DSTREF_HREF "urn:liberty:dst:2006-08:ref"
/**
 * LASSO_IDWSF2_DSTREF_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_DSTREF_PREFIX "dstref"

/**
 * LASSO_IDWSF2_IMS_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_IMS_HREF "urn:liberty:ims:2006-08"
/**
 * LASSO_IDWSF2_IMS_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_IMS_PREFIX "ims"

/**
 * LASSO_IDWSF2_IS_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_IS_HREF "urn:liberty:is:2006-08"
/**
 * LASSO_IDWSF2_IS_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_IS_PREFIX "is"

/**
 * LASSO_IDWSF2_PS_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_PS_HREF "urn:liberty:ps:2006-08"
/**
 * LASSO_IDWSF2_PS_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_PS_PREFIX "ps"

/**
 * LASSO_IDWSF2_SUBS_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_SUBS_HREF "urn:liberty:ssos:2006-08"
/**
 * LASSO_IDWSF2_SUBS_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_SUBS_PREFIX "subs"

/**
 * LASSO_IDWSF2_SUBSREF_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_SUBSREF_HREF "urn:liberty:ssos:2006-08:ref"
/**
 * LASSO_IDWSF2_SUBSREF_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_SUBSREF_PREFIX "subsref"

/**
 * LASSO_IDWSF2_UTIL_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_UTIL_HREF "urn:liberty:util:2006-08"
/**
 * LASSO_IDWSF2_UTIL_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_UTIL_PREFIX "util"

/**
 * LASSO_IDWSF2_SEC_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_SEC_HREF "urn:liberty:security:2006-08"
/**
 * LASSO_IDWSF2_SEC_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_SEC_PREFIX "sec"

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

/*
 * WS-Security Utility
 */

/**
 * LASSO_WSUTIL1_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_WSUTIL1_HREF \
	"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
/**
 * LASSO_WSUTIL1_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_WSUTIL1_PREFIX "wsutil"

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

/*
 * ID-WSF 2.0 Data Service First Level Status codes
 */

/**
 * LASSO_DST2_STATUS_CODE_OK:
 *
 * First level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE1_OK "OK"

/**
 * LASSO_DST2_STATUS_CODE_PARTIAL:
 *
 * First level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE1_PARTIAL "Partial"

/**
 * LASSO_DST2_STATUS_CODE_FAILED:
 *
 * First level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE1_FAILED "Failed"

/*
 * ID-WSF 2.0 Data Service Second Level Status codes
 */

/**
 * LASSO_DST2_STATUS_CODE2_ACTION_NOT_AUTHORIZED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_ACTION_NOT_AUTHORIZED "ActionNotAuthorized"

/**
 * LASSO_DST2_STATUS_CODE2_AGGREGATION_NOT_SUPPORTED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_AGGREGATION_NOT_SUPPORTED "AggregationNotSupported"

/**
 * LASSO_DST2_STATUS_CODE2_ALL_RETURNED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_ALL_RETURNED "AllReturned"

/**
 * LASSO_DST2_STATUS_CODE2_CHANGE_HISTORY_NOT_SUPPORTED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_CHANGE_HISTORY_NOT_SUPPORTED "ChangeHistoryNotSupported"

/**
 * LASSO_DST2_STATUS_CODE2_CHANGED_SINCE_RETURNS_ALL:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_CHANGED_SINCE_RETURNS_ALL "ChangedSinceReturnsAll"

/**
 * LASSO_DST2_STATUS_CODE2_DATA_TOO_LONG:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_DATA_TOO_LONG "DataTooLong"

/**
 * LASSO_DST2_STATUS_CODE2_DOES_NOT_EXIST:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_DOES_NOT_EXIST "DoesNotExist"

/**
 * LASSO_DST2_STATUS_CODE2_EMPTY_REQUEST:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_EMPTY_REQUEST "EmptyRequest"

/**
 * LASSO_DST2_STATUS_CODE2_EXISTS_ALREADY:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_EXISTS_ALREADY "ExistsAlready"

/**
 * LASSO_DST2_STATUS_CODE2_EXTENSION_NOT_SUPPORTED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_EXTENSION_NOT_SUPPORTED "ExtensionNotSupported"

/**
 * LASSO_DST2_STATUS_CODE2_FORMAT_NOT_SUPPORTED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_FORMAT_NOT_SUPPORTED "FormatNotSupported"

/**
 * LASSO_DST2_STATUS_CODE2_INVALID_DATA:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_INVALID_DATA "InvalidData"

/**
 * LASSO_DST2_STATUS_CODE2_INVALID_EXPIRES:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_INVALID_EXPIRES "InvalidExpires"

/**
 * LASSO_DST2_STATUS_CODE2_INVALID_ITEM_ID_REF:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_INVALID_ITEM_ID_REF "InvalidItemIDRef"

/**
 * LASSO_DST2_STATUS_CODE2_INVALID_OBJECT_TYPE:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_INVALID_OBJECT_TYPE "InvalidObjectType"

/**
 * LASSO_DST2_STATUS_CODE2_INVALID_PREDEFINED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_INVALID_PREDEFINED "InvalidPredefined"

/**
 * LASSO_DST2_STATUS_CODE2_INVALID_SELECT:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_INVALID_SELECT "InvalidSelect"

/**
 * LASSO_DST2_STATUS_CODE2_INVALID_SET_ID:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_INVALID_SET_ID "InvalidSetID"

/**
 * LASSO_DST2_STATUS_CODE2_INVALID_SET_REQ:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_INVALID_SET_REQ "InvalidSetReq"

/**
 * LASSO_DST2_STATUS_CODE2_INVALID_SORT:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_INVALID_SORT "InvalidSort"

/**
 * LASSO_DST2_STATUS_CODE2_ITEM_ID_DUPLICATED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_ITEM_ID_DUPLICATED "ItemIDDuplicated"

/**
 * LASSO_DST2_STATUS_CODE2_RESULT_QUERY_NOT_SUPPORTED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_RESULT_QUERY_NOT_SUPPORTED "ResultQueryNotSupported"

/**
 * LASSO_DST2_STATUS_CODE2_MISSING_CREDENTIALS:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_MISSING_CREDENTIALS "MissingCredentials"

/**
 * LASSO_DST2_STATUS_CODE2_MISSING_DATA_ELEMENT:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_MISSING_DATA_ELEMENT "MissingDataElement"

/**
 * LASSO_DST2_STATUS_CODE2_MISSING_EXPIRATION:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_MISSING_EXPIRATION "MissingExpiration"

/**
 * LASSO_DST2_STATUS_CODE2_MISSING_ITEM_ID:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_MISSING_ITEM_ID "MissingItemID"

/**
 * LASSO_DST2_STATUS_CODE2_MISSING_NEW_DATA_ELEMENT:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_MISSING_NEW_DATA_ELEMENT "MissingNewDataElement"

/**
 * LASSO_DST2_STATUS_CODE2_MISSING_OBJECT_TYPE:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_MISSING_OBJECT_TYPE "MissingObjectType"

/**
 * LASSO_DST2_STATUS_CODE2_MISSING_SECURITY_MECH_ID_ELEMENT:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_MISSING_SECURITY_MECH_ID_ELEMENT "MissingSecurityMechIDElement"

/**
 * LASSO_DST2_STATUS_CODE2_MISSING_SELECT:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_MISSING_SELECT "MissingSelect"

/**
 * LASSO_DST2_STATUS_CODE2_MODIFIED_SINCE:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_MODIFIED_SINCE "ModifiedSince"

/**
 * LASSO_DST2_STATUS_CODE2_NEW_OR_EXISTING:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_NEW_OR_EXISTING "NewOrExisting"

/**
 * LASSO_DST2_STATUS_CODE2_NO_MORE_ELEMENTS:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_NO_MORE_ELEMENTS "NoMoreElements"

/**
 * LASSO_DST2_STATUS_CODE2_NO_MORE_OBJECTS:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_NO_MORE_OBJECTS "NoMoreObjects"

/**
 * LASSO_DST2_STATUS_CODE2_NO_MULTIPLE_ALLOWED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_NO_MULTIPLE_ALLOWED "NoMultipleAllowed"

/**
 * LASSO_DST2_STATUS_CODE2_NO_MULTIPLE_RESOURCES:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_NO_MULTIPLE_RESOURCES "NoMultipleResources"

/**
 * LASSO_DST2_STATUS_CODE2_NO_SUCH_TEST:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_NO_SUCH_TEST "NoSuchTest"

/**
 * LASSO_DST2_STATUS_CODE2_OBJECT_TYPE_MISMATCH:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_OBJECT_TYPE_MISMATCH "ObjectTypeMismatch"

/**
 * LASSO_DST2_STATUS_CODE2_PAGINATION_NOT_SUPPORTED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_PAGINATION_NOT_SUPPORTED "PaginationNotSupported"

/**
 * LASSO_DST2_STATUS_CODE2_REQUESTED_AGGREGATION_NOT_SUPPORTED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_REQUESTED_AGGREGATION_NOT_SUPPORTED "RequestedAggregationNotSupported"

/**
 * LASSO_DST2_STATUS_CODE2_REQUESTED_PAGINATION_NOT_SUPPORTED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_REQUESTED_PAGINATION_NOT_SUPPORTED "RequestedPaginationNotSupported"

/**
 * LASSO_DST2_STATUS_CODE2_REQUESTED_SORTING_NOT_SUPPORTED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_REQUESTED_SORTING_NOT_SUPPORTED "RequestedSortingNotSupported"

/**
 * LASSO_DST2_STATUS_CODE2_REQUESTED_TRIGGER_NOT_SUPPORTED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_REQUESTED_TRIGGER_NOT_SUPPORTED "RequestedTriggerNotSupported"

/**
 * LASSO_DST2_STATUS_CODE2_SECURITY_MECH_ID_NOT_ACCEPTED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_SECURITY_MECH_ID_NOT_ACCEPTED "SecurityMechIDNotAccepted"

/**
 * LASSO_DST2_STATUS_CODE2_SET_OR_NEW_QUERY:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_SET_OR_NEW_QUERY "SetOrNewQuery"

/**
 * LASSO_DST2_STATUS_CODE2_SORT_NOT_SUPPORTED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_SORT_NOT_SUPPORTED "SortNotSupported"

/**
 * LASSO_DST2_STATUS_CODE2_STATIC_NOT_SUPPORTED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_STATIC_NOT_SUPPORTED "StaticNotSupported"

/**
 * LASSO_DST2_STATUS_CODE2_TIME_OUT:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_TIME_OUT "TimeOut"

/**
 * LASSO_DST2_STATUS_CODE2_TRIGGER_NOT_SUPPORTED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_TRIGGER_NOT_SUPPORTED "TriggerNotSupported"

/**
 * LASSO_DST2_STATUS_CODE2_UNEXPECTED_ERROR:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_UNEXPECTED_ERROR "UnexpectedError"

/**
 * LASSO_DST2_STATUS_CODE2_UNSPECIFIED_ERROR:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_UNSPECIFIED_ERROR "UnspecifiedError"

/**
 * LASSO_DST2_STATUS_CODE2_UNSUPPORTED_OBJECT_TYPE:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_UNSUPPORTED_OBJECT_TYPE "UnsupportedObjectType"

/**
 * LASSO_DST2_STATUS_CODE2_UNSUPPORTED_PREDEFINED:
 *
 * Second level status code for ID-WSF 2.0 Data Service Template response.
 * FIXME: define me !
 */
#define LASSO_DST2_STATUS_CODE2_UNSUPPORTED_PREDEFINED "UnsupportedPredefined"


/*
 * Libert Security Mechanism, token usage */
#define LASSO_IDWSF2_SEC_TOKEN_USAGE_SECURITY_TOKEN "urn:liberty:security:tokenusage:2006-08:SecurityToken"
#define LASSO_IDWSF2_SEC_TOKEN_USAGE_TARGET_IDENTITY "urn:liberty:security:tokenusage:2006-08:TargetIdentity"
#define LASSO_IDWSF2_SEC_TOKEN_USAGE_INVOCATION_IDENTITY "urn:liberty:security:tokenusage:2006-08:InvocationIdentity"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_INVALID_ACTOR:
 *
 * There is an issue with the actor attribute on the indicated header block in the indicated
 * message.
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_INVALID_ACTOR "InvalidActor"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_INVALID_MUST_UNDERSTAND:
 *
 * There is an issue with the mustUnderstand attribute on the indicated header block in the indicated message. 
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_INVALID_MUST_UNDERSTAND "InvalidMustUnderstand"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_STALE_MSG:
 *
 * The indicated inbound SOAP-bound ID-* message has a timestamp value outside of the receivers
 * allowable time window.
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_STALE_MSG "StaleMsg"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_DUPLICATE_MSG:
 *
 * The indicated inbound SOAP-bound ID-* message appears to be a duplicate.
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_DUPLICATE_MSG "DuplicateMsg"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_INVALID_REF_TO_MSG_ID:
 *
 * The indicated inbound SOAP-bound ID-* message appears to incorrectly refer to the preceding
 * message in the message thread.
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_INVALID_REF_TO_MSG_ID "InvalidRefToMsgID"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_PROVIDER_ID_NOT_VALID:
 *
 * The receiver does not consider the claimed Provider ID to be valid. 
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_PROVIDER_ID_NOT_VALID "ProviderIDNotValid"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_AFFILIATION_ID_NOT_VALID:
 *
 * The receiver does not consider the claimed Affiliation ID to be valid. 
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_AFFILIATION_ID_NOT_VALID "AffiliationIDNotValid"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_TARGET_IDENTITY_NOT_VALID:
 *
 * The receiver does not consider the target identity to be valid. 
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_TARGET_IDENTITY_NOT_VALID "TargetIdentityNotValid"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_FRAMEWORK_VERSION_MISMATCH:
 *
 * The framework version used in the conveyed ID-* message does not match what was expected by the
 * receiver.
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_FRAMEWORK_VERSION_MISMATCH "FrameworkVersionMismatch"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_ID_STAR_MSG_NOT_UNDERSTOOD:
 *
 * There was a problem with understanding/parsing the conveyed ID-* message.
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_ID_STAR_MSG_NOT_UNDERSTOOD "IDStarMsgNotUnderstood"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_PROC_CTX_U_R_I_NOT_UNDERSTOOD:
 *
 * The receiver did not understand the processing context facet URI. 
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_PROC_CTX_U_R_I_NOT_UNDERSTOOD "ProcCtxURINotUnderstood"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_PROC_CTX_UNWILLING:
 *
 * The receiver is unwilling to apply the sender’s stipulated processing context.
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_PROC_CTX_UNWILLING "ProcCtxUnwilling"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_CANNOT_HONOUR_USAGE_DIRECTIVE:
 *
 * The receiver is unable or unwilling to honor the stipulated usage directive.
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_CANNOT_HONOUR_USAGE_DIRECTIVE "CannotHonourUsageDirective"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_ENDPOINT_UPDATED:
 *
 * The request cannot be processed at this endpoint. This is typically used in conjunction with the
 * &lt;EndpointUpdate&gt; header block to indicate the endpoint to which the request should be
 * resubmitted.
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_ENDPOINT_UPDATED "EndpointUpdated"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_INAPPROPRIATE_CREDENTIALS:
 *
 * The sender has submitted a request that does not meet the needs of the receiver. The receiver may
 * indicate credentials that are acceptable to them via a &lt;CredentialsContext&gt; or
 * <EndpointUpdate> header block.
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_CLIENT_INAPPROPRIATE_CREDENTIALS "InappropriateCredentials"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_PROCESSING_TIMEOUT:
 *
 * The sender is indicating that processing of the request has failed due to  the processing taking
 * longer than the maxProcessingTime specified on the request &lt;Timeout&gt; header block.
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_PROCESSING_TIMEOUT "ProcessingTimeout"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_INTERACTION_REQUIRED:
 *
 * The recipient has a need to start an interaction in order to satisfy the service request but the
 * interact attribute value was set to DoNotInteract.
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_INTERACTION_REQUIRED "InteractionRequired"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_INTERACTION_REQUIRED_FOR_DATA:
 *
 * the service request could not be satisfied because the WSP would have to interact with the
 * requesting principal in order to obtain (some of) the requested data but the interact attribute
 * value was set to DoNotInteractForData.
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_INTERACTION_REQUIRED_FOR_DATA "InteractionRequiredForData"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_INTERACTION_TIME_NOT_SUFFICIENT:
 *
 * The recipient has a need to start an interaction but has reason to believe that more time is
 * needed that allowed for by the value of the maxInteractTime attribute.
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_INTERACTION_TIME_NOT_SUFFICIENT "InteractionTimeNotSufficient"

/**
 * LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_INTERACTION_TIMEOUT:
 *
 * The recipient could not satisfy the service request due to an unfinished interaction.
 */
#define LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_INTERACTION_TIMEOUT "InteractionTimeout"

#define LASSO_IDWSF2_DISCOVERY_RESULT_TYPE_BEST "best"
#define LASSO_IDWSF2_DISCOVERY_RESULT_TYPE_ALL "all"
#define LASSO_IDWSF2_DISCOVERY_RESULT_TYPE_ONLY_ONE "only-one"

#define LASSO_SB2_USER_INTERACTION_INTERACT_IF_NEEDED "InteractIfNeeded"
#define LASSO_SB2_USER_INTERACTION_DO_NOT_INTERACT "DoNotInteract"
#define LASSO_SB2_USER_INTERACTION_DO_NOT_INTERACT_FOR_DATA "DoNotInteractForData"

#endif /* __LASSO_IDWSF_STRINGS_H__ */

