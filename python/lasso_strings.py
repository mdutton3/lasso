# $Id$
# 
# PyLasso - Python bindings for Lasso library
#
# Copyright (C) 2004 Entr'ouvert
# http://lasso.labs.libre-entreprise.org
#
# Author: Valery Febvre <vfebvre@easter-eggs.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# * $Id$ 
# *
# * Lasso - A free implementation of the Liberty Alliance specifications.
# *
# * Copyright (C) 2004 Entr'ouvert
# * http://lasso.entrouvert.org
# * 
# * Author: Valery Febvre <vfebvre@easter-eggs.com>
# *
# * This program is free software; you can redistribute it and/or modify
# * it under the terms of the GNU General Public License as published by
# * the Free Software Foundation; either version 2 of the License, or
# * (at your option) any later version.
# * 
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# * 
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
# */


# *****************************************************************************/
# * Lasso                                                                     */
# *****************************************************************************/

# * prefix & href */
lassoHRef = "http://www.entrouvert.org/namespaces/lasso/0.0"
lassoPrefix = "lasso"

# *****************************************************************************/
# * Liberty Alliance                                                          */
# *****************************************************************************/

# * prefix & href */
libHRef = "urn:liberty:iff:2003-08"
libPrefix = "lib"

# * Versioning */
libMajorVersion = "1"
libMinorVersion = "2"

# * NameIDPolicyType */
libNameIDPolicyTypeNone = "none"
libNameIDPolicyTypeOneTime = "onetime"
libNameIDPolicyTypeFederated = "federated"
libNameIDPolicyTypeAny = "any"

# * AuthnContextComparison */
libAuthnContextComparisonExact = "exact"
libAuthnContextComparisonMinimum = "minimum"
libAuthnContextComparisonBetter = "better"

# * StatusCodes */
libStatusCodeFederationDoesNotExist = "lib:FederationDoesNotExist"
libStatusCodeInvalidAssertionConsumerServiceIndex = "lib:InvalidAssertionConsumerServiceIndex"
libStatusCodeInvalidSignature = "lib:InvalidSignature"
libStatusCodeNoAuthnContext = "lib:NoAuthnContext"
libStatusCodeNoAvailableIDP = "lib:NoAvailableIDP"
libStatusCodeNoPassive = "lib:NoPassive"
libStatusCodeNoSupportedIDP = "lib:NoSupportedIDP"
libStatusCodeProxyCountExceeded = "lib:ProxyCountExceeded"
libStatusCodeUnknownPrincipal = "lib:UnknownPrincipal"
libStatusCodeUnsignedAuthnRequest = "lib:UnsignedAuthnRequest"

# * ProtocolProfile */
libProtocolProfileSSOGet = "http://projectliberty.org/profiles/sso-get"
libProtocolProfileSSOPost = "http://projectliberty.org/profiles/sso-post"
libProtocolProfileBrwsArt = "http://projectliberty.org/profiles/brws-art"
libProtocolProfileBrwsPost = "http://projectliberty.org/profiles/brws-post"
libProtocolProfileFedTermIdpHttp = "http://projectliberty.org/profiles/fedterm-idp-http"
libProtocolProfileFedTermIdpSoap = "http://projectliberty.org/profiles/fedterm-idp-soap"
libProtocolProfileFedTermSpHttp = "http://projectliberty.org/profiles/fedterm-sp-http"
libProtocolProfileFedTermSpSoap = "http://projectliberty.org/profiles/fedterm-sp-soap"
libProtocolProfileRniIdpHttp = "http://projectliberty.org/profiles/rni-idp-http"
libProtocolProfileRniIdpSoap = "http://projectliberty.org/profiles/rni-idp-soap"
libProtocolProfileRniSpHttp = "http://projectliberty.org/profiles/rni-sp-http"
libProtocolProfileRniSpSoap = "http://projectliberty.org/profiles/rni-sp-soap"
libProtocolProfileSloSpHttp = "http://projectliberty.org/profiles/slo-sp-http"
libProtocolProfileSloSpSoap = "http://projectliberty.org/profiles/slo-sp-soap"
libProtocolProfileSloIdpHttp = "http://projectliberty.org/profiles/slo-idp-http"
libProtocolProfileSloIdpSoap = "http://projectliberty.org/profiles/slo-idp-soap"

# * NameIdentifier formats */
libNameIdentifierFormatFederated = "urn:liberty:iff:nameid:federated"
libNameIdentifierFormatOneTime = "urn:liberty:iff:nameid:one-time"
libNameIdentifierFormatEncrypted = "urn:liberty:iff:nameid:encrypted"
libNameIdentifierFormatEntityID = "urn:liberty:iff:nameid:entityID"

# *****************************************************************************/
# * METADATA                                                                  */
# *****************************************************************************/

# * prefix & href */
metadataHRef = "urn:liberty:metadata:2003-08"
metadataPrefix = "md"

# *****************************************************************************/
# * SAML                                                                      */
# *****************************************************************************/

# * prefix & href */
samlAssertionHRef = "urn:oasis:names:tc:SAML:1.0:assertion"
samlAssertionPrefix = "saml"
samlProtocolHRef = "urn:oasis:names:tc:SAML:1.0:protocol"
samlProtocolPrefix = "samlp"

# * Versioning */
samlMajorVersion = "1"
samlMinorVersion = "1"

# * StatusCodes */
samlStatusCodeRequestDenied = "Samlp:RequestDenied"
samlStatusCodeSuccess = "Samlp:Success"

# * AuthenticationMethods */
samlAuthenticationMethodPassword = "urn:oasis:names:tc:SAML:1.0:am:password"
samlAuthenticationMethodKerberos = "urn:ietf:rfc:1510"
samlAuthenticationMethodSecureRemotePassword = "urn:ietf:rfc:2945"
samlAuthenticationMethodHardwareToken = "urn:oasis:names:tc:SAML:1.0:am:HardwareToken"
samlAuthenticationMethodSmartcardPki = "urn:ietf:rfc:2246"
samlAuthenticationMethodSoftwarePki = "urn:oasis:names:tc:SAML:1.0:am:X509-PKI"
samlAuthenticationMethodPgp = "urn:oasis:names:tc:SAML:1.0:am:PGP"
samlAuthenticationMethodSPki = "urn:oasis:names:tc:SAML:1.0:am:SPKI"
samlAuthenticationMethodXkms = "urn:oasis:names:tc:SAML:1.0:am:XKMS"
samlAuthenticationMethodXmlDSig = "urn:ietf:rfc:3075"
samlAuthenticationMethodUnspecified = "urn:oasis:names:tc:SAML:1.0:am:unspecified"

# * ConfirmationMethods */
samlConfirmationMethodArtifact01 = "urn:oasis:names:tc:SAML:1.0:cm:artifact-01"
samlConfirmationMethodBearer = "urn:oasis:names:tc:SAML:1.0:cm:bearer"
samlConfirmationMethodHolderOfKey = "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key"
samlConfirmationMethodSenderVouches = "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches"

# *****************************************************************************/
# * SOAP                                                                      */
# *****************************************************************************/

# * prefix & href */
soapEnvHRef = "http://schemas.xmlsoap.org/soap/envelope/"
soapEnvPrefix = "soap-env"
