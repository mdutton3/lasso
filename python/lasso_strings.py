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
# * Liberty Alliance                                                          */
# *****************************************************************************/

# * Versioning */
LibMajorVersion = "1"
LibMinorVersion = "2"

# * NameIDPolicyType */
LibNameIDPolicyTypeNone = "none"
LibNameIDPolicyTypeOneTime = "onetime"
LibNameIDPolicyTypeFederated = "federated"
LibNameIDPolicyTypeAny = "any"

# * AuthnContextComparison */
LibAuthnContextComparisonExact = "exact"
LibAuthnContextComparisonMinimum = "minimum"
LibAuthnContextComparisonBetter = "better"

# * StatusCodes */
LibStatusCodeFederationDoesNotExist = "lib:FederationDoesNotExist"
LibStatusCodeNoPassive = "lib:NoPassive"

# *****************************************************************************/
# * SAML                                                                      */
# *****************************************************************************/

# * Versioning */
SamlMajorVersion = "1"
SamlMinorVersion = "0"

# * StatusCodes */
SamlStatusCodeRequestDenied = "Samlp:RequestDenied"
SamlStatusCodeSuccess = "Samlp:Success"

# * AuthenticationMethods */
SamlAuthenticationMethodPassword = "urn:oasis:names:tc:SAML:1.0:am:password"
SamlAuthenticationMethodKerberos = "urn:ietf:rfc:1510"
SamlAuthenticationMethodSecureRemotePassword = "urn:ietf:rfc:2945"
SamlAuthenticationMethodHardwareToken = "urn:oasis:names:tc:SAML:1.0:am:HardwareToken"
SamlAuthenticationMethodSmartcardPki = "urn:ietf:rfc:2246"
SamlAuthenticationMethodSoftwarePki = "urn:oasis:names:tc:SAML:1.0:am:X509-PKI"
SamlAuthenticationMethodPGP = "urn:oasis:names:tc:SAML:1.0:am:PGP"
SamlAuthenticationMethodSPki = "urn:oasis:names:tc:SAML:1.0:am:SPKI"
SamlAuthenticationMethodXkms = "urn:oasis:names:tc:SAML:1.0:am:XKMS"
SamlAuthenticationMethodXmlSign = "urn:ietf:rfc:3075"
SamlAuthenticationMethodUnspecified = "urn:oasis:names:tc:SAML:1.0:am:unspecified"

