/*
 * JLasso -- Java bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: Benjamin Poussin <poussin@codelutin.com>
 *          Emmanuel Raviart <eraviart@entrouvert.com>
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

package com.entrouvert.lasso;

public class Lasso { // Lasso

    static {
        System.loadLibrary("jlasso");
    }

    /* HTTP methods used by Liberty Alliance */
    static final public int httpMethodGet = 1;
    static final public int httpMethodPost = 2;
    static final public int httpMethodRedirect = 3;
    static final public int httpMethodSoap = 4;

    /* Consent types */
    static final public String libConsentObtained = "urn:liberty:consent:obtained";
    static final public String libConsentUnavailable = "urn:liberty:consent:unavailable";
    static final public String libConsentInapplicable = "urn:liberty:consent:inapplicable";

    /* NameIDPolicy types */
    static final public String libNameIdPolicyTypeNone = "none";
    static final public String libNameIdPolicyTypeOneTime = "onetime";
    static final public String libNameIdPolicyTypeFederated = "federated";
    static final public String libNameIdPolicyTypeAny = "any";

    /* Login ProtocolProfile types */
    static final public int loginProtocolProfileBrwsArt = 1;
    static final public int loginProtocolProfileBrwsPost = 2;

    /* Message types */
    static final public int messageTypeNone = 0;
    static final public int messageTypeAuthnRequest = 1;
    static final public int messageTypeAuthnResponse = 2;
    static final public int messageTypeRequest = 3;
    static final public int messageTypeResponse = 4;
    static final public int messageTypeArtifact = 5;

    /* Provider types */
    static final public int providerTypeSp  = 1;
    static final public int providerTypeIdp = 2;

    /* Request types */
    static final public int requestTypeLogin = 1;
    static final public int requestTypeLogout = 2;
    static final public int requestTypeFederationTermination  = 3;
    static final public int requestTypeRegisterNameIdentifier = 4;
    static final public int requestTypeNameIdentifierMapping  = 5;

    /* AuthenticationMethod types */
    static final public String samlAuthenticationMethodPassword = "urn:oasis:names:tc:SAML:1.0:am:password";
    static final public String samlAuthenticationMethodKerberos = "urn:ietf:rfc:1510";
    static final public String samlAuthenticationMethodSecureRemotePassword = "urn:ietf:rfc:2945";
    static final public String samlAuthenticationMethodHardwareToken = "urn:oasis:names:tc:SAML:1.0:am:HardwareToken";
    static final public String samlAuthenticationMethodSmartcardPki = "urn:ietf:rfc:2246";
    static final public String samlAuthenticationMethodSoftwarePki = "urn:oasis:names:tc:SAML:1.0:am:X509-PKI";
    static final public String samlAuthenticationMethodPgp = "urn:oasis:names:tc:SAML:1.0:am:PGP";
    static final public String samlAuthenticationMethodSPki = "urn:oasis:names:tc:SAML:1.0:am:SPKI";
    static final public String samlAuthenticationMethodXkms = "urn:oasis:names:tc:SAML:1.0:am:XKMS";
    static final public String samlAuthenticationMethodXmlDSig = "urn:ietf:rfc:3075";
    static final public String samlAuthenticationMethodUnspecified = "urn:oasis:names:tc:SAML:1.0:am:unspecified";

    /* SignatureMethod types */
    static final public int signatureMethodRsaSha1 = 1;
    static final public int signatureMethodDsaSha1 = 2;

    native static public int init();
    native static public int getRequestTypeFromSoapMsg(String soapRequestMsg);
    native static public int shutdown();

} // Lasso

