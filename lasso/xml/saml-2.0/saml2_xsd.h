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

#ifndef __LASSO_SAML2_XSD_H__
#define __LASSO_SAML2_XSD_H__

/* SAML 2.0 Metadata XSD */
#define LASSO_SAML2_METADATA_ELEMENT_ENTITY_DESCRIPTOR "EntityDescriptor"
#define LASSO_SAML2_METADATA_ELEMENT_ENTITIES_DESCRIPTOR "EntitiesDescriptor"
#define LASSO_SAML2_METADATA_ELEMENT_IDP_SSO_DESCRIPTOR "IDPSSODescriptor"
#define LASSO_SAML2_METADATA_ELEMENT_SP_SSO_DESCRIPTOR "SPSSODescriptor"
#define LASSO_SAML2_METADATA_ELEMENT_ATTRIBUTE_AUTHORITY_DESCRIPTOR "AttributeAuthorityDescriptor"
#define LASSO_SAML2_METADATA_ELEMENT_PDP_DESCRIPTOR "PDPDescriptor"
#define LASSO_SAML2_METADATA_ELEMENT_AUTHN_DESCRIPTOR "AuthnAuthorityDescriptor"
#define LASSO_SAML2_METADATA_ELEMENT_ORGANIZATION "Organization"
#define LASSO_SAML2_METADATA_ELEMENT_KEY_DESCRIPTOR "KeyDescriptor"
#define LASSO_SAML2_METADATA_ELEMENT_ASSERTION_CONSUMER_SERVICE "AssertionConsumerService"
#define LASSO_SAML2_METADATA_ATTRIBUTE_BINDING "Binding"
#define LASSO_SAML2_METADATA_ATTRIBUTE_VALID_UNTIL "validUntil"
#define LASSO_SAML2_METADATA_ATTRIBUTE_CACHE_DURATION "cacheDuration"
#define LASSO_SAML2_METADATA_ATTRIBUTE_LOCATION "Location"
#define LASSO_SAML2_METADATA_ATTRIBUTE_RESPONSE_LOCATION "ResponseLocation"
#define LASSO_SAML2_METADATA_ATTRIBUTE_INDEX "index"
#define LASSO_SAML2_METADATA_ATTRIBUTE_ISDEFAULT "isDefault"
#define LASSO_SAML2_METADATA_ATTRIBUTE_AUTHN_REQUEST_SIGNED "AuthnRequestsSigned"
#define LASSO_SAML2_METADATA_ATTRIBUTE_WANT_AUTHN_REQUEST_SIGNED "WantAuthnRequestsSigned"
#define LASSO_SAML2_METADATA_ATTRIBUTE_ERROR_URL "errorURL"
#define LASSO_SAML2_METADATA_ATTRIBUTE_PROTOCOL_SUPPORT_ENUMERATION "protocolSupportEnumeration"


/* SAML 2.0 Assertion XSD */
#define LASSO_SAML2_ASSERTION_ELEMENT_ATTRIBUTE "Attribute"

#endif /* __LASSO_SAML2_XSD_H__ */
