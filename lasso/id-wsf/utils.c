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

/**
 * lasso_security_mech_is_saml_authentication:
 * @security_mech_id: the URI of an authentication mechanism
 *
 * Return value: %TRUE if @security_mech_id is one of
 * urn:liberty:security:2003-08:NULL:SAML,
 * urn:liberty:security:2003-08:TLS:SAML or
 * urn:liberty:security:2003-08:ClientTLS:SAML, FALSE otherwise. 
 */

#include <glib.h>
#include <lasso/xml/strings.h>
#include <string.h>

gboolean
lasso_security_mech_id_is_saml_authentication(const gchar *security_mech_id)
{
	if (!security_mech_id)
		return FALSE;

	if (strcmp(security_mech_id, LASSO_SECURITY_MECH_SAML) == 0 ||
			strcmp(security_mech_id, LASSO_SECURITY_MECH_TLS_SAML) == 0 ||
			strcmp(security_mech_id, LASSO_SECURITY_MECH_CLIENT_TLS_SAML) == 0)
		return TRUE;

	return FALSE;
}

/** 
 * lasso_security_mech_is_x509_authentication:
 * @security_mech_id: the URI of an authentication mechanism
 *
 * Return value: %TRUE if @security_mech_id is one of
 * urn:liberty:security:2003-08:NULL:X509,
 * urn:liberty:security:2003-08:TLS:X509 or
 * urn:liberty:security:2003-08:ClientTLS:X509, FALSE otherwise. 
 */
gboolean
lasso_security_mech_id_is_x509_authentication(const char *security_mech_id)
{
	if (strcmp(security_mech_id, 
			LASSO_SECURITY_MECH_CLIENT_TLS_X509) == 0 ||
			strcmp(security_mech_id, 
					LASSO_SECURITY_MECH_TLS_X509) == 0 ||
			strcmp(security_mech_id, 
					LASSO_SECURITY_MECH_X509) == 0) {
		return TRUE;
	}
	return FALSE;
}

/** 
 * lasso_security_mech_is_null_authentication:
 * @security_mech_id: the URI of an authentication mechanism
 *
 * Return value: %TRUE if @security_mech_id is one of
 * urn:liberty:security:2003-08:NULL:NULL,
 * urn:liberty:security:2003-08:TLS:NULL or
 * urn:liberty:security:2003-08:ClientTLS:NULL, FALSE otherwise.
 */
gboolean
lasso_security_mech_id_is_null_authentication(const char *security_mech_id)
{
	if (strcmp(security_mech_id, 
			LASSO_SECURITY_MECH_CLIENT_TLS) == 0 ||
			strcmp(security_mech_id, 
					LASSO_SECURITY_MECH_TLS) == 0 ||
			strcmp(security_mech_id, 
					LASSO_SECURITY_MECH_NULL) == 0) {
		return TRUE;
	}
	return FALSE;
}
