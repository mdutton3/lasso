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
%rename(Saml2AuthnContext) LassoSaml2AuthnContext;
#endif
typedef struct {
#ifndef SWIG_PHP_RENAMES
	%rename(authnContextClassRef) AuthnContextClassRef;
#endif
	char *AuthnContextClassRef;
#ifndef SWIG_PHP_RENAMES
	%rename(authnContextDeclRef) AuthnContextDeclRef;
#endif
	char *AuthnContextDeclRef;
#ifndef SWIG_PHP_RENAMES
	%rename(authenticatingAuthority) AuthenticatingAuthority;
#endif
	char *AuthenticatingAuthority;
} LassoSaml2AuthnContext;
%extend LassoSaml2AuthnContext {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2AuthnContext();
	~LassoSaml2AuthnContext();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2AuthnContext lasso_saml2_authn_context_new
#define delete_LassoSaml2AuthnContext(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2AuthnContext_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

