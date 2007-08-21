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
%rename(Samlp2RequestedAuthnContext) LassoSamlp2RequestedAuthnContext;
#endif
typedef struct {
#ifndef SWIG_PHP_RENAMES
	%rename(comparison) Comparison;
#endif
	char *Comparison;
} LassoSamlp2RequestedAuthnContext;
%extend LassoSamlp2RequestedAuthnContext {

#ifndef SWIG_PHP_RENAMES
	%rename(authnContextClassRef) AuthnContextClassRef;
#endif
	%newobject AuthnContextClassRef_get;
	LassoStringList *AuthnContextClassRef;

#ifndef SWIG_PHP_RENAMES
	%rename(authnContextDeclRef) AuthnContextDeclRef;
#endif
	%newobject AuthnContextDeclRef_get;
	LassoStringList *AuthnContextDeclRef;


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2RequestedAuthnContext();
	~LassoSamlp2RequestedAuthnContext();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* AuthnContextClassRef */

#define LassoSamlp2RequestedAuthnContext_get_AuthnContextClassRef(self) get_string_list((self)->AuthnContextClassRef)
#define LassoSamlp2RequestedAuthnContext_AuthnContextClassRef_get(self) get_string_list((self)->AuthnContextClassRef)
#define LassoSamlp2RequestedAuthnContext_set_AuthnContextClassRef(self,value) set_string_list((gpointer*)&(self)->AuthnContextClassRef, (value))
#define LassoSamlp2RequestedAuthnContext_AuthnContextClassRef_set(self,value) set_string_list((gpointer*)&(self)->AuthnContextClassRef, (value))
                    

/* AuthnContextDeclRef */

#define LassoSamlp2RequestedAuthnContext_get_AuthnContextDeclRef(self) get_string_list((self)->AuthnContextDeclRef)
#define LassoSamlp2RequestedAuthnContext_AuthnContextDeclRef_get(self) get_string_list((self)->AuthnContextDeclRef)
#define LassoSamlp2RequestedAuthnContext_set_AuthnContextDeclRef(self,value) set_string_list((gpointer*)&(self)->AuthnContextDeclRef, (value))
#define LassoSamlp2RequestedAuthnContext_AuthnContextDeclRef_set(self,value) set_string_list((gpointer*)&(self)->AuthnContextDeclRef, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2RequestedAuthnContext lasso_samlp2_requested_authn_context_new
#define delete_LassoSamlp2RequestedAuthnContext(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2RequestedAuthnContext_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

