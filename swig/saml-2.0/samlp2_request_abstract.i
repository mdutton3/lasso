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
%rename(Samlp2RequestAbstract) LassoSamlp2RequestAbstract;
#endif
typedef struct {
#ifndef SWIG_PHP_RENAMES
	%rename(iD) ID;
#endif
	char *ID;
#ifndef SWIG_PHP_RENAMES
	%rename(version) Version;
#endif
	char *Version;
#ifndef SWIG_PHP_RENAMES
	%rename(issueInstant) IssueInstant;
#endif
	char *IssueInstant;
#ifndef SWIG_PHP_RENAMES
	%rename(destination) Destination;
#endif
	char *Destination;
#ifndef SWIG_PHP_RENAMES
	%rename(consent) Consent;
#endif
	char *Consent;
} LassoSamlp2RequestAbstract;
%extend LassoSamlp2RequestAbstract {

#ifndef SWIG_PHP_RENAMES
	%rename(issuer) Issuer;
#endif
	%newobject Issuer_get;
	LassoSaml2NameID *Issuer;

#ifndef SWIG_PHP_RENAMES
	%rename(extensions) Extensions;
#endif
	%newobject Extensions_get;
	LassoSamlp2Extensions *Extensions;


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2RequestAbstract();
	~LassoSamlp2RequestAbstract();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Issuer */

#define LassoSamlp2RequestAbstract_get_Issuer(self) get_node((self)->Issuer)
#define LassoSamlp2RequestAbstract_Issuer_get(self) get_node((self)->Issuer)
#define LassoSamlp2RequestAbstract_set_Issuer(self,value) set_node((gpointer*)&(self)->Issuer, (value))
#define LassoSamlp2RequestAbstract_Issuer_set(self,value) set_node((gpointer*)&(self)->Issuer, (value))
                    

/* Extensions */

#define LassoSamlp2RequestAbstract_get_Extensions(self) get_node((self)->Extensions)
#define LassoSamlp2RequestAbstract_Extensions_get(self) get_node((self)->Extensions)
#define LassoSamlp2RequestAbstract_set_Extensions(self,value) set_node((gpointer*)&(self)->Extensions, (value))
#define LassoSamlp2RequestAbstract_Extensions_set(self,value) set_node((gpointer*)&(self)->Extensions, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2RequestAbstract lasso_samlp2_request_abstract_new
#define delete_LassoSamlp2RequestAbstract(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2RequestAbstract_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

