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
%rename(Saml2BaseIDAbstract) LassoSaml2BaseIDAbstract;
#endif
typedef struct {
#ifndef SWIG_PHP_RENAMES
	%rename(nameQualifier) NameQualifier;
#endif
	char *NameQualifier;
#ifndef SWIG_PHP_RENAMES
	%rename(spNameQualifier) SPNameQualifier;
#endif
	char *SPNameQualifier;
} LassoSaml2BaseIDAbstract;
%extend LassoSaml2BaseIDAbstract {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2BaseIDAbstract();
	~LassoSaml2BaseIDAbstract();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2BaseIDAbstract lasso_saml2_base_idabstract_new
#define delete_LassoSaml2BaseIDAbstract(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2BaseIDAbstract_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

