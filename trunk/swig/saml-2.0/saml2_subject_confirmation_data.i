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
%rename(Saml2SubjectConfirmationData) LassoSaml2SubjectConfirmationData;
#endif
typedef struct {
#ifndef SWIG_PHP_RENAMES
	%rename(notBefore) NotBefore;
#endif
	char *NotBefore;
#ifndef SWIG_PHP_RENAMES
	%rename(notOnOrAfter) NotOnOrAfter;
#endif
	char *NotOnOrAfter;
#ifndef SWIG_PHP_RENAMES
	%rename(recipient) Recipient;
#endif
	char *Recipient;
#ifndef SWIG_PHP_RENAMES
	%rename(inResponseTo) InResponseTo;
#endif
	char *InResponseTo;
#ifndef SWIG_PHP_RENAMES
	%rename(address) Address;
#endif
	char *Address;
} LassoSaml2SubjectConfirmationData;
%extend LassoSaml2SubjectConfirmationData {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2SubjectConfirmationData();
	~LassoSaml2SubjectConfirmationData();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2SubjectConfirmationData lasso_saml2_subject_confirmation_data_new
#define delete_LassoSaml2SubjectConfirmationData(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2SubjectConfirmationData_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

