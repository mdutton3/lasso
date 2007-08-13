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
%rename(Saml2Subject) LassoSaml2Subject;
#endif
typedef struct {
} LassoSaml2Subject;
%extend LassoSaml2Subject {

#ifndef SWIG_PHP_RENAMES
	%rename(baseID) BaseID;
#endif
	%newobject BaseID_get;
	LassoSaml2BaseIDAbstract *BaseID;

#ifndef SWIG_PHP_RENAMES
	%rename(nameID) NameID;
#endif
	%newobject NameID_get;
	LassoSaml2NameID *NameID;

#ifndef SWIG_PHP_RENAMES
	%rename(encryptedID) EncryptedID;
#endif
	%newobject EncryptedID_get;
	LassoSaml2EncryptedElement *EncryptedID;

#ifndef SWIG_PHP_RENAMES
	%rename(subjectConfirmation) SubjectConfirmation;
#endif
	%newobject SubjectConfirmation_get;
	LassoSaml2SubjectConfirmation *SubjectConfirmation;


	/* Constructor, Destructor & Static Methods */
	LassoSaml2Subject();
	~LassoSaml2Subject();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* BaseID */

#define LassoSaml2Subject_get_BaseID(self) get_node((self)->BaseID)
#define LassoSaml2Subject_BaseID_get(self) get_node((self)->BaseID)
#define LassoSaml2Subject_set_BaseID(self,value) set_node((gpointer*)&(self)->BaseID, (value))
#define LassoSaml2Subject_BaseID_set(self,value) set_node((gpointer*)&(self)->BaseID, (value))
                    

/* NameID */

#define LassoSaml2Subject_get_NameID(self) get_node((self)->NameID)
#define LassoSaml2Subject_NameID_get(self) get_node((self)->NameID)
#define LassoSaml2Subject_set_NameID(self,value) set_node((gpointer*)&(self)->NameID, (value))
#define LassoSaml2Subject_NameID_set(self,value) set_node((gpointer*)&(self)->NameID, (value))
                    

/* EncryptedID */

#define LassoSaml2Subject_get_EncryptedID(self) get_node((self)->EncryptedID)
#define LassoSaml2Subject_EncryptedID_get(self) get_node((self)->EncryptedID)
#define LassoSaml2Subject_set_EncryptedID(self,value) set_node((gpointer*)&(self)->EncryptedID, (value))
#define LassoSaml2Subject_EncryptedID_set(self,value) set_node((gpointer*)&(self)->EncryptedID, (value))
                    

/* SubjectConfirmation */

#define LassoSaml2Subject_get_SubjectConfirmation(self) get_node((self)->SubjectConfirmation)
#define LassoSaml2Subject_SubjectConfirmation_get(self) get_node((self)->SubjectConfirmation)
#define LassoSaml2Subject_set_SubjectConfirmation(self,value) set_node((gpointer*)&(self)->SubjectConfirmation, (value))
#define LassoSaml2Subject_SubjectConfirmation_set(self,value) set_node((gpointer*)&(self)->SubjectConfirmation, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2Subject lasso_saml2_subject_new
#define delete_LassoSaml2Subject(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2Subject_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

