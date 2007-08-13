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
%rename(Saml2Conditions) LassoSaml2Conditions;
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
} LassoSaml2Conditions;
%extend LassoSaml2Conditions {

#ifndef SWIG_PHP_RENAMES
	%rename(condition) Condition;
#endif
	%newobject Condition_get;
	LassoNodeList *Condition;

#ifndef SWIG_PHP_RENAMES
	%rename(audienceRestriction) AudienceRestriction;
#endif
	%newobject AudienceRestriction_get;
	LassoNodeList *AudienceRestriction;

#ifndef SWIG_PHP_RENAMES
	%rename(oneTimeUse) OneTimeUse;
#endif
	%newobject OneTimeUse_get;
	LassoNodeList *OneTimeUse;

#ifndef SWIG_PHP_RENAMES
	%rename(proxyRestriction) ProxyRestriction;
#endif
	%newobject ProxyRestriction_get;
	LassoNodeList *ProxyRestriction;


	/* Constructor, Destructor & Static Methods */
	LassoSaml2Conditions();
	~LassoSaml2Conditions();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Condition */

#define LassoSaml2Conditions_get_Condition(self) get_node((self)->Condition)
#define LassoSaml2Conditions_Condition_get(self) get_node((self)->Condition)
#define LassoSaml2Conditions_set_Condition(self,value) set_node((gpointer*)&(self)->Condition, (value))
#define LassoSaml2Conditions_Condition_set(self,value) set_node((gpointer*)&(self)->Condition, (value))
                    

/* AudienceRestriction */

#define LassoSaml2Conditions_get_AudienceRestriction(self) get_node((self)->AudienceRestriction)
#define LassoSaml2Conditions_AudienceRestriction_get(self) get_node((self)->AudienceRestriction)
#define LassoSaml2Conditions_set_AudienceRestriction(self,value) set_node((gpointer*)&(self)->AudienceRestriction, (value))
#define LassoSaml2Conditions_AudienceRestriction_set(self,value) set_node((gpointer*)&(self)->AudienceRestriction, (value))
                    

/* OneTimeUse */

#define LassoSaml2Conditions_get_OneTimeUse(self) get_node((self)->OneTimeUse)
#define LassoSaml2Conditions_OneTimeUse_get(self) get_node((self)->OneTimeUse)
#define LassoSaml2Conditions_set_OneTimeUse(self,value) set_node((gpointer*)&(self)->OneTimeUse, (value))
#define LassoSaml2Conditions_OneTimeUse_set(self,value) set_node((gpointer*)&(self)->OneTimeUse, (value))
                    

/* ProxyRestriction */

#define LassoSaml2Conditions_get_ProxyRestriction(self) get_node((self)->ProxyRestriction)
#define LassoSaml2Conditions_ProxyRestriction_get(self) get_node((self)->ProxyRestriction)
#define LassoSaml2Conditions_set_ProxyRestriction(self,value) set_node((gpointer*)&(self)->ProxyRestriction, (value))
#define LassoSaml2Conditions_ProxyRestriction_set(self,value) set_node((gpointer*)&(self)->ProxyRestriction, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2Conditions lasso_saml2_conditions_new
#define delete_LassoSaml2Conditions(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2Conditions_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

