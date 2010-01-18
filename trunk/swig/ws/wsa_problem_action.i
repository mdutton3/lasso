/* $Id: wsa_problem_action.i,v 1.0 2005/10/14 15:17:55 fpeters Exp $ 
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

#ifndef SWIGPHP4
%rename(WsAddrProblemAction) LassoWsAddrProblemAction;
#endif
typedef struct {
#ifndef SWIGPHP4
	%rename(soapAction) SoapAction;
#endif
	char *SoapAction;
} LassoWsAddrProblemAction;
%extend LassoWsAddrProblemAction {

#ifndef SWIGPHP4
	%rename(action) Action;
#endif
	%newobject *Action_get;
	LassoWsAddrAttributedURI *Action;

	/* any attribute */
	%immutable attributes;
	%newobject attributes_get;
	LassoStringDict *attributes;

	/* Constructor, Destructor & Static Methods */
	LassoWsAddrProblemAction();
	~LassoWsAddrProblemAction();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Action */

#define LassoWsAddrProblemAction_get_Action(self) get_node((self)->Action)
#define LassoWsAddrProblemAction_Action_get(self) get_node((self)->Action)
#define LassoWsAddrProblemAction_set_Action(self,value) set_node((gpointer*)&(self)->Action, (value))
#define LassoWsAddrProblemAction_Action_set(self,value) set_node((gpointer*)&(self)->Action, (value))
                    

/* any attribute */
LassoStringDict* LassoWsAddrProblemAction_attributes_get(LassoWsAddrProblemAction *self);
#define LassoWsAddrProblemAction_get_attributes LassoWsAddrProblemAction_attributes_get
LassoStringDict* LassoWsAddrProblemAction_attributes_get(LassoWsAddrProblemAction *self) {
        return self->attributes;
}
/* TODO: implement attributes_set */


/* Constructors, destructors & static methods implementations */

#define new_LassoWsAddrProblemAction lasso_wsa_problem_action_new
#define delete_LassoWsAddrProblemAction(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoWsAddrProblemAction_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

