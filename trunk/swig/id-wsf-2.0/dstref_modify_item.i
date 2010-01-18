/* $Id: dstref_modify_item.i,v 1.0 2005/10/14 15:17:55 fpeters Exp $ 
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
%rename(IdWsf2DstRefModifyItem) LassoIdWsf2DstRefModifyItem;
#endif
typedef struct {
#ifndef SWIGPHP4
	%rename(select) Select;
#endif
	char *Select;
	char *notChangedSince;
	gboolean overrideAllowed;
	char *id;
	char *itemID;
} LassoIdWsf2DstRefModifyItem;
%extend LassoIdWsf2DstRefModifyItem {

#ifndef SWIGPHP4
	%rename(newData) NewData;
#endif
	%newobject *NewData_get;
	LassoIdWsf2DstRefAppData *NewData;

	/* Constructor, Destructor & Static Methods */
	LassoIdWsf2DstRefModifyItem();
	~LassoIdWsf2DstRefModifyItem();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* NewData */

#define LassoIdWsf2DstRefModifyItem_get_NewData(self) get_node((self)->NewData)
#define LassoIdWsf2DstRefModifyItem_NewData_get(self) get_node((self)->NewData)
#define LassoIdWsf2DstRefModifyItem_set_NewData(self,value) set_node((gpointer*)&(self)->NewData, (value))
#define LassoIdWsf2DstRefModifyItem_NewData_set(self,value) set_node((gpointer*)&(self)->NewData, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoIdWsf2DstRefModifyItem lasso_idwsf2_dstref_modify_item_new
#define delete_LassoIdWsf2DstRefModifyItem(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIdWsf2DstRefModifyItem_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

