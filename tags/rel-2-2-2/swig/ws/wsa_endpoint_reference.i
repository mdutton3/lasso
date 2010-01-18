/* $Id: wsa_endpoint_reference.i,v 1.0 2005/10/14 15:17:55 fpeters Exp $ 
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
%rename(WsAddrEndpointReference) LassoWsAddrEndpointReference;
#endif
typedef struct {
} LassoWsAddrEndpointReference;
%extend LassoWsAddrEndpointReference {

#ifndef SWIGPHP4
	%rename(address) Address;
#endif
	%newobject *Address_get;
	LassoWsAddrAttributedURI *Address;

#ifndef SWIGPHP4
	%rename(referenceParameters) ReferenceParameters;
#endif
	%newobject *ReferenceParameters_get;
	LassoWsAddrReferenceParameters *ReferenceParameters;

#ifndef SWIGPHP4
	%rename(metadata) Metadata;
#endif
	%newobject *Metadata_get;
	LassoWsAddrMetadata *Metadata;

	/* any attribute */
	%immutable attributes;
	%newobject attributes_get;
	LassoStringDict *attributes;

	/* Constructor, Destructor & Static Methods */
	LassoWsAddrEndpointReference();
	~LassoWsAddrEndpointReference();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Address */

#define LassoWsAddrEndpointReference_get_Address(self) get_node((self)->Address)
#define LassoWsAddrEndpointReference_Address_get(self) get_node((self)->Address)
#define LassoWsAddrEndpointReference_set_Address(self,value) set_node((gpointer*)&(self)->Address, (value))
#define LassoWsAddrEndpointReference_Address_set(self,value) set_node((gpointer*)&(self)->Address, (value))
                    

/* ReferenceParameters */

#define LassoWsAddrEndpointReference_get_ReferenceParameters(self) get_node((self)->ReferenceParameters)
#define LassoWsAddrEndpointReference_ReferenceParameters_get(self) get_node((self)->ReferenceParameters)
#define LassoWsAddrEndpointReference_set_ReferenceParameters(self,value) set_node((gpointer*)&(self)->ReferenceParameters, (value))
#define LassoWsAddrEndpointReference_ReferenceParameters_set(self,value) set_node((gpointer*)&(self)->ReferenceParameters, (value))
                    

/* Metadata */

#define LassoWsAddrEndpointReference_get_Metadata(self) get_node((self)->Metadata)
#define LassoWsAddrEndpointReference_Metadata_get(self) get_node((self)->Metadata)
#define LassoWsAddrEndpointReference_set_Metadata(self,value) set_node((gpointer*)&(self)->Metadata, (value))
#define LassoWsAddrEndpointReference_Metadata_set(self,value) set_node((gpointer*)&(self)->Metadata, (value))
                    

/* any attribute */
LassoStringDict* LassoWsAddrEndpointReference_attributes_get(LassoWsAddrEndpointReference *self);
#define LassoWsAddrEndpointReference_get_attributes LassoWsAddrEndpointReference_attributes_get
LassoStringDict* LassoWsAddrEndpointReference_attributes_get(LassoWsAddrEndpointReference *self) {
        return self->attributes;
}
/* TODO: implement attributes_set */


/* Constructors, destructors & static methods implementations */

#define new_LassoWsAddrEndpointReference lasso_wsa_endpoint_reference_new
#define delete_LassoWsAddrEndpointReference(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoWsAddrEndpointReference_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

