/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#ifndef __LASSO_DISCO_MODIFY_H__
#define __LASSO_DISCO_MODIFY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>

#define LASSO_TYPE_DISCO_MODIFY (lasso_disco_modify_get_type())
#define LASSO_DISCO_MODIFY(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_DISCO_MODIFY, LassoDiscoModify))
#define LASSO_DISCO_MODIFY_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_DISCO_MODIFY, LassoDiscoModifyClass))
#define LASSO_IS_DISCO_MODIFY(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DISCO_MODIFY))
#define LASSO_IS_DISCO_MODIFY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DISCO_MODIFY))
#define LASSO_DISCO_MODIFY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DISCO_MODIFY, LassoDiscoModifyClass)) 

typedef struct _LassoDiscoModify LassoDiscoModify;
typedef struct _LassoDiscoModifyClass LassoDiscoModifyClass;

/*
The schema fragment (liberty-idwsf-disco-svc-1.0-errata-v1.0.xsd):

<xs:element name="Modify" type="ModifyType"/>
<xs:complexType name="ModifyType">
   <xs:sequence>
      <xs:group ref="ResourceIDGroup"/>
      <xs:element name="InsertEntry" type="InsertEntryType" minOccurs="0" maxOccurs="unbounded"/>
      <xs:element name="RemoveEntry" type="RemoveEntryType" minOccurs="0" maxOccurs="unbounded"/>
   </xs:sequence>
   <xs:attribute name="id" type="xs:ID" use="optional"/>
</xs:complexType>

<xs:group name="ResourceIDGroup">
   <xs:sequence>
      <xs:choice minOccurs="0" maxOccurs="1">
         <xs:element ref="ResourceID"/>
         <xs:element ref="EncryptedResourceID"/>
      </xs:choice>
   </xs:sequence>
</xs:group>
*/

struct _LassoDiscoModify {
	LassoNode parent;

	char *ResourceID;
	char *EncryptedResourceID;

	GList *InsertEntry;
	GList *RemoveEntry;

	char *id;
};

struct _LassoDiscoModifyClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_disco_modify_get_type (void);

LASSO_EXPORT LassoDiscoModify* lasso_disco_modify_new (char     *resourceID,
						       gboolean  encrypted);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DISCO_MODIFY_H__ */
