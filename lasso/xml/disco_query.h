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

#ifndef __LASSO_LIB_DISCO_QUERY_H__
#define __LASSO_DISCO_QUERY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/xml/disco_requested_service_type.h>

#define LASSO_TYPE_DISCO_QUERY (lasso_disco_query_get_type())
#define LASSO_DISCO_QUERY(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
                                LASSO_TYPE_DISCO_QUERY, LassoDiscoQuery))
#define LASSO_DISCO_QUERY_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
                                        LASSO_TYPE_DISCO_QUERY, LassoDiscoQueryClass))
#define LASSO_IS_DISCO_QUERY(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DISCO_QUERY))
#define LASSO_IS_DISCO_QUERY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),LASSO_TYPE_DISCO_QUERY))
#define LASSO_DISCO_QUERY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), \
                                        LASSO_TYPE_DISCO_QUERY, LassoDiscoQueryClass)) 

typedef struct _LassoDiscoQuery LassoDiscoQuery;
typedef struct _LassoDiscoQueryClass LassoDiscoQueryClass;

/*
The schema fragment (liberty-idwsf-disco-svc-v1.0.xsd):

<xs: group name="ResourceIDGroup">
  <xs: sequence>
     <xs: choice minOccurs="0" maxOccurs="1">
       <xs: element ref="ResourceID"/>
       <xs: element ref="EncryptedResourceID"/>
     </xs: choice>
  </xs: sequence>
</xs: group>

<xs: element name="Query" type="QueryType"/>
<xs: complexType name="QueryType">
  <xs: sequence>
     <xs: group ref="ResourceIDGroup"/>
     <xs: element name="RequestedServiceType" minOccurs="0" maxOccurs="unbounded">
       <xs: complexType>
          <xs: sequence>
            <xs: element ref="ServiceType"/>
            <xs: element ref="Options" minOccurs="0"/>
          </xs: sequence>
       </xs: complexType>
     </xs: element>
  </xs: sequence>
  <xs: attribute name="id" type="xs: ID" use="optional"/>
</xs: complexType>
*/

struct _LassoDiscoQuery {
  LassoNode parent;

  char *ResourceID;
  char *EncryptedResourceID;
  GList *RequestedServiceType;
  gchar *id;
};

struct _LassoDiscoQueryClass {
  LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_disco_query_get_type(void);
LASSO_EXPORT LassoDiscoQuery* lasso_disco_query_new(const char *resourceID, gboolean is_encrypted);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DISCO_QUERY_H__ */
