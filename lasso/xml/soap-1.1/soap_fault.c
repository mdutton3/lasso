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

#include "./soap_fault.h"
#include "../private.h"
#include "../../utils.h"

/**
 * SECTION:soap_fault
 * @short_description: object mapping for a soap11:Fault
 * @stability: Stable
 *
 * <figure>
 * <title>Schema fragment for soap11:Fault</title>
 * <programlisting>
 * <![CDATA[
 * <xs: element name="Fault" type="tns: Fault"/>
 * <xs: complexType name="Fault" final="extension">
 *   <xs: annotation>
 *     <xs: documentation>
 *       Fault reporting structure
 *     </xs: documentation>
 *   </xs: annotation>
 *   <xs: sequence>
 *     <xs: element name="faultcode" type="xs: QName"/>
 *     <xs: element name="faultstring" type="xs: string"/>
 *     <xs: element name="faultactor" type="xs: anyURI" minOccurs="0"/>
 *     <xs: element name="detail" type="tns: detail" minOccurs="0"/>
 *   </xs: sequence>
 *  </xs: complexType>
 *
 *  <xs: complexType name="detail">
 *    <xs: sequence>
 *      <xs: any namespace="##any" minOccurs="0" maxOccurs="unbounded" processContents="lax"/>
 *    </xs: sequence>
 *    <xs: anyAttribute namespace="##any" processContents="lax"/>
 *  </xs: complexType>
 * ]]>
 * </programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "faultcode", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoSoapFault, faultcode), NULL, NULL, NULL},
	{ "faultstring", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoSoapFault, faultstring), NULL, NULL, NULL},
	{ "detail", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSoapFault, Detail), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSoapFaultClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Fault");
	lasso_node_class_set_ns(nclass, LASSO_SOAP_ENV_HREF, LASSO_SOAP_ENV_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_soap_fault_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSoapFaultClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSoapFault),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSoapFault", &this_info, 0);
	}
	return this_type;
}

LassoSoapFault*
lasso_soap_fault_new()
{
	LassoSoapFault *node;

	node = g_object_new(LASSO_TYPE_SOAP_FAULT, NULL);

	return node;
}

LassoSoapFault*
lasso_soap_fault_new_from_message(const gchar *message)
{
	LassoSoapFault *node;

	g_return_val_if_fail(message != NULL, NULL);

	node = g_object_new(LASSO_TYPE_SOAP_FAULT, NULL);
	lasso_node_init_from_message(LASSO_NODE(node), message);

	return node;
}

LassoSoapFault*
lasso_soap_fault_new_full(const char *faultcode, const char *faultstring)
{
	LassoSoapFault *soap_fault;

	if (! faultcode && ! faultstring)
		return NULL;
	soap_fault = g_object_new(LASSO_TYPE_SOAP_FAULT, NULL);
	lasso_assign_string(soap_fault->faultcode, faultcode);
	lasso_assign_string(soap_fault->faultstring, faultstring);

	return soap_fault;
}

