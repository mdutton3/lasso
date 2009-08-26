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

#include "private.h"
#include "ds_rsa_key_value.h"

/*
 * SECTION:ds_rsa_key_value
 * @short_description: Object representation of an XML DSIG element to hold an RSA key
 *
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Modulus", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoDsRsaKeyValue, Modulus), NULL, NULL, NULL},
	{ "Exponent", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoDsRsaKeyValue, Exponent), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoDsRsaKeyValueClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "RsaKeyValue");
	lasso_node_class_set_ns(nclass, LASSO_DS_HREF, LASSO_DS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_ds_rsa_key_value_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDsRsaKeyValueClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDsRsaKeyValue),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDsRsaKeyValue", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_ds_rsa_key_value_new:
 *
 * Creates a new #LassoDsRsaKeyValue object.
 *
 * Return value: a newly created #LassoDsRsaKeyValue object
 **/
LassoDsRsaKeyValue*
lasso_ds_rsa_key_value_new()
{
	return g_object_new(LASSO_TYPE_DS_RSA_KEY_VALUE, NULL);
}
