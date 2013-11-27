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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "../private.h"
#include "ds_x509_data.h"

/**
 * SECTION:ds_x509_data
 * @short_description: object mapping for an XML DSIG KeyValue element
 *
 */

struct _LassoDsX509DataPrivate {
	char *X509Certificate;
	char *X509SubjectName;
	char *X509CRL;
};
#define LASSO_DS_X509_DATA_GET_PRIVATE(o) \
	   (G_TYPE_INSTANCE_GET_PRIVATE ((o), LASSO_TYPE_DS_X509_DATA, LassoDsX509DataPrivate))

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "X509Certificate", SNIPPET_CONTENT|SNIPPET_PRIVATE,
		G_STRUCT_OFFSET(LassoDsX509DataPrivate, X509Certificate), NULL, NULL, NULL},
	{ "X509SubjectName", SNIPPET_CONTENT|SNIPPET_PRIVATE,
		G_STRUCT_OFFSET(LassoDsX509DataPrivate, X509SubjectName), NULL, NULL, NULL},
	{ "X509CRL", SNIPPET_CONTENT|SNIPPET_PRIVATE, G_STRUCT_OFFSET(LassoDsX509DataPrivate,
			X509CRL), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDsX509Data *x509_data)
{
	x509_data->private_data = LASSO_DS_X509_DATA_GET_PRIVATE(x509_data);
}

static void
class_init(LassoDsX509DataClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "X509Data");
	lasso_node_class_set_ns(nclass, LASSO_DS_HREF, LASSO_DS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	g_type_class_add_private(klass, sizeof(LassoDsX509DataPrivate));
}

GType
lasso_ds_x509_data_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDsX509DataClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDsX509Data),
			0,
			(GInstanceInitFunc)instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDsX509Data", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_ds_x509_data_new:
 *
 * Creates a new #LassoDsX509Data object.
 *
 * Return value: a newly created #LassoDsX509Data object
 **/
LassoDsX509Data*
lasso_ds_x509_data_new()
{
	return g_object_new(LASSO_TYPE_DS_X509_DATA, NULL);
}

/**
 * lasso_ds_x509_data_get_certificate:
 * @x509_data: a #LassoDsX509Data object
 *
 * Return the content of the X509Certificate sub-element, it should be a base64 encoded string.
 *
 * Return value:(transfer none): the string currently set in the X509Certificate private field of
 * the #LassoDsX509Data structure.
 */
const char*
lasso_ds_x509_data_get_certificate(LassoDsX509Data *x509_data) {
	lasso_return_val_if_fail(LASSO_IS_DS_X509_DATA(x509_data), NULL);
	return x509_data->private_data->X509Certificate;
}

/**
 * lasso_ds_x509_data_set_certificate:
 * @x509_data: a #LassoDsX509Data object
 * @certificate: a base64 encoded string of the DER representation of the X509 certificate
 *
 * Set the content of the X509Certificate sub-element, it should be a base64 encoded string.
 *
 */
void
lasso_ds_x509_data_set_certificate(LassoDsX509Data *x509_data, const char *certificate) {
	lasso_return_if_fail(LASSO_IS_DS_X509_DATA(x509_data));
	lasso_assign_string(x509_data->private_data->X509Certificate, certificate);
}

/**
 * lasso_ds_x509_data_get_subject_name:
 * @x509_data: a #LassoDsX509Data object
 *
 * Return the content of the X509SubjectName sub-element, it should be a base64 encoded string.
 *
 * Return value:(transfer none): the string currently set in the X509SubjectName private field of
 * the #LassoDsX509Data structure.
 */
const char*
lasso_ds_x509_data_get_subject_name(LassoDsX509Data *x509_data) {
	lasso_return_val_if_fail(LASSO_IS_DS_X509_DATA(x509_data), NULL);
	return x509_data->private_data->X509SubjectName;
}

/**
 * lasso_ds_x509_data_set_subject_name:
 * @x509_data: a #LassoDsX509Data object
 * @subject_name: a base64 encoded string of the DER representation of the X509 subject_name
 *
 * Set the content of the X509SubjectName sub-element, it should be a base64 encoded string.
 *
 */
void
lasso_ds_x509_data_set_subject_name(LassoDsX509Data *x509_data, const char *subject_name) {
	lasso_return_if_fail(LASSO_IS_DS_X509_DATA(x509_data));
	lasso_assign_string(x509_data->private_data->X509SubjectName, subject_name);
}

/**
 * lasso_ds_x509_data_get_crl:
 * @x509_data: a #LassoDsX509Data object
 *
 * Return the content of the X509CRL sub-element, it should be a base64 encoded string.
 *
 * Return value:(transfer none): the string currently set in the X509CRL private field of
 * the #LassoDsX509Data structure.
 */
const char*
lasso_ds_x509_data_get_crl(LassoDsX509Data *x509_data) {
	lasso_return_val_if_fail(LASSO_IS_DS_X509_DATA(x509_data), NULL);
	return x509_data->private_data->X509CRL;
}

/**
 * lasso_ds_x509_data_set_crl:
 * @x509_data: a #LassoDsX509Data object
 * @crl: a base64 encoded string of the DER representation of the X509 CRL
 *
 * Set the content of the X509CRL sub-element, it should be a base64 encoded string.
 *
 */
void
lasso_ds_x509_data_set_crl(LassoDsX509Data *x509_data, const char *crl) {
	lasso_return_if_fail(LASSO_IS_DS_X509_DATA(x509_data));
	lasso_assign_string(x509_data->private_data->X509CRL, crl);
}
