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

#include <glib.h>
#include "registry-private.h"


/**
 * SECTION:registry
 * @short_description: Class to store a mapping of QName to other QName.
 *
 * This object implement a function of (namespace, name, namespace) -> namespace.
 * For the moment there is no need to enumerate all (namespace, name) pair given
 * a base pair (i.e. a function (namespace, name) -> [(namespace,name)].
 *
 * A QName is a name qualified by a namespace.
 *
 * For internal use inside lasso we define the following namespace:
 * http://lasso.entrouvert.org/ns/GObject,
 * http://lasso.entrouvert.org/ns/python.
 */

typedef struct _LassoRegistryRecord LassoRegistryRecord;

struct _LassoRegistryRecord {
	GQuark from_namespace;
	GQuark from_name;
	GQuark to_namespace;
	GQuark to_name;
};


static LassoRegistry *lasso_registry_get_default() {
	static LassoRegistry *default_registry = NULL;
	if (default_registry == NULL) {
		default_registry = lasso_registry_new();
	}
	return default_registry;
}

/**
 * lasso_registry_record_equal:
 * @record1: left record
 * @record2: right record
 *
 * Tests if two #LassoRegistryRecord are equal.
 *
 * Return value: TRUE if all field of record1 are equal to record2.
 */
gboolean lasso_registry_record_equal(LassoRegistryRecord *record1, LassoRegistryRecord *record2)
{
	return record1->from_namespace == record2->from_namespace
		&& record1->from_name == record2->from_name
		&& record1->to_namespace == record2->to_namespace;
}

/**
 * lasso_registry_record_hash:
 * @record: a #LassoRegistryRecord structure
 *
 * Return a hash value obtained from the three first fields of a
 * #LassoRecordRegistry structure.
 *
 * Return value: an integer hash for the record.
 */
guint lasso_registry_record_hash(LassoRegistryRecord *record)
{
	return g_direct_hash((void*)(record->from_namespace
		^ record->from_name
		^ record->to_namespace));
}


/**
 * lasso_registry_new:
 *
 * Allocate a new #LassoRegistry structure and initialize its fields.
 *
 * Return value: a newly allocated #LassoRegistry object.
 */
LassoRegistry *lasso_registry_new()
{
	LassoRegistry *ret = g_new0(LassoRegistry, 1);

	ret->hash_map = g_hash_table_new((GHashFunc) lasso_registry_record_hash, (GEqualFunc) lasso_registry_record_equal);

	return ret;
}

/**
 * lasso_regsitry_get_mapping:
 *
 * Retrieve the mapping of a QName into another namespace, i.e. to another
 * QName.
 *
 * Return value: a constant string of NULL if no mapping exist.
 */
const char* lasso_registry_get_mapping(LassoRegistry *registry, const char *from_namespace,
		const char *from_name, const char *to_namespace)
{
	LassoRegistryRecord record;
	LassoRegistryRecord *found;

	record.from_namespace = g_quark_from_string(from_namespace);
	record.from_name = g_quark_from_string(from_name);
	record.to_namespace = g_quark_from_string(to_namespace);

	found = g_hash_table_lookup(registry->hash_map, &record);

	if (found) {
		return g_quark_to_string(found->to_name);
	} else {
		return NULL;
	}
}

/**
 * lasso_registry_add_mapping:
 *
 * Add a new mapping from a QName to a QName.
 *
 * Return value: 0 if successfull, -1 if it already exists, -2 if arguments
 * are invalid.
 */
gint lasso_registry_add_mapping(LassoRegistry *registry, const char *from_namespace,
		const char *from_name, const char *to_namespace, const char *to_name)
{
	LassoRegistryRecord *a_record;

	g_return_val_if_fail(registry && from_namespace && from_name && to_namespace && to_name, -2);

	if (! lasso_registry_get_mapping(registry, from_namespace, from_name, to_namespace)) {
		a_record = g_new0(LassoRegistryRecord, 1);
		a_record->from_namespace = g_quark_from_string(from_namespace);
		a_record->from_name = g_quark_from_string(from_name);
		a_record->to_namespace = g_quark_from_string(to_namespace);
		a_record->to_name = g_quark_from_string(to_name);
		g_hash_table_insert(registry->hash_map, a_record, a_record);
		return 0;
	}
	return -1;
}




/**
 * lasso_registry_default_add_mapping:
 * @from_namespace: the namespace of the mapped QName
 * @from_name: the name of the mapped QName
 * @to_namespace: the namepsace of the mapped to QName
 * @to_name: the name of the mapped to QName
 *
 * Add a new mapping from a QName to a QName.
 *
 * Return value: 0 if successfull, -1 if it already exists, -2 if arguments
 * are invalid.
 */
gint lasso_registry_default_add_mapping(const char *from_namespace,
		const char *from_name, const char *to_namespace, const char *to_name)
{
	LassoRegistry *default_registry = lasso_registry_get_default();

	return lasso_registry_add_mapping(default_registry, from_namespace, from_name, to_namespace, to_name);
}


/**
 * lasso_registry_default_get_mapping:
 * @from_namespace: the namespace of the mapped QName
 * @from_name: the name of the mapped QName
 * @to_namespace: the namepsace of the mapped to QName
 *
 * Retrieve the name of the QName in the namespace to_namespace that maps the
 * QName from_namespace:from_name.
 *
 * Return value: the name string of the QName or NULL if no mapping exists.
 */
const char* lasso_registry_default_get_mapping(const char *from_namespace,
		const char *from_name, const char *to_namespace)
{
	LassoRegistry *default_registry = lasso_registry_get_default();

	return lasso_registry_get_mapping(default_registry, from_namespace, from_name, to_namespace);
}
