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
#include "./registry-private.h"
#include "./errors.h"
#include "./utils.h"


/**
 * SECTION:registry
 * @short_description: Class to store a mapping of qualified names (QName) to other qualified names.
 *
 * A qualified name is a name or a string in the context of another name, or namespace.
 * This object implement a function of a tuple (namespace, name, namespace) to a name.  For the
 * moment there is no need to enumerate all tuples (namespace, name) pair given a base pair, i.e. a
 * function from tuple (namespace, name) to a list of tuples (namespace,name).
 *
 * We support two kinds of mapping:
 * <itemizedlist>
 * <listitem><para>you can give a direct mapping between two QName,</para></listitem>
 * <listitem><para>or you can give a function that will manage mapping between one namespace and
 * another one.</para></listitem>
 * </itemizedlist>
 *
 * For internal use inside lasso we define the following namespaces:
 * <itemizedlist>
 * <listitem><para>#LASSO_LASSO_HREF and,</para></listitem>
 * <listitem><para>#LASSO_PYTHON_HREF.</para></listitem>
 * </itemizedlist>
 *
 * For functional mappings the mapping function must return constant strings created using
 * g_intern_string() or using g_type_name().
 */

typedef struct _LassoRegistryDirectMappingRecord LassoRegistryDirectMappingRecord;

struct _LassoRegistryDirectMappingRecord {
	GQuark from_namespace;
	GQuark from_name;
	GQuark to_namespace;
	GQuark to_name;
};

typedef struct _LassoRegistryFunctionalMappingRecord LassoRegistryFunctionalMappingRecord;

struct _LassoRegistryFunctionalMappingRecord {
	GQuark from_namespace;
	GQuark to_namespace;
	LassoRegistryTranslationFunction translation_function;
};

static LassoRegistry *default_registry = NULL;

static LassoRegistry *lasso_registry_get_default() {
	if (default_registry == NULL) {
		default_registry = lasso_registry_new();
	}
	return default_registry;
}

void lasso_registry_default_shutdown()
{
	if (default_registry)
		lasso_registry_destroy(default_registry);
	default_registry = NULL;
}

/**
 * lasso_registry_direct_mapping_equal:
 * @record1: left record
 * @record2: right record
 *
 * Tests if two #LassoRegistryDirectMappingRecord are equal.
 *
 * Return value: TRUE if all field of record1 are equal to record2.
 */
gboolean lasso_registry_direct_mapping_equal(LassoRegistryDirectMappingRecord *record1,
		LassoRegistryDirectMappingRecord *record2)
{
	return record1->from_namespace == record2->from_namespace
		&& record1->from_name == record2->from_name
		&& record1->to_namespace == record2->to_namespace;
}

/**
 * lasso_registry_functional_mapping_equal:
 * @record1: left record
 * @record2: right record
 *
 * Tests if two #LassoRegistryFunctionalMappingRecord are equal, i.e.  if they are functional
 * mapping between the same namespace.
 *
 * Return value: TRUE if record1 is equal to record2
 */
gboolean lasso_registry_functional_mapping_equal(LassoRegistryFunctionalMappingRecord *record1,
		LassoRegistryFunctionalMappingRecord *record2)
{
	return record1->from_namespace == record2->from_namespace &&
		record1->to_namespace == record2->to_namespace;
}

/**
 * lasso_registry_direct_mapping_hash:
 * @record: a #LassoRegistryDirectMappingRecord structure
 *
 * Return a hash value obtained from the three first fields of a #LassoRecordRegistry structure.
 *
 * Return value: an integer hash for the record.
 */
guint lasso_registry_direct_mapping_hash(LassoRegistryDirectMappingRecord *record)
{
	return g_direct_hash((gpointer)((ptrdiff_t)record->from_namespace
		^ (ptrdiff_t)record->from_name
		^ (ptrdiff_t)record->to_namespace));
}

/**
 * lasso_registry_functional_mapping_hash:
 * @record: a #LassoRegistryFunctionalMappingRecord structure
 *
 * Return a hash value obtained from the source and destination namespace of the mapping.
 *
 * Return value: an integer hash for the record.
 */
guint lasso_registry_functional_mapping_hash(LassoRegistryFunctionalMappingRecord *record)
{
	return g_direct_hash((gpointer)((ptrdiff_t)record->from_namespace
				^ (ptrdiff_t)record->to_namespace));
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

	ret->direct_mapping = g_hash_table_new_full(
			(GHashFunc) lasso_registry_direct_mapping_hash,
			(GEqualFunc) lasso_registry_direct_mapping_equal,
			NULL,
			g_free);

	ret->functional_mapping = g_hash_table_new_full(
			(GHashFunc) lasso_registry_functional_mapping_hash,
			(GEqualFunc) lasso_registry_functional_mapping_equal,
			NULL,
			g_free);

	return ret;
}

/**
 * lasso_registry_destroy:
 * @registry: the #LassoRegistry object
 *
 * Destroy a #LassoRegistry.
 */
void lasso_registry_destroy(LassoRegistry *registry)
{
	g_return_if_fail(registry);

	lasso_release_ghashtable(registry->direct_mapping);
	lasso_release_ghashtable(registry->functional_mapping);
	lasso_release(registry);
}

static LassoRegistryTranslationFunction lasso_registry_get_translation_function(GHashTable *functional_mappings, GQuark from_ns_quark, GQuark to_ns_quark)
{
		LassoRegistryFunctionalMappingRecord functional_mapping, *functional_mapping_found;
		functional_mapping.from_namespace = from_ns_quark;
		functional_mapping.to_namespace = to_ns_quark;
		functional_mapping_found = g_hash_table_lookup(functional_mappings, &functional_mapping);

		if (functional_mapping_found) {
			return functional_mapping_found->translation_function;
		}
		return NULL;
}

static const char *lasso_registry_get_functional_mapping(GHashTable *functional_mappings,
		GQuark from_ns_namespace, const char *from_name, GQuark to_ns_namespace)
{
	LassoRegistryTranslationFunction translation_function;

	translation_function = lasso_registry_get_translation_function(functional_mappings, from_ns_namespace, to_ns_namespace);
	if (translation_function) {
		return translation_function(g_quark_to_string(from_ns_namespace), from_name, g_quark_to_string(to_ns_namespace));
	}
	return NULL;
}

static const char *lasso_registry_get_direct_mapping(GHashTable *direct_mappings,
		GQuark from_ns_quark, const char *from_name, GQuark to_ns_quark)
{
	GQuark from_name_quark = g_quark_try_string(from_name);
	LassoRegistryDirectMappingRecord record, *found;

	if (from_name_quark == 0)
		return NULL;

	record.from_namespace = from_ns_quark;
	record.from_name = from_name_quark;
	record.to_namespace = to_ns_quark;

	found = g_hash_table_lookup(direct_mappings, &record);

	if (found) {
		return g_quark_to_string(found->to_name);
	}
	return NULL;
}

/**
 * lasso_regsitry_get_mapping:
 *
 * Retrieve the mapping of a QName into another namespace, i.e. to another
 * QName. It first tries the functional mapping, then tries with the direct mapping.
 *
 * Return value: a constant string of NULL if no mapping exist.
 */
const char* lasso_registry_get_mapping(LassoRegistry *registry, const char *from_namespace,
		const char *from_name, const char *to_namespace)
{
	GQuark from_ns_quark, to_ns_quark;
	const char *ret = NULL;

	from_ns_quark = g_quark_try_string(from_namespace);
	to_ns_quark = g_quark_try_string(to_namespace);

	if (from_ns_quark == 0 || to_ns_quark == 0) {
		return NULL;
	}

	ret = lasso_registry_get_functional_mapping(registry->functional_mapping, from_ns_quark, from_name, to_ns_quark);
	if (ret == NULL) {
		ret = lasso_registry_get_direct_mapping(registry->direct_mapping, from_ns_quark, from_name, to_ns_quark);
	}

	return ret;
}

/**
 * lasso_registry_add_direct_mapping:
 *
 * Add a new mapping from a QName to a QName.
 *
 * Return value: 0 if successfull, LASSO_REGISTRY_ERROR_KEY_EXISTS if it already exists,
 * LASSO_PARAM_ERROR_INVALID_VALUE if arguments
 * are invalid.
 */
gint lasso_registry_add_direct_mapping(LassoRegistry *registry, const char *from_namespace,
		const char *from_name, const char *to_namespace, const char *to_name)
{
	LassoRegistryDirectMappingRecord *a_record;

	g_return_val_if_fail(registry && from_namespace && from_name && to_namespace && to_name, LASSO_PARAM_ERROR_INVALID_VALUE);

	if (lasso_registry_get_mapping(registry, from_namespace, from_name, to_namespace)) {
		return LASSO_REGISTRY_ERROR_KEY_EXISTS;
	}
	a_record = g_new0(LassoRegistryDirectMappingRecord, 1);
	a_record->from_namespace = g_quark_from_string(from_namespace);
	a_record->from_name = g_quark_from_string(from_name);
	a_record->to_namespace = g_quark_from_string(to_namespace);
	a_record->to_name = g_quark_from_string(to_name);
	g_hash_table_insert(registry->direct_mapping, a_record, a_record);
	return 0;
}

/**
 * lasso_registry_add_functional_mapping:
 * @registry: a #LassoRegistry
 * @from_namespace: URI of the source namespace
 * @to_namespace: URI of the destination namespace
 * @translation_function: a function mapping string to string from the first namespace to the second one
 *
 * Register a new mapping from from_namesapce to to_namespace using the
 * translation_function. This functions is not forced to return a value for
 * any string, it can return NULL.
 *
 * Return value: 0 if successfull, LASSO_REGISTRY_ERROR_KEY_EXISTS if this mapping is already registered,
 * LASSO_PARAM_ERROR_INVALID_VALUE if one the argument is invalid.
 */
gint lasso_registry_add_functional_mapping(LassoRegistry *registry, const char *from_namespace,
		const char *to_namespace, LassoRegistryTranslationFunction translation_function)
{
	LassoRegistryFunctionalMappingRecord *a_record;
	GQuark to_ns_quark, from_ns_quark;

	g_return_val_if_fail(registry != NULL && from_namespace != NULL && to_namespace != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);
	from_ns_quark = g_quark_from_string(from_namespace);
	to_ns_quark = g_quark_from_string(to_namespace);
	if (lasso_registry_get_translation_function(registry->functional_mapping, from_ns_quark, to_ns_quark)) {
		return LASSO_REGISTRY_ERROR_KEY_EXISTS;
	}
	a_record = g_new0(LassoRegistryFunctionalMappingRecord, 1);
	a_record->from_namespace = from_ns_quark;
	a_record->to_namespace = to_ns_quark;
	a_record->translation_function = translation_function;

	g_hash_table_insert(registry->functional_mapping, a_record, a_record);

	return 0;
}

/**
 * lasso_registry_default_add_direct_mapping:
 * @from_namespace: the namespace of the mapped QName
 * @from_name: the name of the mapped QName
 * @to_namespace: the namepsace of the mapped to QName
 * @to_name: the name of the mapped to QName
 *
 * Add a new mapping from a QName to a QName.
 *
 * Return value: 0 if successfull, LASSO_REGISTRY_ERROR_KEY_EXISTS if this mapping is already registered,
 * LASSO_PARAM_ERROR_INVALID_VALUE if one the argument is invalid.
 */
gint lasso_registry_default_add_direct_mapping(const char *from_namespace,
		const char *from_name, const char *to_namespace, const char *to_name)
{
	LassoRegistry *default_registry = lasso_registry_get_default();

	return lasso_registry_add_direct_mapping(default_registry, from_namespace, from_name, to_namespace, to_name);
}

/**
 * lasso_registry_default_add_functional_mapping:
 *
 * @from_namespace: URI of the source namespace
 * @to_namespace: URI of the destination namespace
 * @translation_function: a function mapping string to string from the first namespace to the second one
 *
 * Register a new mapping from from_namesapce to to_namespace using the translation_function into
 * the default mapping. This functions is not forced to return a value for any string, it can return
 * NULL.
 *
 * Return value: 0 if successfull, LASSO_REGISTRY_ERROR_KEY_EXISTS if this mapping is already registered,
 * LASSO_PARAM_ERROR_INVALID_VALUE if one the argument is invalid.
 */
gint lasso_registry_default_add_functional_mapping(const char *from_namespace,
		const char *to_namespace, LassoRegistryTranslationFunction translation_function)
{
	LassoRegistry *default_registry = lasso_registry_get_default();

	return lasso_registry_add_functional_mapping(default_registry, from_namespace, to_namespace, translation_function);
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
