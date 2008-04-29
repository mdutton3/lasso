#include <php.h>
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include <lasso/lasso.h>
#include "php_lasso.h"

int le_lasso_server;

ZEND_GET_MODULE(lasso)

typedef struct {
	GObject *obj;
	char *typename;
} PhpGObjectPtr;

PHP_FUNCTION(lasso_get_object_typename)
{
	PhpGObjectPtr *self;
	zval *zval_self;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zval_self) == FAILURE) {
		RETURN_FALSE;
	}

	ZEND_FETCH_RESOURCE(self, PhpGObjectPtr *, &zval_self, -1, PHP_LASSO_SERVER_RES_NAME, le_lasso_server);
	RETURN_STRING(self->typename, 1);
}

static char*
get_string_from_xml_node(xmlNode *xmlnode)
{
	xmlOutputBufferPtr buf;
	char *xmlString;

	if (xmlnode == NULL) {
		return NULL;
	}

	buf = xmlAllocOutputBuffer(NULL);
	if (buf == NULL) {
		xmlString = NULL;
	} else {
		xmlNodeDumpOutput(buf, NULL, xmlnode, 0, 1, NULL);
		xmlOutputBufferFlush(buf);
		if (buf->conv == NULL) {
			xmlString = estrdup((char*)buf->buffer->content);
		} else {
			xmlString = estrdup((char*)buf->conv->content);
		}
		xmlOutputBufferClose(buf);
	}

	return xmlString;
}

static xmlNode*
get_xml_node_from_string(char *string)
{
	xmlDoc *doc;
	xmlNode *node;

	doc = xmlReadDoc((xmlChar*)string, NULL, NULL, XML_PARSE_NONET);
	node = xmlDocGetRootElement(doc);
	if (node != NULL) {
		node = xmlCopyNode(node, 1);
	}
	xmlFreeDoc(doc);

	return node;
}

static GList*
get_list_from_array_of_strings(zval* array)
{
	HashTable* hashtable;
	HashPosition pointer;
	int size;
	zval** data;
	zval temp;
	GList* result = NULL;

	hashtable = Z_ARRVAL_P(array);
	size = zend_hash_num_elements(hashtable);
	for (zend_hash_internal_pointer_reset_ex(hashtable, &pointer);
			zend_hash_get_current_data_ex(hashtable, (void**) &data, &pointer) == SUCCESS;
			zend_hash_move_forward_ex(hashtable, &pointer)) {
		temp = **data;
		zval_copy_ctor(&temp);
		convert_to_string(&temp);
		result = g_list_append(result, estrndup(Z_STRVAL(temp), Z_STRLEN(temp)));
		zval_dtor(&temp);
	}
	return result;
}

/* utility functions */

#if (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION < 14)
  /* copy of private struct and g_hash_table_get_keys from GLib internals
   * (as this function is useful but new in 2.14) */

typedef struct _GHashNode  GHashNode;

struct _GHashNode
{
  gpointer   key;
  gpointer   value;
  GHashNode *next;
  guint      key_hash;
};

struct _GHashTable
{
  gint             size;
  gint             nnodes;
  GHashNode      **nodes;
  GHashFunc        hash_func;
  GEqualFunc       key_equal_func;
  volatile gint    ref_count;
  GDestroyNotify   key_destroy_func;
  GDestroyNotify   value_destroy_func;
};

GList *
g_hash_table_get_keys (GHashTable *hash_table)
{
  GHashNode *node;
  gint i;
  GList *retval;

  g_return_val_if_fail (hash_table != NULL, NULL);

  retval = NULL;
  for (i = 0; i < hash_table->size; i++)
    for (node = hash_table->nodes[i]; node; node = node->next)
      retval = g_list_prepend (retval, node->key);

  return retval;
}

#endif

static void
set_array_from_hashtable_of_objects(GHashTable *value, zval **array)
{
	GList *keys;
	GObject *item_value;
	PhpGObjectPtr *tmp_item;
	zval *item;

	array_init(*array);
	for (keys = g_hash_table_get_keys(value); keys; keys = g_list_next(keys)) {
		item_value = g_hash_table_lookup(value, keys->data);
		if (item_value) {
			tmp_item = (PhpGObjectPtr *)emalloc(sizeof(PhpGObjectPtr));
			tmp_item->obj = G_OBJECT(item_value);
			tmp_item->typename = estrdup(G_OBJECT_TYPE_NAME(G_OBJECT(item_value)));
			ZEND_REGISTER_RESOURCE(item, tmp_item, le_lasso_server);
			add_assoc_zval(*array, (char*)keys->data, item);
		} else {
			add_assoc_null(*array, (char*)keys->data);
		}
	}
	g_list_free(keys);
}

static GHashTable*
get_hashtable_from_array_of_strings(zval* array)
{
	HashTable* hashtable;
	HashPosition pointer;
	int size;
	char *key;
	unsigned int key_len;
	unsigned long index;
	zval** data;
	zval temp;
	GHashTable* result = NULL;

	hashtable = Z_ARRVAL_P(array);
	size = zend_hash_num_elements(hashtable);
	for (zend_hash_internal_pointer_reset_ex(hashtable, &pointer);
			zend_hash_get_current_data_ex(hashtable, (void**) &data, &pointer) == SUCCESS;
			zend_hash_move_forward_ex(hashtable, &pointer)) {
		temp = **data;
		zval_copy_ctor(&temp);
		convert_to_string(&temp);
		if (zend_hash_get_current_key_ex(hashtable, &key, &key_len, &index, 0, &pointer) == HASH_KEY_IS_STRING) {
			g_hash_table_insert(result, key, estrndup(Z_STRVAL(temp), Z_STRLEN(temp))); 
		} else {
			g_hash_table_insert(result, (void*)index, estrndup(Z_STRVAL(temp), Z_STRLEN(temp))); 
		}
		zval_dtor(&temp);
	}
	return result;
}

static GHashTable*
get_hashtable_from_array_of_objects(zval *array)
{
	HashTable *hashtable;
	HashPosition pointer;
	int size;
	char *key;
	unsigned int key_len;
	unsigned long index;
	zval **data;
	PhpGObjectPtr *cvt_temp;
	GHashTable *result = NULL;

	result = g_hash_table_new(g_str_hash, g_str_equal);
	hashtable = Z_ARRVAL_P(array);
	size = zend_hash_num_elements(hashtable);
	for (zend_hash_internal_pointer_reset_ex(hashtable, &pointer);
			zend_hash_get_current_data_ex(hashtable, (void**) &data, &pointer) == SUCCESS;
			zend_hash_move_forward_ex(hashtable, &pointer)) {
		cvt_temp = (PhpGObjectPtr*) zend_fetch_resource(data TSRMLS_CC, -1, PHP_LASSO_SERVER_RES_NAME, NULL, 1, le_lasso_server);
		if (zend_hash_get_current_key_ex(hashtable, &key, &key_len, &index, 0, &pointer) == HASH_KEY_IS_STRING) {
			if (cvt_temp != NULL) {
				g_hash_table_insert(result, key, cvt_temp->obj);
			} else {
				g_hash_table_insert(result, key, NULL);
			} 
		} else {
			if (cvt_temp != NULL) {
				g_hash_table_insert(result, (gpointer)index, cvt_temp->obj); 
			} else {
				g_hash_table_insert(result, (gpointer)index, NULL); 
			} 
		}
	}
	return result;
}

