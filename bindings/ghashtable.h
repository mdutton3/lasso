#ifndef G_HASHTABLE_H
#define G_HASHTABLE_H 1
#if (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION < 14)

#include "../lasso/utils.h"

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

/* Helper functions to access JNI interface functions */
#if (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION < 12)
static gboolean return_true(G_GNUC_UNUSED gpointer a, G_GNUC_UNUSED gpointer b,
		G_GNUC_UNUSED gpointer c)
{
	return TRUE;
}

G_GNUC_UNUSED static void
g_hash_table_remove_all (GHashTable *hash_table)
{
    lasso_return_if_fail(hash_table != NULL);

    g_hash_table_foreach_remove (hash_table, (GHRFunc)return_true, NULL);
}
#endif
  /* copy of private struct and g_hash_table_get_keys from GLib internals
   * (as this function is useful but new in 2.14) */


G_GNUC_UNUSED static GList *
g_hash_table_get_keys (GHashTable *hash_table)
{
  GHashNode *node;
  gint i;
  GList *retval;

  lasso_return_val_if_fail(hash_table != NULL, NULL);

  retval = NULL;
  for (i = 0; i < hash_table->size; i++)
    for (node = hash_table->nodes[i]; node; node = node->next)
      retval = g_list_prepend (retval, node->key);

  return retval;
}

G_GNUC_UNUSED static GList *
g_hash_table_get_values (GHashTable *hash_table)
{
    GHashNode *node;
    gint i;
    GList *retval;

    lasso_return_val_if_fail(hash_table != NULL, NULL);

    retval = NULL;
    for (i = 0; i < hash_table->size; i++)
        for (node = hash_table->nodes[i]; node; node = node->next)
            retval = g_list_prepend (retval, node->value);

    return retval;
}
#endif
#endif /* G_HASHTABLE_H */
