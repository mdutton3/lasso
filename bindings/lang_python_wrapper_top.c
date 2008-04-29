#include <Python.h>
#include <structmember.h>
#include <lasso/lasso.h>
#include <lasso_config.h>

GQuark lasso_wrapper_key;

PyMODINIT_FUNC init_lasso(void);
static PyObject* get_pystring_from_xml_node(xmlNode *xmlnode);
static xmlNode*  get_xml_node_from_pystring(PyObject *string);
static PyObject* get_dict_from_hashtable_of_strings(GHashTable *value);
static PyObject* get_dict_from_hashtable_of_objects(GHashTable *value);
static PyObject* PyGObjectPtr_New(GObject *obj);

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

static PyObject*
get_dict_from_hashtable_of_strings(GHashTable *value)
{
	GList *keys;
	PyObject *dict;
	char *item_value;
	PyObject *item;

	dict = PyDict_New();

	keys = g_hash_table_get_keys(value);
	for (; keys; keys = g_list_next(keys)) {
		item_value = g_hash_table_lookup(value, keys->data);
		if (item_value) {
			item = PyString_FromString(item_value);
			PyDict_SetItemString(dict, (char*)keys->data, item); 
		} else {
			PyDict_SetItemString(dict, (char*)keys->data, Py_None); 
		}
	}
	g_list_free(keys);

	return PyDictProxy_New(dict);
}

static PyObject*
get_dict_from_hashtable_of_objects(GHashTable *value)
{
	GList *keys;
	PyObject *dict;
	GObject *item_value;
	PyObject *item;

	dict = PyDict_New();

	keys = g_hash_table_get_keys(value);
	for (; keys; keys = g_list_next(keys)) {
		item_value = g_hash_table_lookup(value, keys->data);
		if (item_value) {
			item = PyGObjectPtr_New(G_OBJECT(item_value));
			PyDict_SetItemString(dict, (char*)keys->data, item); 
		} else {
			PyDict_SetItemString(dict, (char*)keys->data, Py_None); 
		}
	}
	g_list_free(keys);

	return PyDictProxy_New(dict);
}

static PyObject*
get_pystring_from_xml_node(xmlNode *xmlnode)
{
	xmlOutputBufferPtr buf;
	PyObject *pystring = NULL;

	if (xmlnode == NULL) {
		return NULL;
	}

	buf = xmlAllocOutputBuffer(NULL);
	if (buf == NULL) {
		pystring = NULL;
	} else {
		xmlNodeDumpOutput(buf, NULL, xmlnode, 0, 1, NULL);
		xmlOutputBufferFlush(buf);
		if (buf->conv == NULL) {
			pystring = PyString_FromString((char*)buf->buffer->content);
		} else {
			pystring = PyString_FromString((char*)buf->conv->content);
		}
		xmlOutputBufferClose(buf);
	}

	return pystring;
}

static xmlNode*
get_xml_node_from_pystring(PyObject *string) {
	xmlDoc *doc;
	xmlNode *node;

	doc = xmlReadDoc((xmlChar*)PyString_AsString(string), NULL, NULL, XML_PARSE_NONET);
	node = xmlDocGetRootElement(doc);
	if (node != NULL) {
		node = xmlCopyNode(node, 1);
	}
	xmlFreeDoc(doc);

	return node;
}


/* wrapper around GObject */

typedef struct {
	PyObject_HEAD
	GObject *obj;
	PyObject *typename;
} PyGObjectPtr;

static PyTypeObject PyGObjectPtrType;

static void
PyGObjectPtr_dealloc(PyGObjectPtr *self)
{
#ifdef LASSO_DEBUG
	fprintf(stderr, "dealloc (%p ptr to %p (type:%s, rc:%d))\n",
			self, self->obj,
			G_OBJECT_TYPE_NAME(self->obj),
			self->obj->ref_count);
#endif
	g_object_unref(self->obj);
	Py_XDECREF(self->typename);
	self->ob_type->tp_free((PyObject*)self);
}

static PyObject*
PyGObjectPtr_New(GObject *obj)
{
	PyGObjectPtr *self;

	if (obj == NULL) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	self = (PyGObjectPtr*)g_object_get_qdata(obj, lasso_wrapper_key);
	if (self != NULL) {
		Py_INCREF(self);
	} else {
		self = (PyGObjectPtr*)PyObject_NEW(PyGObjectPtr, &PyGObjectPtrType);
		g_object_set_qdata_full(obj, lasso_wrapper_key, self, NULL);
		self->obj = obj;
		self->typename = PyString_FromString(G_OBJECT_TYPE_NAME(obj)+5);
	}
	return (PyObject*)self;
}

static PyObject *
PyGObjectPtr_repr(PyGObjectPtr *obj)
{
	return PyString_FromFormat("<PyGObjectPtr to %p (type: %s, refcount: %d)>",
			obj->obj,
			G_OBJECT_TYPE_NAME(obj->obj),
			obj->obj->ref_count);
}

static PyMemberDef PyGObjectPtr_members[] = {
	{"typename", T_OBJECT, offsetof(PyGObjectPtr, typename), 0, "typename"},
	{NULL}
};


static PyTypeObject PyGObjectPtrType = {
	PyObject_HEAD_INIT(NULL)
	0, /* ob_size */
	"_lasso.PyGObjectPtr", /* tp_name */
	sizeof(PyGObjectPtr),  /* tp_basicsize */
	0,                     /* tp_itemsize */
	(destructor)PyGObjectPtr_dealloc, /* tp_dealloc */
	0,       /*tp_print*/
	0,                      /*tp_getattr*/
	0,       /*tp_setattr*/
	0,       /*tp_compare*/
	(reprfunc)PyGObjectPtr_repr,       /*tp_repr*/
	0,       /*tp_as_number*/
	0,       /*tp_as_sequence*/
	0,       /*tp_as_mapping*/
	0,       /*tp_hash */
	0,       /*tp_call*/
	0,       /*tp_str*/
	0,       /*tp_getattro*/
	0,       /*tp_setattro*/
	0,       /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,  /*tp_flags*/
	"PyGObjectPtr objects",   /* tp_doc */
	0,       /* tp_traverse */
	0,       /* tp_clear */
	0,       /* tp_richcompare */
	0,       /* tp_weaklistoffset */
	0,       /* tp_iter */
	0,       /* tp_iternext */
	0,       /* tp_methods */
	PyGObjectPtr_members,   /* tp_members */
};

