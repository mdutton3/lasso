#include <Python.h>
#include <structmember.h>
#include <lasso/lasso.h>
#include <lasso_config.h>
#include "../ghashtable.h"

GQuark lasso_wrapper_key;

PyMODINIT_FUNC init_lasso(void);
static PyObject* get_pystring_from_xml_node(xmlNode *xmlnode);
static xmlNode*  get_xml_node_from_pystring(PyObject *string);
static PyObject* get_dict_from_hashtable_of_objects(GHashTable *value);
static PyObject* PyGObjectPtr_New(GObject *obj);
static void set_hashtable_of_pygobject(GHashTable *a_hash, PyObject *dict);
static void set_list_of_strings(GList **a_list, PyObject *seq);
static void set_list_of_xml_nodes(GList **a_list, PyObject *seq);
static void set_list_of_pygobject(GList **a_list, PyObject *seq);
static PyObject *get_list_of_strings(GList *a_list);
static PyObject *get_list_of_xml_nodes(GList *a_list);
static PyObject *get_list_of_pygobject(GList *a_list);
static gboolean valid_seq(PyObject *seq);
static void free_list(GList **a_list, GFunc free_help);

typedef struct {
	PyObject_HEAD
	GObject *obj;
	PyObject *typename;
} PyGObjectPtr;
static PyTypeObject PyGObjectPtrType;

/* utility functions */
static PyObject *
noneRef() {
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject*
get_dict_from_hashtable_of_objects(GHashTable *value)
{
	GList *keys;
	PyObject *dict,*proxy;
	GObject *item_value;
	PyObject *item;

	dict = PyDict_New();

	keys = g_hash_table_get_keys(value);
	for (; keys; keys = g_list_next(keys)) {
		item_value = g_hash_table_lookup(value, keys->data);
		if (item_value) {
			item = PyGObjectPtr_New(G_OBJECT(item_value));
			PyDict_SetItemString(dict, (char*)keys->data, item); 
			Py_DECREF(item);
		} else {
			PyErr_Warn(PyExc_RuntimeWarning, "hashtable contains a null value");
		}
	}
	g_list_free(keys);

	proxy = PyDictProxy_New(dict);
	Py_DECREF(dict);
	return proxy;
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

static gboolean
valid_seq(PyObject *seq) {
	if (! seq || ( seq != Py_None && ! PyTuple_Check(seq))) {
		 PyErr_SetString(PyExc_TypeError, "value should be tuple");
		 return 0;
	}
	return 1;
}

static void
free_list(GList **a_list, GFunc free_help) {
	if (*a_list) {
		g_list_foreach(*a_list, free_help, NULL);
		g_list_free(*a_list);
	}
}

/** Remove all elements from a_hash and replace them with
 * the key-values pairs from the python dict. 
 * Increase reference of new values before removeing
 * values from the hash, so if there are somme common
 * values with RefCoun = 1 they won't be deallocated.
 * */
static void 
set_hashtable_of_pygobject(GHashTable *a_hash, PyObject *dict) {
	PyObject *key, *value;
	int i;

	if (! a_hash) {
		 PyErr_SetString(PyExc_TypeError, "hashtable does not exist");
		 return;
	}
	if (dict != Py_None && ! PyDict_Check(dict)) {
		 PyErr_SetString(PyExc_TypeError, "value should be a frozen dict");
		 return;
	}
	i = 0;
	// Increase ref count of common object between old and new
	// value of the hashtable
	while (PyDict_Next(dict, &i, &key, &value)) {
		if (! PyString_Check(key) || ! PyObject_TypeCheck(value, &PyGObjectPtrType))
		{
		    	PyErr_SetString(PyExc_TypeError, 
					"value should be a dict,"
					"with string keys"
					"and GObjectPtr values");
			goto failure;
		}
		g_object_ref(((PyGObjectPtr*)value)->obj);
	}
	g_hash_table_remove_all (a_hash);
	while (PyDict_Next(dict, &i, &key, &value)) {
		char *ckey = g_strdup(PyString_AsString(key));
		g_hash_table_replace (a_hash, ckey, ((PyGObjectPtr*)value)->obj);
	}
	return;
failure:
	i = 0;
	while (PyDict_Next(dict, &i, &key, &value)) {
		if (! PyString_Check(key) || ! PyObject_TypeCheck(value, &PyGObjectPtrType))
			break;
		g_object_unref((PyGObjectPtr*)value);
	}
}

/** Set the GList* pointer, pointed by a_list, to a pointer on a new GList 
 * created by converting the python seq into a GList of char*.
 */
static void
set_list_of_strings(GList **a_list, PyObject *seq) {
	GList *list = NULL;
	int l = 0,i;

	g_return_if_fail(valid_seq(seq));
	if (seq != Py_None) {
		l = PySequence_Length(seq);
	}
	for (i=0; i<l; i++) {
		PyObject *pystr = PySequence_Fast_GET_ITEM(seq, i);
		if (! PyString_Check(pystr)) {
			PyErr_SetString(PyExc_TypeError, 
					"value should be a tuple of strings");
			goto failure;
		}
		list = g_list_append(list, g_strdup(PyString_AsString(pystr)));
	}
	free_list(a_list, (GFunc)g_free);
	*a_list = list;
	return;
failure:
	free_list(&list, (GFunc)g_free);
}

/** Set the GList* pointer, pointed by a_list, to a pointer on a new GList 
 * created by converting the python seq into a GList of xmlNode*.
 */
static void
set_list_of_xml_nodes(GList **a_list, PyObject *seq) {
	GList *list = NULL;
	int l = 0,i;

	g_return_if_fail(valid_seq(seq));
	if (seq != Py_None) {
		l = PySequence_Length(seq);
	}
	for (i=0; i<l; i++) {
		PyObject *item = PySequence_Fast_GET_ITEM(seq, i);
		xmlNode *item_node;
		if (! PyString_Check(item)) {
			PyErr_SetString(PyExc_TypeError, 
					"value should be a tuple of strings");
			goto failure;
		}
		item_node = get_xml_node_from_pystring(item);
		list = g_list_append(list, item_node);
	}
	free_list(a_list, (GFunc)xmlFreeNode);
	*a_list = list;
	return;
failure:
	free_list(&list, (GFunc)xmlFreeNode);
}

/** Set the GList* pointer, pointed by a_list, to a pointer on a new GList 
 * created by converting the python seq into a GList of GObject*.
 */
static void
set_list_of_pygobject(GList **a_list, PyObject *seq) {
	GList *list = NULL;
	int l = 0,i;

	g_return_if_fail(valid_seq(seq));
	if (seq != Py_None) {
		l = PySequence_Length(seq);
	}
	for (i=0; i<l; i++) {
		PyObject *item = PySequence_Fast_GET_ITEM(seq, i);
		GObject *gobject;
		if (! PyObject_TypeCheck(item, &PyGObjectPtrType)) {
			PyErr_SetString(PyExc_TypeError, 
					"value should be a tuple of PyGobject");
			goto failure;
		}
		gobject = g_object_ref(((PyGObjectPtr*)item)->obj);
		list = g_list_append(list, gobject);
	}
	free_list(a_list, (GFunc)g_object_unref);
	*a_list = list;
	return;
failure:
	free_list(&list, (GFunc)g_object_unref);
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
/** Return a tuple containing the string contained in a_list */
static PyObject *
get_list_of_strings(GList *a_list) {
	PyObject *a_tuple = NULL;
	int i = 0;

	if (! a_list) {
		return noneRef();
	}
	a_tuple = PyTuple_New(g_list_length(a_list));
	if (! a_tuple)
		goto failure;
	while (a_list) {
		if (a_list->data) {
			PyObject *str = PyString_FromString((const char*)a_list->data);
			if (!str) {
				goto failure;
			}
			PyTuple_SetItem(a_tuple, i, str);
			i++;
		} else {
			PyErr_Warn(PyExc_RuntimeWarning, 
				"list contains a NULL value");
		}
		a_list = a_list->next;
	}
	if (_PyTuple_Resize(&a_tuple, i))
		goto failure;
	return a_tuple;
failure:
	PyErr_SetString(PyExc_TypeError, "Allocation problem in get_list_of_strings");
	Py_XDECREF(a_tuple); 	
	return noneRef();
}

static PyObject *
get_list_of_xml_nodes(GList *a_list) {
	PyObject *a_tuple = NULL;
	int i = 0;

	if (! a_list) {
		return noneRef();
	}
	a_tuple = PyTuple_New(g_list_length(a_list));
	if (! a_tuple)
		goto failure;
	while (a_list) {
		if (a_list->data) {
			PyObject *str = get_pystring_from_xml_node((xmlNode*)a_list->data);
			if (str) {
				PyTuple_SetItem(a_tuple, i, str);
				i++;
			} else {
				PyErr_Warn(PyExc_RuntimeWarning, 
					"could not convert an xmlNode to a string");
			}
		} else {
			PyErr_Warn(PyExc_RuntimeWarning, 
				"list contains a NULL value");
		}
		a_list = a_list->next;
	}
	if (_PyTuple_Resize(&a_tuple, i))
		goto failure;
	return a_tuple;
failure:
	PyErr_SetString(PyExc_TypeError, "Allocation problem in get_list_of_strings");
	Py_XDECREF(a_tuple); 	
	return noneRef();
}

static PyObject *
get_list_of_pygobject(GList *a_list) {
	PyObject *a_tuple = NULL;
	int i = 0;

	if (! a_list) {
		return noneRef();
	}
	a_tuple = PyTuple_New(g_list_length(a_list));
	if (! a_tuple)
		goto failure;
	while (a_list) {
		if (a_list->data) {
			PyObject *pygobject;
			pygobject = PyGObjectPtr_New((GObject*)a_list->data);
			if (pygobject) {
				PyTuple_SetItem(a_tuple, i, pygobject);
				i++;
			} else {
				PyErr_Warn(PyExc_RuntimeWarning, 
					"could not convert a GObject to a PyGobject");
			}
		} else {
			PyErr_Warn(PyExc_RuntimeWarning, 
				"list contains a NULL value");
		}
		a_list = a_list->next;
	}
	if (_PyTuple_Resize(&a_tuple, i))
		goto failure;
	return a_tuple;
failure:
	PyErr_SetString(PyExc_TypeError, "Allocation problem in get_list_of_strings");
	Py_XDECREF(a_tuple); 	
	return noneRef();
}

/* wrapper around GObject */



static void
PyGObjectPtr_dealloc(PyGObjectPtr *self)
{
#ifdef LASSO_DEBUG
	fprintf(stderr, "dealloc (%p ptr to %p (type:%s, rc:%d))\n",
			self, self->obj,
			G_OBJECT_TYPE_NAME(self->obj),
			self->obj->ref_count);
#endif
	g_object_set_qdata_full(self->obj, lasso_wrapper_key, NULL, NULL);
	g_object_unref(self->obj);
	Py_XDECREF(self->typename);
	self->ob_type->tp_free((PyObject*)self);
}

static PyObject*
PyGObjectPtr_New(GObject *obj)
{
	PyGObjectPtr *self;

	if (obj == NULL) {
		return noneRef();
	}

	self = (PyGObjectPtr*)g_object_get_qdata(obj, lasso_wrapper_key);
	if (self != NULL) {
		Py_INCREF(self);
	} else {
		self = (PyGObjectPtr*)PyObject_NEW(PyGObjectPtr, &PyGObjectPtrType);
		g_object_set_qdata_full(obj, lasso_wrapper_key, self, NULL);
		self->obj = g_object_ref(obj);
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

static PyObject* 
PyGObjectPtr_get_refcount(PyGObjectPtr *self, void *closure)
{
	PyObject *refcount;

	refcount = PyInt_FromLong(self->obj->ref_count);
	Py_INCREF(refcount);
	return refcount;
}

static PyGetSetDef PyGObjectPtr_getseters[] = {
	{"refcount", (getter)PyGObjectPtr_get_refcount, NULL,
		"reference count of intern GObject*", NULL},
	{NULL}  /* Sentinel */
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
	PyGObjectPtr_getseters, /* tp_getset */
};

static void
set_object_field(GObject **a_gobject_ptr, PyGObjectPtr *a_pygobject) {
	if (*a_gobject_ptr) {
		g_object_unref(*a_gobject_ptr);
	}
	if ((PyObject*)a_pygobject == Py_None) {
		*a_gobject_ptr = NULL; 
	} else {
		*a_gobject_ptr = g_object_ref(a_pygobject->obj);
	}
}
