#include <Python.h>
#include <structmember.h>
#include <lasso/lasso.h>

GQuark lasso_wrapper_key;


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

