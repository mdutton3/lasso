#include <Python.h>
#include <lasso/lasso.h>

GQuark lasso_wrapper_key;


typedef struct {
	PyObject_HEAD
	GObject *obj;
} PyGObjectPtr;

static PyTypeObject PyGObjectPtrType;

static void
PyGObjectPtr_dealloc(PyGObjectPtr *self)
{
	g_object_unref(self->obj);
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
	}
	return (PyObject*)self;
}

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
	0,       /*tp_repr*/
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
};

