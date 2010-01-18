PyMODINIT_FUNC
init_lasso(void)
{
	PyObject *m, *d;

	if (PyType_Ready(&PyGObjectPtrType) < 0)
		return;

	m = Py_InitModule3("_lasso", lasso_methods, "_lasso wrapper module");
        d = PyModule_GetDict(m);
        register_constants(d);

	lasso_wrapper_key = g_quark_from_static_string("PyLasso::wrapper");

	Py_INCREF(&PyGObjectPtrType);
	PyModule_AddObject(m, "PyGObjectPtr", (PyObject *)&PyGObjectPtrType);
}

