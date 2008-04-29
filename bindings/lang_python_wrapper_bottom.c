PyMODINIT_FUNC
init_lasso(void)
{
	if (PyType_Ready(&PyGObjectPtrType) < 0)
		return;

	m = Py_InitModule3("_lasso", lasso_methods, "_lasso wrapper module");
	lasso_init();

	lasso_wrapper_key = g_quark_from_static_string("PyLasso::wrapper");

	Py_INCREF(&PyGObjectPtrType);
	PyModule_AddObject(m, "PyGobjectPtr", (PyObject *)&PyGobjectPtrType);


}

