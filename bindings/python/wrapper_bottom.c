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
	lasso_init();
	lasso_log_set_handler(G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION | G_LOG_LEVEL_MASK,
			lasso_python_log, NULL);
}

