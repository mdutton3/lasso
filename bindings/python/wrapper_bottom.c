// Module init has changed quite a bit between Python 2 & 3.
// Defines taken from <http://python3porting.com/cextensions.html>.

#if PY_MAJOR_VERSION >= 3
  #define MOD_ERROR_VAL NULL
  #define MOD_SUCCESS_VAL(val) val
  #define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name(void)
  #define MOD_DEF(ob, name, doc, methods) \
          static struct PyModuleDef moduledef = { \
            PyModuleDef_HEAD_INIT, name, doc, -1, methods, NULL, NULL, NULL, NULL}; \
          ob = PyModule_Create(&moduledef);
#else
  #define MOD_ERROR_VAL
  #define MOD_SUCCESS_VAL(val)
  #define MOD_INIT(name) void init##name(void)
  #define MOD_DEF(ob, name, doc, methods) \
          ob = Py_InitModule3(name, methods, doc);
#endif

MOD_INIT(_lasso)
{
	PyObject *m, *d;

	if (PyType_Ready(&PyGObjectPtrType) < 0)
		return MOD_ERROR_VAL;

	MOD_DEF(m, "_lasso", "_lasso wrapper module", lasso_methods);
        d = PyModule_GetDict(m);
        register_constants(d);

	lasso_wrapper_key = g_quark_from_static_string("PyLasso::wrapper");

	Py_INCREF(&PyGObjectPtrType);
	PyModule_AddObject(m, "PyGObjectPtr", (PyObject *)&PyGObjectPtrType);

	lasso_init();
	lasso_log_set_handler(G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION | G_LOG_LEVEL_MASK,
			lasso_python_log, NULL);

    return MOD_SUCCESS_VAL(m);
}

