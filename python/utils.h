#ifndef __PYLASSO_UTILS_H__
#define __PYLASSO_UTILS_H__

#undef _POSIX_C_SOURCE
#include <Python.h>

extern PyObject *lasso_error;

int CheckArgs(PyObject *args, char *format);

#endif /* __PYLASSO_UTILS_H__ */
