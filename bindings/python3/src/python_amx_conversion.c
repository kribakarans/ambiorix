/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2023 SoftAtHome
**
** Redistribution and use in source and binary forms, with or without modification,
** are permitted provided that the following conditions are met:
**
** 1. Redistributions of source code must retain the above copyright notice,
** this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above copyright notice,
** this list of conditions and the following disclaimer in the documentation
** and/or other materials provided with the distribution.
**
** Subject to the terms and conditions of this license, each copyright holder
** and contributor hereby grants to those receiving rights under this license
** a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
** (except for failure to satisfy the conditions of this license) patent license
** to make, have made, use, offer to sell, sell, import, and otherwise transfer
** this software, where such license applies only to those patent claims, already
** acquired or hereafter acquired, licensable by such copyright holder or contributor
** that are necessarily infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright holders and
** non-copyrightable additions of contributors, in source or binary form) alone;
** or
**
** (b) combination of their Contribution(s) with the work of authorship to which
** such Contribution(s) was added by such copyright holder or contributor, if,
** at the time the Contribution is added, such addition causes such combination
** to be necessarily infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any copyright
** holder or contributor is granted under this license, whether expressly, by
** implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
** AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
** LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
** SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
** CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
** OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
** USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/

#include <Python.h>

#define SAHTRACES_LEVEL 500
#define SAHTRACES_ENABLED

#include <dlfcn.h>

#include "python_amx.h"
#include "python_amx_conversion.h"
#include "python_amx_error_conversion.h"

#define ME "python_amx_conversion"

/* Helper functions */

void
pythondatetime2variant(PyObject* value, amxc_var_t* var) {
    PyObject* modDateTime = PyImport_ImportModule("datetime");
    PyObject* PyTimeZone = PyObject_GetAttrString(modDateTime, "timezone");
    PyObject* PyUTC = PyObject_GetAttrString(PyTimeZone, "utc");
    PyObject* utc_dt = PyObject_CallMethod(value, "astimezone", "O", PyUTC);
    PyObject* ts = PyObject_CallMethod(utc_dt, "timestamp", NULL);
    double seconds = (double) PyFloat_AsDouble(ts);
    int microseconds = (int) PyLong_AsLong(PyObject_GetAttrString(utc_dt, "microsecond"));
    amxc_ts_t var_ts;
    var_ts.sec = (int64_t) seconds;
    var_ts.nsec = (int32_t) microseconds * 1000;
    var_ts.offset = 0;
    amxc_var_set(amxc_ts_t, var, &var_ts);

    Py_DECREF(ts);
    Py_DECREF(utc_dt);
    Py_DECREF(PyUTC);
    Py_DECREF(PyTimeZone);
    Py_DECREF(modDateTime);

}

static void
pythondict2variant(PyObject* dict, amxc_var_t* var) {
    PyObject* key = NULL;
    PyObject* value = NULL;
    Py_ssize_t pos = 0;
    amxc_var_t converted_value;
    amxc_var_init(&converted_value);
    amxc_var_set_type(var, AMXC_VAR_ID_HTABLE);

    while(PyDict_Next(dict, &pos, &key, &value)) {
        python2variant(value, &converted_value);
        amxc_var_t* subvar = amxc_var_add_new_key(var, PyUnicode_AsUTF8(key));
        amxc_var_copy(subvar, &converted_value);

    }
    amxc_var_clean(&converted_value);
}

static void
pythonlist2variant(PyObject* list, amxc_var_t* var) {
    PyObject* value = NULL;
    PyObject* iterator = PyObject_GetIter(list);

    amxc_var_set_type(var, AMXC_VAR_ID_LIST);

    while((value = PyIter_Next(iterator))) {
        amxc_var_t converted_value;
        amxc_var_init(&converted_value);
        python2variant(value, &converted_value);

        amxc_var_t* subvar = amxc_var_add_new(var);
        amxc_var_copy(subvar, &converted_value);
        amxc_var_clean(&converted_value);
        Py_DECREF(value);
    }
    Py_DECREF(iterator);
}

void
python2variant(PyObject* value, amxc_var_t* var) {
    PyObject* modDateTime = PyImport_ImportModule("datetime");
    PyObject* PyDateTime = PyObject_GetAttrString(modDateTime, "datetime");
    PyObject* PyBuiltins = PyEval_GetBuiltins();
    PyObject* PyIsInstance = PyDict_GetItemString(PyBuiltins, "isinstance");
    PyObject* isDateTime = PyObject_CallFunctionObjArgs(PyIsInstance, value, PyDateTime, NULL);
    if(PyUnicode_Check(value) == 1) {
        amxc_var_set(cstring_t, var, PyUnicode_AsUTF8(value));
    } else if(PyBool_Check(value) == 1) {
        if(PyObject_IsTrue(value) == 0) {
            amxc_var_set(bool, var, false);
        } else {
            amxc_var_set(bool, var, true);
        }
    } else if((PyLong_Check(value) == 1) && (PyLong_CheckExact(value) == 0)) {
        amxc_var_set(int32_t, var, (int32_t) PyLong_AsLong(value));
    } else if(PyLong_CheckExact(value) == 1) {
        amxc_var_set(int64_t, var, (int64_t) PyLong_AsLongLong(value));
    } else if(PyFloat_Check(value) == 1) {
        amxc_var_set(double, var, (double) PyFloat_AsDouble(value));
    } else if(PyDict_Check(value) == 1) {
        pythondict2variant(value, var);
    } else if(PyList_Check(value) == 1) {
        pythonlist2variant(value, var);
    } else if(PyBool_Check(isDateTime) == 1) {
        pythondatetime2variant(value, var);
    }

    Py_DECREF(modDateTime);
    Py_DECREF(PyDateTime);
    Py_DECREF(isDateTime);
}

static PyObject*
variant2pythonlist(const amxc_var_t* const var) {
    int res = 0;
    PyObject* resultlist = PyList_New(0);
    if(resultlist == NULL) {
        amx2pythonerror(-1, "Could not allocate memory");
        goto exit;
    }

    amxc_var_for_each(item, var) {
        PyObject* element = variant2python(item);
        res = PyList_Append(resultlist, element);
        Py_DECREF(element);
        if(res < 0) {
            amx2pythonerror(-1, "Could not add element to list");
            goto exit;
        }
    }

exit:
    return resultlist;
}

static PyObject*
variant2pythondict(const amxc_var_t* const var) {
    PyObject* value = NULL;
    PyObject* key = NULL;
    const amxc_htable_t* var_table = amxc_var_constcast(amxc_htable_t, var);
    PyObject* resultmap = PyDict_New();
    if(resultmap == NULL) {
        amx2pythonerror(-1, "Could not allocate memory");
        goto exit;
    }

    amxc_htable_iterate(it, var_table) {
        key = PyUnicode_FromString(amxc_htable_it_get_key(it));
        value = variant2python(amxc_var_from_htable_it(it));
        PyDict_SetItem(resultmap, key, value);
        Py_DECREF(key);
        Py_DECREF(value);
    }

exit:
    return resultmap;
}

PyObject*
variant2pythondatetime(const amxc_var_t* const var) {
    PyObject* modDateTime = PyImport_ImportModule("datetime");
    PyObject* PyDateTime = PyObject_GetAttrString(modDateTime, "datetime");
    PyObject* PyTimeZone = PyObject_GetAttrString(modDateTime, "timezone");
    PyObject* PyUTC = PyObject_GetAttrString(PyTimeZone, "utc");
    PyObject* retval = NULL;
    const amxc_ts_t* var_ts = amxc_var_constcast(amxc_ts_t, var);
    struct tm converted;
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    int microseconds = 0;

    if(amxc_ts_to_tm_utc(var_ts, &converted) != 0) {
        PyErr_SetString(PyExc_RuntimeError, "Datetime object could not be converted");
        goto exit;
    }

    year = converted.tm_year + 1900;
    month = converted.tm_mon + 1;
    day = converted.tm_mday;
    hour = converted.tm_hour;
    minute = converted.tm_min;
    second = converted.tm_sec;
    microseconds = var_ts->nsec / 1000;

    retval = PyObject_CallObject(PyDateTime, Py_BuildValue("iiiiiiiO", year, month, day, hour, minute, second, microseconds, PyUTC));

exit:
    Py_DECREF(PyUTC);
    Py_DECREF(PyTimeZone);
    Py_DECREF(PyDateTime);
    Py_DECREF(modDateTime);

    return retval;
}

PyObject*
variant2python(const amxc_var_t* const var) {
    PyObject* result = NULL;
    char* txt = NULL;
    uint32_t type = amxc_var_type_of(var);

    switch(type) {
    default:
    case AMXC_VAR_ID_NULL:
        Py_RETURN_NONE;
        break;
    case AMXC_VAR_ID_CSTRING:
    case AMXC_VAR_ID_CSV_STRING:
    case AMXC_VAR_ID_SSV_STRING:;
        txt = amxc_var_dyncast(cstring_t, var);
        if(txt != NULL) {
            result = PyUnicode_FromString(txt);
            free(txt);
        } else {
            amx2pythonerror(-1, "Could not create string");
        }
        break;
    case AMXC_VAR_ID_INT8:
    case AMXC_VAR_ID_INT16:
    case AMXC_VAR_ID_INT32:
    case AMXC_VAR_ID_FD:
        result = PyLong_FromLong(amxc_var_dyncast(int32_t, var));
        break;
    case AMXC_VAR_ID_INT64:
        result = PyLong_FromLongLong(amxc_var_constcast(int64_t, var));
        break;
    case AMXC_VAR_ID_UINT8:
    case AMXC_VAR_ID_UINT16:
    case AMXC_VAR_ID_UINT32:
        result = PyLong_FromUnsignedLong(amxc_var_dyncast(uint32_t, var));
        break;
    case AMXC_VAR_ID_UINT64:
        result = PyLong_FromUnsignedLongLong(amxc_var_constcast(uint64_t, var));
        break;
    case AMXC_VAR_ID_DOUBLE:
    case AMXC_VAR_ID_FLOAT:
        result = PyFloat_FromDouble(amxc_var_dyncast(double, var));
        break;
    case AMXC_VAR_ID_BOOL:
        if(amxc_var_constcast(bool, var)) {
            Py_RETURN_TRUE;
        } else {
            Py_RETURN_FALSE;
        }
        break;
    case AMXC_VAR_ID_LIST:
        result = variant2pythonlist(var);
        break;
    case AMXC_VAR_ID_HTABLE:
        result = variant2pythondict(var);
        break;
    case AMXC_VAR_ID_TIMESTAMP:
        result = variant2pythondatetime(var);
        break;
    }
    return result;
}
