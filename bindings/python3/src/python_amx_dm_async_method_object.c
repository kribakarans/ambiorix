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

#include <sys/time.h>
#include <stdbool.h>
#include "python_amx.h"
#include "python_amx_conversion.h"
#include "python_amx_error_conversion.h"
#include "python_amx_connection_object.h"
#include "python_amx_request_object.h"
#include "python_amx_dm_async_method_object.h"

#define ME "python_amx_dm_method_object"

static int
object_traverse(PAMXDMAsyncMethodObject* self, visitproc visit, void* arg) {
    Py_VISIT(self->req_list);
    return 0;
}

static int
object_clear(PAMXDMAsyncMethodObject* self) {
    Py_CLEAR(self->req_list);
    return 0;
}

static void
PAMXDMAsyncMethod_dealloc(PAMXDMAsyncMethodObject* self) {
    object_clear(self);
    free(self->name);
    free(self->path);
    PyObject_GC_UnTrack(self);
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject*
PAMXDMAsyncMethod_new(PyTypeObject* type, PyObject* args, UNUSED PyObject* kwds) {
    PAMXDMAsyncMethodObject* self = NULL;
    const char* path = NULL;
    const char* name = NULL;

    if(PyArg_ParseTuple(args, "ss", &path, &name) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    self = (PAMXDMAsyncMethodObject*) type->tp_alloc(type, 0);
    if(self == NULL) {
        amx2pythonerror(-1, "tp_alloc failure.");
        goto exit;
    }

    self->path = strdup(path);
    self->name = strdup(name);

    self->req_list = PyList_New(0);
    if(self->req_list == NULL) {
        amx2pythonerror(-1, "list alloc failure.");
        goto exit;
    }

    return (PyObject*) self;
exit:
    if(self != NULL) {
        Py_XDECREF(self->req_list);
        if(self->name != NULL) {
            free(self->name);
            self->name = NULL;
        }
        if(self->path != NULL) {
            free(self->path);
            self->path = NULL;
        }
        Py_TYPE(self)->tp_free((PyObject*) self);
    }
    return NULL;
}

static int
PAMXDMAsyncMethod_init(UNUSED PyObject* self, UNUSED PyObject* args, UNUSED PyObject* kwds) {
    return 0;
}

static PyObject* method_call(PyObject* self, PyObject* args, PyObject* kwargs) {
    PyObject* parameters = NULL;
    PyObject* cb_function = NULL;
    PyObject* userdata = NULL;
    amxb_request_t* request = NULL;
    PyObject* retval = NULL;
    data_t* d = NULL;
    static const char* kwlist_literals[] = {"parameters", "callback", "userdata", NULL};
    char* kwlist[4];
    amxc_var_t converted_value;
    amxc_var_init(&converted_value);
    transform_kwlist(kwlist, kwlist_literals);

    if(PyArg_ParseTupleAndKeywords(args, kwargs, "|O!OO", kwlist, &PyDict_Type, &parameters, &cb_function, &userdata) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    if((cb_function != NULL) && (PyCallable_Check(cb_function) == 0)) {
        PyErr_SetString(PyExc_TypeError, "event callback is not callable.");
        goto exit;
    }

    if((userdata != NULL) && (cb_function == NULL)) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }


    d = init_data(cb_function, userdata);
    if(d == NULL) {
        amx2pythonerror(-1, "Failed to initialize user data.");
        goto exit;
    }

    if(parameters != NULL) {
        python2variant(parameters, &converted_value);
    }

    request = amxb_async_call(((PAMXDMAsyncMethodObject*) self)->bus,
                              ((PAMXDMAsyncMethodObject*) self)->path,
                              ((PAMXDMAsyncMethodObject*) self)->name,
                              &converted_value,
                              async_handler,
                              d);
    if(request == NULL) {
        amx2pythonerror(-1, "Could not perform amxb_async_call");
        goto exit;
    }

    retval = PyObject_CallObject((PyObject*) get_pamxRequest_type(), NULL);
    if(retval == NULL) {
        amx2pythonerror(-1, "Could not create request");
        goto exit;
    }
    ((PAMXRequestObject*) retval)->request = request;
    ((PAMXRequestObject*) retval)->data = d;

    PyList_Append(((PAMXDMAsyncMethodObject*) self)->req_list, retval);

exit:
    if(PyErr_Occurred() != NULL) {
        amxb_close_request(&request);
        free_data(d);
        d = NULL;
        Py_XDECREF(retval);
    }
    amxc_var_clean(&converted_value);
    return retval;
}

static PyMethodDef PAMXDMAsyncMethod_methods[] = {
    {NULL, NULL, 0, NULL}
};

static PyTypeObject PAMXDMAsyncMethodType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pamx.DMAsyncMethod",
    .tp_basicsize = sizeof(PAMXDMAsyncMethodObject),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor) PAMXDMAsyncMethod_dealloc,
    .tp_call = method_call,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_doc = "pamx dm async method object",
    .tp_traverse = (traverseproc) object_traverse,
    .tp_methods = PAMXDMAsyncMethod_methods,
    .tp_init = (initproc) PAMXDMAsyncMethod_init,
    .tp_new = PAMXDMAsyncMethod_new,
};

PyTypeObject* get_pamxDMAsyncMethod_type() {
    return &PAMXDMAsyncMethodType;
}
