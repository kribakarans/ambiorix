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
#include "python_amx_dm_protected_object.h"

#define ME "python_amx_dm_method_object"

static int
object_traverse(PAMXDMAsyncObject* self, visitproc visit, void* arg) {
    Py_VISIT(self->dict);
    Py_VISIT(self->protected_obj);
    return 0;
}

static void
PAMXDMAsync_dealloc(PAMXDMAsyncObject* self) {
    Py_CLEAR(self->dict);
    Py_CLEAR(self->protected_obj);
    PyObject_GC_UnTrack(self);
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject*
PAMXDMAsync_new(PyTypeObject* type, PyObject* args, UNUSED PyObject* kwds) {
    PAMXDMAsyncObject* self = (PAMXDMAsyncObject*) type->tp_alloc(type, 0);
    PyObject* dict = NULL;
    PyObject* protected_dict = NULL;
    PyObject* params = NULL;
    if(self == NULL) {
        amx2pythonerror(-1, "tp_alloc failure.");
        goto exit;
    }
    if(PyArg_ParseTuple(args, "O!O!", &PyDict_Type, &dict, &PyDict_Type, &protected_dict) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    params = Py_BuildValue("(O)", protected_dict);
    self->protected_obj = PyObject_CallObject((PyObject*) get_pamxDMProtected_type(), params);
    Py_DECREF(params);

    self->dict = dict;
    Py_INCREF(self->dict);
    return (PyObject*) self;

exit:
    if(self != NULL) {
        Py_XDECREF(self->dict);
        Py_TYPE(self)->tp_free((PyObject*) self);
    }
    return NULL;
}

static int
PAMXDMAsync_init(UNUSED PyObject* self, UNUSED PyObject* args, UNUSED PyObject* kwds) {
    return 0;
}

static PyObject* object_getattro(PyObject* self, PyObject* attr_obj) {
    PyObject* dict = ((PAMXDMAsyncObject*) self)->dict;
    PyObject* retval = NULL;
    if(PyDict_Contains(dict, attr_obj) == 1) {
        retval = PyDict_GetItem(dict, attr_obj);
        Py_INCREF(retval);
        goto exit;
    }

    if(strncmp(PyUnicode_AsUTF8(attr_obj), "__dict__", 8) == 0) {
        retval = PyDict_Copy(((PAMXDMAsyncObject*) self)->dict);
        if(retval == NULL) {
            goto exit;
        }
        goto exit;
    }

    retval = PyObject_GenericGetAttr(self, attr_obj);

exit:
    return retval;
}

static PyObject*
DMAsyncObject_getProtected(PAMXDMAsyncObject* self, UNUSED void* closure) {
    PyObject* retval = self->protected_obj;
    Py_INCREF(retval);
    return retval;
}

static int
DMAsyncObject_setProtected(UNUSED PAMXDMAsyncObject* self, UNUSED PyObject* value, UNUSED void* closure) {
    PyErr_SetString(PyExc_TypeError, "Cannot manually set protected.");
    return -1;
}

static PyGetSetDef DMAsyncObject_getsetters[] = {
    {"protected", (getter) DMAsyncObject_getProtected, (setter) DMAsyncObject_setProtected,
        "protected methods", NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject PAMXDMAsyncType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pamx.DMAsync",
    .tp_basicsize = sizeof(PAMXDMAsyncObject),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor) PAMXDMAsync_dealloc,
    .tp_getattro = object_getattro,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_doc = "pamx dm async object",
    .tp_traverse = (traverseproc) object_traverse,
    .tp_getset = DMAsyncObject_getsetters,
    .tp_init = (initproc) PAMXDMAsync_init,
    .tp_new = PAMXDMAsync_new,
};

PyTypeObject* get_pamxDMAsync_type() {
    return &PAMXDMAsyncType;
}
