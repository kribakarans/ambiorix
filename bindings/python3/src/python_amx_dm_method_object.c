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
#define _GNU_SOURCE
#include <sys/time.h>
#include <stdbool.h>
#include <stdio.h>
#include "python_amx.h"
#include "python_amx_conversion.h"
#include "python_amx_error_conversion.h"
#include "python_amx_dm_method_object.h"

#define ME "python_amx_dm_method_object"

static void
PAMXDMMethod_dealloc(PAMXDMMethodObject* self) {
    free(self->name);
    free(self->path);
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject*
PAMXDMMethod_new(PyTypeObject* type, PyObject* args, UNUSED PyObject* kwds) {
    PAMXDMMethodObject* self;
    const char* path = NULL;
    const char* name = NULL;
    self = (PAMXDMMethodObject*) type->tp_alloc(type, 0);

    if(self == NULL) {
        amx2pythonerror(-1, "tp_alloc failure.");
        goto exit;
    }

    if(PyArg_ParseTuple(args, "ss", &path, &name) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    self->path = strdup(path);
    self->name = strdup(name);

    return (PyObject*) self;
exit:
    if(self != NULL) {
        Py_TYPE(self)->tp_free((PyObject*) self);
    }
    return NULL;
}

static int
PAMXDMMethod_init(UNUSED PyObject* self, UNUSED PyObject* args, UNUSED PyObject* kwds) {
    return 0;
}

static PyObject* method_call(PyObject* self, PyObject* args, UNUSED PyObject* kwargs) {
    PyObject* dict = NULL;
    PyObject* result = NULL;
    int timeout_sec = 5;
    int call_retval = -1;
    amxc_var_t retval;
    amxc_var_t converted_value;
    amxc_var_init(&retval);
    amxc_var_init(&converted_value);
    char* error_message = NULL;

    if(PyArg_ParseTuple(args, "|O!i", &PyDict_Type, &dict, &timeout_sec) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    if(dict != NULL) {
        python2variant(dict, &converted_value);
    }

    call_retval = amxb_call(((PAMXDMMethodObject*) self)->bus, ((PAMXDMMethodObject*) self)->path, ((PAMXDMMethodObject*) self)->name, &converted_value, &retval, timeout_sec);
    if(call_retval != 0) {
        if(0 > asprintf(&error_message, "Could not perform call, amxb_call returned code:  %d", call_retval)) {
            amx2pythonerror(call_retval, "Function call failed, could not generate detailed error message");
            goto exit;
        }
        amx2pythonerror(call_retval, error_message);
        free(error_message);
        goto exit;
    }

    result = variant2python(&retval);

exit:
    amxc_var_clean(&retval);
    amxc_var_clean(&converted_value);
    return result;
}

static PyMethodDef PAMXDMMethod_methods[] = {
    {NULL, NULL, 0, NULL}
};

static PyTypeObject PAMXDMMethodType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pamx.DMMethod",
    .tp_basicsize = sizeof(PAMXDMMethodObject),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor) PAMXDMMethod_dealloc,
    .tp_call = method_call,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "pamx dm method object",
    .tp_methods = PAMXDMMethod_methods,
    .tp_init = (initproc) PAMXDMMethod_init,
    .tp_new = PAMXDMMethod_new,
};

PyTypeObject* get_pamxDMMethod_type() {
    return &PAMXDMMethodType;
}
