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

#include "python_amx.h"
#include "python_amx_backend_singleton.h"
#include "python_amx_error_conversion.h"
#include "python_amx_conversion.h"
#include "structmember.h"
#include <amxc/amxc_macros.h>


#define ME "python_amx_object"

static void
PAMXBACKEND_dealloc(PAMXBACKENDObject* self) {
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject*
PAMXBACKEND_new(struct _typeobject* type, UNUSED PyObject* args, UNUSED PyObject* kwds) {
    PAMXBACKENDObject* self = (PAMXBACKENDObject*) type->tp_alloc(type, 0);
    if(self == NULL) {
        amx2pythonerror(-1, "allocation failure");
        goto exit;
    }
    return (PyObject*) self;
exit:
    return NULL;
}

static int
PAMXBACKEND_init(UNUSED PyObject* self, UNUSED PyObject* args, UNUSED PyObject* kwds) {
    return 0;
}

static PyObject*
pamx_load_backend(UNUSED PyObject* self, PyObject* args) {
    const char* path = NULL;
    int loaded = 0;
    if(PyArg_ParseTuple(args, "s", &path) == 0) {
        amx2pythonerror(-1, "No path was provided");
        goto exit;
    }

    loaded = amxb_be_load(path);
    if(loaded != 0) {
        amx2pythonerror(loaded, "Could not load backend");
        goto exit;
    }
    Py_RETURN_NONE;

exit:
    return NULL;
}

static PyObject*
pamx_set_backend_config(UNUSED PyObject* self, PyObject* args) {
    int retval = -1;
    amxc_var_t converted_config;
    PyObject* dict = NULL;
    amxc_var_init(&converted_config);

    if(PyArg_ParseTuple(args, "|O!", &PyDict_Type, &dict) == 0) {
        amx2pythonerror(-1, "Incorrect parameters");
        goto exit;
    }

    if(dict != NULL) {
        python2variant(dict, &converted_config);
        retval = amxb_set_config(&converted_config);
    } else {
        retval = amxb_set_config(NULL);
    }
    if(retval != 0) {
        amx2pythonerror(retval, "Could not set config");
        goto exit;
    }
    Py_RETURN_NONE;

exit:
    amxc_var_clean(&converted_config);
    return NULL;
}

static PyObject* pamx_list_backends(UNUSED PyObject* self, UNUSED PyObject* args) {
    PyObject* resultlist = PyList_New(0);
    PyObject* py_name = NULL;
    amxc_array_t* names = amxb_be_list();
    size_t size = 0;

    if(resultlist == NULL) {
        amx2pythonerror(-1, "Could not create list");
        goto exit;
    }

    if(names != NULL) {
        size = amxc_array_size(names);
        for(size_t i = 0; i < size; i++) {
            const char* name = (const char*) amxc_array_get_data_at(names, i);
            py_name = PyUnicode_FromString(name);
            PyList_Append(resultlist, py_name);
            Py_DECREF(py_name);
        }
        amxc_array_delete(&names, NULL);
    }

exit:
    return resultlist;
}

static PyObject*
pamx_remove_backend(UNUSED PyObject* self, PyObject* args) {
    const char* name = NULL;
    int removed = 0;
    if(PyArg_ParseTuple(args, "s", &name) == 0) {
        amx2pythonerror(-1, "No name was provided");
        goto exit;
    }

    removed = amxb_be_remove(name);
    if(removed != 0) {
        amx2pythonerror(removed, "Could not remove backend");
        goto exit;
    }

    Py_RETURN_NONE;
exit:
    return NULL;
}


static PyMemberDef PAMXBACKEND_members[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef PAMXBACKEND_methods[] = {
    {
        "load", (PyCFunction) pamx_load_backend, METH_VARARGS,
        "Load specified backend"
    },
    {
        "remove", (PyCFunction) pamx_remove_backend, METH_VARARGS,
        "Remove loaded backend"
    },
    {
        "set_config", (PyCFunction) pamx_set_backend_config, METH_VARARGS,
        "Set backend config"
    },
    {
        "list", (PyCFunction) pamx_list_backends, METH_NOARGS,
        "List the loaded backends."
    },

    {NULL, NULL, 0, NULL}
};

static PyTypeObject PAMXBACKENDType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pamx.backend",
    .tp_basicsize = sizeof(PAMXBACKENDObject),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor) PAMXBACKEND_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "pamx backend object",
    .tp_methods = PAMXBACKEND_methods,
    .tp_members = PAMXBACKEND_members,
    .tp_init = (initproc) PAMXBACKEND_init,
    .tp_new = PAMXBACKEND_new,
};

PyTypeObject* get_pamx_backend_type() {
    return &PAMXBACKENDType;
}
