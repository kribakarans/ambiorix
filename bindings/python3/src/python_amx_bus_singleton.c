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
#include "python_amx_bus_singleton.h"
#include "python_amx_conversion.h"
#include "python_amx_connection_object.h"
#include "python_amx_eventloop.h"
#include "python_amx_error_conversion.h"
#include "structmember.h"


#define ME "python_amx_object"

static int
object_traverse(PAMXBUSObject* self, visitproc visit, void* arg) {
    Py_VISIT(self->con_list);
    return 0;
}

static int
object_clear(PAMXBUSObject* self) {
    Py_CLEAR(self->con_list);
    return 0;
}

static void
PAMXBUS_dealloc(PAMXBUSObject* self) {
    eventloop_destroy();
    object_clear(self);
    free_access_levels();
    set_python_amx(NULL);
    PyObject_GC_UnTrack(self);
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject*
PAMXBUS_new(struct _typeobject* type, __attribute__((unused)) PyObject* args, __attribute__((unused)) PyObject* kwds) {
    PAMXBUSObject* self = NULL;
    self = (PAMXBUSObject*) type->tp_alloc(type, 0);

    if(self == NULL) {
        amx2pythonerror(-1, "tp_alloc failed");
        goto exit;
    }
    self->con_list = PyList_New(0);
    if(self->con_list == NULL) {
        amx2pythonerror(-1, "cannot create python list.");
        goto exit;
    }

    set_python_amx((PyObject*) self);
    eventloop_create();

exit:
    if(PyErr_Occurred() != NULL) {
        eventloop_destroy();
        free_access_levels();
        if(self != NULL) {
            Py_XDECREF(self->con_list);
            Py_TYPE(self)->tp_free((PyObject*) self);
        }
        set_python_amx(NULL);
    }
    return get_python_amx();
}

static int
PAMXBUS_init(UNUSED PyObject* self, UNUSED PyObject* args, UNUSED PyObject* kwds) {
    return 0;
}

static PyObject*
pamx_connect(PyObject* self, PyObject* args) {
    PyObject* retval = NULL;

    retval = PyObject_CallObject((PyObject*) get_pamxConnection_type(), args);
    if(retval == NULL) {
        amx2pythonerror(-1, "cannot create connection.");
        goto exit;
    }

    PyList_Append(((PAMXBUSObject*) self)->con_list, retval);
    eventloop_create();


exit:
    return retval;
}

static PyObject*
pamx_who_has(PyObject* self, PyObject* args) {
    const char* path = NULL;
    PyObject* value = NULL;
    PyObject* retval = NULL;
    amxb_bus_ctx_t* bus = NULL;
    PyObject* iterator = PyObject_GetIter(((PAMXBUSObject*) self)->con_list);

    if(PyArg_ParseTuple(args, "s", &path) == 0) {
        amx2pythonerror(-1, "No path was provided");
        goto exit;
    }

    bus = amxb_be_who_has(path);
    if(bus == NULL) {
        amx2pythonerror(-1, "Could not find provided path.");
        goto exit;
    }

    while((value = PyIter_Next(iterator))) {
        if(((PAMXConnectionObject*) value)->bus_ctx == bus) {
            retval = value;
            break;
        }
        Py_DECREF(value);
    }

    if(retval == NULL) {
        amx2pythonerror(-1, "Could not find matching connection.");
        goto exit;
    }

exit:
    Py_CLEAR(iterator);
    return retval;
}

static PyMemberDef PAMXBUS_members[] = {
    {NULL}  /* Sentinel */
};

static PyObject*
pamx_disconnect(PyObject* self, UNUSED PyObject* args) {
    PyObject* iterator = PyObject_GetIter(((PAMXBUSObject*) self)->con_list);
    PyObject* value = NULL;
    PyObject* retval = NULL;

    while((value = PyIter_Next(iterator))) {
        retval = PyObject_CallMethod(value, "close", NULL);
        Py_DECREF(value);
        if(!retval) {
            amx2pythonerror(-1, "Could not disconnect current connections.");
            goto exit;
        }
        Py_XDECREF(retval);
    }

    Py_RETURN_NONE;
exit:
    return NULL;
}

static PyMethodDef PAMXBUS_methods[] = {
    {
        "connect", (PyCFunction) pamx_connect, METH_VARARGS,
        "Open connection to the given url"
    },
    {
        "who_has", (PyCFunction) pamx_who_has, METH_VARARGS,
        "Open connection to bus that offers specific object"
    },
    {
        "close_connections", (PyCFunction) pamx_disconnect, METH_NOARGS,
        "Close the connections."
    },
    {NULL, NULL, 0, NULL}
};

static PyTypeObject PAMXBUSType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pamx.bus",
    .tp_basicsize = sizeof(PAMXBUSObject),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor) PAMXBUS_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_doc = "pamx object",
    .tp_traverse = (traverseproc) object_traverse,
    .tp_methods = PAMXBUS_methods,
    .tp_members = PAMXBUS_members,
    .tp_init = (initproc) PAMXBUS_init,
    .tp_new = PAMXBUS_new,
};

PyTypeObject* get_pamx_bus_type() {
    return &PAMXBUSType;
}
