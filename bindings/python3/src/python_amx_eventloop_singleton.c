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
#include "python_amx_eventloop.h"
#include "python_amx_eventloop_singleton.h"
#include "python_amx_error_conversion.h"
#include "structmember.h"


#define ME "python_amx_object"

static void
PAMXEVENTLOOP_dealloc(PAMXEVENTLOOPObject* self) {
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject*
PAMXEVENTLOOP_new(struct _typeobject* type, UNUSED PyObject* args, UNUSED PyObject* kwds) {
    PAMXEVENTLOOPObject* self;
    self = (PAMXEVENTLOOPObject*) type->tp_alloc(type, 0);
    if(self == NULL) {
        amx2pythonerror(-1, "tp_alloc failure");
        goto exit;
    }

    return (PyObject*) self;
exit:
    return NULL;
}

static int
PAMXEVENTLOOP_init(UNUSED PyObject* self, UNUSED PyObject* args, UNUSED PyObject* kwds) {
    return 0;
}

static PyObject* pamx_starteventloop(UNUSED PyObject* self, UNUSED PyObject* args) {
    int started = 0;
    started = eventloop_start();
    if(started != 0) {
        amx2pythonerror(started, "Could not start event loop.");
        goto exit;
    }

    if(PyErr_Occurred() != NULL) {
        goto exit;
    }

    Py_RETURN_NONE;
exit:
    return NULL;
}

static PyObject* pamx_stopeventloop(UNUSED PyObject* self, UNUSED PyObject* args) {
    int stopped = 0;
    stopped = eventloop_stop();
    if(stopped != 0) {
        amx2pythonerror(stopped, "Could not stop event loop.");
        goto exit;
    }

    Py_RETURN_NONE;
exit:
    return NULL;
}


static PyMemberDef PAMXEVENTLOOP_members[] = {
    {NULL}  /* Sentinel */
};


static PyMethodDef PAMXEVENTLOOP_methods[] = {
    {
        "start", (PyCFunction) pamx_starteventloop, METH_NOARGS,
        "Start the event loop."
    },
    {
        "stop", (PyCFunction) pamx_stopeventloop, METH_NOARGS,
        "Stop the event loop."
    },

    {NULL, NULL, 0, NULL}
};

static PyTypeObject PAMXEVENTLOOPType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pamx.eventloop",
    .tp_basicsize = sizeof(PAMXEVENTLOOPObject),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor) PAMXEVENTLOOP_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "pamx eventloop object",
    .tp_methods = PAMXEVENTLOOP_methods,
    .tp_members = PAMXEVENTLOOP_members,
    .tp_init = (initproc) PAMXEVENTLOOP_init,
    .tp_new = PAMXEVENTLOOP_new,
};

PyTypeObject* get_pamx_eventloop_type() {
    return &PAMXEVENTLOOPType;
}
