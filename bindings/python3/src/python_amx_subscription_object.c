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
#include "python_amx_subscription_object.h"
#include "python_amx_connection_object.h"
#include "python_amx_error_conversion.h"

#define ME "python_amx_subscription_object"

static void
PAMXSub_dealloc(PAMXSubObject* self) {
    if(self->closed == false) {
        amxb_unsubscribe(self->bus, self->path, notify_handler, self->data);
    }
    if(self->data != NULL) {
        free_data(self->data);
        self->data = NULL;
    }
    free(self->path);
    self->path = NULL;

    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject*
PAMXSub_new(PyTypeObject* type, UNUSED PyObject* args, UNUSED PyObject* kwds) {
    PAMXSubObject* self;
    self = (PAMXSubObject*) type->tp_alloc(type, 0);
    if(self == NULL) {
        amx2pythonerror(-1, "tp_alloc failure.");
        goto exit;
    }
    self->closed = false;

    return (PyObject*) self;
exit:
    return NULL;
}

static int
PAMXSub_init(UNUSED PyObject* self, UNUSED PyObject* args, UNUSED PyObject* kwds) {
    return 0;
}

static PyObject*
pamx_close(PyObject* self, UNUSED PyObject* args) {
    char* path = (((PAMXSubObject*) self)->path);
    data_t* sub_data = (((PAMXSubObject*) self)->data);
    int call_retval = -1;

    call_retval = amxb_unsubscribe((((PAMXSubObject*) self)->bus), path, notify_handler, sub_data);

    if(call_retval != 0) {
        amx2pythonerror(call_retval, "Could not perform unsubscribe");
        goto exit;
    }

    ((PAMXSubObject*) self)->closed = true;
    Py_RETURN_NONE;

exit:
    return NULL;
}


static PyMethodDef sub_methods[] = {
    {
        "close", (PyCFunction) pamx_close, METH_NOARGS,
        "Close the subscription."
    },
    {NULL, NULL, 0, NULL}
};

static PyTypeObject PAMXSubType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pamx.PAMXSub",
    .tp_basicsize = sizeof(PAMXSubObject),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor) PAMXSub_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "pamx subscription object",
    .tp_methods = sub_methods,
    .tp_init = (initproc) PAMXSub_init,
    .tp_new = PAMXSub_new,
};

PyTypeObject* get_pamxSub_type() {
    return &PAMXSubType;
}
