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
#include "python_amx_timer.h"
#include "python_amx_conversion.h"
#include "structmember.h"
#include "python_amx_error_conversion.h"
#include "python_amx_eventloop.h"
#include <amxc/amxc_macros.h>

#define ME "python_amx_timer"

static int
timer_traverse(pamx_timer_t* self, visitproc visit, void* arg) {
    Py_VISIT(self->timer_func);
    Py_VISIT(self->timer_data);
    return 0;
}

static int
timer_clear(pamx_timer_t* self) {
    Py_CLEAR(self->timer_func);
    Py_CLEAR(self->timer_data);
    return 0;
}

static void
timer_dealloc(pamx_timer_t* self) {
    amxp_timer_stop(self->timer);
    amxp_timer_delete(&(self->timer));
    timer_clear(self);
    PyObject_GC_UnTrack(self);
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static void pamx_timer_handle(UNUSED amxp_timer_t* timer, void* userdata) {
    pamx_timer_t* tu = NULL;
    PyObject* retval = NULL;
    if(userdata != NULL) {
        tu = (pamx_timer_t*) userdata;
        if((tu->timer_func != NULL) && (tu->timer_data != NULL)) {
            retval = PyObject_CallObject(tu->timer_func, tu->timer_data);
            if(retval == NULL) {
                printf("\nError occurred in timer handler\n");
                eventloop_stop();
            }
            Py_XDECREF(retval);
        }
    }
}


static PyObject*
timer_new(struct _typeobject* type, PyObject* args, PyObject* kwds) {
    char const* kwlist_literals[] = {"callback", "callback_data", "interval", NULL};
    char* kwlist[4];
    PyObject* callback = NULL;
    PyObject* callback_data = NULL;
    uint64_t interval = 0;
    pamx_timer_t* self = NULL;
    int created = -1;
    transform_kwlist(kwlist, kwlist_literals);
    self = (pamx_timer_t*) type->tp_alloc(type, 0);
    if(self == NULL) {
        amx2pythonerror(-1, "tp_alloc failure.");
        goto exit;
    }

    if(PyArg_ParseTupleAndKeywords(args, kwds, "O|OI", kwlist,
                                   &callback,
                                   &callback_data,
                                   &interval) == 0) {
        amx2pythonerror(-1, "Could not build timer, incorrect parameters");
        goto exit;
    }

    if(PyCallable_Check(callback) == 0) {
        amx2pythonerror(-1, "Could not build timer, callback is not callable");
        goto exit;
    }

    self->timer_func = callback;
    Py_INCREF(self->timer_func);

    if(callback_data) {
        self->timer_data = Py_BuildValue("(O)", callback_data);
    } else {
        self->timer_data = Py_BuildValue("()");
    }

    created = amxp_timer_new(&(self->timer), pamx_timer_handle, self);
    if(created != 0) {
        amx2pythonerror(created, "Could not create timer.");
        goto exit;
    }

    self->interval = interval;
    if(interval != 0) {
        created = amxp_timer_set_interval(self->timer, interval);
        if(created != 0) {
            amx2pythonerror(created, "Could not create timer, could not set interval");
            goto exit;
        }
    }

    return (PyObject*) self;
exit:
    if(self != NULL) {
        amxp_timer_delete(&(self->timer));
        Py_XDECREF(self->timer_func);
        Py_XDECREF(self->timer_data);
        Py_TYPE(self)->tp_free((PyObject*) self);
    }
    return NULL;

}

static int
timer_init(UNUSED PyObject* self, UNUSED PyObject* args, UNUSED PyObject* kwds) {
    return 0;
}

static PyObject* pamx_timer_start(PyObject* self, PyObject* args) {
    unsigned int timeout = 0;
    amxp_timer_t* timer = ((pamx_timer_t*) self)->timer;
    int started = -1;
    if(PyArg_ParseTuple(args, "I", &timeout) == 0) {
        amx2pythonerror(-1, "No runtime given for timer.");
        goto exit;
    }

    started = amxp_timer_start(timer, timeout);
    if(started != 0) {
        amx2pythonerror(started, "Could not start timer.");
        goto exit;
    }

    Py_RETURN_NONE;
exit:
    return NULL;
}

static PyObject* pamx_timer_stop(PyObject* self, UNUSED PyObject* args) {
    amxp_timer_t* timer = ((pamx_timer_t*) self)->timer;
    int stopped = amxp_timer_stop(timer);
    if(stopped != 0) {
        amx2pythonerror(stopped, "Could not stop timer.");
        goto exit;
    }

    Py_RETURN_NONE;
exit:
    return NULL;
}

static PyMethodDef pamx_timer_methods[] = {
    {
        "start", (PyCFunction) pamx_timer_start, METH_VARARGS,
        "Start timer."
    },
    {
        "stop", (PyCFunction) pamx_timer_stop, METH_NOARGS,
        "Stop timer."
    },
    {NULL, NULL, 0, NULL}
};

static PyObject*
Timer_getInterval(pamx_timer_t* self, UNUSED void* closure) {
    return PyLong_FromUnsignedLong(self->interval);
}

static int
Timer_setInterval(pamx_timer_t* self, PyObject* value, UNUSED void* closure) {
    amxp_timer_t* timer = ((pamx_timer_t*) self)->timer;
    int set = -1;
    int retval = -1;
    if(PyLong_Check(value) == 0) {
        PyErr_SetString(PyExc_TypeError, "interval value must be an int.");
        goto exit;
    }

    self->interval = PyLong_AsUnsignedLongLong(value);

    set = amxp_timer_set_interval(timer, self->interval);
    if(set != 0) {
        amx2pythonerror(set, "Could not set interval.");
        goto exit;
    }

    retval = 0;

exit:
    return retval;
}

static PyObject*
Timer_getState(pamx_timer_t* self, UNUSED void* closure) {
    amxp_timer_t* timer = self->timer;
    PyObject* retval = NULL;
    switch(amxp_timer_get_state(timer)) {
    case amxp_timer_off:
        retval = PyUnicode_FromString("OFF");
        break;
    case amxp_timer_started:
        retval = PyUnicode_FromString("STARTED");
        break;
    case amxp_timer_running:
        retval = PyUnicode_FromString("RUNNING");
        break;
    case amxp_timer_expired:
        retval = PyUnicode_FromString("EXPIRED");
        break;
    default:
        Py_RETURN_NONE;
    }

    return retval;
}

static int
Timer_setState(UNUSED pamx_timer_t* self, UNUSED PyObject* value, UNUSED void* closure) {
    PyErr_SetString(PyExc_AttributeError, "Cannot manually set state");
    return -1;
}

static PyObject*
Timer_getRemaining(pamx_timer_t* self, UNUSED void* closure) {
    amxp_timer_t* timer = self->timer;
    unsigned int value = amxp_timer_remaining_time(timer);
    return PyLong_FromUnsignedLong(value);
}

static int
Timer_setRemaining(UNUSED pamx_timer_t* self, UNUSED PyObject* value, UNUSED void* closure) {
    PyErr_SetString(PyExc_TypeError, "Cannot manually set remaining time.");
    return -1;
}

static PyGetSetDef Timer_getsetters[] = {
    {"interval", (getter) Timer_getInterval, (setter) Timer_setInterval,
        "interval of timer", NULL},
    {"state", (getter) Timer_getState, (setter) Timer_setState,
        "state of timer", NULL},
    {"remaining", (getter) Timer_getRemaining, (setter) Timer_setRemaining,
        "remaining time of timer", NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject PAMXTimerType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pamx.Timer",
    .tp_basicsize = sizeof(pamx_timer_t),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor) timer_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_doc = "pamx timer",
    .tp_traverse = (traverseproc) timer_traverse,
    .tp_clear = (inquiry) timer_clear,
    .tp_methods = pamx_timer_methods,
    .tp_getset = Timer_getsetters,
    .tp_init = (initproc) timer_init,
    .tp_new = timer_new,
};

PyTypeObject* get_pamx_timer_type() {
    return &PAMXTimerType;
}
