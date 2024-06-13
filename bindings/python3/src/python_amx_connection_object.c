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
#include "python_amx_connection_object.h"
#include "python_amx_request_object.h"
#include "python_amx_eventloop.h"
#include "python_amx_conversion.h"
#include "python_amx_error_conversion.h"
#include "python_amx_subscription_object.h"

#include <event2/event.h>

#define ME "python_amx_connection_object"

static int
object_traverse(PAMXConnectionObject* self, visitproc visit, void* arg) {
    Py_VISIT(self->sub_list);
    Py_VISIT(self->req_list);
    return 0;
}

static void
PAMXConnection_dealloc(PAMXConnectionObject* self) {
    Py_CLEAR(self->sub_list);
    Py_CLEAR(self->req_list);
    free(self->uri);
    self->uri = NULL;
    amxb_free(&(self->bus_ctx));

    amxc_llist_delete(&(self->list_cb_list), delete_list_data);

    if(self->el_data != NULL) {
        event_del(self->el_data);
        free(self->el_data);
        self->el_data = NULL;
    }

    PyObject_GC_UnTrack(self);
    Py_TYPE(self)->tp_free((PyObject*) self);

}

static PyObject*
PAMXConnection_new(PyTypeObject* type, PyObject* args, UNUSED PyObject* kwds) {
    const char* uri = NULL;
    int connected = -1;
    PAMXConnectionObject* self = (PAMXConnectionObject*) type->tp_alloc(type, 0);
    if(self == NULL) {
        amx2pythonerror(-1, "Could not allocate memory");
        return NULL;
    }
    if(PyArg_ParseTuple(args, "s", &uri) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    connected = amxb_connect(&(self->bus_ctx), uri);
    if(connected != 0) {
        amx2pythonerror(-1, "Could not connect to provided uri");
        goto exit;
    }

    amxb_set_access(self->bus_ctx, AMXB_PUBLIC);
    self->access_level = AMXB_PUBLIC;

    self->uri = strdup(uri);
    self->sub_list = PyList_New(0);
    self->req_list = PyList_New(0);
    if((self->sub_list == NULL) || (self->req_list == NULL)) {
        amx2pythonerror(-1, "Could not allocate lists");
        goto exit;
    }

    amxc_llist_new(&(self->list_cb_list));
    self->closed = false;
    return (PyObject*) self;

exit:
    if(self != NULL) {
        if(self->uri != NULL) {
            free(self->uri);
            self->uri = NULL;
        }
        amxc_llist_delete(&(self->list_cb_list), delete_list_data);
        amxb_free(&(self->bus_ctx));
        Py_XDECREF(self->sub_list);
        Py_XDECREF(self->req_list);
        Py_TYPE(self)->tp_free((PyObject*) self);
    }
    return NULL;
}

static int
PAMXConnection_init(UNUSED PyObject* self, UNUSED PyObject* args, UNUSED PyObject* kwds) {
    return 0;
}

static PyObject*
pamx_get(PyObject* self, PyObject* args, PyObject* kwds) {
    const char* path;
    int depth = 0;
    int timeout_sec = 5;
    int retval = -1;
    amxc_var_t retrieved;
    PyObject* result = NULL;
    static const char* kwlist_literals[] = {"path", "depth", "timeout_sec", NULL};
    char* kwlist[4];
    transform_kwlist(kwlist, kwlist_literals);
    amxc_var_init(&retrieved);
    if(PyArg_ParseTupleAndKeywords(args, kwds, "s|ii", kwlist, &path, &depth, &timeout_sec) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    retval = amxb_get((((PAMXConnectionObject*) self)->bus_ctx), path, depth, &retrieved, timeout_sec);
    if(retval != 0) {
        amx2pythonerror(retval, "Could not perform get");
        goto exit;
    }

    result = variant2python(&retrieved);

exit:
    amxc_var_clean(&retrieved);
    return result;
}

static PyObject*
pamx_set(PyObject* self, PyObject* args) {
    const char* path = NULL;
    PyObject* dict = NULL;
    PyObject* result = NULL;
    int timeout_sec = 5;
    int retval = -1;
    amxc_var_t set;
    amxc_var_t converted_value;
    amxc_var_init(&set);
    amxc_var_init(&converted_value);


    if(!PyArg_ParseTuple(args, "sO!|i", &path, &PyDict_Type, &dict, &timeout_sec)) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    python2variant(dict, &converted_value);

    retval = amxb_set((((PAMXConnectionObject*) self)->bus_ctx), path, &converted_value, &set, timeout_sec);
    if(retval != 0) {
        amx2pythonerror(retval, "Could not perform set");
        goto exit;
    }

    result = variant2python(&set);

exit:
    amxc_var_clean(&set);
    amxc_var_clean(&converted_value);
    return result;

}

static PyObject*
pamx_add(PyObject* self, PyObject* args, PyObject* kwds) {
    const char* path = NULL;
    const char* name = NULL;
    PyObject* dict = NULL;
    PyObject* result = NULL;
    uint32_t index = 0;
    int timeout_sec = 5;
    int retval = -1;
    amxc_var_t ret;
    amxc_var_t converted_value;
    static const char* kwlist_literals[] = {"path", "values", "index", "name", "timeout_sec", NULL};
    char* kwlist[6];
    transform_kwlist(kwlist, kwlist_literals);
    amxc_var_init(&ret);
    amxc_var_init(&converted_value);


    if(PyArg_ParseTupleAndKeywords(args, kwds, "sO!|Isi", kwlist, &path, &PyDict_Type, &dict, &index, &name, &timeout_sec) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    python2variant(dict, &converted_value);
    retval = amxb_add((((PAMXConnectionObject*) self)->bus_ctx), path, index, name, &converted_value, &ret, timeout_sec);
    if(retval != 0) {
        amx2pythonerror(retval, "Could not perform set");
        goto exit;
    }

    result = variant2python(&ret);

exit:
    amxc_var_clean(&ret);
    amxc_var_clean(&converted_value);
    return result;
}

static PyObject*
pamx_del(PyObject* self, PyObject* args, PyObject* kwds) {
    const char* path = NULL;
    const char* name = NULL;
    PyObject* result = NULL;
    uint32_t index = 0;
    int timeout_sec = 5;
    int retval = -1;
    amxc_var_t ret;
    static const char* kwlist_literals[] = {"path", "index", "name", "timeout_sec", NULL};
    char* kwlist[5];
    transform_kwlist(kwlist, kwlist_literals);
    amxc_var_init(&ret);

    if(PyArg_ParseTupleAndKeywords(args, kwds, "s|Isi", kwlist, &path, &index, &name, &timeout_sec) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    retval = amxb_del((((PAMXConnectionObject*) self)->bus_ctx), path, index, name, &ret, timeout_sec);
    if(retval != 0) {
        amx2pythonerror(retval, "Could not perform set");
        goto exit;
    }

    result = variant2python(&ret);

exit:
    amxc_var_clean(&ret);
    return result;
}

static PyObject*
pamx_call(PyObject* self, PyObject* args) {
    const char* path = NULL;
    const char* function = NULL;
    PyObject* dict = NULL;
    PyObject* result = NULL;
    int timeout_sec = 5;
    int call_retval = -1;
    amxc_var_t retval;
    amxc_var_t converted_value;
    amxc_var_init(&retval);
    amxc_var_init(&converted_value);
    if(PyArg_ParseTuple(args, "ss|O!i", &path, &function, &PyDict_Type, &dict, &timeout_sec) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    if(dict != NULL) {
        python2variant(dict, &converted_value);
    }

    call_retval = amxb_call((((PAMXConnectionObject*) self)->bus_ctx), path, function, &converted_value, &retval, timeout_sec);
    if(call_retval != 0) {
        amx2pythonerror(call_retval, "Could not perform call");
        goto exit;
    }

    result = variant2python(&retval);

exit:
    amxc_var_clean(&retval);
    amxc_var_clean(&converted_value);
    return result;
}

void notify_handler(const char* const sig_name,
                    const amxc_var_t* const data,
                    void* const sub_data) {

    if(sub_data != NULL) {
        data_t* d = ((data_t*) sub_data);
        PyObject* params = NULL;
        PyObject* python_data = variant2python(data);
        PyObject* retval = NULL;
        if(d->data != NULL) {
            params = Py_BuildValue("sOO", sig_name, python_data, d->data);
        } else {
            params = Py_BuildValue("sO", sig_name, python_data);
        }

        retval = PyObject_CallObject(d->function, params);
        if((retval == NULL) || PyErr_Occurred()) {
            eventloop_stop();
        }

        Py_DECREF(params);
        Py_DECREF(python_data);
        Py_XDECREF(retval);
    }

}


static PyObject*
pamx_subscribe(PyObject* self, PyObject* args) {
    const char* path = NULL;
    const char* expression = NULL;
    PyObject* function = NULL;
    PyObject* data = NULL;
    data_t* d = NULL;
    int call_retval = -1;
    PyObject* retval = NULL;
    if(PyArg_ParseTuple(args, "ssO|O", &path, &expression, &function, &data) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    if(PyCallable_Check(function) == 0) {
        PyErr_SetString(PyExc_TypeError, "event callback is not callable.");
        goto exit;
    }

    d = init_data(function, data);
    if(d == NULL) {
        amx2pythonerror(-1, "Cannot initialize userdata");
        goto exit;
    }

    call_retval = amxb_subscribe((((PAMXConnectionObject*) self)->bus_ctx), path, expression, notify_handler, d);
    if(call_retval != 0) {
        amx2pythonerror(call_retval, "Could not perform subscribe");
        goto exit;
    }

    retval = PyObject_CallObject((PyObject*) get_pamxSub_type(), NULL);
    if(retval == NULL) {
        amx2pythonerror(-1, "Cannot initialize subscription");
        goto exit;
    }
    ((PAMXSubObject*) retval)->bus = (((PAMXConnectionObject*) self)->bus_ctx);
    ((PAMXSubObject*) retval)->path = strdup(path);
    ((PAMXSubObject*) retval)->data = d;

    PyList_Append(((PAMXConnectionObject*) self)->sub_list, retval);

    return retval;

exit:
    if(PyErr_Occurred() != NULL) {
        free_data(d);
        d = NULL;
        Py_XDECREF(retval);
    }
    return NULL;
}

static PyObject*
pamx_describe(PyObject* self, PyObject* args, PyObject* kwds) {
    const char* path = NULL;
    int functions = 0;
    int parameters = 0;
    int objects = 0;
    int instances = 0;
    int timeout_sec = 5;
    uint32_t flags = 0;
    int retval = 0;
    amxc_var_t ret;
    PyObject* result = NULL;
    static const char* kwlist_literals[] = {"path", "functions", "parameters", "objects", "instances", "timeout_sec", NULL};
    char* kwlist[7];
    transform_kwlist(kwlist, kwlist_literals);
    amxc_var_init(&ret);

    if(PyArg_ParseTupleAndKeywords(args, kwds, "s|ppppi", kwlist, &path, &functions, &parameters, &objects, &instances, &timeout_sec) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }
    if(functions != 0) {
        flags |= AMXB_FLAG_FUNCTIONS;
    }
    if(parameters != 0) {
        flags |= AMXB_FLAG_PARAMETERS;
    }
    if(objects != 0) {
        flags |= AMXB_FLAG_OBJECTS;
    }
    if(instances != 0) {
        flags |= AMXB_FLAG_INSTANCES;
    }

    retval = amxb_describe((((PAMXConnectionObject*) self)->bus_ctx), path, flags, &ret, timeout_sec);
    if(retval != 0) {
        amx2pythonerror(retval, "Could not perform describe");
        goto exit;
    }
    result = variant2python(&ret);

exit:
    amxc_var_clean(&ret);
    return result;
}

static void list_handler(UNUSED const amxb_bus_ctx_t* bus_ctx,
                         const amxc_var_t* const data,
                         void* priv) {

    if(priv != NULL) {
        data_t* d = ((data_t*) priv);

        PyObject* params = NULL;
        PyObject* python_data = variant2python(data);
        PyObject* retval = NULL;

        if(d->data != NULL) {
            params = Py_BuildValue("OO", python_data, d->data);
        } else {
            params = Py_BuildValue("(O)", python_data);
        }

        retval = PyObject_CallObject(d->function, params);

        if((retval == NULL) || PyErr_Occurred()) {
            eventloop_stop();
        }

        Py_DECREF(params);
        Py_DECREF(python_data);
        Py_XDECREF(retval);
    }

}

static PyObject*
pamx_list(PyObject* self, PyObject* args, PyObject* kwds) {
    const char* path = NULL;
    int functions = 0;
    int parameters = 0;
    int objects = 0;
    int instances = 0;
    uint32_t flags = 0;
    int retval = -1;
    PyObject* function = NULL;
    PyObject* data = NULL;
    list_data_t* d = NULL;
    static const char* kwlist_literals[] = {"path", "function", "userdata", "functions", "parameters", "objects", "instances", NULL};
    char* kwlist[8];
    transform_kwlist(kwlist, kwlist_literals);
    if(PyArg_ParseTupleAndKeywords(args, kwds, "sO|Opppp", kwlist, &path, &function, &data, &functions, &parameters, &objects, &instances) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    if(PyCallable_Check(function) == 0) {
        PyErr_SetString(PyExc_TypeError, "event callback is not callable.");
        goto exit;
    }

    if(functions != 0) {
        flags |= AMXB_FLAG_FUNCTIONS;
    }
    if(parameters != 0) {
        flags |= AMXB_FLAG_PARAMETERS;
    }
    if(objects != 0) {
        flags |= AMXB_FLAG_OBJECTS;
    }
    if(instances != 0) {
        flags |= AMXB_FLAG_INSTANCES;
    }

    d = init_list_data(function, data);
    if(d == NULL) {
        amx2pythonerror(-1, "Cannot initialize userdata");
        goto exit;
    }


    amxc_llist_append((((PAMXConnectionObject*) self)->list_cb_list), &(d->ll_it));

    retval = amxb_list((((PAMXConnectionObject*) self)->bus_ctx), path, flags, list_handler, d);
    if(retval != 0) {
        amx2pythonerror(retval, "Could not perform list");
        goto exit;
    }

    Py_RETURN_NONE;

exit:
    if(PyErr_Occurred() != NULL) {
        if(d != NULL) {
            amxc_llist_it_clean(&(d->ll_it), delete_list_data);
        }
    }
    return NULL;
}


static PyObject*
pamx_get_supported(PyObject* self, PyObject* args, PyObject* kwds) {
    static const char* kwlist_literals[] = {"path", "first_level", "functions", "parameters", "events", "timeout_sec", NULL};
    char* kwlist[7];
    const char* path = NULL;
    int first_level = 0;
    int functions = 0;
    int parameters = 0;
    int events = 0;
    int timeout_sec = 5;
    uint32_t flags = 0;
    int retval = 0;
    PyObject* result = NULL;
    amxc_var_t ret;
    amxc_var_init(&ret);
    transform_kwlist(kwlist, kwlist_literals);

    if(PyArg_ParseTupleAndKeywords(args, kwds, "s|ppppi", kwlist, &path, &first_level, &functions, &parameters, &events, &timeout_sec) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }
    if(first_level != 0) {
        flags |= AMXB_FLAG_FIRST_LVL;
    }
    if(functions != 0) {
        flags |= AMXB_FLAG_FUNCTIONS;
    }
    if(parameters != 0) {
        flags |= AMXB_FLAG_PARAMETERS;
    }
    if(events != 0) {
        flags |= AMXB_FLAG_EVENTS;
    }

    retval = amxb_get_supported((((PAMXConnectionObject*) self)->bus_ctx), path, flags, &ret, timeout_sec);
    if(retval != 0) {
        amx2pythonerror(retval, "Could not perform get_supported");
        goto exit;
    }

    result = variant2python(&ret);

exit:
    amxc_var_clean(&ret);
    return result;
}

static PyObject*
pamx_disconnect(PyObject* self, UNUSED PyObject* args) {
    int retval = -1;

    if(((PAMXConnectionObject*) self)->closed == true) {
        retval = 0;
    } else {
        retval = amxb_disconnect((((PAMXConnectionObject*) self)->bus_ctx));
    }
    if(retval != 0) {
        amx2pythonerror(retval, "Could not perform amxb_disconnect");
        goto exit;
    }

    ((PAMXConnectionObject*) self)->closed = true;
    Py_RETURN_NONE;
exit:
    return NULL;
}

void async_handler(UNUSED const amxb_bus_ctx_t* bus_ctx,
                   amxb_request_t* req,
                   int status,
                   void* priv) {

    PyObject* retval = NULL;
    if(priv != NULL) {
        data_t* d = ((data_t*) priv);
        if(req == NULL) {
            amx2pythonerror(status, "Error during async operation.");
            return;
        }

        if(d->function) {
            PyObject* params = NULL;
            PyObject* python_data = NULL;
            if(req->result && d->data) {
                python_data = variant2python(req->result);
                params = Py_BuildValue("OO", python_data, d->data);
            } else if(!req->result && d->data) {
                params = Py_BuildValue("(O)", d->data);
            } else if(req->result && !d->data) {
                python_data = variant2python(req->result);
                params = Py_BuildValue("(O)", python_data);
            } else {
                params = Py_BuildValue("()");
            }

            retval = PyObject_CallObject(d->function, params);
            Py_DECREF(params);
            Py_XDECREF(python_data);
            Py_XDECREF(retval);
        }
    }
}



static PyObject*
pamx_async_call(PyObject* self, PyObject* args, PyObject* kwds) {
    const char* path = NULL;
    const char* function = NULL;
    PyObject* parameters = NULL;
    PyObject* cb_function = NULL;
    PyObject* userdata = NULL;
    amxb_request_t* request = NULL;
    PyObject* retval = NULL;
    data_t* d = NULL;
    static const char* kwlist_literals[] = {"path", "function", "parameters", "callback", "userdata", NULL};
    char* kwlist[6];
    amxc_var_t converted_value;
    amxc_var_init(&converted_value);
    transform_kwlist(kwlist, kwlist_literals);
    if(PyArg_ParseTupleAndKeywords(args, kwds, "ss|O!OO", kwlist, &path, &function, &PyDict_Type, &parameters, &cb_function, &userdata) == 0) {
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
        amx2pythonerror(-1, "Cannot initialize userdata");
        goto exit;
    }

    if(parameters != NULL) {
        python2variant(parameters, &converted_value);
    }

    request = amxb_async_call((((PAMXConnectionObject*) self)->bus_ctx), path, function, &converted_value, async_handler, d);
    if(request == NULL) {
        amx2pythonerror(-1, "Could not perform amxb_async_call");
        goto exit;
    }

    retval = PyObject_CallObject((PyObject*) get_pamxRequest_type(), NULL);
    ((PAMXRequestObject*) retval)->request = request;
    ((PAMXRequestObject*) retval)->data = d;

    PyList_Append(((PAMXConnectionObject*) self)->req_list, retval);

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

static PyObject*
Connection_getUri(PAMXConnectionObject* self, UNUSED void* closure) {
    return PyUnicode_FromString(self->uri);
}

static int
Connection_setUri(UNUSED PAMXConnectionObject* self, UNUSED PyObject* value, UNUSED void* closure) {
    PyErr_SetString(PyExc_TypeError, "Cannot manually set uri on open connection.");
    return -1;
}

static PyObject*
Connection_getAccess(PAMXConnectionObject* self, UNUSED void* closure) {
    PyObject* retval = NULL;
    switch(self->access_level) {
    case AMXB_PUBLIC:
        retval = PyUnicode_FromString("public");
        break;
    case AMXB_PROTECTED:
        retval = PyUnicode_FromString("protected");
        break;
    default:
        PyErr_SetString(PyExc_TypeError, "Unknown access level.");
    }
    return retval;
}

static int
Connection_setAccess(PAMXConnectionObject* self, PyObject* value, UNUSED void* closure) {
    int retval = -1;
    amxc_var_t* level = amxc_var_get_key(get_access_levels(), PyUnicode_AsUTF8(value), AMXC_VAR_FLAG_DEFAULT);
    if(level == NULL) {
        PyErr_SetString(PyExc_TypeError, "Unknown access level.");
        goto exit;
    }
    self->access_level = amxc_var_dyncast(int32_t, level);
    amxb_set_access(self->bus_ctx, self->access_level);
    retval = 0;

exit:
    return retval;
}

static PyGetSetDef Connection_getsetters[] = {
    {"uri", (getter) Connection_getUri, (setter) Connection_setUri,
        "uri of connection", NULL},
    {"access_level", (getter) Connection_getAccess, (setter) Connection_setAccess,
        "access level of connection", NULL},
    {NULL}  /* Sentinel */
};

#pragma GCC diagnostic ignored "-Wcast-function-type"
#pragma GCC diagnostic push
static PyMethodDef connection_methods[] = {
    {
        "get", (PyCFunction) pamx_get, METH_VARARGS | METH_KEYWORDS,
        "Open connection with the pcb bus"
    },
    {
        "set", (PyCFunction) pamx_set, METH_VARARGS,
        "Perform set operation"
    },
    {
        "add", (PyCFunction) pamx_add, METH_VARARGS | METH_KEYWORDS,
        "Perform add operation"
    },
    {
        "delete", (PyCFunction) pamx_del, METH_VARARGS | METH_KEYWORDS,
        "Perform delete operation"
    },
    {
        "describe", (PyCFunction) pamx_describe, METH_VARARGS | METH_KEYWORDS,
        "Perform describe operation"
    },
    {
        "async_call", (PyCFunction) pamx_async_call, METH_VARARGS | METH_KEYWORDS,
        "Perform async_call operation"
    },
    {
        "get_supported", (PyCFunction) pamx_get_supported, METH_VARARGS | METH_KEYWORDS,
        "Perform get_supported operation"
    },
    {
        "list", (PyCFunction) pamx_list, METH_VARARGS | METH_KEYWORDS,
        "Perform list operation"
    },
    {
        "call", (PyCFunction) pamx_call, METH_VARARGS,
        "Perform call operation"
    },
    {
        "subscribe", (PyCFunction) pamx_subscribe, METH_VARARGS,
        "Perform subscribe operation"
    },
    {
        "close", (PyCFunction) pamx_disconnect, METH_NOARGS,
        "Close the connection."
    },
    {NULL, NULL, 0, NULL}
};
#pragma GCC diagnostic pop

static PyTypeObject PAMXConnectionType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pamx.PAMXConnection",
    .tp_basicsize = sizeof(PAMXConnectionObject),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor) PAMXConnection_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_doc = "pamx connection object",
    .tp_traverse = (traverseproc) object_traverse,
    .tp_methods = connection_methods,
    .tp_getset = Connection_getsetters,
    .tp_init = (initproc) PAMXConnection_init,
    .tp_new = PAMXConnection_new,
};

PyTypeObject* get_pamxConnection_type() {
    return &PAMXConnectionType;
}
