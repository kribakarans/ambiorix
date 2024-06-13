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
#include "python_amx_backend_singleton.h"
#include "python_amx_eventloop_singleton.h"
#include "python_amx_connection_object.h"
#include "python_amx_dm_param_object.h"
#include "python_amx_dm_method_object.h"
#include "python_amx_dm_async_method_object.h"
#include "python_amx_dm_async_object.h"
#include "python_amx_dm_mngt_object.h"
#include "python_amx_dm_object.h"
#include "python_amx_dm_protected_object.h"
#include "python_amx_request_object.h"
#include "python_amx_subscription_object.h"
#include "python_amx_timer.h"

#define ME "python_amx"

static PyObject* python_amx = NULL;
static PyObject* python_amx_error = NULL;

static amxc_var_t access_levels;

PyObject* get_python_amx() {
    return python_amx;
}

void set_python_amx(PyObject* value) {
    python_amx = value;
}

PyObject* get_python_amx_error() {
    return python_amx_error;
}

list_data_t* init_list_data(PyObject* function, PyObject* userdata) {
    list_data_t* d = (list_data_t*) calloc(1, sizeof(list_data_t));

    if(d != NULL) {
        d->function = function;
        Py_XINCREF(d->function);

        d->data = userdata;
        Py_XINCREF(d->data);
    }


    return d;
}

void delete_list_data(amxc_llist_it_t* lit) {
    if(lit != NULL) {
        list_data_t* d = amxc_container_of(lit, list_data_t, ll_it);
        Py_XDECREF(d->function);
        Py_XDECREF(d->data);
        free(d);
    }
}

data_t* init_data(PyObject* function, PyObject* userdata) {
    data_t* d = (data_t*) calloc(1, sizeof(data_t));

    if(d != NULL) {
        d->function = function;
        Py_XINCREF(d->function);

        d->data = userdata;
        Py_XINCREF(d->data);
    }
    return d;
}

void free_data(data_t* data) {
    if(data != NULL) {
        Py_XDECREF(data->function);
        Py_XDECREF(data->data);
        free(data);
    }
}

amxc_var_t* get_access_levels(void) {
    return &access_levels;
}

void free_access_levels(void) {
    amxc_var_clean(&access_levels);
}

void transform_kwlist(char* kwlist[], const char* literals[]) {
    int i = 0;
    for(i = 0; literals[i] != NULL; i++) {
        kwlist[i] = (char*) literals[i];
    }
    kwlist[i] = NULL;
}


static PyModuleDef pamxmodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "pamx",
    .m_doc = "AMX Python bindings modules.",
    .m_size = -1,
};

typedef PyTypeObject* (* get_pamx_type_t) (void);

get_pamx_type_t types[] = {
    get_pamx_bus_type, get_pamx_backend_type, get_pamx_eventloop_type, get_pamx_timer_type,
    get_pamxConnection_type, get_pamxRequest_type, get_pamxSub_type, get_pamxDMParameter_type,
    get_pamxDMMethod_type, get_pamxDMAsyncMethod_type, get_pamxDMAsync_type, get_pamxDMObject_type,
    get_pamxDMMNGT_type, get_pamxDMProtected_type
};


PyMODINIT_FUNC
PyInit_pamx(void) {
    PyObject* bus = NULL;
    PyObject* backend = NULL;
    PyObject* eventloop = NULL;
    PyObject* m = NULL;
    PyObject* error_dict = PyDict_New();

    for(int i = 0; i < (int) (sizeof(types) / sizeof(types[0])); i++) {
        if(PyType_Ready(types[i]()) < 0) {
            return NULL;
        }
    }

    m = PyModule_Create(&pamxmodule);
    if(m == NULL) {
        return NULL;
    }

    amxc_var_init(&access_levels);
    amxc_var_set_type(&access_levels, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(int32_t, &access_levels, "public", AMXB_PUBLIC);
    amxc_var_add_key(int32_t, &access_levels, "protected", AMXB_PROTECTED);

    PyDict_SetItemString(error_dict, "code", Py_None);
    python_amx_error = PyErr_NewException("pamx.AMXError", PyExc_RuntimeError, error_dict);

    Py_INCREF(get_python_amx_error());
    PyModule_AddObject(m, "AMXError", (PyObject*) get_python_amx_error());

    bus = PyObject_CallObject((PyObject*) get_pamx_bus_type(), NULL);
    PyModule_AddObject(m, "bus", (PyObject*) bus);

    backend = PyObject_CallObject((PyObject*) get_pamx_backend_type(), NULL);
    PyModule_AddObject(m, "backend", (PyObject*) backend);

    eventloop = PyObject_CallObject((PyObject*) get_pamx_eventloop_type(), NULL);
    PyModule_AddObject(m, "eventloop", (PyObject*) eventloop);

    PyModule_AddObject(m, "Timer", (PyObject*) get_pamx_timer_type());

    PyModule_AddObject(m, "DMObject", (PyObject*) get_pamxDMObject_type());

    return m;
}