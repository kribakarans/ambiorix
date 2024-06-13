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


#ifndef __PYTHON_AMX_H__
#define __PYTHON_AMX_H__

#ifdef __cplusplus
extern "C"
{
#endif
#include "Python.h"
#include <stdbool.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxd/amxd_dm.h>
#include <amxb/amxb.h>

#include <event2/event.h>

#define EXIT(rv, code, label) rv = code; goto label;
#define WHEN_FAILED(x, rv, label) rv = x; if(rv != 0) {goto label;}
#define UNUSED __attribute__((unused))

#define SAHTRACES_ENABLED

typedef struct _list_data {
    PyObject* function;
    PyObject* data;
    amxc_llist_it_t ll_it;
} list_data_t;

typedef struct _sub_data {
    PyObject* function;
    PyObject* data;
} data_t;

typedef struct _pamx {
    PyObject_HEAD
    PyObject* con_list;
} PAMXBUSObject;

typedef struct _pamx_backend {
    PyObject_HEAD
} PAMXBACKENDObject;

typedef struct _pamx_eventloop {
    PyObject_HEAD
} PAMXEVENTLOOPObject;

typedef struct _pamx_dmparameter {
    PyObject_HEAD
    char* name;
    char* path;
    bool readonly;
    amxb_bus_ctx_t* bus;
} PAMXDMParamObject;

typedef struct _pamx_dmmethod {
    PyObject_HEAD
    char* name;
    char* path;
    amxb_bus_ctx_t* bus;
} PAMXDMMethodObject;

typedef struct _pamx_dmasyncmethod {
    PyObject_HEAD
    char* name;
    char* path;
    PyObject* req_list;
    amxb_bus_ctx_t* bus;
} PAMXDMAsyncMethodObject;

typedef struct _pamx_dmasync {
    PyObject_HEAD
    PyObject* dict;
    PyObject* protected_obj;
} PAMXDMAsyncObject;

typedef struct _pamx_dmprotected {
    PyObject_HEAD
    PyObject* dict;
} PAMXDMProtectedObject;

typedef struct _pamx_dmmngt {
    PyObject_HEAD
    PyObject* dm_object;
    PyObject* dict;
} PAMXDMMNGTObject;

typedef struct _pamx_dmobject {
    PyObject_HEAD
    PyObject* params_dict;
    PyObject* functions_dict;
    PyObject* async;
    PyObject* mngt;
    char* path;
    char* type_name;
    uint32_t index;
    PyObject* sub_list;
    amxb_bus_ctx_t* bus;
} PAMXDMObject;

typedef struct {
    PyObject_HEAD
    char* uri;
    amxb_bus_ctx_t* bus_ctx;
    struct event* el_data;
    PyObject* sub_list;
    PyObject* req_list;
    amxc_llist_t* list_cb_list;
    int32_t access_level;
    bool closed;
} PAMXConnectionObject;

typedef struct {
    PyObject_HEAD
    amxb_request_t* request;
    data_t* data;
    bool closed;
} PAMXRequestObject;

typedef struct {
    PyObject_HEAD
    char* path;
    data_t* data;
    amxb_bus_ctx_t* bus;
    bool closed;
} PAMXSubObject;

typedef struct _pamx_timer {
    PyObject_HEAD
    amxp_timer_t* timer;
    uint64_t interval;
    PyObject* timer_func;
    PyObject* timer_data;
} pamx_timer_t;

PyObject* get_python_amx(void);

PyObject* get_python_amx_error(void);

amxc_var_t* get_access_levels(void);

void free_access_levels(void);

void set_python_amx(PyObject* value);

list_data_t* init_list_data(PyObject* function, PyObject* userdata);

void delete_list_data(amxc_llist_it_t* lit);

data_t* init_data(PyObject* function, PyObject* userdata);

void free_data(data_t* sub_data);

void transform_kwlist(char* kwlist[], const char* literals[]);

#ifdef __cplusplus
}
#endif

#endif // __PYTHON_AMX_H__
