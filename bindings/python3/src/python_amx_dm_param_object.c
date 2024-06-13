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
#include "python_amx_dm_param_object.h"

#define ME "python_amx_dm_param_object"

static void
PAMXDMParam_dealloc(PAMXDMParamObject* self) {
    free(self->name);
    free(self->path);
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject*
PAMXDMParam_new(PyTypeObject* type, PyObject* args, UNUSED PyObject* kwds) {
    PAMXDMParamObject* self = NULL;
    const char* path = NULL;
    const char* name = NULL;
    int readonly = 0;

    self = (PAMXDMParamObject*) type->tp_alloc(type, 0);
    if(self == NULL) {
        amx2pythonerror(-1, "tp_alloc failure.");
        goto exit;
    }

    if(PyArg_ParseTuple(args, "ssp", &path, &name, &readonly) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    self->path = strdup(path);
    self->name = strdup(name);
    self->readonly = readonly;

    return (PyObject*) self;
exit:
    if(self != NULL) {
        Py_TYPE(self)->tp_free((PyObject*) self);
    }
    return NULL;
}

static int
PAMXDMParam_init(UNUSED PyObject* self, UNUSED PyObject* args, UNUSED PyObject* kwds) {
    return 0;
}

static PyObject* param_get(PyObject* self, UNUSED PyObject* obj, UNUSED PyObject* type) {
    int get_retval = -1;
    PyObject* retval = NULL;
    amxc_var_t* param = NULL;
    amxc_string_t full_path;
    amxc_var_t retrieved;
    amxc_var_init(&retrieved);
    if(amxc_string_init(&full_path, 0) != 0) {
        amx2pythonerror(-1, "Could not allocate string.");
        goto exit;
    }

    amxc_string_appendf(&full_path, "%s%s", ((PAMXDMParamObject*) self)->path, ((PAMXDMParamObject*) self)->name);

    get_retval = amxb_get(((PAMXDMParamObject*) self)->bus, amxc_string_get(&full_path, 0), 0, &retrieved, 5);
    if(get_retval != 0) {
        amx2pythonerror(get_retval, "Could not perform get");
        goto exit;
    }

    param = amxc_var_get_pathf(&retrieved, AMXC_VAR_FLAG_DEFAULT, "0.'%s'.'%s'",
                               ((PAMXDMParamObject*) self)->path, ((PAMXDMParamObject*) self)->name);

    retval = variant2python(param);

exit:
    amxc_string_clean(&full_path);
    amxc_var_clean(&retrieved);
    return retval;
}

static int param_set(PyObject* self, UNUSED PyObject* obj, PyObject* value) {
    int retval = -1;
    amxc_var_t set;
    amxc_var_t params;
    amxc_var_t* subvar = NULL;
    amxc_var_init(&set);
    amxc_var_init(&params);
    amxc_var_set_type(&params, AMXC_VAR_ID_HTABLE);

    if(((PAMXDMParamObject*) self)->readonly == true) {
        amx2pythonerror(retval, "Parameter is readonly");
        goto exit;
    }

    subvar = amxc_var_add_new_key(&params, ((PAMXDMParamObject*) self)->name);
    python2variant(value, subvar);

    retval = amxb_set(((PAMXDMParamObject*) self)->bus, ((PAMXDMParamObject*) self)->path, &params, &set, 5);
    if(retval != 0) {
        amx2pythonerror(retval, "Could not perform set");
        retval = -1;
        goto exit;
    }

exit:
    amxc_var_clean(&params);
    amxc_var_clean(&set);
    return retval;
}

static PyMethodDef PAMXDMParam_methods[] = {
    {NULL, NULL, 0, NULL}
};

static PyTypeObject PAMXDMParamType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pamx.DMParameter",
    .tp_basicsize = sizeof(PAMXDMParamObject),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor) PAMXDMParam_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "pamx dm parameter object",
    .tp_methods = PAMXDMParam_methods,
    .tp_descr_get = (descrgetfunc) param_get,
    .tp_descr_set = (descrsetfunc) param_set,
    .tp_init = (initproc) PAMXDMParam_init,
    .tp_new = PAMXDMParam_new,
};

PyTypeObject* get_pamxDMParameter_type() {
    return &PAMXDMParamType;
}
