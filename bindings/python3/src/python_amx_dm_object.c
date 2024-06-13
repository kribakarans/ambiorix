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
#include <stdio.h>
#include <string.h>
#include "python_amx.h"
#include "python_amx_connection_object.h"
#include "python_amx_request_object.h"
#include "python_amx_conversion.h"
#include "python_amx_error_conversion.h"
#include "python_amx_dm_param_object.h"
#include "python_amx_dm_method_object.h"
#include "python_amx_dm_mngt_object.h"
#include "python_amx_dm_async_object.h"
#include "python_amx_dm_async_method_object.h"
#include "python_amx_dm_object.h"
#define ME "python_amx_dm_object"


static int
object_traverse(PAMXDMObject* self, visitproc visit, void* arg) {
    Py_VISIT(self->params_dict);
    Py_VISIT(self->functions_dict);
    Py_VISIT(self->mngt);
    Py_VISIT(self->async);
    Py_VISIT(self->sub_list);
    return 0;
}

static int
object_clear(PAMXDMObject* self) {
    Py_CLEAR(self->params_dict);
    Py_CLEAR(self->functions_dict);
    Py_CLEAR(self->async);
    Py_CLEAR(self->mngt);
    Py_CLEAR(self->sub_list);
    return 0;
}

static void
PAMXDM_dealloc(PAMXDMObject* self) {
    object_clear(self);
    free(self->path);
    free(self->type_name);
    PyObject_GC_UnTrack(self);
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static void
create_dm_params(PyObject* params_dict, const char* const path, amxb_bus_ctx_t* bus, amxc_var_t* params) {
    PyObject* key = NULL;
    PyObject* py_readonly = NULL;
    PyObject* py_params = NULL;
    PyObject* value = NULL;
    amxc_var_t* readonly = NULL;
    const amxc_htable_t* var_table = amxc_var_constcast(amxc_htable_t, params);
    amxc_htable_iterate(it, var_table) {
        key = PyUnicode_FromString(amxc_htable_it_get_key(it));
        readonly = amxc_var_get_path(amxc_var_from_htable_it(it), "attributes.read-only", AMXC_VAR_FLAG_DEFAULT);
        py_readonly = variant2python(readonly);
        py_params = Py_BuildValue("ssO", path, amxc_htable_it_get_key(it), py_readonly);
        value = PyObject_CallObject((PyObject*) get_pamxDMParameter_type(), py_params);
        if(value != NULL) {
            ((PAMXDMParamObject*) value)->bus = bus;
            PyDict_SetItem(params_dict, key, value);
            Py_DECREF(value);
        } else {
            amx2pythonerror(-1, "Could not create DM parameter.");
        }
        Py_DECREF(py_params);
        Py_DECREF(key);
        Py_DECREF(py_readonly);
    }
}

static void
create_dm_functions(PyObject* functions_dict, PyObject* mngt_dict, const char* const path, amxb_bus_ctx_t* bus, amxc_var_t* functions) {
    PyObject* params = NULL;
    PyObject* value = NULL;
    amxc_var_t* protected_function = NULL;
    const amxc_htable_t* var_table = amxc_var_constcast(amxc_htable_t, functions);
    amxc_htable_iterate(it, var_table) {
        protected_function = amxc_var_get_path(amxc_var_from_htable_it(it), "attributes.protected", AMXC_VAR_FLAG_DEFAULT);
        params = Py_BuildValue("ss", path, amxc_htable_it_get_key(it));
        value = PyObject_CallObject((PyObject*) get_pamxDMMethod_type(), params);
        if(value != NULL) {
            ((PAMXDMMethodObject*) value)->bus = bus;
            if((amxc_var_get_bool(protected_function) == true) && (strncmp(amxc_htable_it_get_key(it), "_", 1) == 0)) {
                if(strncmp(amxc_htable_it_get_key(it), "_del", 4) == 0) {
                    PyDict_SetItemString(mngt_dict, "delete", value);
                } else {
                    PyDict_SetItemString(mngt_dict, amxc_htable_it_get_key(it) + 1, value);
                }
            } else {
                PyDict_SetItemString(functions_dict, amxc_htable_it_get_key(it), value);
            }
        } else {
            amx2pythonerror(-1, "Could not create DM method.");
        }
        Py_XDECREF(value);
        Py_DECREF(params);
    }
}

static PyObject*
create_async_dm_functions(const char* const path, amxb_bus_ctx_t* bus, amxc_var_t* functions) {
    PyObject* params = NULL;
    PyObject* async_value = NULL;
    PyObject* async_params = NULL;
    PyObject* retval = NULL;
    amxc_var_t* protected_function = NULL;
    const amxc_htable_t* var_table = amxc_var_constcast(amxc_htable_t, functions);
    PyObject* async_methods = PyDict_New();
    PyObject* async_protected_methods = PyDict_New();
    if((async_methods == NULL) || (async_protected_methods == NULL)) {
        amx2pythonerror(-1, "allocation failure.");
        goto exit;
    }

    amxc_htable_iterate(it, var_table) {
        protected_function = amxc_var_get_path(amxc_var_from_htable_it(it), "attributes.protected", AMXC_VAR_FLAG_DEFAULT);
        params = Py_BuildValue("ss", path, amxc_htable_it_get_key(it));
        async_value = PyObject_CallObject((PyObject*) get_pamxDMAsyncMethod_type(), params);
        if(async_value != NULL) {
            ((PAMXDMAsyncMethodObject*) async_value)->bus = bus;
            if(amxc_var_get_bool(protected_function) == true) {
                if(strncmp(amxc_htable_it_get_key(it), "_", 1) == 0) {
                    if(strncmp(amxc_htable_it_get_key(it), "_del", 4) == 0) {
                        PyDict_SetItemString(async_protected_methods, "delete", async_value);
                    } else {
                        PyDict_SetItemString(async_protected_methods, amxc_htable_it_get_key(it) + 1, async_value);
                    }
                } else {
                    PyDict_SetItemString(async_protected_methods, amxc_htable_it_get_key(it), async_value);
                }
            } else {
                PyDict_SetItemString(async_methods, amxc_htable_it_get_key(it), async_value);
            }
            Py_DECREF(async_value);
        } else {
            amx2pythonerror(-1, "Could not create DM method.");
        }
        Py_DECREF(params);

    }
    async_params = Py_BuildValue("OO", async_methods, async_protected_methods);
    Py_DECREF(async_methods);
    Py_DECREF(async_protected_methods);
    retval = PyObject_CallObject((PyObject*) get_pamxDMAsync_type(), async_params);
    if(retval == NULL) {
        amx2pythonerror(-1, "Could not create async_methods.");
    }
    Py_DECREF(async_params);

exit:
    return retval;
}

static bool
is_valid_object_path(const char* path) {
    char ch = '.';
    char* end = NULL;
    bool retval = false;

    end = strrchr((char*) path, ch);
    if(end == NULL) {
        goto exit;
    }

    if(strlen(end) != 1) {
        goto exit;
    }

    retval = true;
exit:
    return retval;
}

static PyObject*
PAMXDM_new(PyTypeObject* type, PyObject* args, UNUSED PyObject* kwds) {
    PAMXDMObject* self = (PAMXDMObject*) type->tp_alloc(type, 0);
    const char* path = NULL;
    char* object_path = NULL;
    int describe = -1;
    amxc_var_t* object = NULL;
    amxc_var_t* params = NULL;
    amxc_var_t* functions = NULL;
    amxb_bus_ctx_t* bus = NULL;
    PyObject* mngt_dict = NULL;
    PyObject* mngt_params = NULL;
    PyObject* result = NULL;
    amxc_var_t retval;
    amxc_var_init(&retval);
    self->path = NULL;
    self->type_name = NULL;
    amxc_var_t* type_name_var = NULL;
    amxc_var_t* index_var = NULL;
    amxc_var_t* object_path_var = NULL;
    amxc_string_t path_string;
    PAMXConnectionObject* pyConnection = NULL;

    amxc_string_init(&path_string, 0);

    if(self == NULL) {
        amx2pythonerror(-1, "tp_alloc failure.");
        goto exit;
    }

    if(PyArg_ParseTuple(args, "s|O!", &path, get_pamxConnection_type(), &pyConnection) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    if(is_valid_object_path(path) == false) {
        amx2pythonerror(-1, "Given path is an invalid object path.");
        goto exit;
    }

    // Check if a PAMXConnectionObject was passed and is of the correct type
    if(pyConnection && PyObject_TypeCheck(pyConnection, get_pamxConnection_type())) {
        bus = pyConnection->bus_ctx; // Access the bus_ctx from the PAMXConnectionObject
    } else {
        bus = amxb_be_who_has(path);
    }

    if(bus == NULL) {
        amx2pythonerror(-1, "Could not find provided path.");
        goto exit;
    }

    self->bus = bus;

    describe = amxb_describe(bus, path, AMXB_FLAG_FUNCTIONS | AMXB_FLAG_PARAMETERS, &retval, 5);
    if(describe != 0) {
        amx2pythonerror(describe, "Could not perform describe");
        goto exit;
    }

    object = amxc_var_get_index(&retval, 0, AMXC_VAR_FLAG_DEFAULT);
    type_name_var = amxc_var_get_path(object, "type_name", AMXC_VAR_FLAG_DEFAULT);
    self->type_name = amxc_var_dyncast(cstring_t, type_name_var);

    object_path_var = amxc_var_get_path(object, "path", AMXC_VAR_FLAG_DEFAULT);
    object_path = amxc_var_dyncast(cstring_t, object_path_var);
    if(strcmp(self->type_name, "instance") == 0) {
        index_var = amxc_var_get_path(object, "index", AMXC_VAR_FLAG_DEFAULT);
        self->index = amxc_var_dyncast(uint32_t, index_var);
        amxc_string_appendf(&path_string, "%s%u.", object_path, self->index);
        self->path = amxc_string_take_buffer(&path_string);
    } else {
        self->path = strdup(object_path);
    }

    self->params_dict = PyDict_New();
    if(self->params_dict == NULL) {
        amx2pythonerror(-1, "Could not create parameter dict");
        goto exit;
    }

    self->functions_dict = PyDict_New();
    if(self->functions_dict == NULL) {
        amx2pythonerror(-1, "Could not create function dict");
        goto exit;
    }

    self->sub_list = PyList_New(0);
    if(self->sub_list == NULL) {

        amx2pythonerror(-1, "Could not create subscription list.");
        goto exit;
    }

    mngt_dict = PyDict_New();
    if(mngt_dict == NULL) {
        amx2pythonerror(-1, "Could not create mngt dict.");
        goto exit;
    }

    params = amxc_var_get_key(object, "parameters", AMXC_VAR_FLAG_DEFAULT);
    functions = amxc_var_get_key(object, "functions", AMXC_VAR_FLAG_DEFAULT);
    if(strncmp(self->type_name, "template", 8) != 0) {
        create_dm_params(self->params_dict, self->path, self->bus, params);
    }
    create_dm_functions(self->functions_dict, mngt_dict, self->path, self->bus, functions);
    self->async = create_async_dm_functions(self->path, self->bus, functions);
    mngt_params = Py_BuildValue("OO", (PyObject*) self, mngt_dict);
    self->mngt = PyObject_CallObject((PyObject*) get_pamxDMMNGT_type(), mngt_params);
    Py_DECREF(mngt_params);
    Py_DECREF((PyObject*) self);
    Py_DECREF(mngt_dict);

    if(PyErr_Occurred() != NULL) {
        amx2pythonerror(-1, "Could not create async_methods.");
        goto exit;
    }

    result = (PyObject*) self;

exit:
    free(object_path);
    amxc_string_clean(&path_string);
    if(PyErr_Occurred() != NULL) {
        if(self != NULL) {
            free(self->path);
            Py_XDECREF(self->params_dict);
            Py_XDECREF(self->functions_dict);
            Py_XDECREF(self->sub_list);
            Py_XDECREF(self->async);
            Py_TYPE(self)->tp_free((PyObject*) self);
        }
    }
    amxc_var_clean(&retval);
    return result;
}

static int
PAMXDM_init(UNUSED PyObject* self, UNUSED PyObject* args, UNUSED PyObject* kwds) {
    return 0;
}

static PyObject* object_getattro(PyObject* self, PyObject* attr_obj) {
    PyObject* dict = ((PAMXDMObject*) self)->params_dict;
    PyObject* retval = NULL;
    PyObject* key = NULL;
    PyObject* value = NULL;
    PyObject* param_value = NULL;
    Py_ssize_t pos = 0;
    if(PyDict_Contains(dict, attr_obj) == 1) {
        PyObject* param = PyDict_GetItem(dict, attr_obj);
        retval = PyObject_CallMethod(param, "__get__", "O", self);
        goto exit;
    }

    dict = ((PAMXDMObject*) self)->functions_dict;
    if(PyDict_Contains(dict, attr_obj) == 1) {
        retval = PyDict_GetItem(dict, attr_obj);
        Py_INCREF(retval);
        goto exit;
    }

    if(strncmp(PyUnicode_AsUTF8(attr_obj), "__dict__", 8) == 0) {
        retval = PyDict_Copy(((PAMXDMObject*) self)->params_dict);
        if(retval == NULL) {
            goto exit;
        }
        while(PyDict_Next(retval, &pos, &key, &value)) {
            param_value = PyObject_CallMethod(value, "__get__", "O", self);
            if(param_value == NULL) {
                goto exit;
            }
            PyDict_SetItemString(retval, PyUnicode_AsUTF8(key), param_value);
            Py_DECREF(param_value);
        }
        PyDict_Merge(retval, ((PAMXDMObject*) self)->functions_dict, 0);
        goto exit;
    }

    retval = PyObject_GenericGetAttr(self, attr_obj);

exit:
    return retval;
}

int object_setattro(PyObject* self, PyObject* attr_obj, PyObject* v) {
    int retval = -1;
    PyObject* dict = ((PAMXDMObject*) self)->params_dict;
    if(PyDict_Contains(dict, attr_obj) == 1) {
        PyObject* param = PyDict_GetItem(dict, attr_obj);
        if(PyObject_CallMethod(param, "__set__", "OO", self, v) != NULL) {
            retval = 0;
            goto exit;
        } else {
            retval = -1;
            goto exit;
        }
    }

    if(PyObject_GenericSetAttr(self, attr_obj, v) == 0) {
        retval = 0;
        goto exit;
    } else {
        retval = -1;
        goto exit;
    }

exit:
    return retval;
}

static PyObject*
DMObject_getAsync(PAMXDMObject* self, UNUSED void* closure) {
    PyObject* retval = self->async;
    Py_INCREF(retval);
    return retval;
}

static int
DMObject_setAsync(UNUSED PAMXDMObject* self, UNUSED PyObject* value, UNUSED void* closure) {
    PyErr_SetString(PyExc_TypeError, "Cannot manually set async.");
    return -1;
}

static PyObject*
DMObject_getMNGT(PAMXDMObject* self, UNUSED void* closure) {
    PyObject* retval = self->mngt;
    Py_INCREF(retval);
    return retval;
}

static int
DMObject_setMNGT(UNUSED PAMXDMObject* self, UNUSED PyObject* value, UNUSED void* closure) {
    PyErr_SetString(PyExc_TypeError, "Cannot manually set dmmngt.");
    return -1;
}

static PyGetSetDef DMObject_getsetters[] = {
    {"async_methods", (getter) DMObject_getAsync, (setter) DMObject_setAsync,
        "async methods", NULL},
    {"dmmngt", (getter) DMObject_getMNGT, (setter) DMObject_setMNGT,
        "async methods", NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject PAMXDMType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pamx.DMObject",
    .tp_basicsize = sizeof(PAMXDMObject),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor) PAMXDM_dealloc,
    .tp_getattro = object_getattro,
    .tp_setattro = object_setattro,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_doc = "pamx dm object",
    .tp_traverse = (traverseproc) object_traverse,
    .tp_getset = DMObject_getsetters,
    .tp_init = (initproc) PAMXDM_init,
    .tp_new = PAMXDM_new,
};

PyTypeObject* get_pamxDMObject_type() {
    return &PAMXDMType;
}
