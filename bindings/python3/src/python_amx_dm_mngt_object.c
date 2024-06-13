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
#include "python_amx_connection_object.h"
#include "python_amx_request_object.h"
#include "python_amx_dm_object.h"
#include "python_amx_dm_mngt_object.h"
#include "python_amx_subscription_object.h"


#define ME "python_amx_dm_mngt_object"

static int
object_traverse(PAMXDMMNGTObject* self, visitproc visit, void* arg) {
    Py_VISIT(self->dm_object);
    Py_VISIT(self->dict);
    return 0;
}

static void
PAMXDMMNGT_dealloc(PAMXDMMNGTObject* self) {
    Py_CLEAR(self->dict);
    Py_CLEAR(self->dm_object);
    PyObject_GC_UnTrack(self);
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject*
PAMXDMMNGT_new(PyTypeObject* type, PyObject* args, UNUSED PyObject* kwds) {
    PAMXDMMNGTObject* self = (PAMXDMMNGTObject*) type->tp_alloc(type, 0);
    PyObject* dict = NULL;
    PyObject* dm_object = NULL;
    if(self == NULL) {
        amx2pythonerror(-1, "tp_alloc failure.");
        goto exit;
    }
    if(PyArg_ParseTuple(args, "O!O!", get_pamxDMObject_type(), &dm_object, &PyDict_Type, &dict) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    self->dm_object = dm_object;
    Py_INCREF(self->dm_object);
    self->dict = dict;
    Py_INCREF(self->dict);
    return (PyObject*) self;

exit:
    if(self != NULL) {
        Py_XDECREF(self->dm_object);
        Py_XDECREF(self->dict);
        Py_TYPE(self)->tp_free((PyObject*) self);
    }
    return NULL;
}

static int
PAMXDMMNGT_init(UNUSED PyObject* self, UNUSED PyObject* args, UNUSED PyObject* kwds) {
    return 0;
}

static PyObject* object_getattro(PyObject* self, PyObject* attr_obj) {
    PyObject* dict = ((PAMXDMMNGTObject*) self)->dict;
    PyObject* retval = NULL;
    if(PyDict_Contains(dict, attr_obj) == 1) {
        retval = PyDict_GetItem(dict, attr_obj);
        Py_INCREF(retval);
        goto exit;
    }

    if(strncmp(PyUnicode_AsUTF8(attr_obj), "__dict__", 8) == 0) {
        retval = PyDict_Copy(((PAMXDMMNGTObject*) self)->dict);
        goto exit;
    }

    retval = PyObject_GenericGetAttr(self, attr_obj);

exit:
    return retval;
}

static PyObject*
object_subscribe(PyObject* self, PyObject* args) {
    const char* expression = NULL;
    PyObject* function = NULL;
    PyObject* data = NULL;
    PyObject* retval = NULL;
    PyObject* dm_object = (((PAMXDMMNGTObject*) self)->dm_object);
    data_t* d = NULL;
    char* path = (((PAMXDMObject*) dm_object)->path);
    int call_retval = -1;
    if(PyArg_ParseTuple(args, "sO|O", &expression, &function, &data) == 0) {
        amx2pythonerror(-1, "Incorrect parameters.");
        goto exit;
    }

    if(PyCallable_Check(function) == 0) {
        PyErr_SetString(PyExc_TypeError, "event callback is not callable.");
        goto exit;
    }

    d = init_data(function, data);
    if(d == NULL) {
        amx2pythonerror(-1, "Failed to initialize user data");
        goto exit;
    }

    call_retval = amxb_subscribe(((PAMXDMObject*) dm_object)->bus, path, expression, notify_handler, d);
    if(call_retval != 0) {
        amx2pythonerror(call_retval, "Could not perform subscribe");
        goto exit;
    }

    retval = PyObject_CallObject((PyObject*) get_pamxSub_type(), NULL);
    if(retval == NULL) {
        amx2pythonerror(-1, "Failed to create subscription.");
        goto exit;
    }

    ((PAMXSubObject*) retval)->bus = ((PAMXDMObject*) dm_object)->bus;
    ((PAMXSubObject*) retval)->path = strdup(path);
    ((PAMXSubObject*) retval)->data = d;
    PyList_Append(((PAMXDMObject*) dm_object)->sub_list, retval);

exit:
    if(PyErr_Occurred() != NULL) {
        free_data(d);
        d = NULL;
        Py_XDECREF(retval);
    }

    return retval;
}

static void
fill_object_dict(const PAMXDMObject* dm_object, PyObject* dict, amxc_var_t* objects) {
    amxc_string_t full_path;
    PyObject* params = NULL;
    PyObject* py_instance = NULL;
    char* object_string = NULL;
    int describe = -1;
    amxc_var_t desc;
    amxc_var_t* desc_object = NULL;
    amxc_var_t* obj_name = NULL;
    char* name_string = NULL;
    amxc_var_for_each(object, objects) {
        if(amxc_string_init(&full_path, 0) != 0) {
            amx2pythonerror(-1, "Could not allocate string.");
            goto exit;
        }
        object_string = amxc_var_dyncast(cstring_t, object);
        amxc_var_init(&desc);
        amxc_string_appendf(&full_path, "%s%s.", dm_object->path, object_string);
        describe = amxb_describe(dm_object->bus, amxc_string_get(&full_path, 0), 0, &desc, 5);
        if(describe != 0) {
            amx2pythonerror(describe, "Could not perform describe");
            goto exit;
        }

        desc_object = amxc_var_get_index(&desc, 0, AMXC_VAR_FLAG_DEFAULT);
        obj_name = amxc_var_get_path(desc_object, "name", AMXC_VAR_FLAG_DEFAULT);
        name_string = amxc_var_dyncast(cstring_t, obj_name);

        params = Py_BuildValue("(s)", amxc_string_get(&full_path, 0));
        py_instance = PyObject_CallObject((PyObject*) get_pamxDMObject_type(), params);
        Py_DECREF(params);
        PyDict_SetItemString(dict, name_string, py_instance);
        Py_DECREF(py_instance);
        amxc_string_clean(&full_path);
        free(object_string);
        free(name_string);
        amxc_var_clean(&desc);

    }

exit:
    return;

}

static PyObject*
object_instances(PyObject* self, UNUSED PyObject* args) {
    int describe = -1;
    PyObject* dm_object = (((PAMXDMMNGTObject*) self)->dm_object);
    PyObject* retval = PyDict_New();
    amxc_var_t* instances = NULL;
    amxc_var_t desc;
    amxc_var_init(&desc);
    amxc_var_t* object = NULL;
    if(retval == NULL) {
        amx2pythonerror(-1, "Cannot allocate PyDict");
        goto exit;
    }
    if(strncmp(((PAMXDMObject*) dm_object)->type_name, "template", 8) != 0) {
        Py_DECREF(retval);
        amxc_var_clean(&desc);
        Py_RETURN_NONE;
    }

    describe = amxb_describe(((PAMXDMObject*) dm_object)->bus, ((PAMXDMObject*) dm_object)->path, AMXB_FLAG_INSTANCES, &desc, 5);
    if(describe != 0) {
        amx2pythonerror(describe, "Could not perform describe");
        goto exit;
    }

    object = amxc_var_get_index(&desc, 0, AMXC_VAR_FLAG_DEFAULT);
    instances = amxc_var_get_path(object, "instances", AMXC_VAR_FLAG_DEFAULT);
    fill_object_dict(((PAMXDMObject*) dm_object), retval, instances);

exit:
    amxc_var_clean(&desc);
    return retval;

}


static PyObject*
object_subobjects(PyObject* self, UNUSED PyObject* args) {
    int describe = -1;
    PyObject* dm_object = (((PAMXDMMNGTObject*) self)->dm_object);
    PyObject* retval = PyDict_New();
    amxc_var_t* subobjects = NULL;
    amxc_var_t desc;
    amxc_var_init(&desc);
    amxc_var_t* object = NULL;
    if(retval == NULL) {
        amx2pythonerror(-1, "Cannot allocate PyDict");
        goto exit;
    }

    describe = amxb_describe(((PAMXDMObject*) dm_object)->bus, ((PAMXDMObject*) dm_object)->path, AMXB_FLAG_OBJECTS, &desc, 5);
    if(describe != 0) {
        amx2pythonerror(describe, "Could not perform describe");
        goto exit;
    }

    object = amxc_var_get_index(&desc, 0, AMXC_VAR_FLAG_DEFAULT);
    subobjects = amxc_var_get_path(object, "objects", AMXC_VAR_FLAG_DEFAULT);
    fill_object_dict(((PAMXDMObject*) dm_object), retval, subobjects);

exit:
    amxc_var_clean(&desc);
    return retval;
}

static PyObject*
DMMNGT_getType(PAMXDMMNGTObject* self, UNUSED void* closure) {
    PyObject* dm_object = (((PAMXDMMNGTObject*) self)->dm_object);
    PyObject* retval = PyUnicode_FromString(((PAMXDMObject*) dm_object)->type_name);
    return retval;
}

static int
DMMNGT_setType(UNUSED PAMXDMMNGTObject* self, UNUSED PyObject* value, UNUSED void* closure) {
    PyErr_SetString(PyExc_TypeError, "Cannot manually set type_name.");
    return -1;
}


static PyGetSetDef PAMXDMMNGT_getsetters[] = {
    {"type_name", (getter) DMMNGT_getType, (setter) DMMNGT_setType,
        "type_name", NULL},
    {NULL}  /* Sentinel */
};

static PyMethodDef PAMXDMMNGT_methods[] = {
    {
        "subscribe", (PyCFunction) object_subscribe, METH_VARARGS, NULL
    },
    {
        "instances", (PyCFunction) object_instances, METH_NOARGS, NULL
    },
    {
        "objects", (PyCFunction) object_subobjects, METH_NOARGS, NULL
    },
    {NULL, NULL, 0, NULL}
};

static PyTypeObject PAMXDMMNGTType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pamx.DMMNGT",
    .tp_basicsize = sizeof(PAMXDMMNGTObject),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor) PAMXDMMNGT_dealloc,
    .tp_getattro = object_getattro,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_doc = "pamx dmmngt object",
    .tp_traverse = (traverseproc) object_traverse,
    .tp_methods = PAMXDMMNGT_methods,
    .tp_getset = PAMXDMMNGT_getsetters,
    .tp_init = (initproc) PAMXDMMNGT_init,
    .tp_new = PAMXDMMNGT_new,
};

PyTypeObject* get_pamxDMMNGT_type() {
    return &PAMXDMMNGTType;
}
