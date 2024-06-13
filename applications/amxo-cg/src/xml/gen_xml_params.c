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

#include "gen_xml.h"

static xmlNodePtr gen_xml_search_param(amxd_object_t* object, const char* name) {
    xmlNodePtr param = NULL;
    char* path = NULL;
    xml_gen_t* xml_ctx = gen_xml_get_ctx();

    path = amxd_object_get_path(object, AMXD_OBJECT_SUPPORTED);
    param = gen_xml_find(xml_ctx->doc, path, name);
    free(path);

    if(param != NULL) {
        goto exit;
    }

    path = amxd_object_get_path(object, AMXD_OBJECT_INDEXED);
    param = gen_xml_find(xml_ctx->doc, path, name);
    free(path);

exit:
    return param;
}

static bool gen_xml_skip_protected_param(amxo_parser_t* parser, uint64_t pattr_bitmask) {
    bool retval = false;
    amxc_var_t* amxo_cg = amxo_parser_get_config(parser, "amxo-cg");
    bool skip_protected = GET_BOOL(amxo_cg, "skip-protected");

    if(IS_BIT_SET(pattr_bitmask, amxd_pattr_protected) && skip_protected) {
        retval = true;
    }

    return retval;
}

void gen_xml_parameter_start(amxo_parser_t* parser,
                             amxd_object_t* object,
                             const char* name,
                             int64_t attr_bitmask,
                             uint32_t type) {

    const char* attr_names[] = {
        "multi-instance", "instance", "private", "read-only", "persistent",
        "volatile", "instance-counter", "key", "unique", "protected", "mutable"
    };
    xml_gen_t* xml_ctx = gen_xml_get_ctx();
    amxc_string_t* full_path = gen_xml_compute_full_path(object, name, NULL);

    when_true(gen_xml_skip_protected_param(parser, attr_bitmask), exit);

    gen_xml_translate_path(parser, full_path, NULL);

    xml_ctx->xml_param = gen_xml_search_param(object, name);

    if(xml_ctx->xml_param == NULL) {
        xml_ctx->xml_param = xmlNewNode(xml_ctx->ns, BAD_CAST "parameter");
        xmlSetNsProp(xml_ctx->xml_param, xml_ctx->ns,
                     BAD_CAST "name", BAD_CAST name);
        xmlSetNsProp(xml_ctx->xml_param, xml_ctx->ns,
                     BAD_CAST "path", BAD_CAST amxc_string_get(full_path, 0));
        xmlSetNsProp(xml_ctx->xml_param, xml_ctx->ns,
                     BAD_CAST "type", BAD_CAST gen_xml_odl_type(type));
        gen_xml_attributes(xml_ctx->xml_param, attr_bitmask,
                           amxd_pattr_max, attr_names);
        xmlAddChild(xml_ctx->xml_object, xml_ctx->xml_param);
        gen_xml_add_defined(parser, xml_ctx->xml_param);

        gen_xml_add_description(xml_ctx->xml_param);
        gen_xml_add_version(xml_ctx->xml_param);
    }

exit:
    amxc_string_delete(&full_path);
}

void gen_xml_parameter_set(amxo_parser_t* parser,
                           amxd_object_t* object,
                           amxd_param_t* param,
                           amxc_var_t* value) {
    xmlNodePtr xml_value = NULL;
    xmlNodePtr content = NULL;
    char* data = amxc_var_dyncast(cstring_t, value);
    xml_gen_t* xml_ctx = gen_xml_get_ctx();

    when_true(gen_xml_skip_protected_param(parser, amxd_param_get_attrs(param)), exit);

    if(xml_ctx->xml_param == NULL) {
        gen_xml_parameter_start(parser,
                                object,
                                amxd_param_get_name(param),
                                amxd_param_get_attrs(param),
                                amxd_param_get_type(param));
    }
    when_null(xml_ctx->xml_param, exit);

    gen_xml_add_defined(parser, xml_ctx->xml_param);

    xml_value = gen_xml_find_node(xml_ctx->xml_param, "default");
    if(xml_value != NULL) {
        xmlUnlinkNode(xml_value);
        xmlFreeNode(xml_value);
    }
    xml_value = xmlNewNode(xml_ctx->ns, BAD_CAST "default");
    if(data != NULL) {
        content = xmlNewCDataBlock(xml_ctx->doc, BAD_CAST data, strlen(data));
        xmlAddChild(xml_value, content);
    }
    xmlAddChild(xml_ctx->xml_param, xml_value);

exit:
    free(data);
}

void gen_xml_parameter_constraint(amxo_parser_t* parser,
                                  UNUSED amxd_object_t* object,
                                  amxd_param_t* param,
                                  const char* name,
                                  const amxc_var_t* data) {
    xmlNodePtr xml_constraint = NULL;
    xml_gen_t* xml_ctx = gen_xml_get_ctx();

    when_null(xml_ctx->xml_param, exit);
    when_true(gen_xml_skip_protected_param(parser, amxd_param_get_attrs(param)), exit);

    xml_constraint = xmlNewNode(xml_ctx->ns, BAD_CAST "constraint");
    xmlSetNsProp(xml_constraint, xml_ctx->ns, BAD_CAST "name", BAD_CAST name);
    gen_xml_add_description(xml_constraint);
    gen_xml_add_defined(parser, xml_constraint);
    if(data != NULL) {
        xmlNodePtr xml_data = NULL;
        xmlNodePtr content = NULL;
        amxc_var_t json_data;
        amxc_var_init(&json_data);
        amxc_var_convert(&json_data, data, AMXC_VAR_ID_JSON);
        const char* str = amxc_var_constcast(jstring_t, &json_data);
        content = xmlNewCDataBlock(xml_ctx->doc, BAD_CAST str, strlen(str));
        xml_data = xmlNewNode(xml_ctx->ns, BAD_CAST "data");
        xmlAddChild(xml_constraint, xml_data);
        xmlAddChild(xml_data, content);
        amxc_var_clean(&json_data);
    }

    xmlAddChild(xml_ctx->xml_param, xml_constraint);

exit:
    return;
}

void gen_xml_parameter_end(UNUSED amxo_parser_t* parser,
                           UNUSED amxd_object_t* object,
                           UNUSED amxd_param_t* param) {
    xml_gen_t* xml_ctx = gen_xml_get_ctx();
    xml_ctx->xml_param = NULL;
}

void gen_xml_set_counter(UNUSED amxo_parser_t* parser,
                         amxd_object_t* object,
                         const char* name) {
    xml_gen_t* xml_ctx = gen_xml_get_ctx();
    amxd_object_t* parent = amxd_object_get_parent(object);
    amxc_string_t* full_path = gen_xml_compute_full_path(parent, name, NULL);
    const char* attr_names[] = {
        "multi-instance", "instance", "private", "read-only", "persistent",
        "volatile", "instance-counter", "key", "unique", "protected", "mutable"
    };

    gen_xml_translate_path(parser, full_path, NULL);
    xml_ctx->xml_param = gen_xml_search_param(parent, name);

    if(xml_ctx->xml_param == NULL) {
        amxd_param_t* param = amxd_object_get_param_def(object, name);
        uint32_t attr_bitmask = amxd_param_get_attrs(param);

        xml_ctx->xml_param = xmlNewNode(xml_ctx->ns, BAD_CAST "parameter");
        xmlSetNsProp(xml_ctx->xml_param, xml_ctx->ns,
                     BAD_CAST "name", BAD_CAST name);
        xmlSetNsProp(xml_ctx->xml_param, xml_ctx->ns,
                     BAD_CAST "path", BAD_CAST amxc_string_get(full_path, 0));
        xmlSetNsProp(xml_ctx->xml_param, xml_ctx->ns,
                     BAD_CAST "type", BAD_CAST gen_xml_odl_type(AMXC_VAR_ID_UINT32));
        gen_xml_attributes(xml_ctx->xml_param, attr_bitmask,
                           amxd_pattr_max, attr_names);
        xmlAddChild(xml_ctx->xml_object->parent, xml_ctx->xml_param);
        gen_xml_add_defined(parser, xml_ctx->xml_param);

        gen_xml_add_description(xml_ctx->xml_param);
        gen_xml_add_version(xml_ctx->xml_param);
    }

    amxc_string_delete(&full_path);
}
