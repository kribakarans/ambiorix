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

static void gen_xml_func_add_ret(xml_gen_t* xml_ctx, uint32_t type) {
    xmlNodePtr return_node = xmlNewNode(xml_ctx->ns, BAD_CAST "return");
    xmlSetNsProp(return_node, xml_ctx->ns,
                 BAD_CAST "type", BAD_CAST gen_xml_odl_type(type));
    xmlAddChild(xml_ctx->xml_func, return_node);
    gen_xml_add_return_tag(return_node);
}

static void gen_xml_add_arg_description(xmlNodePtr node, const char* name) {
    xmlNodePtr item = NULL;
    xmlNodePtr content = NULL;
    const tag_t* tag = NULL;
    xml_gen_t* xml_ctx = gen_xml_get_ctx();

    if(!ocg_comment_is_available()) {
        goto exit;
    }

    tag = ocg_comment_get_tag("param", name);
    if(tag == NULL) {
        goto exit;
    }

    item = xmlNewNode(xml_ctx->ns, BAD_CAST "description");
    xmlAddChild(node, item);
    content = xmlNewText(BAD_CAST tag->rest);
    xmlAddChild(item, content);

exit:
    return;
}

static bool gen_xml_skip_protected_func(amxo_parser_t* parser, uint64_t fattr_bitmask) {
    bool retval = false;
    amxc_var_t* amxo_cg = amxo_parser_get_config(parser, "amxo-cg");
    bool skip_protected = GET_BOOL(amxo_cg, "skip-protected");

    if(IS_BIT_SET(fattr_bitmask, amxd_fattr_protected) && skip_protected) {
        retval = true;
    }

    return retval;
}

void gen_xml_func_start(amxo_parser_t* parser,
                        UNUSED amxd_object_t* object,
                        const char* name,
                        int64_t attr_bitmask,
                        uint32_t type) {
    const char* attr_names[] = {
        "private", "protected", "template", "instance"
    };
    xml_gen_t* xml_ctx = gen_xml_get_ctx();
    amxc_string_t* full_path = gen_xml_compute_full_path(object, name, NULL);

    when_true(gen_xml_skip_protected_func(parser, attr_bitmask), exit);

    gen_xml_translate_path(parser, full_path, NULL);

    xml_ctx->xml_func = xmlNewNode(xml_ctx->ns, BAD_CAST "function");
    xmlSetNsProp(xml_ctx->xml_func, xml_ctx->ns,
                 BAD_CAST "name", BAD_CAST name);
    xmlSetNsProp(xml_ctx->xml_func, xml_ctx->ns,
                 BAD_CAST "path", BAD_CAST amxc_string_get(full_path, 0));
    gen_xml_attributes(xml_ctx->xml_func, attr_bitmask,
                       amxd_fattr_max, attr_names);
    xmlAddChild(xml_ctx->xml_object, xml_ctx->xml_func);
    gen_xml_add_defined(parser, xml_ctx->xml_func);

    gen_xml_func_add_ret(xml_ctx, type);

    gen_xml_add_description(xml_ctx->xml_func);
    gen_xml_add_version(xml_ctx->xml_func);

exit:
    amxc_string_delete(&full_path);
}

void gen_xml_func_end(UNUSED amxo_parser_t* parser,
                      UNUSED amxd_object_t* object,
                      UNUSED amxd_function_t* func) {
    xml_gen_t* xml_ctx = gen_xml_get_ctx();
    xml_ctx->xml_func = NULL;
}

void gen_xml_func_add_param(UNUSED amxo_parser_t* parser,
                            amxd_object_t* parent,
                            amxd_function_t* func,
                            const char* name,
                            int64_t attr_bitmask,
                            uint32_t type,
                            UNUSED amxc_var_t* def_val) {
    xmlNodePtr arg = NULL;
    const char* attr_names[] = {
        "in", "out", "mandatory", "strict"
    };
    xml_gen_t* xml_ctx = gen_xml_get_ctx();
    amxc_string_t* full_path = gen_xml_compute_full_path(parent, name, func->name);

    when_true(gen_xml_skip_protected_func(parser, amxd_function_get_attrs(func)), exit);

    gen_xml_translate_path(parser, full_path, NULL);

    arg = xmlNewNode(xml_ctx->ns, BAD_CAST "argument");
    xmlSetNsProp(arg, xml_ctx->ns,
                 BAD_CAST "name", BAD_CAST name);
    xmlSetNsProp(arg, xml_ctx->ns,
                 BAD_CAST "path", BAD_CAST amxc_string_get(full_path, 0));
    xmlSetNsProp(arg, xml_ctx->ns,
                 BAD_CAST "type", BAD_CAST gen_xml_odl_type(type));
    gen_xml_attributes(arg, attr_bitmask, amxd_aattr_max, attr_names);
    xmlAddChild(xml_ctx->xml_func, arg);
    gen_xml_add_arg_description(arg, name);

exit:
    amxc_string_delete(&full_path);
}
