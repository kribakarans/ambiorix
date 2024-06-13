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

static int isdot(int c) {
    return c == '.'? 1:0;
}

const char* gen_xml_odl_type(uint32_t type) {
    const char* type_names[] = {
        "void", "string", "int8", "int16", "int32", "int64", "uint8", "uint16",
        "uint32", "uint64", "float", "double", "bool", "list", "table", "fd",
        "datetime", "csv_string", "ssv_string"
    };

    if(type == AMXC_VAR_ID_ANY) {
        return "variant";
    } else if(type > AMXC_VAR_ID_ANY) {
        amxc_var_type_t* var_type = amxc_var_get_type(type);
        if(var_type == NULL) {
            return "unknown";
        }
        return amxc_var_get_type_name_from_id(type);
    }

    return type_names[type];
}

void gen_xml_translate_path(amxo_parser_t* parser, amxc_string_t* path, amxc_string_t* name) {
    amxc_var_t* amxo_cg = amxo_parser_get_config(parser, "amxo-cg");
    amxc_var_t* translate = GET_ARG(amxo_cg, "translate");
    amxc_var_t* matching = NULL;
    amxd_path_t orig_path;

    amxd_path_init(&orig_path, amxc_string_get(path, 0));
    when_null(translate, exit);

    matching = amxc_var_get_key(translate, amxd_path_get(&orig_path, AMXD_OBJECT_TERMINATE), AMXC_VAR_FLAG_DEFAULT);
    while(matching == NULL) {
        char* p = amxd_path_get_last(&orig_path, true);
        if(p == NULL) {
            break;
        }
        free(p);
        matching = amxc_var_get_key(translate, amxd_path_get(&orig_path, AMXD_OBJECT_TERMINATE), AMXC_VAR_FLAG_DEFAULT);
    }

    if(matching != NULL) {
        char* trans_name = NULL;
        // translate path
        amxc_string_replace(path, amxc_var_key(matching), GET_CHAR(matching, NULL), 1);
        when_null(name, exit);
        // get new name
        amxd_path_setf(&orig_path, false, "%s", amxc_string_get(path, 0));
        trans_name = amxd_path_get_last(&orig_path, true);
        if(trans_name != NULL) {
            amxc_string_push_buffer(name, trans_name, strlen(trans_name) + 1);
            amxc_string_trimr(name, isdot);
        }
    }

exit:
    amxd_path_clean(&orig_path);
    return;
}

xmlNodePtr gen_xml_find(xmlDocPtr doc,
                        const char* path,
                        const char* param) {
    xmlXPathContextPtr xpath_ctx = xmlXPathNewContext(doc);
    xmlXPathObjectPtr xpath_obj = NULL;
    xmlNodePtr node = NULL;
    amxc_string_t xpath_expr;
    int size = 0;

    xmlXPathRegisterNs(xpath_ctx, BAD_CAST NULL, BAD_CAST "http://www.w3.org/1999/xhtml");
    xmlXPathRegisterNs(xpath_ctx, BAD_CAST "odl", BAD_CAST "http://www.softathome.com/odl");

    amxc_string_init(&xpath_expr, 0);
    if(param == NULL) {
        amxc_string_setf(&xpath_expr, "//odl:object[@odl:path='%s']", path);
    } else {
        amxc_string_setf(&xpath_expr,
                         "//odl:object[@odl:path='%s']/odl:parameter[@odl:name='%s']",
                         path, param);
    }
    xpath_obj = xmlXPathEvalExpression(BAD_CAST amxc_string_get(&xpath_expr, 0), xpath_ctx);
    if(xpath_obj == NULL) {
        goto exit;
    }

    size = (xpath_obj->nodesetval != NULL) ? xpath_obj->nodesetval->nodeNr : 0;

    switch(size) {
    case 0:     // not found -> ok
        break;
    case 1:     // exact one found -> ok
        node = xpath_obj->nodesetval->nodeTab[0];
        break;
    default:
        // error case
        break;
    }

exit:
    amxc_string_clean(&xpath_expr);
    xmlXPathFreeObject(xpath_obj);
    xmlXPathFreeContext(xpath_ctx);
    return node;
}

xmlNodePtr gen_xml_get_parent_node(xmlDocPtr doc, amxc_string_t* path) {
    amxd_path_t parent_path;
    xmlNodePtr node = NULL;
    char* current = NULL;
    xml_gen_t* xml_ctx = gen_xml_get_ctx();

    amxd_path_init(&parent_path, amxc_string_get(path, 0));
    current = amxd_path_get_last(&parent_path, true);
    free(current);
    current = NULL;

    if(amxc_string_is_empty(&parent_path.path)) {
        node = xml_ctx->xml_dm_root;
    } else {
        node = gen_xml_find(doc, amxd_path_get(&parent_path, AMXD_OBJECT_TERMINATE), NULL);
    }

    if(node == NULL) {
        xmlNodePtr parent_node = NULL;
        amxc_string_t name;

        // add the node
        current = amxd_path_get_last(&parent_path, false);
        amxc_string_init(&name, 0);
        amxc_string_setf(&name, "%s", current);
        amxc_string_trimr(&name, isdot);
        free(current);
        current = NULL;

        node = xmlNewNode(xml_ctx->ns, BAD_CAST "object");
        xmlSetNsProp(node, xml_ctx->ns, BAD_CAST "name", BAD_CAST amxc_string_get(&name, 0));
        xmlSetNsProp(node, xml_ctx->ns, BAD_CAST "path", BAD_CAST amxd_path_get(&parent_path, AMXD_OBJECT_TERMINATE));
        parent_node = gen_xml_get_parent_node(doc, &parent_path.path);

        amxc_string_clean(&name);

        // add to parent
        xmlAddChild(parent_node, node);
    }

    amxd_path_clean(&parent_path);
    return node;
}

xmlNodePtr gen_xml_find_node(xmlNodePtr parent, const char* name) {
    xmlNodePtr node = NULL;
    if(parent == NULL) {
        goto exit;
    }
    if(parent->children == NULL) {
        goto exit;
    }

    node = parent->children;
    while(node != NULL) {
        if(xmlStrcmp(node->name, BAD_CAST name) == 0) {
            break;
        }
        node = node->next;
    }

exit:
    return node;
}

void gen_xml_attributes(xmlNodePtr node,
                        uint32_t bitmask,
                        uint32_t max,
                        const char* names[]) {
    xml_gen_t* xml_ctx = gen_xml_get_ctx();
    for(uint32_t i = 0; i < max; i++) {
        if(IS_BIT_SET(bitmask, i)) {
            xmlSetNsProp(node, xml_ctx->ns, BAD_CAST names[i], BAD_CAST "true");
        } else {
            xmlUnsetNsProp(node, xml_ctx->ns, BAD_CAST names[i]);
        }
    }
}

void gen_xml_add_defined(amxo_parser_t* parser, xmlNodePtr item) {
    xml_gen_t* xml_ctx = gen_xml_get_ctx();
    xmlNodePtr node = NULL;
    amxc_string_t line;
    amxc_string_init(&line, 0);

    amxc_string_setf(&line, "%d", parser->line);

    node = gen_xml_find_node(item, "defined");
    if(node == NULL) {
        node = xmlNewNode(xml_ctx->ns, BAD_CAST "defined");
        xmlAddChild(item, node);
    }

    xmlSetNsProp(node, xml_ctx->ns,
                 BAD_CAST "file", BAD_CAST parser->file);
    xmlSetNsProp(node, xml_ctx->ns,
                 BAD_CAST "line", BAD_CAST amxc_string_get(&line, 0));

    amxc_string_clean(&line);
}

amxc_string_t* gen_xml_compute_full_path(amxd_object_t* object,
                                         const char* name,
                                         const char* func) {
    amxc_string_t* full_path = NULL;
    char* path = amxd_object_get_path(object, AMXD_OBJECT_SUPPORTED | AMXD_OBJECT_TERMINATE);

    amxc_string_new(&full_path, 0);

    if(func == NULL) {
        amxc_string_setf(full_path, "%s%s", path, name);
    } else {
        amxc_string_setf(full_path, "%s%s(%s)", path, func, name);
    }

    free(path);
    return full_path;
}
