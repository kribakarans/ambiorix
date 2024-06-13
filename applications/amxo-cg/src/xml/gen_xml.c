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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>

#include "gen_xml.h"

static xml_gen_t xml_ctx;

static void gen_xml_add_location(amxo_parser_t* parser, const char* file) {
    xmlNodePtr node = NULL;
    const char* component = GETP_CHAR(&parser->config, "name");

    node = xmlNewNode(xml_ctx.ns, BAD_CAST "location");

    xmlSetNsProp(node, xml_ctx.ns,
                 BAD_CAST "file", BAD_CAST file);
    xmlSetNsProp(node, xml_ctx.ns,
                 BAD_CAST "component", BAD_CAST component);
    xmlSetNsProp(node, xml_ctx.ns,
                 BAD_CAST "path", BAD_CAST file);

    xmlAddChild(xml_ctx.xml_locations, node);
}

static void gen_xml_build_file_name(amxo_parser_t* parser,
                                    amxc_string_t* file,
                                    const char* dir_name,
                                    const char* base_name) {
    struct stat statbuf;

    // Improvement: strip extenstion from basename

    // No filename or directory name given, use the base name + ".xml"
    if((dir_name == NULL) || (*dir_name == 0)) {
        amxc_string_setf(file, "./%s.xml", base_name);
        ocg_message(&parser->config, "Generate xml file [%s]", amxc_string_get(file, 0));
        goto exit;
    }

    if(stat(dir_name, &statbuf) == 0) {
        if(S_ISDIR(statbuf.st_mode)) {
            // it is a directory - use given dir + base name + ".xml"
            ocg_message(&parser->config, "Output directory [%s]", dir_name);
            amxc_string_setf(file, "%s/%s.xml", dir_name, base_name);
            ocg_message(&parser->config, "Generate xml file [%s]", amxc_string_get(file, 0));
            goto exit;
        }
    }

    // it is just a file name
    ocg_message(&parser->config, "Output file [%s]", dir_name);
    amxc_string_setf(file, "%s", dir_name);
    ocg_message(&parser->config, "Generate xml file [%s]", amxc_string_get(file, 0));

exit:
    return;
}

static void gen_xml_start(amxo_parser_t* parser) {
    amxc_var_t* gens = amxo_parser_get_config(parser, "generators");
    amxc_var_t* var_dir_name = amxc_var_get_key(gens,
                                                "xml",
                                                AMXC_VAR_FLAG_DEFAULT);
    const char* dir_name = amxc_var_constcast(cstring_t, var_dir_name);
    char* filename = parser->file == NULL ? strdup("out") : strdup(parser->file);
    char* bn = basename(filename);
    amxc_string_t file;
    amxc_string_init(&file, 0);

    if(xml_ctx.doc == NULL) {
        gen_xml_build_file_name(parser, &file, dir_name, bn);
        xml_ctx.xml_file_name = amxc_string_take_buffer(&file);

        xml_ctx.doc = xmlNewDoc(BAD_CAST "1.0");
        xml_ctx.xml_root = xmlNewNode(NULL, BAD_CAST "odl:datamodel-set");
        xmlNewNs(xml_ctx.xml_root, BAD_CAST "http://www.w3.org/1999/xhtml", BAD_CAST NULL);
        xml_ctx.ns = xmlNewNs(xml_ctx.xml_root, BAD_CAST "http://www.softathome.com/odl", BAD_CAST "odl");

        xmlDocSetRootElement(xml_ctx.doc, xml_ctx.xml_root);

        xml_ctx.xml_locations = xmlNewNode(xml_ctx.ns, BAD_CAST "locations");
        gen_xml_add_location(parser, parser->file);
        xmlAddChild(xml_ctx.xml_root, xml_ctx.xml_locations);
    }

    amxc_string_clean(&file);
    free(filename);
}

static void gen_xml_end(UNUSED amxo_parser_t* parser) {

}

static void gen_xml_close(amxo_parser_t* parser) {
    int retval = 0;
    if(xml_ctx.xml_file_name != NULL) {
        ocg_message(&parser->config, "Creating file [%s]", xml_ctx.xml_file_name);
        retval = xmlSaveFormatFileEnc(xml_ctx.xml_file_name, xml_ctx.doc, "UTF-8", 1);
        if(retval == -1) {
            ocg_error(&parser->config, "Failed to write [%s]", xml_ctx.xml_file_name);
        }
    }

    xmlFreeDoc(xml_ctx.doc);
    xmlCleanupParser();
    xml_ctx.doc = NULL;
    xml_ctx.xml_root = NULL;
    xml_ctx.xml_dm_root = NULL;
    xml_ctx.xml_object = NULL;
    xml_ctx.xml_param = NULL;
    xml_ctx.xml_func = NULL;
    xml_ctx.ns = NULL;
    xml_ctx.object_skip = 0;

    free(xml_ctx.xml_file_name);
    xml_ctx.xml_file_name = NULL;
}

static void gen_xml_section_start(amxo_parser_t* parser,
                                  int section_id) {
    xml_ctx.section = section_id;
    switch(section_id) {
    case 0:     // config
        break;
    case 1:     // define
        if(xml_ctx.xml_dm_root == NULL) {
            xml_ctx.xml_dm_root = xmlNewNode(xml_ctx.ns, BAD_CAST "datamodel");
            xmlSetNsProp(xml_ctx.xml_dm_root, xml_ctx.ns, BAD_CAST "source", BAD_CAST parser->file);
            xmlAddChild(xml_ctx.xml_root, xml_ctx.xml_dm_root);
        }
        break;
    case 2:     // populate
        break;
    }
}

static void gen_xml_open_include(amxo_parser_t* parser, const char* incfile) {
    gen_xml_add_location(parser, incfile);
}

static void gen_xml_set_action_cb(UNUSED amxo_parser_t* parser,
                                  amxd_object_t* object,
                                  amxd_param_t* param,
                                  amxd_action_t action_id,
                                  const char* action_name,
                                  const amxc_var_t* data) {
    switch(action_id) {
    case action_param_validate:
        gen_xml_parameter_constraint(parser, object, param, action_name, data);
        break;
    default:
        break;
    }

    return;
}

static amxo_hooks_t fgen_hooks = {
    .it = { .next = NULL, .prev = NULL, .llist = NULL },
    .comment = NULL,
    .start = gen_xml_start,
    .end = gen_xml_end,
    .start_include = gen_xml_open_include,
    .end_include = NULL,
    .set_config = NULL,
    .start_section = gen_xml_section_start,
    .end_section = NULL,
    .create_object = gen_xml_object_start,
    .add_instance = gen_xml_object_instance,
    .select_object = gen_xml_object_select,
    .end_object = gen_xml_object_end,
    .add_param = gen_xml_parameter_start,
    .set_param = gen_xml_parameter_set,
    .end_param = gen_xml_parameter_end,
    .add_func = gen_xml_func_start,
    .add_func_arg = gen_xml_func_add_param,
    .end_func = gen_xml_func_end,
    .add_mib = gen_xml_object_add_mib,
    .set_counter = gen_xml_set_counter,
    .set_action_cb = gen_xml_set_action_cb,
};

void ocg_gen_xml(amxo_parser_t* parser, bool enable) {
    if(enable) {
        amxo_parser_set_hooks(parser, &fgen_hooks);
    } else {
        gen_xml_close(parser);
        amxo_parser_unset_hooks(parser, &fgen_hooks);
    }
}

xml_gen_t* gen_xml_get_ctx(void) {
    return &xml_ctx;
}

void gen_xml_add_description(xmlNodePtr node) {
    xmlNodePtr item = NULL;

    if(!ocg_comment_is_available()) {
        goto exit;
    }

    // TODO: cross reference resolving

    item = gen_xml_find_node(node, "description");
    if(item == NULL) {
        char* text = strdup(ocg_comment_get());
        char* paragraph = strtok(text, "\n");
        xmlNodePtr p = NULL;
        xmlNodePtr content = NULL;

        item = xmlNewNode(xml_ctx.ns, BAD_CAST "description");
        xmlAddChild(node, item);
        p = xmlNewNode(NULL, BAD_CAST "p");
        xmlAddChild(item, p);

        while(paragraph != NULL) {
            content = xmlNewText(BAD_CAST paragraph);
            xmlAddChild(p, content);
            content = xmlNewText(BAD_CAST " ");
            xmlAddChild(p, content);

            if(paragraph[strlen(paragraph) + 1] == '\n') {
                p = xmlNewNode(NULL, BAD_CAST "p");
                xmlAddChild(item, p);
            }

            paragraph = strtok(NULL, "\n");
        }
        free(text);
    }

exit:
    return;
}

void gen_xml_add_version(xmlNodePtr node) {
    xmlNodePtr item = NULL;
    const tag_t* tag = NULL;

    if(!ocg_comment_is_available()) {
        goto exit;
    }
    tag = ocg_comment_get_tag("version", NULL);
    if(tag == NULL) {
        goto exit;
    }

    item = gen_xml_find_node(node, "version-description");
    if(item == NULL) {
        xmlNodePtr content = NULL;
        item = xmlNewNode(xml_ctx.ns, BAD_CAST "version-description");
        xmlAddChild(node, item);
        content = xmlNewText(BAD_CAST tag->arg1);
        xmlAddChild(item, content);
    }

exit:
    return;
}

void gen_xml_add_return_tag(xmlNodePtr node) {
    xmlNodePtr item = NULL;
    const tag_t* tag = NULL;

    if(!ocg_comment_is_available()) {
        goto exit;
    }
    tag = ocg_comment_get_tag("return", NULL);
    if(tag == NULL) {
        goto exit;
    }

    item = gen_xml_find_node(node, "description");
    if(item == NULL) {
        xmlNodePtr content = NULL;
        item = xmlNewNode(xml_ctx.ns, BAD_CAST "description");
        xmlAddChild(node, item);
        content = xmlNewText(BAD_CAST tag->arg1);
        xmlAddChild(item, content);
        if(tag->rest != NULL) {
            content = xmlNewText(BAD_CAST " ");
            xmlAddChild(item, content);
            content = xmlNewText(BAD_CAST tag->rest);
            xmlAddChild(item, content);
        }
    }

exit:
    return;
}
