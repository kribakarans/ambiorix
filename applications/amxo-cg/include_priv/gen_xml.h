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

#if !defined(__GEN_XML_H__)
#define __GEN_XML_H__

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>
#include <amxo/amxo.h>
#include <amxo/amxo_hooks.h>

#include "utils.h"

typedef struct _xml_gen {
    xmlDocPtr doc;
    xmlNsPtr ns;
    xmlNodePtr xml_root;
    xmlNodePtr xml_locations;
    xmlNodePtr xml_dm_root;
    xmlNodePtr xml_object;
    xmlNodePtr xml_param;
    xmlNodePtr xml_func;
    char* xml_file_name;
    uint32_t section;
    uint32_t object_skip;
} xml_gen_t;

xml_gen_t* gen_xml_get_ctx(void);

// Utility functions
///////////////////////////////////////////////////////////////////////////////
const char* gen_xml_odl_type(uint32_t type);

void gen_xml_add_root_obj(amxo_parser_t* parser);

void gen_xml_translate_path(amxo_parser_t* parser,
                            amxc_string_t* path,
                            amxc_string_t* name);

xmlNodePtr gen_xml_find(xmlDocPtr doc,
                        const char* path,
                        const char* param);

xmlNodePtr gen_xml_find_node(xmlNodePtr parent, const char* name);

xmlNodePtr gen_xml_get_parent_node(xmlDocPtr doc, amxc_string_t* path);

void gen_xml_attributes(xmlNodePtr node,
                        uint32_t bitmask,
                        uint32_t max,
                        const char* names[]);

void gen_xml_add_defined(amxo_parser_t* parser, xmlNodePtr item);

void gen_xml_add_description(xmlNodePtr node);

void gen_xml_add_version(xmlNodePtr node);

void gen_xml_add_return_tag(xmlNodePtr node);

amxc_string_t* gen_xml_compute_full_path(amxd_object_t* object,
                                         const char* name,
                                         const char* func);
///////////////////////////////////////////////////////////////////////////////

// Data Model Object XML generation - ODL parser hook functions
///////////////////////////////////////////////////////////////////////////////
void gen_xml_object_start(amxo_parser_t* parser,
                          amxd_object_t* parent,
                          const char* name,
                          int64_t attr_bitmask,
                          amxd_object_type_t type);

void gen_xml_object_instance(amxo_parser_t* parser,
                             amxd_object_t* parent,
                             uint32_t index,
                             const char* name);

void gen_xml_object_select(amxo_parser_t* parser,
                           amxd_object_t* parent,
                           const char* path);

void gen_xml_object_end(amxo_parser_t* parser,
                        amxd_object_t* object);

void gen_xml_object_add_mib(amxo_parser_t* parser,
                            amxd_object_t* object,
                            const char* mib_name);
///////////////////////////////////////////////////////////////////////////////

// Data Model Parameters XML generation - ODL parser hook functions
///////////////////////////////////////////////////////////////////////////////
void gen_xml_parameter_start(amxo_parser_t* parser,
                             amxd_object_t* object,
                             const char* name,
                             int64_t attr_bitmask,
                             uint32_t type);

void gen_xml_parameter_set(amxo_parser_t* parser,
                           amxd_object_t* object,
                           amxd_param_t* param,
                           amxc_var_t* value);

void gen_xml_parameter_constraint(amxo_parser_t* parser,
                                  amxd_object_t* object,
                                  amxd_param_t* param,
                                  const char* name,
                                  const amxc_var_t* data);

void gen_xml_parameter_end(amxo_parser_t* parser,
                           amxd_object_t* object,
                           amxd_param_t* param);

void gen_xml_set_counter(amxo_parser_t* parser,
                         amxd_object_t* parent,
                         const char* name);
///////////////////////////////////////////////////////////////////////////////

// Data Model Function XML generation - ODL parser hook functions
///////////////////////////////////////////////////////////////////////////////
void gen_xml_func_start(amxo_parser_t* parser,
                        amxd_object_t* object,
                        const char* name,
                        int64_t attr_bitmask,
                        uint32_t type);

void gen_xml_func_add_param(amxo_parser_t* parser,
                            amxd_object_t* parent,
                            amxd_function_t* func,
                            const char* name,
                            int64_t attr_bitmask,
                            uint32_t type,
                            amxc_var_t* def_val);

void gen_xml_func_end(amxo_parser_t* parser,
                      amxd_object_t* object,
                      amxd_function_t* func);
///////////////////////////////////////////////////////////////////////////////



#ifdef __cplusplus
}
#endif

#endif // __GEN_XML_H__
