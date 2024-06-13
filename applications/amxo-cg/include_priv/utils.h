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

#if !defined(__UTILS_H__)
#define __UTILS_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <yajl/yajl_gen.h>
#include <amxc/amxc.h>
#include <amxj/amxj_variant.h>
#include <amxp/amxp.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxo/amxo.h>
#include <amxo/amxo_hooks.h>

#define CONSTRUCTOR __attribute__((constructor))
#define DESTRUCTOR __attribute__((destructor))
#define UNUSED __attribute__((unused))

typedef struct _tag {
    amxc_llist_it_t it;
    char* line;
    char* tag;
    char* arg1;
    char* rest;
} tag_t;

int ocg_parse_arguments(amxo_parser_t* parser,
                        amxc_var_t* config,
                        int argc,
                        char** argv);

int ocg_config_load(amxo_parser_t* parser);

void ocg_config_changed(amxo_parser_t* parser, int section_id);

int ocg_apply_config(amxo_parser_t* parser,
                     amxc_var_t* config);

void ocg_config_remove_generators(amxo_parser_t* parser);

void ocg_usage(int argc, char* argv[]);
void ocg_sub_usage(const char* help_topic);
void ocg_error(amxc_var_t* config, const char* fmt, ...);
void ocg_warning(amxc_var_t* config, const char* fmt, ...);
void ocg_message(amxc_var_t* config, const char* fmt, ...);

void ocg_dump_config(amxo_parser_t* parser);

void ocg_verbose_logging(amxo_parser_t* parser, bool enable);

void ocg_gen_dm_methods(amxo_parser_t* parser, bool enable);
void ocg_gen_xml(amxo_parser_t* parser, bool enable);

int ocg_add(amxo_parser_t* parser, const char* input);
int ocg_add_include(amxo_parser_t* parser, const char* input);
void ocg_build_include_tree(amxc_var_t* config);
int ocg_verify_include_tree(amxc_var_t* config);
int ocg_run(amxo_parser_t* parser);
void ocg_dump_include_tree(amxc_var_t* config, amxc_htable_t* tree_item, int indent);
void ocg_dump_files_list(amxc_var_t* config);
void ocg_reset(void);

void ocg_comment_parse(amxo_parser_t* parser, const char* comment);

bool ocg_comment_is_available(void);
const tag_t* ocg_comment_get_tag(const char* name, const char* arg1);
const char* ocg_comment_get(void);
void ocg_comment_set_clear(amxo_parser_t* parser, bool enable);

#ifdef __cplusplus
}
#endif

#endif // __UTILS_H__
