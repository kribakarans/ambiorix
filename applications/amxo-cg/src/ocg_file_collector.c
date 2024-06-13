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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <errno.h>

#include <amxp/amxp_dir.h>

#include "utils.h"

typedef enum _collection_type {
    odl_add,
    odl_scan_dir,
    odl_include
} collection_type_t;

typedef struct _odl_file {
    char* file;
    uint32_t use_count;
    uint32_t error_count;
    collection_type_t type;
    amxc_htable_it_t it;
    amxc_llist_it_t lit;
} odl_file_t;

typedef struct _odl_tree_item {
    odl_file_t* odl_ref;
    amxc_htable_it_t it;
    amxc_htable_t odl_files;
} odl_tree_item_t;

typedef struct _ocg_scan_data {
    amxo_parser_t* parser;
    collection_type_t type;
} ocg_scan_data_t;

static amxc_htable_t odl_files;
static amxc_llist_t list_files;
static odl_tree_item_t odl_tree_root;

static odl_tree_item_t* tree_current = NULL;

static int ocg_scan_dir(amxo_parser_t* parser,
                        const char* path,
                        collection_type_t type);

static void ocg_clean_odl_files(UNUSED const char* key, amxc_htable_it_t* it) {
    odl_file_t* odl_file = amxc_container_of(it, odl_file_t, it);
    amxc_llist_it_take(&odl_file->lit);
    free(odl_file->file);
    free(odl_file);
}

static void ocg_clean_odl_tree(UNUSED const char* key, amxc_htable_it_t* it) {
    odl_tree_item_t* tree_item = amxc_container_of(it, odl_tree_item_t, it);
    amxc_htable_clean(&tree_item->odl_files, ocg_clean_odl_tree);
    free(tree_item);
}

static void CONSTRUCTOR ocg_scan_init(void) {
    amxc_htable_init(&odl_files, 64);
    odl_tree_root.odl_ref = NULL;
    odl_tree_root.it.ait = NULL;
    odl_tree_root.it.key = NULL;
    odl_tree_root.it.next = NULL;
    amxc_htable_init(&odl_tree_root.odl_files, 32);
    amxc_llist_init(&list_files);
}

static void DESTRUCTOR ocg_scan_clean(void) {
    amxc_htable_clean(&odl_tree_root.odl_files, ocg_clean_odl_tree);
    amxc_htable_clean(&odl_files, ocg_clean_odl_files);
}

static odl_file_t* ocg_add_file(char* file, collection_type_t type) {
    amxc_htable_it_t* it = amxc_htable_get(&odl_files, file);
    odl_file_t* odl_file = NULL;

    if(it == NULL) {
        odl_file = (odl_file_t*) calloc(1, sizeof(odl_file_t));
        odl_file->file = file;
        odl_file->type = type;
        amxc_htable_insert(&odl_files, file, &odl_file->it);
        amxc_llist_append(&list_files, &odl_file->lit);
    } else {
        free(file);
        odl_file = amxc_container_of(it, odl_file_t, it);
        odl_file->type = type;
    }

    return odl_file;
}

static int ocg_add_implementation(amxo_parser_t* parser,
                                  const char* input,
                                  collection_type_t type) {
    struct stat path_stat;
    char* full_path = NULL;
    int retval = stat(input, &path_stat);

    if(retval != 0) {
        ocg_error(&parser->config, "[%s] - %s", input, strerror(errno));
        goto exit;
    }

    if(S_ISREG(path_stat.st_mode)) {
        const char* extension = strstr(input, ".odl");
        if((extension != NULL) && (extension[4] == 0)) {
            full_path = realpath(input, NULL);
            if(full_path != NULL) {
                ocg_message(&parser->config, "Add file [%s]", full_path);
                ocg_add_file(full_path, type);
            }
        }
    } else if(S_ISDIR(path_stat.st_mode)) {
        full_path = realpath(input, NULL);
        if(full_path != NULL) {
            ocg_message(&parser->config, "Scan directory [%s]", full_path);
            ocg_scan_dir(parser, full_path, type);
        }
        free(full_path);
    }

exit:
    return retval;
}

static int ocg_scan_add(const char* name, void* priv) {
    ocg_scan_data_t* data = (ocg_scan_data_t*) priv;
    return ocg_add_implementation(data->parser, name, data->type);
}

static int ocg_scan_dir(amxo_parser_t* parser,
                        const char* path,
                        collection_type_t type) {
    int retval = -1;
    ocg_scan_data_t data = {
        .parser = parser,
        .type = type
    };

    retval = amxp_dir_scan(path, "d_type == DT_REG || d_type == DT_DIR", false, ocg_scan_add, &data);

    return retval;
}

static void ocg_reset_parser(amxo_parser_t* parser, amxc_var_t* config, const char* file_name) {
    char* full_path = strdup(file_name);
    char* name = basename(full_path);

    amxc_var_clean(&parser->config);
    amxc_var_copy(&parser->config, config);

    name[strlen(name) - 4] = 0;
    amxc_var_add_key(cstring_t, &parser->config, "name", name);

    free(full_path);
}

static void ocg_clean_tree_root(void) {
    amxc_htable_for_each(it, (&odl_tree_root.odl_files)) {
        odl_tree_item_t* tree_item = amxc_container_of(it, odl_tree_item_t, it);
        if(tree_item->odl_ref->use_count > 0) {
            tree_item->odl_ref->error_count = 0;
            amxc_htable_it_clean(&tree_item->it, ocg_clean_odl_tree);
            continue;
        }
    }
}

static int ocg_parse_files(amxo_parser_t* parser,
                           amxd_dm_t* dm,
                           amxc_var_t* base_config,
                           collection_type_t type) {
    int rv = 0;
    bool cont = GET_BOOL(&parser->config, "continue");
    bool reset = GET_BOOL(&parser->config, "reset");

    amxc_llist_for_each(it, &list_files) {
        odl_file_t* odl_file = amxc_container_of(it, odl_file_t, lit);
        const char* file = odl_file->file;
        amxc_htable_it_t* ti_it = amxc_htable_get(&odl_tree_root.odl_files, file);
        odl_tree_item_t* ti = NULL;
        if(ti_it == NULL) {
            continue;
        }
        ti = amxc_container_of(ti_it, odl_tree_item_t, it);
        if(ti->odl_ref->type != type) {
            continue;
        }
        if(reset) {
            amxd_dm_clean(dm);
            amxd_dm_init(dm);
        }
        if(type != odl_include) {
            ocg_message(&parser->config, "Parsing file [%s]", file);
            ocg_reset_parser(parser, base_config, file);
        } else {
            ocg_message(&parser->config, "Including file [%s]", file);
        }
        rv += amxo_parser_parse_file(parser, file, amxd_dm_get_root(dm));
        if(rv != 0) {
            ocg_error(&parser->config, "Error parsing [%s]", file);
            ocg_error(&parser->config, "%s", amxc_string_get(&parser->msg, 0));
            if(!cont) {
                break;
            }
        }
    }

    return rv;
}

static void ocg_open_include(amxo_parser_t* parser, const char* incfile) {
    amxc_htable_it_t* it = amxc_htable_get(&odl_files, incfile);
    odl_file_t* odl_file = NULL;
    odl_tree_item_t* tree_item = NULL;
    bool orig_silent = GET_BOOL(&parser->config, "silent");
    amxc_var_t* silent = GET_ARG(&parser->config, "silent");

    if(it == NULL) {
        amxc_var_set(bool, silent, false);
        ocg_message(&parser->config, "Add included file [%s]", incfile);
        amxc_var_set(bool, silent, orig_silent);
        odl_file = ocg_add_file(strdup(incfile), odl_include);
    } else {
        odl_file = amxc_container_of(it, odl_file_t, it);
        odl_file->type = odl_include;
    }
    odl_file->use_count++;
    amxc_llist_it_take(&odl_file->lit);

    it = amxc_htable_get(&tree_current->odl_files, incfile);
    if(it == NULL) {
        tree_item = (odl_tree_item_t*) calloc(1, sizeof(odl_tree_item_t));
        tree_item->odl_ref = odl_file;
        amxc_htable_init(&tree_item->odl_files, 10);
        amxc_htable_insert(&tree_current->odl_files, incfile, &tree_item->it);
    } else {
        tree_item = amxc_container_of(it, odl_tree_item_t, it);
    }
    tree_current = tree_item;
}

static void ocg_end_include(UNUSED amxo_parser_t* parser, UNUSED const char* incfile) {
    tree_current = amxc_container_of(tree_current->it.ait->array, odl_tree_item_t, odl_files);
}

static amxo_hooks_t ocg_hooks = {
    .it = { .next = NULL, .prev = NULL, .llist = NULL },
    .comment = NULL,
    .start = NULL,
    .end = NULL,
    .start_include = ocg_open_include,
    .end_include = ocg_end_include,
    .set_config = NULL,
    .start_section = NULL,
    .end_section = NULL,
    .create_object = NULL,
    .add_instance = NULL,
    .select_object = NULL,
    .end_object = NULL,
    .add_param = NULL,
    .set_param = NULL,
    .end_param = NULL,
    .add_func = NULL,
    .add_func_arg = NULL,
    .end_func = NULL,
    .add_mib = NULL,
    .set_counter = NULL,
    .set_action_cb = NULL,
};

static void ocg_check_odl_file(amxo_parser_t* parser,
                               amxd_object_t* root,
                               const char* file_name,
                               odl_file_t* odl_file) {
    odl_tree_item_t* tree_item = (odl_tree_item_t*) calloc(1, sizeof(odl_tree_item_t));
    tree_item->odl_ref = odl_file;
    amxc_htable_init(&tree_item->odl_files, 10);
    amxc_htable_insert(&odl_tree_root.odl_files, file_name, &tree_item->it);

    tree_current = tree_item;
    if(amxo_parser_parse_file(parser, file_name, root) != 0) {
        odl_file->error_count++;
    } else {
        if(parser->post_includes != NULL) {
            amxc_var_for_each(f, parser->post_includes) {
                const char* file = amxc_var_constcast(cstring_t, f);
                ocg_open_include(parser, file);
                if(amxo_parser_parse_file(parser, file, root) != 0) {
                    odl_file->error_count++;
                }
                ocg_end_include(parser, file);
                amxc_var_delete(&f);
            }
        }
    }
}

void ocg_build_include_tree(amxc_var_t* config) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    amxc_var_t* silent = NULL;
    bool org_silent = false;

    amxc_array_t* files = amxc_htable_get_sorted_keys(&odl_files);
    size_t nr_of_files = amxc_array_size(files);

    silent = GET_ARG(config, "silent");
    if(silent == NULL) {
        silent = amxc_var_add_key(bool, config, "silent", true);
    } else {
        org_silent = amxc_var_dyncast(bool, silent);
    }

    for(size_t i = 0; i < nr_of_files; i++) {
        const char* file_name = (const char*) amxc_array_get_data_at(files, i);
        amxc_htable_it_t* it = amxc_htable_get(&odl_files, file_name);
        odl_file_t* odl_file = amxc_container_of(it, odl_file_t, it);

        amxo_parser_init(&parser);
        amxo_parser_set_hooks(&parser, &ocg_hooks);

        if(odl_file->use_count == 0) {
            amxc_var_t* var = NULL;
            amxd_dm_init(&dm);
            ocg_reset_parser(&parser, config, file_name);
            var = amxo_parser_claim_config(&parser, "odl-resolve");
            amxc_var_set(bool, var, false);
            var = amxo_parser_claim_config(&parser, "odl-import");
            amxc_var_set(bool, var, false);

            ocg_check_odl_file(&parser, amxd_dm_get_root(&dm), file_name, odl_file);

            amxd_dm_clean(&dm);
        }

        amxo_parser_clean(&parser);
    }


    amxc_array_delete(&files, NULL);
    ocg_clean_tree_root();
    amxc_var_set(bool, silent, org_silent);
}

int ocg_add(amxo_parser_t* parser, const char* input) {
    return ocg_add_implementation(parser, input, odl_add);
}

int ocg_add_include(amxo_parser_t* parser, const char* input) {
    return ocg_add_implementation(parser, input, odl_include);
}

int ocg_run(amxo_parser_t* parser) {
    int rv = 0;
    bool cont = GET_BOOL(&parser->config, "continue");

    amxc_var_t base_config;
    amxd_dm_t dm;
    amxc_var_t* silent = NULL;
    amxc_var_t* comment_warnings = NULL;

    comment_warnings = amxc_var_add_key(bool, &parser->config, "comment-warnings", true);
    silent = GET_ARG(&parser->config, "silent");
    if(silent != NULL) {
        amxc_var_set(bool, comment_warnings, amxc_var_dyncast(bool, silent));
        amxc_var_set(bool, silent, false);
    }

    amxc_var_init(&base_config);
    amxc_var_copy(&base_config, &parser->config);

    amxd_dm_init(&dm);
    ocg_comment_set_clear(parser, true);

    rv += ocg_parse_files(parser, &dm, &base_config, odl_add);
    if((rv != 0) && !cont) {
        goto exit;
    }
    rv += ocg_parse_files(parser, &dm, &base_config, odl_scan_dir);
    if((rv != 0) && !cont) {
        goto exit;
    }
    rv += ocg_parse_files(parser, &dm, &base_config, odl_include);

exit:
    ocg_comment_set_clear(parser, false);
    amxd_dm_clean(&dm);
    amxc_var_clean(&base_config);
    return rv;
}

void ocg_dump_include_tree(amxc_var_t* config, amxc_htable_t* tree_item, int indent) {
    amxc_array_t* files = NULL;
    size_t nr_of_files = 0;
    bool silent = GET_BOOL(config, "silent");
    if(silent) {
        goto exit;
    }
    if(tree_item == NULL) {
        tree_item = &odl_tree_root.odl_files;
    }

    files = amxc_htable_get_sorted_keys(tree_item);
    nr_of_files = amxc_array_size(files);

    for(size_t i = 0; i < nr_of_files; i++) {
        const char* key = (const char*) amxc_array_get_data_at(files, i);
        amxc_htable_it_t* it = amxc_htable_get(tree_item, key);
        odl_tree_item_t* odl_tree_item = amxc_container_of(it, odl_tree_item_t, it);

        fprintf(stderr, "       ");
        for(int j = 0; j < indent; j++) {
            if(j + 1 < indent) {
                fprintf(stderr, "|   ");
            } else {
                fprintf(stderr, "|---");
            }
        }

        fprintf(stderr, "%s  (includes %zd, used %d)\n",
                odl_tree_item->odl_ref->file,
                amxc_htable_size(&odl_tree_item->odl_files),
                odl_tree_item->odl_ref->use_count);

        ocg_dump_include_tree(config, &odl_tree_item->odl_files, indent + 1);
    }
    amxc_array_delete(&files, NULL);

exit:
    return;
}

void ocg_dump_files_list(amxc_var_t* config) {
    ocg_message(config, "Files that will be parsed are:");
    amxc_llist_for_each(it, &list_files) {
        odl_file_t* odl_file = amxc_container_of(it, odl_file_t, lit);
        if(odl_file->type != odl_include) {
            fprintf(stderr, "       %s\n", odl_file->file);
        } else {
            fprintf(stderr, "       %s (included)\n", odl_file->file);
        }
    }
}

void ocg_reset(void) {
    amxc_htable_clean(&odl_tree_root.odl_files, ocg_clean_odl_tree);
    amxc_htable_clean(&odl_files, ocg_clean_odl_files);

    amxc_htable_init(&odl_files, 64);
    odl_tree_root.odl_ref = NULL;
    odl_tree_root.it.ait = NULL;
    odl_tree_root.it.key = NULL;
    odl_tree_root.it.next = NULL;
    amxc_htable_init(&odl_tree_root.odl_files, 32);
}