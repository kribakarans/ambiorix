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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libgen.h>

#include "utils.h"
#include "colors.h"

#define COPT_INCDIRS "include-dirs"
#define COPT_LIBDIRS "import-dirs"
#define COPT_MIBDIRS "mib-dirs"
#define COPT_CFG_DIR "cfg-dir"
#define COPT_PLUGIN_DIR "plugin-dir"

#define CFG_DIR "/etc/amx"
#define PLUGIN_DIR "/usr/lib/amx"

static int check_exists(amxc_var_t* config, const char* path) {
    struct stat path_stat;
    char* check_path = strdup(path);
    char* dir = NULL;
    int retval = stat(check_path, &path_stat);

    if(retval == 0) {
        goto exit;
    }

    dir = dirname(check_path);
    retval = stat(dir, &path_stat);

    if(retval == 0) {
        goto exit;
    }

    ocg_error(config, "[%s] - %s", path, strerror(errno));

exit:
    free(check_path);
    return retval;
}

static void build_file_name(amxc_string_t* file_path, const char* directory) {
    char* current_wd = getcwd(NULL, 0);
    char* real_path = NULL;

    amxc_string_setf(file_path, "%s/%s", current_wd, directory == NULL ? "" : directory);
    real_path = realpath(amxc_string_get(file_path, 0), NULL);

    if((real_path == NULL) || (*real_path == 0)) {
        int len = 0;

        free(current_wd);
        free(real_path);

        current_wd = amxc_string_take_buffer(file_path);
        current_wd = dirname(current_wd);
        len = strlen(current_wd) + 1;
        real_path = realpath(current_wd, NULL);
        amxc_string_setf(file_path, "%s/%s", real_path, current_wd + len);
    } else {
        amxc_string_setf(file_path, "%s", real_path);
    }

    free(current_wd);
    free(real_path);
}

static int add_generator(amxc_var_t* config, char* input) {
    int retval = 1;
    int i = 0;
    char* generator = strdup(input);
    char* directory = NULL;
    amxc_var_t* generators = GET_ARG(config, "generators");
    static const char* valids[] = {
        "dm_methods",
        "xml",
        NULL
    };

    directory = strchr(generator, ',');
    if(directory != NULL) {
        directory[0] = 0;
        directory++;
    }
    for(i = 0; valids[i] != NULL; i++) {
        if(strcmp(generator, valids[i]) == 0) {
            break;
        }
    }

    if(valids[i] == NULL) {
        ocg_error(config, "Invalid generator [%s]", generator);
        goto exit;
    }

    if(GET_ARG(generators, valids[i]) != NULL) {
        ocg_error(config, "Duplicate generator specified [%s]", generator);
        retval = 3;
        goto exit;
    }

    if((directory == NULL) || (*directory == 0)) {
        ocg_warning(config, "Generator [%s] missing output directory", generator);
        ocg_message(config, "Using current directory", generator);
    } else {
        retval = check_exists(config, directory);
        if(retval != 0) {
            goto exit;
        }
    }

    if((directory == NULL) || (*directory == 0) || (directory[0] != '/')) {
        amxc_string_t file_path;
        amxc_string_init(&file_path, 0);
        build_file_name(&file_path, directory);
        amxc_var_add_key(cstring_t, generators, valids[i], amxc_string_get(&file_path, 0));
        amxc_string_clean(&file_path);
    } else {
        amxc_var_add_key(cstring_t, generators, valids[i], directory);
    }

    retval = 0;

exit:
    free(generator);
    return retval;
}

static void ocg_generators(amxo_parser_t* parser) {
    const amxc_htable_t* gens
        = amxc_var_constcast(amxc_htable_t,
                             amxo_parser_get_config(parser, "generators"));
    ocg_gen_dm_methods(parser, amxc_htable_contains(gens, "dm_methods"));
    ocg_gen_xml(parser, amxc_htable_contains(gens, "xml"));
}

static void ocg_config_add_dir(amxc_var_t* var_dirs, const char* dir) {
    bool found = false;
    const amxc_llist_t* dirs = amxc_var_constcast(amxc_llist_t, var_dirs);

    amxc_llist_for_each(it, dirs) {
        amxc_var_t* var_dir = amxc_var_from_llist_it(it);
        const char* stored_dir = amxc_var_constcast(cstring_t, var_dir);
        if((stored_dir != NULL) && (strcmp(dir, stored_dir) == 0)) {
            found = true;
            break;
        }
    }

    if(!found) {
        amxc_var_add(cstring_t, var_dirs, dir);
    }
}

static void ocg_config_set_default_dirs(amxo_parser_t* parser) {
    amxc_var_t* inc_dirs = amxo_parser_claim_config(parser, COPT_INCDIRS);
    amxc_var_t* lib_dirs = amxo_parser_claim_config(parser, COPT_LIBDIRS);
    amxc_var_t* mib_dirs = amxo_parser_claim_config(parser, COPT_MIBDIRS);
    amxc_var_t* cfg_dir = amxo_parser_claim_config(parser, COPT_CFG_DIR);
    amxc_var_t* plugin_dir = amxo_parser_claim_config(parser, COPT_PLUGIN_DIR);

    amxc_var_set(cstring_t, cfg_dir, CFG_DIR);
    amxc_var_set(cstring_t, plugin_dir, PLUGIN_DIR);

    ocg_config_add_dir(inc_dirs, ".");
    ocg_config_add_dir(inc_dirs, "${prefix}${cfg-dir}/${name}");
    ocg_config_add_dir(inc_dirs, "${prefix}${cfg-dir}/modules");

    ocg_config_add_dir(lib_dirs, "${prefix}${plugin-dir}/${name}");
    ocg_config_add_dir(lib_dirs, "${prefix}${plugin-dir}/modules");
    ocg_config_add_dir(lib_dirs, "${prefix}/usr/local/lib/amx/${name}");
    ocg_config_add_dir(lib_dirs, "${prefix}/usr/local/lib/amx/modules");

    ocg_config_add_dir(mib_dirs, "${prefix}${cfg-dir}/${name}/mibs");
}

int ocg_parse_arguments(UNUSED amxo_parser_t* parser,
                        amxc_var_t* config,
                        int argc,
                        char** argv) {
    int c;
    amxc_var_t* incdirs = NULL;
    amxc_var_t* incodls = NULL;
    amxc_var_t* libdirs = NULL;
    amxc_var_t* generators = NULL;
    amxc_var_set_type(config, AMXC_VAR_ID_HTABLE);

    while(1) {
        int option_index = 0;

        static struct option long_options[] = {
            {"help", optional_argument, 0, 'h' },
            {"verbose", no_argument, 0, 'v' },
            {"include-odl", required_argument, 0, 'i' },
            {"include-dir", required_argument, 0, 'I' },
            {"import-dir", required_argument, 0, 'L' },
            {"import-resolve", no_argument, 0, 'R' },
            {"generator", required_argument, 0, 'G' },
            {"silent", no_argument, 0, 's' },
            {"no-warnings", no_argument, 0, 'w'},
            {"continue", no_argument, 0, 'c' },
            {"no-colors", no_argument, 0, 'n' },
            {"dump-config", no_argument, 0, 'd' },
            {"reset", no_argument, 0, 'r' },
            {"config", required_argument, 0, 'C' },
            {0, 0, 0, 0 }
        };

        c = getopt_long(argc, argv, "h::vi:I:L:RG:swcndrC:",
                        long_options, &option_index);
        if(c == -1) {
            break;
        }

        switch(c) {
        case 'I':
            if(incdirs == NULL) {
                incdirs = amxc_var_add_key(amxc_llist_t,
                                           config,
                                           "include-dirs",
                                           NULL);
            }
            ocg_config_add_dir(incdirs, optarg);
            break;

        case 'i':
            if(incodls == NULL) {
                incodls = amxc_var_add_key(amxc_llist_t,
                                           config,
                                           "include-odls",
                                           NULL);
            }
            ocg_config_add_dir(incodls, optarg);
            break;

        case 'L':
            if(libdirs == NULL) {
                libdirs = amxc_var_add_key(amxc_llist_t,
                                           config,
                                           "import-dirs",
                                           NULL);
            }
            ocg_config_add_dir(libdirs, optarg);
            break;

        case 'R':
            amxc_var_add_key(bool, config, "import-resolve", true);
            break;

        case 'G':
            if(generators == NULL) {
                generators = amxc_var_add_key(amxc_htable_t,
                                              config,
                                              "generators",
                                              NULL);
            }
            if(add_generator(config, optarg) != 0) {
                return -1;
            }
            break;

        case 's':
            amxc_var_add_key(bool, config, "silent", true);
            break;
        case 'w':
            amxc_var_add_key(bool, config, "no-warnings", true);
            break;
        case 'c':
            amxc_var_add_key(bool, config, "continue", true);
            break;
        case 'd':
            amxc_var_add_key(bool, config, "dump-config", true);
            break;
        case 'r':
            amxc_var_add_key(bool, config, "reset", true);
            break;
        case 'C':
            amxc_var_add_key(cstring_t, config, "config-file", optarg);
            break;
        case 'n':
            enable_colors(false);
            break;
        case 'h':
            if(optarg != NULL) {
                ocg_sub_usage(optarg);
            } else {
                ocg_usage(argc, argv);
            }
            return -1;
            break;

        case 'v':
            amxc_var_add_key(bool, config, "verbose", true);
            break;

        default:
            printf("?? getopt returned character code 0%o ??\n", c);
        }
    }

    return optind;
}

int ocg_config_load(amxo_parser_t* parser) {
    int rv = 0;
    struct stat sb;
    const char* cfg_file = GET_CHAR(amxo_parser_get_config(parser, "config-file"), NULL);
    amxd_dm_t dm;

    amxd_dm_init(&dm);

    if(stat(cfg_file, &sb) == 0) {
        rv = amxo_parser_parse_file(parser, cfg_file, amxd_dm_get_root(&dm));
    }

    amxd_dm_clean(&dm);

    return rv;
}

void ocg_config_changed(amxo_parser_t* parser, int section_id) {
    bool verbose = amxc_var_dyncast(bool,
                                    amxo_parser_get_config(parser, "verbose"));

    if(section_id != 0) {
        return;
    }

    ocg_verbose_logging(parser, verbose);
    ocg_generators(parser);
    ocg_dump_config(parser);
}

int ocg_apply_config(amxo_parser_t* parser,
                     amxc_var_t* config) {
    int retval = 0;
    bool import_resolve = GET_BOOL(config, "import-resolve");
    const amxc_htable_t* options = amxc_var_constcast(amxc_htable_t, config);
    amxc_var_t* var = NULL;

    amxc_htable_for_each(it, options) {
        amxc_var_t* option = amxc_var_from_htable_it(it);
        const char* key = amxc_htable_it_get_key(it);
        retval = amxo_parser_set_config(parser, key, option);
    }

    ocg_config_set_default_dirs(parser);

    if(!import_resolve) {
        var = amxo_parser_claim_config(parser, "odl-resolve");
        amxc_var_set(bool, var, false);
        var = amxo_parser_claim_config(parser, "odl-import");
        amxc_var_set(bool, var, false);
    }

    return retval;
}

void ocg_config_remove_generators(amxo_parser_t* parser) {
    amxc_var_t* gens = amxo_parser_get_config(parser, "generators");

    amxc_var_clean(gens);
    amxc_var_set_type(gens, AMXC_VAR_ID_HTABLE);
    ocg_config_changed(parser, 0);
}