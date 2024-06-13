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
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <syslog.h>
#include <cap-ng.h>

#include <amxrt/amxrt.h>

#include "amxrt_priv.h"

static amxrt_t rt;

static bool amxrt_file_exists(const char* filename) {
    struct stat buffer;

    return (stat(filename, &buffer) == 0);
}

static int amxrt_parse_odl_string(amxo_parser_t* parser,
                                  amxd_object_t* root) {
    const char* odl_str = NULL;
    int retval = 0;

    odl_str = amxc_var_constcast(cstring_t, GET_ARG(&parser->config, AMXRT_COPT_ODL));
    if(odl_str != NULL) {
        retval = amxo_parser_parse_string(parser, odl_str, root);
        if(retval != 0) {
            amxrt_print_failure(parser, odl_str);
        }
    }

    return retval;
}

static int amxrt_parse_odl_extensions(amxo_parser_t* parser, amxd_object_t* root) {
    int retval = 0;

    const char* ext_dir = GET_CHAR(&parser->config, AMXRT_COPT_EXT_DIR);
    amxc_string_t opt_include;

    amxc_string_init(&opt_include, 0);
    when_str_empty(ext_dir, exit);

    amxc_string_setf(&opt_include, "#include '%s';", ext_dir);

    retval = amxo_parser_parse_string(parser, amxc_string_get(&opt_include, 0), root);

exit:
    amxc_string_clean(&opt_include);
    return retval;
}

static int amxrt_try_default_odl(amxo_parser_t* parser, amxd_object_t* root) {
    char* name = amxc_var_dyncast(cstring_t, GET_ARG(&parser->config, AMXRT_COPT_NAME));
    char* prefix = amxc_var_dyncast(cstring_t, GET_ARG(&parser->config, AMXRT_COPT_PREFIX_PATH));
    char* cfg_dir = amxc_var_dyncast(cstring_t, GET_ARG(&parser->config, AMXRT_COPT_CFG_DIR));
    struct stat sb;
    int retval = 0;

    amxc_string_t include;
    amxc_string_init(&include, 32);
    amxc_string_appendf(&include, "%s/%s/%s/%s.odl", prefix, cfg_dir, name, name);

    if(stat(amxc_string_get(&include, 0), &sb) == 0) {
        retval = amxo_parser_parse_file(parser, amxc_string_get(&include, 0), root);
        if(retval != 0) {
            amxrt_print_failure(parser, amxc_string_get(&include, 0));
        }
    }
    amxc_string_clean(&include);

    free(cfg_dir);
    free(prefix);
    free(name);

    return retval;
}

static int amxrt_parse_odl_files(amxo_parser_t* parser,
                                 int argc,
                                 char* argv[],
                                 int index,
                                 amxd_object_t* root) {
    int retval = 0;

    if(index >= argc) {
        retval = amxrt_try_default_odl(parser, root);
    } else {
        while(index < argc) {
            retval = amxo_parser_parse_file(parser, argv[index++], root);
            if(retval != 0) {
                amxrt_print_failure(parser, argv[index - 1]);
                break;
            }
        }
    }

    return retval;
}

static int amxrt_create_pid_file(pid_t pid, const char* name) {
    amxc_string_t pidfile;
    int retval = -1;
    FILE* pf = NULL;

    amxc_string_init(&pidfile, 64);

    // create pidfile
    amxc_string_appendf(&pidfile, "/var/run/%s.pid", name);
    pf = fopen(amxc_string_get(&pidfile, 0), "w");
    if((pf == NULL) && (errno == EACCES)) {
        amxc_string_reset(&pidfile);
        amxc_string_appendf(&pidfile, "/var/run/%s/%s.pid", name, name);
        pf = fopen(amxc_string_get(&pidfile, 0), "w");
    }
    if(pf != NULL) {
        fprintf(pf, "%d", pid);
        fflush(pf);
        fclose(pf);
        retval = 0;
    } else {
        amxrt_print_error("Failed to create pidfile");
    }

    amxc_string_clean(&pidfile);
    return retval;
}

static void amxrt_remove_pid_file(const char* name) {
    amxc_string_t pidfile;
    amxc_string_init(&pidfile, 64);

    amxc_string_appendf(&pidfile, "/var/run/%s.pid", name);
    if(!amxrt_file_exists(amxc_string_get(&pidfile, 0))) {
        amxc_string_reset(&pidfile);
        amxc_string_appendf(&pidfile, "/var/run/%s/%s.pid", name, name);
    }

    if(amxrt_file_exists(amxc_string_get(&pidfile, 0))) {
        unlink(amxc_string_get(&pidfile, 0));
    }

    amxc_string_clean(&pidfile);
}

static int amxrt_apply_process_settings(amxo_parser_t* parser) {
    int retval = 0;
    int pid = -1;
    bool pidfile = amxc_var_dyncast(bool, GET_ARG(&parser->config, AMXRT_COPT_PID_FILE));
    char* name = amxc_var_dyncast(cstring_t, GET_ARG(&parser->config, AMXRT_COPT_NAME));

    int priority = amxc_var_dyncast(uint32_t, GET_ARG(&parser->config, AMXRT_COPT_PRIORITY));

    pid = getpid();
    retval = setpriority(PRIO_PROCESS, pid, priority);
    when_failed(retval, leave);

    if(pidfile && (name != NULL)) {
        amxrt_create_pid_file(pid, name);
    }

    if(GET_BOOL(&parser->config, AMXRT_COPT_LOG) &&
       ( GET_CHAR(&parser->config, AMXRT_COPT_NAME) != NULL)) {
        openlog(GET_CHAR(&parser->config, AMXRT_COPT_NAME), LOG_CONS | LOG_PID, LOG_USER);
        syslog(LOG_USER | LOG_INFO, "** MARK **");
    }

    retval = amxrt_caps_apply();

leave:
    free(name);
    return retval;
}

static int amxrt_register(amxo_parser_t* parser, amxd_dm_t* dm) {
    int retval = 0;

    retval = amxrt_connection_register_dm(parser, dm);
    when_failed(retval, leave);
    amxc_var_set(bool, GET_ARG(&parser->config, AMXRT_COPT_EVENT), true);
    if(parser->post_includes != NULL) {
        retval = amxo_parser_invoke_entry_points(parser, dm, AMXO_START);
        when_failed(retval, leave);
        retval = amxo_parser_invoke_entry_points(parser, dm, AMXO_ODL_LOADED);
        when_failed(retval, leave);
    } else {
        retval = amxo_parser_invoke_entry_points(parser, dm, AMXO_START);
        when_failed(retval, leave);
    }

    retval = amxo_parser_start_synchronize(parser);
    if(retval != 0) {
        amxrt_print_error("Runtime - synchronizations failed to start (nr failed = %d)\n", retval);
        amxrt_print_message("Runtime - Are all required objects available?");
    }

leave:
    return retval;
}

static void amxrt_handle_events(amxd_dm_t* dm, amxo_parser_t* parser) {
    bool handle_events = GET_BOOL(&parser->config, AMXRT_COPT_HANDLE_EVENTS);

    if(handle_events) {
        while(amxp_signal_read() == 0) {
        }
    }
    amxp_sigmngr_trigger_signal(&dm->sigmngr, "app:start", NULL);
}

static void amxrt_wait_done(UNUSED const char* const s,
                            UNUSED const amxc_var_t* const d,
                            UNUSED void* const p) {
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* req = GET_ARG(&parser->config, AMXRT_COPT_REQUIRES);

    amxc_var_clean(req);
    amxc_var_set_type(req, AMXC_VAR_ID_LIST);

    amxrt_print_message("RunTime - All required objects available - continue");

    amxp_sigmngr_resume(&dm->sigmngr);

    if(amxrt_register(parser, dm) != 0) {
        amxrt_print_error("Failed to register data model");
        amxrt_el_stop();
    } else {
        amxrt_handle_events(dm, parser);
        amxp_slot_disconnect(NULL, "wait:done", amxrt_wait_done);
    }
}

amxrt_t* amxrt_get(void) {
    return &rt;
}

amxc_var_t* amxrt_get_config(void) {
    return &rt.parser.config;
}

amxo_parser_t* amxrt_get_parser(void) {
    return &rt.parser;
}

amxd_dm_t* amxrt_get_dm(void) {
    return &rt.dm;
}

void amxrt_new(void) {
    amxd_dm_init(&rt.dm);
    amxo_parser_init(&rt.parser);
    amxc_llist_init(&rt.event_sources);
    amxc_llist_init(&rt.cmd_line_args);
    rt.usage_doc = "[OPTIONS] <odl files>";

    // command line options given with -F are stored here and can not be overwritten
    // by odl config section options
    amxc_var_init(&rt.forced_options);
    amxc_var_set_type(&rt.forced_options, AMXC_VAR_ID_HTABLE);

    amxrt_config_add_options(&rt.parser);

    amxp_sigmngr_add_signal(NULL, "config:changed");
    amxp_sigmngr_add_signal(NULL, "wait:done");
    amxp_sigmngr_add_signal(NULL, "wait:cancel");

    amxrt_cmd_line_add_default_options();
}

int amxrt(int argc, char* argv[], amxrt_arg_fn_t fn) {
    int retval = 0;

    retval = amxrt_init(argc, argv, fn);
    when_failed(retval, leave);
    retval = amxrt_register_or_wait();
    when_failed(retval, leave);
    retval = amxrt_run();

leave:
    amxrt_stop();
    return retval;
}

static void amxrt_log(const char* bus_name,
                      const char* dm_op,
                      const char* path,
                      int result) {
    syslog(LOG_USER | LOG_CRIT, "AMXB: Bus = %s, operator = %s, path = %s, result = %d", bus_name, dm_op, path, result);
}

int amxrt_init(int argc, char* argv[], amxrt_arg_fn_t fn) {
    int retval = 0;
    int index = 0;
    amxc_var_t* syssigs = NULL;
    amxo_parser_t* parser = amxrt_get_parser();

    amxc_var_set_type(&rt.forced_options, AMXC_VAR_ID_HTABLE);
    retval = amxrt_config_init(argc, argv, &index, fn);
    when_failed_status(retval, leave, retval = 10);
    retval = amxrt_load_odl_files(argc, argv, index);
    when_failed_status(retval, leave, retval = 11);
    amxrt_config_scan_backend_dirs();

    amxo_parser_add_entry_point(parser, amxrt_dm_save_load_main);

    retval = amxrt_connect();
    when_failed_status(retval, leave, retval = 12);

    if(GET_BOOL(&rt.parser.config, AMXRT_COPT_LOG)) {
        amxb_set_log_cb(amxrt_log);
    }

    if(GET_INT32(&rt.parser.config, AMXRT_COPT_AMXB_INTERNAL_TO) != 0) {
        amxb_set_internal_timeout(GET_INT32(&rt.parser.config, AMXRT_COPT_AMXB_INTERNAL_TO));
    }

    if(GET_INT32(&rt.parser.config, AMXRT_COPT_AMXB_MINIMAL_TO) != 0) {
        amxb_set_minimal_timeout(GET_INT32(&rt.parser.config, AMXRT_COPT_AMXB_MINIMAL_TO));
    }

    syssigs = GET_ARG(&rt.parser.config, "system-signals");
    if(syssigs != NULL) {
        amxrt_enable_syssigs(syssigs);
    }

    retval = amxrt_el_create();
    when_failed_status(retval, leave, retval = -13);

leave:
    return retval;
}

void amxrt_delete(void) {
    amxd_dm_clean(&rt.dm);
    amxo_resolver_import_close_all();
    amxb_be_remove_all();

    amxrt_cmd_line_options_reset();
    amxc_var_clean(&rt.forced_options);

    amxo_parser_clean(&rt.parser);
}

int amxrt_register_or_wait(void) {
    int retval = 0;
    amxc_var_t* req = NULL;
    const amxc_llist_t* lreq = NULL;

    req = GET_ARG(&rt.parser.config, AMXRT_COPT_REQUIRES);
    lreq = amxc_var_constcast(amxc_llist_t, req);

    if((lreq == NULL) || amxc_llist_is_empty(lreq)) {
        retval = amxrt_register(&rt.parser, &rt.dm);
        when_failed_status(retval, leave, retval = -14);
        amxrt_handle_events(&rt.dm, &rt.parser);
    } else {
        if(GET_BOOL(&rt.parser.config, AMXRT_COPT_SUSPEND)) {
            amxp_sigmngr_suspend(&rt.dm.sigmngr);
        }
        amxp_slot_connect(NULL, "wait:done", NULL, amxrt_wait_done, NULL);
        amxc_var_for_each(path, req) {
            const char* txt_path = GET_CHAR(path, NULL);
            if(amxd_dm_findf(&rt.dm, "%s", txt_path) == NULL) {
                amxrt_print_message("RunTime - Waiting for required object '%s'", txt_path);
                retval = amxb_wait_for_object(txt_path);
                if(retval != AMXB_STATUS_OK) {
                    amxrt_print_error("RunTime - Waiting failed for object '%s'", txt_path);
                    break;
                }
            }
        }
    }

    when_failed_status(retval, leave, retval = -14);

leave:
    return retval;
}

int amxrt_run(void) {
    int retval = 0;

    if(GET_BOOL(&rt.parser.config, AMXRT_COPT_DUMP_CONFIG)) {
        amxrt_print_configuration();
    }
    if(GET_BOOL(&rt.parser.config, AMXRT_COPT_DUMP_CAPS)) {
        amxrt_caps_dump();
    }

    amxrt_el_start();

    return retval;
}

void amxrt_stop(void) {
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();
    char* name = amxc_var_dyncast(cstring_t, GET_ARG(&parser->config, AMXRT_COPT_NAME));
    amxc_var_t* req = GET_ARG(&parser->config, AMXRT_COPT_REQUIRES);

    amxrt_el_destroy();

    amxo_parser_stop_synchronize(parser);

    if((req == NULL) || amxc_llist_is_empty(amxc_var_constcast(amxc_llist_t, req))) {
        amxo_parser_rinvoke_entry_points(parser, dm, AMXO_STOP);
    }

    amxb_set_config(NULL);

    amxrt_remove_pid_file(name);

    if(GET_BOOL(&parser->config, AMXRT_COPT_LOG) &&
       ( GET_CHAR(&parser->config, AMXRT_COPT_NAME) != NULL)) {
        closelog();
    }

    free(name);
}

int amxrt_load_odl_files(int argc, char* argv[], int index) {
    int retval = 0;
    amxd_object_t* root = NULL;
    bool dm_eventing_enabled = false;

    dm_eventing_enabled = GET_BOOL(&rt.parser.config, AMXRT_COPT_EVENT);
    amxp_sigmngr_enable(&rt.dm.sigmngr, dm_eventing_enabled);
    root = amxd_dm_get_root(&rt.dm);
    retval = amxrt_parse_odl_string(&rt.parser, root);
    when_failed(retval, leave);
    retval = amxrt_parse_odl_files(&rt.parser, argc, argv, index, root);
    when_failed(retval, leave);
    retval = amxrt_parse_odl_extensions(&rt.parser, root);
    when_failed(retval, leave);

    amxo_parser_scan_mib_dirs(&rt.parser, NULL);
    amxp_sigmngr_enable(&rt.dm.sigmngr, true);

leave:
    return retval;
}

int amxrt_connect(void) {
    int retval = 0;

    retval = amxrt_connection_load_backends(&rt.parser.config);
    when_failed(retval, leave);

    amxrt_connection_detect_sockets(&rt.parser.config);

    // Daemonize before opening sockets
    // Some bus systems requires this.
    // Daemonizing (going to background) changes process id, sometimes the process id
    // is used in the initial handshake
    if(amxc_var_constcast(bool, GET_ARG(&rt.parser.config, AMXRT_COPT_DAEMON))) {
        retval = daemon(1, 0);
        when_failed(retval, leave);
    }

    retval = amxrt_connection_connect_all(&rt.parser);
    when_failed(retval, leave);
    retval = amxrt_connection_listen_all(&rt.parser);
    when_failed(retval, leave);
    retval = amxrt_apply_process_settings(&rt.parser);
    when_failed(retval, leave);

leave:
    return retval;
}

void amxrt_enable_syssigs(amxc_var_t* syssigs) {
    if(amxc_var_type_of(syssigs) == AMXC_VAR_ID_LIST) {
        amxc_var_for_each(var, syssigs) {
            uint32_t sigid = amxc_var_dyncast(uint32_t, var);
            if((sigid != 0) &&
               ( sigid != SIGALRM) &&
               ( sigid != SIGTERM) &&
               ( sigid != SIGINT)) {
                amxp_syssig_enable(sigid, true);
            }
        }
    } else {
        uint32_t sigid = amxc_var_dyncast(uint32_t, syssigs);
        if((sigid != 0) &&
           ( sigid != SIGALRM) &&
           ( sigid != SIGTERM) &&
           ( sigid != SIGINT)) {
            amxp_syssig_enable(sigid, true);
        }
    }
}
