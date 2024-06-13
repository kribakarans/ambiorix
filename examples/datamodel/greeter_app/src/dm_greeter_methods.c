/****************************************************************************
**
** Copyright (c) 2020 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "greeter.h"
#include "greeter_dm_funcs.h"

static uint32_t remove_oldest_history(amxd_object_t* history_obj,
                                      uint32_t count) {
    amxd_trans_t transaction;
    amxd_dm_t* dm = amxd_object_get_dm(history_obj);
    greeter_stats_t* stats = greeter_get_stats();

    amxd_trans_init(&transaction);
    amxd_trans_set_attr(&transaction, amxd_tattr_change_ro, true);

    amxd_trans_select_object(&transaction, history_obj);

    amxd_object_for_each(instance, it, history_obj) {
        amxd_object_t* inst = amxc_llist_it_get_data(it, amxd_object_t, it);
        bool retain = amxd_object_get_value(bool, inst, "Retain", NULL);
        if(retain) {
            continue;
        }
        amxd_trans_del_inst(&transaction, amxd_object_get_index(inst), NULL);
        count--;
        stats->del_history++;
        if(count == 0) {
            break;
        }
    }

    amxd_trans_apply(&transaction, dm);
    amxd_trans_clean(&transaction);
    return count;
}

static bool add_message_history(amxd_object_t* greeter_obj,
                                amxc_var_t* from,
                                amxc_var_t* msg,
                                amxc_var_t* retain) {
    bool retval = false;
    amxd_dm_t* dm = amxd_object_get_dm(greeter_obj);
    uint32_t max_history = 0;
    amxd_object_t* history_obj = amxd_object_get_child(greeter_obj, "History");
    uint32_t current_instances = amxd_object_get_instance_count(history_obj);
    greeter_stats_t* stats = greeter_get_stats();
    amxd_trans_t transaction;
    amxd_trans_init(&transaction);
    amxd_trans_set_attr(&transaction, amxd_tattr_change_ro, true);

    max_history = amxd_object_get_value(uint32_t, greeter_obj, "MaxHistory", NULL);

    if(current_instances >= max_history) {
        if(remove_oldest_history(history_obj, 1) != 0) {
            goto exit;
        }
    }

    amxd_trans_select_object(&transaction, history_obj);
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_param(&transaction, "From", from);
    amxd_trans_set_param(&transaction, "Message", msg);
    amxd_trans_set_param(&transaction, "Retain", retain);
    if(amxd_trans_apply(&transaction, dm) != amxd_status_ok) {
        goto exit;
    }

    stats->add_history++;
    retval = true;

exit:
    amxd_trans_clean(&transaction);
    return retval;
}

static bool is_running(amxd_object_t* greeter_obj) {
    amxd_param_t* state_param = amxd_object_get_param_def(greeter_obj, "State");
    const char* state = amxc_var_constcast(cstring_t, &state_param->value);

    return (strcmp(state, "Running") == 0);
}

amxd_status_t _function_dump(amxd_object_t* object,
                             amxd_function_t* func,
                             amxc_var_t* args,
                             amxc_var_t* ret) {
    char* path = amxd_object_get_path(object, AMXD_OBJECT_NAMED);
    printf("Function call: \n");
    printf("Object   - %s\n", path);
    printf("Function - %s\n", amxd_function_get_name(func));
    amxc_var_copy(ret, args);
    if(args != NULL) {
        fflush(stdout);
        amxc_var_dump(args, STDOUT_FILENO);
    }
    free(path);
    return amxd_status_ok;
}

amxd_status_t _Greeter_say(amxd_object_t* greeter,
                           UNUSED amxd_function_t* func,
                           amxc_var_t* args,
                           amxc_var_t* ret) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* from = GET_ARG(args, "from");
    amxc_var_t* msg = GET_ARG(args, "message");
    amxc_var_t* retain = GET_ARG(args, "retain");
    char* from_txt = amxc_var_dyncast(cstring_t, from);
    char* msg_txt = amxc_var_dyncast(cstring_t, msg);

    if(!is_running(greeter)) {
        printf("!! service is not running !!\n");
        goto exit;
    }

    if(!add_message_history(greeter, from, msg, retain)) {
        goto exit;
    }

    printf("==> %s says '%s'\n", from_txt, msg_txt);
    fflush(stdout);
    amxc_var_set(cstring_t, ret, msg_txt);

    status = amxd_status_ok;
exit:
    free(from_txt);
    free(msg_txt);
    return status;
}

amxd_status_t _History_clear(amxd_object_t* history,
                             UNUSED amxd_function_t* func,
                             amxc_var_t* args,
                             amxc_var_t* ret) {
    uint32_t count = 0;
    amxd_dm_t* dm = amxd_object_get_dm(history);
    amxd_trans_t transaction;
    greeter_stats_t* stats = greeter_get_stats();
    amxd_trans_init(&transaction);
    bool force = amxc_var_dyncast(bool, GET_ARG(args, "force"));

    amxd_trans_set_attr(&transaction, amxd_tattr_change_ro, true);
    amxd_trans_select_object(&transaction, history);
    amxd_object_for_each(instance, it, history) {
        amxd_object_t* inst = amxc_llist_it_get_data(it, amxd_object_t, it);
        bool retain = amxd_object_get_value(bool, inst, "Retain", NULL);
        if(!retain || force) {
            amxd_trans_del_inst(&transaction, amxd_object_get_index(inst), NULL);
            count++;
        }
    }

    if(amxd_trans_apply(&transaction, dm) != amxd_status_ok) {
        count = 0;
    } else {
        stats->del_history += count;
    }
    amxd_trans_clean(&transaction);

    amxc_var_set(uint32_t, ret, count);
    return amxd_status_ok;
}

amxd_status_t _Greeter_setMaxHistory(amxd_object_t* greeter,
                                     UNUSED amxd_function_t* func,
                                     amxc_var_t* args,
                                     amxc_var_t* ret) {
    amxd_object_t* history_obj = amxd_object_get_child(greeter, "History");
    amxd_dm_t* dm = amxd_object_get_dm(greeter);
    uint32_t newmax = 0;
    uint32_t oldmax = 0;
    amxd_trans_t transaction;
    amxd_trans_init(&transaction);
    amxd_trans_set_attr(&transaction, amxd_tattr_change_ro, true);

    oldmax = amxd_object_get_value(uint32_t, greeter, "MaxHistory", NULL);
    newmax = amxc_var_dyncast(uint32_t, GET_ARG(args, "max"));

    if(newmax < oldmax) {
        uint32_t instance_count = amxc_llist_size(&history_obj->instances);
        if(instance_count > newmax) {
            // less allowed, remove oldest until new max can be set
            newmax += remove_oldest_history(history_obj, instance_count - newmax);
        }
    }

    amxd_trans_select_object(&transaction, greeter);
    amxd_trans_set_value(uint32_t, &transaction, "MaxHistory", newmax);
    amxd_trans_apply(&transaction, dm);
    amxd_trans_clean(&transaction);

    amxc_var_set(uint32_t, ret, newmax);
    return amxd_status_ok;
}

amxd_status_t _Greeter_save(amxd_object_t* greeter,
                            UNUSED amxd_function_t* func,
                            amxc_var_t* args,
                            amxc_var_t* ret) {
    amxo_parser_t* parser = amxrt_get_parser();
    const char* file = GET_CHAR(args, "file");
    int retval = amxo_parser_save_object(parser, file, greeter, false);
    amxc_var_set(bool, ret, retval == 0);
    return amxd_status_ok;
}

amxd_status_t _Greeter_load(amxd_object_t* greeter,
                            UNUSED amxd_function_t* func,
                            amxc_var_t* args,
                            amxc_var_t* ret) {
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();
    const char* file = GET_CHAR(args, "file");
    int retval = 0;
    amxd_object_t* history = amxd_object_findf(greeter, "History");
    amxc_var_t clear_args;

    amxc_var_init(&clear_args);
    amxc_var_set_type(&clear_args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &clear_args, "force", true);
    amxd_object_invoke_function(history, "clear", &clear_args, ret);
    amxc_var_clean(&clear_args);

    retval = amxo_parser_parse_file(parser, file, amxd_dm_get_root(dm));
    amxc_var_set(bool, ret, retval == 0);
    return amxd_status_ok;
}

amxd_status_t _periodic_inform(amxd_object_t* object,
                               UNUSED amxd_function_t* func,
                               amxc_var_t* args,
                               amxc_var_t* ret) {
    int secs = amxc_var_dyncast(uint32_t, GET_ARG(args, "secs"));
    amxd_status_t status = amxd_status_ok;

    if(secs == 0) {
        status = amxd_object_delete_pi(object);
    } else {
        status = amxd_object_new_pi(object, secs);
    }

    amxc_var_clean(ret);

    return status;
}

amxd_status_t _Statistics_reset(UNUSED amxd_object_t* object,
                                UNUSED amxd_function_t* func,
                                UNUSED amxc_var_t* args,
                                amxc_var_t* ret) {
    greeter_stats_t* stats = greeter_get_stats();

    stats->add_history = 0;
    stats->del_history = 0;
    stats->events = 0;

    amxc_var_clean(ret);
    return amxd_status_ok;
}
