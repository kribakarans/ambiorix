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
#include <string.h>
#include <signal.h>

#include <event2/event.h>

#include <amxrt/amxrt.h>
#include "amxrt_priv.h"

static struct event_base* base = NULL;

typedef struct _el_data {
    struct event* read;
    struct event* can_write;
    amxc_llist_it_t it;
} el_data_t;

static void amxrt_el_free_event_source(amxc_llist_it_t* it) {
    el_data_t* el_data = amxc_container_of(it, el_data_t, it);
    if(el_data->read != NULL) {
        event_del(el_data->read);
        free(el_data->read);
    }
    if(el_data->can_write != NULL) {
        event_del(el_data->can_write);
        free(el_data->can_write);
    }

    free(el_data);
}

static void amxrt_el_add_event_source(struct event* source, amxp_connection_t* con) {
    amxrt_t* rt = amxrt_get();
    el_data_t* el_data = (el_data_t*) calloc(1, sizeof(el_data_t));
    el_data->read = source;
    event_add(source, NULL);

    if(con != NULL) {
        con->el_data = el_data;
    }

    amxc_llist_append(&rt->event_sources, &el_data->it);
}

static void amxrt_el_signal_cb(UNUSED evutil_socket_t fd,
                               UNUSED short event,
                               UNUSED void* arg) {
    amxrt_el_stop();
}

static void amxrt_el_signal_timers(UNUSED evutil_socket_t fd,
                                   UNUSED short event,
                                   UNUSED void* arg) {
    amxp_timers_calculate();
    amxp_timers_check();
}

static void amxrt_el_connection_read_cb(UNUSED evutil_socket_t fd,
                                        UNUSED short flags,
                                        void* arg) {
    amxp_connection_t* con = (amxp_connection_t*) arg;
    con->reader(fd, con->priv);
}

static void amxrt_el_connection_can_write_cb(UNUSED evutil_socket_t fd,
                                             UNUSED short flags,
                                             void* arg) {
    amxp_connection_t* con = (amxp_connection_t*) arg;
    el_data_t* el_data = (el_data_t*) con->el_data;
    amxo_fd_cb_t cb = con->can_write;

    con->can_write = NULL;
    event_del(el_data->can_write);
    free(el_data->can_write);
    el_data->can_write = NULL;

    cb(fd, con->priv);
}

static void amxrt_el_amxp_signal_read_cb(UNUSED evutil_socket_t fd,
                                         UNUSED short flags,
                                         UNUSED void* arg) {
    amxp_signal_read();
}

static void amxrt_el_amxp_syssignal_read_cb(UNUSED evutil_socket_t fd,
                                            UNUSED short flags,
                                            UNUSED void* arg) {
    amxp_syssig_read();
}

static void amxrt_el_slot_add_fd(UNUSED const char* const sig_name,
                                 const amxc_var_t* const data,
                                 UNUSED void* const priv) {
    amxp_connection_t* con = NULL;
    struct event* source = NULL;

    when_true(amxc_var_type_of(data) != AMXC_VAR_ID_FD, leave);

    con = amxp_connection_get(amxc_var_constcast(fd_t, data));
    when_null(con, leave);

    source = event_new(base, con->fd, EV_READ | EV_PERSIST, amxrt_el_connection_read_cb, con);
    amxrt_el_add_event_source(source, con);

leave:
    return;
}

static void amxrt_el_slot_wait_write_fd(UNUSED const char* const sig_name,
                                        const amxc_var_t* const data,
                                        UNUSED void* const priv) {
    amxp_connection_t* con = NULL;
    el_data_t* el_data = NULL;

    when_true(amxc_var_type_of(data) != AMXC_VAR_ID_FD, leave);

    con = amxp_connection_get(amxc_var_constcast(fd_t, data));
    when_null(con, leave);

    el_data = (el_data_t*) con->el_data;
    when_null(el_data, leave);
    if(el_data->can_write != NULL) {
        event_del(el_data->can_write);
        free(el_data->can_write);
    }
    el_data->can_write = event_new(base,
                                   con->fd,
                                   EV_WRITE,
                                   amxrt_el_connection_can_write_cb,
                                   con);
    event_add(el_data->can_write, NULL);

leave:
    return;
}

static void amxrt_el_slot_remove_fd(UNUSED const char* const sig_name,
                                    const amxc_var_t* const data,
                                    UNUSED void* const priv) {
    amxc_llist_t* connections = amxp_connection_get_connections();
    amxp_connection_t* con = NULL;

    when_true(amxc_var_type_of(data) != AMXC_VAR_ID_FD, leave);

    con = amxrt_el_get_connection(connections, amxc_var_constcast(fd_t, data));
    if(con == NULL) {
        connections = amxp_connection_get_listeners();
        con = amxrt_el_get_connection(connections, amxc_var_constcast(fd_t, data));
    }
    when_null(con, leave);

    if(con->el_data != NULL) {
        el_data_t* el_data = (el_data_t*) con->el_data;
        if(el_data != NULL) {
            amxc_llist_it_clean(&el_data->it, amxrt_el_free_event_source);
        }
        con->el_data = NULL;
    }

leave:
    return;
}

static void amxrt_el_add_read_fd(amxc_llist_t* connections) {
    struct event* source = NULL;

    amxc_llist_for_each(it, connections) {
        amxp_connection_t* con = amxc_llist_it_get_data(it, amxp_connection_t, it);
        source = event_new(base, con->fd, EV_READ | EV_PERSIST, amxrt_el_connection_read_cb, con);
        amxrt_el_add_event_source(source, con);
    }
}

static void amxrt_el_remove_fd(amxc_llist_t* connections) {
    amxc_llist_for_each(it, connections) {
        amxp_connection_t* con = amxc_llist_it_get_data(it, amxp_connection_t, it);
        el_data_t* el_data = (el_data_t*) con->el_data;
        if(el_data != NULL) {
            amxc_llist_it_clean(&el_data->it, amxrt_el_free_event_source);
        }
        con->el_data = NULL;
    }
}

amxp_connection_t* amxrt_el_get_connection(amxc_llist_t* cons, int fd) {
    amxp_connection_t* con = NULL;
    amxc_llist_for_each(it, cons) {
        con = amxc_llist_it_get_data(it, amxp_connection_t, it);
        if(con->fd == fd) {
            break;
        }
        con = NULL;
    }

    return con;
}

int amxrt_el_create(void) {
    amxo_parser_t* parser = amxrt_get_parser();
    int retval = -1;
    struct event* event_source = NULL;

    base = event_base_new();
    when_null(base, leave);

    event_source = evsignal_new(base, SIGINT, amxrt_el_signal_cb, NULL);
    amxrt_el_add_event_source(event_source, NULL);

    event_source = evsignal_new(base, SIGTERM, amxrt_el_signal_cb, NULL);
    amxrt_el_add_event_source(event_source, NULL);

    event_source = evsignal_new(base, SIGALRM, amxrt_el_signal_timers, NULL);
    amxrt_el_add_event_source(event_source, NULL);

    event_source = event_new(base, amxp_signal_fd(), EV_READ | EV_PERSIST, amxrt_el_amxp_signal_read_cb, NULL);
    amxrt_el_add_event_source(event_source, NULL);

    event_source = event_new(base, amxp_syssig_get_fd(), EV_READ | EV_PERSIST, amxrt_el_amxp_syssignal_read_cb, NULL);
    amxrt_el_add_event_source(event_source, NULL);

    amxrt_el_add_read_fd(amxp_connection_get_connections());
    amxrt_el_add_read_fd(amxp_connection_get_listeners());

    amxp_slot_connect(NULL, "connection-added", NULL, amxrt_el_slot_add_fd, parser);
    amxp_slot_connect(NULL, "connection-wait-write", NULL, amxrt_el_slot_wait_write_fd, parser);
    amxp_slot_connect(NULL, "listen-added", NULL, amxrt_el_slot_add_fd, parser);
    amxp_slot_connect(NULL, "connection-deleted", NULL, amxrt_el_slot_remove_fd, parser);
    amxp_slot_connect(NULL, "listen-deleted", NULL, amxrt_el_slot_remove_fd, parser);

    retval = 0;

leave:
    return retval;
}

int amxrt_el_start(void) {
    int retval = -1;
    amxd_dm_t* dm = amxrt_get_dm();

    if(base != NULL) {
        retval = event_base_dispatch(base);
    }

    amxp_sigmngr_trigger_signal(&dm->sigmngr, "app:stop", NULL);
    amxp_sigmngr_trigger_signal(NULL, "wait:cancel", NULL);

    return retval;
}

int amxrt_el_stop(void) {
    int retval = -1;
    if(base != NULL) {
        retval = event_base_loopbreak(base);
    }
    return retval;
}

int amxrt_el_destroy(void) {
    amxrt_t* rt = amxrt_get();

    amxp_slot_disconnect(NULL, "connection-added", amxrt_el_slot_add_fd);
    amxp_slot_disconnect(NULL, "listen-added", amxrt_el_slot_add_fd);
    amxp_slot_disconnect(NULL, "connection-deleted", amxrt_el_slot_remove_fd);

    amxrt_el_remove_fd(amxp_connection_get_connections());
    amxrt_el_remove_fd(amxp_connection_get_listeners());

    amxc_llist_clean(&rt->event_sources, amxrt_el_free_event_source);

    if(base != NULL) {
        event_base_free(base);
        base = NULL;
    }

    return 0;
}
