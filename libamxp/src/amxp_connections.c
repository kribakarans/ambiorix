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

#include <string.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_connection.h>

static amxc_llist_t listeners;
static amxc_llist_t connections;

static amxp_connection_t* amxp_connection_get_internal(amxc_llist_t* list,
                                                       int fd) {
    amxp_connection_t* con = NULL;

    amxc_llist_for_each(it, list) {
        con = amxc_llist_it_get_data(it, amxp_connection_t, it);
        if(con->fd == fd) {
            break;
        }
        con = NULL;
    }

    return con;
}

static int amxp_can_add_connection(int fd,
                                   uint32_t type) {
    int retval = -1;
    amxp_connection_t* con = NULL;

    if(type == AMXP_CONNECTION_LISTEN) {
        con = amxp_connection_get_internal(&listeners, fd);
    } else {
        con = amxp_connection_get_internal(&connections, fd);
    }

    retval = con == NULL ? 0 : -1;

    return retval;
}

static int amxp_connection_add_impl(amxp_connection_t* con,
                                    amxp_fd_cb_t reader) {
    int retval = -1;
    amxc_var_t var_fd;

    amxc_var_init(&var_fd);
    amxc_var_set(fd_t, &var_fd, con->fd);

    con->reader = reader;
    if(con->type == AMXP_CONNECTION_LISTEN) {
        amxc_llist_append(&listeners, &con->it);
        amxp_sigmngr_trigger_signal(NULL, "listen-added", &var_fd);
    } else {
        amxc_llist_append(&connections, &con->it);
        amxp_sigmngr_trigger_signal(NULL, "connection-added", &var_fd);
    }

    retval = 0;

    amxc_var_clean(&var_fd);
    return retval;
}

static void amxp_connection_free(amxc_llist_it_t* it) {
    amxp_connection_t* con = amxc_llist_it_get_data(it, amxp_connection_t, it);
    free(con->uri);
    free(con);
}

int amxp_connection_add(int fd,
                        amxp_fd_cb_t reader,
                        const char* uri,
                        uint32_t type,
                        void* priv) {
    int retval = -1;
    amxp_connection_t* con = NULL;

    when_null(reader, exit);
    when_true(fd < 0, exit);

    retval = amxp_can_add_connection(fd, type);
    when_failed(retval, exit);

    retval = -1;
    con = (amxp_connection_t*) calloc(1, sizeof(amxp_connection_t));
    when_null(con, exit);

    con->uri = uri == NULL ? NULL : strdup(uri);
    con->fd = fd;
    con->priv = priv;
    con->type = type;

    retval = amxp_connection_add_impl(con, reader);

exit:
    if(retval != 0) {
        free(con);
    }
    return retval;
}

int amxp_connection_wait_write(int fd,
                               amxp_fd_cb_t can_write_cb) {
    int retval = -1;
    amxp_connection_t* con = NULL;
    amxc_var_t var_fd;
    const char* signal = "connection-wait-write";

    amxc_var_init(&var_fd);
    when_true(fd < 0, exit);
    when_null(can_write_cb, exit);

    con = amxp_connection_get_internal(&connections, fd);
    when_null(con, exit);

    amxc_var_set(fd_t, &var_fd, fd);
    amxp_sigmngr_trigger_signal(NULL, signal, &var_fd);
    con->can_write = can_write_cb;

    retval = 0;

exit:
    amxc_var_clean(&var_fd);
    return retval;
}

int amxp_connection_remove(int fd) {
    int retval = -1;
    amxp_connection_t* con = NULL;
    amxc_var_t var_fd;
    const char* signal = "connection-deleted";

    amxc_var_init(&var_fd);

    con = amxp_connection_get_internal(&connections, fd);
    if(con == NULL) {
        signal = "listen-deleted";
        con = amxp_connection_get_internal(&listeners, fd);
    }
    when_null(con, exit);

    amxc_var_set(fd_t, &var_fd, fd);
    amxp_sigmngr_trigger_signal(NULL, signal, &var_fd);
    amxc_llist_it_clean(&con->it, amxp_connection_free);

    retval = 0;

exit:
    amxc_var_clean(&var_fd);
    return retval;
}

amxp_connection_t* amxp_connection_get(int fd) {
    amxp_connection_t* con = NULL;

    con = amxp_connection_get_internal(&connections, fd);
    if(con != NULL) {
        goto exit;
    }
    con = amxp_connection_get_internal(&listeners, fd);

exit:
    return con;
}

amxp_connection_t* amxp_connection_get_first(uint32_t type) {
    amxp_connection_t* con = NULL;

    amxc_llist_for_each(it, &connections) {
        con = amxc_llist_it_get_data(it, amxp_connection_t, it);
        if(con->type == type) {
            break;
        }
        con = NULL;
    }

    return con;
}

amxp_connection_t* amxp_connection_get_next(amxp_connection_t* con,
                                            uint32_t type) {
    amxc_llist_it_t* it = NULL;
    when_null(con, exit);
    when_true(con->it.llist != &connections, exit);

    it = amxc_llist_it_get_next(&con->it);
    con = NULL;
    while(it) {
        con = amxc_llist_it_get_data(it, amxp_connection_t, it);
        if(con->type == type) {
            break;
        }
        con = NULL;
        it = amxc_llist_it_get_next(it);
    }

exit:
    return con;
}

int amxp_connection_set_el_data(int fd,
                                void* el_data) {
    int retval = -1;
    amxp_connection_t* con = NULL;

    con = amxp_connection_get_internal(&connections, fd);
    if(con == NULL) {
        con = amxp_connection_get_internal(&listeners, fd);
    }

    when_null(con, exit);
    con->el_data = el_data;

    retval = 0;

exit:
    return retval;
}

amxc_llist_t* amxp_connection_get_connections(void) {
    return &connections;
}

amxc_llist_t* amxp_connection_get_listeners(void) {
    return &listeners;
}

DESTRUCTOR static void amxp_connection_cleanup(void) {
    amxc_llist_clean(&connections, amxp_connection_free);
    amxc_llist_clean(&listeners, amxp_connection_free);
}
