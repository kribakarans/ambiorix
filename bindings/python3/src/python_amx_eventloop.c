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
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>

#include <event2/event.h>
#include "python_amx.h"
#include "python_amx_eventloop.h"
#include "python_amx_error_conversion.h"

static struct event_base* base = NULL;
static struct event* signal_int = NULL;
static struct event* signal_term = NULL;
static struct event* signal_alarm = NULL;
static struct event* amxp_sig = NULL;
static struct event* amxp_syssig = NULL;
static bool loop_created = false;


static void eventloop_signal_cb(UNUSED evutil_socket_t fd,
                                UNUSED short event,
                                UNUSED void* arg) {

    eventloop_stop();
}

static void eventloop_read_cb(UNUSED evutil_socket_t fd,
                              UNUSED short flags,
                              void* arg) {
    amxb_bus_ctx_t* bus_ctx = (amxb_bus_ctx_t*) arg;
    amxb_read(bus_ctx);
}

static void eventloop_timers(UNUSED evutil_socket_t fd,
                             UNUSED short event,
                             UNUSED void* arg) {
    amxp_timers_calculate();
    amxp_timers_check();
}

static void el_amxp_signal_read_cb(UNUSED evutil_socket_t fd,
                                   UNUSED short flags,
                                   UNUSED void* arg) {
    amxp_signal_read();
}

static void el_amxp_syssignal_read_cb(UNUSED evutil_socket_t fd,
                                      UNUSED short flags,
                                      UNUSED void* arg) {
    amxp_syssig_read();
}

static void destroy_connection_events() {
    PyObject* list = NULL;
    PyObject* value = NULL;
    PyObject* iterator = NULL;
    if(get_python_amx() != NULL) {
        list = ((PAMXBUSObject*) get_python_amx())->con_list;
        iterator = PyObject_GetIter(list);
        while((value = PyIter_Next(iterator))) {
            PAMXConnectionObject* conn = ((PAMXConnectionObject*) value);
            if(conn->el_data != NULL) {
                event_del(conn->el_data);
                free(conn->el_data);
                conn->el_data = NULL;
            }
            Py_DECREF(value);
        }
        Py_DECREF(iterator);
    }
}

int eventloop_destroy(void) {

    if(signal_int != NULL) {
        event_del(signal_int);
    }
    if(signal_term != NULL) {
        event_del(signal_term);
    }
    if(signal_alarm != NULL) {
        event_del(signal_alarm);
    }
    if(amxp_sig != NULL) {
        event_del(amxp_sig);
    }

    if(amxp_syssig != NULL) {
        event_del(amxp_syssig);
    }

    destroy_connection_events();

    if(base != NULL) {
        event_base_free(base);
        base = NULL;
    }

    free(signal_int);
    signal_int = NULL;
    free(signal_term);
    signal_term = NULL;
    free(signal_alarm);
    signal_alarm = NULL;
    free(amxp_sig);
    amxp_sig = NULL;
    free(amxp_syssig);
    amxp_syssig = NULL;

    loop_created = false;
    return 0;
}

static int create_connection_events() {
    PyObject* list = NULL;
    PyObject* value = NULL;
    PyObject* iterator = NULL;
    int retval = -1;
    if(get_python_amx() != NULL) {
        list = ((PAMXBUSObject*) get_python_amx())->con_list;
        iterator = PyObject_GetIter(list);
        while((value = PyIter_Next(iterator))) {
            PAMXConnectionObject* conn = ((PAMXConnectionObject*) value);
            int fd = amxb_get_fd(conn->bus_ctx);
            if(conn->closed == false) {
                conn->el_data = event_new(base,
                                          fd,
                                          EV_READ | EV_PERSIST,
                                          eventloop_read_cb,
                                          conn->bus_ctx);

                if(conn->el_data == NULL) {
                    printf("el_data creation failed\n");
                    Py_DECREF(value);
                    Py_DECREF(iterator);
                    goto exit;
                }
                event_add(conn->el_data, NULL);
            }
            Py_DECREF(value);
        }
        Py_DECREF(iterator);
    }

    retval = 0;
exit:
    return retval;
}

int eventloop_create() {
    int retval = -1;

    if(loop_created) {
        eventloop_destroy();
    }

    if(base == NULL) {
        base = event_base_new();
    }

    if(base == NULL) {
        printf("Creation of event base failed\n");
        EXIT(retval, -1, exit);
    }

    signal_int = evsignal_new(base,
                              SIGINT,
                              eventloop_signal_cb,
                              NULL);
    event_add(signal_int, NULL);

    signal_term = evsignal_new(base,
                               SIGTERM,
                               eventloop_signal_cb,
                               NULL);
    event_add(signal_term, NULL);

    signal_alarm = evsignal_new(base,
                                SIGALRM,
                                eventloop_timers,
                                NULL);
    event_add(signal_alarm, NULL);

    amxp_sig = event_new(base,
                         amxp_signal_fd(),
                         EV_READ | EV_PERSIST,
                         el_amxp_signal_read_cb,
                         NULL);
    event_add(amxp_sig, NULL);

    amxp_syssig = event_new(base,
                            amxp_syssig_get_fd(),
                            EV_READ | EV_PERSIST,
                            el_amxp_syssignal_read_cb,
                            NULL);
    event_add(amxp_syssig, NULL);


    if(create_connection_events() != 0) {
        eventloop_destroy();
        EXIT(retval, -1, exit);
    }

    loop_created = true;
    retval = 0;
exit:
    return retval;
}

int eventloop_start(void) {

    int retval = 0;
    if(!loop_created) {
        retval = -1;
        goto exit;
    }

    retval = event_base_dispatch(base);

exit:
    return retval;

}

int eventloop_stop(void) {
    int retval = 0;
    if(base != NULL) {
        retval = event_base_loopbreak(base);
    }

    return retval;
}
