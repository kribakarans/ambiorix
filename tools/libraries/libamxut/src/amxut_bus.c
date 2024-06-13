/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2023 SoftAtHome
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

#include "amxut/amxut_bus.h"
#include <stdlib.h>
#include <stdio.h>

#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>
#include <amxb/amxb_register.h>
#include <amxd/amxd_dm.h>

#include "debug/sahtrace.h"

#include <stdarg.h> // needed for cmocka
#include <setjmp.h> // needed for cmocka
#include <unistd.h> // needed for cmocka
// Let's not trust users to check error return values and just immediately stop the test on errors.
// We use cmocka's asserts for that.
#include <cmocka.h>

#include "amxut/amxut_sahtrace.h"

#define DUMMY_BUS_SO   "libamxb_dummy.so"
#define DUMMY_BUS_NAME "dummy"

typedef struct {
    amxd_dm_t dm;
    amxo_parser_t parser;
    amxb_bus_ctx_t* bus_ctx;
} amxut_bus_t;

static amxut_bus_t* bus = NULL;


#if !defined(NO_DOXYGEN) // doxygen can not handle the attribute
static void amxut_bus_trace(sah_trace_level lvl, const char* format, ...) __attribute__ ((format(printf, 2, 3)));
#endif
static void amxut_bus_trace(sah_trace_level lvl, const char* format, ...) {
    va_list args;
    va_start(args, format);
    if(sahTraceZoneLevel(sahTraceGetZone("amxut_bus")) >= lvl) {
        vprintf(format, args);
    }
    va_end(args);
}

void amxut_bus_handle_events(void) {
    amxut_bus_trace(TRACE_LEVEL_INFO, "Handling events ");
    while(amxp_signal_read() == 0) {
        amxut_bus_trace(TRACE_LEVEL_INFO, ".");
    }
    amxut_bus_trace(TRACE_LEVEL_INFO, "\n");
}

static void s_connection_read(UNUSED int fd, UNUSED void* priv) {
    // Do nothing
}

int amxut_bus_setup(void** state) {
    int err = -1;
    assert_null(bus);

    // Let's number the steps so it's a lot easier to track which step here corresponds to
    // which step in amxut_bus_teardown.

    // -1: set up sahtrace
    amxut_sahtrace_setup(state);

    // 0: allocate memory
    bus = (amxut_bus_t*) calloc(1, sizeof(amxut_bus_t));

    // 1: init datamodel
    assert_int_equal(amxd_dm_init(&bus->dm), amxd_status_ok);

    // 2: init parser
    assert_int_equal(amxo_parser_init(&bus->parser), 0);

    // 3: load dummy bus backend
    err = amxb_be_load(DUMMY_BUS_SO);
    if(err != 0) {
        fail_msg("Error loading dummy bus backend " DUMMY_BUS_SO ": error %i. Did you install mod-amxb-dummy?", err);
    }

    // 4: add some default signals
    amxp_sigmngr_add_signal(NULL, "connection-added");
    amxp_sigmngr_add_signal(NULL, "listen-added");
    amxp_sigmngr_add_signal(NULL, "connection-deleted");

    // 5: Create dummy/fake bus connections
    assert_int_equal(amxb_connect(&bus->bus_ctx, "dummy:/tmp/dummy.sock"), 0);

    // 6: connect dummy bus backend
    amxo_connection_add(&bus->parser, amxb_get_fd(bus->bus_ctx), s_connection_read, "dummy://", AMXO_BUS, bus->bus_ctx);

    // 7: register data model
    amxb_register(bus->bus_ctx, &bus->dm);

    // 8. Handle any unhandled events
    amxut_bus_handle_events();

    return 0;
}

int amxut_bus_teardown(void** state) {
    assert_non_null(bus);

    // Note: just destroy in the opposite order than in which you created!

    // 8. Handle any unhandled events
    // libamxb might (internally) create events which it assumes will be handled
    // If these are not handled they will leak when the queue is removed
    amxut_bus_handle_events();

    // 7: Cleanup `amxb_register`:
    // From its doc: "To unregister the data model, it is sufficient to close the connection
    //                to the bus system."
    // So do nothing for that.

    // 6 & 5: Cleanup the `amxo_connection_add` and `amxb_connect`
    amxb_free(&bus->bus_ctx);

    // 4: Cleanup signals
    // (skipped for now, but should happen)

    // 3: Cleanup `amxb_be_load`
    assert_int_equal(amxb_be_remove(DUMMY_BUS_NAME), 0);

    // 2: Cleanup the `amxo_parser_init`:
    amxo_parser_clean(&bus->parser);

    // 1: Cleanup the `amxd_dm_init`
    amxd_dm_clean(&bus->dm);

    // 0: Cleanup the `calloc`
    free(bus);
    bus = NULL;

    // -1: Cleanup sahtrace
    amxut_sahtrace_teardown(state);

    return 0;
}

amxd_dm_t* amxut_bus_dm(void) {
    assert_non_null(bus);
    return &bus->dm;
}

amxb_bus_ctx_t* amxut_bus_ctx(void) {
    assert_non_null(bus);
    return bus->bus_ctx;
}

amxo_parser_t* amxut_bus_parser(void) {
    assert_non_null(bus);
    return &bus->parser;
}