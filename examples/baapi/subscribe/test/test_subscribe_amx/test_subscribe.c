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
#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <unistd.h>

#include "test_subscribe.h"
#include "main.h"

int __wrap_amxrt_connect(void);
int __wrap_amxb_wait_for_object(const char* object);
int __wrap_amxb_subscribe(amxb_bus_ctx_t* const ctx, const char* object, const char* expression, amxp_slot_fn_t slot_cb, void* priv);
amxb_bus_ctx_t* __wrap_amxb_be_who_has(const char* object);

static void call_notification_cb(const amxc_var_t* const data, void* const priv) {
    amxp_slot_fn_t fn = (amxp_slot_fn_t) priv;
    fn("MyObject", data, NULL);
    amxrt_el_stop();
}

int __wrap_amxrt_connect(void) {
    return 0;
}

int __wrap_amxb_wait_for_object(UNUSED const char* object) {
    return (int) mock();
}

int __wrap_amxb_subscribe(UNUSED amxb_bus_ctx_t* const ctx,
                          UNUSED const char* object,
                          UNUSED const char* expression,
                          amxp_slot_fn_t slot_cb,
                          UNUSED void* priv) {
    int retval = (int) mock();
    if(retval == 0) {
        amxc_var_t event_data;
        amxc_var_init(&event_data);
        amxc_var_set_type(&event_data, AMXC_VAR_ID_HTABLE);
        amxc_var_add_key(cstring_t, &event_data, "notification", "dummy-event");
        amxp_sigmngr_deferred_call(NULL, call_notification_cb, &event_data, slot_cb);
        amxc_var_clean(&event_data);
    }
    return retval;
}

amxb_bus_ctx_t* __wrap_amxb_be_who_has(UNUSED const char* object) {
    static amxb_bus_ctx_t fake;
    int retval = mock();

    if(retval == 0) {
        return &fake; // fake address
    } else {
        return NULL;
    }
}

int test_subscribe_setup(UNUSED void** state) {
    return 0;
}

int test_subscribe_teardown(UNUSED void** state) {
    return 0;
}

void test_fails_when_no_path_given(UNUSED void** state) {
    char* argv[] = {"amx-subscribe"};
    assert_int_not_equal(SUBSCRIBE_MAIN(sizeof(argv) / sizeof(argv[0]), argv), 0);
}

void test_can_subscribe(UNUSED void** state) {
    char* argv[] = {"amx-subscribe", "MyObject."};
    will_return(__wrap_amxb_wait_for_object, 0);
    will_return(__wrap_amxb_be_who_has, 0);
    will_return(__wrap_amxb_subscribe, 0);

    amxp_sigmngr_emit_signal(NULL, "wait:done", NULL);
    assert_int_equal(SUBSCRIBE_MAIN(sizeof(argv) / sizeof(argv[0]), argv), 0);
}

void test_can_subscribe_with_expression(UNUSED void** state) {
    char* argv[] = {"amx-subscribe", "MyObject.", "notification == 'dm:object-changed'"};
    will_return(__wrap_amxb_wait_for_object, 0);
    will_return(__wrap_amxb_be_who_has, 0);
    will_return(__wrap_amxb_subscribe, 0);

    amxp_sigmngr_emit_signal(NULL, "wait:done", NULL);
    assert_int_equal(SUBSCRIBE_MAIN(sizeof(argv) / sizeof(argv[0]), argv), 0);
}

void test_stop_when_subscribe_fails(UNUSED void** state) {
    char* argv[] = {"amx-subscribe", "MyObject.", "notification == 'dm:object-changed'"};
    will_return(__wrap_amxb_wait_for_object, 0);
    will_return(__wrap_amxb_be_who_has, 0);
    will_return(__wrap_amxb_subscribe, -1);

    amxp_sigmngr_emit_signal(NULL, "wait:done", NULL);
    assert_int_not_equal(SUBSCRIBE_MAIN(sizeof(argv) / sizeof(argv[0]), argv), 0);
}

void test_stop_when_wait_for_fails(UNUSED void** state) {
    char* argv[] = {"amx-subscribe", "MyObject.", "notification == 'dm:object-changed'"};
    will_return(__wrap_amxb_wait_for_object, -1);

    assert_int_not_equal(SUBSCRIBE_MAIN(sizeof(argv) / sizeof(argv[0]), argv), 0);
}

void test_stop_when_no_bus_ctx_found(UNUSED void** state) {
    char* argv[] = {"amx-subscribe", "MyObject.", "notification == 'dm:object-changed'"};
    will_return(__wrap_amxb_wait_for_object, 0);
    will_return(__wrap_amxb_be_who_has, -1);

    amxp_sigmngr_emit_signal(NULL, "wait:done", NULL);
    assert_int_not_equal(SUBSCRIBE_MAIN(sizeof(argv) / sizeof(argv[0]), argv), 0);
}
