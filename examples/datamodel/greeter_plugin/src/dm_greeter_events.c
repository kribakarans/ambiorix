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
#include "dm_greeter.h"

static void emit_state_event(amxd_object_t* greeter, const char* old_state) {
    amxc_var_t data;

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &data, "State", old_state);
    amxd_object_send_changed(greeter, &data, false);
    amxc_var_clean(&data);
}

void _print_event(const char* const sig_name,
                  const amxc_var_t* const data,
                  UNUSED void* const priv) {
    greeter_stats_t* stats = greeter_get_stats();
    stats->events++;
    printf("Signal received - %s\n", sig_name);
    printf("Signal data = \n");
    fflush(stdout);
    if(!amxc_var_is_null(data)) {
        amxc_var_dump(data, STDOUT_FILENO);
    }
}

void _enable_greeter(UNUSED const char* const sig_name,
                     const amxc_var_t* const data,
                     UNUSED void* const priv) {
    amxd_object_t* object = amxd_dm_signal_get_object(greeter_get_dm(), data);
    amxd_param_t* state_param = amxd_object_get_param_def(object, "State");

    // Can not use amxd_object_set_value here or a transaction here,
    // as it will call the validation functions and validation will fail
    // because "Start" => "Running" is not a valid state change.

    // Extra checks can be done to check if the service can be set in "Running"
    // state, otherwise revert to Idle, here just set it to "Running" and
    // emit event.
    amxc_var_set(cstring_t, &state_param->value, "Running");
    emit_state_event(object, "Start");
}

void _disable_greeter(UNUSED const char* const sig_name,
                      const amxc_var_t* const data,
                      UNUSED void* const priv) {
    amxd_object_t* object = amxd_dm_signal_get_object(greeter_get_dm(), data);
    amxd_param_t* state_param = amxd_object_get_param_def(object, "State");

    // Can not use amxd_object_set_value here, as it will call the
    // validation functions.
    // Stop => Idle is not a valid state change.
    amxc_var_set(cstring_t, &state_param->value, "Idle");
    emit_state_event(object, "Stop");
}
