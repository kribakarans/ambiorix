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

#include "cpu_info.h"
#include "dm_cpu_info.h"

void _print_event(const char* const sig_name,
                  const amxc_var_t* const data,
                  UNUSED void* const priv) {
    printf("Signal received - %s\n", sig_name);
    if(data != NULL) {
        printf("Signal data = \n");
        fflush(stdout);
        amxc_var_dump(data, STDOUT_FILENO);
    }
}

void _update_timer(const char* const sig_name,
                   const amxc_var_t* const data,
                   void* const priv) {
    amxd_object_t* cpu_mon = amxd_dm_signal_get_object(cpu_get_dm(), data);
    uint32_t secs = GETP_UINT32(data, "parameters.Interval.to");
    bool periodic_enabled = amxd_object_get_value(bool, cpu_mon, "PeriodicInform", NULL);
    amxp_timer_t* timer = (amxp_timer_t*) cpu_mon->priv;

    if(timer == NULL) {
        amxp_timer_new(&timer, cpu_dm_emit_stats, NULL);
        cpu_mon->priv = timer;
    }

    if(secs == 0) {
        amxp_timer_stop(timer);
        _disable_periodic_inform(sig_name, data, priv);
        goto exit;
    }

    if(periodic_enabled) {
        _disable_periodic_inform(sig_name, data, priv);
        _enable_periodic_inform(sig_name, data, priv);
    }

    amxp_timer_set_interval(timer, secs * 1000);
    amxp_timer_start(timer, 0);

exit:
    return;
}

void _enable_periodic_inform(UNUSED const char* const sig_name,
                             const amxc_var_t* const data,
                             UNUSED void* const priv) {
    amxd_object_t* cpu_mon = amxd_dm_signal_get_object(cpu_get_dm(), data);
    amxd_object_t* cpu_templ = amxd_object_get(cpu_mon, "CPU");
    uint32_t secs = amxd_object_get_value(uint32_t, cpu_mon, "Interval", NULL);

    if(secs == 0) {
        goto exit;
    }

    amxd_object_for_each(instance, obj_it, cpu_templ) {
        amxd_object_t* cpu_inst = amxc_container_of(obj_it, amxd_object_t, it);
        amxd_object_new_pi(cpu_inst, secs);
    }

exit:
    return;
}

void _disable_periodic_inform(UNUSED const char* const sig_name,
                              const amxc_var_t* const data,
                              UNUSED void* const priv) {
    amxd_object_t* cpu_mon = amxd_dm_signal_get_object(cpu_get_dm(), data);
    amxd_object_t* cpu_templ = amxd_object_get(cpu_mon, "CPU");

    amxd_object_for_each(instance, obj_it, cpu_templ) {
        amxd_object_t* cpu_inst = amxc_container_of(obj_it, amxd_object_t, it);
        amxd_object_delete_pi(cpu_inst);
    }
}
