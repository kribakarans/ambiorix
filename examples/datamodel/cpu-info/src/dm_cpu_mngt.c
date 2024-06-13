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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cpu_info.h"
#include "dm_cpu_info.h"

static uint64_t cpu_dm_calc_usage(cpu_usage_t* old, cpu_usage_t* cur) {
    uint64_t percentage = 0;
    uint64_t owj = old->user + old->nice + old->system;
    uint64_t otj = owj + old->idle + old->iowait + old->irq + old->softirq;

    uint64_t nwj = cur->user + cur->nice + cur->system;
    uint64_t ntj = nwj + cur->idle + cur->iowait + cur->irq + cur->softirq;
    percentage = ((nwj - owj) * 100);
    if((ntj - otj) != 0) {
        percentage /= (ntj - otj);
    } else {
        percentage = 999;
    }
    return percentage;
}

static int32_t cpu_dm_get_id(amxd_object_t* cpu_instance) {
    int32_t id = -1;
    if(cpu_instance != NULL) {
        id = amxd_object_get_index(cpu_instance) - 1;
    }

    return id;
}

static cpu_usage_t* cpu_dm_get_prev_data(amxd_object_t* cpu_instance,
                                         amxd_param_t* usage) {
    cpu_usage_t* data = NULL;
    if(cpu_instance != NULL) {
        data = (cpu_usage_t*) cpu_instance->priv;
    } else {
        data = (cpu_usage_t*) usage->priv;
    }

    return data;
}

static cpu_usage_t* cpu_dm_allocate_data(amxd_object_t* cpu_instance,
                                         amxd_param_t* usage) {
    cpu_usage_t* data = (cpu_usage_t*) calloc(1, sizeof(cpu_usage_t));
    if(cpu_instance != NULL) {
        cpu_instance->priv = data;
    } else {
        usage->priv = data;
    }

    return data;
}

void cpu_dm_add_objects(void) {
    amxc_var_t cpu_data;
    amxd_dm_t* dm = cpu_get_dm();
    amxd_object_t* cpu_templ = amxd_dm_findf(dm, "CPUMonitor.CPU.");
    amxd_trans_t transaction;

    amxd_trans_init(&transaction);
    amxd_trans_set_attr(&transaction, amxd_tattr_change_ro, true);
    amxc_var_init(&cpu_data);
    cpu_info_read(&cpu_data, -1);

    amxc_var_for_each(var, (&cpu_data)) {
        amxc_var_t* var_id = amxc_var_get_key(var, "ID", AMXC_VAR_FLAG_DEFAULT);
        uint32_t id = amxc_var_dyncast(uint32_t, var_id);
        amxd_trans_select_object(&transaction, cpu_templ);
        amxd_trans_add_inst(&transaction, id + 1, NULL);
    }

    amxd_trans_apply(&transaction, dm);
    amxc_var_clean(&cpu_data);
    amxd_trans_clean(&transaction);
}

// this function is called from within object & parameter
// action implementations and therefor it is limmited in the possibility
// to read/write objects and/or parameters.
uint64_t cpu_dm_get_stats(amxd_object_t* cpu_instance,
                          amxd_param_t* usage) {
    cpu_usage_t usage_data;
    int32_t id = cpu_dm_get_id(cpu_instance);
    cpu_usage_t* prev_udata = cpu_dm_get_prev_data(cpu_instance, usage);
    uint64_t percentage = 0;

    cpu_stats_read(&usage_data, id);
    if(prev_udata == NULL) {
        prev_udata = cpu_dm_allocate_data(cpu_instance, usage);
    } else {
        percentage = cpu_dm_calc_usage(prev_udata, &usage_data);
    }
    memcpy(prev_udata, &usage_data, sizeof(cpu_usage_t));
    return percentage;
}

void cpu_dm_emit_stats(UNUSED amxp_timer_t* timer, UNUSED void* priv) {
    amxc_var_t cpu_usage;
    amxc_var_t* cpus = NULL;
    amxd_object_t* cpu = amxd_dm_findf(cpu_get_dm(), "CPUMonitor.");
    amxd_object_t* cpu_templ = amxd_object_findf(cpu, "CPU.");
    uint64_t percent = 0;

    amxc_var_init(&cpu_usage);
    amxc_var_set_type(&cpu_usage, AMXC_VAR_ID_HTABLE);
    percent = amxd_object_get_value(uint64_t, cpu, "Usage", NULL);
    amxc_var_add_key(uint64_t, &cpu_usage, "Usage", percent);

    cpus = amxc_var_add_key(amxc_llist_t, &cpu_usage, "CPUs", NULL);
    amxd_object_for_each(instance, obj_it, cpu_templ) {
        amxd_object_t* cpu_inst = amxc_container_of(obj_it, amxd_object_t, it);
        percent = amxd_object_get_value(uint64_t, cpu_inst, "Usage", NULL);
        amxc_var_add(uint64_t, cpus, percent);
    }

    amxd_object_emit_signal(cpu, "cpu:usage", &cpu_usage);

    amxc_var_clean(&cpu_usage);
}