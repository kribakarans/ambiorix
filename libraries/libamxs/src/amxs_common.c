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
#include <string.h>

#include <amxc/amxc.h>

#include <amxs/amxs_types.h>

#include "amxs_priv.h"

static int amxs_validate_attributes_single(int attr) {
    int ret = -1;

    if(((attr & AMXS_SYNC_ONLY_A_TO_B) != 0) &&
       ((attr & AMXS_SYNC_ONLY_B_TO_A) != 0)) {
        goto exit;
    }

    if(((attr & AMXS_SYNC_ONLY_A_TO_B) != 0) &&
       ((attr & AMXS_SYNC_INIT_B) != 0)) {
        goto exit;
    }

    if(((attr & AMXS_SYNC_ONLY_B_TO_A) != 0) &&
       ((attr & AMXS_SYNC_INIT_B) == 0)) {
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}

static int amxs_validate_attributes_hierarchy(int parent_attr, int child_attr) {
    int ret = -1;

    if(((parent_attr & AMXS_SYNC_ONLY_B_TO_A) != 0) &&
       ((child_attr & AMXS_SYNC_ONLY_A_TO_B) != 0)) {
        goto exit;
    }

    if(((parent_attr & AMXS_SYNC_ONLY_A_TO_B) != 0) &&
       ((child_attr & AMXS_SYNC_ONLY_B_TO_A) != 0)) {
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}

amxs_status_t amxs_validate_attributes(int parent_attr, int child_attr) {
    amxs_status_t status = amxs_status_invalid_attr;

    when_failed(amxs_validate_attributes_single(parent_attr), exit);
    when_failed(amxs_validate_attributes_single(child_attr), exit);
    when_failed(amxs_validate_attributes_hierarchy(parent_attr, child_attr), exit);

    status = amxs_status_ok;

exit:
    return status;
}

amxs_status_t amxs_update_child_attributes(int parent_attr, int* child_attr) {
    amxs_status_t status = amxs_status_invalid_attr;
    when_null(child_attr, exit);

    *child_attr |= (parent_attr & (AMXS_SYNC_ONLY_A_TO_B | AMXS_SYNC_ONLY_B_TO_A));

    if((*child_attr & AMXS_SYNC_ONLY_B_TO_A) != 0) {
        *child_attr |= AMXS_SYNC_INIT_B;
    }

    status = amxs_status_ok;

exit:
    return status;
}

void amxs_llist_it_delete_subscription(amxc_llist_it_t* it) {
    amxb_subscription_t* sub = amxc_container_of(it, amxb_subscription_t, it);

    amxb_subscription_delete(&sub);
}

