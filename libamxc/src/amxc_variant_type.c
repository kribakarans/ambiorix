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
#include <stdint.h>

#include <amxc/amxc_variant_type.h>
#include <amxc_variant_priv.h>
#include <amxc/amxc_macros.h>

static amxc_htable_t amxc_variant_types;
static amxc_array_t amxc_array_types;

/**
   @file
   @brief
   Ambiorix variant type API implementation
 */


static int amxc_var_allocate_types(void) {
    int retval = -1;

    when_failed(amxc_htable_init(&amxc_variant_types, AMXC_VAR_ID_CUSTOM_BASE), exit);
    when_failed(amxc_array_init(&amxc_array_types, AMXC_VAR_ID_CUSTOM_BASE), exit);

    retval = 0;

exit:
    return retval;
}

static void amxc_var_free_types(void) {
    amxc_htable_clean(&amxc_variant_types, NULL);
    amxc_array_clean(&amxc_array_types, NULL);
}

static amxc_array_it_t* amxc_var_next_available_id(void) {
    amxc_array_it_t* ait = amxc_array_get_at(&amxc_array_types, AMXC_VAR_ID_CUSTOM_BASE - 1);
    ait = amxc_array_it_get_next_free(ait);
    return ait;
}

static amxc_array_it_t* amxc_var_get_type_position(const uint32_t index) {
    amxc_array_it_t* ait = NULL;

    if(index == UINT32_MAX) {
        // no index specified - take first free item after fixed types
        ait = amxc_var_next_available_id();
        if(!ait) {
            // no more free positions, grow array and add
            when_failed(amxc_array_grow(&amxc_array_types, 5), exit)
            ait = amxc_var_next_available_id();
        }
    } else {
        // index specified
        // this can be only called from inside (fixed types)
        // no need to check if there is already a type registered here
        ait = amxc_array_get_at(&amxc_array_types, index);
    }

exit:
    return ait;
}

uint32_t PRIVATE amxc_var_add_type(amxc_var_type_t* const type,
                                   const uint32_t index) {
    uint32_t type_id = -1;
    amxc_array_it_t* ait = NULL;
    amxc_htable_it_t* hit = NULL;
    when_null(type, exit);

    hit = amxc_htable_get(&amxc_variant_types, type->name);
    if(hit == &type->hit) {
        type_id = type->type_id;
        goto exit;
    }

    when_not_null(hit, exit);

    // TODO?: move into constructor, this is lib init code
    if(amxc_htable_is_empty(&amxc_variant_types)) {
        // nothing allocated yet - pre-allocate all fixed items
        when_failed(amxc_var_allocate_types(), exit);
    }

    ait = amxc_var_get_type_position(index);
    when_null(ait, exit);

    amxc_array_it_set_data(ait, type);
    amxc_htable_it_init(&type->hit);
    if(amxc_htable_insert(&amxc_variant_types, type->name, &type->hit) == -1) {
        amxc_array_it_take_data(ait);
        goto exit;
    }

    type->type_id = amxc_array_it_index(ait);
    type_id = type->type_id;

exit:
    return type_id;
}

int PRIVATE amxc_var_remove_type(amxc_var_type_t* const type) {
    int retval = -1;
    amxc_array_it_t* it = NULL;
    amxc_htable_it_t* hit = amxc_htable_get(&amxc_variant_types, type->name);
    when_null(hit, exit);
    when_true(hit != &type->hit, exit);

    amxc_htable_it_take(hit);
    amxc_htable_it_clean(hit, NULL);

    it = amxc_array_get_at(&amxc_array_types, type->type_id);
    amxc_array_it_take_data(it);

    type->type_id = AMXC_VAR_ID_MAX;

    // TODO?: move into destructor, this is lib exit code
    // if hash table is empty, no more types are registered, clear buffers
    if(amxc_htable_is_empty(&amxc_variant_types)) {
        amxc_var_free_types();
    }

    retval = 0;

exit:
    return retval;
}

amxc_array_t* amxc_variant_get_types_array(void) {
    return &amxc_array_types;
}

amxc_var_type_t* amxc_var_get_type(uint32_t type_id) {
    amxc_var_type_t* type = NULL;
    amxc_array_it_t* ait = amxc_array_get_at(&amxc_array_types, type_id);
    when_null(ait, exit);

    type = (amxc_var_type_t*) ait->data;

exit:
    return type;
}

uint32_t amxc_var_register_type(amxc_var_type_t* const type) {
    int retval = -1;
    when_null(type, exit);

    retval = amxc_var_add_type(type, AMXC_VAR_ID_MAX);

exit:
    return retval;
}

int amxc_var_unregister_type(amxc_var_type_t* const type) {
    int retval = -1;
    when_null(type, exit);
    when_true(type->type_id < AMXC_VAR_ID_CUSTOM_BASE, exit);

    retval = amxc_var_remove_type(type);

exit:
    return retval;
}

const char* amxc_var_get_type_name_from_id(const uint32_t type_id) {
    const char* name = NULL;
    amxc_var_type_t* type = NULL;
    amxc_array_it_t* ait = amxc_array_get_at(&amxc_array_types, type_id);
    when_null(ait, exit);
    when_null(ait->data, exit);

    type = (amxc_var_type_t*) ait->data;
    name = type->name;

exit:
    return name;
}

uint32_t amxc_var_get_type_id_from_name(const char* const name) {
    uint32_t type_id = AMXC_VAR_ID_MAX;
    amxc_htable_it_t* hit = NULL;
    amxc_var_type_t* type = NULL;
    when_null(name, exit);
    when_true(*name == 0, exit);

    hit = amxc_htable_get(&amxc_variant_types, name);
    when_null(hit, exit);

    type = amxc_htable_it_get_data(hit, amxc_var_type_t, hit);
    type_id = type->type_id;

exit:
    return type_id;
}
