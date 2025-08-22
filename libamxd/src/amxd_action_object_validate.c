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

#include "amxd_priv.h"

#include <amxd/amxd_dm.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_expression.h>

#include "amxd_assert.h"

static bool amxd_object_validate_filter(UNUSED amxd_object_t* const object,
                                        UNUSED int32_t depth,
                                        void* priv) {
    amxd_status_t* status = (amxd_status_t*) priv;
    return (*status == amxd_status_ok);
}

static void amxd_object_validate_impl(amxd_object_t* const object,
                                      UNUSED int32_t depth,
                                      void* priv) {
    amxd_status_t* status = (amxd_status_t*) priv;
    *status = amxd_dm_invoke_action(object,
                                    NULL,
                                    action_object_validate,
                                    NULL,
                                    NULL);
}

static amxd_status_t is_instance_unique(amxd_object_t* object) {
    amxd_object_t* matching_obj = NULL;
    amxd_status_t retval = amxd_status_ok;
    amxd_object_t* templ = amxd_object_get_parent(object);
    amxp_expr_t* expr = NULL;
    amxc_var_t data;
    amxc_var_init(&data);

    amxd_object_get_key_params(object, &data, amxd_dm_access_private);
    amxd_object_new_key_expr(templ, &expr, &data);

    // if no key parameters are defined in the template object the expression will be NULL
    when_null(expr, exit);

    matching_obj = amxd_object_find_instance(templ, expr);
    if(matching_obj == object) {
        matching_obj = amxd_object_find_next_instance(matching_obj, expr);
    }
    when_true_status(matching_obj != NULL, exit, retval = amxd_status_duplicate);

exit:
    amxc_var_clean(&data);
    amxp_expr_delete(&expr);

    return retval;
}


amxd_status_t amxd_action_object_validate(amxd_object_t* const object,
                                          UNUSED amxd_param_t* const p,
                                          amxd_action_t reason,
                                          UNUSED const amxc_var_t* const args,
                                          UNUSED amxc_var_t* const retval,
                                          UNUSED void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    when_null(object, exit);
    when_true_status(reason != action_object_validate,
                     exit,
                     status = amxd_status_function_not_implemented);

    if(amxd_object_get_type(object) == amxd_object_instance) {
        status = is_instance_unique(object);
    } else {
        status = amxd_status_ok;
    }

exit:
    return status;
}

amxd_status_t amxd_object_validate(amxd_object_t* const object,
                                   int32_t depth) {
    amxd_status_t status = amxd_status_ok;

    when_null(object, exit);

    amxd_object_hierarchy_walk(object,
                               amxd_direction_down,
                               amxd_object_validate_filter,
                               amxd_object_validate_impl,
                               depth,
                               &status);

exit:
    return status;
}

