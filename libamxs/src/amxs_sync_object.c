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

#include <amxs/amxs_sync_object.h>
#include <amxs/amxs_sync_param.h>
#include <amxs/amxs_util.h>

#include "amxs_priv.h"
#include "amxs_sync_entry.h"

amxs_status_t amxs_sync_object_new(amxs_sync_object_t** object,
                                   const char* object_a,
                                   const char* object_b,
                                   int attributes,
                                   amxs_translation_cb_t translation_cb,
                                   amxs_action_cb_t action_cb,
                                   void* priv) {
    return amxs_sync_entry_new(object,
                               object_a,
                               object_b,
                               attributes,
                               translation_cb,
                               action_cb,
                               amxs_sync_type_object,
                               priv);
}

amxs_status_t amxs_sync_object_new_copy(amxs_sync_object_t** object,
                                        const char* object_a,
                                        const char* object_b,
                                        int attributes) {
    return amxs_sync_object_new(object,
                                object_a,
                                object_b,
                                attributes,
                                amxs_sync_object_copy_trans_cb,
                                amxs_sync_object_copy_action_cb,
                                NULL);
}

void amxs_sync_object_delete(amxs_sync_object_t** object) {
    when_null(object, exit);
    when_null(*object, exit);
    when_false((*object)->type == amxs_sync_type_object, exit);

    amxs_sync_entry_delete(object);

exit:
    return;
}

amxs_status_t amxs_sync_object_add_param(amxs_sync_object_t* object, amxs_sync_param_t* param) {
    amxs_status_t status = amxs_status_unknown_error;
    when_null(object, exit);
    when_null(param, exit);
    when_false_status(object->type == amxs_sync_type_object, exit, status = amxs_status_invalid_type);
    when_false_status(param->type == amxs_sync_type_param, exit, status = amxs_status_invalid_type);

    status = amxs_sync_entry_add_entry(object, param);

exit:
    return status;
}

amxs_status_t amxs_sync_object_add_new_param(amxs_sync_object_t* object,
                                             const char* param_a,
                                             const char* param_b,
                                             int attributes,
                                             amxs_translation_cb_t translation_cb,
                                             amxs_action_cb_t action_cb,
                                             void* priv) {
    amxs_status_t status = amxs_status_unknown_error;
    amxs_sync_param_t* param = NULL;

    status = amxs_sync_param_new(&param, param_a, param_b, attributes, translation_cb, action_cb, priv);
    when_failed(status, exit);

    status = amxs_sync_object_add_param(object, param);
    if(status != amxs_status_ok) {
        amxs_sync_param_delete(&param);
    }

exit:
    return status;
}

amxs_status_t amxs_sync_object_add_new_copy_param(amxs_sync_object_t* object,
                                                  const char* param_a,
                                                  const char* param_b,
                                                  int attributes) {
    return amxs_sync_object_add_new_param(object,
                                          param_a,
                                          param_b,
                                          attributes | AMXS_SYNC_PARAM_BATCH,
                                          NULL,
                                          NULL,
                                          NULL);
}

amxs_status_t amxs_sync_object_add_object(amxs_sync_object_t* parent, amxs_sync_object_t* child) {
    amxs_status_t status = amxs_status_unknown_error;
    when_null(parent, exit);
    when_null(child, exit);
    when_false_status(parent->type == amxs_sync_type_object, exit, status = amxs_status_invalid_type);
    when_false_status(child->type == amxs_sync_type_object, exit, status = amxs_status_invalid_type);

    status = amxs_sync_entry_add_entry(parent, child);

exit:
    return status;
}

amxs_status_t amxs_sync_object_add_new_object(amxs_sync_object_t* parent,
                                              const char* object_a,
                                              const char* object_b,
                                              int attributes,
                                              amxs_translation_cb_t translation_cb,
                                              amxs_action_cb_t action_cb,
                                              void* priv) {
    amxs_status_t status = amxs_status_unknown_error;
    amxs_sync_object_t* child = NULL;

    status = amxs_sync_object_new(&child, object_a, object_b, attributes, translation_cb, action_cb, priv);
    when_failed(status, exit);

    status = amxs_sync_object_add_object(parent, child);
    if(status != amxs_status_ok) {
        amxs_sync_object_delete(&child);
    }

exit:
    return status;
}

amxs_status_t amxs_sync_object_add_new_copy_object(amxs_sync_object_t* parent,
                                                   const char* object_a,
                                                   const char* object_b,
                                                   int attributes) {
    return amxs_sync_object_add_new_object(parent,
                                           object_a,
                                           object_b,
                                           attributes,
                                           amxs_sync_object_copy_trans_cb,
                                           amxs_sync_object_copy_action_cb,
                                           NULL);
}
