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
#if !defined(__AMXD_PRIV_H__)
#define __AMXD_PRIV_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_types.h>

typedef amxd_status_t (* list_part_fn_t) (amxd_object_t* const object,
                                          const amxc_var_t* args,
                                          amxc_var_t* const retval);
typedef struct _list_parts {
    const char* name;
    list_part_fn_t fn;
} list_parts_t;

#define GET_FIELD(var, field) \
    amxc_var_get_path(var, field, AMXC_VAR_FLAG_DEFAULT)

amxd_dm_cb_t* PRIVATE amxd_get_action(const amxc_llist_t* const cb_fns,
                                      const amxd_action_t reason,
                                      amxd_action_fn_t fn);

void PRIVATE amxd_function_arg_clean(amxd_func_arg_t* const arg);

bool PRIVATE amxd_param_is_unique(amxd_object_t* const templ,
                                  amxd_object_t* const current,
                                  amxd_param_t* const param,
                                  const amxc_var_t* const value);

amxd_status_t PRIVATE amxd_action_set_values(amxd_object_t* const object,
                                             amxd_dm_access_t access,
                                             bool ro,
                                             const amxc_var_t* values,
                                             amxc_var_t* retval,
                                             bool required);

void PRIVATE amxd_param_free(amxd_param_t** param);

amxd_status_t PRIVATE amxd_param_counter_destroy(amxd_object_t* const object,
                                                 amxd_param_t* const param,
                                                 amxd_action_t reason,
                                                 const amxc_var_t* const args,
                                                 amxc_var_t* const retval,
                                                 void* priv);

amxc_var_t* PRIVATE amxd_resolve_param_ref(amxd_object_t* object,
                                           amxc_var_t* ref);

bool PRIVATE amxd_must_add(const amxc_var_t* const args,
                           const char* name,
                           amxd_object_t* object);


#ifdef __cplusplus
}
#endif

#endif // __AMXD_PRIV_H__
