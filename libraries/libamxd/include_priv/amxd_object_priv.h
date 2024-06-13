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
#if !defined(__AMXD_OBJECT_PRIV_H__)
#define __AMXD_OBJECT_PRIV_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxp/amxp_slot.h>
#include <amxp/amxp_expression.h>

typedef struct _get_supported_args {
    bool functions;
    bool params;
    bool events;
    bool first_lvl;
    amxc_var_t* ret;
    amxd_dm_access_t access;
} get_supported_args_t;

PRIVATE
void amxd_object_free_func_it(amxc_llist_it_t* it);

PRIVATE
const char* amxd_object_template_get_alias(amxc_var_t* templ_params,
                                           amxc_var_t* values);

PRIVATE
amxd_status_t amxd_object_init(amxd_object_t* const object,
                               const amxd_object_type_t type,
                               const char* name,
                               amxc_var_t* templ_params,
                               amxc_var_t* values);
PRIVATE
void amxd_object_destroy_handlers(amxd_object_t* const object);

PRIVATE
void amxd_object_clean(amxd_object_t* const object);

PRIVATE
amxd_object_t* amxd_object_find_internal(amxd_object_t* const object,
                                         bool* key_path,
                                         amxd_path_t* path,
                                         amxd_status_t* status);

PRIVATE
amxd_status_t amxd_object_resolve_internal(amxd_object_t* const object,
                                           bool* key_path,
                                           amxc_llist_t* paths,
                                           amxd_path_t* path);

PRIVATE
void amxd_fetch_item(amxc_var_t* const full_data,
                     const char* item,
                     amxc_var_t* const data);

PRIVATE
amxd_function_t* amxd_object_get_self_func(const amxd_object_t* const object,
                                           const char* name);

PRIVATE
amxd_status_t amxd_object_copy_params(amxd_object_t* const dst,
                                      const amxd_object_t* const src);

PRIVATE
amxd_status_t amxd_object_copy_funcs(amxd_object_t* const dst,
                                     const amxd_object_t* const src);

PRIVATE
amxd_status_t amxd_object_copy_events(amxd_object_t* const dst,
                                      const amxd_object_t* const src);

PRIVATE
amxd_status_t amxd_object_copy_mib_names(amxd_object_t* const dst,
                                         const amxd_object_t* const src);

PRIVATE
amxd_status_t amxd_object_copy_children(amxd_object_t* const dst,
                                        const amxd_object_t* const src);

PRIVATE
amxd_status_t amxd_object_derive(amxd_object_t** object,
                                 amxd_object_t* const base,
                                 amxd_object_t* const parent);

PRIVATE
amxd_status_t amxd_object_build_key_expr(amxc_var_t* const templ_params,
                                         amxp_expr_t** expr,
                                         const amxc_htable_t* const data);

#ifdef __cplusplus
}
#endif

#endif // __AMXD_OBJECT_PRIV_H__
