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
#if !defined(__AMXD_DM_PRIV_H__)
#define __AMXD_DM_PRIV_H__

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _amxd_deferred_call {
    amxc_llist_it_t it;
    amxc_llist_it_t dm_it;
    amxp_deferred_fn_t cb;
    amxd_deferred_cancel_t cancel;
    uint32_t call_id;
    void* caller_priv;
    void* called_priv;
} amxd_deferred_ctx_t;


void PRIVATE amxd_object_init_base(amxd_object_t* const object,
                                   const amxd_object_type_t type);

void PRIVATE amxd_init_base(void);

void PRIVATE amxd_dm_event(const char* signal,
                           const amxd_object_t* const object,
                           amxc_var_t* const data,
                           bool trigger);

bool PRIVATE amxd_object_is_base(const amxd_object_t* const object);

amxd_status_t PRIVATE amxd_dm_base_add_funcs(amxd_object_t* object);

void PRIVATE amxd_dm_set_derived_from(amxd_object_t* const object);

void PRIVATE amxd_def_funcs_remove_args(amxc_var_t* args);

void PRIVATE amxd_common_set_flag(amxc_var_t** flags, const char* flag);

void PRIVATE amxd_common_unset_flag(amxc_var_t** flags, const char* flag);

bool PRIVATE amxd_common_has_flag(const amxc_var_t* const flags, const char* flag);

amxd_deferred_ctx_t* PRIVATE amxd_find_deferred(uint64_t call_id);

void PRIVATE amxd_dm_cancel_deferred(amxd_dm_t* dm);

#ifdef __cplusplus
}
#endif

#endif // __AMXD_DM_PRIV_H__
