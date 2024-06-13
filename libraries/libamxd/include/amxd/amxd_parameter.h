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

#if !defined(__AMXD_PARAMETER_H__)
#define __AMXD_PARAMETER_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <amxd/amxd_types.h>
#include <amxd/amxd_parameter_action.h>

amxd_status_t amxd_param_new(amxd_param_t** param,    // dm parameter definition
                             const char* name,        // the parameter name that will be visible in dm
                             const uint32_t type);    // parameter type (is one of available amxc_var types)

amxd_status_t amxd_param_delete(amxd_param_t** param);

amxd_status_t amxd_param_copy(amxd_param_t** dest,
                              const amxd_param_t* const source);

// query the parameter
amxd_object_t* amxd_param_get_owner(const amxd_param_t* const param);       // returns object were definition is
const char* amxd_param_get_name(const amxd_param_t* const param);           //

static inline
uint32_t amxd_param_get_type(const amxd_param_t* const param) {
    return param == NULL ? AMXC_VAR_ID_NULL : amxc_var_type_of(&param->value);
}

amxd_status_t amxd_param_set_attr(amxd_param_t* param,
                                  const amxd_pattr_id_t attr,
                                  const bool enable);

amxd_status_t amxd_param_set_attrs(amxd_param_t* param,
                                   const uint32_t bitmask,
                                   bool enable);

uint32_t amxd_param_get_attrs(const amxd_param_t* const param);

bool amxd_param_is_attr_set(const amxd_param_t* const param,
                            const amxd_pattr_id_t attr);

void amxd_param_set_flag(amxd_param_t* param, const char* flag);

void amxd_param_unset_flag(amxd_param_t* param, const char* flag);

bool amxd_param_has_flag(const amxd_param_t* const param, const char* flag);

amxd_status_t amxd_param_set_value(amxd_param_t* const param,
                                   const amxc_var_t* const value);

amxd_status_t amxd_param_get_value(amxd_param_t* const param,
                                   amxc_var_t* const value);

amxd_status_t amxd_param_validate(amxd_param_t* const param,
                                  const amxc_var_t* const value);

amxd_status_t amxd_param_describe(amxd_param_t* const param,
                                  amxc_var_t* const value);

amxd_status_t amxd_param_counter_update(amxd_param_t* counter);

#ifdef __cplusplus
}
#endif

#endif // __AMXD_PARAMETER_H__
