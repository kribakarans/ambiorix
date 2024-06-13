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

#if !defined(__AMX_CLI_H__)
#define __AMX_CLI_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <string.h>

#include <yajl/yajl_gen.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxj/amxj_variant.h>

#include <amxt/amxt_tty.h>
#include <amxt/amxt_variant.h>
#include <amxt/amxt_cmd.h>
#include <amxt/amxt_ctrl.h>
#include <amxt/amxt_log.h>

#include <amxm/amxm.h>

typedef struct _cli_app {
    amxt_tty_t* tty;
    amxc_var_t aliases;
    char* shared_object;
    char* module;
} cli_app_t;

int amx_cli_args_parse(cli_app_t* cli, int argc, char** argv, amxc_string_t* cmds);

int amx_cli_init(cli_app_t* cli, const char* name, bool silent);

void amx_cli_clean(cli_app_t* cli);

void amx_cli_run_script(cli_app_t* cli, bool silent);

void amx_cli_configure_self_modules(cli_app_t* cli);

char* amxc_cli_take_cmd(amxc_var_t* cmd_parts);

const char* amx_cli_get_shared_object(void);
const char* amx_cli_get_module(void);
const char* amx_cli_get_alias(const char* alias);
amxt_tty_t* amx_cli_get_tty(void);

void amx_cli_set_shared_object(const char* name);
void amx_cli_set_module(const char* name);
amxc_var_t* amx_cli_get_aliases(void);
void amx_cli_set_alias(const char* alias, const char* cmd);

void amx_cli_complete_add_funcs(amxm_module_t* mod,
                                const char* start,
                                amxc_var_t* words);

int mod_amx_complete_cmd_variable(const char* function_name,
                                  amxc_var_t* args,
                                  amxc_var_t* words);

#ifdef __cplusplus
}
#endif

#endif // __AMX_CLI_H__
