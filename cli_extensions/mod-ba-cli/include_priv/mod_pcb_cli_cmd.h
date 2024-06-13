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

#if !defined(__MOD_PCB_CLI_CMD_H__)
#define __MOD_PCB_CLI_CMD_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#include <amxc/amxc.h>
#include <amxt/amxt_cmd.h>
#include <amxt/amxt_tty.h>

#include <amxb/amxb.h>

typedef enum _pcb_cli_cmd {
    PCB_HELP,
    PCB_CD,
    PCB_LIST,
    PCB_LS,
    PCB_DUMP,
    PCB_RESOLVE,
    PCB_SUBSCRIPTIONS,
    PCB_REQUESTS,
    PCB_GSDM,
    PCB_GI,
    PCB_GET,
    PCB_SET_PRIMITIVE,
    PCB_SET_TABLE,
    PCB_ADD,
    PCB_DEL,
    PCB_INVOKE,
    PCB_SUBSCRIBE,
    PCB_UNSUBSCRIBE,
    PCB_MAX,
} pcb_cli_cmd_t;

#define CMD_EMPTY_PATH  0x01
#define CMD_SEARCH_PATH 0x02
#define CMD_PARAM_PATH  0x04
#define CMD_FUNC_PATH   0x08
#define CMD_HAS_VALUES  0x10
#define CMD_MORE        0x20

typedef struct _pcb_cli_cmd_flags {
    uint32_t cmd_flags;
    uint32_t value_flags;
} pcb_cli_cmd_flags_t;

pcb_cli_cmd_flags_t* mod_pcb_cli_get_cmd_flags(uint32_t index);
amxt_cmd_help_t* mod_pcb_cli_get_help(uint32_t index);

char* mod_pcb_cli_build_path(amxc_var_t* args);

int PRIVATE mod_pcb_cli_cmd_parse(amxc_var_t* args,
                                  uint32_t cmd_index,
                                  amxb_bus_ctx_t** bus_ctx,
                                  char** input_path,
                                  amxc_var_t* cmd_opts,
                                  amxc_var_t* values);

void PRIVATE mod_pcb_cli_cmd_complete(amxc_var_t* args,
                                      uint32_t flags,
                                      const char* options[],
                                      amxc_var_t* ret);

void PRIVATE mod_pcb_cli_params_complete(amxc_var_t* args,
                                         amxc_var_t* ret);

void PRIVATE mod_pcb_cli_args_complete(amxc_var_t* args,
                                       amxc_var_t* ret);

int PRIVATE mod_pcb_cli_cmd_list(const char* function_name,
                                 amxc_var_t* args,
                                 amxc_var_t* ret);

int PRIVATE mod_pcb_cli_cmd_complete_common(const char* function_name,
                                            amxc_var_t* args,
                                            amxc_var_t* ret);

int PRIVATE mod_pcb_cli_cmd_dump(const char* function_name,
                                 amxc_var_t* args,
                                 amxc_var_t* ret);

int PRIVATE mod_pcb_cli_cmd_resolve(const char* function_name,
                                    amxc_var_t* args,
                                    amxc_var_t* ret);

int PRIVATE mod_pcb_cli_cmd_subscriptions(const char* function_name,
                                          amxc_var_t* args,
                                          amxc_var_t* ret);

int PRIVATE mod_pcb_cli_cmd_requests(const char* function_name,
                                     amxc_var_t* args,
                                     amxc_var_t* ret);

int PRIVATE mod_pcb_cli_cmd_gsdm(const char* function_name,
                                 amxc_var_t* args,
                                 amxc_var_t* ret);

int PRIVATE mod_pcb_cli_cmd_gi(const char* function_name,
                               amxc_var_t* args,
                               amxc_var_t* ret);

int PRIVATE mod_pcb_cli_get(amxt_tty_t* tty,
                            amxb_bus_ctx_t* bus_ctx,
                            amxc_var_t* options,
                            const char* path,
                            amxc_var_t* cmd);

int PRIVATE mod_pcb_cli_set_primitive(amxt_tty_t* tty,
                                      amxb_bus_ctx_t* bus_ctx,
                                      amxc_var_t* options,
                                      const char* path,
                                      amxc_var_t* cmd);

int PRIVATE mod_pcb_cli_set_table(amxt_tty_t* tty,
                                  amxb_bus_ctx_t* bus_ctx,
                                  amxc_var_t* options,
                                  const char* path,
                                  amxc_var_t* cmd);

int PRIVATE mod_pcb_cli_add(amxt_tty_t* tty,
                            amxb_bus_ctx_t* bus_ctx,
                            amxc_var_t* options,
                            const char* path,
                            amxc_var_t* cmd);

int mod_pcb_cli_del(amxt_tty_t* tty,
                    amxb_bus_ctx_t* bus_ctx,
                    amxc_var_t* options,
                    const char* path,
                    amxc_var_t* cmd);

int PRIVATE mod_pcb_cli_call(amxt_tty_t* tty,
                             amxb_bus_ctx_t* bus_ctx,
                             amxc_var_t* options,
                             const char* path,
                             amxc_var_t* cmd);

void PRIVATE mod_pcb_cli_subscriptions_init(void);
void PRIVATE mod_pcb_cli_subscriptions_clean(void);

void PRIVATE mod_pcb_cli_requests_init(void);
void PRIVATE mod_pcb_cli_requests_clean(void);

// Output commands
bool PRIVATE mod_pcb_cli_output_json(amxt_tty_t* tty, amxc_var_t* data);
void PRIVATE mod_pcb_cli_output_flat(amxt_tty_t* tty, amxc_var_t* data, bool params_only);
void PRIVATE mod_pcb_cli_output_list(amxt_tty_t* tty, amxc_var_t* data);

void PRIVATE mod_pcb_cli_output_changed_event(amxt_tty_t* tty, const amxc_var_t* data);
void PRIVATE mod_pcb_cli_output_pi_event(amxt_tty_t* tty, const amxc_var_t* data);
void PRIVATE mod_pcb_cli_output_instance_add_event(amxt_tty_t* tty, const amxc_var_t* data);
void PRIVATE mod_pcb_cli_output_instance_del_event(amxt_tty_t* tty, const amxc_var_t* data);
void PRIVATE mod_pcb_cli_output_add_event(amxt_tty_t* tty, const amxc_var_t* data);
void PRIVATE mod_pcb_cli_output_del_event(amxt_tty_t* tty, const amxc_var_t* data);
void PRIVATE mod_pcb_cli_output_event(amxt_tty_t* tty, const amxc_var_t* data);


#ifdef __cplusplus
}
#endif

#endif // __MOD_PCB_CLI_CMD_H__
