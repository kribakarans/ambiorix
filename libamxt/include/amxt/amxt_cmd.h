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

#if !defined(__AMXT_CMD_H__)
#define __AMXT_CMD_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define AMXT_VP_ERROR_ARRAY     1
#define AMXT_VP_ERROR_TABLE     2
#define AMXT_VP_ERROR_COMPOSITE 3
#define AMXT_VP_ERROR_KEY       4
#define AMXT_VP_ERROR_TYPE      5
#define AMXT_VP_ERROR_VALUE     6

#define AMXT_VP_ARRAY           0x01
#define AMXT_VP_TABLE           0x02
#define AMXT_VP_COMPOSITE       0x04
#define AMXT_VP_PRIMITIVE       0x08

typedef struct _cmd_help {
    const char* cmd;
    const char* usage;
    const char* brief;
    const char* desc;
    const char** options;
} amxt_cmd_help_t;

#include <amxt/amxt_cmd_parts.h>
#include <amxt/amxt_cmd_words.h>
#include <amxt/amxt_cmd_options.h>
#include <amxt/amxt_cmd_parse.h>
#include <amxt/amxt_cmd_complete.h>

bool amxt_cmd_is_empty(amxc_var_t* parts);
void amxt_cmd_remove_until(amxc_var_t* parts, const char* marker);
void amxt_cmd_triml(amxc_var_t* parts, const char sep);
void amxt_cmd_trimr(amxc_var_t* parts, const char sep);
void amxt_cmd_trim(amxc_var_t* parts, const char sep);
uint32_t amxt_cmd_count_separators(amxc_var_t* parts, const char sep);
int amxt_cmd_index(const char* cmd, amxt_cmd_help_t* help);
void amxt_cmd_print_help(amxt_tty_t* tty,
                         amxt_cmd_help_t* help,
                         const char* cmd);

void amxt_cmd_error_excess(amxt_tty_t* tty,
                           amxc_var_t* args,
                           const char* usage);

#ifdef __cplusplus
}
#endif

#endif // ___AMXT_CTRL_H___
