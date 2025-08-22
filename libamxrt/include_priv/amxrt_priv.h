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

#if !defined(__AMXRT_PRIV_H__)
#define __AMXRT_PRIV_H__

#ifdef __cplusplus
extern "C"
{
#endif


#define AMXRT_CVAL_PLUGIN_DIR "/usr/lib/amx"
#define AMXRT_CVAL_CFG_DIR "/etc/amx"
#define AMXRT_CVAL_BACKEND_DIR "/usr/bin/mods/amxb"
#define AMXRT_CVAL_STORAGE_TYPE "odl"

#define COLOR_BLACK      "\033[30m"
#define COLOR_RED        "\033[31m"
#define COLOR_GREEN      "\033[32m"
#define COLOR_YELLOW     "\033[33m"
#define COLOR_BLUE       "\033[34m"
#define COLOR_MAGENTA    "\033[35m"
#define COLOR_CYAN       "\033[36m"
#define COLOR_WHITE      "\033[37m"

#define COLOR_BRIGHT_BLACK      "\033[30;1m"
#define COLOR_BRIGHT_RED        "\033[31;1m"
#define COLOR_BRIGHT_GREEN      "\033[32;1m"
#define COLOR_BRIGHT_YELLOW     "\033[33;1m"
#define COLOR_BRIGHT_BLUE       "\033[34;1m"
#define COLOR_BRIGHT_MAGENTA    "\033[35;1m"
#define COLOR_BRIGHT_CYAN       "\033[36;1m"
#define COLOR_BRIGHT_WHITE      "\033[37;1m"

#define COLOR_RESET      "\033[0m"

#define BLUE   0
#define GREEN  1
#define RED    2
#define WHITE  3
#define CYAN   4
#define YELLOW 5
#define RESET  6

#define c(x) get_color(x)

typedef struct _runtime {
    amxd_dm_t dm;
    amxo_parser_t parser;
    amxc_llist_t cmd_line_args;
    amxc_var_t forced_options;
    amxc_llist_t event_sources;
    const char* usage_doc;
} amxrt_t;

typedef struct _runtime_options {
    char short_option;
    const char* long_option;
    int has_args;
    int id;
    const char* doc;
    const char* arg_doc;
    amxc_llist_it_t it;
} amxrt_arg_t;

PRIVATE
const char* get_color(uint32_t cc);

PRIVATE
amxrt_t* amxrt_get(void);

PRIVATE
void amxrt_cmd_line_add_default_options(void);

PRIVATE
void amxrt_print_help(void);

PRIVATE
void amxrt_print_configuration(void);

PRIVATE
void amxrt_print_error(const char* fmt, ...);

PRIVATE
void amxrt_print_message(const char* fmt, ...);

PRIVATE
void amxrt_print_failure(amxo_parser_t* parser, const char* string);

PRIVATE
void amxrt_config_add_options(amxo_parser_t* parser);

PRIVATE
void amxrt_connection_detect_sockets(amxc_var_t* config);

PRIVATE
int amxrt_connection_load_backends(amxc_var_t* config);

PRIVATE
int amxrt_connection_connect_all(amxo_parser_t* parser);

PRIVATE
int amxrt_connection_listen_all(amxo_parser_t* parser);

PRIVATE
int amxrt_connection_register_dm(amxo_parser_t* parser, amxd_dm_t* dm);

PRIVATE
amxp_connection_t* amxrt_el_get_connection(amxc_llist_t* cons, int fd);

PRIVATE
int amxrt_dm_create_dir(amxo_parser_t* parser, uid_t uid, gid_t gid);

#ifdef __cplusplus
}
#endif

#endif // __AMXRT_PRIV_H__
