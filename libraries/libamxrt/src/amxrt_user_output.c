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
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include <amxrt/amxrt.h>
#include "amxrt_priv.h"

static const char* colors[] = {
    COLOR_BRIGHT_BLUE,
    COLOR_BRIGHT_GREEN,
    COLOR_BRIGHT_RED,
    COLOR_BRIGHT_WHITE,
    COLOR_BRIGHT_CYAN,
    COLOR_BRIGHT_YELLOW,
    COLOR_RESET
};

static void amxrt_cmd_line_arg(const char so,
                               const char* lo,
                               const char* args,
                               const char* description) {
    int pre_length = 4 + 2 + 4 + strlen(lo);

    printf("    %s-%c%s       %s--%s%s",
           c(GREEN), so, c(RESET),
           c(GREEN), lo, c(RESET));

    if(args != NULL) {
        pre_length += 3 + strlen(args);
        printf("%s %s %s ", c(BLUE), args, c(RESET));
    }
    for(int i = 39 - pre_length; i > 0; i--) {
        printf(" ");
    }
    printf("%s%s%s\n", c(WHITE), description, c(RESET));
}

static void amxrt_print_notes(void) {
    printf("\n");
    printf("%sNotes:%s\n", c(CYAN), c(RESET));
    printf(" %s*%s Short and long options take the same arguments\n", c(YELLOW), c(RESET));
    printf("\n");
    printf(" %s*%s At least one odl file or odl string must be specified\n", c(YELLOW), c(RESET));
    printf("\n");
    printf(" %s*%s Each bus backend can only be specified once\n", c(YELLOW), c(RESET));
    printf("\n");
    printf(" %s*%s The process daemizes (-D) after the entry points are called, but before\n", c(YELLOW), c(RESET));
    printf("   the data model is registered to the busses.\n");
    printf("\n");
    printf(" %s*%s All command line options can be put in the config section of one\n", c(YELLOW), c(RESET));
    printf("   of the main odls.\n");
}

static void amxrt_print_config_example(void) {
    printf("\n");
    printf("%sExample config section:%s\n", c(CYAN), c(RESET));
    printf("\n");
    printf("%s%%config%s {\n", c(GREEN), c(RESET));
    printf("    %suris%s = %s\"pcb:/var/run/pcb_sys,ubus:/var/run/ubus/ubus.sock\"%s;\n", c(BLUE), c(RESET), c(CYAN), c(RESET));
    printf("    %sbackends%s = %s\"/usr/bin/mods/amxb/mod-amxb-pcb.so,/usr/bin/mods/amxb/mod-amxb-ubus.so\"%s;\n", c(BLUE), c(RESET), c(CYAN), c(RESET));
    printf("    %sauto-detect%s = %strue%s;\n", c(BLUE), c(RESET), c(CYAN), c(RESET));
    printf("    %sauto-connect%s = %strue%s;\n", c(BLUE), c(RESET), c(CYAN), c(RESET));
    printf("    %sinclude-dirs%s = %s\".\"%s;\n", c(BLUE), c(RESET), c(CYAN), c(RESET));
    printf("    %simport-dirs%s = %s\".\"%s;\n", c(BLUE), c(RESET), c(CYAN), c(RESET));
    printf("    %sdaemon%s = %sfalse%s;\n", c(BLUE), c(RESET), c(CYAN), c(RESET));
    printf("    %spriority%s = %s0%s;\n", c(BLUE), c(RESET), c(CYAN), c(RESET));
    printf("}\n");
}

const char* get_color(uint32_t cc) {
    if(cc < RESET) {
        return colors[cc];
    }
    return colors[RESET];
}

void amxrt_print_usage(void) {
    amxrt_t* rt = amxrt_get();
    const char* name = GET_CHAR(&rt->parser.config, "name");

    printf("%s %s\n", name, rt->usage_doc);

    if(!amxc_llist_is_empty(&rt->cmd_line_args)) {
        printf("\n");
        printf("%sOptions%s:\n", c(CYAN), c(RESET));
        printf("\n");

        amxc_llist_for_each(it, &rt->cmd_line_args) {
            amxrt_arg_t* arg = amxc_container_of(it, amxrt_arg_t, it);
            amxrt_cmd_line_arg(arg->short_option,
                               arg->long_option == NULL ? "" : arg->long_option,
                               arg->arg_doc,
                               arg->doc);
        }
    }

    printf("\n");
}

void amxrt_print_help(void) {
    amxrt_print_usage();
    amxrt_print_notes();
    amxrt_print_config_example();
}

void amxrt_print_configuration(void) {
    amxrt_t* rt = amxrt_get();

    fprintf(stderr, "\n%sConfiguration:%s\n", c(GREEN), c(RESET));
    fflush(stderr);
    amxc_var_dump(&rt->parser.config, STDERR_FILENO);
}

void amxrt_print_error(const char* fmt, ...) {
    amxc_var_t* config = amxrt_get_config();
    va_list args;

    if(GET_BOOL(config, AMXRT_COPT_LOG)) {
        va_start(args, fmt);
        vsyslog(LOG_USER | LOG_ERR, fmt, args);
        va_end(args);
    } else {
        fprintf(stderr, "%sERROR%s -- %s", c(RED), c(RESET), c(WHITE));

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);

        fprintf(stderr, "%s\n", c(RESET));
    }
}

void amxrt_print_message(const char* fmt, ...) {
    amxc_var_t* config = amxrt_get_config();
    va_list args;

    if(GET_BOOL(config, AMXRT_COPT_LOG)) {
        va_start(args, fmt);
        vsyslog(LOG_USER | LOG_NOTICE, fmt, args);
        va_end(args);
    } else {
        fprintf(stderr, "%sINFO%s -- %s", c(YELLOW), c(RESET), c(WHITE));

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);

        fprintf(stderr, "%s\n", c(RESET));
    }
}


void amxrt_print_failure(amxo_parser_t* parser, const char* string) {
    amxc_var_t* config = amxrt_get_config();
    const char* msg = amxo_parser_get_message(parser);

    if(GET_BOOL(config, AMXRT_COPT_LOG)) {
        syslog(LOG_USER | LOG_CRIT, "Failed parsing - %s", string == NULL ? "###" : string);
        syslog(LOG_USER | LOG_CRIT, "Reason - %s", msg == NULL ? "###" : msg);
    } else {
        fprintf(stderr, "%sERROR%s -- Failed parsing %s%s%s\n",
                c(RED), c(RESET),
                c(CYAN), string == NULL ? "###" : string, c(RESET));

        fprintf(stderr, "%sREASON%s -- %s%s%s\n",
                c(BLUE), c(RESET),
                c(CYAN), msg == NULL ? "###" : msg, c(RESET));
    }
}
