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
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxt/amxt_tty.h>
#include <amxt/amxt_cmd.h>

#include "amxt_priv.h"


#define AMXT_OPTION_OK          0
#define AMXT_OPTION_INVALID     1
#define AMXT_OPTION_CONTINUE    2

#define AMXT_OPTION_SHORT       1
#define AMXT_OPTION_LONG        2

static bool amxt_option_is_valid(const char* option, const char* valid[]) {
    uint32_t i = 0;
    bool retval = false;

    if(valid == NULL) {
        retval = true;
        goto exit;
    }

    while(valid[i] != NULL) {
        if(strcmp(option, valid[i]) == 0) {
            retval = true;
            break;
        }
        i++;
    }

exit:
    return retval;
}

static uint32_t amxt_option_add(amxc_var_t* options,
                                uint32_t type,
                                amxc_var_t* option_value,
                                amxc_string_t* option_name,
                                const char* valids[]) {
    uint32_t retval = AMXT_OPTION_OK;

    if(option_value != NULL) {
        amxc_var_set(cstring_t, option_value, amxc_string_get(option_name, 0));
        amxc_var_cast(option_value, AMXC_VAR_ID_ANY);
        goto exit;
    }
    if(type == AMXT_OPTION_SHORT) {
        const char* opts = amxc_string_get(option_name, 0);
        size_t nr_opts = amxc_string_text_length(option_name);
        char opt[2] = { 0, 0 };
        for(size_t i = 0; i < nr_opts; i++) {
            opt[0] = opts[i];
            if(amxt_option_is_valid(opt, valids)) {
                amxc_var_add_key(bool, options, opt, true);
            } else {
                retval = AMXT_OPTION_INVALID;
                break;
            }
        }
    } else {
        if(amxt_option_is_valid(amxc_string_get(option_name, 0), valids)) {
            amxc_var_add_key(bool, options, amxc_string_get(option_name, 0), true);
        } else {
            retval = AMXT_OPTION_INVALID;
        }
    }

exit:
    if(retval == AMXT_OPTION_OK) {
        amxc_string_reset(option_name);
    }
    return retval;
}

static uint32_t amxt_option_create(amxc_var_t* options,
                                   uint32_t type,
                                   amxc_var_t** option_value,
                                   amxc_string_t* option_name,
                                   const char* valids[]) {
    uint32_t retval = AMXT_OPTION_OK;
    if(type == AMXT_OPTION_SHORT) {
        if(amxc_string_text_length(option_name) > 1) {
            retval = AMXT_OPTION_INVALID;
            goto exit;
        }
        if(amxt_option_is_valid(amxc_string_get(option_name, 0), valids)) {
            *option_value = amxc_var_add_new_key(options, amxc_string_get(option_name, 0));
            amxc_string_reset(option_name);
            retval = AMXT_OPTION_CONTINUE;
        } else {
            retval = AMXT_OPTION_INVALID;
        }
    } else {
        if(amxt_option_is_valid(amxc_string_get(option_name, 0), valids)) {
            *option_value = amxc_var_add_new_key(options, amxc_string_get(option_name, 0));
            amxc_string_reset(option_name);
            retval = AMXT_OPTION_CONTINUE;
        } else {
            retval = AMXT_OPTION_INVALID;
        }
    }
exit:
    return retval;
}

static uint32_t amxt_option_build(const char* part,
                                  UNUSED uint32_t type,
                                  amxc_var_t* options,
                                  amxc_string_t* option_name,
                                  amxc_var_t** option_value,
                                  const char* valids[]) {
    uint32_t retval = AMXT_OPTION_OK;
    if(part == NULL) {
        retval = amxt_option_add(options, type, *option_value, option_name, valids);
        goto exit;
    }
    switch(part[0]) {
    case ' ':
        retval = amxt_option_add(options, type, *option_value, option_name, valids);
        *option_value = NULL;
        break;
    case '=':
        retval = amxt_option_create(options, type, option_value, option_name, valids);
        break;
    default:
        amxc_string_appendf(option_name, "%s", part);
        retval = AMXT_OPTION_CONTINUE;
        break;
    }

exit:
    return retval;
}

uint32_t amxt_cmd_get_options(amxc_var_t* parts,
                              amxc_var_t* options,
                              const char* valid[]) {
    uint32_t retval = 1;
    const char* str_part = NULL;
    uint32_t option_type = 0;
    amxc_string_t helper;
    amxc_var_t* option = NULL;

    amxc_string_init(&helper, 64);
    when_null(parts, exit);
    when_null(options, exit);

    amxt_cmd_triml(parts, ' ');

    retval = 0;
    amxc_var_set_type(options, AMXC_VAR_ID_HTABLE);
    amxc_var_for_each(part, parts) {
        str_part = amxc_var_constcast(cstring_t, part);
        if(option_type == 0) {
            if(str_part[0] != '-') {
                break;
            }
            amxc_string_reset(&helper);
            option_type++;
            amxc_var_delete(&part);
        } else if(option_type == AMXT_OPTION_SHORT) {
            if(str_part[0] == '-') {
                option_type++;
                amxc_var_delete(&part);
            }
        }
        if(part != NULL) {
            retval = amxt_option_build(str_part, option_type, options, &helper, &option, valid);
            switch(retval) {
            case AMXT_OPTION_OK:
                option_type = 0;
                option = NULL;
                amxc_var_delete(&part);
                break;
            case AMXT_OPTION_INVALID:
                amxt_cmd_prepend_part(parts, amxc_string_get(&helper, 0));
                amxt_cmd_prepend_part(parts, "-");
                if(option_type == AMXT_OPTION_LONG) {
                    amxt_cmd_prepend_part(parts, "-");
                }
                amxc_string_reset(&helper);
                break;
            case AMXT_OPTION_CONTINUE:
                amxc_var_delete(&part);
                retval = 0;
                break;
            }
        }
        if(retval != 0) {
            break;
        }
    }

    if((retval == 0) && (amxc_string_text_length(&helper) != 0)) {
        retval = amxt_option_build(NULL, option_type, options, &helper, &option, valid);
    }

exit:
    amxc_string_clean(&helper);
    return retval;
}

int amxt_cmd_parse_options(amxt_tty_t* tty,
                           amxc_var_t* parts,
                           amxc_var_t* options,
                           const char* valid_options[]) {
    int retval = 1;

    when_null(tty, exit);
    when_null(parts, exit);
    when_null(options, exit);

    if(amxt_cmd_get_options(parts, options, valid_options) != 0) {
        char* option = amxt_cmd_pop_word(parts);
        uint32_t index = 0;
        amxt_tty_errorf(tty, "Invalid option(s) '%s'\n", option);
        amxt_tty_messagef(tty, "Valid options:\n");
        while(valid_options[index] != NULL) {
            if(strlen(valid_options[index]) == 1) {
                amxt_tty_writef(tty, "\t-%s\n", valid_options[index]);
            } else {
                amxt_tty_writef(tty, "\t--%s\n", valid_options[index]);
            }
            index++;
        }
        free(option);
        goto exit;
    }

    retval = 0;

exit:
    return retval;
}
