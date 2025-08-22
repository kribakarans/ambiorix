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


static int amxt_cmd_parse_values_impl(amxc_var_t* args,
                                      uint32_t flags,
                                      amxc_var_t* values,
                                      amxc_string_t* helper,
                                      amxc_string_t* parsed);

static int amxt_values_array_start(amxc_var_t* args,
                                   const char* key,
                                   uint32_t flags,
                                   amxc_var_t* values,
                                   amxc_string_t* helper,
                                   amxc_string_t* parsed) {
    int rv = 0;
    if(!amxc_string_is_empty(helper)) {
        rv = AMXT_VP_ERROR_VALUE;
        goto exit;
    }
    if(amxc_var_type_of(values) == AMXC_VAR_ID_NULL) {
        if((flags & AMXT_VP_ARRAY) != 0) {
            amxc_var_set_type(values, AMXC_VAR_ID_LIST);
        } else {
            rv = AMXT_VP_ERROR_ARRAY;
        }
    } else {
        if((flags & AMXT_VP_COMPOSITE) != 0) {
            amxc_var_t* array = NULL;
            if(amxc_var_type_of(values) == AMXC_VAR_ID_LIST) {
                array = amxc_var_add(amxc_llist_t, values, NULL);
                rv = amxt_cmd_parse_values_impl(args, flags, array, helper, parsed);
            } else {
                array = amxc_var_add_key(amxc_llist_t, values, key, NULL);
                rv = amxt_cmd_parse_values_impl(args, flags, array, helper, parsed);
            }
        } else {
            rv = AMXT_VP_ERROR_COMPOSITE;
        }
    }

exit:
    return rv;
}

static int amxt_values_table_start(amxc_var_t* args,
                                   const char* key,
                                   uint32_t flags,
                                   amxc_var_t* values,
                                   amxc_string_t* helper,
                                   amxc_string_t* parsed) {
    int rv = 0;
    if(!amxc_string_is_empty(helper)) {
        rv = AMXT_VP_ERROR_VALUE;
        goto exit;
    }
    if(amxc_var_type_of(values) == AMXC_VAR_ID_NULL) {
        if((flags & AMXT_VP_TABLE) != 0) {
            amxc_var_set_type(values, AMXC_VAR_ID_HTABLE);
        } else {
            rv = AMXT_VP_ERROR_ARRAY;
        }
    } else {
        if((flags & AMXT_VP_COMPOSITE) != 0) {
            amxc_var_t* table = NULL;
            if(amxc_var_type_of(values) == AMXC_VAR_ID_LIST) {
                table = amxc_var_add(amxc_htable_t, values, NULL);
                rv = amxt_cmd_parse_values_impl(args, flags, table, helper, parsed);
            } else {
                table = amxc_var_add_key(amxc_htable_t, values, key, NULL);
                rv = amxt_cmd_parse_values_impl(args, flags, table, helper, parsed);
            }
        } else {
            rv = AMXT_VP_ERROR_COMPOSITE;
        }
    }

exit:
    return rv;
}

static int amxt_values_get_key(amxc_var_t* values,
                               char** key,
                               amxc_string_t* helper) {
    int rv = 0;
    if(amxc_var_type_of(values) != AMXC_VAR_ID_HTABLE) {
        rv = AMXT_VP_ERROR_TYPE;
    } else if(*key == NULL) {
        amxc_string_trim(helper, NULL);
        *key = amxc_string_dup(helper, 0, amxc_string_text_length(helper));
        amxc_string_reset(helper);
    } else {
        rv = AMXT_VP_ERROR_KEY;
    }

    return rv;
}

static int amxt_values_set(amxc_var_t* values,
                           const char* key,
                           amxc_string_t* helper,
                           bool is_string) {
    int rv = 0;
    const char* value = amxc_string_get(helper, 0);
    if(amxc_var_type_of(values) == AMXC_VAR_ID_HTABLE) {
        if(key != NULL) {
            amxc_var_t* data = amxc_var_add_key(cstring_t, values, key, value);
            if(!is_string) {
                amxc_var_cast(data, AMXC_VAR_ID_ANY);
            }
            amxc_string_reset(helper);
        } else {
            rv = AMXT_VP_ERROR_KEY;
        }
    } else {
        amxc_var_t* data = amxc_var_add(cstring_t, values, value);
        if(!is_string) {
            amxc_var_cast(data, AMXC_VAR_ID_ANY);
        }
        amxc_string_reset(helper);
    }

    return rv;
}

static int amxt_cmd_parse_values_impl(amxc_var_t* args,
                                      uint32_t flags,
                                      amxc_var_t* values,
                                      amxc_string_t* helper,
                                      amxc_string_t* parsed) {
    int rv = 0;
    char* part = NULL;
    char* key = NULL;
    bool is_sq_string = false;
    bool is_dq_string = false;
    uint32_t type = AMXC_VAR_ID_ANY;
    bool add_value = false;

    amxt_cmd_triml(args, ' ');
    part = amxt_cmd_pop_part(args);
    while(part != NULL) {
        amxc_string_appendf(parsed, "%s", part);
        switch(part[0]) {
        case 0:
            amxc_string_append(parsed, " ", 1);
            break;
        case '\'':
            if(is_sq_string) {
                is_sq_string = false;
            } else {
                if(is_dq_string) {
                    amxc_string_appendf(helper, "%s", part);
                } else {
                    amxc_string_reset(helper);
                    is_sq_string = true;
                    type = AMXC_VAR_ID_CSTRING;
                }
            }
            break;
        case '"':
            if(is_dq_string) {
                is_dq_string = false;
            } else {
                if(is_sq_string) {
                    amxc_string_appendf(helper, "%s", part);
                } else {
                    amxc_string_reset(helper);
                    is_dq_string = true;
                    type = AMXC_VAR_ID_CSTRING;
                }
            }
            break;
        case '[':
            if(is_sq_string || is_dq_string) {
                amxc_string_appendf(helper, "%s", part);
                break;
            }
            rv = amxt_values_array_start(args, key, flags,
                                         values, helper, parsed);
            when_failed(rv, exit);
            add_value = false;
            amxc_string_reset(helper);
            free(key);
            key = NULL;
            break;
        case ']':
            if(is_sq_string || is_dq_string) {
                amxc_string_appendf(helper, "%s", part);
                break;
            }
            if(add_value) {
                amxc_string_resolve_esc(helper);
                rv = amxt_values_set(values, key, helper, type == AMXC_VAR_ID_CSTRING);
                amxt_cmd_triml(args, ' ');
            }
            goto exit;
            break;
        case '{':
        case '(':
            if(is_sq_string || is_dq_string) {
                amxc_string_appendf(helper, "%s", part);
                break;
            }
            rv = amxt_values_table_start(args, key, flags,
                                         values, helper, parsed);
            when_failed(rv, exit);
            add_value = false;
            amxc_string_reset(helper);
            free(key);
            key = NULL;
            break;
        case '}':
        case ')':
            if(is_sq_string || is_dq_string) {
                amxc_string_appendf(helper, "%s", part);
                break;
            }
            if(add_value) {
                amxc_string_resolve_esc(helper);
                rv = amxt_values_set(values, key, helper, type == AMXC_VAR_ID_CSTRING);
                amxt_cmd_triml(args, ' ');
            }
            goto exit;
            break;
        case '=':
            if(is_sq_string || is_dq_string) {
                amxc_string_appendf(helper, "%s", part);
                break;
            }
            is_sq_string = false;
            is_dq_string = false;
            rv = amxt_values_get_key(values, &key, helper);
            amxt_cmd_triml(args, ' ');
            when_failed(rv, exit);
            break;
        case ',':
            if(is_sq_string || is_dq_string) {
                amxc_string_appendf(helper, "%s", part);
                break;
            }
            if(add_value) {
                amxc_string_resolve_esc(helper);
                rv = amxt_values_set(values, key, helper, type == AMXC_VAR_ID_CSTRING);
                type = AMXC_VAR_ID_ANY;
                amxt_cmd_triml(args, ' ');
                when_failed(rv, exit);
                free(key);
                key = NULL;
            }
            is_sq_string = false;
            is_dq_string = false;
            add_value = false;
            break;
        default:
            add_value = true;
            amxc_string_appendf(helper, "%s", part);
            break;
        }
        free(part);
        part = amxt_cmd_pop_part(args);
    }

    amxc_string_resolve_esc(helper);

    if(!amxc_string_is_empty(helper)) {
        if(amxc_var_type_of(values) == AMXC_VAR_ID_HTABLE) {
            rv = amxt_values_set(values, key, helper, type == AMXC_VAR_ID_CSTRING);
        } else if(amxc_var_type_of(values) == AMXC_VAR_ID_LIST) {
            rv = amxt_values_set(values, key, helper, type == AMXC_VAR_ID_CSTRING);
        } else if(((flags & AMXT_VP_PRIMITIVE) != 0) &&
                  ( amxc_var_type_of(values) == AMXC_VAR_ID_NULL)) {
            amxc_var_set(cstring_t, values, amxc_string_get(helper, 0));
            if(type != AMXC_VAR_ID_CSTRING) {
                amxc_var_cast(values, AMXC_VAR_ID_ANY);
            }
            amxc_string_reset(helper);
        } else {
            rv = AMXT_VP_ERROR_TYPE;
        }
    }

exit:
    free(part);
    free(key);
    return rv;
}

static amxc_string_split_status_t
amxt_cmd_build_parts(amxc_llist_t* all, amxc_var_t* cmd_parts) {

    amxc_string_split_status_t retval = AMXC_ERROR_STRING_SPLIT_INVALID_INPUT;

    bool quotes = false;
    bool shebang = false;
    amxc_string_t str_part;

    amxc_var_set_type(cmd_parts, AMXC_VAR_ID_LIST);
    amxc_string_init(&str_part, 0);

    amxc_llist_for_each(it, all) {
        amxc_string_t* part = amxc_string_from_llist_it(it);
        const char* txt_part = amxc_string_get(part, 0);

        if(amxc_string_text_length(part) == 1) {
            switch(txt_part[0]) {
            case '"':
            case '\'':
                quotes = !quotes;
                if(!quotes) {
                    if(!amxc_string_is_empty(&str_part)) {
                        amxc_string_trim(&str_part, NULL);
                        amxc_var_add(cstring_t, cmd_parts, amxc_string_get(&str_part, 0));
                        amxc_string_reset(&str_part);
                    }
                    shebang = false;
                }
                amxc_var_add(cstring_t, cmd_parts, txt_part);
                break;
            case '!':
                if(!quotes) {
                    amxc_string_append(&str_part, txt_part, amxc_string_text_length(part));
                    shebang = true;
                } else {
                    amxc_string_append(&str_part, txt_part, amxc_string_text_length(part));
                }
                break;
            case ' ':
                if(!shebang) {
                    amxc_var_add(cstring_t, cmd_parts, txt_part);
                } else {
                    shebang = false;
                }
                break;
            default:
                if(quotes || shebang) {
                    amxc_string_append(&str_part, txt_part, amxc_string_text_length(part));
                    if(shebang) {
                        amxc_string_trim(&str_part, NULL);
                        amxc_var_add(cstring_t, cmd_parts, amxc_string_get(&str_part, 0));
                        amxc_string_reset(&str_part);
                        shebang = false;
                    }
                } else {
                    amxc_var_add(cstring_t, cmd_parts, txt_part);
                }
                break;
            }
        } else {
            if(quotes || shebang) {
                amxc_string_append(&str_part, txt_part, amxc_string_text_length(part));
                if(shebang) {
                    amxc_string_trim(&str_part, NULL);
                    amxc_var_add(cstring_t, cmd_parts, amxc_string_get(&str_part, 0));
                    amxc_string_reset(&str_part);
                    shebang = false;
                }
            } else {
                amxc_var_add(cstring_t, cmd_parts, txt_part);
            }
        }
    }

    if(amxc_string_text_length(&str_part) > 0) {
        amxc_string_trim(&str_part, NULL);
        amxc_var_add(cstring_t, cmd_parts, amxc_string_get(&str_part, 0));
    }
    amxc_string_clean(&str_part);

    retval = AMXC_STRING_SPLIT_OK;

    return retval;
}

amxc_string_split_status_t amxt_cmd_parse_line(char* txt,
                                               size_t length,
                                               amxc_var_t* parts,
                                               const char** reason) {
    amxc_string_t temp;
    amxc_string_split_status_t status = AMXC_STRING_SPLIT_OK;

    amxc_string_init(&temp, 0);
    amxc_string_push_buffer(&temp, txt, length + 1);

    status = amxc_string_split(&temp, parts, amxt_cmd_build_parts, reason);

    amxc_string_take_buffer(&temp);
    amxc_string_clean(&temp);
    return status;
}

char* amxt_cmd_take_all(amxc_var_t* parts) {
    amxc_string_t all;
    char* part = NULL;

    amxc_string_init(&all, 64);

    when_null(parts, exit);

    part = amxt_cmd_pop_part(parts);
    while(part != NULL) {
        if(part[0] == 0) {
            amxc_string_append(&all, " ", 1);
        } else {
            amxc_string_appendf(&all, "%s", part);
        }
        free(part);
        part = amxt_cmd_pop_part(parts);
    }

    part = amxc_string_take_buffer(&all);

exit:
    amxc_string_clean(&all);
    return part;
}

int amxt_cmd_parse_values(amxt_tty_t* tty,
                          amxc_var_t* args,
                          uint32_t flags,
                          amxc_var_t* values) {
    int retval = 0;
    amxc_string_t parsed;
    amxc_string_t helper;
    const char* error_msg[] = {
        "Invalid value - array not allowed",
        "Invalid value - table not allowed",
        "Invalid value - no composites allowed (only simple types)",
        "Missing key or name",
        "Invalid type",
        "Missing value",
    };

    amxc_string_init(&helper, 32);
    amxc_string_init(&parsed, 32);

    amxc_var_set_type(values, AMXC_VAR_ID_NULL);
    retval = amxt_cmd_parse_values_impl(args, flags, values, &helper, &parsed);
    if(retval != 0) {
        uint32_t length = amxc_string_text_length(&parsed);
        amxt_tty_errorf(tty, "%s\n", amxc_string_get(&parsed, 0));
        amxt_tty_errorf(tty, "${color.red}%*.*s${color.reset}\n", length, length, "^");
        amxt_tty_errorf(tty, "%s\n", error_msg[retval - 1]);
    }
    amxc_string_clean(&parsed);
    amxc_string_clean(&helper);
    return retval;
}

int amxt_cmd_get_values(amxc_var_t* args,
                        uint32_t flags,
                        amxc_var_t* values) {
    int retval = 0;
    amxc_string_t parsed;
    amxc_string_t helper;

    amxc_string_init(&helper, 32);
    amxc_string_init(&parsed, 32);

    retval = amxt_cmd_parse_values_impl(args, flags, values, &helper, &parsed);

    amxc_string_clean(&parsed);
    amxc_string_clean(&helper);
    return retval;
}