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

#include <ctype.h>

#include "amx_cli.h"
#include "amx_cli_parser.h"


static void amx_cli_self_mods(amxc_var_t* words, const char* start) {
    amxc_string_t cmd;
    amxm_shared_object_t* so = amxm_get_so("self");
    size_t mod_count = amxm_so_count_modules(so);
    size_t slen = start == NULL ? 0 : strlen(start);

    amxc_string_init(&cmd, 0);

    for(size_t i = 0; i < mod_count; i++) {
        char* mod_name = amxm_so_probe(so, i);
        amxc_string_setf(&cmd, "!%s ", mod_name);
        free(mod_name);
        if((slen == 0) || (strncmp(start, amxc_string_get(&cmd, 0), slen) == 0)) {
            amxc_var_add(cstring_t, words, amxc_string_get(&cmd, 0));
        }
        amxc_string_reset(&cmd);
    }

    amxc_string_clean(&cmd);
}

static void amx_cli_aliases(amxc_var_t* words, const char* start) {
    amxc_var_t* aliases = amx_cli_get_aliases();
    amxc_array_t* keys = amxc_htable_get_sorted_keys(&aliases->data.vm);
    size_t count = amxc_array_size(keys);
    size_t slen = start == NULL ? 0 : strlen(start);

    for(size_t index = 0; index < count; index++) {
        amxc_array_it_t* it = amxc_array_get_at(keys, index);
        const char* alias = (const char*) amxc_array_it_get_data(it);
        if((slen == 0) || (strncmp(start, alias, slen) == 0)) {
            amxc_var_add(cstring_t, words, alias);
        }
    }

    amxc_array_delete(&keys, NULL);
}

static int amx_cli_complete_funcs(amxc_var_t* cmd_parts,
                                  char* part,
                                  amxc_var_t* words) {
    int retval = 1;
    const char* so = NULL;
    char* mod = NULL;
    char* func = NULL;

    if((part != NULL) && (part[0] == '!')) {
        so = "self";
        mod = strdup(part + 1);
        part = NULL;
        when_null(mod, exit);
    } else {
        so = amx_cli_get_shared_object();
        mod = part != NULL ? strdup(part) : NULL;
        part = NULL;
    }
    if(amxm_get_module(so, mod) == NULL) {
        amxt_cmd_prepend_part(cmd_parts, mod);
        free(mod);
        mod = amx_cli_get_module() == NULL ? NULL : strdup(amx_cli_get_module());
    }
    when_null(mod, exit);

    amxt_cmd_triml(cmd_parts, ' ');
    func = amxt_cmd_pop_part(cmd_parts);
    if(!amxm_has_function(so, mod, func)) {
        amxm_module_t* m = amxm_get_module(so, mod);
        amx_cli_complete_add_funcs(m, func, words);
        amxt_cmd_prepend_part(cmd_parts, func);
        free(func);
        func = NULL;
        when_true(!amxm_has_function(so, mod, "__complete"), exit);
        amxm_execute_function(so, mod, "__complete", cmd_parts, words);
    } else {
        amxc_string_t complete_func;
        amxc_string_init(&complete_func, 0);
        amxc_string_setf(&complete_func, "__complete_%s", func);
        free(func);
        func = amxc_string_take_buffer(&complete_func);
        when_true(!amxm_has_function(so, mod, func), exit);
        amxm_execute_function(so, mod, func, cmd_parts, words);
    }

    retval = 0;

exit:
    free(func);
    free(mod);
    return retval;
}

static uint32_t amx_cli_biggest_common(const amxc_var_t* words,
                                       amxc_var_t** var_biggest) {
    const char* txt_biggest = NULL;
    uint32_t len_biggest = 0;

    amxc_var_for_each(word, words) {
        const char* current = amxc_var_constcast(cstring_t, word);
        uint32_t len_current = strlen(current);
        uint32_t len_max = len_biggest > len_current ? len_current : len_biggest;

        if(txt_biggest == NULL) {
            *var_biggest = word;
            txt_biggest = current;
            len_biggest = len_current;
            continue;
        }

        len_biggest = 0;
        for(uint32_t i = 0; i < len_max; i++) {
            if(txt_biggest[i] != current[i]) {
                break;
            }
            len_biggest++;
        }

        if(len_biggest < len_max) {
            *var_biggest = word;
            txt_biggest = current;
        }
    }

    if(len_biggest == 0) {
        *var_biggest = NULL;
    }
    return len_biggest;
}

static uint32_t amx_cli_matching_size(const char* text,
                                      const char* w,
                                      uint32_t bcs) {
    uint32_t ms = bcs;
    while(ms > 0) {
        if(strncmp(text - ms, w, ms) == 0) {
            break;
        }
        ms--;
    }

    return ms;
}

static void amx_cli_complete_or_dump(amxt_tty_t* tty,
                                     const amxc_var_t* words) {
    amxt_il_t* il = amxt_tty_il(tty);
    const char* txt = amxt_il_text(il, amxt_il_no_flags, 0);
    int il_length = amxt_il_text_length(il, amxt_il_no_flags, 0);
    int il_pos = amxt_il_cursor_pos(il);
    amxc_var_t* word = NULL;
    int bcs = amx_cli_biggest_common(words, &word);
    int ms = 0;

    if(bcs > 0) {
        const char* w = amxc_var_constcast(cstring_t, word);
        ms = amx_cli_matching_size(txt + il_pos, w, bcs > il_pos ? il_pos : bcs);
    }

    if(bcs - ms > 0) {
        amxc_string_flags_t mode = amxt_il_mode(il);
        const char* w = amxc_var_constcast(cstring_t, word);
        word->data.s[bcs] = 0;
        amxt_il_set_mode(il, amxc_string_insert);
        amxt_il_insert_block(il, w + ms, strlen(w) - ms);
        amxt_il_set_mode(il, mode);
        amxt_tty_cursor_move(tty, -il_pos, 0);
        amxt_tty_line_clear(tty, amxt_clear_line_cursor_to_end);

        txt = amxt_il_text(il, amxt_il_no_flags, 0);
        il_length = amxt_il_text_length(il, amxt_il_no_flags, 0);
        amxt_tty_write_raw(tty, txt, il_length);
        amxt_tty_cursor_move(tty, -(il_length - il_pos) + strlen(w) - ms, 0);
    } else {
        if(amxc_llist_size(&words->data.vl) > 1) {
            amxt_tty_writef(tty, "${color.reset}\n\n");
            amxc_var_for_each(var_word, (words)) {
                const char* w = amxc_var_constcast(cstring_t, var_word);
                amxt_tty_writef(tty, "%s\n", w);
            }
            amxt_tty_writef(tty, "\n");
            amxt_tty_show_prompt(tty);
            amxt_tty_write_raw(tty, txt, il_length);
            amxt_tty_cursor_move(tty, -(il_length - il_pos), 0);
        }
    }

    return;
}

static void amx_cli_complete_cmd(amxc_var_t* cmd_data) {
    amxc_var_t* cmd_parts = GET_ARG(cmd_data, "cmd");
    amxc_var_t* words = NULL;
    char* part = NULL;
    amxt_tty_t* tty = GET_TTY(cmd_data);

    amxc_var_new(&words);
    amxc_var_set_type(words, AMXC_VAR_ID_LIST);

    amxt_cmd_triml(cmd_parts, ' ');
    part = amxc_cli_take_cmd(cmd_parts);

    if(amxt_cmd_is_empty(cmd_parts)) {
        amx_cli_self_mods(words, part);
        amx_cli_aliases(words, part);
    }
    if(amx_cli_complete_funcs(cmd_parts, part, words) != 0) {
        amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", words);
        amxc_var_delete(&words);
    }

    free(part);
}

void amx_cli_slot_docomplete(UNUSED const char* const sig_name,
                             const amxc_var_t* const words,
                             void* priv) {
    amxt_tty_t* tty = (amxt_tty_t*) priv;
    amxt_il_t* il = amxt_tty_il(tty);
    const char* txt = amxt_il_text(il, amxt_il_no_flags, 0);
    int il_length = amxt_il_text_length(il, amxt_il_no_flags, 0);

    if(amxc_var_type_of(words) == AMXC_VAR_ID_LIST) {
        amx_cli_complete_or_dump(tty, words);
    } else {
        char* help_txt = amxc_var_dyncast(cstring_t, words);
        amxt_tty_writef(tty, "\n\n%s\n", help_txt);
        amxt_tty_show_prompt(tty);
        amxt_tty_write(tty, txt, il_length);
        free(help_txt);
    }
}

void amx_cli_slot_complete(UNUSED const char* const sig_name,
                           const amxc_var_t* const data,
                           UNUSED void* priv) {
    amxc_var_t* var_txt = GET_ARG(data, "text");
    amxc_var_t* var_tty = GET_ARG(data, "tty");
    char* txt = amxc_var_dyncast(cstring_t, var_txt);
    amxt_tty_t* tty = amxc_var_constcast(amxt_tty_t, var_tty);
    amxt_il_t* il = amxt_tty_il(tty);
    size_t length = amxt_il_cursor_pos(il);
    amxc_var_t args;
    amxc_var_t* cmd_parts = NULL;

    txt[length] = 0;
    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);

    cmd_parts = amxc_var_add_key(amxc_llist_t, &args, "cmd", NULL);
    amxc_var_add_key(amxt_tty_t, &args, "tty", tty);
    amxt_cmd_parse_line(txt, length, cmd_parts, NULL);
    amxt_cmd_triml(cmd_parts, ' ');
    amx_cli_complete_cmd(&args);

    free(txt);
    amxc_var_clean(&args);
}

void amx_cli_complete_add_funcs(amxm_module_t* mod,
                                const char* start,
                                amxc_var_t* words) {
    amxc_array_t* funcs = amxm_module_get_function_names(mod);

    uint32_t len = start == NULL ? 0 : strlen(start);
    size_t func_count = amxc_array_size(funcs);
    for(size_t index = 0; index < func_count; index++) {
        amxc_array_it_t* it = amxc_array_get_at(funcs, index);
        const char* func_name = (const char*) amxc_array_it_get_data(it);
        if(strncmp(func_name, "__", 2) == 0) {
            continue;
        }
        if((start == NULL) || (strncmp(start, func_name, len) == 0)) {
            amxc_var_add(cstring_t, words, func_name);
        }
    }
    amxc_array_delete(&funcs, NULL);
}
