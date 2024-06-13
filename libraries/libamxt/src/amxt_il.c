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
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <amxc/amxc_string.h>
#include <amxt/amxt_il.h>

#include "amxt_priv.h"

int amxt_il_new(amxt_il_t** il, const size_t size) {
    int retval = -1;
    when_null(il, exit);

    *il = (amxt_il_t*) calloc(1, sizeof(amxt_il_t));
    when_null(*il, exit);

    if(amxc_string_init(&(*il)->buffer, size) != 0) {
        free(*il);
        *il = NULL;
        goto exit;
    }

    (*il)->mode = amxc_string_insert;
    retval = 0;

exit:
    return retval;
}

void amxt_il_delete(amxt_il_t** il) {
    when_null(il, exit);

    amxc_string_clean(&(*il)->buffer);
    free((*il));
    *il = NULL;

exit:
    return;
}

int amxt_il_init(amxt_il_t* const il, const size_t size) {
    int retval = -1;
    when_null(il, exit);

    when_failed(amxc_string_init(&il->buffer, size), exit);
    il->cursor_pos = 0;
    il->mode = amxc_string_insert;

    retval = 0;

exit:
    return retval;
}

void amxt_il_clean(amxt_il_t* const il) {
    when_null(il, exit);

    amxc_string_clean(&il->buffer);
    il->cursor_pos = 0;
    il->mode = amxc_string_insert;

exit:
    return;
}

void amxt_il_reset(amxt_il_t* const il) {
    when_null(il, exit);

    amxc_string_reset(&il->buffer);
    il->cursor_pos = 0;
    il->mode = amxc_string_insert;

exit:
    return;
}

int amxt_il_insert_block(amxt_il_t* const il,
                         const char* const block,
                         const int block_len) {
    int retval = -1;

    when_null(il, exit);
    when_null(block, exit);

    if(block_len == 0) {
        retval = 0;
        goto exit;
    }

    when_failed(amxc_string_set_at(&il->buffer,
                                   il->cursor_pos,
                                   block,
                                   block_len,
                                   il->mode), exit);
    il->cursor_pos += block_len;
    retval = 0;

exit:
    return retval;
}

int amxt_il_remove_char(amxt_il_t* const il, const amxt_il_flags_t flags) {
    int retval = -1;
    int cursor_pos = 0;

    when_null(il, exit);
    if(flags & amxt_il_keep_cursor_pos) {
        if(il->cursor_pos == amxc_string_text_length(&il->buffer)) {
            retval = 0;
            goto exit;
        }
        cursor_pos = il->cursor_pos;
    } else {
        if(il->cursor_pos == 0) {
            retval = 0;
            goto exit;
        }
        cursor_pos = il->cursor_pos - 1;
    }

    retval = amxc_string_remove_at(&il->buffer, cursor_pos, 1);

    if(((flags & amxt_il_keep_cursor_pos) != amxt_il_keep_cursor_pos) &&
       ( retval == 0)) {
        il->cursor_pos--;
    }

exit:
    return retval;
}

int amxt_il_set_cursor_pos(amxt_il_t* const il, const uint32_t pos) {
    size_t length = 0;
    int new_pos = 0;

    when_null(il, exit);
    length = amxc_string_text_length(&il->buffer);
    if(pos > length) {
        il->cursor_pos = length;
    } else {
        il->cursor_pos = pos;
    }

    new_pos = il->cursor_pos;

exit:
    return new_pos;
}

int amxt_il_move_cursor(amxt_il_t* const il, const int delta) {
    int new_pos = 0;
    size_t length = 0;

    when_null(il, exit);
    length = amxc_string_text_length(&il->buffer);
    if((int) il->cursor_pos + delta > (int) length) {
        il->cursor_pos = length;
    } else if((int) il->cursor_pos + delta < 0) {
        il->cursor_pos = 0;
    } else {
        il->cursor_pos += delta;
    }

    new_pos = il->cursor_pos;

exit:
    return new_pos;
}

const char* amxt_il_text(const amxt_il_t* const il,
                         const amxt_il_flags_t flags,
                         const int offset) {
    const char* text = NULL;
    uint32_t cursor_pos = 0;

    when_null(il, exit);

    cursor_pos = 0;
    if(flags & amxt_il_text_after_cursor) {
        cursor_pos = il->cursor_pos;
    }

    if((int) cursor_pos + offset < 0) {
        text = amxc_string_get(&il->buffer, 0);
    } else if(cursor_pos + offset > amxc_string_text_length(&il->buffer)) {
        text = amxc_string_get(&il->buffer, amxc_string_text_length(&il->buffer));
    } else {
        text = amxc_string_get(&il->buffer, cursor_pos + offset);
        if(text == NULL) {
            text = "";
        }
    }

exit:
    return text;
}

size_t amxt_il_text_length(const amxt_il_t* const il,
                           const amxt_il_flags_t flags,
                           const int offset) {
    size_t text_length = 0;
    const char* text = NULL;
    when_null(il, exit);

    text = amxt_il_text(il, flags, offset);
    text_length = strlen(text);

exit:
    return text_length;
}

amxc_string_flags_t amxt_il_mode(const amxt_il_t* const il) {
    return il != NULL ? il->mode : amxc_string_insert;
}

int amxt_il_set_mode(amxt_il_t* const il,
                     const amxc_string_flags_t mode) {
    int retval = -1;
    when_null(il, exit);

    il->mode = mode;
    retval = 0;

exit:
    return retval;
}
