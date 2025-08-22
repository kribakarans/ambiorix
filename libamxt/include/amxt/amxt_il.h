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

#if !defined(__AMXT_IL_H__)
#define __AMXT_IL_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

#ifndef __AMXC_STRING_H__
#error "include <amxc/amxc_string.h> before <amxt/amxt_il.h>"
#endif

#if !defined(USE_DOXYGEN)
#define AMXT_INLINE static inline
#else
/**
   @brief
   Helper macro for inlining functions
 */
#define AMXT_INLINE
#endif

typedef enum _amxt_il_flags {
    amxt_il_no_flags             = 0x00,
    amxt_il_keep_cursor_pos      = 0x01,
    amxt_il_text_after_cursor    = 0x02,
} amxt_il_flags_t;

typedef struct _amxt_il {
    amxc_string_t buffer;
    uint32_t cursor_pos;
    amxc_string_flags_t mode;
} amxt_il_t;

int amxt_il_new(amxt_il_t** il, const size_t size);
void amxt_il_delete(amxt_il_t** il);

int amxt_il_init(amxt_il_t* const il, const size_t size);
void amxt_il_clean(amxt_il_t* const il);
void amxt_il_reset(amxt_il_t* const il);

int amxt_il_insert_block(amxt_il_t* const il,
                         const char* const block,
                         const int block_len);
int amxt_il_remove_char(amxt_il_t* const il,
                        const amxt_il_flags_t flags);

AMXT_INLINE
int amxt_il_cursor_pos(const amxt_il_t* const il) {
    return il != NULL ? il->cursor_pos : 0;
}

int amxt_il_set_cursor_pos(amxt_il_t* const il, const uint32_t pos);
int amxt_il_move_cursor(amxt_il_t* const il, const int delta);

const char* amxt_il_text(const amxt_il_t* const il,
                         const amxt_il_flags_t flags,
                         const int offset);

size_t amxt_il_text_length(const amxt_il_t* const il,
                           const amxt_il_flags_t flags,
                           const int offset);

amxc_string_flags_t amxt_il_mode(const amxt_il_t* const il);

int amxt_il_set_mode(amxt_il_t* const il, const amxc_string_flags_t mode);

#ifdef __cplusplus
}
#endif

#endif // __AMXT_IL_H__
