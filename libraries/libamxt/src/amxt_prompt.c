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

#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <amxc/amxc_string.h>
#include <amxt/amxt_prompt.h>

#include "amxt_priv.h"

int amxt_prompt_init(amxt_prompt_t* const prompt) {
    int retval = -1;
    when_null(prompt, exit);

    when_failed(amxc_string_init(&prompt->prompt, 0), exit);
    prompt->resolve = NULL;

    retval = 0;

exit:
    return retval;
}

int amxt_prompt_clean(amxt_prompt_t* const prompt) {
    int retval = -1;
    when_null(prompt, exit);

    amxc_string_clean(&prompt->prompt);

    retval = 0;

exit:
    return retval;
}

int amxt_prompt_set_resolver(amxt_prompt_t* const prompt,
                             amxt_prompt_resolve_fn_t fn,
                             void* priv) {
    int retval = -1;
    when_null(prompt, exit);

    prompt->resolve = fn;
    prompt->priv = priv;

    retval = 0;

exit:
    return retval;
}

int amxt_prompt_set(amxt_prompt_t* const prompt, const char* txt) {
    int retval = -1;
    when_null(prompt, exit);
    when_null(txt, exit);
    when_true(*txt == 0x00, exit);

    amxc_string_reset(&prompt->prompt);
    retval = amxc_string_set_at(&prompt->prompt,
                                0,
                                txt,
                                strlen(txt),
                                amxc_string_no_flags);
exit:
    return retval;
}

char* amxt_prompt_get(const amxt_prompt_t* const prompt) {
    char* text = NULL;
    amxc_string_t resolved;
    size_t len = amxt_prompt_length(prompt) + 1;

    amxc_string_init(&resolved, len);
    when_null(prompt, exit);

    amxc_string_set_at(&resolved,
                       0,
                       amxc_string_get(&prompt->prompt, 0),
                       len,
                       amxc_string_no_flags);

    if(prompt->resolve != NULL) {
        prompt->resolve(&resolved, prompt->priv);
    }

    text = amxc_string_take_buffer(&resolved);

exit:
    amxc_string_clean(&resolved);
    return text;
}

size_t amxt_prompt_length(const amxt_prompt_t* const prompt) {
    return prompt != NULL ? amxc_string_text_length(&prompt->prompt) : 0;
}
