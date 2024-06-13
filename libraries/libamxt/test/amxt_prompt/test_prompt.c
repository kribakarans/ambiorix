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
#include <sys/time.h>
#include <sys/resource.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <cmocka.h>

#include <amxc/amxc.h>
#include <amxt/amxt_prompt.h>

#include "test_prompt.h"

#include <amxc/amxc_macros.h>
void test_prompt_init_clean(UNUSED void** state) {
    amxt_prompt_t prompt;

    assert_int_not_equal(amxt_prompt_init(NULL), 0);
    assert_int_equal(amxt_prompt_init(&prompt), 0);
    assert_int_equal(amxt_prompt_length(&prompt), 0);

    assert_int_not_equal(amxt_prompt_clean(NULL), 0);
    assert_int_equal(amxt_prompt_clean(&prompt), 0);
}


void test_prompt_set_get(UNUSED void** state) {
    amxt_prompt_t prompt;
    char* txt = NULL;
    assert_int_not_equal(amxt_prompt_set(NULL, "test>"), 0);
    assert_ptr_equal(amxt_prompt_get(NULL), NULL);
    assert_int_equal(amxt_prompt_length(NULL), 0);

    assert_int_equal(amxt_prompt_init(&prompt), 0);

    assert_int_not_equal(amxt_prompt_set(&prompt, NULL), 0);
    assert_int_not_equal(amxt_prompt_set(&prompt, ""), 0);

    assert_int_equal(amxt_prompt_init(&prompt), 0);
    assert_int_equal(amxt_prompt_set(&prompt, "test>"), 0);
    txt = amxt_prompt_get(&prompt);
    assert_string_equal(txt, "test>");
    free(txt);
    assert_int_equal(amxt_prompt_length(&prompt), 5);

    assert_int_equal(amxt_prompt_clean(&prompt), 0);
}

static void test_resolve_prompt(amxc_string_t* txt, UNUSED void* priv) {
    amxc_string_setf(txt, "changed <");
}

void test_prompt_set_resolver_fn(UNUSED void** state) {
    amxt_prompt_t prompt;
    char* txt = NULL;

    assert_int_equal(amxt_prompt_init(&prompt), 0);
    assert_int_equal(amxt_prompt_set_resolver(&prompt, test_resolve_prompt, NULL), 0);

    assert_int_equal(amxt_prompt_set(&prompt, "test>"), 0);
    txt = amxt_prompt_get(&prompt);
    assert_string_equal(txt, "changed <");
    free(txt);

    assert_int_equal(amxt_prompt_clean(&prompt), 0);
}
