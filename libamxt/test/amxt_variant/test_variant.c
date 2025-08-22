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
#include <amxp/amxp.h>
#include <amxt/amxt_tty.h>
#include <amxt/amxt_variant.h>

#include "test_variant.h"

#include <amxc/amxc_macros.h>
static int istty = 0;

int __wrap_isatty(int fd);
int __wrap_ttyname_r(int fd, char* buf, size_t buflen);
int __wrap_open(const char* path, int oflag, int mode);
int __real_open(const char* path, int oflag, int mode);

int __wrap_ttyname_r(UNUSED int fd, char* buf, size_t buflen) {
    strncpy(buf, "/tmp/test_tty", buflen);

    return 0;
}

int __wrap_open(const char* path, int oflag, int mode) {
    if(strcmp(path, "/tmp/test_tty") == 0) {
        return 0;
    }
    return __real_open(path, oflag, mode);
}

int __wrap_isatty(UNUSED int fd) {
    return istty;
}

void test_variant_init_copy_clean(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    amxc_var_t var_tty;
    amxc_var_t copy_tty;
    const amxt_tty_t* tty2 = NULL;

    amxc_var_init(&var_tty);
    amxc_var_init(&copy_tty);

    istty = 1;
    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);
    assert_ptr_not_equal(tty, NULL);

    assert_ptr_equal(amxc_var_set(amxt_tty_t, &var_tty, tty), 0);
    assert_ptr_equal(amxc_var_copy(&copy_tty, &var_tty), 0);

    tty2 = amxc_var_constcast(amxt_tty_t, &copy_tty);
    assert_ptr_equal(tty2, tty);

    amxc_var_clean(&var_tty);
    amxc_var_clean(&copy_tty);
    amxt_tty_close(&tty);
}

void test_variant_convert_to_null(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    amxc_var_t src_var;
    amxc_var_t dst_var;

    amxc_var_init(&src_var);
    amxc_var_init(&dst_var);

    istty = 1;
    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);
    assert_ptr_not_equal(tty, NULL);

    assert_ptr_equal(amxc_var_set(amxt_tty_t, &src_var, tty), 0);
    assert_int_equal(amxc_var_convert(&dst_var, &src_var, AMXC_VAR_ID_NULL), 0);

    amxc_var_clean(&src_var);
    amxc_var_clean(&dst_var);
    amxt_tty_close(&tty);
}

void test_variant_convert_to_fd(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    amxc_var_t src_var;
    amxc_var_t dst_var;

    amxc_var_init(&src_var);
    amxc_var_init(&dst_var);

    istty = 1;
    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);
    assert_ptr_not_equal(tty, NULL);

    assert_ptr_equal(amxc_var_set(amxt_tty_t, &src_var, tty), 0);
    assert_int_equal(amxc_var_convert(&dst_var, &src_var, AMXC_VAR_ID_FD), 0);
    assert_int_equal(amxc_var_type_of(&dst_var), AMXC_VAR_ID_FD);

    assert_int_not_equal(amxc_var_convert(&dst_var, &src_var, AMXC_VAR_ID_CUSTOM_BASE), 0);

    assert_int_equal(amxc_var_convert(&dst_var, &src_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&dst_var), AMXC_VAR_ID_FD);

    amxc_var_clean(&src_var);
    amxc_var_clean(&dst_var);
    amxt_tty_close(&tty);
}

void test_variant_take(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    const amxt_tty_t* tty2 = NULL;
    amxc_var_t var;

    amxc_var_init(&var);

    istty = 1;
    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);
    assert_ptr_not_equal(tty, NULL);

    assert_ptr_equal(amxc_var_set(amxt_tty_t, &var, tty), 0);

    tty2 = amxc_var_get_const_amxt_tty_t(&var);
    assert_ptr_equal(tty2, tty);
    tty2 = amxc_var_get_const_amxt_tty_t(NULL);
    assert_ptr_equal(tty2, NULL);

    amxc_var_set(cstring_t, &var, "Hello world");
    tty2 = amxc_var_get_const_amxt_tty_t(&var);
    assert_ptr_equal(tty2, NULL);

    assert_ptr_equal(amxc_var_set(amxt_tty_t, &var, tty), 0);
    tty2 = amxc_var_take_amxt_tty_t(&var);
    assert_ptr_equal(tty2, tty);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_NULL);
    tty2 = amxc_var_take_amxt_tty_t(NULL);
    assert_ptr_equal(tty2, NULL);

    amxc_var_set(cstring_t, &var, "Hello world");
    tty2 = amxc_var_take_amxt_tty_t(&var);
    assert_ptr_equal(tty2, NULL);

    amxc_var_clean(&var);
    amxt_tty_close(&tty);
}

void test_variant_add(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    amxc_var_t var;

    amxc_var_init(&var);

    istty = 1;
    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);
    assert_ptr_not_equal(tty, NULL);

    amxc_var_set_type(&var, AMXC_VAR_ID_LIST);
    assert_ptr_not_equal(amxc_var_add_new_amxt_tty_t(&var, tty), NULL);

    amxc_var_set_type(&var, AMXC_VAR_ID_CSTRING);
    assert_ptr_equal(amxc_var_add_new_amxt_tty_t(&var, tty), NULL);

    amxc_var_set_type(&var, AMXC_VAR_ID_HTABLE);
    assert_ptr_not_equal(amxc_var_add_new_key_amxt_tty_t(&var, "key", tty), NULL);

    amxc_var_set_type(&var, AMXC_VAR_ID_CSTRING);
    assert_ptr_equal(amxc_var_add_new_key_amxt_tty_t(&var, "key", tty), NULL);

    assert_ptr_equal(amxc_var_add_new_amxt_tty_t(NULL, tty), NULL);
    assert_ptr_equal(amxc_var_add_new_key_amxt_tty_t(NULL, "key", tty), NULL);

    amxc_var_clean(&var);
    amxt_tty_close(&tty);
}
