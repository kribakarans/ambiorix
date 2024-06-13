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

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/variant_siginfo.h>
#include <amxp/amxp_dir.h>

#include "test_dir.h"

static int test_add_to_list(const char* name, void* priv) {
    amxc_string_t* f = NULL;
    amxc_llist_t* l = (amxc_llist_t*) priv;

    amxc_string_new(&f, 0);
    amxc_string_setf(f, "%s", name);
    amxc_llist_append(l, &f->it);

    return 0;
}

int test_dir_teardown(UNUSED void** state) {
    rmdir("./subdir/nextlevel");
    rmdir("./subdir/otherdir/next");
    rmdir("./subdir/otherdir");
    rmdir("./subdir/nextlevel");
    rmdir("/tmp/subdir/nextlevel");
    rmdir("./subdir");

    return 0;
}

void test_dir_make(UNUSED void** state) {
    assert_int_equal(amxp_dir_make("./subdir/nextlevel", 0777), 0);
    assert_int_equal(amxp_dir_make("./subdir/otherdir", 0777), 0);
    assert_int_equal(amxp_dir_make("./subdir/otherdir/next", 0777), 0);
    assert_int_equal(amxp_dir_make("./subdir/nextlevel", 0777), 0);
    assert_int_equal(amxp_dir_make("/tmp/subdir/nextlevel", 0777), 0);

    assert_int_not_equal(amxp_dir_make("", 0777), 0);
    assert_int_not_equal(amxp_dir_make(NULL, 0777), 0);
}

void test_dir_scan(UNUSED void** state) {
    amxc_llist_t files;
    amxc_llist_init(&files);

    assert_int_equal(amxp_dir_scan(".", "d_type == DT_REG", true, test_add_to_list, &files), 0);
    assert_int_equal(amxc_llist_size(&files), 5);
    amxc_llist_clean(&files, amxc_string_list_it_free);

    assert_int_equal(amxp_dir_scan(".", "d_type == DT_DIR", true, test_add_to_list, &files), 0);
    assert_int_equal(amxc_llist_size(&files), 4);
    amxc_llist_clean(&files, amxc_string_list_it_free);

    assert_int_equal(amxp_dir_scan(".", "d_type == DT_DIR", false, test_add_to_list, &files), 0);
    assert_int_equal(amxc_llist_size(&files), 1);
    amxc_llist_clean(&files, amxc_string_list_it_free);

    assert_int_equal(amxp_dir_scan(".", "d_type == DT_LNK", true, test_add_to_list, &files), 0);
    assert_int_equal(amxc_llist_size(&files), 0);
    amxc_llist_clean(&files, amxc_string_list_it_free);

    assert_int_equal(amxp_dir_scan(".", "d_type in [DT_BLK, DT_CHR, DT_FIFO, DT_SOCK, DT_UNKNOWN]", true, test_add_to_list, &files), 0);
    assert_int_equal(amxc_llist_size(&files), 0);
    amxc_llist_clean(&files, amxc_string_list_it_free);

    assert_int_equal(amxp_dir_scan(".", "d_type == DT_INVALID", true, test_add_to_list, &files), 0);
    assert_int_equal(amxc_llist_size(&files), 0);
    amxc_llist_clean(&files, amxc_string_list_it_free);

    assert_int_equal(amxp_dir_scan(".", "d_name matches '.*\\.c'", true, test_add_to_list, &files), 0);
    assert_int_equal(amxc_llist_size(&files), 2);
    amxc_llist_clean(&files, amxc_string_list_it_free);

    assert_int_not_equal(amxp_dir_scan("/notexisting", NULL, true, test_add_to_list, &files), 0);
    assert_true(amxc_llist_is_empty(&files));

    assert_int_not_equal(amxp_dir_scan(NULL, NULL, true, test_add_to_list, &files), 0);
    assert_true(amxc_llist_is_empty(&files));

    assert_int_not_equal(amxp_dir_scan("", NULL, true, test_add_to_list, &files), 0);
    assert_true(amxc_llist_is_empty(&files));

    assert_int_not_equal(amxp_dir_scan("./test_dir.c", NULL, true, test_add_to_list, &files), 0);
    assert_true(amxc_llist_is_empty(&files));
}

void test_dir_is_empty(UNUSED void** state) {
    assert_false(amxp_dir_is_empty("."));
    assert_true(amxp_dir_is_empty(""));
    assert_true(amxp_dir_is_empty(NULL));

    assert_false(amxp_dir_is_empty("./subdir"));
    assert_true(amxp_dir_is_empty("./subdir/nextlevel"));

    assert_true(amxp_dir_is_empty("./test_dir.c"));
}

void test_dir_is_a_directory(UNUSED void** state) {
    assert_true(amxp_dir_is_directory("."));
    assert_false(amxp_dir_is_directory(""));
    assert_false(amxp_dir_is_directory(NULL));

    assert_true(amxp_dir_is_directory("./subdir"));
    assert_true(amxp_dir_is_directory("./subdir/nextlevel"));

    assert_false(amxp_dir_is_directory("./test_dir.c"));
}
