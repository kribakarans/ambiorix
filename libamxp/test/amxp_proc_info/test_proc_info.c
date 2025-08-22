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

#include <sys/types.h>
#include <dirent.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <fcntl.h>
#include <cmocka.h>
#include <string.h>
#include <stdio.h>

#include <amxc/amxc.h>
#include <amxp/amxp_proc_info.h>

#include "test_proc_info.h"

#include <amxc/amxc_macros.h>
DIR* __real_opendir(const char* name);
DIR* __wrap_opendir(const char* name);

FILE* __wrap_fopen(const char* pathname, const char* mode);
FILE* __real_fopen(const char* pathname, const char* mode);

DIR* __wrap_opendir(const char* name) {
    if(strcmp(name, "/proc/") == 0) {
        return __real_opendir("./proc/");
    } else {
        return __real_opendir(name);
    }
}

FILE* __wrap_fopen(const char* pathname, const char* mode) {
    if(strncmp(pathname, "/proc/", 6) == 0) {
        amxc_string_t fake_file;
        FILE* retval = NULL;
        amxc_string_init(&fake_file, 0);
        amxc_string_setf(&fake_file, ".%s", pathname);
        retval = __real_fopen(amxc_string_get(&fake_file, 0), mode);
        amxc_string_clean(&fake_file);
        return retval;
    } else {
        return __real_fopen(pathname, mode);
    }
}

void test_proc_info_find_all(UNUSED void** state) {
    amxc_llist_t procs;

    amxc_llist_init(&procs);
    assert_int_equal(amxp_proci_findf(&procs, NULL), 0);

    amxc_llist_for_each(it, (&procs)) {
        amxp_proc_info_t* pi = amxc_container_of(it, amxp_proc_info_t, it);
        printf("Name %s\n", pi->name);
    }
    assert_int_equal(amxc_llist_size(&procs), 2);

    amxc_llist_clean(&procs, amxp_proci_free_it);

    assert_int_not_equal(amxp_proci_findf(NULL, NULL), 0);
}

void test_proc_info_find_filtered(UNUSED void** state) {
    amxc_llist_t procs;

    amxc_llist_init(&procs);

    assert_int_equal(amxp_proci_findf(&procs, "ppid == %d", 6038), 0);
    amxc_llist_for_each(it, (&procs)) {
        amxp_proc_info_t* pi = amxc_container_of(it, amxp_proc_info_t, it);
        assert_int_equal(pi->parent_pid, 6038);
        printf("Name %s\n", pi->name);
    }
    assert_int_equal(amxc_llist_size(&procs), 1);

    amxc_llist_clean(&procs, amxp_proci_free_it);

    assert_int_equal(amxp_proci_findf(&procs, "parent_pid == %d", 1610), 0);
    amxc_llist_for_each(it, (&procs)) {
        amxp_proc_info_t* pi = amxc_container_of(it, amxp_proc_info_t, it);
        assert_int_equal(pi->parent_pid, 1610);
        printf("Name %s\n", pi->name);
    }
    assert_int_equal(amxc_llist_size(&procs), 1);

    amxc_llist_clean(&procs, amxp_proci_free_it);

    assert_int_equal(amxp_proci_findf(&procs, "name == 'ssh_server'"), 0);
    amxc_llist_for_each(it, (&procs)) {
        amxp_proc_info_t* pi = amxc_container_of(it, amxp_proc_info_t, it);
        assert_string_equal(pi->name, "ssh_server");
        printf("Name %s\n", pi->name);
    }
    assert_int_equal(amxc_llist_size(&procs), 1);

    amxc_llist_clean(&procs, amxp_proci_free_it);

    assert_int_equal(amxp_proci_findf(&procs, "state == 'R'"), 0);
    assert_int_equal(amxc_llist_size(&procs), 0);

    assert_int_equal(amxp_proci_findf(&procs, "invalid_field > 1000"), 0);
    assert_int_equal(amxc_llist_size(&procs), 0);
}

void test_proc_info_find_fails_with_invalid_expr(UNUSED void** state) {
    amxc_llist_t procs;

    amxc_llist_init(&procs);

    assert_int_not_equal(amxp_proci_findf(&procs, "ppid <> %d", 6038), 0);
    assert_int_equal(amxc_llist_size(&procs), 0);

    amxc_llist_clean(&procs, amxp_proci_free_it);
}
