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
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

#include <amxc/amxc_variant.h>
#include <amxc/amxc_llist.h>
#include <amxc/amxc_htable.h>

#include <amxm/amxm.h>

#include <amxm_priv.h>
#include <limits.h>

#include "test_executable.h"

#include <amxc/amxc_macros.h>

#define STREMPTY "\0"
#define STRLARGE    "                                        " \
    "                                        " \
    "                                        " \
    "                                        " \
    "                                        " \
    "                                        " \
    "                                        " \
    "                                        "

/* *******************
 * Helper functions
 * *******************
 */
void rand_str(char* charset, size_t charset_len, char* dest, size_t dest_len) {
    while(--dest_len) {
        size_t index = (double) rand() / RAND_MAX * (charset_len - 1);
        *dest++ = charset[index];
    }
    *dest = '\0';
}

void gen_module_namespace_str(char* dest, size_t dest_len) {
    char charset[] = "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "/.+?*[]{}-+";
    dest_len--;
    rand_str(charset, sizeof(charset), dest, dest_len);
}

void gen_function_name_str(char* dest, size_t dest_len) {
    char charset[] = "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "/.+?*[]{}-+";
    dest_len--;
    rand_str(charset, sizeof(charset), dest, dest_len);
}

/* ********************
 * Shared object (so)
 * ********************
 */
void test_open_shared_object_args(UNUSED void** state) {
    amxm_shared_object_t* so = NULL;

    assert_int_not_equal(amxm_so_open(&so, NULL, "module.so"), 0);
    assert_ptr_equal(so, NULL);
    assert_int_not_equal(amxm_so_open(&so, "module", NULL), 0);
    assert_ptr_equal(so, NULL);
    assert_int_not_equal(amxm_so_open(&so, NULL, NULL), 0);
    assert_ptr_equal(so, NULL);

    assert_int_not_equal(amxm_so_open(&so, STREMPTY, "module.so"), 0);
    assert_ptr_equal(so, NULL);
    assert_int_not_equal(amxm_so_open(&so, "module", STREMPTY), 0);
    assert_ptr_equal(so, NULL);
    assert_int_not_equal(amxm_so_open(&so, STREMPTY, STREMPTY), 0);
    assert_ptr_equal(so, NULL);

    assert_int_not_equal(amxm_so_open(&so, STRLARGE, "module.so"), 0);
    assert_ptr_equal(so, NULL);
    assert_int_not_equal(amxm_so_open(&so, "module", STRLARGE), 0);
    assert_ptr_equal(so, NULL);
    assert_int_not_equal(amxm_so_open(&so, STRLARGE, STRLARGE), 0);
    assert_ptr_equal(so, NULL);
}

void test_close_shared_object_args(UNUSED void** state) {
    int amxm_so_close(amxm_shared_object_t** so);

    amxm_shared_object_t* so = NULL;

    assert_int_not_equal(amxm_so_close(NULL), 0);
    assert_int_not_equal(amxm_so_close(&so), 0);

    assert_int_not_equal(amxm_close_so(NULL), 0);
    assert_int_not_equal(amxm_close_so(STREMPTY), 0);
    assert_int_not_equal(amxm_close_so(STRLARGE), 0);

    assert_int_not_equal(amxm_close_so("somethingthatnotexists"), 0);
}

void test_get_shared_object_args(UNUSED void** state) {
    amxm_shared_object_t* so = NULL;

    so = amxm_get_so(NULL);
    assert_ptr_not_equal(so, NULL);

    so = amxm_get_so(STREMPTY);
    assert_ptr_not_equal(so, NULL);

    so = amxm_get_so(STRLARGE);
    assert_ptr_equal(so, NULL);
}

void test_get_module_args(UNUSED void** state) {
    amxm_module_t* mod = NULL;

    mod = amxm_get_module(NULL, NULL);
    assert_ptr_equal(mod, NULL);

    mod = amxm_get_module(NULL, STREMPTY);
    assert_ptr_equal(mod, NULL);

    mod = amxm_get_module(NULL, STRLARGE);
    assert_ptr_equal(mod, NULL);

    mod = amxm_get_module(STREMPTY, NULL);
    assert_ptr_equal(mod, NULL);

    mod = amxm_get_module(STREMPTY, STREMPTY);
    assert_ptr_equal(mod, NULL);

    mod = amxm_get_module(STREMPTY, STRLARGE);
    assert_ptr_equal(mod, NULL);

    mod = amxm_get_module(STRLARGE, NULL);
    assert_ptr_equal(mod, NULL);
}


#define MOD_TEST_SO_1 "module_test_so_1"
void test_open_close_shared_object(UNUSED void** state) {
    amxm_shared_object_t* so = NULL;
    const char* err_msg = NULL;

    assert_int_equal(amxm_so_open(&so, MOD_TEST_SO_1, "./run_mod.so"), 0);
    assert_ptr_not_equal(so, NULL);
    err_msg = amxm_so_error();
    assert_ptr_equal(err_msg, NULL);

    // try to open same module with same name
    assert_int_not_equal(amxm_so_open(&so, MOD_TEST_SO_1, "./run_mod.so"), 0);
    assert_ptr_equal(so, NULL);
    err_msg = amxm_so_error();
    assert_ptr_equal(err_msg, NULL);

    // try to open non existing module
    so = amxm_get_so("nonexisting");
    assert_ptr_equal(so, NULL);

    // get opened (existing) module
    so = amxm_get_so(MOD_TEST_SO_1);
    assert_ptr_not_equal(so, NULL);

    // close that module
    assert_int_equal(amxm_so_close(&so), 0);
    assert_ptr_equal(so, NULL);

    // try to find it again (non existing)
    so = amxm_get_so(MOD_TEST_SO_1);
    assert_ptr_equal(so, NULL);

    return;
}
#undef MOD_TEST_SO_1

#define MOD_TEST_SO_2 "module_test_so_2"
void test_open_close_shared_object_by_name(UNUSED void** state) {
    amxm_shared_object_t* so = NULL;
    const char* err_msg = NULL;

    assert_int_equal(amxm_so_open(&so, MOD_TEST_SO_2, "./run_mod.so"), 0);
    assert_ptr_not_equal(so, NULL);
    err_msg = amxm_so_error();
    assert_ptr_equal(err_msg, NULL);

    // try to open module with wrong path
    assert_int_not_equal(amxm_so_open(&so, "failingmod", "/tmp/deadbeef_tmp_amxm.so"), 0);
    assert_ptr_equal(so, NULL);
    err_msg = amxm_so_error();
    assert_ptr_not_equal(err_msg, NULL);

    so = amxm_get_so(MOD_TEST_SO_2);
    assert_ptr_not_equal(so, NULL);

    assert_int_equal(amxm_close_so(MOD_TEST_SO_2), 0);
    assert_int_not_equal(amxm_so_close(&so), 0);
    assert_ptr_equal(amxm_get_so(MOD_TEST_SO_2), NULL);

    return;
}
#undef MOD_TEST_SO_2

/* ********************
 * Module namespace
 * ********************
 */
#define MOD_TEST_SO_3 "module_test_so_3"
void test_register_module_args(UNUSED void** state) {
    amxm_module_t* mod = NULL;
    const char* err_msg = NULL;

    assert_int_not_equal(amxm_module_register(NULL, NULL, "module"), 0);
    assert_int_not_equal(amxm_module_register(NULL, NULL, NULL), 0);

    assert_int_equal(amxm_module_register(&mod, NULL, "module"), 0);
    assert_ptr_not_equal(mod, NULL);

    {
        amxm_shared_object_t* so = NULL;
        assert_int_equal(amxm_so_open(&so, MOD_TEST_SO_3, "./run_mod.so"), 0);
        assert_ptr_not_equal(amxm_get_so(MOD_TEST_SO_3), NULL);
        assert_ptr_not_equal(so, NULL);
        err_msg = amxm_so_error();
        assert_ptr_equal(err_msg, NULL);

        assert_int_not_equal(amxm_module_register(&mod, so, NULL), 0);
        assert_ptr_equal(mod, NULL);

        assert_int_not_equal(amxm_module_register(&mod, so, STREMPTY), 0);
        assert_ptr_equal(mod, NULL);

        assert_int_not_equal(amxm_module_register(&mod, so, STRLARGE), 0);
        assert_ptr_equal(mod, NULL);

        assert_int_equal(amxm_so_close(&so), 0);
        assert_ptr_equal(so, NULL);
    }

}
#undef MOD_TEST_SO_3

void test_close_module_args(UNUSED void** state) {
    assert_int_not_equal(amxm_module_deregister(NULL), 0);
}

void test_get_number_of_modules_args(UNUSED void** state) {
    assert_int_equal(amxm_so_count_modules(NULL), 0);
}

void test_probe_modules(UNUSED void** state) {
    char* str = amxm_so_probe(NULL, 0);
    assert_ptr_equal(str, NULL);
}

#define MOD_TEST_SO_4 "module_test_so_4"
void test_get_module(UNUSED void** state) {
    amxm_module_t* mod;
    const char* err_msg = NULL;

    mod = amxm_so_get_module(NULL, "module");
    assert_ptr_not_equal(mod, NULL);

    {
        amxm_shared_object_t* so = NULL;
        assert_int_equal(amxm_so_open(&so, MOD_TEST_SO_4, "./run_mod.so"), 0);
        assert_ptr_not_equal(amxm_get_so(MOD_TEST_SO_4), NULL);
        assert_ptr_not_equal(so, NULL);
        err_msg = amxm_so_error();
        assert_ptr_equal(err_msg, NULL);

        mod = amxm_so_get_module(so, NULL);
        assert_ptr_equal(mod, NULL);

        mod = amxm_so_get_module(so, STREMPTY);
        assert_ptr_equal(mod, NULL);

        mod = amxm_so_get_module(so, STRLARGE);
        assert_ptr_equal(mod, NULL);

        assert_int_equal(amxm_so_close(&so), 0);
        assert_ptr_equal(so, NULL);
    }

}

#define MOD_TEST_SO_5 "module_test_so_5"
#define MOD_TEST_MOD_5_1 "module_1"
#define MOD_TEST_MOD_5_2 "module_2"
#define MOD_TEST_MOD_5_3 "FREEBYCLOSE"
void test_modules(UNUSED void** state) {
    amxm_module_t* mod;
    char* str;
    char module_ns[AMXM_MODULE_NAME_LENGTH];

    // setup test
    amxm_shared_object_t* so = NULL;
    assert_int_equal(amxm_so_open(&so, MOD_TEST_SO_5, "./run_mod.so"), 0);

    // insert modules
    assert_int_equal(amxm_module_register(&mod, so, MOD_TEST_MOD_5_1), 0);
    assert_ptr_not_equal(mod, NULL);

    assert_int_equal(amxm_module_register(&mod, so, MOD_TEST_MOD_5_2), 0);

    // test insert with same name (should fail)
    assert_int_not_equal(amxm_module_register(&mod, so, MOD_TEST_MOD_5_2), 0);

    assert_int_equal(amxm_so_count_modules(so), 2);

    // probe last module
    str = amxm_so_probe(so, 1);
    assert_ptr_not_equal(str, NULL);
    free(str);

    // probe modules (too far)
    str = amxm_so_probe(so, 2);
    assert_ptr_equal(str, NULL);
    free(str);

    // check closing module
    mod = amxm_so_get_module(so, MOD_TEST_MOD_5_2);
    amxm_module_deregister(&mod);
    assert_int_equal(amxm_so_count_modules(so), 1);

    // probe first/last module
    str = amxm_so_probe(so, 0);
    assert_ptr_not_equal(str, NULL);

    // get module by name
    mod = amxm_so_get_module(so, str);
    assert_ptr_not_equal(mod, NULL);

    free(str);

    // close second module
    amxm_module_deregister(&mod);
    assert_int_equal(amxm_so_count_modules(so), 0);

    // test large insert
    for(size_t i = 0; i < 5000; i++) {
        gen_module_namespace_str(module_ns, sizeof(module_ns));
        assert_int_equal(amxm_module_register(&mod, so, module_ns), 0);
        assert_int_equal(amxm_so_count_modules(so), i + 1);
    }

    // cleanup list
    while(amxm_so_count_modules(so)) {
        str = amxm_so_probe(so, 0);
        assert_ptr_not_equal(str, NULL);

        mod = amxm_so_get_module(so, str);

        assert_ptr_not_equal(mod, NULL);
        amxm_module_deregister(&mod);

        free(str);
    }

    // register module (close should clean)
    assert_int_equal(amxm_module_register(&mod, so, MOD_TEST_MOD_5_3), 0);
    assert_ptr_not_equal(mod, NULL);

    // following close should clean everything up nicely
    assert_int_equal(amxm_so_close(&so), 0);
    assert_ptr_equal(so, NULL);
}
#undef MOD_TEST_SO_5
#undef MOD_TEST_MOD_5_1
#undef MOD_TEST_MOD_5_2
#undef MOD_TEST_MOD_5_3

/* ********************
 * Functions
 * ********************
 */
int my_testing_function(const char* const function_name, amxc_var_t* args, amxc_var_t* ret) {
    int error = 0;
    assert_ptr_not_equal(function_name, NULL);
    assert_ptr_not_equal(args, NULL);
    assert_ptr_not_equal(ret, NULL);

    printf("%s: %d: %s\n", __FILE__, __LINE__, function_name);

    return error;
}

int my_other_testing_function(const char* const function_name, amxc_var_t* args, amxc_var_t* ret) {
    int error = 0;
    assert_ptr_not_equal(function_name, NULL);
    assert_ptr_not_equal(args, NULL);
    assert_ptr_not_equal(ret, NULL);

    printf("%s: %d: %s\n", __FILE__, __LINE__, function_name);

    return error;
}

#define MOD_TEST_SO_51 "module_test_so_51"
#define MOD_TEST_MOD_51 "module_test_mod_51"
void test_has_function(UNUSED void** state) {
    amxm_shared_object_t* so = NULL;
    amxm_module_t* mod = NULL;
    assert_int_equal(amxm_so_open(&so, MOD_TEST_SO_51, "./run_mod.so"), 0);

    assert_int_equal(amxm_module_register(&mod, so, MOD_TEST_MOD_51), 0);
    assert_ptr_not_equal(mod, NULL);

    assert_false(amxm_has_function(NULL, NULL, NULL));
    assert_false(amxm_has_function(STREMPTY, NULL, NULL));
    assert_false(amxm_has_function(STRLARGE, NULL, NULL));
    assert_false(amxm_has_function(NULL, STREMPTY, NULL));
    assert_false(amxm_has_function(STREMPTY, STRLARGE, NULL));
    assert_false(amxm_has_function(STRLARGE, NULL, STREMPTY));
    assert_false(amxm_has_function(STRLARGE, NULL, STRLARGE));

    assert_int_equal(amxm_module_add_function(mod, "functionname_51", my_testing_function), 0);

    assert_true(amxm_has_function(MOD_TEST_SO_51, MOD_TEST_MOD_51, "functionname_51"));
    assert_true(amxm_so_has_function(so, MOD_TEST_MOD_51, "functionname_51"));
    assert_true(amxm_module_has_function(mod, "functionname_51"));

    assert_false(amxm_has_function(MOD_TEST_SO_51, MOD_TEST_MOD_51, "functionname_52"));
    assert_false(amxm_so_has_function(so, MOD_TEST_MOD_51, "functionname_52"));
    assert_false(amxm_module_has_function(mod, "functionname_52"));

    assert_int_equal(amxm_so_close(&so), 0);
    assert_ptr_equal(so, NULL);
}
#undef MOD_TEST_SO_51
#undef MOD_TEST_MOD_51

#define MOD_TEST_SO_6 "module_test_so_6"
#define MOD_TEST_MOD_6 "module_test_mod_6"
void test_register_function_args(UNUSED void** state) {
    assert_int_not_equal(amxm_module_add_function(NULL, "functionname_1", my_testing_function), 0);

    {
        amxm_shared_object_t* so = NULL;
        amxm_module_t* mod = NULL;
        assert_int_equal(amxm_so_open(&so, MOD_TEST_SO_6, "./run_mod.so"), 0);

        assert_int_equal(amxm_module_register(&mod, so, MOD_TEST_MOD_6), 0);
        assert_ptr_not_equal(mod, NULL);

        assert_int_not_equal(amxm_module_add_function(mod, NULL, my_testing_function), 0);
        assert_int_not_equal(amxm_module_add_function(mod, STREMPTY, my_testing_function), 0);
        assert_int_not_equal(amxm_module_add_function(mod, STRLARGE, my_testing_function), 0);
        assert_int_not_equal(amxm_module_add_function(mod, "functionname_2", NULL), 0);

        assert_int_equal(amxm_so_close(&so), 0);
        assert_ptr_equal(so, NULL);
    }
}
#undef MOD_TEST_SO_6
#undef MOD_TEST_MOD_6

#define MOD_TEST_SO_8 "module_test_so_8"
#define MOD_TEST_MOD_8 "module_test_mod_8"
void test_execute_function_args(UNUSED void** state) {
    amxc_var_t* ret = NULL;
    amxc_var_t* args = NULL;

    amxc_var_new(&args);
    amxc_var_new(&ret);

    assert_int_not_equal(amxm_module_execute_function(NULL, "functionname_4", args, ret), 0);
    {
        amxm_shared_object_t* so = NULL;
        amxm_module_t* mod = NULL;
        assert_int_equal(amxm_so_open(&so, MOD_TEST_SO_8, "./run_mod.so"), 0);

        assert_int_equal(amxm_module_register(&mod, so, MOD_TEST_MOD_8), 0);
        assert_ptr_not_equal(mod, NULL);

        assert_int_not_equal(amxm_module_execute_function(mod, NULL, args, ret), 0);
        assert_int_not_equal(amxm_module_execute_function(mod, STREMPTY, args, ret), 0);
        assert_int_not_equal(amxm_module_execute_function(mod, STRLARGE, args, ret), 0);
        assert_int_not_equal(amxm_module_execute_function(mod, "functionname_5", NULL, ret), 0);
        assert_int_not_equal(amxm_module_execute_function(mod, "functionname_6", args, NULL), 0);
        assert_int_not_equal(amxm_module_execute_function(mod, "functionname_7", args, ret), 0);
        assert_int_not_equal(amxm_execute_function(NULL, MOD_TEST_MOD_8, "functionname_8", args, ret), 0);
        assert_int_not_equal(amxm_execute_function(STREMPTY, MOD_TEST_MOD_8, "functionname_9", args, ret), 0);
        assert_int_not_equal(amxm_execute_function(STRLARGE, MOD_TEST_MOD_8, "functionname_10", args, ret), 0);
        assert_int_not_equal(amxm_execute_function(MOD_TEST_SO_8, NULL, "functionname_11", args, ret), 0);
        assert_int_not_equal(amxm_execute_function(MOD_TEST_SO_8, STREMPTY, "functionname_12", args, ret), 0);
        assert_int_not_equal(amxm_execute_function(MOD_TEST_SO_8, STRLARGE, "functionname_13", args, ret), 0);

        assert_int_equal(amxm_so_close(&so), 0);
        assert_ptr_equal(so, NULL);
    }

    amxc_var_delete(&args);
    amxc_var_delete(&ret);

}
#undef MOD_TEST_SO_8
#undef MOD_TEST_MOD_8

#define MOD_TEST_SO_11 "module_test_so_11"
#define MOD_TEST_MOD_11 "module_test_mod_11"
void test_delete_function_args(UNUSED void** state) {
    int ret;

    {
        amxm_shared_object_t* so = NULL;
        amxm_module_t* mod = NULL;
        assert_int_equal(amxm_so_open(&so, MOD_TEST_SO_11, "./run_mod.so"), 0);

        assert_int_equal(amxm_module_register(&mod, so, MOD_TEST_MOD_11), 0);
        assert_ptr_not_equal(mod, NULL);

        ret = amxm_module_remove_function(mod, NULL);
        assert_int_not_equal(ret, 0);

        ret = amxm_module_remove_function(mod, STREMPTY);
        assert_int_not_equal(ret, 0);

        ret = amxm_module_remove_function(mod, STRLARGE);
        assert_int_not_equal(ret, 0);

        ret = amxm_so_remove_function(so, NULL, "functionname_14");
        assert_int_not_equal(ret, 0);

        ret = amxm_so_remove_function(so, STREMPTY, "functionname_15");
        assert_int_not_equal(ret, 0);

        ret = amxm_so_remove_function(so, STRLARGE, "functionname_16");
        assert_int_not_equal(ret, 0);

        assert_int_equal(amxm_so_close(&so), 0);
        assert_ptr_equal(so, NULL);
    }
}
#undef MOD_TEST_SO_11
#undef MOD_TEST_MOD_11

#define MOD_TEST_SO_9 "module_test_so_9"
#define MOD_TEST_MOD_9 "module_test_mod_9"
#define MOD_TEST_FUNC_9_1 "working_function_1"
#define MOD_TEST_FUNC_9_2 "working_function_2"
void test_functions(UNUSED void** state) {
    amxc_var_t* ret = NULL;
    amxc_var_t* args = NULL;
    amxm_function_callback_t* cb = NULL;
    amxc_htable_it_t* it = NULL;

    // setup test
    amxc_var_new(&args);
    amxc_var_new(&ret);

    amxm_shared_object_t* so = NULL;
    assert_int_equal(amxm_so_open(&so, MOD_TEST_SO_9, "./run_mod.so"), 0);

    amxm_module_t* mod = NULL;
    assert_int_equal(amxm_module_register(&mod, so, MOD_TEST_MOD_9), 0);
    assert_ptr_not_equal(mod, NULL);

    // do worthless test for coverage
    assert_ptr_equal(amxm_so_get_current(), NULL);

    // register functions
    assert_int_equal(amxm_module_add_function(mod, MOD_TEST_FUNC_9_1, my_testing_function), 0);
    assert_int_equal(amxm_module_add_function(mod, MOD_TEST_FUNC_9_2, my_testing_function), 0);

    // execute functions
    assert_int_equal(amxm_module_execute_function(mod, MOD_TEST_FUNC_9_1, args, ret), 0);
    assert_int_equal(amxm_execute_function(MOD_TEST_SO_9, MOD_TEST_MOD_9, MOD_TEST_FUNC_9_2, args, ret), 0);

    // replace function
    assert_int_equal(amxm_module_add_function(mod, MOD_TEST_FUNC_9_1, my_other_testing_function), 0);
    assert_int_equal(amxm_module_add_function(mod, MOD_TEST_FUNC_9_2, my_other_testing_function), 0);

    // check if it's replaced
    it = amxc_htable_get(&mod->amxm_function_htable, MOD_TEST_FUNC_9_1);
    cb = amxc_htable_it_get_data(it, amxm_function_callback_t, it);
    assert_ptr_not_equal(cb, NULL);
    assert_ptr_equal(cb->function_cb, my_other_testing_function);

    it = amxc_htable_get(&mod->amxm_function_htable, MOD_TEST_FUNC_9_2);
    cb = amxc_htable_it_get_data(it, amxm_function_callback_t, it);
    assert_ptr_not_equal(cb, NULL);
    assert_ptr_equal(cb->function_cb, my_other_testing_function);

    // replace function pointer with NULL
    assert_int_equal(amxm_module_add_function(mod, MOD_TEST_FUNC_9_1, NULL), 0);

    // check if it's replaced
    it = amxc_htable_get(&mod->amxm_function_htable, MOD_TEST_FUNC_9_1);
    cb = amxc_htable_it_get_data(it, amxm_function_callback_t, it);
    assert_ptr_not_equal(cb, NULL);
    assert_ptr_equal(cb->function_cb, NULL);

    // execute it
    assert_int_not_equal(amxm_module_execute_function(mod, MOD_TEST_FUNC_9_1, args, ret), 0);

    // delete function by name
    assert_int_equal(amxm_so_remove_function(so, MOD_TEST_MOD_9, MOD_TEST_FUNC_9_1), 0);

    // check if function is really deleted
    assert_ptr_equal(amxc_htable_get(&mod->amxm_function_htable, MOD_TEST_FUNC_9_1), NULL);

    // execute it again (allthough it's deleted)
    assert_int_not_equal(amxm_module_execute_function(mod, MOD_TEST_FUNC_9_1, args, ret), 0);

    // cleanup test
    assert_int_equal(amxm_so_close(&so), 0);
    assert_ptr_equal(so, NULL);

    amxc_var_delete(&args);
    amxc_var_delete(&ret);
}
#undef MOD_TEST_SO_9
#undef MOD_TEST_MOD_9
#undef MOD_TEST_FUNC_9_1
#undef MOD_TEST_FUNC_9_2

#define MOD_TEST_SO_10 "module_test_so_10"
#define MOD_TEST_MOD_10 "module_test_mod_10"
#define MOD_TEST_FUNC_10_1 "working_function_1"
#define MOD_TEST_FUNC_10_2 "working_function_2"
void stress_test_functions(UNUSED void** state) {
    char function_name[AMXM_FUNCTION_NAME_LENGTH];
    int ret;
    amxm_function_callback_t* cb = NULL;
    amxc_htable_it_t* it = NULL;

    amxm_shared_object_t* so = NULL;
    assert_int_equal(amxm_so_open(&so, MOD_TEST_SO_10, "./run_mod.so"), 0);

    amxm_module_t* mod = NULL;
    assert_int_equal(amxm_module_register(&mod, so, MOD_TEST_MOD_10), 0);
    assert_ptr_not_equal(mod, NULL);

    // register functions
    assert_int_equal(amxm_module_add_function(mod, MOD_TEST_FUNC_10_1, my_testing_function), 0);
    assert_int_equal(amxm_module_add_function(mod, MOD_TEST_FUNC_10_2, my_other_testing_function), 0);

    // register a lot of functions
    for(size_t i = 0; i < 15000; i++) {
        gen_function_name_str(function_name, AMXM_FUNCTION_NAME_LENGTH);
        assert_int_equal(amxm_module_add_function(mod, function_name, my_testing_function), 0);

        gen_function_name_str(function_name, AMXM_FUNCTION_NAME_LENGTH);
        assert_int_equal(amxm_module_add_function(mod, function_name, my_other_testing_function), 0);
    }

    // get function callback
    amxc_htable_t* func_htable = &mod->amxm_function_htable;
    assert_ptr_not_equal(func_htable, NULL);

    it = amxc_htable_get(&mod->amxm_function_htable, MOD_TEST_FUNC_10_1);
    cb = amxc_htable_it_get_data(it, amxm_function_callback_t, it);
    assert_ptr_not_equal(cb, NULL);
    assert_ptr_equal(cb->function_cb, my_testing_function);

    it = amxc_htable_get(&mod->amxm_function_htable, MOD_TEST_FUNC_10_2);
    cb = amxc_htable_it_get_data(it, amxm_function_callback_t, it);
    assert_ptr_not_equal(cb, NULL);
    assert_ptr_equal(cb->function_cb, my_other_testing_function);

    // delete last function
    assert_int_equal(amxm_module_remove_function(mod, function_name), 0);

    // delete already deleted function
    ret = amxm_module_remove_function(mod, function_name);
    assert_int_not_equal(ret, 0);

    // cleanup test
    assert_int_equal(amxm_so_close(&so), 0);
    assert_ptr_equal(so, NULL);
}
#undef MOD_TEST_SO_9
#undef MOD_TEST_MOD_9


#define MOD_TEST_SO_11 "module_test_so_11"
#define MOD_TEST_MOD_11 "module_test_mod_11"
#define MOD_TEST_SO_12 "module_test_so_12"
#define MOD_TEST_MOD_12 "module_test_mod_12"
void test_close_all(UNUSED void** state) {
    amxm_shared_object_t* so = NULL;
    const amxc_llist_t* so_list = amxm_get_so_list();

    assert_int_equal(amxc_llist_size(so_list), 1);

    assert_int_equal(amxm_so_open(&so, MOD_TEST_SO_11, "./run_mod.so"), 0);
    assert_int_equal(amxm_so_open(&so, MOD_TEST_SO_12, "./run_mod.so"), 0);
    assert_int_equal(amxc_llist_size(so_list), 3);

    assert_int_equal(amxm_close_all(), 0);
    assert_int_equal(amxc_llist_size(so_list), 0);
}
#undef MOD_TEST_SO_11
#undef MOD_TEST_MOD_11
#undef MOD_TEST_SO_12
#undef MOD_TEST_MOD_12
