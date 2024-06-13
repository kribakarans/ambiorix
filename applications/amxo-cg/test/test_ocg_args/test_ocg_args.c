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
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <getopt.h>
#include <string.h>

#include "utils.h"
#include "colors.h"

#include "test_ocg_args.h"

static amxo_parser_t parser;
static amxc_var_t config;

void test_can_print_help(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-h" };
    int index = 0;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, -1);

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_can_print_xml_generator_help(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-hxml" };
    int index = 0;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, -1);

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_can_print_dmm_generator_help(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "--help=dm_methods" };
    int index = 0;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, -1);

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_can_add_include_dir(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-I", "../test_odls", "-I", "./extra_odls", "-i saved.odl", "-i extra.odl"};
    int index = 0;
    amxc_var_t* inc_dirs = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 7);

    inc_dirs = GET_ARG(&config, "include-dirs");
    assert_non_null(inc_dirs);
    assert_int_equal(amxc_var_type_of(inc_dirs), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(amxc_var_constcast(amxc_llist_t, inc_dirs)), 2);

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_can_add_import_dir(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-L", "../test_import", "-L", "./extra_import" };
    int index = 0;
    amxc_var_t* import_dirs = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 5);

    import_dirs = GET_ARG(&config, "import-dirs");
    assert_non_null(import_dirs);
    assert_int_equal(amxc_var_type_of(import_dirs), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(amxc_var_constcast(amxc_llist_t, import_dirs)), 2);

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_duplicate_dis_are_ignored(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-L", "../test_import", "-L", "../test_import" };
    int index = 0;
    amxc_var_t* import_dirs = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 5);

    import_dirs = GET_ARG(&config, "import-dirs");
    assert_non_null(import_dirs);
    assert_int_equal(amxc_var_type_of(import_dirs), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(amxc_var_constcast(amxc_llist_t, import_dirs)), 1);

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_can_enable_resolving(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-R" };
    int index = 0;
    amxc_var_t* resolve = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 2);

    resolve = GET_ARG(&config, "import-resolve");
    assert_non_null(resolve);
    assert_int_equal(amxc_var_type_of(resolve), AMXC_VAR_ID_BOOL);
    assert_true(amxc_var_constcast(bool, resolve));

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_can_add_generator(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-Gxml", "-Gdm_methods" };
    int index = 0;
    amxc_var_t* generators = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 3);

    generators = GET_ARG(&config, "generators");
    assert_non_null(generators);
    assert_int_equal(amxc_var_type_of(generators), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, generators)), 2);

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_fails_with_invalid_generator(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-Ginvalid" };
    int index = 0;
    amxc_var_t* generators = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, -1);

    generators = GET_ARG(&config, "generators");
    assert_non_null(generators);
    assert_int_equal(amxc_var_type_of(generators), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, generators)), 0);

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_fails_with_duplicate_generator(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-Gxml", "-Gxml" };
    int index = 0;
    amxc_var_t* generators = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, -1);

    generators = GET_ARG(&config, "generators");
    assert_non_null(generators);
    assert_int_equal(amxc_var_type_of(generators), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, generators)), 1);

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_can_add_directory_to_generator(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-Gxml,../test_ocg_args" };
    int index = 0;
    amxc_var_t* generators = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 2);

    generators = GET_ARG(&config, "generators");
    assert_non_null(generators);
    assert_int_equal(amxc_var_type_of(generators), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, generators)), 1);

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_can_add_absolute_directory_to_generator(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-Gxml,/etc" };
    int index = 0;
    amxc_var_t* generators = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 2);

    generators = GET_ARG(&config, "generators");
    assert_non_null(generators);
    assert_int_equal(amxc_var_type_of(generators), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, generators)), 1);

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_can_enable_silent_mode(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-s" };
    int index = 0;
    amxc_var_t* silent = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 2);

    silent = GET_ARG(&config, "silent");
    assert_non_null(silent);
    assert_int_equal(amxc_var_type_of(silent), AMXC_VAR_ID_BOOL);
    assert_true(amxc_var_constcast(bool, silent));

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_can_enable_reset_mode(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-r" };
    int index = 0;
    amxc_var_t* reset = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 2);

    reset = GET_ARG(&config, "reset");
    assert_non_null(reset);
    assert_int_equal(amxc_var_type_of(reset), AMXC_VAR_ID_BOOL);
    assert_true(amxc_var_constcast(bool, reset));

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_can_disable_warnings(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-w" };
    int index = 0;
    amxc_var_t* warning = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 2);

    warning = GET_ARG(&config, "no-warnings");
    assert_non_null(warning);
    assert_int_equal(amxc_var_type_of(warning), AMXC_VAR_ID_BOOL);
    assert_true(amxc_var_constcast(bool, warning));

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_can_enable_continue_on_error(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-c" };
    int index = 0;
    amxc_var_t* cont = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 2);

    cont = GET_ARG(&config, "continue");
    assert_non_null(cont);
    assert_int_equal(amxc_var_type_of(cont), AMXC_VAR_ID_BOOL);
    assert_true(amxc_var_constcast(bool, cont));

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_can_disable_colors(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-n" };
    int index = 0;
    const char* color = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 2);
    color = get_color(YELLOW);
    assert_int_equal(strlen(color), 0);

    enable_colors(true);
    color = get_color(YELLOW);
    assert_int_not_equal(strlen(color), 0);

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_can_enable_verbose(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-v" };
    int index = 0;
    amxc_var_t* verbose = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 2);

    verbose = GET_ARG(&config, "verbose");
    assert_non_null(verbose);
    assert_int_equal(amxc_var_type_of(verbose), AMXC_VAR_ID_BOOL);
    assert_true(amxc_var_constcast(bool, verbose));

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_fails_when_invalid_argument_given(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "--Invalid" };
    int index = 0;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 2);

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_merge_command_line_options_and_parser_config(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-L", "../test_import", "-I", "../test_odl", "-Gxml", "-d" };
    int index = 0;
    amxc_var_t* data = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 7);

    ocg_apply_config(&parser, &config);

    data = GET_ARG(&parser.config, "import-dirs");
    assert_non_null(data);
    assert_int_equal(amxc_var_type_of(data), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(amxc_var_constcast(amxc_llist_t, data)), 5);

    data = GET_ARG(&parser.config, "include-dirs");
    assert_non_null(data);
    assert_int_equal(amxc_var_type_of(data), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(amxc_var_constcast(amxc_llist_t, data)), 4);

    data = GET_ARG(&parser.config, "generators");
    assert_non_null(data);
    assert_int_equal(amxc_var_type_of(data), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, data)), 1);

    data = GET_ARG(&parser.config, "dump-config");
    assert_non_null(data);
    assert_int_equal(amxc_var_type_of(data), AMXC_VAR_ID_BOOL);
    assert_true(amxc_var_constcast(bool, data));

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_can_dump_config(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-d" };
    int index = 0;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 2);

    ocg_apply_config(&parser, &config);

    ocg_config_changed(&parser, 0);
    ocg_config_changed(&parser, 1);

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}

void test_does_not_dump_config_when_silent(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-d", "-s" };
    int index = 0;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    optind = 1;
    index = ocg_parse_arguments(&parser, &config, sizeof(argv) / sizeof(argv[0]), argv);
    assert_int_equal(index, 3);

    ocg_apply_config(&parser, &config);

    ocg_config_changed(&parser, 0);
    ocg_config_changed(&parser, 1);

    amxo_parser_clean(&parser);
    amxc_var_clean(&config);
}
