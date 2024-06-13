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
#include <sys/signalfd.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <fcntl.h>
#include <cmocka.h>

#include <amxc/amxc.h>
#include <amxp/amxp_expression.h>

#include "test_expression.h"

typedef struct _evaluator {
    bool result;
    char text[512];
} eval_t;

#include <amxc/amxc_macros.h>

void test_can_create_expression(UNUSED void** state) {
    amxp_expr_t expression;
    amxp_expr_t* expr = NULL;

    assert_int_equal(amxp_expr_init(&expression, "true"), 0);
    assert_string_equal(expression.expression, "true");
    amxp_expr_clean(&expression);
    assert_ptr_equal(expression.expression, NULL);

    assert_int_equal(amxp_expr_new(&expr, "true"), 0);
    assert_string_equal(expr->expression, "true");
    amxp_expr_clean(expr);
    assert_ptr_equal(expr->expression, NULL);
    amxp_expr_delete(&expr);
    assert_ptr_equal(expr, NULL);
}

void test_can_evaluate_expression(UNUSED void** state) {
    amxp_expr_t expression;
    amxp_expr_status_t status = 0;

    eval_t evals[] = {
        { true, "true" },
        { false, "false"},
        { true, "True"},
        { false, "False"},
        { true, "TrUe"},
        { false, "FaLsE"},
        { false, "true && false" },
        { true, "true || false" },
        { true, "" },
        { true, "True || False" },
        { false, "True && False" }
    };

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        printf("Evaluating \"%s\"\n", evals[i].text);
        assert_int_equal(amxp_expr_init(&expression, evals[i].text), 0);
        assert_true(amxp_expr_eval(&expression, &status) == evals[i].result);
        assert_int_equal(status, 0);
        amxp_expr_clean(&expression);
    }
}

void test_precedence_is_respected(UNUSED void** state) {
    amxp_expr_t expression;
    amxp_expr_status_t status = 0;

    eval_t evals[] = {
        { true, "true || false && true" },
        { true, "(true || false) && true"},
        { false, "false || true && false" },
        { false, "(false || true) && false" },
        { false, "false || false && false" },
        { false, "true && false || true && false"},
        { false, "false || false && true || false"},
        { true, "!(false || false) && true || false"},
        { true, "!false && true"},
        { true, "!false || false"},
        { true, "!false || true"},
        { false, "!(false || true)"},
        { true, "true || false && false || false" },
        { false, "(true || false) && (false || false)" },
    };

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        printf("Evaluating \"%s\"\n", evals[i].text);
        assert_int_equal(amxp_expr_init(&expression, evals[i].text), 0);
        assert_true(amxp_expr_eval(&expression, &status) == evals[i].result);
        assert_int_equal(status, 0);
        amxp_expr_dump_tree(&expression);
        amxp_expr_clean(&expression);
    }
}

void test_comperators_are_correct(UNUSED void** state) {
    amxp_expr_t expression;
    amxp_expr_status_t status = 0;

    eval_t evals[] = {
        { true, "10 > 0" },
        { false, "10 > 10" },
        { false, "10 < 0"},
        { false, "10 < 10"},
        { true, "10 >= 10" },
        { true, "10 <= 10" },
        { true, "\"bagpipe\" >= \"b\"" },
        { true, "\"bagpipe\" >= \"bagpipe\""},
        { false, "\"bagpipe\" <= \"aardvark\"" },
        { true, "\"bagpipe\" >= \"aardvark\""},
        { true, "\"This is some tekst\" != \"Diferent & Also, Text\""},
        { true, "'Text' in ['bagpipe', 'aardvark', 'Text', 10]"},
        { false, "'rabbit' in ['bagpipe', 'aardvark', 'Text', 10]"},
        { true, "'the rabbit went into the rabbit hole' starts with 'the rabbit'"},
        { false, "'Alice went into the rabbit hole' starts  with 'the rabbit'"},
        { true, "'the rabbit went into the rabbit hole' starts\t with 'the rabbit'"},
        { true, "'rabbit' in 'the rabbit went into the rabbit hole'"},
        { true, "'hole' in 'the rabbit went into the rabbit hole'"},
        { false, "'Alice' in 'the rabbit went into the rabbit hole'"},
        { false, "'Alice' in 'Al'"},
        { true, "'Alice' starts with ['Al', 'Ra']" },
        { true, "'Rabbit' starts with ['Al', 'Ra']" },
        { true, "is_empty([])"},
        { false, "is_empty([1,2])"},
        { true, "'the rabbit went into the rabbit hole' ends with 'rabbit hole'"},
        { false, "'the rabbit went into the rabbit hole' ends with 'rabbit pit'"},
        { false, "'the rabbit' ends with 'very long string that does not crash'"},
        { true, "'Rabbit' ends with ['ce', 'it']" }
    };

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        printf("Evaluating \"%s\"\n", evals[i].text);
        fflush(stdout);
        assert_int_equal(amxp_expr_init(&expression, evals[i].text), 0);
        assert_true(amxp_expr_eval(&expression, &status) == evals[i].result);
        assert_int_equal(status, 0);
        amxp_expr_dump_tree(&expression);
        amxp_expr_clean(&expression);
    }
}

void test_can_fetch_fields(UNUSED void** state) {
    amxp_expr_t expression;
    amxc_var_t data;
    amxc_var_t* subtable;
    amxc_var_t* subarray;
    amxc_ts_t now;
    amxp_expr_status_t status = 0;

    eval_t evals[] = {
        { true, "'brown' in CSVText"},
        { true, "TextField == \"This is text\"" },
        { true, "MyTable.Text == \"Hello World\"" },
        { true, ".MyTable.Number == 100" },
        { true, "MyTable.Boolean" },
        { true, "MyArray.0 == \"Item1\""},
        { true, ".MyArray.1 == \"-20000\""},
        { true, "MyArray.2"},
        { true, "MyArray.3 > \"1970-01-01T00:00:00Z\""},
        { true, "\"This is text\" == TextField" },
        { true, "\"Hello World\" == MyTable.Text;" },
        { true, "100 == MyTable.Number" },
        { true, "\"Item1\" == MyArray.0"},
        { true, "\"-20000\" == MyArray.1;"},
        { true, "\"1970-01-01T00:00:00Z\" < MyArray.3"},
        { false, "MyTable.Number > MyArray.1" },
        { true, "MyArray.1 < MyTable.Number" },
        { true, "TextField matches \"This.*\""},
        { false, "TextField matches \"Not This.*\""},
        { true, "TextField starts with 'This'"},
        { false, "TextField starts with 'But Not This'"},
        { true, "'fox' in CSVText"},
        { false, "'red' in CSVText"}
    };

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_ts_now(&now);

    amxc_var_add_key(cstring_t, &data, "TextField", "This is text");
    subtable = amxc_var_add_key(amxc_htable_t, &data, "MyTable", NULL);
    amxc_var_add_key(cstring_t, subtable, "Text", "Hello World");
    amxc_var_add_key(uint32_t, subtable, "Number", 100);
    amxc_var_add_key(bool, subtable, "Boolean", true);
    subarray = amxc_var_add_key(amxc_llist_t, &data, "MyArray", NULL);
    amxc_var_add(cstring_t, subarray, "Item1");
    amxc_var_add(int64_t, subarray, -20000);
    amxc_var_add(bool, subarray, true);
    amxc_var_add(amxc_ts_t, subarray, &now);
    amxc_var_add_key(csv_string_t, &data, "CSVText", "The,big,brown,fox,jumped");

    printf("Test data = ");
    fflush(stdout);
    amxc_var_dump(&data, STDOUT_FILENO);

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        bool result = false;
        printf("Evaluating \"%s\" (expecting %s - ", evals[i].text, evals[i].result ? "true" : "false");
        fflush(stdout);
        assert_int_equal(amxp_expr_init(&expression, evals[i].text), 0);
        amxp_expr_dump_tree(&expression);
        result = amxp_expr_eval_var(&expression, &data, &status);
        assert_int_equal(status, 0);
        printf("got %s)\n", result ? "true" : "false");
        fflush(stdout);
        assert_true(result == evals[i].result);
        amxp_expr_clean(&expression);
    }

    subarray = GETP_ARG(&data, "CSVText");
    assert_int_equal(amxc_var_type_of(subarray), AMXC_VAR_ID_CSV_STRING);

    amxc_var_clean(&data);
}

void test_invalid_field_names(UNUSED void** state) {
    amxp_expr_t expression;
    amxc_var_t data;
    amxc_var_t* subtable;
    amxc_var_t* subarray;
    amxc_ts_t now;
    amxp_expr_status_t status = 0;

    eval_t evals[] = {
        { false, "MyArray.NotExisting == \"Item1\""},
        { false, "MyTable.99"},
        { false, "\"TEXT\" matches Not.Existing.Field.0"},
    };

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_ts_now(&now);

    amxc_var_add_key(cstring_t, &data, "TextField", "This is text");
    subtable = amxc_var_add_key(amxc_htable_t, &data, "MyTable", NULL);
    amxc_var_add_key(cstring_t, subtable, "Text", "Hello World");
    amxc_var_add_key(uint32_t, subtable, "Number", 100);
    amxc_var_add_key(bool, subtable, "Boolean", true);
    subarray = amxc_var_add_key(amxc_llist_t, &data, "MyArray", NULL);
    amxc_var_add(cstring_t, subarray, "Item1");
    amxc_var_add(int64_t, subarray, -20000);
    amxc_var_add(bool, subarray, true);
    amxc_var_add(amxc_ts_t, subarray, &now);
    amxc_var_dump(&data, STDOUT_FILENO);

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        printf("Evaluating \"%s\"\n", evals[i].text);
        assert_int_equal(amxp_expr_init(&expression, evals[i].text), 0);
        assert_false(amxp_expr_eval_var(&expression, &data, &status));
        assert_int_not_equal(status, 0);
        amxp_expr_clean(&expression);
        fflush(stdout);
    }

    amxc_var_clean(&data);
}

void test_invalid_syntax(UNUSED void** state) {
    amxp_expr_t expression;
    amxp_expr_t* expr = NULL;
    eval_t evals[] = {
        { false, "Hello <> Goobey"},
        { false, "\"Text\"Field @ Hello World"},
        { false, "100"},
        { false, "['a', 'b', 'c'] in 'abc'"},
        { false, "'Alice' in 1024"}
    };

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        printf("Evaluating \"%s\"\n", evals[i].text);
        assert_int_not_equal(amxp_expr_init(&expression, evals[i].text), 0);
        fflush(stdout);
    }

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        assert_int_not_equal(amxp_expr_new(&expr, evals[i].text), 0);
        assert_ptr_equal(expr, NULL);
        fflush(stdout);
    }
}

void test_invalid_value_types(UNUSED void** state) {
    amxp_expr_t expression;
    amxp_expr_t* expr = NULL;

    eval_t evals[] = {
        { false, "'Some text' == ['Some', 'text']"},
        { false, "[1,2,3,4] > 10"},
        { false, "[1,2,3,4] matches ['Part1', 'Part2']"}
    };

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        assert_int_equal(amxp_expr_init(&expression, evals[i].text), amxp_expr_status_invalid_value);
        fflush(stdout);
    }

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        assert_int_equal(amxp_expr_new(&expr, evals[i].text), amxp_expr_status_invalid_value);
        assert_ptr_equal(expr, NULL);
        fflush(stdout);
    }
}

static amxp_expr_status_t custom_field_fetcher(UNUSED amxp_expr_t* expr,
                                               amxc_var_t* value,
                                               const char* path,
                                               void* priv) {
    amxp_expr_status_t retval = amxp_expr_status_unknown_error;
    amxc_var_t* data = (amxc_var_t*) priv;
    amxc_var_t* field = amxc_var_get_path(data, path, AMXC_VAR_FLAG_DEFAULT);
    if(amxc_var_is_null(field)) {
        if(strcmp(path, "available") == 0) {
            amxc_var_set(bool, value, true);
        } else {
            amxc_var_set(bool, value, false);
        }
        retval = amxp_expr_status_ok;
    } else {
        if(amxc_var_copy(value, field) == 0) {
            retval = amxp_expr_status_ok;
        }
    }

    return retval;
}

void test_can_use_custom_field_fetcher(UNUSED void** state) {
    amxp_expr_t expression;
    amxc_var_t data;
    amxc_var_t* subtable;
    amxc_var_t* subarray;
    amxc_ts_t now;
    amxp_expr_status_t status = 0;

    eval_t evals[] = {
        { true, "available"},
        { false, "NOT_available"},
        { true, ".MyTable.Number > 100 || available"},
        { true, "MyTable.Number > 100 || available"},
        { false, ".MyTable.Number > 100 || !available"},
        { false, "MyTable.Number > 100 || !available"},
        { false, "{MyTable.Number} > 100 || not_available"}
    };

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_ts_now(&now);

    amxc_var_add_key(cstring_t, &data, "TextField", "This is text");
    subtable = amxc_var_add_key(amxc_htable_t, &data, "MyTable", NULL);
    amxc_var_add_key(cstring_t, subtable, "Text", "Hello World");
    amxc_var_add_key(uint32_t, subtable, "Number", 100);
    amxc_var_add_key(bool, subtable, "Boolean", true);
    subarray = amxc_var_add_key(amxc_llist_t, &data, "MyArray", NULL);
    amxc_var_add(cstring_t, subarray, "Item1");
    amxc_var_add(int64_t, subarray, -20000);
    amxc_var_add(bool, subarray, true);
    amxc_var_add(amxc_ts_t, subarray, &now);

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        printf("Evaluating \"%s\"\n", evals[i].text);
        assert_int_equal(amxp_expr_init(&expression, evals[i].text), 0);
        assert_true(amxp_expr_evaluate(&expression, custom_field_fetcher, &data, &status) == evals[i].result);
        assert_int_equal(status, 0);
        amxp_expr_clean(&expression);
        fflush(stdout);
    }

    amxc_var_clean(&data);
}

void test_api_arguments_validation(UNUSED void** state) {
    amxp_expr_t* expr = NULL;
    amxp_expr_t expression;

    assert_int_not_equal(amxp_expr_new(NULL, ""), 0);
    assert_int_not_equal(amxp_expr_new(&expr, NULL), 0);
    assert_ptr_equal(expr, NULL);

    assert_int_equal(amxp_expr_new(&expr, "10 > 20"), 0);
    assert_ptr_not_equal(expr, NULL);

    amxp_expr_delete(&expr);
    assert_ptr_equal(expr, NULL);
    amxp_expr_delete(&expr);
    amxp_expr_delete(NULL);

    assert_int_not_equal(amxp_expr_init(NULL, "20 < 10"), 0);
    assert_int_not_equal(amxp_expr_init(&expression, NULL), 0);
    amxp_expr_clean(NULL);
}

void test_selects_first_in_first_existing(UNUSED void** state) {
    amxp_expr_t expression;
    amxc_var_t data;
    amxc_var_t* subtable;
    amxc_var_t* subarray;
    amxc_ts_t now;
    amxp_expr_status_t status = 0;

    eval_t evals[] = {
        { false, "first_existing(MyTable.Text, .MyArray.0) == \"Item1\""},
        { true, "first_existing(MyTable.Text, MyArray.0) == \"Hello World\""},
        { true, "first_existing(.MyTable.NotExistingText, MyArray.0) == \"Item1\""},
        { true, "first_existing(.MyTable.NotExistingText, MyArray.99, FakeItem.0.NotExisting, 'Item1') == \"Item1\""},
        { false, "first_existing(.MyTable.NotExistingText, MyArray.99, FakeItem.0.NotExisting, MyTable.Text) == \"Item1\""},
    };

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_ts_now(&now);

    amxc_var_add_key(cstring_t, &data, "TextField", "This is text");
    subtable = amxc_var_add_key(amxc_htable_t, &data, "MyTable", NULL);
    amxc_var_add_key(cstring_t, subtable, "Text", "Hello World");
    amxc_var_add_key(uint32_t, subtable, "Number", 100);
    amxc_var_add_key(bool, subtable, "Boolean", true);
    subarray = amxc_var_add_key(amxc_llist_t, &data, "MyArray", NULL);
    amxc_var_add(cstring_t, subarray, "Item1");
    amxc_var_add(int64_t, subarray, -20000);
    amxc_var_add(bool, subarray, true);
    amxc_var_add(amxc_ts_t, subarray, &now);
    amxc_var_dump(&data, 1);

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        printf("Evaluating \"%s\"\n", evals[i].text);
        assert_int_equal(amxp_expr_init(&expression, evals[i].text), 0);
        assert_true(amxp_expr_eval_var(&expression, &data, &status) == evals[i].result);
        assert_int_equal(status, 0);
        amxp_expr_dump_tree(&expression);
        amxp_expr_clean(&expression);
    }

    amxc_var_clean(&data);
}

void test_fails_with_invalid_regexp(UNUSED void** state) {
    amxp_expr_t expression;
    amxc_var_t data;
    amxc_var_t* subtable;
    amxc_var_t* subarray;
    amxc_ts_t now;

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_ts_now(&now);

    amxc_var_add_key(cstring_t, &data, "TextField", "This is text");
    subtable = amxc_var_add_key(amxc_htable_t, &data, "MyTable", NULL);
    amxc_var_add_key(cstring_t, subtable, "Text", "Hello World");
    amxc_var_add_key(uint32_t, subtable, "Number", 100);
    amxc_var_add_key(bool, subtable, "Boolean", true);
    subarray = amxc_var_add_key(amxc_llist_t, &data, "MyArray", NULL);
    amxc_var_add(cstring_t, subarray, "Item1");
    amxc_var_add(int64_t, subarray, -20000);
    amxc_var_add(bool, subarray, true);
    amxc_var_add(amxc_ts_t, subarray, &now);

    assert_int_not_equal(amxp_expr_init(&expression, "MyTable.Text matches \"[(adadasd.[\""), 0);

    amxc_var_clean(&data);
}

void test_is_empty_function(UNUSED void** state) {
    amxp_expr_t expression;
    amxp_expr_status_t status = 0;

    eval_t evals[] = {
        { true, "is_empty([])"},
        { false, "is_empty([1,2])"}
    };

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        printf("Evaluating \"%s\"\n", evals[i].text);
        assert_int_equal(amxp_expr_init(&expression, evals[i].text), 0);
        assert_true(amxp_expr_eval(&expression, &status) == evals[i].result);
        assert_int_equal(status, 0);
        amxp_expr_clean(&expression);
    }
}

void test_is_empty_function_with_var(UNUSED void** state) {
    amxp_expr_t expression;
    amxp_expr_status_t status = 0;
    amxc_var_t data;
    amxc_var_t* subtable;
    amxc_var_t* subarray;
    amxc_ts_t now;

    eval_t evals[] = {
        { false, "is_empty({MyTable})"},
        { false, "is_empty({MyArray})"},
        { true, "is_empty({EmptyArray})"},
        { true, "is_empty({EmptyTable})"},
        { true, "is_empty({MyTable.NotExisting})"},
        { true, "is_empty({MyArray.99})"},
        { false, "is_empty({})"},
        { true, "is_empty()"},
    };

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_ts_now(&now);

    amxc_var_add_key(cstring_t, &data, "TextField", "This is text");
    subtable = amxc_var_add_key(amxc_htable_t, &data, "MyTable", NULL);
    amxc_var_add_key(cstring_t, subtable, "Text", "Hello World");
    amxc_var_add_key(uint32_t, subtable, "Number", 100);
    amxc_var_add_key(bool, subtable, "Boolean", true);
    subarray = amxc_var_add_key(amxc_llist_t, &data, "MyArray", NULL);
    amxc_var_add(cstring_t, subarray, "Item1");
    amxc_var_add(int64_t, subarray, -20000);
    amxc_var_add(bool, subarray, true);
    amxc_var_add(amxc_ts_t, subarray, &now);
    amxc_var_add_key(amxc_llist_t, &data, "EmptyArray", NULL);
    amxc_var_add_key(amxc_htable_t, &data, "EmptyTable", NULL);

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        printf("Evaluating \"%s\"\n", evals[i].text);
        assert_int_equal(amxp_expr_init(&expression, evals[i].text), 0);
        assert_true(amxp_expr_eval_var(&expression, &data, &status) == evals[i].result);
        assert_int_equal(status, 0);
        amxp_expr_clean(&expression);
    }

    amxc_var_clean(&data);
}

void test_contains(UNUSED void** state) {
    amxp_expr_t expression;
    amxc_var_t data;
    amxc_var_t* subtable;
    amxc_var_t* subarray;
    amxc_ts_t now;
    amxp_expr_status_t status = 0;

    eval_t evals[] = {
        { true, "contains('MyTable.Text')"},
        { false, "contains('MyTable.Text.Extra')"},
        { true, "contains('MyArray.0')"},
        { false, "contains('MyArray.0.Extra')"},
        { false, "contains('MyArray.99')"},
        { true, "contains('Test', 'MyArray.0')"},
        { false, "contains('MyArray.99', 'MyTable.Text.Extra', 'MyArray.0.Extra')"},
    };

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_ts_now(&now);

    amxc_var_add_key(cstring_t, &data, "TextField", "This is text");
    subtable = amxc_var_add_key(amxc_htable_t, &data, "MyTable", NULL);
    amxc_var_add_key(cstring_t, subtable, "Text", "Hello World");
    amxc_var_add_key(uint32_t, subtable, "Number", 100);
    amxc_var_add_key(bool, subtable, "Boolean", true);
    subarray = amxc_var_add_key(amxc_llist_t, &data, "MyArray", NULL);
    amxc_var_add(cstring_t, subarray, "Item1");
    amxc_var_add(int64_t, subarray, -20000);
    amxc_var_add(bool, subarray, true);
    amxc_var_add(amxc_ts_t, subarray, &now);

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        printf("Evaluating \"%s\"\n", evals[i].text);
        assert_int_equal(amxp_expr_init(&expression, evals[i].text), 0);
        assert_true(amxp_expr_eval_var(&expression, &data, &status) == evals[i].result);
        assert_int_equal(status, 0);
        amxp_expr_clean(&expression);
    }

    amxc_var_clean(&data);
}

void test_contains_no_get_field(UNUSED void** state) {
    amxp_expr_t expression;
    amxp_expr_status_t status = 0;
    amxc_var_t data;
    amxc_var_t* subtable = NULL;

    eval_t evals[] = {
        { false, "contains('MyTable.Text')"},
        { false, "contains('MyTable.Text.Extra')"},
        { false, "contains('MyArray.0')"},
        { false, "contains('MyArray.0.Extra')"},
        { false, "contains('MyArray.99')"},
    };

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    subtable = amxc_var_add_key(amxc_htable_t, &data, "MyTable", NULL);
    amxc_var_add_key(cstring_t, subtable, "Text", "Hello World");

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        printf("Evaluating \"%s\"\n", evals[i].text);
        assert_int_equal(amxp_expr_init(&expression, evals[i].text), 0);
        assert_true(amxp_expr_evaluate(&expression, NULL, &data, &status) == evals[i].result);
        assert_int_equal(status, 0);
        amxp_expr_clean(&expression);
    }

    amxc_var_clean(&data);
}

void test_contains_no_data(UNUSED void** state) {
    amxp_expr_t expression;
    amxp_expr_status_t status = 0;

    eval_t evals[] = {
        { false, "contains('MyTable.Text')"},
        { false, "contains('MyTable.Text.Extra')"},
        { false, "contains('MyArray.0')"},
        { false, "contains('MyArray.0.Extra')"},
        { false, "contains('MyArray.99')"},
    };

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        printf("Evaluating \"%s\"\n", evals[i].text);
        assert_int_equal(amxp_expr_init(&expression, evals[i].text), 0);
        assert_true(amxp_expr_evaluate(&expression, NULL, NULL, &status) == evals[i].result);
        assert_int_equal(status, 0);
        amxp_expr_clean(&expression);
    }
}

void test_contains_invalid_usage(UNUSED void** state) {
    amxp_expr_t expression;
    amxp_expr_status_t status = 0;
    amxc_var_t data;

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);

    assert_int_equal(amxp_expr_init(&expression, "contains()"), 0);
    assert_false(amxp_expr_evaluate(&expression, NULL, &data, &status));
    assert_int_equal(status, 0);
    amxp_expr_clean(&expression);

    assert_int_equal(amxp_expr_init(&expression, "contains(100)"), 0);
    assert_false(amxp_expr_evaluate(&expression, NULL, &data, &status));
    assert_int_equal(status, 0);
    amxp_expr_clean(&expression);

    amxc_var_clean(&data);
}

void test_flag_expressions(UNUSED void** state) {
    amxp_expr_t expression;
    amxp_expr_status_t status = 0;
    amxc_set_t set;

    amxc_set_init(&set, false);
    amxc_set_parse(&set, "bridge ipv6 global lan interface");

    assert_int_equal(amxp_expr_init(&expression, "ipv4 || (ipv6 && global)"), 0);
    assert_true(amxp_expr_eval_set(&expression, &set, &status));

    amxc_set_remove_flag(&set, "ipv6");

    assert_false(amxp_expr_eval_set(&expression, &set, &status));

    amxc_set_clean(&set);
    amxp_expr_clean(&expression);
}

void test_flag_expressions_no_operators(UNUSED void** state) {
    amxp_expr_t expression;
    amxp_expr_status_t status = 0;
    amxc_set_t set;

    amxc_set_init(&set, false);
    amxc_set_parse(&set, "bridge ipv6 global lan interface");

    assert_int_equal(amxp_expr_init(&expression, "ipv6 global"), 0);
    assert_true(amxp_expr_eval_set(&expression, &set, &status));

    amxc_set_remove_flag(&set, "ipv6");

    assert_false(amxp_expr_eval_set(&expression, &set, &status));

    amxc_set_clean(&set);
    amxp_expr_clean(&expression);
}

void test_in_operators(UNUSED void** state) {
    amxp_expr_t expression;
    amxp_expr_status_t status = 0;
    eval_t evals[] = {
        { true, "'Some text' in ['Some text', 'other value']"},
        { false, "'Some text' in ['some value', 'other value']"},
        { true, "['Some text', 'other value'] ~= 'Some text'"},
        { false, "['some value', 'other value'] ~= 'Some text'"},
    };

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        printf("Evaluating \"%s\"\n", evals[i].text);
        assert_int_equal(amxp_expr_init(&expression, evals[i].text), 0);
        assert_true(amxp_expr_evaluate(&expression, NULL, NULL, &status) == evals[i].result);
        assert_int_equal(status, 0);
        amxp_expr_clean(&expression);
    }
}

void test_buildf_expression(UNUSED void** state) {
    amxp_expr_t expression;
    const char* expr_fmt = "'Some text' in ['%s', '%s']";

    printf("Building \"%s\"\n", expr_fmt);
    assert_int_equal(amxp_expr_buildf(&expression, expr_fmt, "some value", "other value"), amxp_expr_status_ok);
    amxp_expr_clean(&expression);
}

void test_buildf_expression_allocate(UNUSED void** state) {
    amxp_expr_t* expression = NULL;
    const char* expr_fmt = "'Some text' in ['%s', '%s']";

    printf("Building \"%s\"\n", expr_fmt);
    assert_int_equal(amxp_expr_buildf_new(&expression, expr_fmt, "some value", "other value"), amxp_expr_status_ok);
    amxp_expr_delete(&expression);
}

void test_buildf_expression_invalid_value(UNUSED void** state) {
    amxp_expr_t expression;
    const char* expr_fmt = "password == '%s'";

    printf("Building \"%s\"\n", expr_fmt);
    assert_int_not_equal(amxp_expr_buildf(&expression, expr_fmt, "not password' or '' == '"), amxp_expr_status_ok);
    amxp_expr_clean(&expression);
}

void test_buildf_expression_all_whitelisted(UNUSED void** state) {
    amxp_expr_t expression;
    const char* expr_fmt = "test == '%s'";

    printf("Building \"%s\"\n", expr_fmt);
    assert_int_equal(amxp_expr_buildf(&expression, expr_fmt, "Whitelisted according to specs:"
                                      "!#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz{|}~",
                                      "other value"), amxp_expr_status_ok);
    amxp_expr_clean(&expression);
}

void test_buildf_expression_invalid_args(UNUSED void** state) {
    amxp_expr_t expression;
    const char* bad_expr_fmt = "test == '%s']";
    const char* good_expr_fmt = "test == '%s'";

    assert_int_not_equal(amxp_expr_buildf(&expression, bad_expr_fmt, "test", "other value"), amxp_expr_status_ok);
    assert_int_not_equal(amxp_expr_buildf(NULL, good_expr_fmt, "test"), amxp_expr_status_ok);
    assert_int_not_equal(amxp_expr_buildf(&expression, NULL), amxp_expr_status_ok);

    amxp_expr_clean(&expression);
}

static void s_testhelper_buildf(bool expect_accepted, const char* string) {
    amxp_expr_t expression;
    amxp_expr_status_t status_eval = amxp_expr_status_unknown_error;
    amxp_expr_status_t status_build = amxp_expr_buildf(&expression, "'%s' == '%s'", string, string);
    bool matched = amxp_expr_eval(&expression, &status_eval);
    if(expect_accepted) {
        assert_true(matched);
        assert_int_equal(status_build, amxp_expr_status_ok);
        amxp_expr_clean(&expression);
    } else {
        assert_false(matched);
        assert_int_not_equal(status_build, amxp_expr_status_ok);
    }
}

void test_buildf_are_strings_safe(UNUSED void** state) {
    s_testhelper_buildf(true, "192.168.1.1");
    s_testhelper_buildf(true, "AA:BB:CC:DD:EE:FF");
    s_testhelper_buildf(true, "Hello world!");
    s_testhelper_buildf(true, "Whitelisted according to specs: !#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz{|}~");
    s_testhelper_buildf(true, "");

    s_testhelper_buildf(false, "notpasword' or '' == '");
    s_testhelper_buildf(false, "notpasword\" or \"\" == \"");
    s_testhelper_buildf(false, "192.168.1.1\"); PasswordManager.MasterPassword=hacked; #");
    s_testhelper_buildf(false, "192.168.1.1\\");
    s_testhelper_buildf(false, "We ♥ UTF-8 but it is currently not whitelisted");
}

void test_get_string(UNUSED void** state) {
    const char* expr_string = NULL;

    // GIVEN an expression
    amxp_expr_t expr;
    amxp_expr_buildf(&expr, "username == '%s'", "Alice");

    // WHEN retrieiving its string representation
    expr_string = amxp_expr_get_string(&expr);

    // THEN the string representation is returned
    assert_string_equal("username == 'Alice'", expr_string);

    amxp_expr_clean(&expr);
}

void test_get_string_null(UNUSED void** state) {
    const char* expr_string = NULL;

    // GIVEN a NULL expression
    amxp_expr_t* expr = NULL;

    // WHEN retrieving its string representation
    expr_string = amxp_expr_get_string(expr);

    // THEN NULL is returned
    assert_null(expr_string);
}

void test_expression_with_invalid_list_does_not_memory_leak(UNUSED void** state) {
    // GIVEN a NULL expression
    amxp_expr_t expr;
    assert_int_not_equal(amxp_expr_init(&expr, "[[brackets"), 0);

    amxp_expr_clean(&expr);
}

void test_equals_ignorecase(UNUSED void** state) {
    amxc_var_t data;

    eval_t evals[] = {
        // Case: Exactly the same
        { true, "'HELLO world' ^= 'HELLO world'"},
        // Case: upper/lowercase different
        { true, "'HELLO world' ^= 'hello WORLD'"},
        { true, "'HELLO WORLD' ^= 'hello world'"},
        { true, "'hello world' ^= 'HELLO WORLD'"},
        // Case: different characters
        { false, "'hello world' ^= 'hallo world'"},
        // Expression is substring
        { false, "'abcd' ^= 'abc'"},
        { false, "'abcd' ^= 'bcd'"},
        { false, "'abcd' ^= 'bc'"},
        { false, "'abcd' ^= ''"},
        // Expression is superstring
        { false, "'abc' ^= 'abcd'"},
        { false, "'bcd' ^= 'abcd'"},
        { false, "'bc' ^= 'abcd'"},
        { false, "'' ^= 'abcd'"},
        // Case: Special characters
        { true, "'~♥!@#$%^&*(){}?+_SZVWwvzs-/=][' ^= '~♥!@#$%^&*(){}?+_SZVWwvzs-/=]['"},
        { false, "'~♥!@#$%^&*(){}?+_SZVWwvzs-/=][' ^= '~♥!@#$%^&*(){}?+_SZVWwvzs-/=[]'"},
        // Case: quote characters
        { true, "'He said: \"Hello.\"' ^= 'He said: \"Hello.\"'"},
        { true, "\"He said: 'Hello.'\" ^= \"He said: 'Hello.'\""},
        { false, "\"He said: 'Hello.'\" ^= 'He said: \"Hello.\"'"},
        // Case: Not a string
        { true, "Number ^= '100'" },
        { true, "Boolean ^= \"false\"" },
        { true, "Boolean ^= \"FaLsE\"" },
        { false, "Boolean ^= \"true\"" },
        { true, "CSVText ^= \"the,BIG,brown,fox,jumped\""},
    };

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &data, "Number", 100);
    amxc_var_add_key(bool, &data, "Boolean", false);
    amxc_var_add_key(csv_string_t, &data, "CSVText", "The,big,brown,fox,jumped");

    for(uint32_t i = 0; i < sizeof(evals) / sizeof(evals[0]); i++) {
        amxp_expr_t expression;
        amxp_expr_status_t status = amxp_expr_status_unknown_error;
        printf("Evaluating \"%s\"\n", evals[i].text);
        assert_int_equal(amxp_expr_init(&expression, evals[i].text), 0);
        assert_int_equal(amxp_expr_eval_var(&expression, &data, &status), evals[i].result);
        assert_int_equal(status, 0);
        amxp_expr_clean(&expression);
    }

    amxc_var_clean(&data);
}

