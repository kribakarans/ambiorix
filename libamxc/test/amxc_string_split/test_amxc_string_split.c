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
#include <stdarg.h>
#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include <amxc/amxc_string_split.h>
#include <amxc/amxc_utils.h>

#include "test_amxc_string_split.h"

typedef struct _test_cases {
    uint32_t parts;
    char separator;
    char* text;
} test_cases_t;

#include <amxc/amxc_macros.h>
void test_can_split_string_using_separator(UNUSED void** state) {
    test_cases_t cases[] = {
        {3, ',', "a,[b,c],d"},
        {2, ',', "Phonebook.Contact.[FirstName=='ward'].PhoneNumber.*,Phonebook.Contact."},
        {4, ',', "a , b , c , d"},
        {8, ',', "a,,b,,c,,d,"},
        {4, ',', "ab,cd,ef,gh"},
        {3, ',', "a,\"b,c\",d"},
        {5, ',', " , ab cd , ef gh , ij kl, "},
        {5, ',', " , ab cd , 'ef gh, ef gh' , ij kl, "},
        {5, ',', "[text1 , , , text2,text3]"},
        {3, ',', "[text1 , ,] , text2,text3"},
        {4, ',', "text1 , , , [text2,text3]"},
        {3, ',', "text1 , [ , , text2], text3"},
        {0, 0, NULL}
    };
    amxc_string_t string;
    amxc_llist_t string_list;

    amxc_llist_init(&string_list);
    amxc_string_init(&string, 0);
    for(int i = 0; cases[i].text != NULL; i++) {
        char* data = NULL;
        printf("Split string : %s\n", cases[i].text);
        fflush(stdout);
        data = strdup(cases[i].text);
        amxc_string_push_buffer(&string, data, strlen(cases[i].text) + 1);
        assert_int_equal(amxc_string_split_to_llist(&string, &string_list, cases[i].separator), 0);
        assert_int_equal(amxc_llist_size(&string_list), cases[i].parts);
        amxc_string_take_buffer(&string);
        free(data);
        amxc_llist_clean(&string_list, amxc_string_list_it_free);
    }
}

void test_can_split_string_using_space_separators(UNUSED void** state) {
    test_cases_t cases[] = {
        {1, '\t', "a b c d"},
        {4, ' ', "a  b  c  d"},
        {3, '\t', "a [b\t c] d"},
        {2, '\n', "ab cd\nef\tgh"},
        {3, ' ', "a \"b c\" d"},
        {3, ' ', "[text1 text2 text3]"},
        {3, ' ', "  [text1 text2 text3]  "},
        {0, 0, NULL}
    };
    amxc_string_t string;
    amxc_llist_t string_list;

    amxc_llist_init(&string_list);
    amxc_string_init(&string, 0);
    for(int i = 0; cases[i].text != NULL; i++) {
        char* data = NULL;
        printf("Split string : %s\n", cases[i].text);
        data = strdup(cases[i].text);
        amxc_string_push_buffer(&string, data, strlen(cases[i].text) + 1);
        assert_int_equal(amxc_string_split_to_llist(&string, &string_list, cases[i].separator), 0);
        assert_int_equal(amxc_llist_size(&string_list), cases[i].parts);
        amxc_string_take_buffer(&string);
        free(data);
        amxc_llist_clean(&string_list, amxc_string_list_it_free);
    }
}

void test_check_parts_are_correct(UNUSED void** state) {
    amxc_string_t string;
    char* txt = strdup("a,[b,c],d");
    amxc_llist_t string_list;

    amxc_llist_init(&string_list);
    amxc_string_init(&string, 0);
    amxc_string_push_buffer(&string, txt, strlen(txt) + 1);

    assert_int_equal(amxc_string_split_to_llist(&string, &string_list, ','), 0);
    assert_int_equal(amxc_llist_size(&string_list), 3);
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 0), "a");
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 1), "[b,c]");
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 2), "d");
    amxc_string_take_buffer(&string);
    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    free(txt);

    txt = strdup("a[b\t c]d");
    amxc_string_push_buffer(&string, txt, strlen(txt) + 1);
    assert_int_equal(amxc_string_split_to_llist(&string, &string_list, ','), 0);
    assert_int_equal(amxc_llist_size(&string_list), 1);
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 0), "a[b\tc]d");
    amxc_llist_clean(&string_list, amxc_string_list_it_free);

    assert_int_equal(amxc_string_split_to_llist(&string, &string_list, ' '), 0);
    assert_int_equal(amxc_llist_size(&string_list), 3);
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 0), "a");
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 1), "[b\tc]");
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 2), "d");
    amxc_string_take_buffer(&string);
    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    free(txt);

    txt = strdup("a [b\t c] d");
    amxc_string_push_buffer(&string, txt, strlen(txt) + 1);
    assert_int_equal(amxc_string_split_to_llist(&string, &string_list, ' '), 0);
    assert_int_equal(amxc_llist_size(&string_list), 3);
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 0), "a");
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 1), "[b\tc]");
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 2), "d");
    amxc_string_take_buffer(&string);
    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    free(txt);

    txt = strdup("[a b\tc d text more text]");
    amxc_string_push_buffer(&string, txt, strlen(txt) + 1);
    assert_int_equal(amxc_string_split_to_llist(&string, &string_list, ' '), 0);
    assert_int_equal(amxc_llist_size(&string_list), 6);
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 0), "a");
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 1), "b\tc");
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 2), "d");
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 3), "text");
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 4), "more");
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 5), "text");
    amxc_string_take_buffer(&string);
    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    free(txt);
}

void test_can_split_csv_string_to_variant(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;
    amxc_llist_it_t* it = NULL;
    amxc_var_t* part = NULL;

    amxc_var_init(&variant);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, "part1,part2,part3", 17), 0);
    assert_int_equal(amxc_string_csv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 3);

    it = amxc_llist_get_first(string_list);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part1");

    it = amxc_llist_it_get_next(it);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part2");

    it = amxc_llist_it_get_next(it);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part3");

    assert_int_equal(amxc_string_setf(&string, "Phonebook.Contact.[FirstName=='ward'].PhoneNumber.*,Phonebook.Contact."), 0);
    assert_int_equal(amxc_string_csv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    amxc_var_dump(&variant, 1);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 2);
    assert_string_equal(GETI_CHAR(&variant, 0), "Phonebook.Contact.[FirstName=='ward'].PhoneNumber.*");
    assert_string_equal(GETI_CHAR(&variant, 1), "Phonebook.Contact.");

    assert_int_not_equal(amxc_string_csv_to_var(NULL, NULL, NULL), 0);
    assert_int_not_equal(amxc_string_csv_to_var(&string, NULL, NULL), 0);

    amxc_string_clean(&string);
    amxc_var_clean(&variant);
}

void test_split_csv_handles_sequence_of_commas_as_multiple_items(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;
    const char* text = "a,,,,,b";

    amxc_var_init(&variant);
    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);

    assert_int_equal(amxc_string_csv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 6);

    amxc_string_clean(&string);
    amxc_var_clean(&variant);
}

void test_split_csv_string_handles_comma_in_quotes_correctly(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;
    const char* text = "','";

    amxc_var_init(&variant);
    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);

    assert_int_equal(amxc_string_csv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 1);

    amxc_string_reset(&string);
    text = "\",\"";
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);

    assert_int_equal(amxc_string_csv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 1);

    amxc_string_reset(&string);
    text = ",";
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);

    assert_int_equal(amxc_string_csv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 2);

    amxc_string_clean(&string);
    amxc_var_clean(&variant);
}

void test_split_csv_string_handles_empty_string_correctly(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;

    amxc_var_init(&variant);
    assert_int_equal(amxc_string_init(&string, 0), 0);

    assert_int_equal(amxc_string_csv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 0);

    amxc_string_reset(&string);
    amxc_var_clean(&variant);
}

void test_can_split_csv_string_with_multi_array_to_variant(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;
    amxc_llist_it_t* it = NULL;
    amxc_var_t* part = NULL;

    amxc_var_init(&variant);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, "part1,[part2,part3],part4", 25), 0);
    assert_int_equal(amxc_string_csv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 3);

    it = amxc_llist_get_first(string_list);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part1");

    it = amxc_llist_it_get_next(it);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_LIST);
    assert_ptr_not_equal(amxc_var_constcast(amxc_llist_t, part), NULL);

    it = amxc_llist_it_get_next(it);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part4");

    amxc_string_clean(&string);
    amxc_var_clean(&variant);
}

void test_can_split_csv_string_can_start_with_array_to_variant(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;
    amxc_llist_it_t* it = NULL;
    amxc_var_t* part = NULL;

    amxc_var_init(&variant);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, "[part1,part2],part3,part4", 25), 0);
    assert_int_equal(amxc_string_csv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 3);

    it = amxc_llist_get_first(string_list);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_LIST);
    assert_ptr_not_equal(amxc_var_constcast(amxc_llist_t, part), NULL);

    it = amxc_llist_it_get_next(it);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part3");

    it = amxc_llist_it_get_next(it);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part4");

    amxc_string_clean(&string);
    amxc_var_clean(&variant);
}

void test_can_split_csv_string_supports_multi_level_array_to_variant(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;

    amxc_var_init(&variant);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, "[part1,[part2,part3,[part4,part5]]]", 35), 0);
    assert_int_equal(amxc_string_csv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 1);

    amxc_string_clean(&string);
    amxc_var_clean(&variant);
}

void test_can_split_csv_string_with_single_quotes_to_variant(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;
    amxc_llist_it_t* it = NULL;
    amxc_var_t* part = NULL;
    char* text = "part1,'[part2,part3],part4',long text";
    amxc_var_init(&variant);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);
    assert_int_equal(amxc_string_csv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 3);

    it = amxc_llist_get_first(string_list);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part1");

    it = amxc_llist_it_get_next(it);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "'[part2,part3],part4'");

    it = amxc_llist_it_get_next(it);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "long text");

    amxc_string_clean(&string);
    amxc_var_clean(&variant);
}

void test_can_split_csv_string_with_double_quotes_to_variant(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;
    amxc_llist_it_t* it = NULL;
    amxc_var_t* part = NULL;

    amxc_var_init(&variant);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, "part1,\"[part2,part3],part4\"", 27), 0);
    assert_int_equal(amxc_string_csv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 2);

    it = amxc_llist_get_first(string_list);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part1");

    it = amxc_llist_it_get_next(it);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "\"[part2,part3],part4\"");

    amxc_string_clean(&string);
    amxc_var_clean(&variant);
}

void test_split_csv_can_handle_empty_sublist(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;
    amxc_llist_it_t* it = NULL;
    amxc_var_t* part = NULL;
    const char* txt = "part1,[],part4";

    amxc_var_init(&variant);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, txt, strlen(txt)), 0);
    assert_int_equal(amxc_string_csv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 3);

    it = amxc_llist_get_first(string_list);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part1");

    it = amxc_llist_it_get_next(it);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, part);
    assert_true(amxc_llist_is_empty(string_list));

    amxc_string_clean(&string);
    amxc_var_clean(&variant);
}

void test_can_split_ssv_string_to_variant(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;
    amxc_llist_it_t* it = NULL;
    amxc_var_t* part = NULL;

    amxc_var_init(&variant);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, "part1 part2 part3", 17), 0);
    assert_int_equal(amxc_string_ssv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 3);

    it = amxc_llist_get_first(string_list);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part1");

    it = amxc_llist_it_get_next(it);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part2");

    it = amxc_llist_it_get_next(it);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part3");

    assert_int_not_equal(amxc_string_ssv_to_var(NULL, NULL, NULL), 0);
    assert_int_not_equal(amxc_string_ssv_to_var(&string, NULL, NULL), 0);

    amxc_string_clean(&string);
    amxc_var_clean(&variant);
}

void test_split_ssv_handles_sequence_of_spaces_as_one_separator(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;
    const char* text = "a  \t  \tb";

    amxc_var_init(&variant);
    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);

    assert_int_equal(amxc_string_ssv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 2);

    amxc_string_clean(&string);
    amxc_var_clean(&variant);
}

void test_split_ssv_string_handles_spaces_in_quotes_correctly(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;
    const char* text = "' '";

    amxc_var_init(&variant);
    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);

    assert_int_equal(amxc_string_ssv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 1);

    amxc_string_reset(&string);
    text = "\" \"";
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);

    assert_int_equal(amxc_string_ssv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 1);

    amxc_string_reset(&string);
    text = " ";
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);

    assert_int_equal(amxc_string_ssv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 0);

    amxc_string_clean(&string);
    amxc_var_clean(&variant);
}

void test_can_split_ssv_string_with_single_quotes_to_variant(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;
    amxc_llist_it_t* it = NULL;
    amxc_var_t* part = NULL;

    amxc_var_init(&variant);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, "part1 '[part2 part3] part4'", 27), 0);
    assert_int_equal(amxc_string_ssv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 2);

    it = amxc_llist_get_first(string_list);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part1");

    it = amxc_llist_it_get_next(it);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "'[part2 part3] part4'");

    amxc_string_clean(&string);
    amxc_var_clean(&variant);
}

void test_split_ssv_string_handles_empty_string_correctly(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;

    amxc_var_init(&variant);
    assert_int_equal(amxc_string_init(&string, 0), 0);

    assert_int_equal(amxc_string_ssv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 0);

    amxc_string_reset(&string);
    amxc_var_clean(&variant);
}

void test_can_split_ssv_string_with_multi_array_to_variant(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t variant;
    const amxc_llist_t* string_list = NULL;
    amxc_llist_it_t* it = NULL;
    amxc_var_t* part = NULL;

    amxc_var_init(&variant);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, "part1 [part2 part3] part4", 25), 0);
    assert_int_equal(amxc_string_ssv_to_var(&string, &variant, NULL), 0);
    assert_int_equal(amxc_var_type_of(&variant), AMXC_VAR_ID_LIST);
    string_list = amxc_var_constcast(amxc_llist_t, &variant);
    assert_ptr_not_equal(string_list, NULL);
    assert_int_equal(amxc_llist_size(string_list), 3);

    it = amxc_llist_get_first(string_list);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part1");

    it = amxc_llist_it_get_next(it);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_LIST);
    assert_ptr_not_equal(amxc_var_constcast(amxc_llist_t, part), NULL);

    it = amxc_llist_it_get_next(it);
    part = amxc_var_from_llist_it(it);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(amxc_var_constcast(cstring_t, part), NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "part4");

    amxc_string_clean(&string);
    amxc_var_clean(&variant);
}

void test_split_word_checks_quotes(UNUSED void** state) {
    amxc_string_t string;
    amxc_llist_t string_list;
    const char* text = "\"Double quoted string \\\" with double and ' single quote\"";
    const char* reason = "";

    amxc_llist_init(&string_list);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, &reason), 0);
    assert_int_equal(amxc_llist_size(&string_list), 3);

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_reset(&string);
    text = "\"Missing double quote";
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, &reason), AMXC_ERROR_STRING_MISSING_DQUOTE);
    assert_int_not_equal(strlen(reason), 0);
    printf("%s\n", reason);
    assert_int_equal(amxc_llist_size(&string_list), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, NULL), AMXC_ERROR_STRING_MISSING_DQUOTE);

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_reset(&string);
    text = "'Missing single quote";
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, &reason), AMXC_ERROR_STRING_MISSING_SQUOTE);
    assert_int_not_equal(strlen(reason), 0);
    printf("%s\n", reason);
    assert_int_equal(amxc_llist_size(&string_list), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, NULL), AMXC_ERROR_STRING_MISSING_SQUOTE);

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_reset(&string);
    text = "'single quoted string with double \" and \\' single quote'";
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, &reason), 0);
    assert_int_equal(amxc_llist_size(&string_list), 3);

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_clean(&string);
}

void test_split_word_checks_curly_brackets(UNUSED void** state) {
    amxc_string_t string;
    amxc_llist_t string_list;
    const char* text = "{1, 2, 3}";
    const char* reason = "";

    amxc_llist_init(&string_list);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, &reason), 0);
    assert_int_equal(amxc_llist_size(&string_list), 9);

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_reset(&string);

    text = "{1, 2, 3";
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, &reason), AMXC_ERROR_STRING_MISSING_CBRACKET);
    assert_int_not_equal(strlen(reason), 0);
    printf("%s\n", reason);
    assert_int_equal(amxc_llist_size(&string_list), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, NULL), AMXC_ERROR_STRING_MISSING_CBRACKET);

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_reset(&string);

    text = "1, 2, 3}";
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, &reason), AMXC_ERROR_STRING_MISSING_CBRACKET);
    assert_int_not_equal(strlen(reason), 0);
    printf("%s\n", reason);
    assert_int_equal(amxc_llist_size(&string_list), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, NULL), AMXC_ERROR_STRING_MISSING_CBRACKET);

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_clean(&string);
}

void test_split_word_checks_square_brackets(UNUSED void** state) {
    amxc_string_t string;
    amxc_llist_t string_list;
    const char* text = "[1, 2, 3]";
    const char* reason = "";

    amxc_llist_init(&string_list);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, &reason), 0);
    assert_int_equal(amxc_llist_size(&string_list), 9);

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_reset(&string);

    text = "[1, 2, 3";
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, &reason), AMXC_ERROR_STRING_MISSING_SBRACKET);
    assert_int_not_equal(strlen(reason), 0);
    printf("%s\n", reason);
    assert_int_equal(amxc_llist_size(&string_list), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, NULL), AMXC_ERROR_STRING_MISSING_SBRACKET);

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_reset(&string);

    text = "1, 2, 3]";
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, &reason), AMXC_ERROR_STRING_MISSING_SBRACKET);
    assert_int_not_equal(strlen(reason), 0);
    printf("%s\n", reason);
    assert_int_equal(amxc_llist_size(&string_list), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, NULL), AMXC_ERROR_STRING_MISSING_SBRACKET);

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_clean(&string);
}

void test_split_word_checks_round_brackets(UNUSED void** state) {
    amxc_string_t string;
    amxc_llist_t string_list;
    const char* text = "(1, 2, 3)";
    const char* reason = "";

    amxc_llist_init(&string_list);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, &reason), 0);
    assert_int_equal(amxc_llist_size(&string_list), 9);

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_reset(&string);

    text = "(1, 2, 3";
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, &reason), AMXC_ERROR_STRING_MISSING_RBRACKET);
    assert_int_not_equal(strlen(reason), 0);
    printf("%s\n", reason);
    assert_int_equal(amxc_llist_size(&string_list), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, NULL), AMXC_ERROR_STRING_MISSING_RBRACKET);

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_reset(&string);

    text = "1, 2, 3)";
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, &reason), AMXC_ERROR_STRING_MISSING_RBRACKET);
    assert_int_not_equal(strlen(reason), 0);
    printf("%s\n", reason);
    assert_int_equal(amxc_llist_size(&string_list), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, NULL), AMXC_ERROR_STRING_MISSING_RBRACKET);

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_clean(&string);
}

void test_amxc_string_split_word(UNUSED void** state) {
    amxc_string_t string;
    amxc_llist_t string_list;
    const char* parts[] = {
        "This", " ", "is", " ", "a", " ", "text", "\t", "with", " ", "space", " ", "characters", " ", "and",
        " ", "\"", "quoted text with \\\" escapes", "\"", " ", "and", " ", ",", " ", "some", " ", "(",
        "punctuation", ")", ".", " ", "A", " ", "=", " ", "The", " ", "end", " ", NULL
    };

    const char* text = "  This is a text\t\t  with space characters and \"quoted text with \\\" escapes\" and , some (punctuation). A = The end   ";
    amxc_llist_init(&string_list);
    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);

    assert_int_equal(amxc_string_split_word(&string, &string_list, NULL), 0);
    amxc_llist_for_each(it, (&string_list)) {
        amxc_string_t* s = amxc_string_from_llist_it(it);
        const char* p = amxc_string_get(s, 0);
        printf("*%s*\n", p);
    }
    assert_int_equal(amxc_llist_size(&string_list), 39);

    for(int i = 0; parts[i] != NULL; i++) {
        const char* txt_part = amxc_string_get_text_from_llist(&string_list, i);
        assert_string_equal(txt_part, parts[i]);
    }

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_clean(&string);
}

void test_amxc_string_split_word_quotes2(UNUSED void** state) {
    amxc_string_t string;
    amxc_llist_t string_list;
    int counter = 0;

    const char* text = "!History.save \"/tmp/test.txt\"";

    amxc_llist_init(&string_list);
    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);
    assert_int_equal(amxc_string_split_word(&string, &string_list, NULL), 0);

    amxc_llist_for_each(it, (&string_list)) {
        amxc_string_t* s = amxc_string_from_llist_it(it);
        const char* p = amxc_string_get(s, 0);
        assert_ptr_not_equal(p, NULL);

        switch(counter) {
        case 0:
            assert_string_equal(p, "!");
            break;
        case 1:
            assert_string_equal(p, "History");
            break;
        case 2:
            assert_string_equal(p, ".");
            break;
        case 3:
            assert_string_equal(p, "save");
            break;
        case 4:
            assert_string_equal(p, " ");
            break;
        case 5:
            assert_string_equal(p, "\"");
            break;
        case 6:
            assert_string_equal(p, "/tmp/test.txt");
            break;
        case 7:
            assert_string_equal(p, "\"");
            break;
        }

        printf("[%s]\n", p);
        counter++;
    }

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_clean(&string);
}

void test_amxc_string_split_word_can_start_with_punctuation(UNUSED void** state) {
    amxc_string_t string;
    amxc_llist_t string_list;

    const char* text = ",some more text here";
    amxc_llist_init(&string_list);
    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);

    assert_int_equal(amxc_string_split_word(&string, &string_list, NULL), 0);
    assert_int_equal(amxc_llist_size(&string_list), 8);

    amxc_llist_clean(&string_list, amxc_string_list_it_free);
    amxc_string_clean(&string);
}

void test_functions_validates_input_arguments(UNUSED void** state) {
    amxc_string_t string;
    amxc_llist_t string_list;

    const char* text = "some,more [text,here";
    amxc_llist_init(&string_list);
    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_append(&string, text, strlen(text)), 0);

    assert_int_not_equal(amxc_string_split_to_llist(NULL, &string_list, ':'), 0);
    assert_int_equal(amxc_llist_size(&string_list), 0);
    assert_int_not_equal(amxc_string_split_to_llist(&string, NULL, ':'), 0);
    assert_int_equal(amxc_llist_size(&string_list), 0);
    assert_int_not_equal(amxc_string_split_to_llist(&string, &string_list, 'a'), 0);
    assert_int_equal(amxc_llist_size(&string_list), 0);
    assert_int_not_equal(amxc_string_split_to_llist(&string, &string_list, '9'), 0);
    assert_int_equal(amxc_llist_size(&string_list), 0);
    assert_int_not_equal(amxc_string_split_to_llist(&string, &string_list, ']'), 0);
    assert_int_equal(amxc_llist_size(&string_list), 0);
    assert_int_not_equal(amxc_string_split_to_llist(&string, &string_list, '['), 0);
    assert_int_equal(amxc_llist_size(&string_list), 0);
    assert_int_not_equal(amxc_string_split_to_llist(&string, &string_list, ','), 0);
    assert_int_equal(amxc_llist_size(&string_list), 0);

    assert_ptr_equal(amxc_string_get_text_from_llist(&string_list, 100), NULL);
    assert_ptr_equal(amxc_string_get_text_from_llist(NULL, 100), NULL);

    amxc_string_clean(&string);
    amxc_llist_clean(&string_list, amxc_string_list_it_free);
}

void test_split_string_on_new_line(UNUSED void** state) {
    amxc_string_t string;
    amxc_llist_t string_list;

    amxc_llist_init(&string_list);
    amxc_string_init(&string, 0);
    amxc_string_setf(&string, "This is the first line\nThis is the second line");

    assert_int_equal(amxc_string_split_to_llist(&string, &string_list, '\n'), 0);
    assert_int_equal(amxc_llist_size(&string_list), 2);

    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 0), "This is the first line");
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 1), "This is the second line");

    amxc_string_clean(&string);
    amxc_llist_clean(&string_list, amxc_string_list_it_free);

    amxc_string_setf(&string, "This is the first line \n This is the second line");

    assert_int_equal(amxc_string_split_to_llist(&string, &string_list, '\n'), 0);
    assert_int_equal(amxc_llist_size(&string_list), 2);

    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 0), "This is the first line ");
    assert_string_equal(amxc_string_get_text_from_llist(&string_list, 1), "This is the second line");

    amxc_llist_clean(&string_list, amxc_string_list_it_free);

    assert_int_equal(amxc_string_split_to_llist(&string, &string_list, ' '), 0);
    assert_int_equal(amxc_llist_size(&string_list), 10);

    amxc_string_clean(&string);
    amxc_llist_clean(&string_list, amxc_string_list_it_free);
}
