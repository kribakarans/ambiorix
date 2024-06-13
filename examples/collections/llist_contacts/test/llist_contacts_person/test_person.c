/****************************************************************************
**
** Copyright (c) 2020 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include <amxc/amxc.h>

#include "contacts.h"
#include "test_person.h"

#define UNUSED __attribute__((unused))

void test_person_new_delete(UNUSED void** state) {
    amxc_llist_t fields;
    amxc_string_t data;
    person_t* person = NULL;

    amxc_string_init(&data, 0);
    amxc_llist_init(&fields);
    amxc_string_setf(&data, "Violet,Elliott,Female,25,v.elliott@randatmail.com,896-3242-73,Married");

    assert_int_equal(amxc_string_split_to_llist(&data, &fields, ','), 0);
    assert_int_equal(person_new(&person, &fields), 0);
    assert_non_null(person);

    assert_string_equal(person->first_name, "Violet");
    assert_string_equal(person->last_name, "Elliott");
    assert_int_equal(person->gender, female);
    assert_int_equal(person->age, 25);
    assert_string_equal(person->email, "v.elliott@randatmail.com");
    assert_string_equal(person->phone, "896-3242-73");
    assert_int_equal(person->mstatus, married);

    person_del(&person);
    assert_null(person);

    amxc_string_clean(&data);
    amxc_llist_clean(&fields, amxc_string_list_it_free);
}

void test_person_new_strips_quotes(UNUSED void** state) {
    amxc_llist_t fields;
    amxc_string_t data;
    person_t* person = NULL;

    amxc_string_init(&data, 0);
    amxc_llist_init(&fields);
    amxc_string_setf(&data, "\"Violet\",\"Elliott\",\"Male\",\"25\",\"v.elliott@randatmail.com\",\"896-3242-73\",\"Single\"");

    assert_int_equal(amxc_string_split_to_llist(&data, &fields, ','), 0);
    assert_int_equal(person_new(&person, &fields), 0);
    assert_non_null(person);

    assert_string_equal(person->first_name, "Violet");
    assert_string_equal(person->last_name, "Elliott");
    assert_int_equal(person->gender, male);
    assert_int_equal(person->age, 25);
    assert_string_equal(person->email, "v.elliott@randatmail.com");
    assert_string_equal(person->phone, "896-3242-73");
    assert_int_equal(person->mstatus, single);

    person_del(&person);
    assert_null(person);

    amxc_string_clean(&data);
    amxc_llist_clean(&fields, amxc_string_list_it_free);
}

void test_person_new_invalid(UNUSED void** state) {
    amxc_llist_t fields;
    amxc_string_t data;
    person_t* person = NULL;

    amxc_string_init(&data, 0);
    amxc_llist_init(&fields);

    const char* test_array[] = {
        "\"Violet\",\"Elliott\",\"Transgender\",\"25\",\"v.elliott@randatmail.com\",\"896-3242-73\",\"Single\"", //wrong gender
        "\"Violet\",\"Elliott\",\"Male\",\"25\",\"v.elliott@randatmail.com\",\"896-3242-73\",\"Cohabiting\"",    //wrong mstatus
        "\"Violet\",\"Elliott\",\"Male\",\"v.elliott@randatmail.com\",\"Cohabiting\"",                           //missing phone and age
        "\"Violet\",\"Elliott\",\"Male\",\"200\",\"v.elliott@randatmail.com\",\"896-3242-73\",\"Single\"",       //wrong age
        "\"Violet\",\"Elliott\",\"Male\",\"100\",\"v.elliott\",\"896-3242-73\",\"Single\"",                      //wrong mail
        "\"Violet\",\"Elliott\",\"Male\",\"100\",\"v.elliott@de.o\",\"896-3242-73\",\"Single\"",                 //wrong mail
        "\"Violet\",\"Elliott\",\"Male\",\"100\",\"@randatmail.com\",\"896-3242-73\",\"Single\"",                //wrong mail
        NULL
    };

    for(int i = 0; test_array[i] != NULL; i++) {
        amxc_string_setf(&data, test_array[i]);

        assert_int_equal(amxc_string_split_to_llist(&data, &fields, ','), 0);
        assert_int_equal(person_new(&person, &fields), -1);

        assert_null(person);

        amxc_string_reset(&data);
        amxc_llist_clean(&fields, amxc_string_list_it_free);
    }

    amxc_string_clean(&data);
}

void test_person_print(UNUSED void** state) {
    amxc_llist_t fields;
    amxc_string_t data;
    person_t* person = NULL;

    amxc_string_init(&data, 0);
    amxc_llist_init(&fields);

    const char* test_array[] = {
        "\"Violet\",\"Elliott\",\"Male\",\"25\",\"v.elliott@randatmail.com\",\"896-3242-73\",\"Single\"",
        "\"Violet\",\"Elliott\",\"Female\",\"25\",\"v.elliott@randatmail.com\",\"896-3242-73\",\"Married\"",
        NULL
    };

    for(int i = 0; test_array[i] != NULL; i++) {
        amxc_string_setf(&data, test_array[i]);

        assert_int_equal(amxc_string_split_to_llist(&data, &fields, ','), 0);
        assert_int_equal(person_new(&person, &fields), 0);
        assert_non_null(person);

        person_print(person);

        person_del(&person);
        assert_null(person);

        amxc_string_reset(&data);
        amxc_llist_clean(&fields, amxc_string_list_it_free);
    }

    amxc_string_clean(&data);
}