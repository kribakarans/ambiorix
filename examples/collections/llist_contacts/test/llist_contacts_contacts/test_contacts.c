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
#include "test_contacts.h"

#define UNUSED __attribute__((unused))

void test_contacts_read(UNUSED void** state) {
    amxc_llist_t contacts;
    contacts_init(&contacts);
    assert_int_equal(contacts_read(&contacts, "data/randomdata_valid.csv", 1), 0);
    contacts_clean(&contacts);
}

void test_contacts_read_invalid_data(UNUSED void** state) {
    amxc_llist_t contacts;
    contacts_init(&contacts);

    assert_int_equal(contacts_read(&contacts, "data/randomdata_invalid.csv", 1), 0); //should pass with warning
    contacts_clean(&contacts);

    assert_int_equal(contacts_read(&contacts, "data/this_file_does_not_exist.csv", 1), -1); //should fail
    contacts_clean(&contacts);
}

void test_contacts_search(UNUSED void** state) {
    amxc_llist_t contacts;
    person_t* person = NULL;

    contacts_init(&contacts);
    assert_int_equal(contacts_read(&contacts, "data/randomdata_valid.csv", 1), 0);
    assert_int_equal(contacts_search(&contacts, "Harris", &person), 0);

    assert_string_equal(person->first_name, "Dainton");
    assert_string_equal(person->last_name, "Harris");
    assert_int_equal(person->gender, male);
    assert_int_equal(person->age, 21);
    assert_string_equal(person->email, "d.harris@randatmail.com");
    assert_string_equal(person->phone, "116-4182-47");
    assert_int_equal(person->mstatus, single);

    assert_int_equal(contacts_search(&contacts, "Trump", &person), -1); //person not in list
    assert_null(person);
    contacts_clean(&contacts);

    assert_int_equal(contacts_read(&contacts, "data/randomdata_invalid.csv", 1), 0);
    assert_int_equal(contacts_search(&contacts, "Cole", &person), -1); //person should not be in list not in list
    contacts_clean(&contacts);
}

void test_contacts_search_family(UNUSED void** state) {
    amxc_llist_t contacts;
    person_t* person = NULL;
    contacts_init(&contacts);
    assert_int_equal(contacts_read(&contacts, "data/randomdata_valid.csv", 1), 0);

    assert_int_equal(contacts_search(&contacts, "Elliott", &person), 0);

    assert_string_equal(person->first_name, "Violet");
    assert_string_equal(person->last_name, "Elliott");
    assert_int_equal(person->gender, female);
    assert_int_equal(person->age, 25);
    assert_string_equal(person->email, "v.elliott@randatmail.com");
    assert_string_equal(person->phone, "896-3242-73");
    assert_int_equal(person->mstatus, married);

    assert_int_equal(contacts_search(&contacts, "Elliott", &person), 0);

    assert_string_equal(person->first_name, "James");
    assert_string_equal(person->last_name, "Elliott");
    assert_int_equal(person->gender, male);
    assert_int_equal(person->age, 23);
    assert_string_equal(person->email, "j.elliott@randatmail.com");
    assert_string_equal(person->phone, "412-8887-99");
    assert_int_equal(person->mstatus, married);

    contacts_clean(&contacts);
}