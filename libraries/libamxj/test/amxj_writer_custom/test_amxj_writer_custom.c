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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <cmocka.h>

#include <yajl/yajl_gen.h>
#include <yajl/yajl_parse.h>

#include <amxc/amxc_string.h>
#include <amxc/amxc_variant_type.h>

#include <amxj/amxj_variant.h>
#include <variant_json_priv.h>

#include "test_amxj_writer_custom.h"

#include <amxc/amxc_macros.h>
#define AMXC_VAR_NAME_CONTACT "contact_t"
#define AMXC_VAR_ID_CONTACT amxc_var_get_type_id_from_name(AMXC_VAR_NAME_CONTACT)

typedef struct _contact_t {
    char name[128];
    uint64_t age;
} contact_t;

static int variant_contact_init(amxc_var_t* const var) {
    int retval = -1;
    contact_t* contact = calloc(1, sizeof(contact_t));
    when_null(contact, exit);

    var->data.data = contact;
    retval = 0;

exit:
    return retval;
}

static void variant_contact_delete(amxc_var_t* var) {
    contact_t* contact = (contact_t*) var->data.data;
    var->data.data = NULL;
    free(contact);
}

static int variant_contact_convert_to(amxc_var_t* const dest,
                                      const amxc_var_t* const src) {
    int retval = -1;
    yajl_gen generator = NULL;
    contact_t* contact = src->data.data;

    when_null(contact, exit);
    when_true(amxc_var_type_of(dest) != AMXC_VAR_ID_JSON, exit);
    generator = amxj_get_json_gen(dest);
    when_null(generator, exit);
    when_true(yajl_gen_map_open(generator) != yajl_gen_status_ok, exit);
    when_true(yajl_gen_string(generator,
                              (unsigned char*) "name",
                              4) != yajl_gen_status_ok, exit);
    when_true(yajl_gen_string(generator,
                              (unsigned char*) contact->name,
                              strlen(contact->name)) != yajl_gen_status_ok, exit);
    when_true(yajl_gen_string(generator,
                              (unsigned char*) "age",
                              3) != yajl_gen_status_ok, exit);
    when_true(yajl_gen_integer(generator,
                               contact->age) != yajl_gen_status_ok, exit);
    when_true(yajl_gen_map_close(generator) != yajl_gen_status_ok, exit);

    retval = 0;

exit:
    return retval;
}

static amxc_var_type_t variant_contact = {
    .init = variant_contact_init,
    .del = variant_contact_delete,
    .copy = NULL,
    .convert_from = NULL,
    .convert_to = variant_contact_convert_to,
    .compare = NULL,
    .get_key = NULL,
    .set_key = NULL,
    .name = AMXC_VAR_NAME_CONTACT
};

CONSTRUCTOR static void variant_contact_register(void) {
    amxc_var_register_type(&variant_contact);
}

DESTRUCTOR static void variant_contact_unregister(void) {
    amxc_var_unregister_type(&variant_contact);
}

void test_amxj_convert_custom_to_json(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t converted_var;
    contact_t* contact = NULL;
    const char* json_string = NULL;

    amxc_var_init(&var);
    amxc_var_init(&converted_var);

    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CONTACT), 0);
    contact = (contact_t*) var.data.data;
    assert_ptr_not_equal(contact, NULL);
    strcpy(contact->name, "John");
    contact->age = 40;

    assert_int_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&converted_var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&converted_var), AMXC_VAR_NAME_JSON);

    assert_ptr_not_equal(converted_var.data.data, NULL);
    json_string = amxc_var_constcast(jstring_t, &converted_var);
    assert_ptr_not_equal(json_string, NULL);

    amxc_var_clean(&var);
    amxc_var_clean(&converted_var);
}

void test_amxj_writer_write_contact_variant(UNUSED void** state) {
    variant_json_t* writer = NULL;
    amxc_var_t var;
    contact_t* contact = NULL;
    int fd = open("test_writer_custom.json", O_WRONLY | O_CREAT, 0644);

    amxc_var_init(&var);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CONTACT), 0);
    contact = (contact_t*) var.data.data;
    assert_ptr_not_equal(contact, NULL);
    strcpy(contact->name, "John");
    contact->age = 40;

    assert_int_equal(amxj_writer_new(&writer, &var), 0);
    assert_ptr_not_equal(writer, NULL);

    assert_int_not_equal(amxj_write(writer, fd), 0);

    amxj_writer_delete(&writer);
    assert_ptr_equal(writer, NULL);

    close(fd);
    amxc_var_clean(&var);
}
