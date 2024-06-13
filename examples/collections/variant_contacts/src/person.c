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

#include "contacts.h"

static int is_quote(int c) {
    if(c == '"') {
        return 1;
    }

    return 0;
}

static void person_set_field(amxc_var_t* person, const char* fname, amxc_llist_t* fields) {
    amxc_llist_it_t* it = NULL;
    amxc_string_t* field = NULL;

    it = amxc_llist_take_first(fields);
    field = amxc_string_from_llist_it(it);
    // remove the leading and trailing " if any
    amxc_string_trim(field, is_quote);

    amxc_var_add_key(cstring_t, person, fname, amxc_string_get(field, 0));

    amxc_string_delete(&field);
}

int person_new(amxc_var_t** person, amxc_llist_t* fields) {
    int retval = -1;
    amxc_var_new(person);
    if(*person == NULL) {
        goto exit;
    }
    amxc_var_set_type(*person, AMXC_VAR_ID_HTABLE);

    // the linked list fields contains all person fields in this order
    person_set_field(*person, "first name", fields);
    person_set_field(*person, "last name", fields);
    person_set_field(*person, "gender", fields);
    person_set_field(*person, "age", fields);
    person_set_field(*person, "email", fields);
    person_set_field(*person, "phone", fields);
    person_set_field(*person, "mstatus", fields);

    retval = 0;

exit:
    if((retval != 0) && (*person != NULL)) {
        amxc_var_delete(person);
    }
    return retval;
}