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

int contacts_read(amxc_var_t* contacts, const char* file_name, int skip_lines) {
    int retval = -1;
    int line_counter = 0;
    FILE* fp;
    char* line = NULL;
    size_t len = 0;
    ssize_t read = 0;
    amxc_string_t csv_line;
    amxc_llist_t fields;
    amxc_var_t* person_data;

    amxc_string_init(&csv_line, 0);
    amxc_llist_init(&fields);
    fp = fopen(file_name, "r");
    if(fp == NULL) {
        goto exit;
    }

    read = getline(&line, &len, fp);
    while(read != -1) {
        if(line_counter < skip_lines) {
            line_counter++;
            read = getline(&line, &len, fp);
            continue;
        }
        amxc_string_push_buffer(&csv_line, line, len);

        // Split the line, which is a comma separated string of fields
        // The fields linked list will be filled with strings,
        if(amxc_string_split_to_llist(&csv_line, &fields, ',') != 0) {
            printf("ERROR: failed to add person @ line %d -- skipping this contact\n", line_counter + 1);
        } else if(person_new(&person_data, &fields) != 0) {
            printf("ERROR: failed to add person @ line %d -- skipping this contact\n", line_counter + 1);
        } else {
            contacts_add_person(contacts, person_data);
        }

        amxc_llist_clean(&fields, amxc_string_list_it_free);
        amxc_string_reset(&csv_line);
        line = NULL;
        len = 0;
        read = getline(&line, &len, fp);
        line_counter++;
    }

    retval = 0;

exit:
    if(fp != NULL) {
        fclose(fp);
    }
    free(line);
    amxc_llist_clean(&fields, amxc_string_list_it_free);
    amxc_string_clean(&csv_line);
    return retval;
}

void contacts_add_person(amxc_var_t* contacts, amxc_var_t* person) {
    const char* last_name = GET_CHAR(person, "last name");

    amxc_var_t* family = amxc_var_get_key(contacts, last_name, AMXC_VAR_FLAG_DEFAULT);
    if(family == NULL) {
        family = amxc_var_add_key(amxc_llist_t, contacts, last_name, NULL);
    }

    amxc_var_set_index(family, 0, person, AMXC_VAR_FLAG_DEFAULT);
}

amxc_var_t* contacts_search(amxc_var_t* contacts, const char* last_name) {
    amxc_var_t* family = amxc_var_get_path(contacts, last_name, AMXC_VAR_FLAG_DEFAULT);

    return family;
}
