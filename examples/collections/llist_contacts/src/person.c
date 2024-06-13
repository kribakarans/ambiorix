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

static void person_set_field(char** pfield, amxc_llist_t* fields) {
    amxc_llist_it_t* it = NULL;
    amxc_string_t* field = NULL;

    it = amxc_llist_take_first(fields);
    field = amxc_string_from_llist_it(it);
    // remove the leading and trailing " if any
    amxc_string_trim(field, is_quote);
    // take the string buffer from amxc_string_t
    // the amxc_string_t will be empty (no buffer) after this call
    *pfield = amxc_string_take_buffer(field);

    amxc_string_delete(&field);
}

static int person_set_email(char** pfield, amxc_llist_t* fields) {
    int retval = -1;
    amxc_llist_it_t* it = NULL;
    amxc_string_t* field = NULL;
    const char* email = NULL;
    uint16_t email_length = 0;
    uint16_t symbols_after_at = 0;
    uint16_t symbols_before_at = 0;
    bool at_present = false;

    it = amxc_llist_get_first(fields);
    field = amxc_string_from_llist_it(it);
    // get string from the amxc_string_t
    email = amxc_string_get(field, 0);
    email_length = amxc_string_text_length(field);

    for(int i = 1; i < email_length - 1; i++) {
        if(at_present == true) {
            symbols_after_at += 1;
        }
        if(email[i] == '@') {
            at_present = true;
        }
        if(at_present == false) {
            symbols_before_at += 1;
        }
    }

    //simple check to prevent wrong email adresses
    if((symbols_before_at < 1) || (symbols_after_at < 5) || (at_present == false)) {
        printf("ERROR: wrong email\n");
        amxc_string_delete(&field);
        goto exit;
    }

    person_set_field(pfield, fields);

    retval = 0;

exit:
    return retval;
}

static int person_set_gender(gender_t* gender, amxc_llist_t* fields) {
    int retval = -1;
    amxc_llist_it_t* it = NULL;
    amxc_string_t* field = NULL;

    it = amxc_llist_take_first(fields);
    field = amxc_string_from_llist_it(it);
    // remove the leading and trailing " if any
    amxc_string_trim(field, is_quote);

    // compare the content of the amxc_string_t with the string "Male"
    // if equal set the gender to the enum `male`
    // I known this is not completly politcally correct, we should also
    // consider X-gender
    if(strcmp(amxc_string_get(field, 0), "Male") == 0) {
        *gender = male;
    } else if(strcmp(amxc_string_get(field, 0), "Female") == 0) {
        *gender = female;
    } else {
        printf("ERROR: wrong gender\n");
        goto exit;
    }

    retval = 0;

exit:
    amxc_string_delete(&field);
    return retval;
}

static int person_set_age(uint32_t* age, amxc_llist_t* fields) {
    int retval = -1;
    amxc_llist_it_t* it = NULL;
    amxc_string_t* field = NULL;

    it = amxc_llist_take_first(fields);
    field = amxc_string_from_llist_it(it);
    // remove the leading and trailing " if any
    amxc_string_trim(field, is_quote);
    // convert the content of the amxc_string_t to a number
    // if it does not contain any number (at the start of the string)
    // atol will return 0 (atol is a standard C function)
    // in google search for "man atol"
    if(atol(amxc_string_get(field, 0)) > 130) {
        printf("ERROR: wrong age\n");
        goto exit;
    }
    *age = atol(amxc_string_get(field, 0));


    retval = 0;

exit:
    amxc_string_delete(&field);
    return retval;
}

static int person_set_mstatus(marital_status_t* mstatus, amxc_llist_t* fields) {
    int retval = -1;
    amxc_llist_it_t* it = NULL;
    amxc_string_t* field = NULL;

    it = amxc_llist_take_first(fields);
    field = amxc_string_from_llist_it(it);
    // remove the leading and trailing " if any
    amxc_string_trim(field, is_quote);

    // compare the content of the amxc_string_t with the string "Single"
    // if equal set the mstatus to the enum `single`
    // I known this is not completly politcally correct, we should also
    // consider people linging together but who are not married
    if(strcmp(amxc_string_get(field, 0), "Single") == 0) {
        *mstatus = single;
    } else if(strcmp(amxc_string_get(field, 0), "Married") == 0) {
        *mstatus = married;
    } else {
        printf("ERROR: wrong marital status\n");
        goto exit;
    }

    retval = 0;

exit:
    amxc_string_delete(&field);
    return retval;
}

int person_new(person_t** person, amxc_llist_t* fields) {
    int retval = -1;

    *person = (person_t*) calloc(1, sizeof(person_t));
    if(*person == NULL) {
        goto exit;
    }

    if(amxc_llist_size(fields) != 7) {
        printf("ERROR: information is missing\n");
        goto exit;
    }

    // the linked list fields contains all person fields in this order
    person_set_field(&(*person)->first_name, fields);
    person_set_field(&(*person)->last_name, fields);
    if(person_set_gender(&(*person)->gender, fields) != 0) {
        printf("ERROR: wrong gender for %s %s \n", (*person)->first_name, (*person)->last_name);
        goto exit;
    }
    if(person_set_age(&(*person)->age, fields) != 0) {
        printf("ERROR: wrong age for %s %s \n", (*person)->first_name, (*person)->last_name);
        goto exit;
    }
    if(person_set_email(&(*person)->email, fields) != 0) {
        printf("ERROR: wrong email for %s %s \n", (*person)->first_name, (*person)->last_name);
        goto exit;
    }
    person_set_field(&(*person)->phone, fields);
    if(person_set_mstatus(&(*person)->mstatus, fields) != 0) {
        printf("ERROR: wrong marital status for %s %s \n", (*person)->first_name, (*person)->last_name);
        goto exit;
    }

    retval = 0;

exit:
    if((retval != 0) && (*person != NULL)) {
        person_del(person);
    }
    return retval;
}

void person_del(person_t** person) {
    // Remove the struct from the linked list
    // If it was already removed nothing happens
    amxc_llist_it_take(&(*person)->it);

    // free all allocated memory.
    free((*person)->first_name);
    free((*person)->last_name);
    free((*person)->email);
    free((*person)->phone);

    free(*person);
    *person = NULL;
}

void person_print(person_t* person) {
    printf("Person : %s %s\n", person->first_name, person->last_name);

    switch(person->gender) {
    case male:
        printf("\tGender = Male\n");
        break;
    case female:
        printf("\tGender = Female\n");
        break;
    }

    printf("\tAge    = %d\n", person->age);
    printf("\tE-Mail = %s\n", person->email);
    printf("\tPhone  = %s\n", person->phone);
    switch(person->mstatus) {
    case single:
        printf("\tStatus = Single\n");
        break;
    case married:
        printf("\tStatus = Married\n");
        break;
    }
}