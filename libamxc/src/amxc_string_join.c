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
#include <string.h>
#include <ctype.h>

#include <amxc/amxc_variant.h>
#include <amxc/amxc_string_join.h>
#include <amxc/amxc_macros.h>

/**
   @file
   @brief
   Ambiorix string API implementation
 */

int amxc_string_join_llist(amxc_string_t* string,
                           const amxc_llist_t* list,
                           char separator) {
    int retval = -1;

    when_null(string, exit);
    when_null(list, exit);
    when_true(isalnum(separator) != 0, exit);
    when_true(separator == '[' || separator == ']', exit);

    if(isspace(separator) != 0) {
        separator = ' ';
    }

    amxc_llist_for_each(it, list) {
        amxc_string_t* part = amxc_string_from_llist_it(it);
        if(!amxc_string_is_empty(string)) {
            amxc_string_appendf(string, "%c", separator);
        }
        amxc_string_append(string,
                           amxc_string_get(part, 0),
                           amxc_string_text_length(part));
    }

    retval = 0;

exit:
    return retval;
}

int amxc_string_join_var_until(amxc_string_t* string,
                               const amxc_var_t* const var,
                               const char* separator,
                               const char* end,
                               bool remove) {
    int retval = -1;
    const amxc_llist_t* list = NULL;
    const char* sep = "";
    when_null(string, exit);
    when_null(var, exit);
    when_true(amxc_var_type_of(var) != AMXC_VAR_ID_LIST, exit);

    list = amxc_var_constcast(amxc_llist_t, var);

    amxc_llist_for_each(it, list) {
        amxc_var_t* part = amxc_var_from_llist_it(it);

        amxc_string_appendf(string, "%s", sep);

        if(amxc_var_type_of(part) == AMXC_VAR_ID_LIST) {
            amxc_string_append(string, "[", 1);
            amxc_string_csv_join_var(string, part);
            amxc_string_append(string, "]", 1);
        } else if((amxc_var_type_of(part) == AMXC_VAR_ID_CSTRING) ||
                  ( amxc_var_type_of(part) == AMXC_VAR_ID_CSV_STRING) ||
                  ( amxc_var_type_of(part) == AMXC_VAR_ID_SSV_STRING)) {
            const char* txt = amxc_var_constcast(cstring_t, part);
            if((txt != NULL) && (end != NULL) && (strcmp(txt, end) == 0)) {
                if(remove) {
                    amxc_var_delete(&part);
                }
                break;
            }
            amxc_string_appendf(string, "%s", txt);
        } else {
            char* txt = amxc_var_dyncast(cstring_t, part);
            if((txt != NULL) && (end != NULL) && (strcmp(txt, end) == 0)) {
                if(remove) {
                    amxc_var_delete(&part);
                }
                free(txt);
                break;
            }
            amxc_string_appendf(string, "%s", txt);
            free(txt);
        }
        if(remove) {
            amxc_var_delete(&part);
        }
        sep = separator;
    }

    retval = 0;

exit:
    return retval;

}

int amxc_string_join_var(amxc_string_t* string,
                         const amxc_var_t* const var,
                         const char* separator) {
    return amxc_string_join_var_until(string, var, separator, NULL, false);
}

int amxc_string_csv_join_var(amxc_string_t* string,
                             const amxc_var_t* const var) {
    return amxc_string_join_var(string, var, ",");
}

int amxc_string_ssv_join_var(amxc_string_t* string,
                             const amxc_var_t* const var) {
    return amxc_string_join_var(string, var, " ");
}
