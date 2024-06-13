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

#include <amxc/amxc_hash.h>
#include <amxc/amxc_htable.h>
#include <amxc/amxc_macros.h>

/**
   @file
   @brief
   Ambiorix hash table iterator API implementation
 */

int amxc_htable_it_init(amxc_htable_it_t* const it) {
    int retval = -1;
    when_null(it, exit);

    it->ait = NULL;
    it->key = NULL;
    it->next = NULL;

    retval = 0;

exit:
    return retval;
}

void amxc_htable_it_clean(amxc_htable_it_t* const it, amxc_htable_it_delete_t func) {
    char* key = NULL;
    when_null(it, exit);

    // remove from htable if it is in one
    amxc_htable_it_take(it);
    key = it->key;
    it->key = NULL;
    if(func != NULL) {
        func(key, it);
    }

    free(key);

exit:
    return;
}

amxc_htable_it_t* amxc_htable_it_get_next(const amxc_htable_it_t* const reference) {
    amxc_htable_it_t* it = NULL;
    when_null(reference, exit);
    when_null(reference->ait, exit);

    if(reference->next != NULL) {
        it = reference->next;
    } else {
        amxc_array_it_t* ait = amxc_array_it_get_next(reference->ait);
        when_null(ait, exit);
        it = (amxc_htable_it_t*) ait->data;
    }

exit:
    return it;
}

amxc_htable_it_t* amxc_htable_it_get_previous(const amxc_htable_it_t* const reference) {
    amxc_htable_it_t* it = NULL;
    when_null(reference, exit);
    when_null(reference->ait, exit);

    if(reference->next != NULL) {
        it = reference->next;
    } else {
        amxc_array_it_t* ait = amxc_array_it_get_previous(reference->ait);
        when_null(ait, exit);
        it = (amxc_htable_it_t*) ait->data;
    }

exit:
    return it;
}

amxc_htable_it_t* amxc_htable_it_get_next_key(const amxc_htable_it_t* const reference) {
    amxc_htable_it_t* it = NULL;
    when_null(reference, exit);
    when_null(reference->ait, exit);

    it = reference->next;
    while(it != NULL && strcmp(it->key, reference->key) != 0) {
        it = it->next;
    }

exit:
    return it;
}

amxc_htable_it_t* amxc_htable_it_get_previous_key(const amxc_htable_it_t* const reference) {
    return amxc_htable_it_get_next_key(reference);
}

void amxc_htable_it_take(amxc_htable_it_t* const it) {
    amxc_htable_t* htable = NULL;
    when_null(it, exit);
    when_null(it->ait, exit);

    htable = (amxc_htable_t*) it->ait->array;
    if(it->ait->data != it) {
        amxc_htable_it_t* prev = (amxc_htable_it_t*) it->ait->data;
        while(prev->next != it) {
            prev = prev->next;
        }
        prev->next = it->next;
    } else {
        if(it->next != NULL) {
            amxc_array_it_set_data(it->ait, it->next);
            it->next = NULL;
        } else {
            amxc_array_it_take_data(it->ait);
        }
    }
    it->ait = NULL;
    it->next = NULL;
    htable->items--;

exit:
    return;
}
