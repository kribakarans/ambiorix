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

#include <amxc/amxc_llist.h>
#include <amxc/amxc_macros.h>

/**
   @file
   @brief
   Ambiorix linked list API implementation
 */

static int amxc_llist_sort_internal(amxc_llist_t* const llist,
                                    amxc_llist_it_cmp_t cmp) {
    int retval = 0;
    bool swapped = false;

    do {
        amxc_llist_it_t* it = amxc_llist_get_first(llist);
        swapped = false;

        while(it != NULL && it->next != NULL) {
            if(cmp(it, it->next) > 0) {
                amxc_llist_it_swap(it, it->next);
                swapped = true;
            } else {
                it = it->next;
            }
        }
    } while(swapped);

    return retval;
}

int amxc_llist_new(amxc_llist_t** llist) {
    int retval = -1;
    when_null(llist, exit);

    *llist = (amxc_llist_t*) calloc(1, sizeof(amxc_llist_t));
    when_null(*llist, exit);

    retval = 0;

exit:
    return retval;
}

void amxc_llist_delete(amxc_llist_t** llist, amxc_llist_it_delete_t func) {
    when_null(llist, exit);

    amxc_llist_clean(*llist, func);
    free(*llist);
    *llist = NULL;
exit:
    return;
}

int amxc_llist_init(amxc_llist_t* const llist) {
    int retval = -1;
    when_null(llist, exit);

    llist->head = NULL;
    llist->tail = NULL;

    retval = 0;

exit:
    return retval;
}

void amxc_llist_clean(amxc_llist_t* const llist, amxc_llist_it_delete_t func) {
    amxc_llist_it_t* it = llist != NULL ? llist->head : NULL;
    while(it != NULL) {
        amxc_llist_it_take(it);
        if(func != NULL) {
            func(it);
        }
        it = llist->head;
    }
}

int amxc_llist_move(amxc_llist_t* const dest, amxc_llist_t* const src) {
    int retval = -1;

    when_null(dest, exit);
    when_null(src, exit);

    amxc_llist_for_each(it, src) {
        amxc_llist_append(dest, it);
    }

    retval = 0;

exit:
    return retval;
}

size_t amxc_llist_size(const amxc_llist_t* const llist) {
    size_t count = 0;

    // no check on null pointer is needed here.
    // amxc_llist_first will return null anyway.
    for(amxc_llist_it_t* it = llist != NULL ? llist->head : NULL;
        it != NULL;
        it = it->next) {
        count++;
    }

    return count;
}

bool amxc_llist_is_empty(const amxc_llist_t* const llist) {
    return llist != NULL ? (llist->head == NULL) : true;
}

int amxc_llist_append(amxc_llist_t* const llist, amxc_llist_it_t* const it) {
    int retval = -1;
    when_null(llist, exit);
    when_null(it, exit);

    if(it->llist != NULL) {
        amxc_llist_it_take(it);
    }

    it->llist = llist;
    it->prev = llist->tail;
    it->next = NULL;

    if(llist->tail != NULL) {
        llist->tail->next = it;
        llist->tail = it;
    } else {
        llist->tail = it;
        llist->head = it;
    }

    retval = 0;

exit:
    return retval;
}

int amxc_llist_prepend(amxc_llist_t* const llist, amxc_llist_it_t* const it) {
    int retval = -1;
    when_null(llist, exit);
    when_null(it, exit);

    if(it->llist != NULL) {
        amxc_llist_it_take(it);
    }

    it->llist = llist;
    it->next = llist->head;
    it->prev = NULL;

    if(llist->head != NULL) {
        llist->head->prev = it;
        llist->head = it;
    } else {
        llist->tail = it;
        llist->head = it;
    }

    retval = 0;
exit:
    return retval;
}

amxc_llist_it_t* amxc_llist_get_at(const amxc_llist_t* const llist,
                                   const unsigned int index) {
    amxc_llist_it_t* it = NULL;
    size_t count = 0;

    for(it = llist != NULL ? llist->head : NULL; it; it = it->next) {
        if(count == index) {
            break;
        }
        count++;
    }

    return it;
}

int amxc_llist_set_at(amxc_llist_t* const llist,
                      const unsigned int index,
                      amxc_llist_it_t* const it) {
    int retval = -1;
    amxc_llist_it_t* reference = NULL;

    size_t count = 0;

    for(reference = llist != NULL ? llist->head : NULL;
        reference;
        reference = reference->next) {
        if(count == index) {
            break;
        }
        count++;
    }

    if(!reference && (index == count)) {
        retval = amxc_llist_append(llist, it);
    } else {
        retval = amxc_llist_it_insert_before(reference, it);
    }
    return retval;
}

int amxc_llist_sort(amxc_llist_t* const llist, amxc_llist_it_cmp_t cmp) {
    int retval = -1;
    when_null(llist, exit);
    when_null(cmp, exit);

    if(amxc_llist_is_empty(llist)) {
        retval = 0;
        goto exit;
    }

    retval = amxc_llist_sort_internal(llist, cmp);

exit:
    return retval;
}