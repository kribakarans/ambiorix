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

static bool amxc_llist_it_are_adjacent(amxc_llist_it_t* const it1,
                                       amxc_llist_it_t* const it2) {
    return (it1->next == it2);
}

static void amxc_llist_it_update(amxc_llist_it_t* const it) {
    if(it->prev == NULL) {
        if(it->llist != NULL) {
            it->llist->head = it;
        }
    } else {
        it->prev->next = it;
    }

    if(it->next == NULL) {
        if(it->llist != NULL) {
            it->llist->tail = it;
        }
    } else {
        it->next->prev = it;
    }
}

/**
   @file
   @brief
   Ambiorix linked list iterator API implementation
 */

int amxc_llist_it_init(amxc_llist_it_t* const it) {
    int retval = -1;
    when_null(it, exit);

    it->next = NULL;
    it->prev = NULL;
    it->llist = NULL;

    retval = 0;

exit:
    return retval;
}

void amxc_llist_it_clean(amxc_llist_it_t* const it, amxc_llist_it_delete_t func) {
    amxc_llist_it_take(it);
    if((it != NULL) && (func != NULL)) {
        func(it);
    }
}

void amxc_llist_it_take(amxc_llist_it_t* const it) {
    when_null(it, exit);
    when_null(it->llist, exit);

    if(it->prev != NULL) {
        it->prev->next = it->next;
    } else {
        it->llist->head = it->next;
    }
    if(it->next != NULL) {
        it->next->prev = it->prev;
    } else {
        it->llist->tail = it->prev;
    }

    it->next = NULL;
    it->prev = NULL;
    it->llist = NULL;
exit:
    return;
}

int amxc_llist_it_insert_before(amxc_llist_it_t* const reference,
                                amxc_llist_it_t* const it) {
    int retval = -1;
    when_null(reference, exit);
    when_null(it, exit);
    when_null(reference->llist, exit);

    amxc_llist_it_take(it);

    it->next = reference;
    it->prev = reference->prev;
    it->llist = reference->llist;
    reference->prev = it;

    if(it->prev != NULL) {
        it->prev->next = it;
    } else {
        it->llist->head = it;
    }

    retval = 0;
exit:
    return retval;
}

int amxc_llist_it_insert_after(amxc_llist_it_t* const reference,
                               amxc_llist_it_t* const it) {
    int retval = -1;
    when_null(reference, exit);
    when_null(it, exit);
    when_null(reference->llist, exit);

    amxc_llist_it_take(it);

    it->next = reference->next;
    it->prev = reference;
    it->llist = reference->llist;
    reference->next = it;

    if(it->next != NULL) {
        it->next->prev = it;
    } else {
        it->llist->tail = it;
    }

    retval = 0;
exit:
    return retval;
}

unsigned int amxc_llist_it_index_of(const amxc_llist_it_t* const it) {
    size_t index = 0;
    const amxc_llist_it_t* pos = NULL;
    if((it == NULL) || (it->llist == NULL)) {
        index = AMXC_LLIST_RANGE;
        goto exit;
    }

    pos = it;
    while(pos->prev) {
        index++;
        pos = pos->prev;
    }

exit:
    return index;
}

int amxc_llist_it_swap(amxc_llist_it_t* it1,
                       amxc_llist_it_t* it2) {
    int retval = -1;
    amxc_llist_it_t* swapperVector[4] = { NULL, NULL, NULL, NULL };

    when_null(it1, exit);
    when_null(it2, exit);

    if(it1 == it2) {
        retval = 0;
        goto exit;
    }

    if(it1->llist != it2->llist) {
        amxc_llist_t* temp = it1->llist;
        it1->llist = it2->llist;
        it2->llist = temp;
    }

    if(it2->next == it1) {
        amxc_llist_it_t* temp = it1;
        it1 = it2;
        it2 = temp;
    }

    swapperVector[0] = it1->prev;
    swapperVector[1] = it2->prev;
    swapperVector[2] = it1->next;
    swapperVector[3] = it2->next;

    if(amxc_llist_it_are_adjacent(it1, it2)) {
        it1->prev = swapperVector[2];
        it2->prev = swapperVector[0];
        it1->next = swapperVector[3];
        it2->next = swapperVector[1];
    } else {
        it1->prev = swapperVector[1];
        it2->prev = swapperVector[0];
        it1->next = swapperVector[3];
        it2->next = swapperVector[2];
    }

    amxc_llist_it_update(it1);
    amxc_llist_it_update(it2);

    retval = 0;

exit:
    return retval;
}