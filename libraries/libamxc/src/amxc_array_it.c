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

#include <amxc/amxc_array.h>
#include <amxc/amxc_macros.h>

/**
   @file
   @brief
   Ambiorix array iterator API implementation
 */

amxc_array_it_t* amxc_array_it_get_next(const amxc_array_it_t* const reference) {
    amxc_array_it_t* it = NULL;
    amxc_array_t* array = NULL;
    size_t pos = 0;
    when_null(reference, exit);

    array = reference->array;
    pos = (reference - array->buffer);
    pos++;
    while(pos < array->items && !array->buffer[pos].data) {
        pos++;
    }

    if(pos < array->items) {
        it = &array->buffer[pos];
    }

exit:
    return it;
}

amxc_array_it_t* amxc_array_it_get_next_free(const amxc_array_it_t* const reference) {
    amxc_array_it_t* it = NULL;
    amxc_array_t* array = NULL;
    size_t pos = 0;
    when_null(reference, exit);

    array = reference->array;
    pos = (reference - array->buffer);
    pos++;
    while(pos < array->items && array->buffer[pos].data != NULL) {
        pos++;
    }

    if(pos < array->items) {
        it = &array->buffer[pos];
    }

exit:
    return it;
}

amxc_array_it_t* amxc_array_it_get_previous(const amxc_array_it_t* const reference) {
    amxc_array_it_t* it = NULL;
    amxc_array_t* array = NULL;
    size_t pos = 0;
    when_null(reference, exit);

    array = reference->array;
    pos = (reference - array->buffer);
    while(pos > 0 && !array->buffer[pos - 1].data) {
        pos--;
    }

    if(pos > 0) {
        it = &array->buffer[pos - 1];
    }

exit:
    return it;
}

amxc_array_it_t* amxc_array_it_get_previous_free(const amxc_array_it_t* const reference) {
    amxc_array_it_t* it = NULL;
    amxc_array_t* array = NULL;
    size_t pos = 0;
    when_null(reference, exit);

    array = reference->array;
    pos = (reference - array->buffer);
    while(pos > 0 && array->buffer[pos - 1].data != NULL) {
        pos--;
    }

    if((pos > 0) && !array->buffer[pos - 1].data) {
        it = &array->buffer[pos - 1];
    }

exit:
    return it;
}

unsigned int amxc_array_it_index(const amxc_array_it_t* const it) {
    size_t index = 0;
    when_null(it, exit);

    index = it - it->array->buffer;

exit:
    return index;
}

int amxc_array_it_set_data(amxc_array_it_t* const it, void* data) {
    int retval = -1;
    unsigned int index = 0;
    amxc_array_t* array = NULL;

    when_null(it, exit);
    when_null(data, exit);

    index = amxc_array_it_index(it);
    array = it->array;
    it->data = data;
    if((index < array->first_used) ||
       ((array->first_used == 0) && (array->buffer[0].data == NULL))) {
        array->first_used = index;
    }
    if(index > array->last_used) {
        array->last_used = index;
    }

    retval = 0;

exit:
    return retval;
}

void* amxc_array_it_take_data(amxc_array_it_t* it) {
    void* data = NULL;
    unsigned int index = 0;
    amxc_array_t* array = NULL;

    when_null(it, exit);
    when_null(it->data, exit);

    index = amxc_array_it_index(it);
    array = it->array;

    data = it->data;
    it->data = NULL;

    if(index == array->first_used) {
        it = amxc_array_it_get_next(it);
        if(it == NULL) {
            array->first_used = 0;
        } else {
            array->first_used = amxc_array_it_index(it);
        }
    }
    if(index == array->last_used) {
        it = amxc_array_it_get_previous(it);
        if(it == NULL) {
            array->last_used = 0;
        } else {
            array->last_used = amxc_array_it_index(it);
        }
    }

exit:
    return data;
}

int amxc_array_it_swap(amxc_array_it_t* const it1,
                       amxc_array_it_t* const it2) {
    int retval = -1;
    void* data = NULL;

    when_null(it1, exit);
    when_null(it2, exit);

    data = it1->data;
    it1->data = it2->data;
    it2->data = data;

exit:
    return retval;
}
