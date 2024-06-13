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

#include <amxc/amxc_array.h>
#include <amxc/amxc_macros.h>

#define AMXC_ARRAY_AUTO_GROW_ITEMS 3
#define AMXC_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/**
   @file
   @brief
   Ambiorix array API implementation
 */

static void amxc_array_initialize_items(amxc_array_t* array, const size_t start_pos) {
    amxc_array_it_t* it = NULL;

    for(size_t index = start_pos; index < array->items; index++) {
        it = &(array->buffer[index]);
        it->array = array;
        it->data = NULL;
    }
}

static void amxc_array_clean_items(amxc_array_t* array,
                                   const size_t start_pos,
                                   const size_t items,
                                   amxc_array_it_delete_t func) {
    amxc_array_it_t* it = NULL;
    for(unsigned int index = start_pos; index < start_pos + items; index++) {
        it = &(array->buffer[index]);
        if(it->data != NULL) {
            if(func != NULL) {
                func(it);
            }
            it->data = NULL;
        }
    }

    return;
}

static int amxc_array_realloc(amxc_array_t* array, const size_t items) {
    int retval = -1;
    amxc_array_it_t* buffer = NULL;

    if(array->buffer != NULL) {
        buffer = (amxc_array_it_t*) realloc(array->buffer, sizeof(amxc_array_it_t) * items);
    } else {
        buffer = (amxc_array_it_t*) calloc(items, sizeof(amxc_array_it_t));
    }
    if(buffer != NULL) {
        array->buffer = buffer;
        array->items = items;
        retval = 0;
    }

    return retval;
}

static size_t amxc_array_calculate_last_used(amxc_array_t* array,
                                             const size_t start) {
    size_t index = start;
    while(index > 0 && array->buffer[index].data == NULL) {
        index--;
    }

    return index;
}

static size_t amxc_array_calculate_first_used(amxc_array_t* array,
                                              const size_t start) {
    size_t index = start;
    while(index < array->items && array->buffer[index].data == NULL) {
        index++;
    }

    return (index == array->items) ? 0 : index;
}

static int amxc_array_sort_internal(amxc_array_t* const array,
                                    amxc_array_it_cmp_t cmp,
                                    int32_t lo,
                                    int32_t high) {
    int retval = 0;
    int32_t i = lo + 1;
    int32_t j = high;

    while(i <= j) {
        while(i <= high &&
              cmp(&array->buffer[i], &array->buffer[lo]) <= 0 &&
              i <= j) {
            i++;
        }
        while(j >= lo &&
              cmp(&array->buffer[j], &array->buffer[lo]) > 0 &&
              i <= j) {
            j--;
        }
        if(i <= j) {
            amxc_array_it_swap(&array->buffer[i], &array->buffer[j]);
        }
    }
    amxc_array_it_swap(&array->buffer[lo], &array->buffer[j]);

    if(j - 1 - lo > 1) {
        amxc_array_sort_internal(array, cmp, lo, j - 1);
    } else {
        if(cmp(&array->buffer[lo], &array->buffer[lo + 1]) > 0) {
            amxc_array_it_swap(&array->buffer[lo], &array->buffer[lo + 1]);
        }
    }
    if(high - (j + 1) > 1) {
        amxc_array_sort_internal(array, cmp, j + 1, high);
    } else {
        if(cmp(&array->buffer[high - 1], &array->buffer[high]) > 0) {
            amxc_array_it_swap(&array->buffer[high - 1], &array->buffer[high]);
        }
    }

    return retval;
}

int8_t amxc_array_new(amxc_array_t** array, const size_t items) {
    int8_t retval = -1;
    when_null(array, exit);

    /* allocate the array structure */
    *array = (amxc_array_t*) calloc(1, sizeof(amxc_array_t));
    when_null(*array, exit);

    /* set the number of items in the array */
    (*array)->items = items;
    (*array)->first_used = 0;
    (*array)->last_used = 0;

    /* if no items need to be pre-allocated, leave */
    if(items == 0) {
        retval = 0;
        goto exit;
    }

    /* allocate the buffer */
    amxc_array_realloc(*array, items);
    if((*array)->buffer == NULL) {
        free(*array);
        *array = NULL;
        goto exit;
    }
    amxc_array_initialize_items(*array, 0);

    retval = 0;

exit:
    return retval;
}

void amxc_array_delete(amxc_array_t** array, amxc_array_it_delete_t func) {
    when_null(array, exit);
    when_null(*array, exit);

    if(func != NULL) {
        // When no delete callback function is given,
        // it is not needed to call the clean items.
        amxc_array_clean_items(*array, 0, (*array)->items, func);
    }

    free((*array)->buffer);
    free(*array);
    *array = NULL;

exit:
    return;
}

int amxc_array_init(amxc_array_t* const array, const size_t items) {
    int retval = -1;
    when_null(array, exit);

    // initialize array data
    array->items = 0;
    array->buffer = NULL;
    array->first_used = 0;
    array->last_used = 0;

    // if no items need to be pre-allocated, leave
    if(items == 0) {
        retval = 0;
        goto exit;
    }

    // allocate the buffer
    amxc_array_realloc(array, items);
    when_null(array->buffer, exit);

    // set the allocated size
    array->items = items;
    amxc_array_initialize_items(array, 0);

    retval = 0;

exit:
    return retval;
}

void amxc_array_clean(amxc_array_t* const array, amxc_array_it_delete_t func) {
    when_null(array, exit);

    if(func != NULL) {
        // When no delete callback function is given,
        // it is not needed to call the clean items.
        amxc_array_clean_items(array, 0, array->items, func);
    }

    free(array->buffer);
    array->buffer = NULL;
    array->items = 0;
    array->first_used = 0;
    array->last_used = 0;

exit:
    return;
}

int amxc_array_grow(amxc_array_t* const array, const size_t items) {
    int retval = -1;
    size_t old_items = 0;
    when_null(array, exit);

    if(items == 0) {
        retval = 0;
        goto exit;
    }

    old_items = array->items;
    retval = amxc_array_realloc(array, array->items + items);
    amxc_array_initialize_items(array, old_items);

exit:
    return retval;
}

int amxc_array_shrink(amxc_array_t* const array,
                      const size_t items,
                      amxc_array_it_delete_t func) {
    int retval = -1;
    when_null(array, exit);
    when_true(items > array->items, exit); // out of range

    if(items == array->items) {
        amxc_array_clean(array, func);

        retval = 0;
        goto exit;
    }

    amxc_array_clean_items(array, array->items - items, items, func);
    retval = amxc_array_realloc(array, array->items - items);
    array->last_used = amxc_array_calculate_last_used(array, array->items - 1);
    if(array->first_used > array->items - 1) {
        array->first_used = 0;
    }

exit:
    return retval;
}

int amxc_array_shift_right(amxc_array_t* const array,
                           const size_t items,
                           amxc_array_it_delete_t func) {
    int retval = -1;
    amxc_array_it_t* src = NULL;
    amxc_array_it_t* dst = NULL;
    size_t len = 0;
    when_null(array, exit);
    when_true(items > array->items, exit);

    if(!items) {
        retval = 0;
        goto exit;
    }

    if(items == array->items) {
        amxc_array_clean_items(array, 0, array->items, func);
        array->last_used = 0;
        array->first_used = 0;
        retval = 0;
        goto exit;
    }

    src = array->buffer;
    dst = &array->buffer[items];
    len = (array->items - items) * sizeof(amxc_array_it_t);

    memmove(dst, src, len);
    amxc_array_clean_items(array, 0, items, func);
    array->first_used = amxc_array_calculate_first_used(array, items);
    array->last_used = amxc_array_calculate_last_used(array, array->items - 1);

    retval = 0;

exit:
    return retval;
}

int amxc_array_shift_left(amxc_array_t* const array,
                          const size_t items,
                          amxc_array_it_delete_t func) {
    int retval = -1;
    amxc_array_it_t* src = NULL;
    amxc_array_it_t* dst = NULL;
    size_t len = 0;
    when_null(array, exit);
    when_true(items > array->items, exit);

    if(!items) {
        retval = 0;
        goto exit;
    }

    if(items == array->items) {
        amxc_array_clean_items(array, 0, array->items, func);
        retval = 0;
        array->last_used = 0;
        array->first_used = 0;
        goto exit;
    }

    src = &array->buffer[items];
    dst = array->buffer;
    len = (array->items - items) * sizeof(amxc_array_it_t);

    memmove(dst, src, len);
    amxc_array_clean_items(array, array->items - items, items, func);
    array->first_used = amxc_array_calculate_first_used(array, 0);
    array->last_used = amxc_array_calculate_last_used(array, array->items - items);

    retval = 0;

exit:
    return retval;
}

bool amxc_array_is_empty(const amxc_array_t* const array) {
    bool retval = true;
    when_null(array, exit);

    if(array->last_used != 0) {
        retval = false;
    }

    if((array->buffer != NULL) && (array->buffer[0].data != NULL)) {
        retval = false;
    }

exit:
    return retval;
}

size_t amxc_array_size(const amxc_array_t* const array) {
    size_t retval = 0;
    when_null(array, exit);

    for(size_t index = 0; index < array->items; index++) {
        if(array->buffer[index].data != NULL) {
            retval++;
        }
    }

exit:
    return retval;
}

amxc_array_it_t* amxc_array_append_data(amxc_array_t* const array, void* data) {
    amxc_array_it_t* it = NULL;
    size_t index = 0;
    when_null(array, exit);
    when_null(data, exit);

    if(!amxc_array_is_empty(array)) {
        index = array->last_used + 1;
    }

    if(index >= array->items) {
        when_failed(amxc_array_grow(array, AMXC_ARRAY_AUTO_GROW_ITEMS), exit)
    }

    it = amxc_array_set_data_at(array, index, data);

exit:
    return it;
}

amxc_array_it_t* amxc_array_prepend_data(amxc_array_t* const array, void* data) {
    amxc_array_it_t* it = NULL;
    size_t index = 0;
    bool grow = false;
    when_null(array, exit);
    when_null(data, exit);

    grow = ((!amxc_array_is_empty(array) && array->first_used == 0) ||
            (array->buffer == NULL));

    if(grow) {
        when_failed(amxc_array_grow(array, AMXC_ARRAY_AUTO_GROW_ITEMS), exit);
        amxc_array_shift_right(array, AMXC_ARRAY_AUTO_GROW_ITEMS, NULL);
    }

    if(!amxc_array_is_empty(array)) {
        index = array->first_used - 1;
    }

    it = amxc_array_set_data_at(array, index, data);

exit:
    return it;
}

amxc_array_it_t* amxc_array_set_data_at(amxc_array_t* const array,
                                        const unsigned int index,
                                        void* data) {
    amxc_array_it_t* it = amxc_array_get_at(array, index);
    when_null(it, exit);

    if(data != NULL) {
        if(amxc_array_is_empty(array)) {
            array->last_used = index;
            array->first_used = index;
        } else {
            array->last_used = (array->last_used < index) ? index : array->last_used;
            array->first_used = (array->first_used > index) ? index : array->first_used;
        }
        it->data = data;
    } else {
        void* tmp = it->data;
        it->data = data;
        if((tmp != NULL) && (index == array->last_used)) {
            array->last_used = amxc_array_calculate_last_used(array, array->last_used);
        }
        if((tmp != NULL) && (index == array->first_used)) {
            array->first_used = amxc_array_calculate_first_used(array, array->first_used);
        }
    }

exit:
    return it;
}

amxc_array_it_t* amxc_array_get_at(const amxc_array_t* const array,
                                   const unsigned int index) {
    amxc_array_it_t* it = NULL;
    when_null(array, exit);
    when_null(array->buffer, exit);
    when_true(index >= array->items, exit);

    it = &array->buffer[index];

exit:
    return it;
}

amxc_array_it_t* amxc_array_get_first(const amxc_array_t* const array) {
    amxc_array_it_t* it = NULL;
    when_null(array, exit);

    if(!amxc_array_is_empty(array)) {
        it = &array->buffer[array->first_used];
    }

exit:
    return it;
}

amxc_array_it_t* amxc_array_get_first_free(const amxc_array_t* const array) {
    amxc_array_it_t* it = NULL;
    size_t index = 0;
    when_null(array, exit);

    while(index < array->items && array->buffer[index].data != NULL) {
        index++;
    }

    if(index < array->items) {
        it = &array->buffer[index];
    }

exit:
    return it;
}

amxc_array_it_t* amxc_array_get_last(const amxc_array_t* const array) {
    amxc_array_it_t* it = NULL;
    when_null(array, exit);

    if(!amxc_array_is_empty(array)) {
        it = &array->buffer[array->last_used];
    }

exit:
    return it;
}

amxc_array_it_t* amxc_array_get_last_free(const amxc_array_t* const array) {
    amxc_array_it_t* it = NULL;
    size_t index = 0;
    when_null(array, exit);

    index = array->items;
    while(index > 0 && array->buffer[index - 1].data != NULL) {
        index--;
    }

    if(index > 0) {
        it = &array->buffer[index - 1];
    }

exit:
    return it;
}

void* amxc_array_take_first_data(amxc_array_t* const array) {
    void* data = NULL;
    amxc_array_it_t* it = amxc_array_get_first(array);
    if(it != NULL) {
        data = it->data;
        amxc_array_set_data_at(array, amxc_array_it_index(it), NULL);
    }
    return data;
}

void* amxc_array_take_last_data(amxc_array_t* const array) {
    void* data = NULL;
    amxc_array_it_t* it = amxc_array_get_last(array);
    if(it != NULL) {
        data = it->data;
        amxc_array_set_data_at(array, amxc_array_it_index(it), NULL);
    }
    return data;
}

int amxc_array_sort(amxc_array_t* const array, amxc_array_it_cmp_t cmp) {
    int retval = -1;
    size_t i = 0;
    when_null(array, exit);
    when_null(cmp, exit);

    if(array->last_used == 0) {
        retval = 0;
        goto exit;
    }
    i = array->last_used;
    do {
        i--;
        if(array->buffer[i].data == NULL) {
            amxc_array_it_swap(&array->buffer[i],
                               &array->buffer[array->last_used]);
            array->last_used--;
        }
    } while(i != 0);

    retval = amxc_array_sort_internal(array, cmp, 0, array->last_used);

exit:
    return retval;
}