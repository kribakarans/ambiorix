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
#include <unistd.h>

#include <amxc/amxc_rbuffer.h>
#include <amxc/amxc_macros.h>

static char* amxc_rbuffer_alloc(amxc_rbuffer_t* const rb, const size_t size) {
    char* buffer = NULL;
    if(rb->buffer_start == NULL) {
        buffer = (char*) calloc(1, size);
    } else {
        buffer = (char*) realloc(rb->buffer_start, size);
    }

    return buffer;
}

/**
   @file
   @brief
   Ambiorix ring buffer API implementation
 */

int amxc_rbuffer_new(amxc_rbuffer_t** rb, const size_t size) {
    int retval = -1;
    when_null(rb, exit);

    *rb = (amxc_rbuffer_t*) calloc(1, sizeof(amxc_rbuffer_t));
    when_null(*rb, exit);

    retval = amxc_rbuffer_init(*rb, size);
    if(retval == -1) {
        free(*rb);
        *rb = NULL;
    }

exit:
    return retval;
}

void amxc_rbuffer_delete(amxc_rbuffer_t** rb) {
    when_null(rb, exit);

    amxc_rbuffer_clean(*rb);
    free(*rb);
    *rb = NULL;

exit:
    return;
}

int amxc_rbuffer_init(amxc_rbuffer_t* const rb, const size_t size) {
    int retval = -1;
    when_null(rb, exit);

    rb->buffer_start = NULL;
    rb->buffer_end = NULL;
    rb->read_pos = NULL;
    rb->write_pos = NULL;

    if(size == 0) {
        retval = 0;
        goto exit;
    }

    rb->buffer_start = amxc_rbuffer_alloc(rb, size);
    when_null(rb->buffer_start, exit);

    rb->buffer_end = rb->buffer_start + size;
    rb->read_pos = rb->buffer_start;
    rb->write_pos = rb->buffer_start;

    retval = 0;

exit:
    return retval;
}

void amxc_rbuffer_clean(amxc_rbuffer_t* const rb) {
    when_null(rb, exit);

    free(rb->buffer_start);
    rb->buffer_start = NULL;
    rb->buffer_end = NULL;
    rb->read_pos = NULL;
    rb->write_pos = NULL;

exit:
    return;
}

int amxc_rbuffer_grow(amxc_rbuffer_t* const rb, const size_t size) {
    int retval = -1;
    size_t read_pos = 0;
    size_t write_pos = 0;
    size_t new_size = 0;
    char* new_buffer = NULL;

    when_null(rb, exit);

    read_pos = rb->read_pos - rb->buffer_start;
    write_pos = rb->write_pos - rb->buffer_start;

    new_size = (rb->buffer_end - rb->buffer_start) + size;
    new_buffer = amxc_rbuffer_alloc(rb, new_size);
    if(!new_buffer) {
        goto exit;
    }

    rb->buffer_start = new_buffer;
    rb->buffer_end = rb->buffer_start + new_size;
    rb->read_pos = rb->buffer_start + read_pos;
    rb->write_pos = rb->buffer_start + write_pos;

    // if the read pointer is after the write pointer,
    // the read pointer must be move the number of bytes
    // the buffer has grown, and the data has to be moved
    if(rb->read_pos > rb->write_pos) {
        memmove(rb->buffer_start + read_pos + size,
                rb->buffer_start + read_pos,
                size);
        memset(rb->buffer_start + read_pos, 0, size);
        rb->read_pos += size;
    } else {
        memset(rb->buffer_start + write_pos, 0, size);
    }

    retval = 0;

exit:
    return retval;
}

// TODO: this function needs refactorying/splitting up - too long
int amxc_rbuffer_shrink(amxc_rbuffer_t* const rb, const size_t size) {
    int retval = -1;
    size_t buffer_size = 0;
    size_t new_size = 0;
    size_t read_pos = 0;
    size_t write_pos = 0;
    char* new_buffer = NULL;
    when_null(rb, exit);

    buffer_size = rb->buffer_end - rb->buffer_start;
    when_true(size > buffer_size, exit);

    if(size == buffer_size) {
        amxc_rbuffer_clean(rb);
        retval = 0;
        goto exit;
    }

    new_size = (rb->buffer_end - rb->buffer_start) - size;
    if(rb->read_pos > rb->write_pos) {
        size_t bytes = rb->read_pos - rb->buffer_start;
        size_t move = (size > bytes) ? bytes : size;
        memmove(rb->buffer_start + move,
                rb->read_pos,
                rb->buffer_end - rb->read_pos);
        rb->read_pos -= move;
        if(rb->read_pos > rb->buffer_start) {
            if(rb->write_pos > rb->read_pos) {
                rb->write_pos = rb->read_pos - 1;
            }
        } else {
            rb->write_pos = rb->buffer_start + new_size;
        }
    } else {
        size_t move = rb->write_pos - rb->read_pos;
        memmove(rb->buffer_start, rb->read_pos, move);
        rb->read_pos = rb->buffer_start;
        if(move > new_size) {
            rb->write_pos = rb->buffer_start + new_size;
        } else {
            rb->write_pos = rb->buffer_start + move;
        }
    }

    read_pos = rb->read_pos - rb->buffer_start;
    write_pos = rb->write_pos - rb->buffer_start;

    new_buffer = (char*) realloc(rb->buffer_start, new_size);

    rb->buffer_start = new_buffer;
    rb->buffer_end = rb->buffer_start + new_size;
    rb->read_pos = rb->buffer_start + read_pos;
    rb->write_pos = rb->buffer_start + write_pos;

    retval = 0;

exit:
    return retval;
}

ssize_t amxc_rbuffer_read(amxc_rbuffer_t* const rb,
                          char* const buf,
                          size_t count) {
    ssize_t retval = -1;
    when_null(rb, exit);
    when_null(buf, exit);

    if((count == 0) || (rb->read_pos == rb->write_pos)) {
        retval = 0;
        goto exit;
    }

    if(rb->read_pos > rb->write_pos) {
        size_t data_size = rb->buffer_end - rb->read_pos;
        if(count > data_size) {
            size_t max_size = 0;
            memcpy(buf, rb->read_pos, data_size);
            count -= data_size;
            max_size = rb->write_pos - rb->buffer_start;
            memcpy(buf + data_size,
                   rb->buffer_start,
                   count > max_size ? max_size : count);
            retval = data_size + (count > max_size ? max_size : count);
            rb->read_pos = rb->buffer_start +
                (count > max_size ? max_size : count);
        } else {
            data_size = rb->write_pos - rb->read_pos;
            memcpy(buf, rb->read_pos, data_size > count ? count : data_size);
            rb->read_pos += data_size > count ? count : data_size;
            retval = data_size > count ? count : data_size;
        }
    } else {
        size_t data_size = rb->write_pos - rb->read_pos;
        memcpy(buf, rb->read_pos, data_size > count ? count : data_size);
        rb->read_pos += data_size > count ? count : data_size;
        retval = data_size > count ? count : data_size;
    }

exit:
    return retval;
}

ssize_t amxc_rbuffer_write(amxc_rbuffer_t* const rb,
                           const char* const buf,
                           const size_t count) {
    ssize_t retval = -1;
    size_t free_space = 0;
    when_null(rb, exit);

    // check space, grow if needed
    free_space = (rb->buffer_end - rb->buffer_start) - amxc_rbuffer_size(rb);
    if(free_space < count) {
        when_failed(amxc_rbuffer_grow(rb, count * 2), exit);
    }

    // check border
    if(rb->write_pos >= rb->read_pos) {
        free_space = rb->buffer_end - rb->write_pos;
        if(count > free_space) {
            memcpy(rb->write_pos, buf, free_space);
            memcpy(rb->buffer_start, buf + free_space, count - free_space);
            rb->write_pos = rb->buffer_start + (count - free_space);
        } else {
            memcpy(rb->write_pos, buf, count);
            rb->write_pos += count;
        }
    } else {
        memcpy(rb->write_pos, buf, count);
        rb->write_pos += count;
    }

    retval = count;

exit:
    return retval;
}

size_t amxc_rbuffer_size(const amxc_rbuffer_t* const rb) {
    size_t retval = 0;
    when_null(rb, exit);
    when_true(rb->read_pos == rb->write_pos, exit);

    if(rb->read_pos > rb->write_pos) {
        retval = (rb->buffer_end - rb->read_pos) +
            (rb->write_pos - rb->buffer_start);
    } else {
        retval = (rb->write_pos - rb->read_pos);
    }

exit:
    return retval;
}
