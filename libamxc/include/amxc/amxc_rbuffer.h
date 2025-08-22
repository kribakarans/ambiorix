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

#if !defined(__AMXC_RBUFFER_H__)
#define __AMXC_RBUFFER_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <unistd.h>

#include <amxc/amxc_common.h>
#include <amxc/amxc_array.h>

/**
   @file
   @brief
   Ambiorix ring buffer API header file
 */

/**
   @ingroup amxc_containers
   @defgroup amxc_rbuffer Ring Buffer
 */

/**
   @ingroup amxc_rbuffer
   @brief
   The ring buffer structure.
 */
typedef struct _amxc_rbuffer {
    char* buffer_start;      /**< The beginning of the buffer */
    char* buffer_end;        /**< The end of the buffer */
    char* read_pos;          /**< Current read position */
    char* write_pos;         /**< Current write position */
} amxc_rbuffer_t;

/**
   @ingroup amxc_rbuffer
   @brief
   Allocates a ring buffer.

   Allocates and initializes memory to store a ring buffer.
   This functions allocates memory for the ring buffer structure as well as
   memory for the ring buffer itself.
   This function allocates memory from the heap, if a ring buffer structure is
   on the stack, it can be initialized using function @ref amxc_rbuffer_init

   The size of the ring buffer is not fixed and can be changed with the
   functions @ref amxc_rbuffer_grow or @ref amxc_rbuffer_shrink

   The size of the ring buffer is expressed in number of bytes that can be
   stored in the ring buffer.

   @note
   The allocated memory must be freed when not used anymore,
   use @ref amxc_rbuffer_delete to free the memory of the ring
   buffer and the ring buffer structure and @ref amxc_rbuffer_clean to free the
   buffer itself, but keep the ring buffer structure.

   @param rb a pointer to the location where the pointer to the new ring buffer
             structure can be stored
   @param size the size of the ring buffer in number of bytes

   @return
   -1 if an error occurred. 0 on success
 */
int amxc_rbuffer_new(amxc_rbuffer_t** rb, const size_t size);

/**
   @ingroup amxc_rbuffer
   @brief
   Frees the previously allocated ring buffer.

   Frees the ring buffer, all data that is still in the buffer will be lost.
   Also frees the allocated memory to store the ring buffer structure and sets
   the pointer in the structure to NULL.

   @note
   Only call this function for ring buffers that are allocated on the heap
   using @ref amxc_rbuffer_new

   @param rb a pointer to the location where the pointer to the ring buffer is
             stored
 */
void amxc_rbuffer_delete(amxc_rbuffer_t** rb);

/**
   @ingroup amxc_rbuffer
   @brief
   Initializes a ring buffer.

   Initializes the ring buffer structure.
   Memory is allocated from the heap to be able to store the number of
   bytes requested.

   This function is typically called for ring buffers that are on the stack.
   Allocating and initializing a ring buffer on the heap can be done
   using @ref amxc_rbuffer_new

   @note
   When calling this function on an already allocated and initialized ring buffer
   a memory leak occurs, the previously allocated buffer is not reachable anymore.
   Use @ref amxc_rbuffer_clean to free the buffer and reset all the pointers in
   the ring buffer structure to NULL.

   @param rb a pointer to the ring buffer structure.
   @param size the size of the ring buffer in number of bytes

   @return
   0 on success or -1 when an error occured.
 */
int amxc_rbuffer_init(amxc_rbuffer_t* const rb, const size_t size);

/**
   @ingroup amxc_rbuffer
   @brief
   Frees the buffer and sets all pointers of the ring buffer structure to NULL.

   @param rb a pointer to the ring buffer structure
 */
void amxc_rbuffer_clean(amxc_rbuffer_t* const rb);

/**
   @ingroup amxc_rbuffer
   @brief
   Grows the ring buffer.

   Increases the capacity of the ring buffer with a number of bytes.
   The extra memory is always allocated behind the current position of the
   write pointer. Growing the ring buffer has no effect on the data that is
   already in the ring buffer.

   @param rb a pointer to the ring buffer structure
   @param size the number of bytes the ring buffer has to grow

   @return
   0 on success.
   -1 if an error has occurred.
 */
int amxc_rbuffer_grow(amxc_rbuffer_t* const rb, const size_t size);

/**
   @ingroup amxc_rbuffer
   @brief
   Shrinks the ring buffer.

   Shrinks the ring buffer by the given number of bytes. The memory is freed.

   @note
   Shrinking the ring buffer could lead to data loss. The buffer shrinks from
   the current read pointer to the write pointer.
   The data loss will always be the last part written in the ring buffer.

   @param rb a pointer to the ring buffer structure
   @param size the number of bytes the ring buffer has to shrink

   @return
   0 on success.
   -1 if an error has occurred.
 */
int amxc_rbuffer_shrink(amxc_rbuffer_t* const rb, const size_t size);

/**
   @ingroup amxc_rbuffer
   @brief
   Reads a number of bytes from the ring buffer.

   Copies bytes from the ring buffer, starting from the current read position,
   into the provided buffer to a maximum number of bytes specified.
   When less bytes then the specified count are copied in the provided buffer,
   no more data is available in the ring buffer.

   @param rb a pointer to the ring buffer structure
   @param buf a pointer to a buffer where the data can be copied in.
   @param count the maximum number of bytes that can be copied

   @return
   The number of bytes copied, when less then the specified maximum,
   the ring buffer is empty.
 */
ssize_t amxc_rbuffer_read(amxc_rbuffer_t* const rb,
                          char* const buf,
                          size_t count);

/**
   @ingroup amxc_rbuffer
   @brief
   Writes a number of bytes to the ring buffer.

   Copies the specified number of bytes to the ring buffer,
   starting from the current write position, from the provided buffer.
   The ring buffer grows when there is not enough space left in the ring buffer.

   @param rb a pointer to the ring buffer structure
   @param buf a pointer to a buffer that contains the data that must be put in
              the ring buffer.
   @param count the number of bytes that need to be copied in the ring buffer

   @return
   The number of bytes copied or -1 when failed to copy the bytes in the ring buffer.
 */
ssize_t amxc_rbuffer_write(amxc_rbuffer_t* const rb,
                           const char* const buf,
                           const size_t count);

/**
   @ingroup amxc_rbuffer
   @brief
   Get the size of the data stored in the ring buffer

   @param rb a pointer to the ring buffer structure

   @return
   The number of bytes stored in the ring buffer
 */
size_t amxc_rbuffer_size(const amxc_rbuffer_t* const rb);

/**
   @ingroup amxc_rbuffer
   @brief
   Get the capacity of the ring buffer

   The capacity is the maximum bytes that can be stored in the ring buffer.
   The capacity - the size is the number of bytes that is currently not used.

   @param rb a pointer to the ring buffer structure

   @return
   The number of bytes that can be stored in the ring buffer
 */
AMXC_INLINE
size_t amxc_rbuffer_capacity(const amxc_rbuffer_t* const rb) {
    return rb != NULL ? rb->buffer_end - rb->buffer_start : 0;
}

/**
   @ingroup amxc_rbuffer
   @brief
   Checks that the ring buffer is empty.

   @param rb a pointer to the ring buffer structure

   @return
   true when there is no data in the ring buffer,
   or false when there is at least 1 byte of data stored in the ring buffer.
 */
AMXC_INLINE
bool amxc_rbuffer_is_empty(const amxc_rbuffer_t* const rb) {
    return rb != NULL ? (rb->read_pos == rb->write_pos) : true;
}

#ifdef __cplusplus
}
#endif

#endif // __AMX_RBUFFER_H__
