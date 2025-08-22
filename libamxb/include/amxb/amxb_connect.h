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

#if !defined(__AMXB_CONNECT_H__)
#define __AMXB_CONNECT_H__

#ifdef __cplusplus
extern "C"
{
#endif

/**
   @file
   @brief
   Ambiorix Bus Agnostic connection API
 */

/**
   @ingroup amxb_baapi
   @defgroup amxb_connect Bus Connections
 */

/**
   @ingroup amxb_connect
   @brief
   Create a bus connection

   Connects to a bus using a uri.

   The uri must be strictly compliant with
   <a href="https://tools.ietf.org/html/rfc3986">RFC 3986</a>. The scheme of the
   uri refers to the backend that is used. The other parts of the uri are used
   by the backend to create a connection

   Searches a bus backend using the scheme of the uri, if found creates a
   connection to the bus and allocates a connection context.

   Multiple connections can be created to different busses.

   @note
   This function allocates memory for the connection context. The connection
   context can be freed using @ref amxb_free

   @param ctx The connection context
   @param uri The connection uri, compliant with RFC 3986

   @return
   - @ref AMXB_STATUS_OK when connection is created
   - @ref AMXB_ERROR_INVALID_URI when invalid URI was passed
   - @ref AMXB_ERROR_NOT_SUPPORTED_SCHEME when no matching backend was found
   - @ref AMXB_ERROR_BACKEND_FAILED when backend failed to connect to the bus
   - @ref AMXB_ERROR_NOT_SUPPORTED_OP when backend does not support connect
                                      operation
   - @ref AMXB_ERROR_UNKNOWN when invalid arguments are passed or
                             when failed to allocate memory
 */
int amxb_connect(amxb_bus_ctx_t** ctx, const char* uri);

/**
   @ingroup amxb_connect
   @brief
   Create a bus connection

   Connects to a bus using a uri and a network interface name or id (aka zone id).

   This function works exactly the same as @ref amxb_connect, the interface name
   will be added to the host part of the uri prefixed with a %.

   @param ctx The connection context
   @param uri The connection uri, compliant with RFC 3986

   @return
   - @ref AMXB_STATUS_OK when connection is created
   - @ref AMXB_ERROR_INVALID_URI when invalid URI was passed
   - @ref AMXB_ERROR_NOT_SUPPORTED_SCHEME when no matching backend was found
   - @ref AMXB_ERROR_BACKEND_FAILED when backend failed to connect to the bus
   - @ref AMXB_ERROR_NOT_SUPPORTED_OP when backend does not support connect
                                      operation
   - @ref AMXB_ERROR_UNKNOWN when invalid arguments are passed or
                             when failed to allocate memory
 */
int amxb_connect_intf(amxb_bus_ctx_t** ctx, const char* uri, const char* intf);

/**
   @ingroup amxb_connect
   @brief
   Create a listen socket

   Creates a listen socket using a specific back-end.

   The uri must be strictly compliant with
   <a href="https://tools.ietf.org/html/rfc3986">RFC 3986</a>. The scheme of the
   uri refers to the backend that is used. The other parts of the uri are used
   by the backend to create a connection

   Searches a bus backend using the scheme of the uri, if found and the
   back-end supports the creation of a listen socket, a listen socket is created.

   Multiple listen sockets can be created using different back-ends.

   When a listen socket is created, its file descriptor should be added to the
   event loop, when data is available on that file descriptor (incoming connection),
   the callback function in the event loop should call @ref amxb_accept

   @note
   This function allocates memory for the connection context. The connection
   context can be freed using @ref amxb_free

   @note
   Not all bus systems or back-ends support the creation of a listen socket.
   Consult the documentation of the back-end or the specific bus system to
   verify that listen sockets are supported.

   @param ctx The connection context
   @param uri The listen uri, compliant with RFC 3986

   @return
   - @ref AMXB_STATUS_OK when connection is created
   - @ref AMXB_ERROR_INVALID_URI when invalid URI was passed
   - @ref AMXB_ERROR_NOT_SUPPORTED_SCHEME when no matching backend was found
   - @ref AMXB_ERROR_BACKEND_FAILED when backend failed to connect to the bus
   - @ref AMXB_ERROR_NOT_SUPPORTED_OP when backend does not support connect
                                      operation
   - @ref AMXB_ERROR_UNKNOWN when invalid arguments are passed or
                             when failed to allocate memory
 */
int amxb_listen(amxb_bus_ctx_t** ctx, const char* uri);

/**
   @ingroup amxb_connect
   @brief
   Accepts an incomming connection request.

   To be able to accept incoming connection requests a listen socket must be
   created first. A listen socket can be created using @ref amxb_listen.

   This function is typically used from within an event loop callback function,
   and should be called when data is available on the created listen socket.

   @note
   This function allocates memory for the new connection context. The connection
   context can be freed using @ref amxb_free

   @param listen_ctx The listen connection context
   @param accepted_ctx The accepted connection

   @return
   - @ref AMXB_STATUS_OK when connection is created
   - @ref AMXB_ERROR_INVALID_URI when invalid URI was passed
   - @ref AMXB_ERROR_NOT_SUPPORTED_SCHEME when no matching backend was found
   - @ref AMXB_ERROR_BACKEND_FAILED when backend failed to connect to the bus
   - @ref AMXB_ERROR_NOT_SUPPORTED_OP when backend does not support connect
                                      operation
   - @ref AMXB_ERROR_UNKNOWN when invalid arguments are passed or
                             when failed to allocate memory
 */
int amxb_accept(amxb_bus_ctx_t* listen_ctx, amxb_bus_ctx_t** accepted_ctx);

/**
   @ingroup amxb_connect
   @brief
   Disconnects a bus connection

   Closes the connection to a bus that was previously created with
   @ref amxb_connect.

   After calling this function the connection is closed and can not be used any
   more.

   @note
   This functions does not free the allocated memory for the connection context.

   @param ctx  the connection context

   @return
   - @ref AMXB_STATUS_OK when connection is disconnected
   - @ref AMXB_ERROR_NOT_SUPPORTED_OP backend does not support disconnect
                                      operation
   - @ref AMXB_ERROR_UNKNOWN invalid arguments are passed

 */
int amxb_disconnect(amxb_bus_ctx_t* ctx);

/**
   @ingroup amxb_connect
   @brief
   Frees allocated memory

   The allocated memory for the connection context is freed.

   The connection is automatically disconnected if it is still connected.

   The pointer to the connection context is reset to NULL

   @param ctx the connection context that was created with @ref amxb_connect
 */
void amxb_free(amxb_bus_ctx_t** ctx);

/**
   @ingroup amxb_connect
   @brief
   Find the bus context for a given uri

   If a connection already exists for a uri, the bus_ctx can be retrieved
   using this function

   @param uri The connection uri

   @return
   the bus context if any exists for the given uri, NULL otherwise.
 */
amxb_bus_ctx_t* amxb_find_uri(const char* uri);

/**
   @ingroup amxb_connect
   @brief
   List all open connections by their uri

   returns an amxc_array_t containing const char * of all connect uris.

   @note
   The returned array contains const char*, the content should not be deleted
   The returned amxc_array_t* must be deleted using amxc_array_delete function.

   @return
   A pointer to an amxc_array_t, which must be freed using amxc_array_delete
   Do not free the content of the array.
 */
amxc_array_t* amxb_list_uris(void);

/**
   @ingroup amxb_connect
   @brief
   Get the connection file descriptor.

   Gets the file descriptor of the connection context.
   Use this function to add the file descriptor to your event loop.

   @param ctx the connection context

   @return
   The valid file descriptor or -1 when no file descriptor is available.
 */
int amxb_get_fd(const amxb_bus_ctx_t* const ctx);

/**
   @ingroup amxb_connect
   @brief
   Reads data from the file descriptor

   Reads data from the file descriptor of the connection context.

   Typically the backend parses the received data and dispatches to the correct
   callbacks if needed.

   This function is typically called whenever your eventloop detects that
   data is available for read on the connection context's file descriptor.

   @param ctx the connection context

   @return
   -1 when failed reading, other values are considered as success and depends on
   the backend implementation, typically the number of bytes read are returned.
 */
int amxb_read(const amxb_bus_ctx_t* const ctx);

/**
   @ingroup amxb_connect
   @brief
   Attempts to read up to count bytes from the file descriptor into the buffer starting at buf

   Reads data from the file descriptor of the connection context, and puts
   the read data in the provided bufffer, up to the given count bytes.

   The data received is put in the buffer as is, not parsing is done.

   This function is typically called whenever your eventloop detects that
   data is available for read on the connection context's file descriptor.

   @note
   do not use @ref amxb_read and @ref amxb_read_raw on the same context, only use one
   of them. When using this function it is up to the implementer to parse
   the received data and call any callbacks if needed.

   @param ctx the connection context
   @param buf pointer to a memory block where data can be put
   @param count maximum number of bytes that can be put in the memory block

   @return
   -1 when failed reading, other values are considered as success and depends on
   the backend implementation, typically the number of bytes read are returned.
 */
int amxb_read_raw(const amxb_bus_ctx_t* const ctx, void* buf, size_t count);

/**
   @ingroup amxb_connect
   @brief
   Sets the access method

   @param ctx the connection context
   @param access the access method, must be one of AMXB_PUBLIC, AMXB_PROTECTED
 */
static inline
void amxb_set_access(amxb_bus_ctx_t* const ctx, uint32_t access) {
    if(ctx != NULL) {
        ctx->access = access;
    }
}

/**
   @ingroup amxb_connect
   @brief
   Checks if the provided context is a listen socket

   With a listen socket connection, incoming connection requests can be handled.
   Using listen sockets it is possible to create an E2E connection between
   different applications, without the need for a broker/dispatcher process.

   Depending on the back-end and bus system used, this feature may not be available.

   @param ctx the connection context

   @return
   true when the provided connection context is a listen socket, false
   otherwise
 */
static inline
bool amxb_is_listen_socket(const amxb_bus_ctx_t* const ctx) {
    return ctx == NULL ? false : ctx->socket_type == AMXB_LISTEN_SOCK;
}

/**
   @ingroup amxb_connect
   @brief
   Checks if the provided context is a data socket

   Data sockets are used to transfer messages between applications.

   @param ctx the connection context

   @return
   true when the provided connection context is a data socket, false
   otherwise
 */
static inline
bool amxb_is_data_socket(const amxb_bus_ctx_t* const ctx) {
    return ctx == NULL ? false : ctx->socket_type == AMXB_DATA_SOCK;
}

#ifdef __cplusplus
}
#endif

#endif // __AMXB_CONNECT_H__
