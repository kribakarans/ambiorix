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

#if !defined(__AMXB_BE_INTF_H__)
#define __AMXB_BE_INTF_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxb/amxb_types.h>

typedef struct _amxb_bus_ctx amxb_bus_ctx_t;
typedef struct _amxb_request amxb_request_t;
typedef struct _amxb_invoke amxb_invoke_t;

/**
   @file
   @brief
   Ambiorix Bus Backend Interface
 */

/**
   @ingroup amxb_baapi
   @defgroup amxb_be_intf Bus Backend Interface

   @paragraph amxb_be_intf_intro Backend Interface Introduction
   The top level bus agnostic API provided by this library has no knowledge of
   the underlying bus systems or protocols used. To be able to connect to a
   software bus system or use a protocol to be able to communicate with other
   processes it is relying on a back-end implementation.

   Back-ends are implemented in a shared object (.so file) which can be dynamically
   loaded at run-time on request. Loading and unloading of back-ends is done using
   the back-end manager API provided by this library (see @ref amxb_be_load, @ref amxb_be_remove).

   Back-ends are identified by a name, a back-end name must be unique. If another
   back-end is loaded with the same name as an already loaded back-end, the load
   will fail.

   Each back-end implementation must provide a pointer to a @ref _amxb_be_funcs structure.
   This structure contains function pointers. These functions will be called by the
   top level bus agnostic API when needed. Note that not all functions must be implemented,
   some are optional, others are mandatory.

   Besides the structure that contains the function pointers, a back-end must provide other
   information as well:
   - Its name (used as identifier)
   - Its current version (MAJOR.MINOR.BUILD)
   - The minimum required version of libamxb
   - The maximum required version of libamxb

   This information must be returned by a function with the name `amxb_be_info`. When
   the back-end is loaded, this function name will be resolved and called.

   Example of ubus back-end:
   @code
    static amxb_be_funcs_t amxb_ubus_impl = {
        .it = { .ait = NULL, .key = NULL, .next = NULL },
        .handle = NULL,
        .connections = { .head = NULL, .tail = NULL },
        .name = "ubus",
        .size = sizeof(amxb_be_funcs_t),
        // function pointers must be set here, these are omitted in this example for simplification
        // See ubus back-end implementation for the full structure
    };

    static amxb_version_t sup_min_lib_version = {
        .major = 4,
        .minor = 2,
        .build = 0
    };

    static amxb_version_t sup_max_lib_version = {
        .major = 4,
        .minor = -1,  // use -1 to indicate any minor version of major version 4
        .build = -1   // use -1 to indicate any build number
    };

    static amxb_version_t ubus_be_version = {
        .major = AMXB_UBUS_VERSION_MAJOR,
        .minor = AMXB_UBUS_VERSION_MINOR,
        .build = AMXB_UBUS_VERSION_BUILD,
    };

    amxb_be_info_t amxb_ubus_be_info = {
        .min_supported = &sup_min_lib_version,
        .max_supported = &sup_max_lib_version,
        .be_version = &ubus_be_version,
        .name = "ubus",
        .description = "AMXB Backend for UBUS (Openwrt/Prplwrt)",
        .funcs = &amxb_ubus_impl,
    };

    amxb_be_info_t* amxb_be_info(void) {
        return &amxb_ubus_be_info;
    }

   @endcode

   @paragraph amxb_be_intf_funcs Backend Interface Functions
   The back-end interface functions can be grouped in two major sets of functions.
   1. Functions used by a data model provided (aka data model server)
   2. Functions used by a data model consumer (aka data model client)

   Some of the functions will be used by providers as well as by consumers. These
   functions are: (known as the common functions)
   - @ref amxb_be_connect_fn_t
   - @ref amxb_be_disconnect_fn_t
   - @ref amxb_be_get_fd_fn_t
   - @ref amxb_be_read_fn_t
   - @ref amxb_be_free_fn_t

   The typical data model provider functions are:
   - @ref amxb_be_listen_fn_t
   - @ref amxb_be_accept_fn_t
   - @ref amxb_be_register_fn_t

   The typical data model consumer functions are:
   - @ref amxb_be_invoke_fn_t
   - @ref amxb_be_async_invoke_fn_t
   - @ref amxb_be_close_request_fn_t
   - @ref amxb_be_wait_request_fn_t
   - @ref amxb_be_subscribe_fn_t
   - @ref amxb_be_unsubscribe_fn_t

   @paragraph amxb_be_intf_responsibilities Backend Responsibilities
   A back-end is mainly a mediator and translator between the generic bus
   agnostic API and the bus or protocol specific implementation.

   All data that is exchanged must be translated from and to ambiorix variants.

   The top level bus agnostic API uses variants, which can contain complex data
   structures.

   It is important that the back-end implementation respects the correct variant
   structures. If these are not respected it will be very difficult for users
   of the generic bus agnostic API to use it and will break the bus agnostic
   nature of this library.

   The back-end functions are never called directly by any implementation.
   The service or application implementation must always call the libamxb APIs.
   The functions in this library will call the correct back-end method when
   needed.

   @paragraph amxb_be_intf_usp_support USP compatibility considerations
   The ambiorix data model implementation (libamxd) is inspired on the broadband
   forum specifications for [USP (TR-369)](https://usp.technology/specification/)
   and the [data model specifications (TR-181)](https://device-data-model.broadband-forum.org/).

   This is also reflected in the data model consumer (client) API in this library.
   This library provides functions that can be mapped on the USP data model operations:
   - get: @ref amxb_get - USP specification [7.5.1 The Get Message](https://usp.technology/specification/07-index-messages.html#sec:the-get-message)
   - set: @ref amxb_set - USP specification [7.4.4 The Set Message](https://usp.technology/specification/07-index-messages.html#sec:set)
   - add: @ref amxb_add - USP specification [7.4.3 The Add Message](https://usp.technology/specification/07-index-messages.html#sec:add)
   - delete: @ref amxb_del - USP specification [7.4.5 The Delete Message](https://usp.technology/specification/07-index-messages.html#sec:delete)
   - get supported data model (gsdm): @ref amxb_get_supported - USP specification [7.5.3 The GetSupportedDM Message](https://usp.technology/specification/07-index-messages.html#sec:the-getsupporteddm-message)
   - get instances: @ref amxb_get_instances - USP specification [7.5.2 The GetInstances Message](https://usp.technology/specification/07-index-messages.html#sec:getinstances)

   If the bus system in use has some knowledge of a data model it is possible to
   implement the back-end interface for the top level API functions for these USP
   like operators.

   A bus system is considered to have knowledge of a data model if:
   1. It supports objects (can be hierarchical)
   2. It supports parameters in these objects (aka attributes), and these parameters can have a name, type and value
   3. It supports methods in these objects
   4. It at least has support to get the parameters and their values for the objects.

   If a bus system only has support for calling methods on objects, it is not considered as
   data model knowledgable. In this case there is no need to implement the USP support
   functions in the back-end interface. If ambiorix data model implementations are
   accessed over such a bus system and the back-end doesn't provide back-end functions
   for the USP support functions, the top level API will try to call the default
   ambiorix data model RPC methods:
   - @ref amxb_get will call RPC method "_get" when no @ref amxb_be_get_t function is provided
   - @ref amxb_set will call RPC method "_set" when no @ref amxb_be_set_t function is provided
   - @ref amxb_add will call RPC method "_add" when no @ref amxb_be_add_t function is provided
   - @ref amxb_del will call RPC method "_del" when no @ref amxb_be_del_t function is provided
   - @ref amxb_get_supported will call RPC method "_get_supported" when no @ref amxb_be_supported_t function is provided
   - @ref amxb_get_instances will call RPC method "_get_instances" when no @ref amxb_be_get_instances_t function is provided

   When implementing the USP like operators in the back-end interface, please make sure
   that:
   - they support search paths and wildcard paths as described in the USP specifications
   - they respect the return structure as described in the documentation of the interface functions.

   More information about the different path types van be found in the USP specification:
   [2.5 Path Names](https://usp.technology/specification/02-index-architecture.html#sec:path-names)

   @paragraph amxb_be_intf_discovery_introspection Data model introspection and discovery
   A backend can provide a specific implementation for data model object discovery and data model introspection.

   The back-end interface functions that are related to object discover and
   introspection are:
   - @ref amxb_be_describe_t
   - @ref amxb_be_list_t
   - @ref amxb_be_has_fn_t
   - @ref amxb_be_wait_for_fn_t
   - @ref amxb_be_capabilities_fn_t

   @paragraph amxb_be_intf_what Which functions need to be implemented?
   Which functions of the back-end interface are needed highly depends on:
   1. The capabilities of the underlying bus system or protocol used.
   2. The goal

   First of all let's make a difference between native data model providers and ambiorix
   data model providers.

   A native data model provider doesn't use any of the ambiorix APIs but uses the
   native bus or protocol APIs. Such a data model provider can only be accessed by
   using the native messages available.

   An ambiorix data model provider, registers for each object a set of "default" RPC methods.
   These providers can be accessed and used by invoking these RPC methods.

   If the goal is to make an ambiorix based data model available on a bus system, and there is
   no need to access the native data model providers, it could be sufficient to implement
   only these methods:
   - @ref amxb_be_connect_fn_t
   - @ref amxb_be_disconnect_fn_t
   - @ref amxb_be_get_fd_fn_t
   - @ref amxb_be_read_fn_t
   - @ref amxb_be_free_fn_t
   - @ref amxb_be_register_fn_t
   - @ref amxb_be_invoke_fn_t
   - @ref amxb_be_async_invoke_fn_t
   - @ref amxb_be_close_request_fn_t
   - @ref amxb_be_wait_request_fn_t
   - @ref amxb_be_subscribe_fn_t
   - @ref amxb_be_unsubscribe_fn_t

   If the used bus system or protocol has some kind of data model and you want to
   access the native bus system data model(s) as well, it is recommended that the
   USP like operators are implemented as well:
   - @ref \amxb_be_get_t
   - @ref amxb_be_set_t
   - @ref amxb_be_add_t
   - @ref amxb_be_del_t
   - @ref amxb_be_supported_t
   - @ref amxb_be_get_instances_t

   When object discovery and/or data model introspection is needed on native data models,
   it is recomended to implement these methods as well
   - @ref amxb_be_describe_t
   - @ref amxb_be_list_t
   - @ref amxb_be_has_fn_t
   - @ref amxb_be_wait_for_fn_t
   - @ref amxb_be_capabilities_fn_t

   When object discovery and/or data model introspection is needed on ambiorix data models
   only it could be that you need to implement these methods (this depends on the
   capabilities of the underlying bus system or protocol used):
   - @ref amxb_be_list_t
   - @ref amxb_be_has_fn_t
   - @ref amxb_be_wait_for_fn_t
   - @ref amxb_be_capabilities_fn_t

   As an example let's take the UBus back-end implementation. UBus doesn't have
   support for a data model. UBus only has support for objects and these objects
   can only contain RPC methods. A client (consumer) can only call these RPC methods.

   In this case only these methods need to be implemented:
   - @ref amxb_be_connect_fn_t
   - @ref amxb_be_disconnect_fn_t
   - @ref amxb_be_get_fd_fn_t
   - @ref amxb_be_read_fn_t
   - @ref amxb_be_free_fn_t
   - @ref amxb_be_register_fn_t
   - @ref amxb_be_invoke_fn_t
   - @ref amxb_be_async_invoke_fn_t
   - @ref amxb_be_close_request_fn_t
   - @ref amxb_be_wait_request_fn_t
   - @ref amxb_be_subscribe_fn_t
   - @ref amxb_be_unsubscribe_fn_t
   - @ref amxb_be_list_t
   - @ref amxb_be_has_fn_t
   - @ref amxb_be_wait_for_fn_t
   - @ref amxb_be_capabilities_fn_t

   This will make it possible:
   - to call the RPC methods of native ubus implementations.
   - register a ambiorix based data model implementation
   - access from a data model consumer the ambiorix based data model implementations
   - receive events from ambiorix based data model implementations
 */


/**
   @ingroup amxb_defines
   @brief
   Back-end supports data model discovery using amxb_describe
 */
#define AMXB_BE_DISCOVER_DESCRIBE 0x0001
/**
   @ingroup amxb_defines
   @brief
   Back-end supports data model discovery using amxb_list
 */
#define AMXB_BE_DISCOVER_LIST     0x0002
/**
   @ingroup amxb_defines
   @brief
   Back-end supports data model discovery using a custom `has` function
 */
#define AMXB_BE_DISCOVER          0x0004
/**
   @ingroup amxb_defines
   @brief
   Back-end supports data model discovery using amxb_resolve
 */
#define AMXB_BE_DISCOVER_RESOLVE  0x0008

//-----------------------------------------------------------------------------
/**
   @ingroup amxb_be_intf
   @brief
   Opens a bus connection or creates a socket connection.

   To be able to make processes communicate with each other a socket connection
   must be created. When using a bus system, this function will typically connect
   to the bus using the bus specific provided API.

   This function is called by the top level bus agnostic API in amxb_connect.

   The top level API expects a valid URI, which is parsed and the separate parts
   of the URI are passed to this function. The scheme of the URI is used to identify
   the back-end that needs to be used (that is the back-end name).

   The passed URI's must be conform to RFC3986

   Examples of uri:
   @code
   //ubus:/var/run/ubus.sock
   //
   //scheme = ubus
   //host = NULL
   //port = NULL
   //path = /var/run/ubus.sock
   amxb_bus_ctx_t* ctx = NULL;

   amxb_connect(&ctx, "ubus:/var/run/ubus.sock");
   @endcode

   The above example will call the connect function of the "ubus" back-end and passes
   the parsed host, port and path to that function. If no back-end with the name
   "ubus" is available, amxb_connect will fail.

   This function must return a pointer to some internal data structure. The top
   level API will pass this pointer to other functions of the same interface.
   It is up to the implementor of the back-end interface to decide what this pointer
   is (can be a pointer to a struct) and what data is contained in the memory block
   referenced by that pointer.

   Example of implementation for ubus (simplified):
   @code
    void* amxb_ubus_connect(const char* host, const char* port, const char* path, amxp_signal_mngr_t* sigmngr) {
        amxb_ubus_t* amxb_ubus_ctx = NULL;

        when_not_null(host, exit);
        when_not_null(port, exit);

        amxb_ubus_ctx = (amxb_ubus_t*) calloc(1, sizeof(amxb_ubus_t));
        when_null(amxb_ubus_ctx, exit);

        amxb_ubus_ctx->ubus_ctx = ubus_connect(path);
        if(amxb_ubus_ctx->ubus_ctx == NULL) {
            free(amxb_ubus_ctx);
            amxb_ubus_ctx = NULL;
        }

    exit:
        return amxb_ubus_ctx;
    }
   @endcode

   @param host host part of the URI, can be NULL or empty
   @param port port part of the URI, can be NULL or empty
   @param path path part of the URI, can be NULL or empty
   @param sigmngr pointer to an amxp signal manager, this must be used to dispatch the events on.

   @return
   returns a pointer to some data block or NULL when failed to connect.
 */
typedef void*(* amxb_be_connect_fn_t) (const char* host,
                                       const char* port,
                                       const char* path,
                                       amxp_signal_mngr_t* sigmngr);

/**
   @ingroup amxb_be_intf
   @brief
   Creates a listen socket.

   Creates a listen socket, other processes can connect to this listen socket.

   This function is called by the top level bus agnostic API in amxb_listen.

   The top level API expects a valid URI, which is parsed and the separate parts
   of the URI are passed to this function. The scheme of the URI is used to identify
   the back-end that needs to be used (that is the back-end name).

   @note
   Not all bus systems or protocols have support for peer to peer connections.
   The implementation of this function is optional. When this function is
   implemented, an implementation for the @ref amxb_be_accept_fn_t will be needed
   as well.

   This function must return a pointer to some internal data structure. The top
   level API will pass this pointer to other functions of the same interface.
   It is up to the implementor of the back-end interface to decide what this pointer
   is (can be a pointer to a struct) and what data is contained in the memory block
   referenced by that pointer.

   @param host host part of the URI, can be NULL or empty
   @param port port part of the URI, can be NULL or empty
   @param path path part of the URI, can be NULL or empty
   @param sigmngr pointer to an amxp signal manager, this must be used to dispatch the events on

   @return
   returns an opaque pointer to some data block or NULL when failed to connect.

   @see amxb_be_accept_fn_t
 */
typedef void*(* amxb_be_listen_fn_t) (const char* host,
                                      const char* port,
                                      const char* path,
                                      amxp_signal_mngr_t* sigmngr);

/**
   @ingroup amxb_be_intf
   @brief
   Accepts or drops an incoming connection.

   When a listen socket was created (see @ref amxb_be_listen_fn_t), an accept function
   implementation is needed. In this function incoming connections can be either
   accepted or dropped.

   This function is called by the top level bus agnostic API in amxb_accept.

   @note
   Not all bus systems or protocols have support for peer to peer connections.
   The implementation of this function is optional unless a listen function is
   provided.

   As with the @ref amxb_be_connect_fn_t, this function must also return a pointer
   to some data block. Typically this will be similar.

   @param ctx an opaque pointer to some data, this pointer was returned by @ref amxb_be_listen_fn_t
   @param sigmngr pointer to an amxp signal manager, this must be used to dispatch the events on.

   @return
   returns an opaque pointer to some data block or NULL when failed to connects.

   @see amxb_be_listen_fn_t
 */
typedef void*(* amxb_be_accept_fn_t) (void* const ctx,
                                      amxp_signal_mngr_t* sigmngr);

/**
   @ingroup amxb_be_intf
   @brief
   Closes a bus connection or disconnects a socket.

   Closes a previously opened bus connection or disconnects from a previously connected
   socket.

   This function is called by the top level bus agnostic API in amxb_disconnect.

   Example of implementation for ubus (simplified):
   @code
    int amxb_ubus_disconnect(void* ctx) {
        amxb_ubus_t* amxb_ubus_ctx = (amxb_ubus_t*) ctx;

        when_null(amxb_ubus_ctx, exit);
        when_null(amxb_ubus_ctx->ubus_ctx, exit);

        amxb_ubus_cancel_requests(amxb_ubus_ctx);
        ubus_free(amxb_ubus_ctx->ubus_ctx);
        blob_buf_free(&amxb_ubus_ctx->b);
        amxb_ubus_ctx->ubus_ctx = NULL;

    exit:
        return 0;
    }
   @endcode

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_listen_fn_t or
              @ref amxb_be_accept_fn_t

   @return
   The function must return 0 on success, any other value indicates an error.

   @see amxb_be_connect_fn_t amxb_be_listen_fn_t amxb_be_accept_fn_t
 */
typedef int (* amxb_be_disconnect_fn_t) (void* const ctx);

/**
   @ingroup amxb_be_intf
   @brief
   Get the file descriptor that represents the opened bus connection or the connected socket.

   The service or application must know when to read data from the connection.
   Typically the service or application implementation will add the file descriptor
   to a select or poll and when data becomes available on the file descriptor one of
   the read functions (amxb_be_read_fn_t or amxb_be_read_raw_fn_t) will be
   called to read the data and dispatch it to the correct handlers.

   This function is called by the top level bus agnostic API in amxb_get_fd.

   @note
   Some bus systems don't provide access to the underlying sockets, so the file
   descriptors are not available. Often these implementations using a read thread
   that will call callback functions.
   To make the bus agnostic API work a file descriptor is needed. A solution for this
   is that the @ref amxb_be_connect_fn_t implementation creates a pipe or socketpair. One end
   of the pipe or socketpair is used in the callback functions to write the data on, the other
   end is returned by this function and can be used to handle the incoming
   messages.

   @warning
   The returned file descriptor must be set in non-blocking mode.

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t

   @return
   The function must return the file descriptor that needs to be monitored

   @see amxb_be_connect_fn_t amxb_be_accept_fn_t
 */
typedef int (* amxb_be_get_fd_fn_t) (void* const ctx);

/**
   @ingroup amxb_be_intf
   @brief
   Read data from file descriptor and dispatch the request.

   When data is available on the file descriptor, which was returned by @ref amxb_be_get_fd_fn_t
   implementation, the top level bus agnostic API will call this function.
   The implementation must read and handle the incoming messages. Typically this is
   done by calling the bus specific API.

   This function is called by the top level bus agnostic API in amxb_read.

   Example of implementation for ubus:
   @code
    int amxb_ubus_read(void* ctx) {
        amxb_ubus_t* amxb_ubus_ctx = (amxb_ubus_t*) ctx;
        struct ubus_context* ubus_ctx = NULL;
        int retval = -1;

        when_null(amxb_ubus_ctx, exit);
        when_null(amxb_ubus_ctx->ubus_ctx, exit);

        ubus_ctx = amxb_ubus_ctx->ubus_ctx;
        ubus_ctx->sock.cb(&ubus_ctx->sock, ULOOP_READ);

        if(ubus_ctx->sock.eof) {
            retval = -1;
        } else {
            retval = 0;
        }

    exit:
        return retval;
    }
   @endcode

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_read_fn_t) (void* const ctx);

typedef int (* amxb_be_read_raw_fn_t) (void* const ctx, void* buf, size_t count);
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
/**
   @ingroup amxb_be_intf
   @brief
   Updates the invoke context with bus specific data.

   In most cases no implementation for this function is needed. This function
   can update or add bus specific data to the invoke context if needed.

   For example in D-Bus an interface name must be provided. This interface name
   is something specific for D-Bus and therefor can not be added by the top level
   generic API.

   It is possible to add some private data pointer to the invoke context as well.

   This function is called by the top level bus agnostic API in amxb_new_invoke.

   @param invoke_ctx a pointer to an invoke context, the invoke context contains
                     the object path, the method name, the interface name (if used)
                     and some private data

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_new_invoke_fn_t) (amxb_invoke_t* invoke_ctx);

/**
   @ingroup amxb_be_intf
   @brief
   Frees the bus specific data from the invoke context.

   In most cases no implementation for this function is needed. This function
   should free any allocated memory that was allocated by the @ref amxb_be_new_invoke_fn_t
   implementation.

   If no implementation for @ref amxb_be_new_invoke_fn_t was provided or the implementation
   doesn't allocate any memory, there is no need to implement this method.

   This function is called by the top level bus agnostic API in amxb_free_invoke.

   @param invoke_ctx a pointer to an invoke context, the invoke context contains
                     the object path, the method name, the interface name (if used)
                     and some private data

 */
typedef void (* amxb_be_free_invoke_fn_t) (amxb_invoke_t* invoke_ctx);

/**
   @ingroup amxb_be_intf
   @brief
   Invokes a remote procedure call in the data model and waits for the reply.

   The top level bus agnostic API will allocate:
   - an invoke context which contains the object path and the method name. Some
     bus systems also need an interface name. When an interface name is needed or extra
     information is needed (as private data) the back-end can implement @ref amxb_be_new_invoke_fn_t
     to provide that information in the invoke context
   - a request context. This request context (pointer) can be used to track the status
     of the request. Most bus systems will use a callback function to provide the
     result of the invoke. The request pointer can be used as private data that will
     be passed to the callback function. See documentation of your bus system.

   This function is called by the top level bus agnostic API in amxb_invoke.

   This implementation is mandatory. When the bus system doesn't support operations
   like get/set/add/delete and so on, the top level bus agnostic API will do an
   invoke of the corresponding ambiorix data model RPC methods.

   For example, ubus doesn't have a specific get operations, when amxb_get is called
   it will first check if the back-end provides an implementation of the @ref amxb_be_get_t,
   if no such implementation is available, it will call this function and calls the _get RPC.

   The result of the invoke must be added to the request->result variant. This
   variant contains a list of variants. The first item in the list must contain
   the return value of the RPC method, the second item can be a hash table containing
   the out arguments.

   Example of implementation for ubus (simplified):
   @code
    int amxb_ubus_invoke(void* const ctx,
                        amxb_invoke_t* invoke_ctx,
                        amxc_var_t* args,
                        amxb_request_t* request,
                        int timeout) {
        amxb_ubus_t* amxb_ubus_ctx = (amxb_ubus_t*) ctx;
        uint32_t id = 0;
        int ret = -1;

        when_str_empty(invoke_ctx->object, exit);

        retval = ubus_lookup_id(amxb_ubus_ctx->ubus_ctx, invoke_ctx->object, &id);
        if(retval != 0) {
            goto exit;
        }

        blob_buf_init(&amxb_ubus_ctx->b, 0);

        if(args != NULL) {
            when_true(amxc_var_type_of(args) != AMXC_VAR_ID_HTABLE, exit);
            const amxc_htable_t* htable = amxc_var_constcast(amxc_htable_t, args);
            // convert arguments to ubus format
            when_failed(amxb_ubus_format_blob_table(htable, &amxb_ubus_ctx->b), exit);
        }

        amxc_var_set_type(request->result, AMXC_VAR_ID_LIST);

        // invoke the remote procedure call
        ret = ubus_invoke(amxb_ubus_ctx->ubus_ctx,
                        id,
                        invoke_ctx->method,
                        amxb_ubus_ctx->b.head,
                        amxb_ubus_result_data,
                        request,
                        timeout * 1000);

        request->bus_retval = ret;

    exit:
        return ret;
    }
   @endcode

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t
   @param invoke_ctx a pointer to an invoke context, the invoke context contains
                     the object path, the method name, the interface name (if used)
                     and some private data
   @param args a htable variant containing the method arguments
   @param request pointer to the invoke request, can be used to track the status of the invoke request
   @param timeout timeout in seconds, if no reply received within the timeout period the invoke fails

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_invoke_fn_t) (void* const ctx,
                                     amxb_invoke_t* invoke_ctx,
                                     amxc_var_t* args,
                                     amxb_request_t* request,
                                     int timeout);

/**
   @ingroup amxb_be_intf
   @brief
   Invokes a remote procedure call in the data model and return immediately without waiting for reply.

   The top level bus agnostic API will allocate:
   - an invoke context which contains the object path and the method name. Some
     bus systems also need an interface name. When an interface name is needed or extra
     information is needed (as private data) the back-end can implement @ref amxb_be_new_invoke_fn_t
     to provide that information in the invoke context
   - a request context. This request context (pointer) can be used to track the status
     of the request. Most bus systems will use a callback function to provide the
     result of the invoke. The request pointer can be used as private data that will
     be passed to the callback function. See documentation of your bus system.

   This function is called by the top level bus agnostic API in amxb_async_invoke.

   The result of the invoke must be added to the request->result variant. This
   variant contains a list of variants. The first item in the list must contain
   the return value of the RPC method, the second item can be a hash table containing
   the out arguments.

   This method must return immediately after sending the invoke request to the bus.
   The return value only indicates if the send was successful. The caller of @ref amxb_async_invoke
   can provide a reply item callback function and a done callback function which
   must be called by the back-end if they are available.

   The caller of @ref amxb_async_invoke can also cancel the invoke request by calling
   @ref amxb_close_request or wait for the result with @ref amxb_wait_for_request. These
   top level bus agnostic API functions will call the back-end implementations
   @ref amxb_be_close_request_fn_t and @ref amxb_be_wait_request_fn_t respectively.

   Example of implementation for ubus (simplified):
   @code
    int amxb_ubus_async_invoke(void* const ctx,
                            amxb_invoke_t* invoke_ctx,
                            amxc_var_t* args,
                            amxb_request_t* request) {
        amxb_ubus_t* amxb_ubus_ctx = (amxb_ubus_t*) ctx;
        uint32_t id = 0;
        int ret = -1;
        struct ubus_request* ubus_req = NULL;

        when_str_empty(invoke_ctx->object, exit);

        retval = ubus_lookup_id(amxb_ubus_ctx->ubus_ctx, invoke_ctx->object, &id);
        if(retval != 0) {
            goto exit;
        }

        blob_buf_init(&amxb_ubus_ctx->b, 0);

        if(args != NULL) {
            when_true(amxc_var_type_of(args) != AMXC_VAR_ID_HTABLE, exit);
            const amxc_htable_t* htable = amxc_var_constcast(amxc_htable_t, args);
            // convert arguments to ubus format
            when_failed(amxb_ubus_format_blob_table(htable, &amxb_ubus_ctx->b), exit);
        }

        amxc_var_set_type(request->result, AMXC_VAR_ID_LIST);

        ubus_req = (struct ubus_request*) calloc(1, sizeof(struct ubus_request));
        when_null(ubus_req, exit);
        request->bus_data = ubus_req;

        ret = ubus_invoke_async(amxb_ubus_ctx->ubus_ctx,
                                id,
                                invoke_ctx->method,
                                amxb_ubus_ctx->b.head,
                                ubus_req);

        // set the ubus callback functions
        ubus_req->data_cb = amxb_ubus_result_data; // translates ubus blob to amxc_variant and calls top level callback function
        ubus_req->complete_cb = amxb_ubus_request_done; // calls top level done function
        ubus_req->priv = request;

        ubus_complete_request_async(amxb_ubus_ctx->ubus_ctx, ubus_req);

    exit:
        if(ret != 0) {
            free(ubus_req);
            request->bus_data = NULL;
        }
        return ret;
    }
   @endcode

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t
   @param invoke_ctx a pointer to an invoke context, the invoke context contains
                     the object path, the method name, the interface name (if used)
                     and some private data
   @param args a htable variant containing the method arguments
   @param request pointer to the invoke request, can be used to track the status of the invoke request

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_async_invoke_fn_t) (void* const ctx,
                                           amxb_invoke_t* invoke_ctx,
                                           amxc_var_t* args,
                                           amxb_request_t* request);

/**
   @ingroup amxb_be_intf
   @brief
   Closes or cancels a pending asynchronous request.

   When the underlying bus system has support for asynchronous requests, and has
   support to abort or cancel them, this function can implement this.

   This function is called by the top level bus agnostic API in amxb_close_request.

   Example of implementation for ubus:
   @code
    int amxb_ubus_close_request(void* const ctx, amxb_request_t* request) {
        amxb_ubus_t* amxb_ubus_ctx = (amxb_ubus_t*) ctx;
        struct ubus_request* ubus_req = (struct ubus_request*) request->bus_data;

        if(request->bus_data != NULL) {
            ubus_abort_request(amxb_ubus_ctx->ubus_ctx, ubus_req);
            free(ubus_req);
            request->bus_data = NULL;
        }
        return 0;
    }
   @endcode

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t
   @param request pointer to the invoke request, can be used to track the status of the invoke request

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_close_request_fn_t) (void* const ctx,
                                            amxb_request_t* request);

/**
   @ingroup amxb_be_intf
   @brief
   Waits until an asynchronous request has finished.

   When the underlying bus system has support for asynchronous requests, and has
   support to wait until the request is finished, this function can implement this.

   This function is called by the top level bus agnostic API in amxb_wait_request.

   Example of implementation for ubus:
   @code
    int amxb_ubus_wait_request(void* const ctx, amxb_request_t* request, int timeout) {
        amxb_ubus_t* amxb_ubus_ctx = (amxb_ubus_t*) ctx;
        struct ubus_request* ubus_req = (struct ubus_request*) request->bus_data;

        return ubus_complete_request(amxb_ubus_ctx->ubus_ctx, ubus_req, timeout);
    }
   @endcode

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t
   @param request pointer to the invoke request, can be used to track the status of the invoke request
   @param timeout timeout in seconds, indicates the maximum time the wait can take. If the timeout occurs, the request is canceled.

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_wait_request_fn_t) (void* const ctx,
                                           amxb_request_t* request,
                                           int timeout);
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
/**
   @ingroup amxb_be_intf
   @brief
   Creates a subscription for a specific object.

   Opens a subscription on a specific data model object. When a subscription
   succeeds the data model provider will send notifications/events to the data model
   consumer to indicate changes on that object.

   The ambiorix data model implementation provides a set of default events:
   - dm:object-changed - whenever a parameter of the object changes its value
   - dm:instance-added - only for multi-instance objects, sent whenever an instance has been added
   - dm:instance-removed - only for multi-instance objects, sent whenever an instance has been deleted

   Depending on the data model implementation other notifications/events can be sent
   as well.

   Typically the back-end keeps track of the opened subscriptions, and will close all
   of them when the connection is closed or when the back-end is unloaded.

   This function is called by the top level bus agnostic API in amxb_subscribe.

   Example of implementation for ubus:
   @code
    int amxb_ubus_subscribe(void* const ctx, const char* object) {
        amxb_ubus_t* amxb_ubus_ctx = (amxb_ubus_t*) ctx;
        amxc_htable_it_t* it = NULL;
        amxb_ubus_sub_t* amxb_ubus_sub = NULL;
        amxc_string_t rel_path;
        amxd_path_t path;
        int ret = -1;
        uint32_t id = 0;

        amxc_string_init(&rel_path, 64);
        amxd_path_init(&path, NULL);
        amxd_path_setf(&path, true, "%s", object);

        when_failed(amxb_ubus_get_longest_path(amxb_ubus_ctx, &path, &rel_path), exit);

        ret = ubus_lookup_id(amxb_ubus_ctx->ubus_ctx, amxd_path_get(&path, 0), &id);
        when_true(ret != 0, exit);

        it = amxc_htable_get(&amxb_ubus_ctx->subscribers, amxd_path_get(&path, 0));
        when_not_null(it, exit);

        amxb_ubus_sub = (amxb_ubus_sub_t*) calloc(1, sizeof(amxb_ubus_sub_t));
        amxc_htable_insert(&amxb_ubus_ctx->subscribers,
                        object,
                        &amxb_ubus_sub->it);

        ret = ubus_register_subscriber(amxb_ubus_ctx->ubus_ctx,
                                    &amxb_ubus_sub->sub);
        when_true(ret != 0, exit);
        amxb_ubus_sub->sub.cb = amxb_ubus_receive_notification;

        ret = ubus_subscribe(amxb_ubus_ctx->ubus_ctx, &amxb_ubus_sub->sub, id);

    exit:
        amxc_string_clean(&rel_path);
        amxd_path_clean(&path);
        return ret;
    }
   @endcode

   Consumer (client) side example of usage of the "amxb_subscribe" function:
   For the full implementation see the subscribe example
   @code
    // the function that is called when an notification/event is received
    static void notify_handler(const char* const sig_name,
                            const amxc_var_t* const data,
                            UNUSED void* const priv) {
        printf("Notification received [%s]:\n", sig_name);
        amxc_var_dump(data, STDOUT_FILENO);
    }

    // a subscription is taken using amxb_subscribe
    retval = amxb_subscribe(bus_ctx, // bus context, created with amxb_connect
                            object_path, // the object you want to receive events from
                            expression,  // optionally a filter expression can be provided
                            notify_handler, // the callback function
                            NULL); // private data

   @endcode

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t
   @param object Data model object path

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_subscribe_fn_t) (void* const ctx,
                                        const char* object);

/**
   @ingroup amxb_be_intf
   @brief
   Removes a subscription for a specific object.

   Closes a subscription on a specific data model object. When there was no
   open subscription for the specified object, the function should succeed and
   do nothing.

   This function is called by the top level bus agnostic API in amxb_unsubscribe.

   Example of implementation for ubus:
   @code
    int amxb_ubus_unsubscribe(void* const ctx, const char* object) {
        amxb_ubus_t* amxb_ubus_ctx = (amxb_ubus_t*) ctx;
        amxb_ubus_sub_t* amxb_ubus_sub = NULL;
        amxc_htable_it_t* it = NULL;
        amxc_string_t rel_path;
        amxd_path_t path;
        int ret = 0;
        uint32_t id = 0;

        amxc_string_init(&rel_path, 64);
        amxd_path_init(&path, NULL);
        amxd_path_setf(&path, true, "%s", object);

        amxb_ubus_get_longest_path(amxb_ubus_ctx, &path, &rel_path);

        it = amxc_htable_get(&amxb_ubus_ctx->subscribers, object);
        when_null(it, leave);
        amxb_ubus_sub = amxc_htable_it_get_data(it, amxb_ubus_sub_t, it);

        ret = ubus_lookup_id(amxb_ubus_ctx->ubus_ctx, amxd_path_get(&path, 0), &id);
        when_true(ret != 0, exit);

        ubus_unsubscribe(amxb_ubus_ctx->ubus_ctx, &amxb_ubus_sub->sub, id);

    exit:
        ret = ubus_unregister_subscriber(amxb_ubus_ctx->ubus_ctx, &amxb_ubus_sub->sub);

        amxc_htable_it_clean(it, NULL);
        amxp_timer_delete(&amxb_ubus_sub->reactivate);
        free(amxb_ubus_sub);

    leave:
        amxc_string_clean(&rel_path);
        amxd_path_clean(&path);

        return ret;
    }
   @endcode

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t
   @param object Data model object path

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_unsubscribe_fn_t) (void* const ctx,
                                          const char* object);
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
/**
   @ingroup amxb_be_intf
   @brief
   Registers an ambiorix data model to the bus system.

   Data model provders (servers) must be able to announce or register the data
   model they provide to the bus system. How the registration is done is highly
   dependant on the bus system or protocol used.

   Some bus systems require that all objects are registered (including instances)
   when the object is available and the objects must be unregistered when they
   are removed. Other bus systems only require that the root objects are
   registered.

   This function will use a lot of the ambiorix data model api to go over the
   available objects to register them on the bus system, and watch local data
   model events to keep track of which objects are added or deleted.

   Often bus specific callback functions must be added as well during the
   registration of the objects. Typically these callback functions are implemented
   in the back-end as well and they will do translation and then call the corresponding
   ambiorix data model API functions and translate the result back to a specific
   bus message.

   As the registration is very important to make ambiorix data model providers
   work correctly on the bus system, this is one of the key methods and must be
   implemented with great care.

   As an example of the registration process take a look at the ubus back-end
   implementation. The full implementation can be found in the file "amxb_ubus_register.c".
   Ubus requires that all objects are registered, including the RPC methods of the
   objects. Ubus doesn't provide any functionality to expose parameters on the bus.
   The ambiorix data model implementation provides an alternative to fetch parameters
   using the "_get" RPC method that is available on all objects.
   In the ubus back-end the method "amxd_object_hierarchy_walk" is used initially
   to register all objects available in the data model, and it adds event callback
   methods to monitor changes in the data model. See function "amxb_ubus_register_dm" in
   the file "amxb_ubus_register.c".

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t
   @param dm pointer to the local data model.

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_register_fn_t) (void* const ctx,
                                       amxd_dm_t* const dm);
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
/**
   @ingroup amxb_be_intf
   @brief
   Frees allocated memory for bus connection

   When memory or any other resources are allocated when creating a bus or
   socket connection, this function can free them.

   This function is called by the top level bus agnostic API in amxb_disconnect.

   Example of implementation for ubus (simplified):
   @code
    void amxb_ubus_free(void* ctx) {
        amxb_ubus_t* amxb_ubus_ctx = (amxb_ubus_t*) ctx;

        when_null(amxb_ubus_ctx, exit);
        amxc_llist_clean(&amxb_ubus_ctx->registered_objs, amxb_ubus_obj_it_free);
        free(amxb_ubus_ctx);

    exit:
        return;
    }
   @endcode

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t
 */
typedef void (* amxb_be_free_fn_t) (void* const ctx);
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
/**
   @ingroup amxb_be_intf
   @brief
   Performs a get operation on one or more objects in the data model tree.

   A get fetches parameter values of one or more objects. The path types that
   must be supported are:
   - object paths, using index addressing and key addressing
   - search paths and wildcard paths
   - parameter paths

   If a path is a key addressing path, search path or wildcard path the fixed part
   of the path will be provided in the argument object, the part containing
   the search expressions or wildcards is passed in the argument search_path.

   Examples:
   @code
   // Assume this path
   "Device.IP.Interface.[Type=='Normal'].IPv4Address.[AddressingType=='Static']."
   // object = "Device.IP.Interface."
   // search_path = "[Type=='Normal'].IPv4Address.[AddressingType=='Static']."

   // Assume this path
   "Phonebook.Contact.*.FirstName"
   // object = "Phonebook.Contact."
   // search_path = "*"
   @endcode

   It  is up to the back end implementation to filter the returned objects. How
   this is done is highly depending on the used bus system. It could be that the
   used bus system has support for filtering, it could be that the bus system
   doesn't support filtering, in the last case the back-end implementation must
   filter the returned objects, and make sure only the matching objects are
   returned.

   The returned objects must be put in the ret variant. The ret variant should
   contain at top level an array, which must contain at index 0 a hash table variant.
   The hash table variant must contain the path of each matching object as key and
   as the value a hash table variant containing the parameter names and their values.

   When a parameter path is provided (not ending on a dot), only the values of this
   parameter must be returned for all matching objects.

   Example:
   @code
    [
        {
            Phonebook.Contact.1. = {
                FirstName = "John"
                LastName = "Doe",
            },
            Phonebook.Contact.2. = {
                FirstName = "Jane"
                LastName = "Doe",
            },
            Phonebook.Contact.3. = {
                FirstName = "Eva"
                LastName = "Elliott",
            }
        }
    ]
   @endcode

   When a depth different from 0 is provided, all levels below the requested objects
   must be returned, with a maximum depth in the hierarchy as specified by the depth parameter.
   When a depth of -1 is given, it will return the full hierarchy starting from the
   matching objects.

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t
   @param object the fixed object path part, without any expressions or wildcards
   @param search_path the part of the path containing the search expressions or wildcards, relative to object
   @param depth the number of levels in the object tree hierarchy that must be returned, relative to the matching objects
   @param access can be set to amxd_dm_access_public (0) or amxd_dm_access_protected (1). When set to amxd_access_public
                 no protected objects or parameters must be returned
   @param ret the variant that will contain the final result of the get
   @param timeout time in seconds to wait for the reply

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_get_t) (void* const ctx,
                               const char* object,
                               const char* search_path,
                               int32_t depth,
                               uint32_t access,
                               amxc_var_t* ret,
                               int timeout);
/**
   @ingroup amxb_be_intf
   @brief
   Performs a get operation on one or more objects in the data model tree.

   This function should work exactly the same as @ref amxb_be_get_t, but is able to filter the parameters
   on the meta-data of the parameter. Only paramerters matching the filter expression should be returned.
   Objects that do not contain matching parameters will be represented by an empty hash table.

   Filtering of parameters can be done on the following meta-data:
   - attributes (counter, instance, key, mutable, persistent, private, protected, read-only, template, unique, volatile)
   - flags
   - name
   - type_id
   - type_name
   - validate
   - value

   A filter is an boolean expression in string format

   Filter expression example:
   @code
   "attributes.persistent==true && 'usersetting' in flags"
   @endcode

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t
   @param object the fixed object path part, without any expressions or wildcards
   @param search_path the part of the path containing the search expressions or wildcards, relative to object
   @param depth the number of levels in the object tree hierarchy that must be returned, relative to the matching objects
   @param access can be set to amxd_dm_access_public (0) or amxd_dm_access_protected (1). When set to amxd_access_public
                 no protected objects or parameters must be returned
   @param ret the variant that will contain the final result of the get
   @param timeout time in seconds to wait for the reply

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_get_filtered_t) (void* const ctx,
                                        const char* object,
                                        const char* search_path,
                                        const char* filter,
                                        int32_t depth,
                                        uint32_t access,
                                        amxc_var_t* ret,
                                        int timeout);

/**
   @ingroup amxb_be_intf
   @brief
   Performs a set operation on one or more objects in the data model tree.

   A set changes parameter values of one or more objects. The path types that
   must be supported are:
   - object paths, using index addressing and key addressing
   - search paths and wildcard paths

   If a path is a key addressing path, search path or wildcard path the fixed part
   of the path will be provided in the argument object, the part containing
   the search expressions or wildcards is passed in the argument search_path.

   Examples:
   @code
   // Assume this path
   "Device.IP.Interface.[Type=='Normal'].IPv4Address.[AddressingType=='Static']."
   // object = "Device.IP.Interface."
   // search_path = "[Type=='Normal'].IPv4Address.[AddressingType=='Static']."

   // Assume this path
   "Phonebook.Contact.*.FirstName"
   // object = "Phonebook.Contact."
   // search_path = "*"
   @endcode

   It is up to the back-end implementation to only set the parameters of the matching
   objects. How this is done is highly depending on the used bus system. It could be
   that the used bus system has support for filtering, it could be that the bus system
   doesn't support filtering, in the last case the back-end implementation must
   make sure that only matching objects are changed.

   The result of the set must be put in the ret variant. The ret variant should
   contain at top level an array, which must contain at index 0 a hash table variant.
   The hash table variant must contain the path of the objects that were changed
   as key, the value is a hash table containing the changed parameters, the name
   as key and the new set value as the value.

   Example:
   When changing all "LastNames" to "Ambiorix" of all contacts using search path
   "Phonebook.Contact.*" the return value could be
   @code{.c}
   [
       Phonebook.Contact.1. = {
           LastName = "Ambiorix"
       },
       Phonebook.Contact.2. = {
           LastName = "Ambiorix"
       },
       Phonebook.Contact.3. = {
           LastName = "Ambiorix"
       }
   ]
   @endcode

   Two hash tables can be provided containing parameters that must be changed.
   The first is passed in the values argument and are the parameters that must be set
   (mandatory parameters), the second is passed in the ovalues argument and are
   the optional parameters. If setting of optional parameters is failing the
   function should not fail.

   When the flags argument, which is a bitmap, contains AMXB_FLAG_PARTIAL and a set
   of one or more parameters fails, none of the parameters should be changed for the object
   and the result variant must contain for the failed parameter the error code and
   if it was optional or required.

   Example:
   @code
   [
       Phonebook.Contact.1. = {
           LastName = {
               error_code = 10,
               required = true
           }
       }
   ]
   @endcode

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t
   @param object the fixed object path part, without any expressions or wildcards
   @param search_path the part of the path containing the search expressions or wildcards, relative to object
   @param flags a bitmap, only AMXB_FLAG_PARTIAL should be taken into account, all other flags must be ignored
   @param values hash table containing all required parameters
   @param ovalues hash table containing all optional parameters
   @param access can be set to amxd_dm_access_public (0) or amxd_dm_access_protected (1). When set to amxd_access_public
                 no protected objects or parameters must be returned
   @param ret the variant that will contain the final result of the set
   @param timeout time in seconds to wait for the reply

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_set_t) (void* const ctx,
                               const char* object,
                               const char* search_path,
                               uint32_t flags,
                               amxc_var_t* values,
                               amxc_var_t* ovalues,
                               uint32_t access,
                               amxc_var_t* ret,
                               int timeout);

/**
   @ingroup amxb_be_intf
   @brief
   Performs an add instance operation on one multi instance object in the data model tree.

   An add instance operator creates a new instance for a multi-instance object.
   The path types that must be supported are:
   - object paths, using index addressing and key addressing

   The path must always point to a multi-instance object.

   When a search path is used, which resolves to multiple objects, the function
   must fail.

   If a path is a key addressing path the fixed part of the path will be provided
   in the argument object, the part containing the search expressions is passed
   in the argument search_path.

   Examples:
   @code
   // Assume this path
   "Device.IP.Interface.[Type=='Normal'].IPv4Address."
   // object = "Device.IP.Interface."
   // search_path = "[Type=='Normal'].IPv4Address."
   @endcode

   An index can be provided, the new instance must use this index. The function
   must fail if there is already an instance with that index. If index is set to
   0 the next available index must be used.

   A name can be provided for the new instance. If an Alias parameter is available,
   the name must be used as value for the Alias parameter. If no Alias parameter
   is available it is up to the back-end implementation to choose what to do
   with the name, it may be ignored or used as an identifier for the instance. If
   used as an identifier, it must be unique, so no other instance may exists with
   the same name.

   When key parameters are defined, all values for the key parameters must be provided
   in the values argument, the function must fail when not all key parameters
   have a value. The back-end implementation must ensure that the key rules are applied.
   All unique keys must be unique, so no other instance can exist with the same
   values. Combined keys must also be unique over all instances.

   The result of the add instance operation must be provided in the ret variant.
   This variant must be a variant containing an array, the first element in this
   array must be a hash table containing the index and the name of the newly created
   instance, the full path (index based) and the object path (name based),
   all key parameters and their values

   Example of a result varian:
   @code
    [
        {
            index = 2,
            name = "cpe-Info-2",
            object = "Greeter.History.1.Info.cpe-Info-2.",
            parameters = {
                Alias = "cpe-Info-2"
            },
            path = "Greeter.History.1.Info.2."
        }
    ]
   @endcode

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t
   @param object the fixed object path part, without any expressions or wildcards
   @param search_path the part of the path containing the search expressions or wildcards, relative to object
   @param index The index of the new instance, when set to 0 the next available index must be used.
   @param name The name of the new created instance, if Alias parameter is available, it must be set as the Alias value
   @param values hash table containing all parameter values for the new instance, all key parameters must be provided
   @param access can be set to amxd_dm_access_public (0) or amxd_dm_access_protected (1). When set to amxd_access_public
                 no protected objects or parameters must be returned
   @param ret the variant that will contain the final result of the add
   @param timeout time in seconds to wait for the reply

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_add_t) (void* const ctx,
                               const char* object,
                               const char* search_path,
                               uint32_t index,
                               const char* name,
                               amxc_var_t* values,
                               uint32_t access,
                               amxc_var_t* ret,
                               int timeout);

/**
   @ingroup amxb_be_intf
   @brief
   Performs a delete instance operation on one object in the data model tree.

   A delete instance operator removes an instance of a multi-instance object.
   The path types that must be supported are:
   - object paths, using index addressing and key addressing
   - search paths and wildcard paths

   The path must point to a multi-instance object or instance objects.

   When a search path is used, which resolves to multiple multi-instance objects, the function
   must fail. When the search path resolves to multiple instance objects, all
   of them must be deleted.

   If a path is a key addressing path the fixed part of the path will be provided
   in the argument object, the part containing the search expressions is passed
   in the argument search_path.

   Examples:
   @code
   // Assume this path
   "Device.IP.Interface.[Type=='Normal'].IPv4Address."
   // object = "Device.IP.Interface."
   // search_path = "[Type=='Normal'].IPv4Address."
   @endcode

   If the path is pointing to an instance object, that instance must be removed. In this
   case the index or name arguments must be ignored.

   When the path is pointing to a multi-instance object then either an index or
   name must be provided. The instance of the multi-instance object with the given
   index or name must be removed.

   If a name is provided and the instance objects contain an Alias parameter, the
   instance where the value of the Alias parameter is matching the name, must be deleted.

   When both an index and name are provided, it is up to the back-end implementation
   to decide what has precedence.

   The result variant (ret) must contain the paths of all deleted objects. This
   includes all objects that are available under the deleted instance

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t
   @param object the fixed object path part, without any expressions or wildcards
   @param search_path the part of the path containing the search expressions or wildcards, relative to object
   @param index The index of the instance that must be deleted.
   @param name The name (Alias) of the instance that must be deleted
   @param access can be set to amxd_dm_access_public (0) or amxd_dm_access_protected (1). When set to amxd_access_public
                 no protected objects or parameters must be returned
   @param ret the variant that will contain the final result of the delete
   @param timeout time in seconds to wait for the reply

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_del_t) (void* const ctx,
                               const char* object,
                               const char* search_path,
                               uint32_t index,
                               const char* name,
                               uint32_t access,
                               amxc_var_t* ret,
                               int timeout);

/**
   @ingroup amxb_be_intf
   @brief
   Performs a get supported data model operation on a data model (sub-)tree.

   The Supported Data Model represents the complete set of Service Elements it is capable of exposing.

   The get supported data model operation is different from the other operators as
   it only returns information about the supported objects.

   This means that path names to multi-instance objects only address the object
   itself and not the instances of the multi-instance objects.

   Path names that contain multi-instance objects in the path name use the
   "{i}" placeholder where normally an instance index is used.

   The paths that are supported are:
   - supported data model paths

   If the provided path is a supported path with "{i}" delimiters, the part before
   the delimiter will be provided as the object and the part starting from the
   delimiter will be provided as the search_path.

   Examples:
   @code
   // Assume this path
   "Device.IP.Interface.{i}.IPv4Address.{i}."
   // object = "Device.IP.Interface."
   // search_path = "{i}.IPv4Address.{i}."
   @endcode

   The result variant (retval) must contain the paths of all supported objects
   in supported data model notation. For each supported object a list
   of the supported RPC methods (commands) and a list of all supported parameters
   must be returned. For multi-instance objects the access field must indicate
   if a client can add or delete instances (access = 1), for parameters the
   access field must indicate that a client can change the value (access = 1).

   Example of a return variant:
   @code
   [
      {
          Phonebook.Contact.{i}.PhoneNumber.{i}. = {
              access = 1
              is_multi_instance = true,
              supported_commands = [
              ],
              supported_params = [
                  {
                      access = 1
                      param_name = "Phone",
                  }
              ],
          }
      }
   ]
   @endcode

   The flags argument indicates what must be returned in the retval variant, this
   argument is a bitmap of or'ed flags:
   - AMXB_FLAG_FUNCTIONS - a list of supported RPC methods (commands) must be returned
   - AMXB_FLAG_PARAMETERS - a list of supported parameters must be returned
   - AMXB_FLAG_EVENTS - a list of supported events must be returned
   - AMXB_FLAG_FIRST_LVL - ony the first level, no sub-objects.

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t
   @param object the fixed object path part, without any {i} delimiters
   @param search_path the part of the path starting from the {i} delimiter
   @param flags A bitmap of or'ed flags: AMXB_FLAG_FUNCTIONS, AMXB_FLAG_PARAMETERS, AMXB_FLAG_FIRST_LVL, AMXB_FLAG_EVENTS
   @param retval the variant that will contain the final result of the get supported data model
   @param timeout time in seconds to wait for the reply

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_get_supported_t) (void* const ctx,
                                         const char* object,
                                         const char* search_path,
                                         uint32_t flags,
                                         amxc_var_t* retval,
                                         int timeout);

typedef int (* amxb_be_describe_t) (void* const ctx,
                                    const char* object,
                                    const char* search_path,
                                    uint32_t flags,
                                    uint32_t access,
                                    amxc_var_t* retval,
                                    int timeout);

typedef int (* amxb_be_list_t) (void* const ctx,
                                const char* object,
                                uint32_t flags,
                                uint32_t access,
                                amxb_request_t* request);

typedef int (* amxb_be_wait_for_fn_t) (void* const ctx,
                                       const char* object);

typedef uint32_t (* amxb_be_capabilities_fn_t) (void* const ctx);

typedef bool (* amxb_be_has_fn_t) (void* const ctx,
                                   const char* object);

/**
   @ingroup amxb_be_intf
   @brief
   Performs a get instances data model operation on multi-instance objects.

   The get instances takes a path name to an object and requests the instances
   of that object that exist and possibly any multi-instance sub-objects that exist
   as well as their instances. This is used for getting a quick map of the
   multi-instance objects and their (unique) key parameters, so that they can be
   addressed and manipulated later.

   @param ctx an opaque pointer to some data, this pointer was returned by
              @ref amxb_be_connect_fn_t or @ref amxb_be_accept_fn_t
   @param object the fixed object path part, without any expressions or wildcards
   @param search_path the part of the path containing the search expressions or wildcards, relative to object
   @param depth The depth relative to the requested object
   @param access can be set to amxd_dm_access_public (0) or amxd_dm_access_protected (1). When set to amxd_access_public
                 no protected objects must be returned
   @param ret the variant that will contain the final result of the get instances
   @param timeout time in seconds to wait for the reply

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_get_instances_t) (void* const ctx,
                                         const char* object,
                                         const char* search_path,
                                         int32_t depth,
                                         uint32_t access,
                                         amxc_var_t* ret,
                                         int timeout);


//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
/**
   @ingroup amxb_be_intf
   @brief
   Passes a hash table variant containing configuration options to the back-end.

   In some cases it must be possible for the top-level service or application
   implementation to pass configuration options to the back-end.

   Which options are available, depends on the back-end implementation. The
   documentation of the back-end must clearly specify which options are available,
   which values are valid, and which effects these configuration options have.

   @param configuration a variant containing a hash table, where the keys are the option names, and the values are
                        the setting.

   @return
   The function returns 0 when successful, any other value indicates an error.
 */
typedef int (* amxb_be_set_config_t) (amxc_var_t* const configuration);
//-----------------------------------------------------------------------------

/**
   @ingroup amxb_be_intf
   @brief
   The back-end interface structure.

   Each back-end must provide exactly one instance of this structure.

   All mandatory function pointers must be set to a valid function, and must
   match the function signature as defined.

   Optional functions may be set to NULL pointer.
 */
struct _amxb_be_funcs {
    amxc_htable_it_t it;                      /**< Reserved for internal use only */
    void* handle;                             /**< Reserved for internal use only */
    amxc_llist_t connections;                 /**< Reserved for internal use only */
    const char* name;                         /**< The back-end name, used as identifier, must be unique */
    size_t size;                              /**< The size of the structure, must be set to sizeof(amxb_be_funcs_t) */
    amxb_be_connect_fn_t connect;             /**< Mandatory: Opens a bus connection or connects to a socket, see @ref amxb_be_connect_fn_t */
    amxb_be_disconnect_fn_t disconnect;       /**< Mandatory: Closes a bus connection or disconnects from a socket, see @ref amxb_be_disconnect_fn_t */
    amxb_be_get_fd_fn_t get_fd;               /**< Mandatory: Returns the file descriptor that needs to be monitored, see @ref amxb_be_get_fd_fn_t */
    amxb_be_read_fn_t read;                   /**< Mandatory: Reads incoming messages and handle them, see @ref amxb_be_read_fn_t */
    amxb_be_new_invoke_fn_t new_invoke;       /**< Optional: Updates the invoke data, @see @ref amxb_be_new_invoke_fn_t */
    amxb_be_free_invoke_fn_t free_invoke;     /**< Mandatory if new_invoke is implemented and allocates memory: frees memory allocated by new_invoke implementation */
    amxb_be_invoke_fn_t invoke;               /**< Mandatory: Calls a RPC method and waits for result, see @ref amxb_be_invoke_fn_t */
    amxb_be_async_invoke_fn_t async_invoke;   /**< Optional: Calls a RPC method and returns immediately, see @ref amxb_be_invoke_fn_t */
    amxb_be_close_request_fn_t close_request; /**< Optional: Closes or cancels a pending async RPC, see @ref amxb_be_close_request_fn_t */
    amxb_be_wait_request_fn_t wait_request;   /**< Optional: Wait for async RPC to complete, see @ref amxb_be_wait_request_fn_t */
    amxb_be_subscribe_fn_t subscribe;         /**< Optional: Creates/opens a subscription for receiving events/notifications, see @ref amxb_be_subscribe_fn_t */
    amxb_be_unsubscribe_fn_t unsubscribe;     /**< Optional: Removes/closes a subscription, see @ref amxb_be_unsubscribe_fn_t */
    amxb_be_free_fn_t free;                   /**< Mandatory: Frees allocated memory for a bus connection, see @ref amxb_be_free_fn_t */
    amxb_be_register_fn_t register_dm;        /**< Optional: Registers an ambiorix data model to the bus system, see @ref amxb_be_register_fn_t */
    amxb_be_get_t get;                        /**< Optional: Performs USP like get operator on data model, see @ref amxb_be_get_t */
    amxb_be_set_t set;                        /**< Optional: Performs USP like set operator on data model, see @ref amxb_be_set_t */
    amxb_be_add_t add;                        /**< Optional: Performs USP like add operator on data model, see @ref amxb_be_add_t */
    amxb_be_del_t del;                        /**< Optional: Performs USP like del operator on data model, see @ref amxb_be_del_t */
    amxb_be_get_supported_t get_supported;    /**< Optional: Performs USP like get supported data model operator, see @ref amxb_be_get_supported_t */
    amxb_be_set_config_t set_config;          /**< Optional: Makes it possible to pass configuration options to the back-end, see @ref amxb_be_set_config_t */
    amxb_be_describe_t describe;
    amxb_be_list_t list;
    amxb_be_listen_fn_t listen; /**< Optional: Creates a listen socket, see @ref amxb_be_listen_fn_t */
    amxb_be_accept_fn_t accept; /**< Mandatory when listen is set, otherwise optional: accepts or drops incoming connections, see @ref amxb_be_accept_fn_t */
    amxb_be_read_raw_fn_t read_raw;
    amxb_be_wait_for_fn_t wait_for;
    amxb_be_capabilities_fn_t capabilities;
    amxb_be_has_fn_t has;
    amxb_be_get_instances_t get_instances;    /**< Optional: Performs USP like get instances operator on data model, see @ref amxb_be_get_instances_t */
    amxb_be_get_filtered_t get_filtered;      /**< Optional: Performs a filtered get, if not available the normal get is used */
};

#ifdef __cplusplus
}
#endif

#endif // __AMXB_BE_INTF_H__
