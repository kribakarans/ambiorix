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

#if !defined(__AMXB_INVOKE_H__)
#define __AMXB_INVOKE_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxb/amxb_types.h>

/**
   @file
   @brief
   Ambiorix Bus Agnostic Remote Function Invocation API
 */

/**
   @ingroup amxb_baapi
   @defgroup amxb_invoke Remote Function Invoke
 */


/**
   @ingroup amxb_invoke
   @brief
   Prepares a remote function invocation

   Allocates a remote function invoke context. Depending on the bus specific
   backend used, this function prepares the remote function invoke.

   The created function invoke context can be re-used many times to call the
   same function.

   @note
   This function allocates memory for the function invoke context. The
   context can be freed using @ref amxb_free_invoke

   @warning
   When the connection represented by the bus context (amxb_bus_ctx) is
   closed, the allocated invoke_ctx is removed and can not be used anymore.

   @param invoke_ctx The place where the function invoke context is stored
   @param ctx the bus connection context
   @param object the path to the object (mandatory)
   @param interface the interface name, that contains the function (optional)
                    when not used provide a NULL pointer
   @param method the name of the function that is going to be called (mandatory)

   @return
   - @ref AMXB_STATUS_OK when function invoke context is created
   - @ref AMXB_ERROR_UNKNOWN when invalid arguments are passed or
                             when failed to allocate memory
 */
int amxb_new_invoke(amxb_invoke_t** invoke_ctx,
                    amxb_bus_ctx_t* const ctx,
                    const char* object,
                    const char* interface,
                    const char* method);

/**
   @ingroup amxb_invoke
   @brief
   Deletes a function invoke context, and frees allocated memory

   Frees the allocated memory for the function invoke context.

   @param invoke_ctx The function invoke context, is reset to NULL
 */
void amxb_free_invoke(amxb_invoke_t** invoke_ctx);

/**
   @ingroup amxb_invoke
   @brief
   Invokes a remote function, as defined by the function invoke context

   Before invoking a function, an function invoke context must be created using
   @ref amxb_new_invoke.

   This method is blocking, it will return when the remote function call is
   done or when it has failed.

   The arguments passed must be in a amxc variant of type AMXC_VAR_ID_HTABLE.
   The order of the arguments is not important.

   The return value must be an initialized amxc variant, the type must not be
   set.

   Optionally a callback function can be given, which is called for each
   individual return value. The private data will be passed to the callback
   function.

   As this function is blocking, a time out in seconds, must be provided. If
   the remote function call is not done in the given timeout, the function
   call (on the client side) is aborted.

   @param invoke_ctx The function invoke context as created with @ref amxb_new_invoke
   @param args the function arguments in a amxc variant htable type
   @param ret when the remote function call is done, it will contain an array of
            return values.
   @param fn a callback function (optional, can be NULL).
   @param priv private data that will be passed to the callback function (optional,
               can be NULL)
   @param timeout in seconds

   @return
   - @ref AMXB_STATUS_OK remote function call done and all ok
   - @ref AMXB_ERROR_NOT_SUPPORTED_OP the backend does not support remote
                                      function calls
   - @ref AMXB_ERROR_UNKNOWN when invalid arguments are passed
   - Or any bus related error. See AMXB_ERROR_BUS_XXXX
 */
int amxb_invoke(amxb_invoke_t* invoke_ctx,
                amxc_var_t* args,
                amxc_var_t* ret,
                amxb_be_cb_fn_t fn,
                void* priv,
                int timeout);

/**
   @ingroup amxb_invoke
   @brief
   Invokes a remote function, as defined by the function invoke context

   Before invoking a function, an function invoke context must be created using
   @ref amxb_new_invoke.

   This method returns immediately, without waiting for the result
   (asynchronous I/O), to be able to receive the result of remote function call
   it is recommended that you use an eventloop.

   The arguments passed must be in a amxc variant of type AMXC_VAR_ID_HTABLE.
   The order of the arguments is not important.

   A callback function can be given, which is called for each
   individual return value. The private data will be passed to the callback
   function. If no callback function is given, the return values can be fetched
   from the request context, see @ref _amxb_request

   A done callback function can be given, which is called when the remote
   function call is finished. The private data will be passed to the done
   callback function. It is recommended to provide a done function, unless you
   are not interested when the remote function is done.

   @note
   This function allocates memory to store the request information.
   When the request is not needed anymore it must be freed using
   @ref amxb_close_request.

   @warning
   When the connection represented by the bus context (amxb_bus_ctx) is
   closed, the allocated request is removed and can not be used anymore.

   @param invoke_ctx The function invoke context as created with @ref amxb_new_invoke
   @param args the function arguments in a amxc variant htable type
   @param fn a callback function
   @param done_fn a done callback function
   @param priv private data that will be passed to the callback function (optional,
               can be NULL)
   @param req the request context.

   @return
   - @ref AMXB_STATUS_OK remote function is started
   - @ref AMXB_ERROR_NOT_SUPPORTED_OP the backend does not support remote
                                      asynchronous function calls
   - @ref AMXB_ERROR_UNKNOWN when invalid arguments are passed
   - Or any bus related error. See AMXB_ERROR_BUS_XXXX
 */
int amxb_async_invoke(amxb_invoke_t* invoke_ctx,
                      amxc_var_t* args,
                      amxb_be_cb_fn_t fn,
                      amxb_be_done_cb_fn_t done_fn,
                      void* priv,
                      amxb_request_t** req);

/**
   @ingroup amxb_invoke
   @brief
   Waits for an asynchronous remote function invoke to finish

   Waits until a remote function invoke, created with @ref amxb_async_invoke
   is finished.

   When a done callback was provided, the done callback will be called before
   this function returns, unless a timeout occurs.

   @param req The remote function invoke request
   @param timeout in seconds

   @return
   - @ref AMXB_STATUS_OK when remote function is finished
   - @ref AMXB_ERROR_UNKNOWN when invalid arguments are passed
 */
int amxb_wait_for_request(amxb_request_t* req, int timeout);

/**
   @ingroup amxb_invoke
   @brief
   Allocates an empty amxb_request_t

   Allocates and initializes an empty amxb_request_t.

   This function is mainly intended for use in back-end implementations.
   Client applications should use @ref amxb_async_invoke to allocate and
   initialize such a structure.

   @param request the request pointer to initialize

   @return
   - @ref AMXB_STATUS_OK when remote function is finished
   - @ref AMXB_ERROR_UNKNOWN when invalid arguments are passed
 */
int amxb_request_new(amxb_request_t** request);

/**
   @ingroup amxb_invoke
   @brief
   Get the bus context of the request if any

   Returns the bus context for which the request was created.

   @param request the request pointer

   @return
   returns the bus context, NULL if the request is not associated with
   a bus context.
 */
amxb_bus_ctx_t* amxb_request_get_ctx(amxb_request_t* request);

/**
   @ingroup amxb_invoke
   @brief
   Closes a previously create remote function called context

   Deletes and frees the request context created with @ref amxb_async_invoke.

   When the context is deleted, none of the callback functions will be called,
   not event when the remote function call was not yet finished.

   @param req The remote function invoke request

   @return
   - @ref AMXB_STATUS_OK when remote function is finished
   - @ref AMXB_ERROR_UNKNOWN when invalid arguments are passed
 */
int amxb_close_request(amxb_request_t** req);

#ifdef __cplusplus
}
#endif

#endif // __AMXB_INVOKE_H__
