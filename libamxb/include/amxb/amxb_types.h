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

#if !defined(__AMXB_TYPES_H__)
#define __AMXB_TYPES_H__

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef __AMXP_SIGNAL_H__
#pragma GCC error "include <amxp/amxp_signal.h> before <amxb/amxb_types.h>"
#endif

#ifndef __AMXD_TYPES_H__
#pragma GCC error "include <amxd/amxd_types.h> before <amxb/amxb_types.h>"
#endif



#define AMXB_PUBLIC         0
#define AMXB_PROTECTED      1

#define AMXB_DATA_SOCK      0
#define AMXB_LISTEN_SOCK    1

typedef struct _amxb_be_funcs amxb_be_funcs_t;
typedef struct _amxb_bus_ctx amxb_bus_ctx_t;

typedef struct _amxb_request amxb_request_t;
typedef struct _amxb_invoke amxb_invoke_t;

typedef void (* amxb_be_cb_fn_t) (const amxb_bus_ctx_t* bus_ctx,
                                  const amxc_var_t* const data,
                                  void* priv);

typedef void (* amxb_be_done_cb_fn_t) (const amxb_bus_ctx_t* bus_ctx,
                                       amxb_request_t* req,
                                       int status,
                                       void* priv);

typedef int (* amxb_be_task_fn_t) (amxb_bus_ctx_t* bus_ctx,
                                   const amxc_var_t* args,
                                   void* priv);

typedef void (* amxb_be_logger_t) (const char* bus_name,
                                   const char* dm_op,
                                   const char* path,
                                   int result);

typedef struct _amxb_version {
    int32_t major;
    int32_t minor;
    int32_t build;
} amxb_version_t;

typedef struct _amxb_be_info {
    const amxb_version_t* min_supported;
    const amxb_version_t* max_supported;
    const amxb_version_t* be_version;
    const char* name;
    const char* description;
    amxb_be_funcs_t* funcs;
} amxb_be_info_t;

typedef amxb_be_info_t* (* amxb_be_info_fn_t)(void);

struct _amxb_bus_ctx {
    amxc_llist_it_t it;
    amxc_htable_it_t hit;
    amxc_llist_t requests;
    amxc_llist_t invoke_ctxs;
    amxp_signal_mngr_t sigmngr;
    const amxb_be_funcs_t* bus_fn;
    void* bus_ctx;
    amxd_dm_t* dm;
    amxc_htable_t subscriptions;
    uint32_t access;
    uint32_t socket_type;
    amxc_llist_t client_subs;
    void* priv;
};

/**
   @ingroup amxb_invoke
   @brief
   A request structure

   Used to track asynchronous invoke see @ref amxb_async_invoke
 */
struct _amxb_request {
    amxc_llist_it_t it;           /**< Linked list iterator, used to store a request in a linked list */
    amxc_var_t* result;           /**< Pointer to a variant where the result can be stored */
    amxb_be_cb_fn_t cb_fn;        /**< Callback function, called for each reply item */
    amxb_be_done_cb_fn_t done_fn; /**< Done function, called when request has finished */
    int bus_retval;               /**< Back-end/bus return value */
    void* bus_data;               /**< Back-end private data, used by the back-end */
    void* priv;                   /**< Private data, added when the request is created */
    uint32_t flags;               /**< Request flags */
};

struct _amxb_invoke {
    amxc_llist_it_t it;
    char* object;
    char* interface;
    char* method;
    void* bus_data;
};

typedef struct _amxb_subscription {
    char* object;
    amxp_slot_fn_t slot_cb;
    void* priv;
    amxc_llist_it_t it;
} amxb_subscription_t;

#ifdef __cplusplus
}
#endif

#endif // __AMXB_TYPES_H__
