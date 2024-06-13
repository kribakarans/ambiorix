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
#if !defined(__AMXB_PCB_H__)
#define __AMXB_PCB_H__

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <ctype.h>
#include <sys/stat.h>

#include <pcb/common/error.h>
#include <pcb/utils.h>
#include <pcb/core.h>
#include <pcb/pcb_client.h>
#include <pcb/utils/privilege.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_function.h>
#include <amxd/amxd_parameter.h>
#include <amxd/amxd_path.h>

#include <amxb/amxb_be.h>
#include <amxb/amxb_operators.h>
#include <amxb/amxb_invoke.h>

#define RESOLV_PARAMETERS     0x0001
#define RESOLV_FUNCTIONS      0x0002
//                            0x0004
#define RESOLV_OBJECTS        0x0008
#define RESOLV_INSTANCES      0x0010
//                            0x0020
#define RESOLV_TEMPLATES      0x0040
#define RESOLV_DESCRIBE       0x0080
#define RESOLV_EXACT_DEPTH    0x0100
#define RESOLV_LIST           0x0200
#define RESOLV_NO_AMX_CHECK   0x0400
#define RESOLV_NO_SINGLETON   0x0800
#define RESOLV_KEY_PARAMETERS 0x1000
//
#define RESOLV_SUB_OBJECTS    0x2000
#define RESOLV_NO_OBJ_PATH    0x4000

#define AMXB_PCB_PROTECTED_ACCESS 0x20000000
#define AMXB_PCB_AMX_EVENTING     0x40000000

#define PARAMETER_ATTR_EVENT 0x10000000   /**< parameter is marked as an event */


typedef void (* amxb_pcb_convert_t) (object_t* obj, amxc_var_t* data, void* priv);

typedef struct _amxb_pcb {
    peer_info_t* peer;
    amxp_signal_mngr_t* sigmngr;
    amxc_htable_t subscriptions;
    amxc_llist_t subscribers;
    amxd_dm_t* dm;
} amxb_pcb_t;

typedef struct _amxb_pcb_sub {
    amxc_htable_it_t it;    // for subcriptions
    amxc_llist_it_t lit;    // for subscribers
    request_t* sub_req;
    amxb_pcb_t* amxb_pcb;
    int reference;
} amxb_pcb_sub_t;

typedef struct _amxb_pcb_deferred {
    amxc_llist_t calls;
    amxc_llist_it_t it;
    request_t* req;
    uint64_t call_id;
    amxb_pcb_t* amxb_pcb;
} amxb_pcb_deferred_t;

amxb_be_info_t* amxb_be_info(void);

PRIVATE
pcb_t* amxb_pcb_ctx(void);

PRIVATE
int amxb_pcb_to_pcb_var_list(const amxc_llist_t* source,
                             variant_list_t* dest);

PRIVATE
int amxb_pcb_to_pcb_var_map(const amxc_htable_t* source,
                            variant_map_t* dest);

PRIVATE
int amxb_pcb_to_pcb_var(const amxc_var_t* source,
                        variant_t* dest);

PRIVATE
int amxb_pcb_from_pcb_var_map(variant_map_t* source,
                              amxc_var_t* dest);

PRIVATE
int amxb_pcb_from_pcb_var_list(variant_list_t* source,
                               amxc_var_t* dest);

PRIVATE
int amxb_pcb_from_pcb_var(const variant_t* source,
                          amxc_var_t* dest);

PRIVATE
int amxb_var_type_from_pcb_arg_type(const uint32_t arg_type);

PRIVATE
void* amxb_pcb_connect(const char* host,
                       const char* port,
                       const char* path,
                       amxp_signal_mngr_t* sigmngr);

PRIVATE
void* amxb_pcb_listen(const char* host,
                      const char* port,
                      const char* path,
                      amxp_signal_mngr_t* sigmngr);

PRIVATE
void* amxb_pcb_accept(AMXB_UNUSED void* const ctx,
                      amxp_signal_mngr_t* sigmngr);

PRIVATE
int amxb_pcb_disconnect(void* ctx);

PRIVATE
int amxb_pcb_get_fd(void* ctx);

PRIVATE
int amxb_pcb_read(void* ctx);

PRIVATE
void amxb_pcb_free(void* ctx);

PRIVATE
int amxb_pcb_invoke_base(request_t** pcb_req,
                         const char* object,
                         const char* method,
                         amxc_var_t* args,
                         amxb_request_t* request,
                         bool key_path);

PRIVATE
int amxb_pcb_invoke_impl(void* const ctx,
                         const char* object,
                         const char* method,
                         amxc_var_t* args,
                         amxb_request_t* request,
                         bool key_path,
                         int timeout);

PRIVATE
int amxb_pcb_invoke_root(void* const ctx,
                         const char* object,
                         const char* method,
                         amxc_var_t* exec_args,
                         amxb_request_t* request,
                         bool key_path,
                         int timeout);

PRIVATE
int amxb_pcb_invoke(void* const ctx,
                    amxb_invoke_t* invoke_ctx,
                    amxc_var_t* args,
                    amxb_request_t* request,
                    int timeout);

PRIVATE
int amxb_pcb_async_invoke(void* const ctx,
                          amxb_invoke_t* invoke_ctx,
                          amxc_var_t* args,
                          amxb_request_t* request);

PRIVATE
int amxb_pcb_wait_request(void* const ctx,
                          amxb_request_t* request,
                          int timeout);

PRIVATE
int amxb_pcb_close_request(void* const ctx,
                           amxb_request_t* request);


PRIVATE
int amxb_pcb_subscribe(void* const ctx,
                       const char* object);

PRIVATE
int amxb_pcb_unsubscribe(void* const ctx,
                         const char* object);

PRIVATE
int amxb_pcb_register(void* const ctx,
                      amxd_dm_t* const dm);

PRIVATE
void amxb_pcb_send_notification(const char* const sig_name,
                                const amxc_var_t* const data,
                                void* const priv);

// PCB Callback functions
PRIVATE
bool amxb_pcb_result_data(request_t* req,
                          reply_item_t* item,
                          pcb_t* pcb,
                          peer_info_t* from,
                          void* userdata);

PRIVATE
bool amxb_pcb_request_done(request_t* req,
                           pcb_t* pcb,
                           peer_info_t* from,
                           void* userdata);

PRIVATE
bool amxb_pcb_notification(request_t* req,
                           reply_item_t* item,
                           pcb_t* pcb,
                           peer_info_t* from,
                           void* userdata);

PRIVATE
void amxb_pcb_clear_pending(void);

PRIVATE
int amxb_pcb_get(void* const ctx,
                 const char* object,
                 const char* search_path,
                 int32_t depth,
                 uint32_t access,
                 amxc_var_t* ret,
                 int timeout);

PRIVATE
int amxb_pcb_get_filtered(void* const ctx,
                          const char* object,
                          const char* search_path,
                          const char* filter,
                          int32_t depth,
                          uint32_t access,
                          amxc_var_t* ret,
                          int timeout);
PRIVATE
int amxb_pcb_set(void* const ctx,
                 const char* object,
                 const char* search_path,
                 uint32_t flags,
                 amxc_var_t* values,
                 amxc_var_t* ovalues,
                 uint32_t access,
                 amxc_var_t* ret,
                 int timeout);

PRIVATE
int amxb_pcb_get_supported(void* const ctx,
                           const char* object,
                           const char* search_path,
                           uint32_t flags,
                           amxc_var_t* ret,
                           int timeout);

PRIVATE
int amxb_pcb_get_instances(void* const ctx,
                           const char* object,
                           const char* search_path,
                           int32_t depth,
                           uint32_t access,
                           amxc_var_t* ret,
                           int timeout);

PRIVATE
int amxb_pcb_describe(void* const ctx,
                      const char* object,
                      const char* search_path,
                      uint32_t flags,
                      uint32_t access,
                      amxc_var_t* ret,
                      int timeout);

PRIVATE
int amxb_pcb_add(void* const ctx,
                 const char* object,
                 const char* search_path,
                 uint32_t index,
                 const char* name,
                 amxc_var_t* values,
                 uint32_t access,
                 amxc_var_t* ret,
                 int timeout);

PRIVATE
int amxb_pcb_del(void* const ctx,
                 const char* object,
                 const char* search_path,
                 uint32_t index,
                 const char* name,
                 uint32_t access,
                 amxc_var_t* ret,
                 int timeout);

PRIVATE
int amxb_pcb_list(void* const ctx,
                  const char* object,
                  uint32_t flags,
                  uint32_t access,
                  amxb_request_t* request);

PRIVATE
uint32_t amxb_pcb_capabilites(void* const ctx);

PRIVATE
bool amxb_pcb_has(void* const ctx, const char* object);

// PCB helper functions
PRIVATE
amxb_bus_ctx_t* amxb_pcb_find_peer(peer_info_t* peer);

PRIVATE
uint32_t amxb_pcb_object_attributes(amxd_object_t* object);

PRIVATE
int amxb_pcb_fetch_object(pcb_t* pcb_ctx,
                          peer_info_t* peer,
                          request_t* req,
                          amxc_var_t* data,
                          amxb_pcb_convert_t fn,
                          void* priv);

PRIVATE
bool amxb_pcb_remote_is_amx(pcb_t* pcb_ctx,
                            peer_info_t* peer,
                            const char* object,
                            int* status);

PRIVATE
void amxb_pcb_cleanup_objects(amxc_var_t* resolved_table);

PRIVATE
void amxb_pcb_request_destroy(request_t* req);

PRIVATE
int amxb_pcb_resolve(amxb_pcb_t* pcb_ctx,
                     const char* object_path,
                     const char* rel_path,
                     const char* filter,
                     int32_t depth,
                     uint32_t flags,
                     bool* key_path,
                     amxc_var_t* resolved_objects);

PRIVATE
void amxb_pcb_error(peer_info_t* peer,
                    request_t* req,
                    uint32_t error,
                    const char* msg);

PRIVATE
amxd_object_t* amxb_pcb_find_object(amxb_pcb_t* amxb_pcb,
                                    request_t* req,
                                    amxc_var_t* rel_path);

PRIVATE
bool amxb_pcb_set_request_done(peer_info_t* peer,
                               request_t* req);

PRIVATE
void amxb_pcb_build_get_args(amxc_var_t* args,
                             request_t* req);

PRIVATE
void amxb_pcb_build_set_args(amxc_var_t* args,
                             request_t* req);

PRIVATE
void amxb_pcb_build_add_instance_args(amxc_var_t* args,
                                      request_t* req);

PRIVATE
void amxb_pcb_build_exec_args(amxc_var_t* args,
                              request_t* req,
                              amxc_var_t* func_def);

PRIVATE
void amxb_pcb_amx_describe_done(const amxc_var_t* const data,
                                void* const priv);

PRIVATE
amxd_status_t amxb_pcb_describe_object(amxb_pcb_deferred_t* fcall,
                                       amxd_object_t* object,
                                       amxc_var_t* describe_args,
                                       amxc_var_t* object_info);

PRIVATE
amxd_status_t amxb_pcb_amx_call(amxb_pcb_deferred_t* fcall,
                                amxd_object_t* object,
                                const char* func_name,
                                amxc_var_t* args,
                                amxc_var_t* ret,
                                amxp_deferred_fn_t cb);

PRIVATE
bool amxb_pcb_handler_common(peer_info_t* peer,
                             request_t* req,
                             amxc_var_t* args,
                             const char* method);

PRIVATE
int amxb_pcb_handle_subscription(request_t* req,
                                 const char* path,
                                 amxb_pcb_t* amxb_pcb);

PRIVATE
void amxb_amxd_status_to_pcb_error(int status,
                                   peer_info_t* peer,
                                   request_t* req,
                                   const char* info);
PRIVATE
int amxb_pcb_error_to_amxd_status(int error);

PRIVATE
void amxb_pcb_exec_return(amxd_status_t status,
                          peer_info_t* peer,
                          request_t* req,
                          amxc_var_t* args,
                          amxc_var_t* ret,
                          const char* func_name);

PRIVATE
bool amxb_pcb_fetch_function_def(peer_info_t* peer,
                                 request_t* req);

// PCB Request handlers
PRIVATE
bool amxb_pcb_get_object(peer_info_t* peer,
                         datamodel_t* datamodel,
                         request_t* req);
PRIVATE
bool amxb_pcb_get_object_v2(peer_info_t* peer,
                            datamodel_t* datamodel,
                            request_t* req);

PRIVATE
bool amxb_pcb_set_object(peer_info_t* peer,
                         datamodel_t* datamodel,
                         request_t* req);

PRIVATE
bool amxb_pcb_set_object_v2(peer_info_t* peer,
                            datamodel_t* datamodel,
                            request_t* req);

PRIVATE
bool amxb_pcb_add_instance(peer_info_t* peer,
                           datamodel_t* datamodel,
                           request_t* req);

PRIVATE
bool amxb_pcb_add_instance_v2(peer_info_t* peer,
                              datamodel_t* datamodel,
                              request_t* req);

PRIVATE
bool amxb_pcb_del_instance(peer_info_t* peer,
                           datamodel_t* datamodel,
                           request_t* req);

PRIVATE
bool amxb_pcb_del_instance_v2(peer_info_t* peer,
                              UNUSED datamodel_t* datamodel,
                              request_t* req);
PRIVATE
bool amxb_pcb_execute(peer_info_t* peer,
                      datamodel_t* datamodel,
                      request_t* req);

PRIVATE
bool amxb_pcb_execute_v2(peer_info_t* peer,
                         datamodel_t* datamodel,
                         request_t* req);

PRIVATE
bool amxb_pcb_close_request_handler(peer_info_t* peer,
                                    request_t* req);

PRIVATE
const amxc_var_t* amxb_pcb_get_config_option(const char* name);


#ifdef __cplusplus
}
#endif

#endif // __AMXB_PCB_H__

