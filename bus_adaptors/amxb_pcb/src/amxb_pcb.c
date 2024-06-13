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
#include "amxb_pcb.h"
#include "amxb_pcb_version.h"

static pcb_t* pcb_ctx = NULL;
static int references = 0;
static amxc_var_t* config_opts = NULL;

static request_handlers_t amxb_pcb_request_handlers = {
    .getObject = amxb_pcb_get_object,
    .setObject = amxb_pcb_set_object,
    .createInstance = amxb_pcb_add_instance,
    .deleteInstance = amxb_pcb_del_instance,
    .findObjects = NULL,
    .executeFunction = amxb_pcb_execute,
    .closeRequest = amxb_pcb_close_request_handler,
    .notify = NULL,
    .openSession = NULL,
};

static void amxb_pcb_remove_subscriptions(UNUSED const char* key,
                                          amxc_htable_it_t* it) {
    amxb_pcb_sub_t* sub = amxc_htable_it_get_data(it, amxb_pcb_sub_t, it);
    request_setData(sub->sub_req, NULL);
    request_setReplyItemHandler(sub->sub_req, NULL);
    request_destroy(sub->sub_req);
    free(sub);
}

static void amxb_pcb_remove_subscribers(amxc_llist_it_t* it) {
    amxb_pcb_sub_t* sub = amxc_llist_it_get_data(it, amxb_pcb_sub_t, lit);
    amxp_slot_disconnect_with_priv(&sub->amxb_pcb->dm->sigmngr, amxb_pcb_send_notification, sub);

    free(sub);
}

static void amxb_pcb_start(void) {
    sigset_t original_mask;
    sigset_t block_mask;

    if(pcb_ctx != NULL) {
        return;
    }

    sigfillset(&block_mask);
    sigprocmask(SIG_SETMASK, &block_mask, &original_mask);

    setenv("PCB_SERIALIZERS", "libpcb_serialize_ddw.so", 1);
    connection_blockSignals(false);
    connection_enableSSL(false);
    connection_initLibrary();
    pcb_ctx = pcb_create("amxb", 0, NULL);
    pcb_setDefaultFormat(pcb_ctx,
                         SERIALIZE_FORMAT(serialize_format_default,
                                          SERIALIZE_DEFAULT_MAJOR,
                                          SERIALIZE_DEFAULT_MINOR));

    pcb_setRequestHandlers(pcb_ctx, &amxb_pcb_request_handlers);

    sigprocmask(SIG_SETMASK, &original_mask, NULL);
}

static void amxb_pcb_stop(void) {
    sigset_t original_mask;
    sigset_t block_mask;

    sigfillset(&block_mask);
    sigprocmask(SIG_SETMASK, &block_mask, &original_mask);

    pcb_destroy(pcb_ctx);
    pcb_ctx = NULL;
    connection_exitLibrary();

    sigprocmask(SIG_SETMASK, &original_mask, NULL);
}

static int amxb_pcb_set_config(amxc_var_t* const configuration) {
    struct stat sb;
    amxc_var_t* acl_dir = GETP_ARG(configuration, "acl-dir");
    bool use_async = GET_BOOL(configuration, "use-async-handlers");
    amxc_var_t* uris = GET_ARG(configuration, "uris");

    config_opts = configuration;

    if(acl_dir == NULL) {
        amxc_var_add_key(cstring_t, config_opts, "acl-dir", "/cfg/etc/acl/");
    }

    if(use_async) {
        amxb_pcb_request_handlers.getObject = amxb_pcb_get_object_v2;
        amxb_pcb_request_handlers.setObject = amxb_pcb_set_object_v2;
        amxb_pcb_request_handlers.createInstance = amxb_pcb_add_instance_v2;
        amxb_pcb_request_handlers.deleteInstance = amxb_pcb_del_instance_v2;
        amxb_pcb_request_handlers.executeFunction = amxb_pcb_execute_v2;
    }

    if((configuration != NULL) && (uris == NULL)) {
        uris = amxc_var_add_key(amxc_llist_t, configuration, "uris", NULL);
    }

    if(stat("/var/run/pcb_sys", &sb) == 0) {
        amxc_var_add(cstring_t, uris, "pcb:/var/run/pcb_sys");
    }

    return 0;
}

const amxc_var_t* amxb_pcb_get_config_option(const char* name) {
    return GET_ARG(config_opts, name);
}

void* amxb_pcb_connect(const char* host,
                       const char* port,
                       const char* path,
                       amxp_signal_mngr_t* sigmngr) {
    amxb_pcb_t* amxb_pcb = NULL;
    peer_info_t* peer = NULL;
    amxb_pcb_start();
    references++;

    if(host && *host && port && *port) {
        peer = connection_connectToTCP(pcb_connection(pcb_ctx),
                                       host,
                                       port,
                                       connection_attr_default);
    } else {
        peer = connection_connectToIPC(pcb_connection(pcb_ctx), path);
    }

    when_null(peer, exit);

    amxb_pcb = (amxb_pcb_t*) calloc(1, sizeof(amxb_pcb_t));
    if(amxb_pcb == NULL) {
        peer_delete(peer);
        goto exit;
    }

    amxc_htable_init(&amxb_pcb->subscriptions, 5);
    amxb_pcb->peer = peer;
    amxb_pcb->sigmngr = sigmngr;

exit:
    if(peer == NULL) {
        references--;
        if(references == 0) {
            amxb_pcb_stop();
        }
    }
    return amxb_pcb;
}

void* amxb_pcb_listen(const char* host,
                      const char* port,
                      const char* path,
                      amxp_signal_mngr_t* sigmngr) {
    amxb_pcb_t* amxb_pcb = NULL;
    peer_info_t* peer = NULL;
    amxb_pcb_start();
    references++;

    if(host && *host && port && *port) {
        peer = connection_listenOnTCP(pcb_connection(pcb_ctx),
                                      host,
                                      port,
                                      connection_attr_default);
    } else {
        peer = connection_listenOnIPC(pcb_connection(pcb_ctx), path);
    }

    when_null(peer, exit);

    amxb_pcb = (amxb_pcb_t*) calloc(1, sizeof(amxb_pcb_t));
    if(amxb_pcb == NULL) {
        peer_delete(peer);
        goto exit;
    }

    amxc_htable_init(&amxb_pcb->subscriptions, 5);
    amxb_pcb->peer = peer;
    amxb_pcb->sigmngr = sigmngr;

exit:
    if(peer == NULL) {
        references--;
        if(references == 0) {
            amxb_pcb_stop();
        }
    }
    return amxb_pcb;
}

void* amxb_pcb_accept(UNUSED void* const ctx,
                      amxp_signal_mngr_t* sigmngr) {
    amxb_pcb_t* amxb_pcb_listen = (amxb_pcb_t*) ctx;
    amxb_pcb_t* amxb_pcb = NULL;
    connection_info_t* pcb_con = NULL;
    connection_t* con = NULL;
    llist_iterator_t* it = NULL;
    peer_info_t* peer = NULL;

    if(!peer_handleRead(amxb_pcb_listen->peer)) {
        goto exit;
    }

    references++;
    pcb_con = pcb_connection(pcb_ctx);
    it = llist_last(&pcb_con->connections);
    con = amxc_container_of(it, connection_t, it);
    when_null(con, exit);
    peer = &con->info;

    amxb_pcb = (amxb_pcb_t*) calloc(1, sizeof(amxb_pcb_t));
    if(amxb_pcb == NULL) {
        peer_delete(peer);
        goto exit;
    }

    amxc_htable_init(&amxb_pcb->subscriptions, 5);
    amxb_pcb->peer = peer;
    amxb_pcb->sigmngr = sigmngr;
    amxb_pcb->dm = amxb_pcb_listen->dm;

exit:
    return amxb_pcb;
}

int amxb_pcb_disconnect(void* ctx) {
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;

    amxb_pcb_clear_pending();
    amxc_htable_clean(&amxb_pcb->subscriptions, amxb_pcb_remove_subscriptions);
    amxc_llist_clean(&amxb_pcb->subscribers, amxb_pcb_remove_subscribers);
    peer_close(amxb_pcb->peer);

    return 0;
}

int amxb_pcb_get_fd(void* ctx) {
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    peer_info_t* peer = amxb_pcb->peer;

    return peer_getFd(peer);
}

int amxb_pcb_read(void* ctx) {
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    peer_info_t* peer = amxb_pcb->peer;
    if(!peer_handleRead(peer)) {
        return -1;
    }

    if(peer_needRead(peer)) {
        peer_handleRead(peer);
    }

    return 0;
}

void amxb_pcb_free(void* ctx) {
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    peer_info_t* peer = amxb_pcb->peer;

    amxb_pcb_disconnect(ctx);
    peer_delete(peer);
    free(amxb_pcb);

    references--;
    if(references == 0) {
        amxb_pcb_stop();
    }

    return;
}

static void amxb_pcb_wait_for_done(UNUSED const char* const sig_name,
                                   UNUSED const amxc_var_t* const d,
                                   void* const priv) {
    amxb_pcb_sub_t* sub = (amxb_pcb_sub_t*) priv;
    amxp_slot_disconnect_with_priv(NULL, amxb_pcb_wait_for_done, sub);
    amxc_llist_it_take(&sub->lit);
    amxc_htable_it_clean(&sub->it, amxb_pcb_remove_subscriptions);
}

static bool amxb_pcb_object_available(request_t* req,
                                      reply_item_t* item,
                                      UNUSED pcb_t* pcb,
                                      UNUSED peer_info_t* from,
                                      void* userdata) {
    amxc_string_t sig_name;
    amxb_pcb_sub_t* sub = (amxb_pcb_sub_t*) userdata;

    amxc_string_init(&sig_name, 0);

    if(reply_item_type(item) == reply_type_object) {
        amxp_slot_disconnect_with_priv(NULL, amxb_pcb_wait_for_done, sub);

        amxc_string_setf(&sig_name, "wait:%s.", request_path(req));
        amxp_sigmngr_emit_signal(NULL, amxc_string_get(&sig_name, 0), NULL);

        amxc_htable_it_clean(&sub->it, amxb_pcb_remove_subscriptions);
    } else if(reply_item_type(item) == reply_type_notification) {
        notification_t* notify = reply_item_notification(item);
        when_false(strcmp(notification_name(notify), "add") == 0, exit);

        amxp_slot_disconnect_with_priv(NULL, amxb_pcb_wait_for_done, sub);
        amxc_string_setf(&sig_name, "wait:%s.", request_path(req));
        amxp_sigmngr_emit_signal(NULL, amxc_string_get(&sig_name, 0), NULL);

        amxc_htable_it_clean(&sub->it, amxb_pcb_remove_subscriptions);
    }

exit:
    amxc_string_clean(&sig_name);
    return true;
}

static int amxb_pcb_wait_for(void* const ctx, const char* object) {
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    int retval = -1;
    peer_info_t* peer = NULL;
    request_t* wait_req = NULL;
    amxd_path_t path;
    uint32_t flags = request_notify_all | request_wait | request_no_object_caching;
    amxb_pcb_sub_t* sub = NULL;
    amxc_string_t sig_name;

    amxc_string_init(&sig_name, 0);
    amxd_path_init(&path, NULL);
    amxd_path_setf(&path, true, "%s", object);

    when_null(amxb_pcb, exit);

    if(!amxd_path_is_instance_path(&path)) {
        flags |= request_common_path_key_notation;
    }

    peer = amxb_pcb->peer;
    wait_req = request_create_getObject(object, 0, flags);

    sub = (amxb_pcb_sub_t*) calloc(1, sizeof(amxb_pcb_sub_t));
    when_null(sub, exit);
    sub->sub_req = wait_req;
    sub->amxb_pcb = amxb_pcb;
    amxc_htable_insert(&amxb_pcb->subscriptions, object, &sub->it);

    request_setReplyItemHandler(wait_req, amxb_pcb_object_available);
    request_setData(wait_req, sub);
    when_false(pcb_sendRequest(pcb_ctx, peer, wait_req), exit);

    amxp_slot_connect(NULL, "wait:cancel", NULL, amxb_pcb_wait_for_done, sub);
    amxc_string_setf(&sig_name, "wait:%s", amxd_path_get(&path, AMXD_OBJECT_TERMINATE));
    amxp_slot_connect(NULL, amxc_string_get(&sig_name, 0), NULL, amxb_pcb_wait_for_done, sub);

    retval = 0;

exit:
    amxd_path_clean(&path);
    amxc_string_clean(&sig_name);
    return retval;
}


static amxb_be_funcs_t amxb_pcb_impl = {
    .it = { .ait = NULL, .key = NULL, .next = NULL },
    .handle = NULL,
    .connections = { .head = NULL, .tail = NULL },
    .name = "pcb",
    .size = sizeof(amxb_be_funcs_t),
    .connect = amxb_pcb_connect,
    .disconnect = amxb_pcb_disconnect,
    .get_fd = amxb_pcb_get_fd,
    .read = amxb_pcb_read,
    .new_invoke = NULL,
    .free_invoke = NULL,
    .invoke = amxb_pcb_invoke,
    .async_invoke = amxb_pcb_async_invoke,
    .close_request = amxb_pcb_close_request,
    .wait_request = amxb_pcb_wait_request,
    .subscribe = amxb_pcb_subscribe,
    .unsubscribe = amxb_pcb_unsubscribe,
    .free = amxb_pcb_free,
    .register_dm = amxb_pcb_register,
    .get = amxb_pcb_get,
    .set = amxb_pcb_set,
    .add = amxb_pcb_add,
    .del = amxb_pcb_del,
    .get_supported = amxb_pcb_get_supported,
    .set_config = amxb_pcb_set_config,
    .describe = amxb_pcb_describe,
    .list = amxb_pcb_list,
    .listen = amxb_pcb_listen,
    .accept = amxb_pcb_accept,
    .read_raw = NULL,
    .wait_for = amxb_pcb_wait_for,
    .capabilities = amxb_pcb_capabilites,
    .has = amxb_pcb_has,
    .get_instances = amxb_pcb_get_instances,
    .get_filtered = amxb_pcb_get_filtered,
};

static amxb_version_t sup_min_lib_version = {
    .major = 4,
    .minor = 8,
    .build = 0
};

static amxb_version_t sup_max_lib_version = {
    .major = 4,
    .minor = -1,
    .build = -1
};

static amxb_version_t pcb_be_version = {
    .major = AMXB_PCB_VERSION_MAJOR,
    .minor = AMXB_PCB_VERSION_MINOR,
    .build = AMXB_PCB_VERSION_BUILD,
};

static amxb_be_info_t amxb_pcb_be_info = {
    .min_supported = &sup_min_lib_version,
    .max_supported = &sup_max_lib_version,
    .be_version = &pcb_be_version,
    .name = "pcb",
    .description = "AMXB Backend for PCB (SAH-SOP)",
    .funcs = &amxb_pcb_impl,
};

amxb_be_info_t* amxb_be_info(void) {
    return &amxb_pcb_be_info;
}

pcb_t* amxb_pcb_ctx(void) {
    return pcb_ctx;
}

amxb_bus_ctx_t* amxb_pcb_find_peer(peer_info_t* peer) {
    amxb_bus_ctx_t* amxb_bus_ctx = NULL;
    amxb_pcb_t* amxb_pcb = NULL;
    amxc_llist_for_each(it, (&amxb_pcb_impl.connections)) {
        amxb_bus_ctx = amxc_llist_it_get_data(it, amxb_bus_ctx_t, it);
        amxb_pcb = (amxb_pcb_t*) amxb_bus_ctx->bus_ctx;
        if(peer == amxb_pcb->peer) {
            break;
        }
        amxb_pcb = NULL;
    }

    return amxb_bus_ctx;
}
