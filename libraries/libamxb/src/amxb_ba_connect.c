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

#include <errno.h>
#include <fcntl.h>

#include <uriparser/Uri.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>

#include <amxb/amxb_be_intf.h>
#include <amxb/amxb.h>

#include "amxb_priv.h"

static amxc_htable_t uri_bus_ctxs;

static int amxb_uri_part_to_string(amxc_string_t* buffer,
                                   UriTextRangeA* tr) {

    return amxc_string_append(buffer, tr->first, tr->afterLast - tr->first);
}

static int amxb_uri_path_to_string(amxc_string_t* buffer,
                                   UriPathSegmentA* ps) {

    const char* sep = "/";
    while(ps) {
        amxc_string_append(buffer, sep, strlen(sep));
        amxb_uri_part_to_string(buffer, &ps->text);
        sep = "/";
        ps = ps->next;
    }

    return 0;
}

static int amxb_uri_parse(const char* uri,
                          char** scheme,
                          char** host,
                          char** port,
                          char** path) {
    int retval = -1;
    UriUriA parsed_uri;
    amxc_string_t uri_part;
    amxc_string_init(&uri_part, 0);

    when_failed(uriParseSingleUriA(&parsed_uri, uri, NULL), exit);
    amxb_uri_part_to_string(&uri_part, &parsed_uri.scheme);
    *scheme = amxc_string_take_buffer(&uri_part);
    when_null(*scheme, exit_clean);
    amxb_uri_part_to_string(&uri_part, &parsed_uri.hostText);
    *host = amxc_string_take_buffer(&uri_part);
    amxb_uri_part_to_string(&uri_part, &parsed_uri.portText);
    *port = amxc_string_take_buffer(&uri_part);
    amxb_uri_path_to_string(&uri_part, parsed_uri.pathHead);
    *path = amxc_string_take_buffer(&uri_part);

    retval = 0;

exit_clean:
    uriFreeUriMembersA(&parsed_uri);

exit:
    amxc_string_clean(&uri_part);
    return retval;
}

static int amxb_bus_ctx_init(amxb_bus_ctx_t** ctx, amxb_be_funcs_t* fns) {
    int retval = -1;

    *ctx = (amxb_bus_ctx_t*) calloc(1, sizeof(amxb_bus_ctx_t));
    when_null(*ctx, exit);

    (*ctx)->bus_fn = fns;
    amxp_sigmngr_init(&(*ctx)->sigmngr);
    amxc_htable_init(&(*ctx)->subscriptions, 5);
    amxc_llist_init(&(*ctx)->client_subs);
    (*ctx)->access = AMXB_PROTECTED;
    (*ctx)->socket_type = AMXB_DATA_SOCK;

    retval = 0;
exit:
    return retval;
}

static int amxb_bus_ctx_create(amxb_bus_ctx_t** ctx,
                               amxb_be_funcs_t** fns,
                               const char* uri,
                               char** scheme,
                               char** host,
                               char** port,
                               char** path) {
    int retval = -1;

    when_null(ctx, exit);
    when_not_null(*ctx, exit);
    if(amxb_uri_parse(uri, scheme, host, port, path) != 0) {
        retval = AMXB_ERROR_INVALID_URI;
        goto exit;
    }

    *fns = amxb_be_find(*scheme);
    if(*fns == NULL) {
        retval = AMXB_ERROR_NOT_SUPPORTED_SCHEME;
        goto exit;
    }

    retval = amxb_bus_ctx_init(ctx, *fns);

exit:
    return retval;
}

static int amxb_bus_ctx_be_init(amxb_bus_ctx_t* ctx,
                                amxb_be_funcs_t* fns,
                                amxb_be_connect_fn_t fn,
                                const char* uri,
                                const char* host,
                                const char* port,
                                const char* path) {
    int retval = -1;

    ctx->bus_ctx = fn(host, port, path, &ctx->sigmngr);
    if(ctx->bus_ctx == NULL) {
        retval = AMXB_ERROR_BACKEND_FAILED;
    } else {
        amxc_llist_append(&fns->connections, &ctx->it);
        amxc_htable_insert(&uri_bus_ctxs, uri, &ctx->hit);
        retval = 0;
    }

    return retval;
}

static void amxb_free_request(amxc_llist_it_t* it) {
    amxb_req_t* req = amxc_container_of(it, amxb_req_t, it);
    if(req->closed && !req->in_flight) {
        free(req);
    }
}

int amxb_connect_intf(amxb_bus_ctx_t** ctx, const char* uri, const char* intf) {
    int retval = -1;
    amxb_be_funcs_t* fns = NULL;
    char* scheme = NULL;
    char* host = NULL;
    char* port = NULL;
    char* path = NULL;

    retval = amxb_bus_ctx_create(ctx, &fns, uri, &scheme, &host, &port, &path);
    when_failed(retval, exit);
    if((host != NULL) && (*host != 0) && (intf != NULL) && (*intf != 0)) {
        // add the interface name/index prefixed with % to the host.
        amxc_string_t host_intf;
        amxc_string_init(&host_intf, 64);
        amxc_string_setf(&host_intf, "%s%%%s", host, intf);
        free(host);
        host = amxc_string_take_buffer(&host_intf);
        amxc_string_clean(&host_intf);
    }

    if(amxb_is_valid_be_func(fns, connect, fns->connect)) {
        retval = amxb_bus_ctx_be_init(*ctx, fns, fns->connect, uri, host, port, path);
    } else {
        retval = AMXB_ERROR_NOT_SUPPORTED_OP;
    }

    if(retval != 0) {
        amxb_free(ctx);
    }

exit:
    free(scheme);
    free(port);
    free(host);
    free(path);
    return retval;
}

int amxb_connect(amxb_bus_ctx_t** ctx, const char* uri) {
    return amxb_connect_intf(ctx, uri, NULL);
}

int amxb_listen(amxb_bus_ctx_t** ctx, const char* uri) {
    int retval = -1;
    amxb_be_funcs_t* fns = NULL;
    char* scheme = NULL;
    char* host = NULL;
    char* port = NULL;
    char* path = NULL;

    retval = amxb_bus_ctx_create(ctx, &fns, uri, &scheme, &host, &port, &path);
    when_failed(retval, exit);
    (*ctx)->socket_type = AMXB_LISTEN_SOCK;
    if(amxb_is_valid_be_func(fns, listen, fns->listen)) {
        retval = amxb_bus_ctx_be_init(*ctx, fns, fns->listen, uri, host, port, path);
    } else {
        retval = AMXB_ERROR_NOT_SUPPORTED_OP;
    }

    if(retval != 0) {
        amxb_free(ctx);
    }

exit:
    free(scheme);
    free(port);
    free(host);
    free(path);
    return retval;
}

int amxb_accept(amxb_bus_ctx_t* listen_ctx, amxb_bus_ctx_t** accepted_ctx) {
    int retval = -1;
    amxb_be_funcs_t* fns = NULL;
    const char* uri = NULL;
    char* scheme = NULL;
    char* host = NULL;
    char* port = NULL;
    char* path = NULL;

    when_null(listen_ctx, exit);
    uri = amxc_htable_it_get_key(&listen_ctx->hit);
    when_null(listen_ctx, exit);
    retval = amxb_bus_ctx_create(accepted_ctx, &fns, uri, &scheme, &host, &port, &path);
    when_failed(retval, exit);
    if(amxb_is_valid_be_func(fns, accept, fns->accept)) {
        (*accepted_ctx)->bus_ctx = fns->accept(listen_ctx->bus_ctx, &listen_ctx->sigmngr);
        if((*accepted_ctx)->bus_ctx == NULL) {
            retval = AMXB_ERROR_BACKEND_FAILED;
        } else {
            (*accepted_ctx)->dm = listen_ctx->dm;
            amxc_llist_append(&fns->connections, &(*accepted_ctx)->it);
            retval = 0;
        }
    } else {
        retval = AMXB_ERROR_NOT_SUPPORTED_OP;
    }

exit:
    free(scheme);
    free(port);
    free(host);
    free(path);
    return retval;
}

int amxb_disconnect(amxb_bus_ctx_t* ctx) {
    int retval = -1;
    const amxb_be_funcs_t* fns = NULL;

    when_null(ctx, exit);
    when_null(ctx->bus_ctx, exit_clean);

    amxb_be_cache_remove_ctx(ctx);

    amxc_llist_for_each(it, &ctx->client_subs) {
        amxb_sub_t* sub = amxc_container_of(it, amxb_sub_t, it);
        amxb_subscription_remove(&sub->data);
    }

    fns = ctx->bus_fn;
    if(amxb_is_valid_be_func(fns, disconnect, fns->disconnect)) {
        retval = fns->disconnect(ctx->bus_ctx);
    } else {
        retval = AMXB_ERROR_NOT_SUPPORTED_OP;
    }

    if(fns->free != NULL) {
        fns->free(ctx->bus_ctx);
    }

exit_clean:
    amxc_llist_clean(&ctx->requests, amxb_free_request);
    amxc_llist_clean(&ctx->invoke_ctxs, NULL);
    amxc_llist_it_take(&ctx->it);
    amxc_htable_it_clean(&ctx->hit, NULL);
    ctx->bus_ctx = NULL;
    ctx->bus_fn = NULL;
exit:
    return retval;
}

void amxb_free(amxb_bus_ctx_t** ctx) {
    when_null(ctx, exit);
    when_null(*ctx, exit);

    amxb_disconnect(*ctx);
    amxp_sigmngr_clean(&(*ctx)->sigmngr);

    amxc_htable_for_each(it, &(*ctx)->subscriptions) {
        amxp_slot_disconnect_with_priv(&(*ctx)->dm->sigmngr, amxb_dm_event_to_object_event, it);
        amxc_htable_it_clean(it, NULL);
        free(it);
    }
    amxc_htable_clean(&(*ctx)->subscriptions, NULL);

    free(*ctx);
    *ctx = NULL;

exit:
    return;
}

amxb_bus_ctx_t* amxb_find_uri(const char* uri) {
    amxc_htable_it_t* hit = amxc_htable_get(&uri_bus_ctxs, uri);
    amxb_bus_ctx_t* ctx = NULL;

    if(hit != NULL) {
        ctx = amxc_htable_it_get_data(hit, amxb_bus_ctx_t, hit);
    }
    return ctx;
}

amxc_array_t* amxb_list_uris(void) {
    amxc_array_t* keys = amxc_htable_get_sorted_keys(&uri_bus_ctxs);
    return keys;
}

int amxb_get_fd(const amxb_bus_ctx_t* const ctx) {
    int retval = -1;
    const amxb_be_funcs_t* fns = NULL;

    when_null(ctx, exit);
    when_null(ctx->bus_ctx, exit);

    fns = ctx->bus_fn;
    if(amxb_is_valid_be_func(fns, get_fd, fns->get_fd)) {
        retval = fns->get_fd(ctx->bus_ctx);
        when_true(retval < 0, exit);
    }

exit:
    return retval;
}

int amxb_read(const amxb_bus_ctx_t* const ctx) {
    int retval = -1;
    const amxb_be_funcs_t* fns = NULL;

    when_null(ctx, exit);
    when_null(ctx->bus_ctx, exit);

    fns = ctx->bus_fn;
    if(amxb_is_valid_be_func(fns, read, fns->read)) {
        retval = fns->read(ctx->bus_ctx);
    }

exit:
    return retval;
}

int amxb_read_raw(const amxb_bus_ctx_t* const ctx, void* buf, size_t count) {
    int retval = -1;
    const amxb_be_funcs_t* fns = NULL;

    when_null(ctx, exit);
    when_null(ctx->bus_ctx, exit);
    when_null(buf, exit);
    when_true(count == 0, exit);

    fns = ctx->bus_fn;
    if(amxb_is_valid_be_func(fns, read_raw, fns->read_raw)) {
        retval = fns->read_raw(ctx->bus_ctx, buf, count);
    }

exit:
    return retval;
}

CONSTRUCTOR static void amxb_initialize_connections(void) {
    amxc_htable_init(&uri_bus_ctxs, 10);
}

DESTRUCTOR static void amxb_cleanup_connections(void) {
    amxc_htable_clean(&uri_bus_ctxs, NULL);
}