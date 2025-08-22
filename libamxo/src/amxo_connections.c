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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "amxo_parser_priv.h"
#include "amxo_parser_hooks_priv.h"
#include "amxo_parser.tab.h"

int amxo_connection_add(UNUSED amxo_parser_t* parser,
                        int fd,
                        amxo_fd_read_t reader,
                        const char* uri,
                        amxo_con_type_t type,
                        void* priv) {

    return amxp_connection_add(fd, reader, uri, type, priv);
}

int amxo_connection_wait_write(UNUSED amxo_parser_t* parser,
                               int fd,
                               amxo_fd_cb_t can_write_cb) {
    return amxp_connection_wait_write(fd, can_write_cb);
}

int amxo_connection_remove(UNUSED amxo_parser_t* parser,
                           int fd) {
    return amxp_connection_remove(fd);
}

amxo_connection_t* amxo_connection_get(UNUSED amxo_parser_t* parser,
                                       int fd) {
    return amxp_connection_get(fd);
}

amxo_connection_t* amxo_connection_get_first(UNUSED amxo_parser_t* parser,
                                             amxo_con_type_t type) {
    return amxp_connection_get_first(type);
}

amxo_connection_t* amxo_connection_get_next(UNUSED amxo_parser_t* parser,
                                            amxo_connection_t* con,
                                            amxo_con_type_t type) {
    return amxp_connection_get_next(con, type);
}

int amxo_connection_set_el_data(UNUSED amxo_parser_t* parser,
                                int fd,
                                void* el_data) {
    return amxp_connection_set_el_data(fd, el_data);
}

amxc_llist_t* amxo_parser_get_connections(UNUSED amxo_parser_t* parser) {
    return amxp_connection_get_connections();
}

amxc_llist_t* amxo_parser_get_listeners(UNUSED amxo_parser_t* parser) {
    return amxp_connection_get_listeners();
}
