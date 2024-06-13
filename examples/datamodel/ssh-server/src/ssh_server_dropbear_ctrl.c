/****************************************************************************
**
** Copyright (c) 2020 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "ssh_server.h"
#include "ssh_server_dropbear_ctrl.h"

int dropbear_ctrl_build_cmd(amxc_array_t* cmd, amxc_var_t* settings) {
    amxc_string_t port_cfg;

    amxc_string_init(&port_cfg, 0);
    amxc_array_append_data(cmd, strdup("dropbear"));
    if(!GET_BOOL(settings, CFG_ALLOW_PWD_LOGIN)) {
        amxc_array_append_data(cmd, strdup("-s"));
    }
    if(!GET_BOOL(settings, CFG_ALLOW_ROOT_LOGIN)) {
        amxc_array_append_data(cmd, strdup("-w"));
    }
    if(!GET_BOOL(settings, CFG_ALLOW_ROOT_PWD_LOGIN)) {
        amxc_array_append_data(cmd, strdup("-g"));
    }
    amxc_array_append_data(cmd, strdup("-F"));
    amxc_array_append_data(cmd, strdup("-E"));
    amxc_array_append_data(cmd, strdup("-R"));

    {
        uint32_t port = GET_UINT32(settings, CFG_PORT);
        const char* address = GET_CHAR(settings, CFG_ADDRESS);
        amxc_array_append_data(cmd, strdup("-p"));
        if((address != NULL) && (*address != 0)) {
            amxc_string_setf(&port_cfg, "%s:%d", address, port);
        } else {
            amxc_string_setf(&port_cfg, "%d", port);
        }
        amxc_array_append_data(cmd, amxc_string_take_buffer(&port_cfg));

    }

    return 0;
}
