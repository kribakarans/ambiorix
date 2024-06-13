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

#if !defined(__DM_CLI_PRIV_H__)
#define __DM_CLI_PRIV_H__

#ifdef __cplusplus
extern "C"
{
#endif

// doxygen has problems with these attributes
#if !defined(USE_DOXYGEN)
#define PRIVATE __attribute__ ((visibility("hidden")))
#define UNUSED __attribute__((unused))
#define WARN_UNUSED_RETURN __attribute__ ((warn_unused_result))
#else
#define PRIVATE
#define UNUSED
#define WARN_UNUSED_RETURN
#endif

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxt/amxt_tty.h>
#include <amxt/amxt_cmd.h>
#include <amxt/amxt_variant.h>

#include <amxm/amxm.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxo/amxo.h>
#include <amxo/amxo_save.h>

#include <amxb/amxb.h>
#include <amxb/amxb_register.h>

PRIVATE
amxm_shared_object_t* dm_cli_get_so(void);

PRIVATE
amxo_parser_t* dm_cli_get_parser(void);

PRIVATE
amxt_tty_t* dm_cli_get_tty(void);

PRIVATE
amxd_dm_t* dm_cli_get_dm(void);

PRIVATE
amxc_llist_t* dm_cli_get_entry_points(void);

PRIVATE
void dm_cli_move_entry_points(amxc_llist_t* dest, amxc_llist_t* src);

PRIVATE
int dm_cli_register_dm(amxd_dm_t* dm);

PRIVATE
void mod_dm_cli_parser_config_init(amxo_parser_t* parser);

#ifdef __cplusplus
}
#endif

#endif // __DM_CLI_PRIV_H__
