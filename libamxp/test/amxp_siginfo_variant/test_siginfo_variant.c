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
#include <sys/time.h>
#include <sys/resource.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <cmocka.h>

#include <amxc/amxc_variant_type.h>
#include <amxp/variant_siginfo.h>
#include <amxp_signal_priv.h>

#include "test_siginfo_variant.h"


#include <amxc/amxc_macros.h>
void test_var_siginfo_new(UNUSED void** state) {
    amxc_var_t var;
    const amxp_siginfo_t* siginfo = NULL;

    amxc_var_init(&var);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_SIGINFO), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_SIGINFO);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_SIGINFO);

    assert_ptr_not_equal(var.data.data, NULL);
    siginfo = amxc_var_constcast(amxp_siginfo_t, &var);
    assert_ptr_not_equal(siginfo, NULL);

    amxc_var_clean(&var);
}

void test_var_siginfo_delete(UNUSED void** state) {
    amxc_var_t var;

    amxc_var_init(&var);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_SIGINFO), 0);
    assert_ptr_not_equal(var.data.data, NULL);
    amxc_var_clean(&var);
    assert_ptr_equal(var.data.data, NULL);
}

void test_var_siginfo_set_copy(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t var_copy;
    amxp_siginfo_t siginfo = {
        .ssi_signo = SIGCHLD,
        .ssi_errno = 0,
        .ssi_code = 123,
        .ssi_pid = 5012,
        .ssi_uid = 100
    };
    const amxp_siginfo_t* copy = NULL;

    amxc_var_init(&var);
    amxc_var_init(&var_copy);
    assert_int_not_equal(amxc_var_set(amxp_siginfo_t, NULL, &siginfo), 0);
    assert_int_not_equal(amxc_var_set(amxp_siginfo_t, &var, NULL), 0);
    assert_int_equal(amxc_var_set(amxp_siginfo_t, &var, &siginfo), 0);
    assert_ptr_not_equal(var.data.data, NULL);
    assert_ptr_not_equal(var.data.data, &siginfo);

    copy = amxc_var_constcast(amxp_siginfo_t, &var_copy);
    assert_ptr_equal(copy, NULL);

    assert_int_equal(amxc_var_copy(&var_copy, &var), 0);
    assert_ptr_not_equal(var_copy.data.data, NULL);

    copy = amxc_var_constcast(amxp_siginfo_t, NULL);
    assert_ptr_equal(copy, NULL);
    copy = amxc_var_constcast(amxp_siginfo_t, &var_copy);
    assert_ptr_not_equal(copy, NULL);
    assert_int_equal(copy->ssi_signo, siginfo.ssi_signo);
    assert_int_equal(copy->ssi_errno, siginfo.ssi_errno);
    assert_int_equal(copy->ssi_code, siginfo.ssi_code);
    assert_int_equal(copy->ssi_pid, siginfo.ssi_pid);
    assert_int_equal(copy->ssi_uid, siginfo.ssi_uid);

    amxc_var_clean(&var);
    amxc_var_clean(&var_copy);
}

