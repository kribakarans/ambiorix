/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2023 SoftAtHome
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

#include "test_amxut_bus.h"
#include <stdlib.h> // Needed for cmocka
#include <setjmp.h> // Needed for cmocka
#include <stdarg.h> // Needed for cmocka
#include <cmocka.h>
#include <amxut/amxut_bus.h>
#include <amxb/amxb.h>
#include <amxd/amxd_dm.h>
#include <amxc/amxc_macros.h>
#include <debug/sahtrace.h>

void amxut_bus_setup__has_datamodel(UNUSED void** state) {
    // GIVEN a bus that has been setup by `amxut_bus_setup`
    // (this is the cmocka test-setup, so not done inside this test)

    // WHEN loading an .odl file
    assert_int_equal(0, amxo_parser_parse_file(amxut_bus_parser(), "../common/test.odl", amxd_dm_get_root(amxut_bus_dm())));

    // THEN the parameters have their default value
    amxc_var_t ret;
    amxc_var_init(&ret);
    assert_int_equal(amxb_get(amxut_bus_ctx(), "Test.", 0, &ret, 5), 0);
    amxc_var_t* parameters = amxc_var_get_first(amxc_var_get_first(&ret));
    assert_string_equal(GETP_CHAR(parameters, "StringParameter"), "Default initial string value");

    // cleanup
    amxc_var_clean(&ret);
}

void amxut_bus_setup__twice(void** state) {
    // This test is to check that running two tests, each with their own test setup, works.

    // So check if in the second run we still have a datamodel:
    amxut_bus_setup__has_datamodel(state);
}

void amxut_bus_setup__has_sahtrace(UNUSED void** state) {
    // @ref amxut_bus_setup() has been called by cmocka already.
    // The specification of @ref amxut_bus_setup() promises that it sets up sahtrace,
    // so verify that:
    assert_true(sahTraceIsOpen());
    assert_true(sahTraceLevel() >= TRACE_LEVEL_ERROR);
    assert_true(sahTraceType() == TRACE_TYPE_STDERR || sahTraceType() == TRACE_TYPE_STDOUT);
}
