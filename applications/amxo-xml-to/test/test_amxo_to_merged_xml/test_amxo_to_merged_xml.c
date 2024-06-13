/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2022 SoftAtHome
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
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>

#include "test_amxo_to_merged_xml.h"
#include "amxo_xml_to.h"

static void amxo_xml_set_test_config(amxc_var_t* config) {
    amxc_var_add_key(cstring_t, config, "cfg-dir", "./");
    amxc_var_add_key(cstring_t, config, "cfg-file", "default.conf");
    amxc_var_add_key(cstring_t, config, "output-dir", "./output");
}

static int parse_args(amxc_var_t* config, int argc, char** argv) {
    amxc_var_init(config);
    amxc_var_set_type(config, AMXC_VAR_ID_HTABLE);
    amxo_xml_set_test_config(config);

    optind = 1;
    amxo_xml_args_parse_cmd(config, argc, argv);
    return optind;
}

static void make_output_dir(void) {
    struct stat st = {0};

    if(stat("./output", &st) == -1) {
        mkdir("./output", 0700);
    }
}

void test_xml_to_merged_xml(UNUSED void** state) {
    char* argv[] = { "amxo-cg", "-x", "merge", "-o", "output-dir=./output", "xml/gmap-server.odl.xml xml/ip.odl.xml" };
    int argc = sizeof(argv) / sizeof(argv[0]);
    amxc_var_t config;
    int retval = -1;
    xmlDocPtr merged = NULL;
    amxc_string_t xsl_ss;
    const char* xsl = NULL;
    const char* config_dir = NULL;

    retval = parse_args(&config, argc, argv);
    assert_int_equal(retval, 5);
    xsl = GET_CHAR(&config, "xsl");
    config_dir = GET_CHAR(&config, "cfg-dir");

    amxc_string_init(&xsl_ss, 0);
    amxc_string_setf(&xsl_ss, "%s/xsl/%s.xsl", config_dir, xsl);

    exsltRegisterAll();
    xmlSubstituteEntitiesDefault(1);
    xmlLoadExtDtdDefaultValue = 0;

    amxo_xml_join_config(&config);
    merged = amxo_xml_merge(config_dir, argc - retval, &argv[retval]);
    assert_non_null(merged);

    make_output_dir();

    assert_int_equal(amxo_xml_files_to_merged_xml(&config, merged, amxc_string_get(&xsl_ss, 0)), 0);

    amxc_string_clean(&xsl_ss);
    xmlFreeDoc(merged);
    amxc_var_clean(&config);
}

void test_xml_to_merged_xml_fails_when_missing_options(UNUSED void** state) {
    amxc_var_t config;
    xmlDocPtr merged = NULL;

    amxc_var_init(&config);
    amxc_var_set_type(&config, AMXC_VAR_ID_HTABLE);

    assert_int_equal(amxo_xml_files_to_merged_xml(&config, merged, "Invalid"), -1);
    assert_int_equal(amxo_xml_files_to_merged_xml(&config, merged, "./xsl/merge.xsl"), -1);
    amxc_var_add_key(cstring_t, &config, "output-dir", "foo");
    assert_int_equal(amxo_xml_files_to_merged_xml(&config, merged, "./xsl/merge.xsl"), -1);
    amxc_var_add_key(cstring_t, &config, "xsl", "merge");
    assert_int_equal(amxo_xml_files_to_merged_xml(&config, merged, "./xsl/merge.xsl"), -1);

    amxc_var_clean(&config);
}
