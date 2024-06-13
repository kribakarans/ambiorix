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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>

#include "amxo_xml_to_assert.h"
#include "amxo_xml_to.h"

typedef struct _app {
    amxc_var_t config;
} app_t;

typedef int (* amxo_xml_convert_t) (amxc_var_t* config,
                                    xmlDocPtr merged,
                                    const char* xsl_ss);

typedef struct _convertor {
    const char* name;
    amxo_xml_convert_t fn;
} convertor_t;

static app_t the_app;

static convertor_t convertors[] = {
    { "html", amxo_xml_files_to_html },
    { "merge", amxo_xml_files_to_merged_xml },
    { "*", amxo_xml_files_to },
    { NULL, NULL}
};

static int xml_convert(amxc_var_t* config, int argc, char** argv) {
    int retval = -1;
    xmlDocPtr merged = NULL;
    amxc_string_t xsl_ss;
    const char* xsl = GET_CHAR(config, "xsl");
    const char* config_dir = GET_CHAR(config, "cfg-dir");

    amxc_string_init(&xsl_ss, 0);

    if((xsl == NULL) || (*xsl == 0)) {
        amxo_xml_print_error("No xsl provided.\n");
        goto leave;
    }
    if(argc <= 0) {
        amxo_xml_print_error("No xml file(s) provided.\n");
        goto leave;
    }

    exsltRegisterAll();
    xmlSubstituteEntitiesDefault(1);
    xmlLoadExtDtdDefaultValue = 0;

    merged = amxo_xml_merge(config_dir, argc, argv);
    if(merged == NULL) {
        amxo_xml_print_error("Merge failed\n");
        goto leave;
    }

    amxc_string_setf(&xsl_ss, "%s/xsl/%s.xsl", config_dir, xsl);

    for(int i = 0; convertors[i].name != NULL; i++) {
        amxo_xml_convert_t convert_fn = NULL;
        int len = strlen(convertors[i].name);
        if(strncmp(convertors[i].name, xsl, len) == 0) {
            convert_fn = convertors[i].fn;
        } else if(strncmp(convertors[i].name, "*", 1) == 0) {
            convert_fn = convertors[i].fn;
        }
        if(convert_fn != NULL) {
            retval = convert_fn(config, merged, amxc_string_get(&xsl_ss, 0));
            break;
        }
    }

leave:
    amxc_string_clean(&xsl_ss);
    if(merged != NULL) {
        xmlFreeDoc(merged);
    }
    return retval;
}

int main(int argc, char* argv[]) {
    int retval = -1;
    amxc_var_init(&the_app.config);
    amxc_var_set_type(&the_app.config, AMXC_VAR_ID_HTABLE);

    amxo_xml_set_config(&the_app.config);

    retval = amxo_xml_args_parse_cmd(&the_app.config, argc, argv);
    if(retval < 0) {
        amxo_xml_print_usage(argc, argv);
        goto leave;
    }
    amxo_xml_join_config(&the_app.config);

    retval = xml_convert(&the_app.config, argc - retval, &argv[retval]);
    if(retval != 0) {
        amxo_xml_print_usage(argc, argv);
        goto leave;
    }

leave:
    amxc_var_clean(&the_app.config);
    return retval;
}