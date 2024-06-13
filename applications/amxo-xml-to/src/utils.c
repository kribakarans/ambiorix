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

xmlDocPtr amxo_xml_merge(const char* config_dir,
                         int argc,
                         char* argv[]) {
    xsltStylesheetPtr xsl_merge = NULL;
    amxc_string_t merge_path;
    amxc_string_t list;
    xmlDocPtr doc = NULL;
    xmlDocPtr merged = NULL;
    const char* paramMerge[3];

    amxc_string_init(&list, 0);
    amxc_string_init(&merge_path, 0);

    amxc_string_setf(&merge_path, "%s/xsl/merge.xsl", config_dir);
    xsl_merge = xsltParseStylesheetFile(BAD_CAST amxc_string_get(&merge_path, 0));
    if(xsl_merge == NULL) {
        amxo_xml_print_error("Unable to load merge stylesheet (%s) - %m\n",
                             amxc_string_get(&merge_path, 0));
        goto leave;
    }

    amxc_string_append(&list, "'", 1);
    for(int i = 0; i < argc; i++) {
        amxc_string_append(&list, ",", 1);
        amxc_string_appendf(&list, "%s", argv[i]);
    }
    amxc_string_append(&list, "'", 1);

    paramMerge[0] = "files";
    paramMerge[1] = amxc_string_get(&list, 0);
    paramMerge[2] = NULL;
    doc = xmlParseDoc(BAD_CAST "<merge></merge>");
    merged = xsltApplyStylesheet(xsl_merge, doc, paramMerge);

leave:
    xmlFreeDoc(doc);
    xsltFreeStylesheet(xsl_merge);
    amxc_string_clean(&list);
    amxc_string_clean(&merge_path);
    return merged;
}

char* amxo_xml_param(const char* value) {
    amxc_string_t helper;
    char* param = NULL;

    if(value != NULL) {
        amxc_string_init(&helper, strlen(value) + 3);
        amxc_string_setf(&helper, "'%s'", value);
    } else {
        amxc_string_init(&helper, 0);
        amxc_string_setf(&helper, "'Value Not Set'");
    }
    param = amxc_string_take_buffer(&helper);
    amxc_string_clean(&helper);

    return param;
}

int amxo_xml_save_result(amxc_var_t* config, xmlDocPtr merged, xsltStylesheetPtr xsl_style) {
    int rc = -1;
    amxc_string_t file;
    const char* xsl = GET_CHAR(config, "xsl");
    const char* output_dir = GET_CHAR(config, "output-dir");
    FILE* fd = NULL;
    amxc_string_init(&file, 0);

    if((output_dir == NULL) || (*output_dir == 0)) {
        amxo_xml_print_error("Option 'output_dir' missing\n");
        goto leave;
    }

    if((xsl == NULL) || (*xsl == 0)) {
        amxo_xml_print_error("Option 'xsl' missing\n");
        goto leave;
    }

    amxc_string_setf(&file, "%s/%s.out", output_dir, xsl);

    fd = fopen(amxc_string_get(&file, 0), "w");
    if(fd == NULL) {
        amxo_xml_print_error("Unable to create (%s) - %m\n",
                             amxc_string_get(&file, 0));
        goto leave;
    }
    xsltSaveResultToFile(fd, merged, xsl_style);

    rc = 0;
leave:
    amxc_string_clean(&file);
    return rc;
}
