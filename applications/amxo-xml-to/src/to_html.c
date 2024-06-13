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

static int xml_html_make(xmlDocPtr merged,
                         const char* xsl_ss,
                         const char* output_dir,
                         const char* title,
                         const char* sub_title,
                         const char* version,
                         const char* stylesheet,
                         const char* copyrights) {
    int retval = -1;
    xmlDocPtr result = NULL;
    xsltStylesheetPtr xsl_html = NULL;
    FILE* fd = NULL;
    const char* params[13] = {
        "output", amxo_xml_param(output_dir),
        "title", amxo_xml_param(title),
        "subtitle", amxo_xml_param(sub_title),
        "version", amxo_xml_param(version),
        "css", amxo_xml_param(stylesheet),
        "copyrights", amxo_xml_param(copyrights),
        NULL
    };
    amxc_string_t index;
    amxc_string_init(&index, 0);

    amxc_string_setf(&index, "%s/index.html", output_dir);

    xsl_html = xsltParseStylesheetFile(BAD_CAST xsl_ss);
    if(xsl_html == NULL) {
        amxo_xml_print_error("Unable to load html stylesheet (%s) - %m\n",
                             xsl_ss);
        goto leave;
    }

    result = xsltApplyStylesheet(xsl_html, merged, params);
    fd = fopen(amxc_string_get(&index, 0), "w");
    if(fd == NULL) {
        amxo_xml_print_error("Unable to create (%s) - %m\n",
                             amxc_string_get(&index, 0));
        goto leave;
    }
    xsltSaveResultToFile(fd, result, xsl_html);

    retval = 0;
    fclose(fd);

leave:
    xmlFreeDoc(result);
    xsltFreeStylesheet(xsl_html);
    xsltCleanupGlobals();
    xmlCleanupParser();
    amxc_string_clean(&index);
    free((char*) params[1]);
    free((char*) params[3]);
    free((char*) params[5]);
    free((char*) params[7]);
    free((char*) params[9]);
    free((char*) params[11]);

    return retval;
}

static int xml_html_add_files(const char* config_dir, const char* output_dir) {
    int retval = 0;
    amxc_string_t cp_cmd;
    amxc_string_init(&cp_cmd, 0);

    amxc_string_setf(&cp_cmd, "cp -f %s/html/* %s/", config_dir, output_dir);
    retval = system(amxc_string_get(&cp_cmd, 0));

    amxc_string_clean(&cp_cmd);
    return retval;
}

int amxo_xml_files_to_html(amxc_var_t* config, xmlDocPtr merged, const char* xsl_ss) {
    int rc = -1;
    const char* config_dir = GET_CHAR(config, "cfg-dir");

    const char* output_dir = GET_CHAR(config, "output-dir");
    const char* title = GET_CHAR(config, "title");
    const char* sub_title = GET_CHAR(config, "sub-title");
    const char* version = GET_CHAR(config, "version");
    const char* css = GET_CHAR(config, "stylesheet");
    const char* copyrights = GET_CHAR(config, "copyrights");

    if((output_dir == NULL) || (*output_dir == 0)) {
        amxo_xml_print_error("Option 'output_dir' missing\n");
        goto leave;
    }
    if((title == NULL) || (*title == 0)) {
        amxo_xml_print_error("Option 'title' missing\n");
        goto leave;
    }
    if((sub_title == NULL) || (*sub_title == 0)) {
        amxo_xml_print_error("Option 'sub-title' missing\n");
        goto leave;
    }
    if((version == NULL) || (*version == 0)) {
        amxo_xml_print_error("Option 'version' missing\n");
        goto leave;
    }

    rc = xml_html_make(merged, xsl_ss, output_dir, title, sub_title, version, css, copyrights);
    if(rc != 0) {
        amxo_xml_print_error("Failed to generate html files\n");
        goto leave;
    }

    rc = xml_html_add_files(config_dir, output_dir);

leave:
    return rc;
}