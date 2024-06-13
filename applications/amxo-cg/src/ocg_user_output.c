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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "utils.h"
#include "colors.h"
#include "version.h"

typedef void (* ocg_help_fn_t) (void);

typedef struct _help_topics {
    const char* topic;
    ocg_help_fn_t fn;
} help_topics_t;

static void ocg_usage_gen_dm_methods(void) {
    printf("\nData model methods C function template generator\n\n");
    printf("Option: -Gdm_methods[,<output file>]\n\n");
    printf("Description:\n");
    printf("------------\n\n");
    printf("\tThis generator generates a file containing with C functions.\n");
    printf("\tEach function in this file represents a data model object method.\n");
    printf("\n");
    printf("\tIf no output file is specified, stdout is used as output\n");
    printf("\n");
    printf("Arguments:\n");
    printf("----------\n");
    printf("\t<output_file> - optional - path (relative or absolute) and file name\n");
    printf("\n");
    printf("Example:\n");
    printf("--------\n");
    printf("\t-Gdm_methods,/tmp/my_dm_funcs.c\n\n");
}

static void ocg_usage_gen_xml(void) {
    printf("\nODL to XML convertor\n\n");
    printf("Option: -Gxml[,<output dir>]\n\n");
    printf("Description:\n");
    printf("------------\n\n");
    printf("\tThis generator generates a xml file for each provided odl file.\n");
    printf("\tUsing xsl transformation, this xml can be transfored to any\n");
    printf("\tother format, like html\n");
    printf("\n");
    printf("\tIf no output directory is specified, the files are created in the\n");
    printf("\tcurrent directory\n");
    printf("\n");
    printf("Arguments:\n");
    printf("----------\n");
    printf("\t<output dir> - optional - path (relative or absolute)\n");
    printf("\n");
    printf("Example:\n");
    printf("--------\n");
    printf("\t-Gxml,./myxmldir/\n\n");
}

void ocg_usage(UNUSED int argc, char* argv[]) {
    printf("Ambiorix ODL File Parser/Generator v%d.%d.%d\n\tpowered by libamxo v%s\n",
           VERSION_MAJOR, VERSION_MINOR, VERSION_BUILD, amxo_lib_version());

    printf("\n%s [OPTIONS] <odl files> <directories>\n", argv[0]);
    printf("\n");
    printf("Options:\n");
    printf("--------\n");
    printf("\t-h   --help             Print this help\n");
    printf("\t-v   --verbose          Print verbose logging\n");
    printf("\t-I   --include-dir      Adds an include directory\n");
    printf("\t-L   --import-dir       Adds an import directory\n");
    printf("\t-R   --import-resolve   Adds an import directory\n");
    printf("\t-i   --include-odl      Adds an odl file that should be treated as include file\n");
    printf("\t-G   --generator        Enables a generator (see generators)\n");
    printf("\t-s   --silent           Supress warnings and messages\n");
    printf("\t-w   --no-warnings      Supress warnings only\n");
    printf("\t-c   --continue         Continue with other files after error\n");
    printf("\t-n   --no-colors        Disable colored output\n");
    printf("\t-d   --dump-config      Dump parser config, unless silent is set\n");
    printf("\t-r   --reset            Clear data model before loading next root odl\n");
    printf("\t-C   --config           Configuration file\n");
    printf("\n");
    printf("WARNING: do not use -r and -i in combination\n");
    printf("\n");
    printf("Generators:\n");
    printf("-----------\n");
    printf("\n");
    printf("\tGenerators can create files during the parsing of the odl file(s).\n\n");
    printf("\tThis %s supports:\n", argv[0]);
    printf("\t  - \"dm_methods\" use '--help=dm_methods' or '-hdm_methods' for more information.\n");
    printf("\t  - \"xml\" use '--help=xml' or '-hxml' for more information.\n");
    printf("\n");
}

void ocg_sub_usage(const char* help_topic) {
    static help_topics_t topics[] = {
        { "dm_methods", ocg_usage_gen_dm_methods },
        { "xml", ocg_usage_gen_xml },
        { NULL, NULL }
    };

    for(int i = 0; topics[i].topic != NULL; i++) {
        if(strcmp(topics[i].topic, help_topic) == 0) {
            topics[i].fn();
        }
    }
}

void ocg_error(UNUSED amxc_var_t* config, const char* fmt, ...) {
    va_list args;

    va_start(args, fmt);
    fprintf(stderr, "%sERROR  %s: %s", c(RED), c(RESET), c(WHITE));
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "%s\n", c(RESET));
    va_end(args);
}

void ocg_warning(amxc_var_t* config, const char* fmt, ...) {
    bool silent = GETP_BOOL(config, "silent");
    bool warnings = !GETP_BOOL(config, "no-warnings");
    va_list args;

    va_start(args, fmt);
    if(!silent && warnings) {
        fprintf(stderr, "%sWARNING%s: %s", c(YELLOW), c(RESET), c(WHITE));
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "%s\n", c(RESET));
    }
    va_end(args);
}

void ocg_message(amxc_var_t* config, const char* fmt, ...) {
    bool silent = GETP_BOOL(config, "silent");
    va_list args;

    va_start(args, fmt);
    if(!silent) {
        fprintf(stderr, "%sINFO   %s: %s", c(GREEN), c(RESET), c(WHITE));
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "%s\n", c(RESET));
    }
    va_end(args);
}

void ocg_dump_config(amxo_parser_t* parser) {
    bool silent = GETP_BOOL(&parser->config, "silent");
    bool dump_conifg = GETP_BOOL(&parser->config, "dump-config");

    if(!silent && dump_conifg) {
        fprintf(stderr, "Current parser configuration:\n");
        fflush(stderr);
        amxc_var_dump(&parser->config, STDERR_FILENO);
    }
}
