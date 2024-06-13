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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <regex.h>
#include <ctype.h>

#include "utils.h"

typedef struct _desc_regexp {
    regex_t tag;
    regmatch_t matches[6];
} desc_regexp_t;

typedef struct _description {
    char* doc;
    amxc_llist_t tags;
} description_t;

static desc_regexp_t desc;
static description_t* last = NULL;

static void ocg_comment_delete(description_t** d);

static void comment_start(UNUSED amxo_parser_t* parser) {
    ocg_comment_delete(&last);
}

static void comment_end(UNUSED amxo_parser_t* parser) {
    ocg_comment_delete(&last);
}

static void comment_start_section(UNUSED amxo_parser_t* parser,
                                  UNUSED int section_id) {
    ocg_comment_delete(&last);
}

static void comment_end_section(UNUSED amxo_parser_t* parser,
                                UNUSED int section_id) {
    ocg_comment_delete(&last);
}

static void comment_create_object(amxo_parser_t* parser,
                                  amxd_object_t* parent,
                                  const char* name,
                                  UNUSED int64_t attr_bitmask,
                                  UNUSED amxd_object_type_t type) {
    bool silent = GET_BOOL(&parser->config, "comment-warnings");
    if(!ocg_comment_is_available() && !silent) {
        char* path = amxd_object_get_path(parent, AMXD_OBJECT_TERMINATE);
        ocg_warning(&parser->config, "Missing documentenation for object [%s%s]",
                    path == NULL ? "" : path, name);
        free(path);
    }
    ocg_comment_delete(&last);
}

static void comment_add_instance(UNUSED amxo_parser_t* parser,
                                 UNUSED amxd_object_t* parent,
                                 UNUSED uint32_t index,
                                 UNUSED const char* name) {
    ocg_comment_delete(&last);
}

static void comment_select_object(UNUSED amxo_parser_t* parser,
                                  UNUSED amxd_object_t* parent,
                                  UNUSED const char* path) {
    ocg_comment_delete(&last);
}

static void comment_end_object(UNUSED amxo_parser_t* parser,
                               UNUSED amxd_object_t* object) {
    ocg_comment_delete(&last);
}

static void comment_add_param(amxo_parser_t* parser,
                              amxd_object_t* object,
                              const char* name,
                              UNUSED int64_t attr_bitmask,
                              UNUSED uint32_t type) {
    bool silent = GET_BOOL(&parser->config, "comment-warnings");
    if(!ocg_comment_is_available() && !silent) {
        char* path = amxd_object_get_path(object, AMXD_OBJECT_TERMINATE);
        ocg_warning(&parser->config, "Missing documentenation for parameter [%s%s]",
                    path == NULL ? "" : path, name);
        free(path);
    }
    ocg_comment_delete(&last);
}

static void comment_set_param(UNUSED amxo_parser_t* parser,
                              UNUSED amxd_object_t* object,
                              UNUSED amxd_param_t* param,
                              UNUSED amxc_var_t* value) {
    ocg_comment_delete(&last);
}

static void comment_end_param(UNUSED amxo_parser_t* parser,
                              UNUSED amxd_object_t* object,
                              UNUSED amxd_param_t* param) {
    ocg_comment_delete(&last);
}

static void comment_add_func(amxo_parser_t* parser,
                             amxd_object_t* object,
                             const char* name,
                             UNUSED int64_t attr_bitmask,
                             UNUSED uint32_t type) {
    bool silent = GET_BOOL(&parser->config, "comment-warnings");
    if(!ocg_comment_is_available() && !silent) {
        char* path = amxd_object_get_path(object, AMXD_OBJECT_TERMINATE);
        ocg_warning(&parser->config, "Missing documentenation for function [%s%s]",
                    path == NULL ? "" : path, name);
        free(path);
    }
}

static void comment_end_func(UNUSED amxo_parser_t* parser,
                             UNUSED amxd_object_t* object,
                             UNUSED amxd_function_t* function) {
    ocg_comment_delete(&last);
}

static amxo_hooks_t comment_hooks = {
    .it = { .next = NULL, .prev = NULL, .llist = NULL },
    .comment = NULL,
    .start = comment_start,
    .end = comment_end,
    .start_include = NULL,
    .end_include = NULL,
    .set_config = NULL,
    .start_section = comment_start_section,
    .end_section = comment_end_section,
    .create_object = comment_create_object,
    .add_instance = comment_add_instance,
    .select_object = comment_select_object,
    .end_object = comment_end_object,
    .add_param = comment_add_param,
    .set_param = comment_set_param,
    .end_param = comment_end_param,
    .add_func = comment_add_func,
    .add_func_arg = NULL,
    .end_func = comment_end_func,
    .add_mib = NULL,
    .set_counter = NULL,
    .set_action_cb = NULL,
};

static void ocg_comment_free_tag(amxc_llist_it_t* it) {
    tag_t* t = (tag_t*) amxc_container_of(it, tag_t, it);
    free(t->line);
    free(t->tag);
    free(t->arg1);
    free(t->rest);
    free(t);
}

static void ocg_comment_parse_tag(description_t* d, amxc_string_t* str) {
    tag_t* t = NULL;
    amxc_string_replace(str, "\n", " ", UINT32_MAX);
    amxc_string_trim(str, NULL);

    t = (tag_t*) calloc(sizeof(tag_t), 1);
    t->line = strdup(amxc_string_get(str, 0));
    if(regexec(&desc.tag, t->line, 6, desc.matches, 0) == 0) {
        t->tag = strndup(t->line + desc.matches[1].rm_so, desc.matches[1].rm_eo - desc.matches[1].rm_so);
        t->arg1 = strndup(t->line + desc.matches[3].rm_so, desc.matches[3].rm_eo - desc.matches[3].rm_so);
        t->rest = strndup(t->line + desc.matches[5].rm_so, desc.matches[5].rm_eo - desc.matches[5].rm_so);
        amxc_llist_append(&d->tags, &t->it);
    } else {
        free(t->line);
        free(t);
    }
}

static int isspace_or_asterisk(int c) {
    if(c == '*') {
        return 1;
    }
    return isspace(c);
}

static int ocg_read_comment(description_t* d, FILE* fd) {
    int retval = -1;
    enum states { DOC, TAG } state = DOC;
    ssize_t read_len = 0;
    char* line = NULL;
    size_t r = 0;
    amxc_string_t doc;
    amxc_string_t line_buf;

    amxc_string_init(&doc, 0);
    amxc_string_init(&line_buf, 0);

    read_len = getline(&line, &r, fd);
    while(read_len != -1) {
        amxc_string_push_buffer(&line_buf, line, read_len + 1);
        amxc_string_trim(&line_buf, isspace_or_asterisk);
        amxc_string_take_buffer(&line_buf);
        if(regexec(&desc.tag, line, 5, desc.matches, 0) == 0) {
            switch(state) {
            case DOC:
                state = TAG;
                d->doc = amxc_string_take_buffer(&doc);
                amxc_string_setf(&doc, "%s\n", line);
                break;
            case TAG:
                ocg_comment_parse_tag(d, &doc);
                amxc_string_clean(&doc);
                amxc_string_setf(&doc, "%s\n", line);
                break;
            }
        } else {
            if(*line == 0) {
                amxc_string_appendf(&doc, "\n");
            } else {
                amxc_string_appendf(&doc, "%s\n", line);
            }
        }

        free(line);
        line = NULL;
        read_len = getline(&line, &r, fd);
    }
    free(line);

    if(state == TAG) {
        ocg_comment_parse_tag(d, &doc);
    } else {
        if(amxc_string_text_length(&doc) > 0) {
            d->doc = amxc_string_take_buffer(&doc);
        } else {
            goto exit;
        }
    }

    retval = 0;

exit:
    amxc_string_clean(&doc);
    return retval;
}

static int ocg_comment_new(description_t** d, const char* comment) {
    int len = 0;
    amxc_string_t buffer;
    FILE* fd = NULL;

    amxc_string_init(&buffer, 0);

    if((comment == NULL) || (*comment == 0)) {
        goto exit;
    }

    (*d) = (description_t*) calloc(sizeof(description_t), 1);
    amxc_llist_init(&(*d)->tags);

    amxc_string_set(&buffer, comment);
    amxc_string_replace(&buffer, "\\n", "\n", UINT32_MAX);
    len = amxc_string_text_length(&buffer);

    fd = fmemopen((void*) amxc_string_get(&buffer, 0), len, "r");
    if(ocg_read_comment(*d, fd) != 0) {
        free((*d));
        *d = NULL;
    }
    fclose(fd);

exit:
    amxc_string_clean(&buffer);
    return 0;
}

static void ocg_comment_delete(description_t** d) {
    if((*d) == NULL) {
        goto exit;
    }

    amxc_llist_clean(&(*d)->tags, ocg_comment_free_tag);

    free((*d)->doc);
    free((*d));
    *d = NULL;

exit:
    return;
}

const tag_t* ocg_comment_get_tag(const char* name, const char* arg1) {
    tag_t* t = NULL;
    if(last == NULL) {
        goto exit;
    }

    amxc_llist_for_each(it, (&last->tags)) {
        t = amxc_container_of(it, tag_t, it);
        if((strcmp(t->tag, name) == 0) &&
           (( arg1 == NULL) || ( strcmp(t->arg1, arg1) == 0))) {
            break;
        }
        t = NULL;
    }

exit:
    return t;
}

bool ocg_comment_is_available(void) {
    return last != NULL;
}

const char* ocg_comment_get(void) {
    return (last == NULL) ? NULL : last->doc;
}

void ocg_comment_parse(UNUSED amxo_parser_t* parser, const char* comment) {
    ocg_comment_delete(&last);
    ocg_comment_new(&last, comment);
}

void ocg_comment_set_clear(amxo_parser_t* parser, bool enable) {
    if(enable) {
        amxo_parser_set_hooks(parser, &comment_hooks);
    } else {
        amxo_parser_unset_hooks(parser, &comment_hooks);
    }
}

static void CONSTRUCTOR ocg_comment_init(void) {
    regcomp(&desc.tag, "[ \t]*@([a-zA-Z0-9]+)([ \t]+([^ \t]+)([ \t]+(.*))?)?", REG_EXTENDED);
}

static void DESTRUCTOR ocg_comment_clean(void) {
    regfree(&desc.tag);
    ocg_comment_delete(&last);
}

