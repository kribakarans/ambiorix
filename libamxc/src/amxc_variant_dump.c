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
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include <amxc/amxc_string.h>
#include <amxc/amxc_variant_type.h>
#include <amxc/amxc_rbuffer.h>
#include <amxc/amxc_string_split.h>
#include <amxc_variant_priv.h>
#include <amxc/amxc_macros.h>

typedef struct _amxc_log_var {
    int fd;
    FILE* stream;
    amxc_string_t message;
} amxc_log_var_t;

typedef int (* amxc_var_dump_fn_t) (const amxc_var_t* const var,
                                    int indent,
                                    amxc_log_var_t* log);

static void amxc_var_log_init(amxc_log_var_t* log, int fd, FILE* stream, size_t msg_length) {
    log->fd = fd;
    log->stream = stream;
    amxc_string_init(&log->message, msg_length);
}

static int amxc_var_write(amxc_log_var_t* log,
                          const char* line,
                          size_t length) {
    int retval = 0;
    if(log->fd != -1) {
        retval = write(log->fd, line, length);
    } else if(log->stream != NULL) {
        retval = fwrite(line, 1, length, log->stream); // size is 1 to return the number of bytes like write()
    } else {
        retval = amxc_string_append(&log->message, line, length);
        if(amxc_string_search(&log->message, "\n", 0) >= 0) {
            syslog(LOG_DAEMON | LOG_DEBUG,
                   "%s", amxc_string_get(&log->message, 0));
            amxc_string_reset(&log->message);
        }
    }
    return retval;
}

static int amxc_var_dump_internal(const amxc_var_t* const var,
                                  int indent,
                                  amxc_log_var_t* log);

static void write_indentation(int indent, amxc_log_var_t* log) {
    for(int i = 0; i < indent; i++) {
        when_true(amxc_var_write(log, " ", 1) == -1, exit);
    }

exit:
    return;
}

static int variant_dump_type(const amxc_var_t* const var,
                             int indent,
                             amxc_log_var_t* log) {
    amxc_string_t txt;
    char addr[64] = "";
    const char* type_name = amxc_var_type_name_of(var);

    write_indentation(indent, log);
    amxc_string_init(&txt, 64);
    amxc_string_append(&txt, "<", 1);
    if(type_name != NULL) {
        amxc_string_append(&txt, type_name, strlen(type_name));
    } else {
        amxc_string_append(&txt, "UNKNOWN", 7);
    }
    amxc_string_append(&txt, ">:", 2);
    if(amxc_var_type_of(var) > AMXC_VAR_ID_ANY) {
        snprintf(addr, 63, "%p:", var->data.data);
        amxc_string_append(&txt, addr, strlen(addr));
    }
    when_true(amxc_var_write(log,
                             amxc_string_get(&txt, 0),
                             amxc_string_text_length(&txt)) == -1,
              exit);

exit:
    amxc_string_clean(&txt);
    return 0;
}

static int variant_dump_null(UNUSED const amxc_var_t* const var,
                             int indent,
                             amxc_log_var_t* log) {
    write_indentation(indent, log);
    when_true(amxc_var_write(log, "<NULL>", 6) == -1, exit);

exit:
    return 0;
}

static int variant_dump_char(const amxc_var_t* const var,
                             int indent,
                             amxc_log_var_t* log) {
    const char* txt = amxc_var_constcast(cstring_t, var);
    write_indentation(indent, log);
    when_true(amxc_var_write(log, "\"", 1) == -1, exit);
    if(txt != NULL) {
        when_true(amxc_var_write(log, txt, strlen(txt)) == -1, exit);
    }
    when_true(amxc_var_write(log, "\"", 1) == -1, exit);

exit:
    return 0;
}

static int variant_dump_default(const amxc_var_t* const var,
                                int indent,
                                amxc_log_var_t* log) {
    int retval = -1;
    char* text = amxc_var_dyncast(cstring_t, var);

    write_indentation(indent, log);

    if(text != NULL) {
        when_true(amxc_var_write(log, text, strlen(text)) == -1, exit);
        retval = 0;
    } else {
        retval = variant_dump_type(var, indent, log);
    }

exit:
    free(text);
    return retval;
}

static int variant_dump_list(const amxc_var_t* const var,
                             int indent,
                             amxc_log_var_t* log) {

    const amxc_llist_t* list = amxc_var_constcast(amxc_llist_t, var);

    when_true(amxc_var_write(log, "[\n", 2) == -1, exit);
    indent += 4;
    amxc_llist_for_each(it, list) {
        amxc_var_t* lvar = amxc_var_from_llist_it(it);
        if((amxc_var_type_of(lvar) == AMXC_VAR_ID_HTABLE) ||
           ( amxc_var_type_of(lvar) == AMXC_VAR_ID_LIST)) {
            write_indentation(indent, log);
        }
        amxc_var_dump_internal(lvar, indent, log);
        if(amxc_llist_it_get_next(it) != NULL) {
            when_true(amxc_var_write(log, ",\n", 2) == -1, exit);
        } else {
            when_true(amxc_var_write(log, "\n", 1) == -1, exit);
        }
    }
    indent -= 4;
    write_indentation(indent, log);
    when_true(amxc_var_write(log, "]", 1) == -1, exit);

exit:
    return 0;
}

static int variant_dump_htable(const amxc_var_t* const var,
                               int indent,
                               amxc_log_var_t* log) {
    const amxc_htable_t* htable = amxc_var_constcast(amxc_htable_t, var);
    amxc_array_t* keys = amxc_htable_get_sorted_keys(htable);
    const char* prev_key = NULL;
    amxc_htable_it_t* it = NULL;

    when_true(amxc_var_write(log, "{\n", 2) == -1, exit);
    indent += 4;
    for(uint32_t i = 0; i < amxc_array_capacity(keys); i++) {
        amxc_var_t* hvar = NULL;
        const char* key
            = (const char*) amxc_array_it_get_data(amxc_array_get_at(keys, i));
        if((prev_key != NULL) && (key != NULL) && (strcmp(key, prev_key) == 0)) {
            it = amxc_htable_it_get_next_key(it);
        } else {
            it = amxc_htable_get(htable, key);
        }
        prev_key = key;
        hvar = amxc_var_from_htable_it(it);
        write_indentation(indent, log);
        if(key != NULL) {
            when_true(amxc_var_write(log, key, strlen(key)) == -1, exit);
        } else {
            when_true(amxc_var_write(log, "UNKNOWN", 7) == -1, exit);
        }
        when_true(amxc_var_write(log, " = ", 3) == -1, exit);
        if((amxc_var_type_of(hvar) == AMXC_VAR_ID_HTABLE) ||
           ( amxc_var_type_of(hvar) == AMXC_VAR_ID_LIST)) {
            amxc_var_dump_internal(hvar, indent, log);
        } else {
            amxc_var_dump_internal(hvar, 0, log);
        }
        if(i + 1 < amxc_array_capacity(keys)) {
            when_true(amxc_var_write(log, ",\n", 2) == -1, exit);
        } else {
            when_true(amxc_var_write(log, "\n", 1) == -1, exit);
        }
    }
    indent -= 4;
    write_indentation(indent, log);
    when_true(amxc_var_write(log, "}", 1) == -1, exit);

exit:
    amxc_array_delete(&keys, NULL);
    return 0;
}

static int variant_dump_fd(const amxc_var_t* const var,
                           int indent,
                           amxc_log_var_t* log) {
    variant_dump_type(var, indent, log);
    return variant_dump_default(var, indent, log);
}

static int variant_dump_ts(const amxc_var_t* const var,
                           int indent,
                           amxc_log_var_t* log) {
    variant_dump_type(var, indent, log);
    return variant_dump_default(var, indent, log);
}

static int amxc_var_dump_internal(const amxc_var_t* const var,
                                  int indent,
                                  amxc_log_var_t* log) {
    int retval = -1;
    amxc_var_dump_fn_t dumpfn[AMXC_VAR_ID_CUSTOM_BASE] = {
        variant_dump_null,
        variant_dump_char,
        variant_dump_default,
        variant_dump_default,
        variant_dump_default,
        variant_dump_default,
        variant_dump_default,
        variant_dump_default,
        variant_dump_default,
        variant_dump_default,
        variant_dump_default,
        variant_dump_default,
        variant_dump_default,
        variant_dump_list,
        variant_dump_htable,
        variant_dump_fd,
        variant_dump_ts,
        variant_dump_char,
        variant_dump_char,
        NULL,
    };

    if(var->type_id >= AMXC_VAR_ID_CUSTOM_BASE) {
        retval = variant_dump_default(var, indent, log);
    } else {
        if(dumpfn[var->type_id] != NULL) {
            retval = dumpfn[var->type_id](var, indent, log);
        }
    }

    return retval;
}

static int amxc_var_dump_impl(const amxc_var_t* const var, int fd, FILE* stream) {
    int retval = 0;
    amxc_log_var_t log;

    amxc_var_log_init(&log, fd, stream, 0);

    if(var == NULL) {
        amxc_var_write(&log, "NULL\n", 5);
        goto exit;
    }

    retval = amxc_var_dump_internal(var, 0, &log);
    when_true(amxc_var_write(&log, "\n", 1) == -1, exit);

exit:
    amxc_string_clean(&log.message);
    return retval;
}

int amxc_var_dump(const amxc_var_t* const var, int fd) {
    return amxc_var_dump_impl(var, fd, NULL);
}

int amxc_var_dump_stream(const amxc_var_t* const var, FILE* stream) {
    return amxc_var_dump_impl(var, -1, stream);
}

int amxc_var_log(const amxc_var_t* const var) {
    amxc_log_var_t log;
    int retval = 0;

    amxc_var_log_init(&log, -1, NULL, 1024);

    if(var == NULL) {
        syslog(LOG_DAEMON | LOG_DEBUG, "NULL");
        goto exit;
    }

    retval = amxc_var_dump_internal(var, 0, &log);
    if(!amxc_string_is_empty(&log.message)) {
        syslog(LOG_DAEMON | LOG_DEBUG, "%s", amxc_string_get(&log.message, 0));
    }

exit:
    amxc_string_clean(&log.message);
    return retval;
}