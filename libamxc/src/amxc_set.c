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
#include <string.h>
#include <ctype.h>
#include <stdio.h>

#include <amxc/amxc_set.h>
#include <amxc/amxc_macros.h>

static void amxc_set_flag_free(amxc_llist_it_t* it) {
    amxc_flag_t* flag = amxc_container_of(it, amxc_flag_t, it);
    free(flag->flag);
    free(flag);
}

static amxc_flag_t* amxc_set_flag_find(const amxc_set_t* const set, const char* flag) {
    amxc_flag_t* f = NULL;
    amxc_llist_iterate(it, &set->list) {
        f = amxc_container_of(it, amxc_flag_t, it);
        if(strcmp(f->flag, flag) == 0) {
            break;
        }
        f = NULL;
    }
    return f;
}

static void amxc_set_flag_add(amxc_set_t* set,
                              const char* flag,
                              int flaglen,
                              int count) {
    amxc_flag_t* f = NULL;
    char* str = NULL;

    if(flaglen != 0) {
        str = (char*) calloc(flaglen + 1, 1);
        when_null(str, exit);
        strncpy(str, flag, flaglen);
    } else {
        str = strdup(flag);
        when_null(str, exit);
    }

    f = amxc_set_flag_find(set, str);
    if(f != NULL) {
        if(set->counted) {
            f->count += count;
            set->count += count;
        }
        free(str);
        goto exit;
    }

    f = (amxc_flag_t*) calloc(1, sizeof(amxc_flag_t));
    if(f == NULL) {
        free(str);
        goto exit;
    }
    f->flag = str;

    amxc_llist_append(&set->list, &f->it);
    f->count = count;
    set->count += count;
    if(set->alert_handler) {
        set->alert_handler(set, f->flag, true, set->priv);
    }

exit:
    return;
}

static void amxc_set_flag_delete(amxc_set_t* set, amxc_llist_it_t* it) {
    amxc_flag_t* flag = amxc_container_of(it, amxc_flag_t, it);
    amxc_llist_it_take(it);
    set->count -= flag->count;
    if(set->alert_handler != NULL) {
        set->alert_handler(set, flag->flag, false, set->priv);
    }
    amxc_set_flag_free(it);
}

int amxc_set_new(amxc_set_t** set, bool counted) {
    int retval = -1;

    when_null(set, exit);

    *set = (amxc_set_t*) calloc(1, sizeof(amxc_set_t));
    when_null(*set, exit);
    retval = amxc_set_init(*set, counted);

exit:
    return retval;
}

void amxc_set_delete(amxc_set_t** set) {
    when_null(set, exit);

    amxc_set_clean(*set);
    free(*set);
    *set = NULL;

exit:
    return;
}

int amxc_set_init(amxc_set_t* const set, bool counted) {
    int retval = -1;

    when_null(set, exit);
    amxc_llist_init(&set->list);
    set->alert_handler = NULL;
    set->counted = counted;
    set->count = 0;
    set->priv = NULL;
    retval = 0;

exit:
    return retval;
}

void amxc_set_clean(amxc_set_t* const set) {
    when_null(set, exit);

    amxc_llist_clean(&set->list, amxc_set_flag_free);
    set->count = 0;

exit:
    return;
}

amxc_set_t* amxc_set_copy(const amxc_set_t* const set) {
    amxc_set_t* copy = NULL;

    when_null(set, exit);
    when_failed(amxc_set_new(&copy, set->counted), exit);

    amxc_set_union(copy, set);

exit:
    return copy;
}

void amxc_set_reset(amxc_set_t* set) {
    when_null(set, exit);

    amxc_llist_for_each(it, &set->list) {
        amxc_set_flag_delete(set, it);
    }

exit:
    return;
}

int amxc_set_parse(amxc_set_t* set, const char* str) {
    int retval = -1;
    amxc_set_t newset;

    when_null(set, exit);
    amxc_set_init(&newset, set->counted);

    if((str != NULL) && (*str != 0)) {
        const char* strptr = str;
        char* newstr = NULL;
        int count = 0;
        do {
            if(!((*str == '\0') || (isspace(*str) != 0) || (*str == ':'))) {
                continue;
            }
            if(str > strptr) {
                if(*str == ':') {
                    count = strtol(str + 1, &newstr, 0);
                    if((*newstr != '\0') && (isspace(*newstr) == 0)) {
                        goto exit_clean;
                    }
                    if(count > 0) {
                        amxc_set_flag_add(&newset, strptr, str - strptr, set->counted ? count : 1);
                    }
                    str = newstr;
                } else {
                    amxc_set_flag_add(&newset, strptr, str - strptr, 1);
                }
            }
            strptr = str + 1;
        } while(*str++);
    }
    // intersect + union instead of simply overwrite to avoid that unchanged flags are cleared and set again
    amxc_set_intersect(set, &newset);
    amxc_set_union(set, &newset);
    if(set->counted) {
        set->count = 0;
        amxc_llist_iterate(it, &set->list) {
            amxc_flag_t* flag = amxc_container_of(it, amxc_flag_t, it);
            amxc_flag_t* new_flag = amxc_set_flag_find(&newset, flag->flag);
            if((flag != NULL) && (new_flag != NULL)) {
                flag->count = new_flag->count;
                set->count += flag->count;
            }
        }
    }
    retval = 0;

exit_clean:
    amxc_set_clean(&newset);
exit:
    return retval;
}

char* amxc_set_to_string_sep(const amxc_set_t* const set, const char* sep) {
    int n = 0;
    char* buf = NULL;
    char* bufptr = NULL;
    char countbuf[16];
    int started = 0;

    when_null(set, exit);
    when_null(sep, exit);

    amxc_llist_iterate(it, &set->list) {
        amxc_flag_t* f = amxc_container_of(it, amxc_flag_t, it);
        n += strlen(f->flag) + started;
        if((f->count != 1) && set->counted) {
            n += sprintf(countbuf, ":%d", f->count);
        }
        started = 1;
    }
    buf = (char*) calloc(n + 1, 1);
    bufptr = buf;
    when_null(buf, exit);

    started = 0;
    amxc_llist_iterate(it, &set->list) {
        amxc_flag_t* f = amxc_container_of(it, amxc_flag_t, it);
        if((f->count != 1) && set->counted) {
            bufptr += sprintf(bufptr, "%s%s:%d", started ? sep : "", f->flag, f->count);
        } else {
            bufptr += sprintf(bufptr, "%s%s", started ? sep : "", f->flag);
        }
        started = 1;
    }

exit:
    return buf;
}

char* amxc_set_to_string(const amxc_set_t* const set) {
    return amxc_set_to_string_sep(set, " ");
}

void amxc_set_add_flag(amxc_set_t* set, const char* flag) {
    when_null(set, exit);
    when_str_empty(flag, exit);

    amxc_set_flag_add(set, flag, 0, 1);

exit:
    return;
}

void amxc_set_remove_flag(amxc_set_t* set, const char* flag) {
    amxc_flag_t* f = NULL;

    when_null(set, exit);
    when_str_empty(flag, exit);

    f = amxc_set_flag_find(set, flag);
    if(f == NULL) {
        goto exit;
    }

    if(set->counted && (f->count > 1)) {
        f->count--;
        set->count--;
    } else {
        amxc_set_flag_delete(set, &f->it);
    }

exit:
    return;
}

bool amxc_set_has_flag(const amxc_set_t* const set, const char* flag) {
    bool retval = false;

    when_null(set, exit);
    when_str_empty(flag, exit);

    retval = amxc_set_flag_find(set, flag) ? true : false;

exit:
    return retval;
}

uint32_t amxc_set_get_count(const amxc_set_t* const set, const char* flag) {
    uint32_t retval = 0;

    when_null(set, exit);

    if((flag != NULL) && (*flag != 0)) {
        amxc_flag_t* f = amxc_set_flag_find(set, flag);
        retval = f != NULL ? f->count : 0;
    } else {
        return set->count;
    }

exit:
    return retval;
}

void amxc_set_union(amxc_set_t* const set, const amxc_set_t* const operand) {
    when_null(set, exit);
    when_null(operand, exit);

    amxc_llist_iterate(it, &operand->list) {
        amxc_flag_t* fo = amxc_container_of(it, amxc_flag_t, it);
        amxc_flag_t* f = amxc_set_flag_find(set, fo->flag);
        if(f == NULL) {
            amxc_set_flag_add(set, fo->flag, 0, set->counted ? fo->count : 1);
        } else if(set->counted) {
            set->count += fo->count;
            f->count += fo->count;
        }
    }

exit:
    return;
}

void amxc_set_intersect(amxc_set_t* const set, const amxc_set_t* const operand) {
    when_null(set, exit);

    if(operand == NULL) {
        amxc_set_reset(set);
        goto exit;
    }

    amxc_llist_for_each(it, &set->list) {
        amxc_flag_t* f = amxc_container_of(it, amxc_flag_t, it);
        amxc_flag_t* fo = amxc_set_flag_find(operand, f->flag);

        if(fo == NULL) {
            amxc_set_flag_delete(set, &f->it);
        } else if(set->counted && (fo->count < f->count)) {
            set->count += fo->count - f->count;
            f->count = fo->count;
        }
    }

exit:
    return;
}

void amxc_set_subtract(amxc_set_t* const set, const amxc_set_t* const operand) {
    when_null(set, exit);
    when_null(operand, exit);

    amxc_llist_iterate(it, &operand->list) {
        amxc_flag_t* fo = amxc_container_of(it, amxc_flag_t, it);
        amxc_flag_t* f = amxc_set_flag_find(set, fo->flag);
        if(f == NULL) {
            continue;
        }
        if(set->counted && (f->count > fo->count)) {
            set->count -= fo->count;
            f->count -= fo->count;
        } else {
            amxc_set_flag_delete(set, &f->it);
        }
    }

exit:
    return;
}

bool amxc_set_is_equal(const amxc_set_t* const set1,
                       const amxc_set_t* const set2) {
    if(set1 != NULL) {
        amxc_llist_iterate(it, &set1->list) {
            amxc_flag_t* f = amxc_container_of(it, amxc_flag_t, it);
            if(amxc_set_get_count(set2, f->flag) != f->count) {
                return false;
            }
        }
    }

    if(set2 != NULL) {
        amxc_llist_iterate(it, &set2->list) {
            amxc_flag_t* f = amxc_container_of(it, amxc_flag_t, it);
            if(amxc_set_get_count(set1, f->flag) != f->count) {
                return false;
            }
        }
    }

    return true;
}

void amxc_set_alert_cb(amxc_set_t* set, amxc_set_alert_t handler, void* priv) {
    when_null(set, exit);

    set->alert_handler = handler;
    set->priv = priv;

exit:
    return;
}

void amxc_set_symmetric_difference(amxc_set_t* const set,
                                   const amxc_set_t* const operand) {
    amxc_set_t* tmp = NULL;

    when_null(set, exit);
    when_null(operand, exit);

    tmp = amxc_set_copy(operand);
    when_null(tmp, exit);

    amxc_set_subtract(tmp, set);
    amxc_set_subtract(set, operand);
    amxc_set_union(set, tmp);

    amxc_set_delete(&tmp);
exit:
    return;
}
