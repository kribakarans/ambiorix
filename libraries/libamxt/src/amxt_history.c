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
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <amxc/amxc.h>
#include <amxt/amxt_history.h>

#include "amxt_priv.h"

int amxt_hist_init(amxt_hist_t* const hist) {
    int retval = -1;
    when_null(hist, exit);

    when_failed(amxc_var_init(&hist->history), exit);
    when_failed(amxc_var_set_type(&hist->history, AMXC_VAR_ID_LIST), exit);
    hist->current_pos = 0;
    hist->max = 40;

    retval = 0;

exit:
    return retval;
}

int amxt_hist_clean(amxt_hist_t* const hist) {
    int retval = -1;
    when_null(hist, exit);

    amxc_var_clean(&hist->history);
    when_failed(amxc_var_set_type(&hist->history, AMXC_VAR_ID_LIST), exit);
    hist->current_pos = 0;

exit:
    return retval;
}

int amxt_hist_set_pos(amxt_hist_t* const hist, const uint32_t index) {
    int retval = -1;
    when_null(hist, exit);
    when_true(amxc_llist_is_empty(&hist->history.data.vl), exit);
    when_true(index > amxc_llist_size(&hist->history.data.vl), exit);

    hist->current_pos = index;
    retval = 0;

exit:
    return retval;
}

int amxt_hist_get_pos(amxt_hist_t* hist) {
    return hist != NULL ? hist->current_pos : 0;
}

int amxt_hist_update(amxt_hist_t* const hist, const char* text) {
    int retval = -1;
    amxc_var_t* var_txt = NULL;
    when_null(hist, exit);

    when_failed(amxc_var_new(&var_txt), exit);
    when_failed(amxc_var_set(cstring_t, var_txt, text), exit);

    retval = amxc_var_set_index(&hist->history,
                                hist->current_pos,
                                var_txt,
                                AMXC_VAR_FLAG_UPDATE);

exit:
    if(retval != 0) {
        amxc_var_delete(&var_txt);
    }
    return retval;
}

int amxt_hist_add(amxt_hist_t* const hist, const char* text) {
    int retval = -1;
    amxc_var_t* var_txt = NULL;
    size_t hist_size = 0;
    when_null(hist, exit);

    hist_size = amxc_llist_size(&hist->history.data.vl);
    if(hist_size >= hist->max) {
        amxc_llist_it_t* last = amxc_llist_take_last(&hist->history.data.vl);
        amxc_var_t* last_var = amxc_var_from_llist_it(last);
        amxc_var_delete(&last_var);
    }
    when_failed(amxc_var_new(&var_txt), exit);
    when_failed(amxc_var_set(cstring_t, var_txt, text), exit);

    retval = amxc_var_set_index(&hist->history,
                                0,
                                var_txt,
                                AMXC_VAR_FLAG_DEFAULT);

exit:
    if(retval != 0) {
        amxc_var_delete(&var_txt);
    }
    return retval;
}

const char* amxt_hist_get_current(const amxt_hist_t* const hist) {
    const char* txt = NULL;
    amxc_var_t* var_txt = NULL;
    const amxc_llist_t* lhist = NULL;
    when_null(hist, exit);
    lhist = amxc_var_constcast(amxc_llist_t, &hist->history);
    when_null(lhist, exit);
    when_true(amxc_llist_is_empty(lhist), exit);

    var_txt = amxc_var_get_index(&hist->history, hist->current_pos, AMXC_VAR_FLAG_DEFAULT);
    when_null(var_txt, exit);
    txt = amxc_var_constcast(cstring_t, var_txt);

exit:
    return txt;
}

const char* amxt_hist_get_next(amxt_hist_t* const hist) {
    const char* txt = NULL;
    amxc_var_t* var_txt = NULL;
    when_null(hist, exit);

    var_txt = amxc_var_get_index(&hist->history, hist->current_pos + 1, AMXC_VAR_FLAG_DEFAULT);
    when_null(var_txt, exit);
    txt = amxc_var_constcast(cstring_t, var_txt);

    hist->current_pos++;

exit:
    return txt;
}

const char* amxt_hist_get_prev(amxt_hist_t* const hist) {
    const char* txt = NULL;
    amxc_var_t* var_txt = NULL;
    when_null(hist, exit);
    when_true(hist->current_pos <= 0, exit);

    hist->current_pos--;

    var_txt = amxc_var_get_index(&hist->history, hist->current_pos, AMXC_VAR_FLAG_DEFAULT);
    txt = amxc_var_constcast(cstring_t, var_txt);

exit:
    return txt;
}

int amxt_hist_save(const amxt_hist_t* const hist, const char* path_name) {
    int retval = -1;
    const amxc_llist_t* list = NULL;
    int fd = -1;
    int open_flags = O_CREAT | O_WRONLY | O_TRUNC;
    int mode_flags = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;


    when_null(hist, exit);
    when_null(path_name, exit);
    when_true(*path_name == 0, exit)

    list = amxc_var_constcast(amxc_llist_t, &hist->history);
    fd = open(path_name, open_flags, mode_flags);

    when_true(fd < 0, exit);
    amxc_llist_for_each_reverse(it, list) {
        amxc_var_t* var_txt = amxc_var_from_llist_it(it);
        const char* txt = amxc_var_constcast(cstring_t, var_txt);
        int length = strlen(txt);

        // line to big, it will be skipped.
        // this is done to keep reading the history file simple,
        // using a fixed buffer size (see amxt_hist_load)
        if(length >= 512) {
            continue;
        }

        if(write(fd, txt, length) != length) {
            close(fd);
            goto exit;
        }
        if(write(fd, "\n", 1) != 1) {
            close(fd);
            goto exit;
        }
    }

    close(fd);

    retval = 0;

exit:
    return retval;
}

int amxt_hist_load(amxt_hist_t* const hist, const char* path_name) {
    int retval = -1;
    FILE* fp = NULL;
    char text[512] = "";

    when_null(hist, exit);
    when_null(path_name, exit);
    when_true(*path_name == 0, exit)

    amxt_hist_clean(hist);

    fp = fopen(path_name, "r");
    when_null(fp, exit);

    while(fgets(text, 512, fp) != NULL) {
        int length = strlen(text);
        // remove the trailing new line
        text[length - 1] = 0;
        amxt_hist_add(hist, text);
    }

    fclose(fp);

    retval = 0;

exit:
    return retval;
}
