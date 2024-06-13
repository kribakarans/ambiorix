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
#include <sys/time.h>
#include <sys/resource.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <cmocka.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxt/amxt_tty.h>

#include "test_tty.h"

#include <amxc/amxc_macros.h>
static char input_data[64] = "";
static bool fail = false;

ssize_t __wrap_read(int fd, void* buf, size_t count);
ssize_t __wrap_write(int fd, void* buf, size_t count);
int __wrap_isatty(int fd);
int __wrap_ttyname_r(int fd, char* buf, size_t buflen);
int __wrap_open(const char* path, int oflag, int mode);
int __real_open(const char* path, int oflag, int mode);

int __wrap_ttyname_r(UNUSED int fd, char* buf, size_t buflen) {
    strncpy(buf, "/tmp/test_tty", buflen);

    return 0;
}

int __wrap_open(const char* path, int oflag, int mode) {
    if(strcmp(path, "/tmp/test_tty") == 0) {
        return 0;
    }
    return __real_open(path, oflag, mode);
}

ssize_t __wrap_read(UNUSED int fd, void* buf, size_t count) {
    if(fail) {
        return -1;
    } else {
        size_t length = strlen(input_data);
        ssize_t bytes = count < length ? count : length;
        if(length != 0) {
            memcpy(buf, input_data, bytes);
            input_data[0] = 0;
        }
        return bytes;
    }
}

ssize_t __wrap_write(UNUSED int fd, UNUSED void* buf, size_t count) {
    ssize_t bytes = count;
    return bytes;
}

int __wrap_isatty(UNUSED int fd) {
    return 1;
}

static bool amxt_test_ctrl_key_noop(UNUSED amxt_tty_t* const tty,
                                    UNUSED const amxt_ctrl_key_t key) {
    return false;
}


void test_tty_open_close(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    int fd = open("/tmp/test.txt", O_CREAT | O_APPEND, S_IRWXU | S_IRWXG | S_IRWXO);

    assert_int_not_equal(amxt_tty_open(NULL, 0), 0);
    assert_ptr_equal(tty, NULL);
    assert_int_equal(amxt_tty_open(&tty, 15), 0);
    assert_ptr_not_equal(tty, NULL);
    amxt_tty_close(&tty);
    assert_int_equal(amxt_tty_open(&tty, fd), 0);
    assert_ptr_not_equal(tty, NULL);
    amxt_tty_close(&tty);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);
    assert_ptr_not_equal(tty, NULL);
    assert_ptr_not_equal(amxt_tty_il(tty), NULL);
    assert_ptr_equal(amxt_tty_il(NULL), NULL);
    assert_int_not_equal(tty->tty_fd, -1);
    assert_int_not_equal(amxt_tty_fd(tty), -1);
    assert_int_equal(amxt_tty_fd(NULL), -1);

    amxt_tty_close(NULL);
    amxt_tty_close(&tty);
    assert_ptr_equal(tty, NULL);
    close(fd);
}

void test_tty_read(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    amxt_il_t* il = NULL;

    assert_int_equal(amxt_tty_read(NULL), 0);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);
    il = amxt_tty_il(tty);
    strcpy(input_data, "Hello World");
    assert_int_equal(amxt_tty_read(tty), 11);
    assert_string_equal(amxt_il_text(il, amxt_il_no_flags, 0), "Hello World");

    input_data[0] = 27;
    input_data[1] = 91;
    input_data[2] = 68;
    input_data[3] = 0;
    assert_int_equal(amxt_tty_read(tty), 3);

    strcpy(input_data, "12");
    assert_int_equal(amxt_tty_read(tty), 2);
    assert_string_equal(amxt_il_text(il, amxt_il_no_flags, 0), "Hello Worl12d");

    fail = true;
    assert_true(amxt_tty_read(tty) < 0);
    fail = false;
    assert_string_equal(amxt_il_text(il, amxt_il_no_flags, 0), "Hello Worl12d");

    input_data[0] = 10;
    input_data[1] = 0;
    assert_int_equal(amxt_tty_read(tty), 1);
    assert_string_equal(amxt_il_text(il, amxt_il_no_flags, 0), "");

    amxt_tty_close(&tty);
}

void test_tty_write(UNUSED void** state) {
    amxt_tty_t* tty = NULL;

    assert_int_equal(amxt_tty_write(NULL, "Hello world", 11), 0);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);
    assert_int_equal(amxt_tty_write(tty, "Hello world", 11), 11);
    assert_int_equal(amxt_tty_write(tty, "Hello world", 0), 0);
    assert_int_equal(amxt_tty_write(tty, NULL, 10), 0);

    amxt_tty_close(&tty);
}

void test_tty_error(UNUSED void** state) {
    amxt_tty_t* tty = NULL;

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);
    assert_int_equal(amxt_tty_errorf(tty, "Hello world"), 11);
    assert_int_equal(amxt_tty_errorf(tty, "Hello %s", "world"), 11);
    assert_int_not_equal(amxt_tty_errorf(tty, NULL), 0);

    amxt_tty_close(&tty);
}

void test_tty_message(UNUSED void** state) {
    amxt_tty_t* tty = NULL;

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);
    assert_int_equal(amxt_tty_messagef(tty, "Hello world"), 11);
    assert_int_equal(amxt_tty_messagef(tty, "Hello %s", "world"), 11);
    assert_int_not_equal(amxt_tty_messagef(tty, NULL), 0);

    amxt_tty_close(&tty);
}

void test_tty_cursor(UNUSED void** state) {
    amxt_tty_t* tty = NULL;

    assert_int_not_equal(amxt_tty_cursor_move(NULL, 10, 10), 0);
    assert_int_not_equal(amxt_tty_set_cursor_column(NULL, 10), 0);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);
    assert_int_equal(amxt_tty_cursor_move(tty, -1, -1), 0);
    assert_int_equal(amxt_tty_cursor_move(tty, 1, 1), 0);

    amxt_tty_close(&tty);
}

void test_tty_prompt(UNUSED void** state) {
    amxt_tty_t* tty = NULL;

    assert_int_not_equal(amxt_tty_set_prompt(NULL, NULL), 0);
    assert_int_not_equal(amxt_tty_show_prompt(NULL), 0);
    assert_ptr_equal(amxt_tty_get_prompt(NULL), NULL);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);
    assert_int_not_equal(amxt_tty_set_prompt(tty, NULL), 0);
    assert_int_not_equal(amxt_tty_set_prompt(tty, ""), 0);
    assert_int_equal(amxt_tty_set_prompt(tty, ">"), 0);
    assert_int_equal(amxt_tty_show_prompt(tty), 0);
    assert_ptr_not_equal(amxt_tty_get_prompt(tty), NULL);

    amxt_tty_close(&tty);
}

void test_tty_accessor_functions(UNUSED void** state) {
    assert_int_not_equal(amxt_tty_fd(NULL), 0);
    assert_ptr_equal(amxt_tty_il(NULL), NULL);
    assert_ptr_equal(amxt_tty_sigmngr(NULL), NULL);
    assert_ptr_equal(amxt_tty_history(NULL), NULL);
}

void test_tty_set_ctrl_key_cb(UNUSED void** state) {
    amxt_tty_t* tty = NULL;

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    amxt_tty_set_ctrl_key_cb(amxt_key_tab, amxt_test_ctrl_key_noop);
    amxt_tty_close(&tty);
}