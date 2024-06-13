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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "amx_cli.h"

#include "amx_cli_parser.h"

#define MOD "record"
#define MOD_DESC "record and playback cli commands"

static int fd = -1;

#define CMD_HELP    0
#define CMD_START   1
#define CMD_STOP    2
#define CMD_PLAY    3

static const char* cmd_play_opts[] = {
    "w", "wait",
    NULL
};

static amxt_cmd_help_t help[] = {
    {
        .cmd = "help",
        .usage = "help [<CMD>]",
        .brief = "Prints help",
        .desc = "Use `help <COMMAND>` to get more information about the <COMMAND>.",
        .options = NULL
    },
    {
        .cmd = "start",
        .usage = "start <FILE>",
        .brief = "Records commands into a file.",
        .desc = "When you need to execute a sequence of commands often, they can be "
            "recorded into a text file.\n"
            "While recording only successful commands are added to the file.\n"
            "Use '!record stop' to stop recording, the 'stop' command is not recorded.",
        .options = NULL
    },
    {
        .cmd = "stop",
        .usage = "stop",
        .brief = "Stops recording commands.",
        .desc = "Stops a started recording.\n"
            "If no recording was started this command has not effect.\n"
            "Use '!record start <FILE>' to start a recording.",
        .options = NULL
    },
    {
        .cmd = "play",
        .usage = "play [<OPTIONS>] <FILE>",
        .brief = "Playback a previously recorded sequence of commands.",
        .desc = "A previous recorded sequence of commands can be playbacked with "
            "this command.\n"
            "The playback of the sequence will stop when the end of the sequence "
            "is reached."
            "Available options:\n"
            "\t-w --wait Wait for key-press before executing next command\n",
        .options = cmd_play_opts
    },
    { NULL, NULL, NULL, NULL, NULL },
};

static void mod_record_slot_cmd_done(UNUSED const char* const sig_name,
                                     const amxc_var_t* const data,
                                     UNUSED void* priv) {
    const char* txt = amxc_var_constcast(cstring_t, data);
    int length = strlen(txt);

    when_true(fd == -1, exit);
    when_true(write(fd, txt, length) != length, exit);
    when_true(write(fd, "\n", 1) != 1, exit);

exit:
    return;
}

static void mod_record_start(UNUSED const char* const sig_name,
                             UNUSED const amxc_var_t* const data,
                             void* priv) {
    amxt_tty_t* tty = (amxt_tty_t*) priv;

    if(amxp_slot_connect(amxt_tty_sigmngr(tty),
                         "tty:cmd-done",
                         NULL,
                         mod_record_slot_cmd_done,
                         NULL) != 0) {
        amxt_tty_errorf(tty, "Failed to connect to slot cmd_done\n");
        close(fd);
        fd = -1;
    } else {
        amxt_tty_line_clear(tty, amxt_clear_line_all);
        amxt_tty_set_cursor_column(tty, 0);
        amxt_tty_messagef(tty, "=== RECORDING STARTED ===\n\n");
        amxt_tty_show_prompt(tty);
    }
}

static void mod_record_type_commands(amxt_tty_t* tty, amxc_var_t* options) {
    amxt_il_t* il = amxt_tty_il(tty);
    char buf[1];
    bool comment = false;
    bool new_line = false;
    amxc_string_t buffer;
    bool wait = GET_BOOL(options, "w") || GET_BOOL(options, "wait");

    amxc_string_init(&buffer, 10);
    amxt_il_reset(il);
    amxt_tty_messagef(tty, "\n\n=== PLAYBACK STARTED ===\n\n");
    amxt_tty_show_prompt(tty);

    while(read(fd, buf, 1) > 0) {
        if(buf[0] == '\n') {
            if(comment == true) {
                amxt_tty_write(tty, buf, 1);
                new_line = true;
                comment = false;
            } else {
                size_t len = amxt_il_text_length(il, amxt_il_text_after_cursor, -1);
                const char* line = amxt_il_text(il, amxt_il_text_after_cursor, -1);
                amxt_tty_write(tty, line, len);
                len = -amxt_il_text_length(il, amxt_il_text_after_cursor, 0);
                amxt_tty_cursor_move(tty, len, 0);
                if(wait) {
                    getchar();
                } else {
                    sleep(1);
                }
                amxt_tty_trigger_cmd(tty, &il->buffer, false);
                while(amxp_signal_read() == 0) {
                }
                new_line = true;
            }
        } else {
            if(comment == true) {
                if((buf[0] == '$') || !amxc_string_is_empty(&buffer)) {
                    amxc_string_append(&buffer, buf, 1);
                    if((buf[0] == ')') || (buf[0] == '}')) {
                        amxc_string_resolve(&buffer, &tty->config);
                        amxt_tty_write(tty, amxc_string_get(&buffer, 0),
                                       amxc_string_text_length(&buffer));
                        amxc_string_reset(&buffer);
                    }
                    continue;
                } else {
                    amxt_tty_write(tty, buf, 1);
                }
            } else {
                size_t len = amxt_il_text_length(il, amxt_il_text_after_cursor, -1);
                const char* line = amxt_il_text(il, amxt_il_text_after_cursor, -1);
                if((len == 0) && (buf[0] == '#')) {
                    amxt_tty_writef(tty, "${color.reset}");
                    comment = true;
                    continue;
                }
                if(new_line) {
                    amxt_tty_show_prompt(tty);
                }
                new_line = false;
                amxt_il_insert_block(il, buf, 1);
                amxt_tty_write(tty, line, len);
                len = -amxt_il_text_length(il, amxt_il_text_after_cursor, 0);
                amxt_tty_cursor_move(tty, len, 0);
            }
        }
        usleep(75000);
    }
    amxt_tty_line_clear(tty, amxt_clear_line_all);
    amxt_tty_messagef(tty, "=== PLAYBACK DONE ===\n\n");
    amxc_string_clean(&buffer);
}

static int mod_record_cmd_help(UNUSED const char* function_name,
                               amxc_var_t* args,
                               UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* cmd = amxt_cmd_pop_word(var_cmd);

    amxt_cmd_print_help(tty, help, cmd);

    free(cmd);
    return 0;
}

static int mod_record_cmd_start(UNUSED const char* function_name,
                                amxc_var_t* args,
                                UNUSED amxc_var_t* ret) {
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    amxt_tty_t* tty = GET_TTY(args);
    char* file = amxt_cmd_pop_word(var_cmd);
    int retval = 1;
    int open_flags = O_CREAT | O_WRONLY | O_TRUNC;
    int mode_flags = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[CMD_START].cmd);
        goto exit;
    }

    if(file == NULL) {
        amxt_tty_errorf(tty, "No file name specified\n");
        goto exit;
    }

    if(fd != -1) {
        amxt_tty_errorf(tty, "A recording or  playback is already started\n");
        goto exit;
    }

    fd = open(file, open_flags, mode_flags);
    if(fd == -1) {
        amxt_tty_errorf(tty, "Failed to open file\n");
        goto exit;
    }

    amxp_slot_connect(tty->sigmngr, "tty:record-start", NULL, mod_record_start, tty);
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:record-start", NULL);

    retval = 0;

exit:
    free(file);
    return retval;
}

static int mod_record_cmd_stop(UNUSED const char* function_name,
                               amxc_var_t* args,
                               UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    int retval = 1;

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[CMD_START].cmd);
        goto exit;
    }

    if(fd == -1) {
        amxt_tty_errorf(tty, "No recording started\n");
        goto exit;
    }

    amxp_slot_disconnect(amxt_tty_sigmngr(tty),
                         "tty:cmd-done",
                         mod_record_slot_cmd_done);
    amxt_tty_messagef(tty, "\n=== RECORDING DONE ===\n");

    close(fd);
    fd = -1;

    retval = 0;

exit:
    return retval;
}

static int mod_record_cmd_play(UNUSED const char* function_name,
                               amxc_var_t* args,
                               UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    amxc_var_t options;
    int rv = 0;
    char* file = NULL;
    int retval = 1;
    int open_flags = O_RDONLY;
    amxc_var_init(&options);

    rv = amxt_cmd_parse_options(tty, var_cmd, &options, help[CMD_PLAY].options);
    when_failed(rv, exit);

    file = amxt_cmd_pop_word(var_cmd);
    if(file == NULL) {
        amxt_tty_errorf(tty, "No file name specified\n");
        goto exit;
    }

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[CMD_PLAY].usage);
        goto exit;
    }

    if(fd != -1) {
        amxt_tty_errorf(tty, "A recording or playback is already started\n");
        goto exit;
    }

    fd = open(file, open_flags);
    if(fd == -1) {
        amxt_tty_errorf(tty, "Failed to open file\n");
        goto exit;
    }

    mod_record_type_commands(tty, &options);

    close(fd);
    fd = -1;
    retval = 0;

exit:
    amxc_var_clean(&options);
    free(file);
    return retval;
}

static int mod_record_complete(const char* function_name,
                               amxc_var_t* args,
                               amxc_var_t* ret) {
    amxt_tty_t* tty = amx_cli_get_tty();
    int index = amxt_cmd_index(function_name + 11, help);
    int opt_type = amxt_cmd_complete_option(args, help[index].options, ret);
    if(opt_type == 0) {
        amxt_cmd_complete_path(function_name, args, ret);
    }
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    return 0;
}

static int mod_record_complete_cmd_help(UNUSED const char* function_name,
                                        amxc_var_t* args,
                                        amxc_var_t* ret) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxt_cmd_complete_help(args, help, ret);
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    return 0;
}

static int mod_record_describe(UNUSED const char* function_name,
                               UNUSED amxc_var_t* args,
                               amxc_var_t* ret) {
    amxc_var_set(cstring_t, ret, MOD_DESC);
    return 0;
}

static AMXM_CONSTRUCTOR mod_record_init(void) {
    amxm_module_t* mod = NULL;
    amxm_shared_object_t* so = amxm_get_so("self");

    if(so == NULL) {
        printf("No self\n");
        return 1;
    }

    if(amxm_module_register(&mod, so, MOD) != 0) {
        printf("Couldn't register module\n");
        return 1;
    }

    amxm_module_add_function(mod, "help", mod_record_cmd_help);
    amxm_module_add_function(mod, "start", mod_record_cmd_start);
    amxm_module_add_function(mod, "stop", mod_record_cmd_stop);
    amxm_module_add_function(mod, "play", mod_record_cmd_play);

    // completion functions
    amxm_module_add_function(mod, "__complete_help", mod_record_complete_cmd_help);
    amxm_module_add_function(mod, "__complete_start", mod_record_complete);
    amxm_module_add_function(mod, "__complete_play", mod_record_complete);

    // description
    amxm_module_add_function(mod, "__describe", mod_record_describe);

    return 0;
}

static AMXM_DESTRUCTOR mod_record_cleanup(void) {
    return 0;
}
