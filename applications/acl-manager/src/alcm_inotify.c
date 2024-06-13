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
#include <string.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#include <debug/sahtrace.h>

#include "aclm.h"
#include "aclm_inotify.h"
#include "aclm_merge.h"
#include "dm_role.h"

#define MAX_EVENTS 1024                                     /* Max. number of events to process at one go */
#define LEN_NAME 256                                        /* Assuming length of the filename won't exceed 8 bytes */
#define EVENT_SIZE ( sizeof(struct inotify_event))          /* Size of one event */
#define BUF_LEN ( MAX_EVENTS * ( EVENT_SIZE + LEN_NAME ))   /* Buffer to store the data of events */

static int inotify_fd = -1;
static amxc_llist_t watch_list;

static int aclm_watch_new(aclm_watch_t** watch, int wd, const char* dir, const char* role) {
    int retval = -1;

    when_null(watch, exit);
    when_true(wd < 0, exit);
    when_str_empty(dir, exit);

    *watch = (aclm_watch_t*) calloc(1, sizeof(aclm_watch_t));
    when_null(*watch, exit);

    (*watch)->wd = wd;
    (*watch)->dir = strdup(dir);
    when_null((*watch)->dir, exit);

    if((role != NULL) && (*role != 0)) {
        (*watch)->role = strdup(role);
    }

    retval = 0;
exit:
    return retval;
}

static void aclm_watch_delete(aclm_watch_t** watch) {
    when_null(watch, exit);
    when_null(*watch, exit);

    if((*watch)->wd > 0) {
        inotify_rm_watch(inotify_fd, (*watch)->wd);
    }
    free((*watch)->role);
    free((*watch)->dir);
    amxc_llist_it_take(&(*watch)->it);
    free(*watch);
    *watch = NULL;

exit:
    return;
}

static int aclm_handle_dir_entry(int fd, const char* root, struct dirent* entry) {
    int wd = 0;
    aclm_watch_t* watch = NULL;
    struct stat sb;
    amxc_string_t full_path;

    amxc_string_init(&full_path, 0);

    if((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0) ||
       (strcmp(entry->d_name, ACLM_MERGE_DIR) == 0)) {
        goto exit;
    }
    amxc_string_setf(&full_path, "%s/%s", root, entry->d_name);

    if((stat(amxc_string_get(&full_path, 0), &sb) != 0) || (!S_ISDIR(sb.st_mode))) {
        goto exit;
    }

    wd = inotify_add_watch(fd, amxc_string_get(&full_path, 0),
                           IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVE);
    SAH_TRACEZ_INFO(ME, "Adding watch for %s with wd = %d", amxc_string_get(&full_path, 0), wd);
    when_true(wd < 0, exit);

    aclm_watch_new(&watch, wd, amxc_string_get(&full_path, 0), entry->d_name);
    amxc_llist_append(&watch_list, &watch->it);

    aclm_role_add(entry->d_name);

exit:
    amxc_string_clean(&full_path);
    return wd;
}

static aclm_watch_t* aclm_watch_from_wd(int wd) {
    amxc_llist_iterate(it, &watch_list) {
        aclm_watch_t* watch = amxc_container_of(it, aclm_watch_t, it);
        if(watch->wd == wd) {
            return watch;
        }
    }
    return NULL;
}

static int aclm_watch_new_dir(const char* parent_dir, const char* child_dir) {
    amxc_string_t full_path;
    int wd = -1;
    aclm_watch_t* watch = NULL;

    amxc_string_init(&full_path, 0);
    amxc_string_setf(&full_path, "%s/%s", parent_dir, child_dir);

    wd = inotify_add_watch(inotify_fd, amxc_string_get(&full_path, 0),
                           IN_CREATE | IN_MODIFY | IN_DELETE);
    SAH_TRACEZ_INFO(ME, "Adding watch for %s with wd = %d", amxc_string_get(&full_path, 0), wd);
    when_true(wd < 0, exit);

    aclm_watch_new(&watch, wd, amxc_string_get(&full_path, 0), child_dir);
    amxc_llist_append(&watch_list, &watch->it);
exit:
    amxc_string_clean(&full_path);
    return wd;
}

static void aclm_find_and_delete_watch(int wd, const char* child_dir) {
    aclm_watch_t* parent_watch = aclm_watch_from_wd(wd);
    aclm_watch_t* child_watch = NULL;
    amxc_string_t full_path;

    amxc_string_init(&full_path, 0);

    when_null(parent_watch, exit);

    amxc_string_setf(&full_path, "%s/%s", parent_watch->dir, child_dir);

    amxc_llist_iterate(it, &watch_list) {
        aclm_watch_t* watch = amxc_container_of(it, aclm_watch_t, it);
        if(strcmp(watch->dir, amxc_string_get(&full_path, 0)) == 0) {
            child_watch = watch;
            break;
        }
    }

    when_null(child_watch, exit);
    SAH_TRACEZ_INFO(ME, "Directory %s was moved or deleted", child_watch->dir);
    aclm_watch_delete(&child_watch);

exit:
    amxc_string_clean(&full_path);
    return;
}

static void aclm_handle_create_or_moved_to(struct inotify_event* event) {
    aclm_watch_t* watch = aclm_watch_from_wd(event->wd);
    if(event->mask & IN_ISDIR) {
        int wd = -1;
        SAH_TRACEZ_INFO(ME, "Directory %s was created under %s\n",
                        event->name, watch->dir);
        wd = aclm_watch_new_dir(watch->dir, event->name);
        if(wd > 0) {
            watch = aclm_watch_from_wd(wd);
            aclm_merge(watch->dir, watch->role);
            aclm_role_add(watch->role);
        }
    } else {
        SAH_TRACEZ_INFO(ME, "The file %s was created in directory %s\n",
                        event->name, watch->dir);
        aclm_merge(watch->dir, watch->role);
    }
}

static void aclm_handle_modify(struct inotify_event* event) {
    if(event->mask & IN_ISDIR) {
        SAH_TRACEZ_WARNING(ME, "Directory %s was modified, not yet sure what this implies",
                           event->name);
    } else {
        aclm_watch_t* watch = aclm_watch_from_wd(event->wd);
        SAH_TRACEZ_INFO(ME, "The file %s was modified in directory %s\n",
                        event->name, watch->dir);
        aclm_merge(watch->dir, watch->role);
    }
}

static void aclm_handle_delete_or_moved_from(struct inotify_event* event) {
    if(event->mask & IN_ISDIR) {
        aclm_role_del(event->name);
        aclm_find_and_delete_watch(event->wd, event->name);
    } else {
        aclm_watch_t* watch = aclm_watch_from_wd(event->wd);
        SAH_TRACEZ_INFO(ME, "The file %s was deleted in or moved from directory %s\n",
                        event->name, watch->dir);
        aclm_merge(watch->dir, watch->role);
    }
}

static void aclm_watch_it_delete(amxc_llist_it_t* it) {
    aclm_watch_t* watch = amxc_container_of(it, aclm_watch_t, it);
    aclm_watch_delete(&watch);
}

static void aclm_inotify_cb(UNUSED int fd, UNUSED void* priv) {
    char buffer[BUF_LEN] = {};
    int len = 0;
    int i = 0;

    SAH_TRACEZ_INFO(ME, "Received new inotify event");
    len = read(fd, buffer, BUF_LEN - 1);
    when_true(len < 0, exit);

    while(i < len) {
        struct inotify_event* event = (struct inotify_event*) &buffer[i];
        if(event->mask & IN_CREATE) {
            aclm_handle_create_or_moved_to(event);
        }
        if(event->mask & IN_MODIFY) {
            aclm_handle_modify(event);
        }
        if(event->mask & IN_DELETE) {
            SAH_TRACEZ_INFO(ME, "Directory %s was deleted", event->name);
            aclm_handle_delete_or_moved_from(event);
        }
        if(event->mask & IN_MOVED_TO) {
            aclm_handle_create_or_moved_to(event);
        }
        if(event->mask & IN_MOVED_FROM) {
            SAH_TRACEZ_INFO(ME, "Directory was moved from %s", event->name);
            aclm_handle_delete_or_moved_from(event);
        }
        i += EVENT_SIZE + event->len;
    }

exit:
    return;
}

static int aclm_add_watches(int fd, const char* root) {
    int wd = -1;
    int retval = -1;
    aclm_watch_t* watch = NULL;
    DIR* dp = NULL;
    struct dirent* entry = NULL;

    wd = inotify_add_watch(fd, root, IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVE);
    SAH_TRACEZ_INFO(ME, "Adding watch for %s with wd = %d", root, wd);
    when_true(wd < 0, exit);

    aclm_watch_new(&watch, wd, root, NULL);
    amxc_llist_append(&watch_list, &watch->it);

    dp = opendir(root);
    when_null(dp, exit);

    for(entry = readdir(dp); entry; entry = readdir(dp)) {
        retval = aclm_handle_dir_entry(fd, root, entry);
        when_true(retval < 0, exit);
    }

    retval = 0;
exit:
    if(dp != NULL) {
        closedir(dp);
    }
    return retval;
}

static void aclm_watches_merge_all(void) {
    amxc_llist_iterate(it, &watch_list) {
        aclm_watch_t* watch = amxc_container_of(it, aclm_watch_t, it);
        if(watch->role != NULL) {
            aclm_merge(watch->dir, watch->role);
        }
    }
}

int aclm_inotify_init(const char* acl_dir) {
    int retval = -1;
    amxo_parser_t* parser = aclm_get_parser();

    amxc_llist_init(&watch_list);

    inotify_fd = inotify_init();
    when_true(inotify_fd < 0, exit);

    retval = aclm_add_watches(inotify_fd, acl_dir);
    when_failed(retval, exit);

    amxo_connection_add(parser, inotify_fd, aclm_inotify_cb, NULL, AMXO_CUSTOM, NULL);

    aclm_watches_merge_all();

exit:
    return retval;
}

void aclm_inotify_clean(void) {
    amxo_parser_t* parser = aclm_get_parser();
    amxc_llist_clean(&watch_list, aclm_watch_it_delete);
    if(inotify_fd != -1) {
        amxo_connection_remove(parser, inotify_fd);
        close(inotify_fd);
    }
}

