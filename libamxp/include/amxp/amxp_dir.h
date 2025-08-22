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

#if !defined(__AMXP_DIR_H__)
#define __AMXP_DIR_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

/**
   @file
   @brief
   Ambiorix directory utilities
 */

/**
   @defgroup amxp_dir Directory Utilities

   File system directory utilities and helper functions
 */

/**
   @ingroup amxp_dir
   @brief
   Matching file/directory callback function signature.

   The @ref amxp_dir_scan function will call the callback function for each
   matching file or directory found.

   @param name full path of the matching file or directory
   @param priv a pointer to some data, provided to @ref amxp_dir_scan

   @return
   When the callback function returns a non-zero value, the scan of the
   directory stops.
 */
typedef  int (* amxp_dir_match_fn_t) (const char* name, void* priv);

/**
   @ingroup amxp_dir
   @brief
   Creates sub-directories

   This function will create all sub-directories, if not existing yet.

   If the path provided contains intermediate sub-directories that don't exist,
   they will be created.

   @param path relative or absolute path to sub-directories that needs to be created
   @param mode the argument mode specifies the permissions to use

   @return
   0 when all directories has been created, otherwise an error occurred
 */
int amxp_dir_make(const char* path, const mode_t mode);

/**
   @ingroup amxp_dir
   @brief
   Creates sub-directories and changes ownership.

   This function will create all sub-directories, if not existing yet.

   When a (sub)directory is created and the given user id and group id are not 0,
   ownership is changed and set to the given user id and group id.

   @param path relative or absolute path to sub-directories that needs to be created
   @param mode the argument mode specifies the permissions to use
   @param uid a user id
   @param gid a group id

   @return
   0 when all directories has been created, otherwise an error occurred
 */
int amxp_dir_owned_make(const char* path, const mode_t mode, uid_t uid, gid_t gid);

/**
   @ingroup amxp_dir
   @brief
   Scans a directory and calls a callback function for each matching entry found

   When no filter is provided, all found entries are considered a match.

   The filter works on the directory entry data. The fields that can be used are:
   - d_name
   - d_type
   - d_ino

   When the  argument recursive is set to true, the scan will enter all found
   directories and scan these as well.

   Filter examples:
   - "d_type == DT_REG" - all regular files are matching
   - "d_type == DT_LNK" - all symbolic links are matching
   - "d_type == DT_REG && d_name matches '.*\\.so'" - all regular files with extention so are matching

   @param path relative or absolute path to a directory that needs to be scanned
   @param filter (optional) an expression that can be used to filter to directory entries
   @param recursive when set to true all found sub-directories will be scanned as well.
   @param fn callback function which is called for each matching entry
   @param priv some private data, will be passed to the callback function

   @return
   0 when scan was successful, otherwise an error occurred
 */
int amxp_dir_scan(const char* path,
                  const char* filter,
                  bool recursive,
                  amxp_dir_match_fn_t fn,
                  void* priv);

/**
   @ingroup amxp_dir
   @brief
   Checks if a directory is empty

   A directory is considered empty when it doesn't contain any file or sub-directory.

   if the given path doesn't exist or is not a directory this function will return
   true.

   @param path relative or absolute path to a directory that needs to be scanned

   @return
   true when the path is an empty directory, doesn't exist or isn't a directory.
 */
bool amxp_dir_is_empty(const char* path);

/**
   @ingroup amxp_dir
   @brief
   Checks if a path is a directory.

   @param path relative or absolute path to a file or directory

   @return
   true when the path is a directory.
 */
bool amxp_dir_is_directory(const char* path);

#ifdef __cplusplus
}
#endif

#endif // __AMXP_DIR_H__