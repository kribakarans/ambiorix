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

#if !defined(__AMXP_PROC_CTRL_H__)
#define __AMXP_PROC_CTRL_H__

#ifdef __cplusplus
extern "C"
{
#endif

/**
   @file
   @brief
   Ambiorix process control
 */

/**
   @defgroup amxp_proc_ctrl Process Control

   Child Process Control and monitor
 */


/**
   @ingroup amxp_proc_ctrl
   @brief
   Command builder callback function signature.

   A callback function is used to build the command that must be launched.

   In the callback function a configuration file can be built.

   An array must be filled with the command and the command arguments.
 */
typedef int (* amxp_proc_ctrl_cmd_t) (amxc_array_t* cmd, amxc_var_t* settings);

/**
   @ingroup amxp_proc_ctrl
   @brief
   Structure containing the child process control.
 */
typedef struct _amxp_proc_ctrl {
    amxc_array_t cmd;           /**< An array containing the command and the arguments */
    amxp_subproc_t* proc;       /**< The child process information structure @ref amxp_subproc_t */
    amxp_timer_t* timer;        /**< Active timer, when the timer expires, the child porcess is stopped */
    amxc_var_t child_proc_pids; /**< A list variant containing the child process pids of the launched child process */
    amxp_proc_ctrl_cmd_t build; /**< Callback function that fills the command array */
} amxp_proc_ctrl_t;

/**
   @ingroup amxp_proc_ctrl
   @brief
   Allocates and initializes an amxp_proc_ctrl_t

   Allocates memory on the heap for an amxp_proc_ctrl_t structure and initializes it.

   The pointer to the allocated memory will be stored in the proc argument.
   The *proc must be initialized to NULL before calling this function.

   To free all allocated memory use @ref amxp_proc_ctrl_delete.

   @param proc will be filled with the pointer to the new allocated amxp_proc_ctrl_t structure
   @param cmd_build_fn callback function that fills the command array

   @return
   0 when successful, otherwise an error code
 */
int amxp_proc_ctrl_new(amxp_proc_ctrl_t** proc, amxp_proc_ctrl_cmd_t cmd_build_fn);

/**
   @ingroup amxp_proc_ctrl
   @brief
   Clean-up and frees previously allocated memory.

   Each allocated amxp_proc_trl_t structure with @ref amxp_proc_ctrl_new
   must be freed when not needed anymore using this function.

   @param proc pointer to previously allocated amxp_proc_ctrl_t struct, will be set to NULL.
 */
void amxp_proc_ctrl_delete(amxp_proc_ctrl_t** proc);

/**
   @ingroup amxp_proc_ctrl
   @brief
   Launches the child process

   Will call the @ref amxp_proc_ctrl_cmd_t callback function. That callback
   function must fill the command array. The provided variant containing
   child process settings will be passed to the callback function as is.

   When an active time is provided in the argument minutes, a timer is started.
   When the timer expires, the launched process is stopped.

   When the time in minutes is set to 0, no timer is started and the child process
   will keep runnning until stopped.

   @param proc pointer to amxp_proc_ctrl_t structure, previously allocated with @ref amxp_proc_ctrl_new
   @param minutes time in minutes the launched process can keep running
   @param settings a variant containing settings, passed to the callback function as is.

   @return
   0 when successful, otherwise an error code
 */
int amxp_proc_ctrl_start(amxp_proc_ctrl_t* proc, uint32_t minutes, amxc_var_t* settings);

/**
   @ingroup amxp_proc_ctrl
   @brief
   Stops the child process

   Stops the child process and the children of the child process.

   @param proc pointer to amxp_proc_trl_t structure, previously allocated with @ref amxp_proc_ctrl_new

   @return
   0 when successful, otherwise an error code
 */
int amxp_proc_ctrl_stop(amxp_proc_ctrl_t* proc);

/**
   @ingroup amxp_proc_ctrl
   @brief
   Sets the active time durations.

   Sets or changes the active duration.

   If the process was already started with an active time (see @ref amxp_proc_ctrl_start),
   the running timer is stopped and restarted with the new provided time.

   If the process was running without an active time set, the timer is started with
   the given time and the child process will be stopped when the timer expires.

   When the new time is set to 0 the timer is stopped and the child process
   will keep running until stopped manually.

   @param proc pointer to amxp_proc_ctrl_t structure, previously allocated with @ref amxp_proc_ctrl_new
   @param minutes new active time
 */
void amxp_proc_ctrl_set_active_duration(amxp_proc_ctrl_t* proc, uint32_t minutes);

/**
   @ingroup amxp_proc_ctrl
   @brief
   Stop all child processes of the child process.

   A child process monitored with the amxp_proc_ctrl can launch its own
   children. These child processes can be stopped using this function.

   @param proc pointer to amxp_proc_trl_t structure, previously allocated with @ref amxp_proc_ctrl_new
 */
void amxp_proc_ctrl_stop_childs(amxp_proc_ctrl_t* proc);

/**
   @ingroup amxp_proc_ctrl
   @brief
   Fetches the process ids of the children of the launched child process.

   The list of found process ids is stored in the amxp_proc_ctrl_t structure.

   The function returns the number of children found.

   Two methods are used to find the list of children:
   - reading file /proc/[pid]/task/[tid]/children
   - scanning all processes in /proc/ and read /proc/[pid]/stat and check the field parent pid.

   @param proc pointer to amxp_proc_trl_t structure, previously allocated with @ref amxp_proc_ctrl_new

   @return
   the number of children found
 */
int amxp_proc_ctrl_get_child_pids(amxp_proc_ctrl_t* proc);

#ifdef __cplusplus
}
#endif

#endif // __AMXP_PROC_CTRL_H__
