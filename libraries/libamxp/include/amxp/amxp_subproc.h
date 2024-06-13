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


#if !defined(__AMXP_SUBPROC_H__)
#define __AMXP_SUBPROC_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/types.h>
#include <amxc/amxc_llist.h>
#include <amxp/amxp_signal.h>

/**
   @file
   @brief
   Ambiorix sub-proccess API header file
 */

/**
   @defgroup amxp_subproc Sub-processes

   @brief
   API to help in launching and monitoring child processes
 */

/**
   @ingroup amxp_subproc
   @brief
   Child process information structure
 */

typedef struct _subproc_t {
    amxc_llist_it_t it;
    pid_t pid;                   /**< The PID of the process */
    bool is_running;             /**< True if the process is currently running */
    int fd[3][2];                /**< fd pairs for FILENO_STDIN, FILENO_STDOUT, FILENO_STDERR,
                                      parent end (0) and child end (1) */
    amxp_signal_mngr_t* sigmngr; /**< Signal manager used to emit signals specific to
                                      the launched child process. See @ref amxp_signal_mngr */
    int status;                  /**< Status of the child process */
} amxp_subproc_t;

/**
   @ingroup amxp_subproc
   @brief
   Constructor function, creates a new child process data structure.

   This function allocates memory, to free the allocated memory use the
   destruction function @ref amxp_subproc_delete

   The *subproc argument must be initialized to NULL before calling this function.

   This function doesn't start the child process. To start a child process use
   @ref amxp_subproc_vstart or @ref amxp_subproc_start.

   @param subproc where to store the subproc pointer

   @return
   0 when successful, otherwise an error code
 */
int amxp_subproc_new(amxp_subproc_t** subproc);

/**
   @ingroup amxp_subproc
   @brief
   Destructor function, deletes a child process data structure.

   This function doesn't stop the child process. To stop a child process use
   @ref amxp_subproc_kill

   @param subproc pointer to the subproc pointer. Will be set to NULL

   @return
   0 when successful, otherwise an error code
 */
int amxp_subproc_delete(amxp_subproc_t** subproc);

/**
   @ingroup amxp_subproc
   @brief
   Opens standard file descriptor to the child process.

   It is possible to read the child stdout or stderr to monitor it's output or
   to write to the child stdin file descriptor.

   @param subproc pointer to the subproc
   @param requested must be one of STDIN_FILENO, STDOUT_FILENO or STDERR_FILENO

   @return
   The opened file descriptor or -1 when an error occurred
 */
int amxp_subproc_open_fd(amxp_subproc_t* subproc, int requested);

/**
   @ingroup amxp_subproc
   @brief
   Start a child process

   Forks and executes a command. Will monitor the child process and handles
   SIGCHLD.

   The process name and it's arguments must be passed as an array of strings,
   the last item in the array must be a NULL pointer.

   Example:
   @code{.c}
       const char* cmd[] = { "dropbear", "-p", "10022", "-F", "-E", "-R", NULL };
       amxp_subproc_vstart(subproc, (char **) cmd);
   @endcode

   @param subproc pointer to the subproc
   @param argv the child process and its arguments

   @return
   0 when child process is launched, any other value when an error occurred
 */
int amxp_subproc_vstart(amxp_subproc_t* const subproc,
                        char** argv);

/**
   @ingroup amxp_subproc
   @brief
   Start a child process

   Forks and executes a command. Will monitor the child process and handles
   SIGCHLD.

   The process name and it's arguments must be passed as individual arguments
   to this function. The last argument must be a NULL pointer.

   Example:
   @code{.c}
       amxp_subproc_start(subproc, (char*)"dropbear", "-p", "10022", "-F", "-E", "-R", NULL);
   @endcode

   @param subproc pointer to the subproc
   @param cmd the child process

   @return
   0 when child process is launched, any other value when an error occurred
 */
int amxp_subproc_start(amxp_subproc_t* const subproc,
                       char* cmd,
                       ...);

/**
   @ingroup amxp_subproc
   @brief
   Start a child process

   Forks and executes a command. Will monitor the child process and handles
   SIGCHLD.

   The process name and its arguments must be passed as an amxc_array_t, where
   all items must be char * and the first item (index 0) is the process name.

   When an empty item is encountered in the array (item containing a NULL pointer),
   it is considered as the end of the process argument list.

   Example:
   @code{.c}
       amxc_array_t cmd;
       amxc_array_init(&cmd, 10);
       amxc_array_append_data(&cmd, "dropbear");
       amxc_array_append_data(&cmd, "-p");
       amxc_array_append_data(&cmd, "10022");
       amxc_array_append_data(&cmd, "-F");
       amxc_array_append_data(&cmd, "-E");
       amxc_array_append_data(&cmd, "-R");
       amxp_subproc_astart(subproc, &cmd);
       amxc_array_clean(&cmd, NULL);
   @endcode

   @param subproc pointer to the subproc
   @param cmd the child process

   @return
   0 when child process is launched, any other value when an error occurred
 */
int amxp_subproc_astart(amxp_subproc_t* const subproc,
                        amxc_array_t* cmd);

/**
   @ingroup amxp_subproc
   @brief
   Sends a Linux signal to the child process

   When the child process is not running this function has no effect.

   @note
   When stopping a child process make sure that the SIGCHILD is correctly handled.
   This can be done using @ref amxp_subproc_wait.

   Example:
   @code{.c}
       amxp_subproc_kill(subproc, SIGTERM);
       amxp_subproc_wait(subproc, 2);
   @endcode

   @param subproc pointer to the subproc
   @param sig the signal id

   @return
   0 when signal is send successful, any other value when an error occurred.
 */
int amxp_subproc_kill(const amxp_subproc_t* const subproc, const int sig);

/**
   @ingroup amxp_subproc
   @brief
   Waits until the child process has stopped

   This function is blocking and will return either when the child process has
   stopped or when a timeout occurs.

   @param subproc pointer to the subproc
   @param timeout_msec time out in milli-seconds

   @return
   -1 - an error occurred
   0 child exited
   1 timeout reached, child is still running
 */
int amxp_subproc_wait(amxp_subproc_t* subproc, int timeout_msec);

/**
   @ingroup amxp_subproc
   @brief
   Starts a child process and waits until it exits

   This function is blocking and will return either when the child process has
   exited or when a timeout occurs.

   When the child process was not able to start an error is returned

   This function first launches the child process by calling @ref amxp_subproc_vstart
   and then waits until it exits using @ref amxp_subproc_wait.

   @param subproc pointer to the subproc
   @param timeout_msec time out in milli seconds
   @param cmd the command used to launch the child process

   @return
   -1 - an error occurred
   0 child launched and exited
   1 timeout reached, child is still running
 */
int amxp_subproc_vstart_wait(amxp_subproc_t* subproc, int timeout_msec, char** cmd);

/**
   @ingroup amxp_subproc
   @brief
   Starts a child process and waits until it exits

   This function is blocking and will return either when the child process has
   exited or when a timeout occurs.

   When the child process was not able to start an error is returned

   This function calls @ref amxp_subproc_vstart_wait to launch the child
   process and to wait until the child exits.

   @param subproc pointer to the subproc
   @param timeout_msec time out in milli seconds
   @param cmd the command used to launch the child process

   @return
   -1 - an error occurred
   0 child launched and exited
   1 timeout reached, child is still running
 */
int amxp_subproc_start_wait(amxp_subproc_t* subproc, int timeout_msec, char* cmd, ...);

/**
   @ingroup amxp_subproc
   @brief
   Retrieve a @ref amxp_subproc_t for a child process using it's process identifier

   Searches in the list of launched and running child processes for a child
   process with a specific process id and returns the @ref amxp_subproc_t pointer
   representing the child process.

   @param pid Process id of the child process

   @return
   pointer to @ref amxp_subproc_t that represents the child process or
   NULL when no child process with the give pid is found.
 */
amxp_subproc_t* amxp_subproc_find(const int pid);

/**
   @ingroup amxp_subproc
   @brief
   Get the PID of a child process

   When the provide @ref amxp_subproc_t is not representing a running child
   process the return pid is 0.

   @param subproc ponter to the @ref amxp_subproc_t structure

   @return
   Process id of the child process, or 0 when not running
 */
pid_t amxp_subproc_get_pid(const amxp_subproc_t* const subproc);

/**
   @ingroup amxp_subproc
   @brief
   Get the @ref amxp_signal_mngr of the child process

   Using the signal manager callback functions (@ref amxp_slots) can be
   connected to the child process.

   The child process will trigger signal "stop" when it exits.
   The data of the signal will contain all the Linux system signal information.

   @see @ref amxp_signal_slots for more information about the Ambiorix
   signal/slot mechanism (observer)

   @param subproc pointer to the @ref amxp_subproc_t structure

   @return
   Pointer to the signal manager (@ref amxp_signal_mngr_t)
 */
amxp_signal_mngr_t* amxp_subproc_get_sigmngr(const amxp_subproc_t* const subproc);

/**
   @ingroup amxp_subproc
   @brief
   Checks if the child process is running.

   Returns true when the child process is running

   @param subproc pointer to the @ref amxp_subproc_t structure

   @return
   true when running, false otherwise
 */
bool amxp_subproc_is_running(const amxp_subproc_t* const subproc);

/**
   @ingroup amxp_subproc
   @brief
   Checks if the child process terminated normally

   Evaluates to a non-zero value if status was returned for a child process that
   terminated normally.

   @param subproc pointer to the @ref amxp_subproc_t structure

   @return
   non-zero value if status was returned for a child process that terminated normally.
 */
int amxp_subproc_ifexited(amxp_subproc_t* subproc);

/**
   @ingroup amxp_subproc
   @brief
   Checks if the child process was stopped because of an uncaught Linux signal.

   Evaluates to a non-zero value if status was returned for a child process that
   terminated due to the receipt of a signal that was not caught (see <signal.h>).

   @param subproc pointer to the @ref amxp_subproc_t structure

   @return
   non-zero value if status was returned for a child process that terminated
   due to the receipt of a signal that was not caught.
 */
int amxp_subproc_ifsignaled(amxp_subproc_t* subproc);

/**
   @ingroup amxp_subproc
   @brief
   Gets the exit code of the child process

   If the value of WIFEXITED(stat_val) is non-zero, this function evaluates to
   the low-order 8 bits of the status argument that the child process passed to
    _exit() or exit(), or the value the child process returned from main().

   @param subproc pointer to the @ref amxp_subproc_t structure

   @return
   Child process exit code
 */
int amxp_subproc_get_exitstatus(amxp_subproc_t* subproc);

/**
   @ingroup amxp_subproc
   @brief
   Gets the Linux signal id that caused the child process to stop

   If the value of WIFSIGNALED(stat_val) is non-zero, this function evaluates to
   the number of the signal that caused the termination of the child process.

   @param subproc pointer to the @ref amxp_subproc_t structure

   @return
   Signal id that caused the child process to stop
 */
int amxp_subproc_get_termsig(amxp_subproc_t* subproc);

#ifdef __cplusplus
}
#endif

#endif // __AMXP_SUBPROC_H__
