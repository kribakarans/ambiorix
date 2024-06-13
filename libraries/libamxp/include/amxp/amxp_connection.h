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

#if !defined(__AMXP_CONNECTION_H__)
#define __AMXP_CONNECTION_H__

#ifdef __cplusplus
extern "C"
{
#endif

/**
   @defgroup amxp_connection Connection management
 */

typedef void (* amxp_fd_cb_t) (int fd, void* priv);

typedef struct _amxp_connection {
    amxc_llist_it_t it;
    char* uri;
    int fd;
    amxp_fd_cb_t reader;
    void* el_data;
    void* priv;
    uint32_t type;
    amxp_fd_cb_t can_write;
} amxp_connection_t;

#define AMXP_CONNECTION_BUS     0
#define AMXP_CONNECTION_LISTEN  1
#define AMXP_CONNECTION_CUSTOM  2

/**
   @ingroup amxp_connection
   @brief
   Adds a file descriptor (fd) to the list of fds that must be watched

   This function will trigger the signal "connection-added" or "listen-added"
   depending on the type given.

   If the type given is "AMXP_CONNECTION_LISTEN" the fd will be added to the list of listen
   fds and the signal "listen-added" is triggered.

   A callback function must be given. This callback function is called whenever
   data is available for read.

   @param fd the fd that must be watched
   @param reader the read callback function, is called when data is available for read
   @param uri (option, can be NULL) a uri representing the fd
   @param type one of AMXP_CONNECTION_BUS, AMXP_CONNECTION_LISTEN, AMXP_CONNECTION_CUSTOM
   @param priv private data, will be passed to the callback function

   @return
   Returns 0 when success, any other value indicates failure.
 */
int amxp_connection_add(int fd,
                        amxp_fd_cb_t reader,
                        const char* uri,
                        uint32_t type,
                        void* priv);

/**
   @ingroup amxp_connection
   @brief
   Adds a watcher to check if a fd is ready for write

   It can happen that a fd is not ready for write. Most of the time the
   write fails with error code EAGAIN or EWOULDBLOCK. Whenever this happens
   it is possible to indicate to the event-loop implementation that the fd
   must be watched and a callback must be called as soon as the fd is available
   again for writing.

   Another use case for this function is a asynchronous connect.

   This function will trigger the signal "connection-wait-write". Event-loop
   implementations can connect to this signal, to add a watcher for the fd.

   Typically when the fd is ready for write the watcher is removed.

   @note
   Before calling this function make sure the fd is added to the list of
   connections using @ref amxp_connection_add

   @param fd the fd that must be watched
   @param can_write_cb a callback function called when the socket is available for write

   @return
   Returns 0 when success, any other value indicates failure.
 */
int amxp_connection_wait_write(int fd,
                               amxp_fd_cb_t can_write_cb);

/**
   @ingroup amxp_connection
   @brief
   Removes the fd from the connection list.

   This function triggers the signal "connection-deleted".

   Event-loop implementations can connect to this signal and when it is triggered
   remove the watchers for the given fd.

   @param fd the fd that must be watched

   @return
   Returns 0 when success, any other value indicates failure.
 */
int amxp_connection_remove(int fd);

/**
   @ingroup amxp_connection
   @brief
   Gets the connection data for a file descriptor

   Searches the connection data for the given fd. The connection data is stored
   in the amxp_connection_t structure.

   @param fd the fd associated with the connection

   @return
   returns pointer to the connection data or NULL if no data is found.
 */
amxp_connection_t* amxp_connection_get(int fd);

/**
   @ingroup amxp_connection
   @brief
   Gets the first connection of the given type

   @param type one of AMXP_CONNECTION_BUS, AMXP_CONNECTION_LISTEN, AMXP_CONNECTION_CUSTOM

   @return
   returns pointer to the connection data or NULL if no data is found.
 */
amxp_connection_t* amxp_connection_get_first(uint32_t type);

/**
   @ingroup amxp_connection
   @brief
   Gets the next connection data for a file descriptor

   @param con starting point reference
   @param type one of AMXP_CONNECTION_BUS, AMXP_CONNECTION_LISTEN, AMXP_CONNECTION_CUSTOM

   @return
   returns pointer to the connection data or NULL if no data is found.
 */
amxp_connection_t* amxp_connection_get_next(amxp_connection_t* con, uint32_t type);

/**
   @ingroup amxp_connection
   @brief
   Sets event-loop data.

   This function is typically used by event-loop implementations to set
   event-loop specific data for the connection

   @param fd the fd that must be watched
   @param el_data some event loop data

   @return
   Returns 0 when success, any other value indicates failure.
 */
int amxp_connection_set_el_data(int fd, void* el_data);

/**
   @ingroup amxp_connection
   @brief
   Get a list of the current connections of the application

   At runtime an application can be connected to a number of sockets. This
   function retrieves a list of sockets the app is connected to.

   @return
   A list with all active socket connections.
 */
amxc_llist_t* amxp_connection_get_connections(void);

/**
   @ingroup amxp_connection
   @brief
   Get of the current listen sockets of the application

   While an application is running, it can have a list of of open listen
   sockets that other applications can connect to.

   @return
   A list with all open listen sockets.
 */
amxc_llist_t* amxp_connection_get_listeners(void);

#ifdef __cplusplus
}
#endif

#endif // __AMXP_CONNECTION_H__

