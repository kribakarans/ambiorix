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

#if !defined(__AMXO_H__)
#define __AMXO_H__

#ifdef __cplusplus
extern "C"
{
#endif

#if !defined(USE_DOXYGEN)
#define AMXO_INLINE static inline
#else
#define AMXO_INLINE
#endif

#include <amxo/amxo_types.h>
#include <amxo/amxo_resolvers.h>
#include <amxo/amxo_hooks.h>
#include <amxo/amxo_mibs.h>
#include <amxo/amxo_save.h>
#include <amxs/amxs.h>

/**
   @file
   @brief
   Ambiorix ODL parser header file
 */

/**
   @defgroup amxo_parser ODL Parser

   Ambiorix ODL parser API

   Defining a data model pure in code is not a pleasant job and very
   repititive. Using an ODL file makes this job a lot easier.

   The odl parser will read the file and create the data model as described
   in that file. The parser can resolve data model function using function
   resolvers, see @ref amxo_resolver
 */

/**
   @ingroup amxo_parser
   @brief
   Returns the version of lib amxo

   Returns the version of lib amxo in string format X.Y.Z, where X is the major,
   Y is the minor and Z is the build number.

   @return
   a zero terminated string
 */
const char* amxo_lib_version(void);

/**
   @ingroup amxo_parser
   @brief
   Initializes a new odl parser instance

   Before using an odl parser, it must be initialized.
   This function is typically called when the parser is declared on the stack.

   When done parsing ODL files, a clean-up of the parser content must be done
   using @ref amxo_parser_clean.

   A odl parser instance can be used multiple times, there is no need for a new
   parser instance to parse another odl file. the same instance can be re-used.

   @note
   Failing to clean the odl parser content could lead to memory leaks.

   @code{.c}
      int load_data_model(amxd_dm_t *dm) {
          int retval = 0;
          amxo_parser_t parser;
          amxd_object_t *root = amxd_dm_get_root(dm);

          amxo_parser_init(&parser);
          retval = amxo_parser_parse_file(&parser, "my_dm_definition.odl", root);
          amxo_parser_clean(&parser);

          return retval;
      }
   @endcode

   @param parser pointer to an odl parser instance

   @return
   0 when successful, otherwise an error code
 */
int amxo_parser_init(amxo_parser_t* parser);

/**
   @ingroup amxo_parser
   @brief
   Cleans up the odl parser instance.

   When done parsing odl files, the parser content must be cleaned.

   @note
   Failing to clean the odl parser content could lead to memory leaks.

   @code{.c}
      int load_data_model(amxd_dm_t *dm) {
          int retval = 0;
          amxo_parser_t parser;
          amxd_object_t *root = amxd_dm_get_root(dm);

          amxo_parser_init(&parser);
          retval = amxo_parser_parse_file(&parser, "my_dm_def.odl", root);
          amxo_parser_clean(&parser);

          return retval;
      }
   @endcode

   @param parser pointer to an odl parser instance
 */
void amxo_parser_clean(amxo_parser_t* parser);

/**
   @ingroup amxo_parser
   @brief
   Allocates memory for a new parser instance on the heap and
   initializes the odl parser

   Before using an odl parser, it must be created and initialized.
   This function is typically called when the parser must be allocated on the
   heap.

   When done parsing ODL files, a clean-up of the parser content can be done
   using @ref amxo_parser_clean. Or when the parser is not needed anymore
   it can be deleted using @ref amxo_parser_delete

   A odl parser instance can be used multiple times, there is no need for a new
   parser instance to parse another odl file. the same instance can be re-used.

   @note
   Failing to delete the odl parser will lead to memory leaks.

   @code{.c}
      int load_data_model(amxd_dm_t *dm) {
          int retval = 0;
          amxo_parser_t *parser = NULL;
          amxd_object_t *root = amxd_dm_get_root(dm);

          amxo_parser_new(&parser);
          retval = amxo_parser_parse_file(parser, "my_dm_def.odl", root);
          amxo_parser_delete(parser);

          return retval;
      }
   @endcode

   @param parser pointer to a pointer to an odl parser instance

   @return
   0 when successful, otherwise an error code
 */
int amxo_parser_new(amxo_parser_t** parser);

/**
   @ingroup amxo_parser
   @brief
   Cleans the odl parser content and frees the allocated memory.

   When done parsing odl files, the parser content must be deleted.

   @note
   Only use this function when the parser was created with @ref amxo_parser_new

   @note
   Failing to delete the odl parser will lead to memory leaks.

   @code{.c}
      int load_data_model(amxd_dm_t *dm) {
          int retval = 0;
          amxo_parser_t *parser = NULL;
          amxd_object_t *root = amxd_dm_get_root(dm);

          amxo_parser_new(&parser);
          retval = amxo_parser_parse_file(parser, "my_dm_def.odl", root);
          amxo_parser_delete(parser);

          return retval;
      }
   @endcode

   @param parser pointer to a pointer to an odl parser instance
 */
void amxo_parser_delete(amxo_parser_t** parser);

/**
   @ingroup amxo_parser
   @brief
   Parses an odl file

   Reads and parses the odl file.
   During parsing of the odl file a data model is created or changed.

   Objects will be added as a child of the provided data model object.
   Typically the data model root object will be used.

   @code{.c}
      int load_data_model(amxd_dm_t *dm) {
          int retval = 0;
          amxo_parser_t parser;
          amxd_object_t *root = amxd_dm_get_root(dm);
          int fd = -1;

          fd = open(my_dm_def.odl, O_RDONLY);
          if (fd != -1) {
              amxo_parser_init(&parser);
              retval = amxo_parser_parse_fd(&parser, fd, root);
              amxo_parser_clean(&parser);
          }
          return retval;
      }
   @endcode

   @param parser the odl parser instance
   @param fd Valid file descriptor
   @param object the root object. All new objects defined in the odl file will
                 by added in this object

    @return
    On success 0 is returned, 1 on failure.
    When parsing failed, more information about the reason can be found in the
    status field or message field. Use @ref amxo_parser_get_status and
    @ref amxo_parser_get_message respectivily.
 */
int amxo_parser_parse_fd(amxo_parser_t* parser,
                         int fd,
                         amxd_object_t* object);

/**
   @ingroup amxo_parser
   @brief
   Parses an odl file

   Opens the odl file and parses it.
   During parsing of the odl file a data model is created or changed.

   Objects will be added as a child of the provided data model object.
   Typically the data model root object will be used.

   This function changes the current working directory while parsing
   the odl file. During the parsing process the current working directory
   is set to the odl's file directory. The current working directory is
   reset to the orignal when parsing is done (success or failure). All include
   files (without path) are always searched in the current working directory

   If this behaviour is unwanted, use @ref amxo_parser_parse_fd instead.

   @code{.c}
      int load_data_model(amxd_dm_t *dm) {
          int retval = 0;
          amxo_parser_t parser;
          amxd_object_t *root = amxd_dm_get_root(dm);

          amxo_parser_init(&parser);
          retval = amxo_parser_parse_file(&parser, "my_dm_def.odl", root);
          amxo_parser_clean(&parser);

          return retval;
      }
   @endcode

   @param parser the odl parser instance
   @param file_path full or relative path to an odl file
   @param object the root object. All new objects defined in the odl file will
                 by added in this object

    @return
    On success 0 is returned, 1 on failure.
    When parsing failed, more information about the reason can be found in the
    status field or message field. Use @ref amxo_parser_get_status and
    @ref amxo_parser_get_message respectivily.
 */
int amxo_parser_parse_file(amxo_parser_t* parser,
                           const char* file_path,
                           amxd_object_t* object);

/**
   @ingroup amxo_parser
   @brief
   Parses a string containing a valid ODL part

   Parses the provided string.
   During parsing of the odl string a data model is created or changed.

   Objects will be added as a child of the provided data model object.
   Typically the data model root object will be used.

   @code{.c}
      int load_data_model(amxd_dm_t *dm) {
          int retval = 0;
          amxo_parser_t parser;
          amxd_object_t *root = amxd_dm_get_root(dm);

          amxo_parser_init(&parser);
          retval = amxo_parser_parse_string(&parser, "include \"my_dm_def.odl\"", root);
          amxo_parser_clean(&parser);

          return retval;
      }
   @endcode

   @param parser the odl parser instance
   @param text A string containing an odl part
   @param object the root object. All new objects defined in the odl file will
                 by added in this object

    @return
    On success 0 is returned, 1 on failure.
    When parsing failed, more information about the reason can be found in the
    status field or message field. Use @ref amxo_parser_get_status and
    @ref amxo_parser_get_message respectivily.
 */
int amxo_parser_parse_string(amxo_parser_t* parser,
                             const char* text,
                             amxd_object_t* object);

/**
   @ingroup amxo_parser
   @brief
   Get the status of the odl parser

   When parsing fails the status can provide more information about the failure
   reason.

   The status is reset to amxd_status_ok when starting a new parse using
   @ref amxo_parser_parse_file, @ref amxo_parser_parse_fd or
   @ref amxo_parser_parse_string, or when calling @ref amxo_parser_clean

   Typically this function is called when parsing has failed.

   @code{.c}
      int load_data_model(amxd_dm_t *dm) {
          int retval = 0;
          amxo_parser_t parser;
          amxd_object_t *root = amxd_dm_get_root(dm);

          amxo_parser_init(&parser);
          retval = amxo_parser_parse_file(&parser, "my_dm_def.odl", root);
          if (retval != 0) {
              printf("ODL parsing failed - status = %d\n", amxo_parser_get_status(parser));
          }
          amxo_parser_clean(&parser);

          return retval;
      }
   @endcode

   @param parser the odl parser instance

    @return
    Returns the status of the parser.
 */
AMXO_INLINE
amxd_status_t amxo_parser_get_status(amxo_parser_t* parser) {
    return parser == NULL ? amxd_status_ok : parser->status;
}

/**
   @ingroup amxo_parser
   @brief
   Get the failure message in human readable form

   When parsing fails the message can provide more information about the
   failure reason.

   When parsing was successful or when no parsing was done a NULL pointer is
   returned.

   Typically this function is called when parsing has failed.

   The messages is reset to NULL when starting a new parse using
   @ref amxo_parser_parse_file, @ref amxo_parser_parse_fd or
   @ref amxo_parser_parse_string, or when calling @ref amxo_parser_clean

   @code{.c}
      int load_data_model(amxd_dm_t *dm) {
          int retval = 0;
          amxo_parser_t parser;
          amxd_object_t *root = amxd_dm_get_root(dm);

          amxo_parser_init(&parser);
          retval = amxo_parser_parse_file(&parser, "my_dm_def.odl", root);
          if (retval != 0) {
              printf("ODL parsing failed - message = %s\n", amxo_parser_get_message(parser));
          }
          amxo_parser_clean(&parser);

          return retval;
      }
   @endcode

   @param parser the odl parser instance

   @return
    The human readable failure message or NULL when there is no message available
 */
AMXO_INLINE
const char* amxo_parser_get_message(amxo_parser_t* parser) {
    return parser == NULL ? NULL : amxc_string_get(&parser->msg, 0);
}

/**
   @ingroup amxo_parser
   @brief
   Get the current file name that is being parsed

   During parsing (in parser hooks) you can get the file name of the current
   file being parsed.

   if a string is being parser - see @ref amxo_parser_parse_string - or parsing
   is started with a file descriptor - see @ref amxo_parser_parse_fd - this
   function will return the string "<unknown>".

   When parsing fails it will return the top level file name, and not the file
   name where the error occured, in case of included odl files.

   @param parser the odl parser instance

   @return
   The file name being parsed or the string "<unknown>" when no file name is
   available.
 */
AMXO_INLINE
const char* amxo_parser_get_file(amxo_parser_t* parser) {
    return parser == NULL ? NULL : parser->file;
}

/**
   @ingroup amxo_parser
   @brief
   Get the current line number that is being parsed

   During parsing (in parser hooks) you can get the line number of the current
   file being parsed.

   When parsing fails it will return the top line number of the top level file,
   in case of included odl files.

   @param parser the odl parser instance

   @return
   The current line number.
 */
AMXO_INLINE
uint32_t amxo_parser_get_line(amxo_parser_t* parser) {
    return parser == NULL ? 0 : parser->line;
}

/**
   @ingroup amxo_parser
   @brief
   Adds an entry point function.

   The parser itself will not call entry points, but will add entry-points if
   defined in the odl.

   Any application or library can add extra entry points to the parser.

   It is up to the application or library that initiates the odl parsing to
   invoke the entry points, see @ref amxo_parser_invoke_entry_points

   Entry point functions must comply with the following signature:

   @code{.c}
   typedef int (*amxo_entry_point_t) (int reason,
                                      amxd_dm_t *dm,
                                      amxo_parser_t *parser);
   @endcode

   @param parser the odl parser instance
   @param fn a valid function pointer (can not be NULL)

   @return
   Returns 0 when success, any other value indicates failure.
 */
int amxo_parser_add_entry_point(amxo_parser_t* parser,
                                amxo_entry_point_t fn);

/**
   @ingroup amxo_parser
   @brief
   Invokes all registered entry points.

   In an odl file entry-points can be defined.  Any application or library can
   register extra entry-points using @ref amxo_parser_add_entry_point.

   It is up to the application to invoke these entry-point functions, the parser
   itself will not call them at any time.

   Provide a well defined reason identifier when invoking the entry point
   functions. The ODL parser library defines two reasons:

   - AMXO_START
   - AMXO_END

   If one of the entry points returns a failure (not 0), the other entry points
   are still called.

   If all entry points are executed successfull and post-include files are available
   these will be loaded as well.

   @param parser the odl parser instance
   @param dm pointer to the data model
   @param reason a reason identifier

   @return
   Returns 0 when success.
   A possitive number indicates the number of failed entry points.
   A negative number indicates failre on the parser side.
 */
int amxo_parser_invoke_entry_points(amxo_parser_t* parser,
                                    amxd_dm_t* dm,
                                    int reason);

/**
   @ingroup amxo_parser
   @brief
   Invokes all registered entry points in reversed order.

   In an odl file entry-points can be defined.  Any application or library can
   register extra entry-points using @ref amxo_parser_add_entry_point.

   It is up to the application to invoke these entry-point functions, the parser
   itself will not call them at any time.

   Provide a well defined reason identifier when invoking the entry point
   functions. The ODL parser library defines two reasons:

   - AMXO_START
   - AMXO_END

   If one of the entry points returns a failure (not 0), the other entry points
   are still called.

   @param parser the odl parser instance
   @param dm pointer to the data model
   @param reason a reason identifier

   @return
   Returns 0 when success.
   A possitive number indicates the number of failed entry points.
   A negative number indicates failure on the parser side.
 */
int amxo_parser_rinvoke_entry_points(amxo_parser_t* parser,
                                     amxd_dm_t* dm,
                                     int reason);

/**
   @ingroup amxo_parser
   @brief
   Start all object and parameter synchronizations that were declared in the loaded
   odl files.

   In an odl file object and parameter synchronization can be set up. All the
   synchronization contexts declared in odl files will be managed by the parser.

   This function will initialize and start the synchronization. Stopping the
   synchronizations managed by the parser is done using @ref amxo_parser_stop_synchronize.

   The function can be called multiple times, without having any effect on
   already running synchronizations. This will allow the load of other odl files
   that add extra object and parameter synchronizations.

   If no synchronizations were declared in the odl file, this function will have
   no effect.

   @note
   Declared synchronizations will fail if one of the synchronization objects is
   not available in any data model.

   @param parser the odl parser instance

   @return
   Returns 0 when success.
   Any other value indicates the number of synchronization contexts that failed
   to start.
 */
int amxo_parser_start_synchronize(amxo_parser_t* parser);

/**
   @ingroup amxo_parser
   @brief
   Stop all object and parameter synchronizations that were declared in odl files.

   In an odl file object and parameter synchronization can be set up. Calling this
   will stop all the synchronization contexts that were declared in odl files.

   If all synchronizations that were declared in odl files are already stopped,
   this function will have no effect.

   If no synchronizations were declared in the odl file, this function will have
   no effect.

   @param parser the odl parser instance
 */
void amxo_parser_stop_synchronize(amxo_parser_t* parser);

/**
   @ingroup amxo_parser
   @brief
   Create a new synchronization context from a synchronization template.

   The paths provided to this function must match (at supported data model level) with
   the paths set in the template.

   The paths provided must both point to existing objects, if one of them does not exist,
   creation of the new context fails.

   @param template the synchronization template name
   @param object_a the path that must be used as path A in the new synchronization context
   @param object_b the path that must be used as path B in the new synchronization context

   @return
   - NULL if failed to create the synchronization context.
   - New synchronization context
 */
amxs_sync_ctx_t* amxo_parser_new_sync_ctx(const char* sync_template,
                                          const char* object_a,
                                          const char* object_b);
/**
   @defgroup amxo_parser_config ODL Parser Configuration Options
   @ingroup amxo_parser

   Ambiorix ODL parser configuration API

   A parser can contain configuration options.
   Accessing these configuration options can be done using these functions.
 */

/**
   @ingroup amxo_parser_config
   @brief
   Gets a configuration option

   The configuration options can be used by the function resolvers, the
   parser or the application itself

   Configuration options change the behaviour of the parser, resolvers or the
   application itself

   @note
   Freeing the returned amxc_var_t* using amxc_var_delete will remove the configuration
   option.

   @param parser the odl parser instance
   @param path the path of the configuration option

   @return
   Returns the config option as a variant or NULL when no option found with
   the name given. Freeing the returned variant will remove the config.
 */
amxc_var_t* amxo_parser_get_config(amxo_parser_t* parser,
                                   const char* path);

/**
   @ingroup amxo_parser_config
   @brief
   Gets or creates a configuration option.

   The configuration options can be used by the function resolvers, the
   parser or the application itself

   Configuration options change the behaviour of the parser, resolvers or the
   application itself

   If the configuration option does not exists, it is added and intialized to
   a "null" variant.

   @param parser the odl parser instance
   @param path the path of the configuration option

   @return
   Returns the config option as a variant.
 */
amxc_var_t* amxo_parser_claim_config(amxo_parser_t* parser,
                                     const char* path);

/**
   @ingroup amxo_parser_config
   @brief
   Sets a configuration option

   The configuration options can be used by the function resolvers or
   by the parser itself.

   Configuration options change the behaviour of the parser, resolvers or the
   application.

   If the configuration option does not exists, it is added. If it exists it's
   value is changed.

   @param parser the odl parser instance
   @param path the path of the configuration option
   @param value the value of the configuration option as a variant

   @return
   Returns 0 when success, any other value indicates failure.
 */
int amxo_parser_set_config(amxo_parser_t* parser,
                           const char* path,
                           amxc_var_t* value);

/**
   @defgroup amxo_parser_connection Connection management
   @ingroup amxo_parser
 */

/**
   @ingroup amxo_parser_connection
   @brief
   Adds a file descriptor (fd) to the list of fds that must be watched

   This function is deprecated use amxp_connection_add instead.

   @param parser the odl parser instance
   @param fd the fd that must be watched
   @param reader the read callback function, is called when data is available for read
   @param uri (option, can be NULL) a uri representing the fd
   @param type one of AMXO_BUS, AMXO_LISTEN, AMXO_CUSTOM
   @param priv private data, will be passed to the callback function

   @return
   Returns 0 when success, any other value indicates failure.
 */
int amxo_connection_add(amxo_parser_t* parser,
                        int fd,
                        amxo_fd_cb_t reader,
                        const char* uri,
                        amxo_con_type_t type,
                        void* priv);

/**
   @ingroup amxo_parser_connection
   @brief
   Adds a watcher to check if a fd is ready for write

   This function is deprecated use amxp_connection_wait_write instead.

   @param parser the odl parser instance
   @param fd the fd that must be watched
   @param writer a callback function called when the socket is available for write

   @return
   Returns 0 when success, any other value indicates failure.
 */
int amxo_connection_wait_write(amxo_parser_t* parser,
                               int fd,
                               amxo_fd_cb_t writer);

/**
   @ingroup amxo_parser_connection
   @brief
   Removes the fd from the connection list.

   This function is deprecated use amxp_connection_remove instead.

   @param parser the odl parser instance
   @param fd the fd that must be watched

   @return
   Returns 0 when success, any other value indicates failure.
 */
int amxo_connection_remove(amxo_parser_t* parser,
                           int fd);

/**
   @ingroup amxo_parser_connection
   @brief
   Gets the connection data for a file descriptor

   This function is deprecated use amxp_connection_get instead.

   @param parser the odl parser instance
   @param fd the fd that must be watched

   @return
   returns pointer to the connection data or NULL if no data is found.
 */
amxo_connection_t* amxo_connection_get(amxo_parser_t* parser,
                                       int fd);

/**
   @ingroup amxo_parser_connection
   @brief
   Sets event-loop data.

   This function is deprecated use amxp_connection_set_el_data instead.

   @param parser the odl parser instance
   @param fd the fd that must be watched
   @param el_data some event loop data

   @return
   Returns 0 when success, any other value indicates failure.
 */
int amxo_connection_set_el_data(amxo_parser_t* parser,
                                int fd,
                                void* el_data);

/**
   @ingroup amxo_parser_connection
   @brief
   Gets the first connection of the given type

   This function is deprecated use amxp_connection_get_first instead.

   @param parser the odl parser instance
   @param type one of AMXO_BUS, AMXO_LISTEN, AMXO_CUSTOM

   @return
   returns pointer to the connection data or NULL if no data is found.
 */
amxo_connection_t* amxo_connection_get_first(amxo_parser_t* parser,
                                             amxo_con_type_t type);

/**
   @ingroup amxo_parser_connection
   @brief
   Gets the next connection data for a file descriptor

   This function is deprecated use amxp_connection_get_next instead.

   @param parser the odl parser instance
   @param con starting point reference
   @param type one of AMXO_BUS, AMXO_LISTEN, AMXO_CUSTOM

   @return
   returns pointer to the connection data or NULL if no data is found.
 */
amxo_connection_t* amxo_connection_get_next(amxo_parser_t* parser,
                                            amxo_connection_t* con,
                                            amxo_con_type_t type);

/**
   @ingroup amxo_parser
   @brief
   Get a list of the current connections of the application

   This function is deprecated use amxp_connection_get_connections instead.

   @param parser the odl parser instance

   @return
   A list with all active socket connections.
 */
amxc_llist_t* amxo_parser_get_connections(amxo_parser_t* parser);

/**
   @ingroup amxo_parser
   @brief
   Get of the current listen sockets of the application

   This function is deprecated use amxp_connection_get_listeners instead.

   @param parser the odl parser instance

   @return
   A list with all open listen sockets.
 */
amxc_llist_t* amxo_parser_get_listeners(amxo_parser_t* parser);

#ifdef __cplusplus
}
#endif

#endif // __AMXO_H__
