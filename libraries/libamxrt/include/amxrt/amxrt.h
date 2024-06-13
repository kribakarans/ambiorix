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

#if !defined(__AMXRT_H__)
#define __AMXRT_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <getopt.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxd/amxd_dm.h>
#include <amxo/amxo.h>
#include <amxo/amxo_mibs.h>
#include <amxb/amxb.h>

#define AMXRT_COPT_URIS "uris"
#define AMXRT_COPT_DATA_URIS "data-uris"
#define AMXRT_COPT_BACKENDS "backends"
#define AMXRT_COPT_AUTO_DETECT "auto-detect"
#define AMXRT_COPT_AUTO_CONNECT "auto-connect"
#define AMXRT_COPT_INCDIRS "include-dirs"
#define AMXRT_COPT_LIBDIRS "import-dirs"
#define AMXRT_COPT_MIBDIRS "mib-dirs"
#define AMXRT_COPT_ODL "ODL"
#define AMXRT_COPT_DAEMON "daemon"
#define AMXRT_COPT_PRIORITY "priority"
#define AMXRT_COPT_PID_FILE "pid-file"
#define AMXRT_COPT_NAME "name"
#define AMXRT_COPT_PREFIX_PATH "prefix"
#define AMXRT_COPT_PLUGIN_DIR "plugin-dir"
#define AMXRT_COPT_CFG_DIR "cfg-dir"
#define AMXRT_COPT_LISTEN "listen"
#define AMXRT_COPT_EVENT "dm-eventing-enabled"
#define AMXRT_COPT_DUMP_CONFIG "dump-config"
#define AMXRT_COPT_DUMP_CAPS "dump-caps"
#define AMXRT_COPT_BACKENDS_DIR "backend-dir"
#define AMXRT_COPT_RW_DATA_PATH "rw_data_path"
#define AMXRT_COPT_STORAGE_DIR "storage-path"
#define AMXRT_COPT_STORAGE_TYPE "storage-type"
#define AMXRT_COPT_ODL_CONFIG "odl"
#define AMXRT_COPT_LOG "log"
#define AMXRT_COPT_REQUIRES "requires"
#define AMXRT_COPT_HANDLE_EVENTS "dm-events-before-start"
#define AMXRT_COPT_SUSPEND "dm-events-suspend-when-requires"
#define AMXRT_COPT_EXT_DIR "extensions-dir"
#define AMXRT_COPT_AMXB_INTERNAL_TO "amxb-internal-timeout"
#define AMXRT_COPT_AMXB_MINIMAL_TO "amxb-minimal-timeout"


#define AMXRT_COPT_DIRECTORY "odl.directory"
#define AMXRT_COPT_DEFAULTS "odl.dm-defaults"
#define AMXRT_COPT_EVENTS "odl.load-dm-events"
#define AMXRT_COPT_OBJECTS "odl.dm-objects"
#define AMXRT_COPT_LOAD "odl.dm-load"
#define AMXRT_COPT_SAVE "odl.dm-save"
#define AMXRT_COPT_ON_CHANGED "odl.dm-save-on-changed"
#define AMXRT_COPT_DELAY "odl.dm-save-delay"
#define AMXRT_COPT_INIT_DELAY "odl.dm-save-init-delay"
#define AMXRT_COPT_STORAGE "storage-type"

typedef int (* amxrt_arg_fn_t) (amxc_var_t* config,
                                int arg_id,
                                const char* value);

/**
   @defgroup amxrt_run_time Runtime

   The ambiorix runtime library can be used to easily create a stand-alone
   data model provider application or data model client.

   The runtime library provides:
   - an ambiorix configuration environment (htable variant)
   - an odl parser (can be used to read and write odl files)
   - a data model storage
   - command line argument parsing
   - an event loop implementation

   The simplest possible way to use this library is in this example code:
   @code
 #include <amxrt/amxrt.h>

   int main(in argc, char* argv[]) {
       int retval = 0;
       amxrt_new();
       retval = amxrt(argc, argv, NULL);
       amxrt_delete();
       return retval;
   }
   @endcode

   The above example can also be written as follows:
   @code
 #include <amxrt/amxrt.h>

   int main(in argc, char* argv[]) {
       int retval = 0;

       amxrt_new();
       retval = amxrt_init(argc, argv, fn);
       when_failed(retval, leave);
       retval = amxrt_register_or_wait();
       when_failed(retval, leave);
       retval = amxrt_run();

   leave:
       amxrt_stop();
       amxrt_delete();
       return retval;
   }
   @endcode

   This gives you to possibility to perform other tasks in between.
 */

/**
   @ingroup amxrt_run_time
   @brief
   Gets the htable variant containing the configuration options

   @return
   The htable variant containing the configuration options.
 */
amxc_var_t* amxrt_get_config(void);

/**
   @ingroup amxrt_run_time
   @brief
   Gets runtime odl parser.

   To manually read the odl files using the parser use any of the libamxo functions.

   Example:
   @code
   amxo_parser_t* odl_parser = amxrt_get_parser();
   amxd_dm_t* dm = amxrt_get_dm();
   amxd_object_t* root = amxd_dm_get_root(dm);

   amxo_parser_parse_file(parser, "/tmp/my_definition.odl", root);
   @endcode

   @return
   The runtime odl parser.
 */
amxo_parser_t* amxrt_get_parser(void);

/**
   @ingroup amxrt_run_time
   @brief
   Gets the runtime data model storage.

   @return
   The amxd_dm_t pointer where the data model is stored.
 */
amxd_dm_t* amxrt_get_dm(void);

/**
   @ingroup amxrt_run_time
   @brief
   Create the ambiorix runtime.

   This function must be called before any other amxrt function.

   This function creates:
   - an odl parser, can be fetched using @ref amxrt_get_parser
   - a data model, can be fetched using @ref amxrt_get_datamodel
   - an empty config, can be fetched using @ref amxrt_get_config

   This function is typically called as first in the main.

   When done with the ambiorix run time, call @ref amxrt_delete
 */
void amxrt_new(void);

/**
   @ingroup amxrt_run_time
   @brief
   This function can create full ambiorix application (data model provider or client).

   Typically this function is called from your main. Optionally a command line option
   handler can be added.

   This function will create and start the event loop, and therefor will only return
   when the event loop has stopped. The event loop can be stopped by calling @ref amxrt_el_stop.
   Typically this is done from within an event handler.

   By default following signals are being monitored and handled:
   - SIGINT - when triggered the eventloop is stopped
   - SIGTERM - when triggered the eventloop is stopped
   - SIGALRM - used for ambiorix timers (amxp_timer_t)

   @note
   When using this function an odl file must be loaded (can be an empty one or an odl
   file that only contains configuration). If no odl file was loaded this function
   will return with an error.

   This function will call the following function (in this order):
   - @ref amxrt_init
   - @ref amxrt_register_or_wait
   - @ref amxrt_run - this will start the event loop, the function will continue when the event loop has been stopped
   - @ref amxrt_stop

   Example of usage:
   @code
 #include <stdio.h>

 #include <amxrt/amxrt.h>

   static int amxrt_handle_cmd_line_arg(amxc_var_t* config,
                                        int arg_id,
                                        UNUSED const char* value) {
       int rv = -1;
       const char* name = GET_CHAR(amxrt_get_config(), "name");
       switch(arg_id) {
          case 'V': {
              printf("%s %d.%d.%d\n", name, 1, 2, 3);
          }
          break;
          default:
              rv = -2;
          break;
       }

       return rv;
   }

   int main(int argc, char* argv[]) {
       int retval = 0;

       amxrt_new();
       amxrt_cmd_line_add_option(0, 'V', "version", no_argument, "Print version", NULL);
       retval = amxrt(argc, argv, amxrt_handle_cmd_line_arg);
       amxrt_delete();

       return retval;
   }
   @endcode

   @param argc the number of arguments available
   @param argv the vector containing the commandline arguments
   @param fn (optional) a pointer to a callback function to handle the option or NULL

   @return
   Non zero indicates an error, 0 will indicate that the event loop has stopped
   without any error.
 */
int amxrt(int argc, char* argv[], amxrt_arg_fn_t fn);

/**
   @ingroup amxrt_run_time
   @brief
   Initializes the ambiorix runtime.

   This function will:
   1. parse the command line options
   2. set the default ambiorix config options
   3. load the odl files (if any)
   4. add the automatic load and save modules entrypoint @ref amxo_parser_add_entry_point
   5. load the ambiorix back-ends
   6. connects to all sockets
   7. enable all system signals that needs to be monitored
   8. create an event loop

   The odl file files that are loaded can be passed as command line arguments
   after the command line options. If no odls are provided at command line the
   runtime will try to load the default odl file for the application, using the
   applications name (argv[0]). The default that it will try to load is "/etc/amx/<appname>/<appname>.odl".
   If no odl files are provided and the default doesn't exist, this function will
   continue without an error.

   The (bus) back-ends loaded can be specified using command line option -B or
   added in one of the odl files in the config section with config name "backends",
   which must be a list of backend shared objects that must be loaded.
   If auto-detection is turned on (this is the default), all shared objects that are valid
   ambiorix back-ends will be loaded from the back-end directory (by default this is
   "/usr/bin/mods/amxb"). The default back-end directory can be changed in a odl file
   config section with config name "backend-dir" or on the command line with "-o backend-dir=<thedir>".

   The sockets that the run-time needs to connect to can be specified with commandline
   option -u or in an odl config section with config name "uris" or "data-uris", both
   configuration settings must be a list of uris. The difference between uris and data-uris is
   that when the application has a data model available it will only be registered using the
   sockets that are mentioned in the "uris".

   @param argc the number of arguments available
   @param argv the vector containing the commandline arguments
   @param fn (optional) a pointer to a callback function to handle the option or NULL

   @return
   Non zero indicates an error
 */
int amxrt_init(int argc, char* argv[], amxrt_arg_fn_t fn);

/**
   @ingroup amxrt_run_time
   @brief
   Register the data model or wait for required data model objects.

   When the application has a data model available, it can be registered using this function.
   As soon as the data model is registered, the application becomes a data model provider.

   If required objects are defined (using odl files with "requires" or using command line option -R),
   then this function will wait until these objects become available on the used bus systems before
   registering the data model.

   The wait can only be fulfilled when an eventloop is running, as it needs event handling.

   When registering of the data model succeeded, the entry-points of the loaded modules/plugins
   are called with reason AMXO_START (0).

   @return
   Non zero indicates an error
 */
int amxrt_register_or_wait(void);

/**
   @ingroup amxrt_run_time
   @brief
   Starts the event loop.

   This function just calls @ref amxrt_el_start.
   This function returns when the event loop is stopped or when starting the
   event loop fails.

   @return
   0 when the event loop stopped, any other value indicates that starting
   the event loop failed.
 */
int amxrt_run(void);

/**
   @ingroup amxrt_run_time
   @brief
   Stops the runtime.

   Only call this function when the event loop has stopped, never call this
   method in event handlers. Call @ref amxrt_el_stop instead and call this function
   after the call that starts the event loop.

   This function will teardown the ambiorix runtime:
   1. destroys the event loop
   2. call the entry points of loaded modules/plugins in reverse order with reason AMXO_STOP
   3. resets the backend configurations
   4. removes the pid file.
   5. closes the syslog (if it was opened)

   This function is typically called when the event loop is stopped and the application
   is going to be closed.
 */
void amxrt_stop(void);

/**
   @ingroup amxrt_run_time
   @brief
   Clean-up ambiorix runtime.

   All open sockets will be closed and all loaded backends will be unloaded.

   This function is typically called just before the application exits.
 */
void amxrt_delete(void);

/**
   @ingroup amxrt_run_time
   @brief
   Load odls files mentioned on the command line or the default odl file.

   By default odl files can be specified after the command line options.
   This function will load these odl files.

   If no odl files are specified at the command line, the default odl file will
   be loaded. The application name (Argv[0]) will be used to find the default odl file.

   The default odl file is "/etc/amx/<appname>/<appname>.odl".

   If no odl files are defined at the commandline and the default odl file does't
   exist, nothing is loaded an no error is thrown.

   This function will also scan the default mib dir for the application. If
   a mib dir is available and contains mib definitions, these are not loaded by default.
   Mib definitions will be loaded when needed.

   @param argc the number of arguments available
   @param argv the vector containing the commandline arguments
   @param index should be set to the first command line that is not an option

   @return
   Non zero indicates an error
 */
int amxrt_load_odl_files(int argc, char* argv[], int index);

/**
   @ingroup amxrt_run_time
   @brief
   Connects to all bus sockets.

   When auto-detect is enabled the ambiorix runtime will check if the well known
   linux domain bus sockets exists and they will be added to the "uris" config.

   Using command line option "-u" extra sockets can be added. It is also possible
   to define the sockets that needs to be opened in the config section of an odl file.

   The supported config options are:
   - "uris" - used to connect on and register the data model of the application
   - "data-uris" - used to connect on, but the data model is not registered on these sockets.
   " "listen" - creates a listening socket, other applications can connect on these.

   @return
   Non zero indicates an error
 */
int amxrt_connect(void);

/**
   @ingroup amxrt_run_time
   @brief
   Enables system signals that should be monitored by the eventloop.

   The default implementation of the event loop will only monitor
   - SIGINT - when triggered the eventloop is stopped
   - SIGTERM - when triggered the eventloop is stopped
   - SIGALRM - used for ambiorix timers (amxp_timer_t)

   If other signals needs to be monitored, a list variant must be created, containing
   the identifiers of the signals and passed to this function.

   @param syssigs list variant containing the signal identifiers.
 */
void amxrt_enable_syssigs(amxc_var_t* syssigs);

/**
   @defgroup amxrt_cmd_line_options Command Line Options

   The command line option parser, reads the options passed on the command line
   and passes them to the configuration.

   The command line option parser can handle short options (starting with a single '-')
   and long options (staring with a double '-'). Options must be put before any
   other arguments on the command line. The command line option parser stops at the first
   argument that is not an option (not starting with a '-').

   The command line option parser uses <a href="https://linux.die.net/man/3/getopt_long">getopt_long</a>
   to parse the options.

   The default options handled are:

   @code
    -h       --help                         Print usage help and exit
    -H       --HELP                         Print extended help and exit
    -B       --backend so file              Loads the shared object as bus backend
    -u       --uri uri                      Adds an uri to the list of uris
    -A       --no-auto-detect               Do not auto detect unix domain sockets and back-ends
    -C       --no-connect                   Do not auto connect the provided or detected uris
    -I       --include-dir dir              Adds include directory for odl parser, multiple allowed
    -L       --import-dir dir               Adds import directory for odl parser, multiple allowed
    -o       --option name=value            Adds a configuration option
    -F       --forced-option name=value     Adds a configuration option, which can not be overwritten by odl files
    -O       --ODL odl-string               An ODL in string format, only one ODL string allowed
    -D       --daemon                       Daemonize the process
    -p       --priority nice level          Sets the process nice level
    -N       --no-pid-file                  Disables the creation of a pid-file in /var/run
    -E       --eventing                     Enables eventing during loading of ODL files
    -d       --dump [caps|config]           Dumps configuration options or capabilities at start-up
    -l       --log                          Write to syslog instead of stdout and stderr
    -R       --requires root object         Checks if datamodel objects are available or waits until they are available
    -V       --version                      Print version
   @endcode

   If the default options doesn't fit your usage, they can be removed by calling
   @ref amxrt_cmd_line_options_reset.

   Adding new options (or re-adding some of the default options) can be done using:
   @ref amxrt_cmd_line_add_option

   Use @ref amxrt_cmd_line_parse to start parsing the given command line options.

   The syntax for parsing options at command line is:
   @code
 # option has no argument or an optional argument
   -o
 # option has a required or optional argument
   -o arg
   -o=arg
   @endcode
 */

/**
   @ingroup amxrt_cmd_line_options
   @brief
   Removes all default options.

   Calling this function will remove all defined default options. If some of them
   are needed they can be re-added using @ref amxrt_cmd_line_add_option
 */
void amxrt_cmd_line_options_reset(void);

/**
   @ingroup amxrt_cmd_line_options
   @brief
   Adds a command line option definition.

   This function adds a command line option definition to the list of accepted options.

   @param id the id of the option, if 0 is given the short_option is used as id.
   @param short_option a single character representing the short option/
   @param long_option a string literal containing the name of the long option without the double '-'
   @param has_args must be one of no_argument (if the option does not take an argument),
                   required_argument (if the option requires an argument) or
                   optional_argument (if the takes an optional argument).
   @param doc a string literal describing the option
   @param arg_doc a string literal describing the argument or NULL if the option doesn't have an argument

   @return
   0 when option definition is added, any other value indicates an error.
 */
int amxrt_cmd_line_add_option(int id, char short_option, const char* long_option, int has_args, const char* doc, const char* arg_doc);

/**
   @ingroup amxrt_cmd_line_options
   @brief
   Set the overall usage documentation string.

   When the function @ref amxrt_print_usage the usage documentation is printed to
   stdout. On the first line the global usage is printed.

   Example (default string)
   @code
   amxrt [OPTIONS] <odl files>
   @endcode

   The first part (until the first space) is the name of the application, this is
   added automatically by @ref amxrt_print_usage (taken from argv[0] and should not
   be added to the provided string.

   Example:
   @code
   amxrt_cmd_line_set_usage_doc("[OPTIONS] <OBJECT PATH> <FILTER>");
   @endcode

   if after this line @ref amxrt_print_usage is called (assuming that the name of
   the application is "amxrt") the output will look like this:
   @code
   amxrt [OPTIONS] <OBJECT PATH> <FILTER>
   @endcode

   @param usage A string literal containing the usage overview.
 */
void amxrt_cmd_line_set_usage_doc(const char* usage);

/**
   @ingroup amxrt_cmd_line_options
   @brief
   Starts parsing the command line options.

   Typically this function is called from within the applications main and
   the argc and argv arguments of the main are passed to this method.

   Optionally a function pointer can be provided. This function will be called
   for each option encountered before the default option handler is used.
   If the argument handle function returns 0, it indicates that the option is handled
   and should not be passed to the default handler, when the callback function returns -1 the
   option parser will stop and the application should exit, when the callback function
   return -2, the default command line argument option handler is called. If the callback
   function returns anything else then 0,-1 or -2, it is considered an error and
   the command line option parser will stop.

   The callback function must match this signature
   @code
   typedef int (* amxrt_arg_fn_t) (amxc_var_t* config,
                                   int arg_id,
                                   const char* value);
   @endcode

   @param argc the number of arguments available
   @param argv the vector containing the commandline arguments
   @param fn (optional) a pointer to a callback function to handle the option or NULL

   @return
   A negative number indicates an error, a positive number indicates the index
   in argv where the parsing has stopped (first non option argument).
   If the returned value equals argc, all command line options were parsed and
   handled.
 */
int amxrt_cmd_line_parse(int argc, char* argv[], amxrt_arg_fn_t fn);

/**
   @ingroup amxrt_cmd_line_options
   @brief
   Parses an command line option or an argument with an assignment.

   This function parses a command line option or command line argument with an assignment.

   The key will be added to the config options. The config can be retrieved using
   @ref amxrt_get_config.

   Example:
   @code
   amxrt -o key=value
   amxrt key=value
   @endcode

   The key can be any string without spaces. The value can a simple value or a JSON
   string.

   If the key contains dots (.), is is used as a path to the config option.

   @param option the command line option value or the command line argument.
   @param force when set to true, odl config sections can not overwrite this value.
 */
void amxrt_cmd_line_parse_assignment(const char* option, bool force);

/**
   @ingroup amxrt_cmd_line_options
   @brief
   Prints the usage information and all available options to stdout.

   Using the usage doc string and the defined options the usage information is
   created and printed to stdout.

   The usage doc string can be set using @ref amxrt_cmd_line_set_usage_doc.

   Options can be added using @ref amxrt_cmd_line_add_option or all removed using
   @ref amxrt_cmd_line_options_reset.

   The default usage information is:
   Example:
   @code
   amxrt [OPTIONS] <odl files>

    -h    --help                          Print usage help and exit
    -H    --HELP                          Print extended help and exit
    -B    --backend <so file>             Loads the shared object as bus backend
    -u    --uri <uri>                     Adds an uri to the list of uris
    -A    --no-auto-detect                Do not auto detect unix domain sockets and back-ends
    -C    --no-connect                    Do not auto connect the provided or detected uris
    -I    --include-dir <dir>             Adds include directory for odl parser, multiple allowed
    -L    --import-dir <dir>              Adds import directory for odl parser, multiple allowed
    -o    --option <name=value>           Adds a configuration option
    -F    --forced-option <name=value>    Adds a configuration option, which can not be overwritten by odl files
    -O    --ODL <odl-string>              An ODL in string format, only one ODL string allowed
    -D    --daemon                        Daemonize the process
    -p    --priority <nice level>         Sets the process nice level
    -N    --no-pid-file                   Disables the creation of a pid-file in /var/run
    -E    --eventing                      Enables eventing during loading of ODL files
    -d    --dump-config                   Dumps configuration options at start-up
    -l    --log                           Write to syslog instead of stdout and stderr
    -R    --requires <root object>        Checks if datamodel objects are available or waits until they are available
    -V    --version                       Print version
   @endcode
 */
void amxrt_print_usage(void);

/**
   @ingroup amxrt_run_time
   @brief
   Initializes the default runtime configuration.

   Sets the default values for all default configuration options.

   Also uses the command line option parser and if needed adapts the configuration
   accordingly.

   @param argc the number of arguments available
   @param argv the vector containing the commandline arguments
   @param index pointer to an integer, will be set to the first command line argument that is not an option.
   @param fn (optional) a pointer to a callback function to handle the option or NULL

   @return
   returns 0 if no error occured.
 */
int amxrt_config_init(int argc, char* argv[], int* index, amxrt_arg_fn_t fn);

/**
   @ingroup amxrt_run_time
   @brief
   Scan backend directories for available backends.

   When auto-detection (configuration option "auto-detect") is enabled, all directories
   in the configuration option "backend-dir" are scanned for valid shared object files.
   Each found shared object file is added to the list of possible backends that can be used.

   When auto-detection is disabled this function will do nothing.
 */
void amxrt_config_scan_backend_dirs(void);

/**
   @ingroup amxrt_run_time
   @brief
   Helper function to read an environment variable and add it's value to the runtime configuration.

   As envrionment variables values can only be fetched as strings, a type must be provided
   to which the value must be converted. The value will be stored using this type in the
   runtime configuration.

   @param var_name The environment variable name.
   @param config_name The runtime configuration option name
   @param var_type The variant type, this is the type how the value will be stored
 */
void amxrt_config_read_env_var(const char* var_name, const char* config_name, int32_t var_type);

/**
   @defgroup amxrt_event_loop Event loop

   A default ambiorix eventloop can be created using the event loop functions in
   this library. The eventloop is implemented using <a href="https://libevent.org/">libevent</a>.

   In computer science, the event loop is a programming construct or design pattern that waits for
   and dispatches events or messages in a program. The event loop works by making a request to some
   internal or external "event provider" (that generally blocks the request until an event has arrived),
   then calls the relevant event handler ("dispatches the event"). The event loop is also sometimes
   referred to as the message dispatcher, message loop, message pump, or run loop.

   The event-loop may be used in conjunction with a reactor, if the event provider follows the file interface,
   which can be selected or 'polled' (the Unix system call, not actual polling). The event loop almost
   always operates asynchronously with the message originator.

   When the event loop forms the central control flow construct of a program, as it often does,
   it may be termed the main loop or main event loop.
   This title is appropriate, because such an event loop is at the highest level of control within the program.

   When the function @ref amxrt_el_create is called all ambiorix file descriptors (fds) are
   added to the eventloop for monitoring (for read), some system signals are added for
   monitoring.

   The system signals that are monitored are:
   - SIGINT - when triggered the eventloop is stopped
   - SIGTERM - when triggered the eventloop is stopped
   - SIGALRM - used for ambiorix timers (amxp_timer_t)

   Extra system signals can be enabled using amxp_syssig_enable, or a htable list can be passed
   to the function @ref amxrt_enable_syssigs. This will cause that the system signals are
   captured and converted to ambiorix signals. To handle them connect callback functions
   to them using amxp_slot_connect.

   By default all opened sockets (opened with @ref amxrt_connect) are added to the event-loop
   as well.

   The ambiorix signals will be handled in the event loop as well. Ambiorix signals can be
   created using amxp_signal_emit.

   For more information about ambiorix signals see <a href="https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxp">libamxp</a>.
 */

/**
   @ingroup amxrt_event_loop
   @brief
   Creates and initializes all needed event loop components.

   It is recommended to first open all needed sockets (like connections to the used
   bus systems), register the data model (if any), enable all system signals that
   needs to be handled before creating the event loop components.


   @return
   0 when the event loop components are created and initialized correctly.
   Any other return value indicates an error.
 */
int amxrt_el_create(void);

/**
   @ingroup amxrt_event_loop
   @brief
   Starts the event loop.

   This function will start the event loop. The event loop will be "waiting" for
   events and if one is received, it will be dispatched (correct callback functions
   are called).

   The event loop will keep running until @ref amxrt_el_stop is called, that is:
   this function will not return until the event loop is stopped.

   IF the event loop fails to start the function returns immediately.

   @return
   Non 0 will indicate that starting the event loop failed.
   0 will indicate that the event loop was stopped.
 */
int amxrt_el_start(void);

/**
   @ingroup amxrt_event_loop
   @brief
   Stops the event loop.

   This function will stop the event loop.

   When the event loop is stopped no events will be dispatched any more.

   After stopping the event loop it can be restarted by calling @ref amxrt_el_start.

   Typically an event loop is started once, and keeps on running for the complete
   lifetime of the application.

   @return
   0 will indicate that the event loop was stopped successfully.
 */
int amxrt_el_stop(void);

/**
   @ingroup amxrt_event_loop
   @brief
   Cleans-up the event loop components

   When the event loop is not needed anymore, all it's components must be
   deleted and removed. Typically this is done just before exiting the application.

   @return
   0 when everything is deleted successfully..
 */
int amxrt_el_destroy(void);

/**
   @ingroup amxrt_run_time
   @brief
   The data model auto load and save module.

   The ambiorix runtime library embeds a module that can be used to automatically
   load and save the data model.

   To make use of this module, it's entry point must be registered. Registering of
   the entry point can be done by calling @ref amxo_parser_add_entry_point.

   @note
   This function should not be called directly.

   Example:
   @code
       amxo_parser_t* parser = amxrt_get_parser();
       amxo_parser_add_entry_point(parser, amxrt_dm_save_load_main);
   @endcode

   This function will be called when the entry points are invoked. See @ref amxrt_register_or_wait
   and @ref amxrt_stop.

   This module needs configuration, see the <a href="https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxrt#odl-persistent-storage">readme</a>
   for more information

   @param reason the reason why the entry point is called.
   @param dm the data model pointer
   @param parser the odl parser

   @return
   returns 0 if no error occured.
 */
int amxrt_dm_save_load_main(int reason, amxd_dm_t* dm, amxo_parser_t* parser);

/**
   @defgroup amxrt_privileges_caps User privileges and capabilities

   For the purpose of performing permission checks, traditional UNIX implementations
   distinguish two categories of processes:
   - privileged processes (whose effective user ID is 0, referred to as superuser or root).
   - unprivileged processes (whose effective UID is nonzero).

   Privileged processes bypass all kernel permission checks, while unprivileged
   processes are subject to full permission checking based on the process's
   credentials (usually: effective UID, effective GID, and supplementary group list).

   Starting with Linux 2.2, Linux divides the privileges traditionally associated
   with superuser into distinct units, known as capabilities, which can be
   independently enabled and disabled.  Capabilities are a per-thread attribute.

   In the %config section it is possible to define to which user the started process
   must switch. Typically the process is started as a privileged process (started with
   root user), but it can drop the root privileges and switch to an unprivileged
   process (user id is nonzero).

   When setting the user name (or id), by default all capabilities are dropped as
   well. It is possible to retain all capabilities are (keep all) or only retain
   some.
 */

/**
   @ingroup amxrt_privileges_caps
   @brief
   Apply the user, group and capabilities as defined in the configuration.

   When everything is initialized user privileges and capabilities can be dropped.

   The user and group to which the process needs to switch (privileges dropping) can
   be defined in the configuration.

   Which capabilities needs to be retained can be defined in the configuration.

   @return
   returns 0 if no error occurred.
 */
int amxrt_caps_apply(void);

/**
   @ingroup amxrt_privileges_caps
   @brief
   Dumps the capabilities of the process.

   Print all capabilities of the process to stdout.
 */
void amxrt_caps_dump(void);

#ifdef __cplusplus
}
#endif

#endif // __AMXRT_H__
