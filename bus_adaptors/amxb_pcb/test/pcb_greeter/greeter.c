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
#include <debug/sahtrace.h>
#include <pcb/core.h>
#include <mtk.h>

#define ME "greeter"
#include <amxc/amxc_macros.h>
static pcb_t* lpcb = NULL;

/*
    Remove count number of oldest history
    Return the number of instances that were not removed
 */
static uint32_t remove_oldest_history(object_t* history_obj, uint32_t count) {
    object_t* msg = NULL;
    // loop over all instances of the history object (using iteration macro)
    // - the instances are always in creation order, so the oldest first
    // - it is possible to iterate in verse order using object_for_each_instance_reverse macro
    object_for_each_instance(msg, history_obj) {
        // fetch the retain parameter value of the instance
        // - here it is fetched as a boolean (no conversion needed)
        // - the other methods work as well, be will apply a conversion
        bool retain = object_parameterBoolValue(msg, "Retain");
        if(retain) {
            // it is a retained message, continue
            continue;
        }
        // delete the history instance and decrease the counter
        object_delete(msg); // this is not really deleting the instance, just mark it for deletion
        count--;
        // reached zero no more to delete
        if(count == 0) {
            break;
        }
    }

    // commit the history object, after this the deleted history instances are gone
    object_commit(history_obj);

    // return the remained
    return count;
}

/*
    Adds a message in the history
 */
static bool add_message_history(object_t* greeter_obj, const char* from, const char* msg, bool retain) {
    // fetch the history object
    object_t* history_obj = object_getObjectByKey(greeter_obj, "History");

    // fetch the Max History parameter
    uint32_t max_history = object_parameterUInt32Value(greeter_obj, "MaxHistory");
    // fetch the number of instances created - can also be done by fetching the value of "HistorySize" parameter
    uint32_t current_instances = object_instanceCount(history_obj);

    // check if maximum history is reached
    // remove oldest not retained message from history
    if(current_instances >= max_history) {
        if(remove_oldest_history(history_obj, 1) != 0) {
            return false;
        }
    }

    // create new history instance and commit it
    // we do not provide an instance index or instance key here
    object_t* msg_obj = object_createInstance(history_obj, 0, NULL);
    if(!msg_obj) {
        // creation of the instance failed
        return false;
    }

    // set the values of the parameters
    // if this fails, rollback and return
    if(!object_parameterSetCharValue(msg_obj, "From", from)) {
        object_rollback(msg_obj);
        return false;
    }
    if(!object_parameterSetCharValue(msg_obj, "Message", msg)) {
        object_rollback(msg_obj);
        return false;
    }
    if(!object_parameterSetBoolValue(msg_obj, "Retain", retain)) {
        object_rollback(msg_obj);
        return false;
    }

    // if creating the instance and setting the values was ok,
    // commiting the object will not fail
    object_commit(msg_obj);

    return true;
}

/*
    Clear the full history.

    When force is not set, the retained messages are not deleted
 */
static uint32_t history_clear(object_t* history_obj, bool force) {
    uint32_t count = 0;
    object_t* msg = NULL;
    // loop over all instances of the history object
    object_for_each_instance(msg, history_obj) {
        bool retain = object_parameterBoolValue(msg, "Retain");
        // if force is set or retain is not set mark the object for deletion
        if(force || !retain) {
            object_delete(msg);
            count++;
        }
    }
    // return the number of marked instances
    //
    // DO NOT COMMIT HERE
    // this function is also used in the load RPC implementation
    // commit is done after loading the saved instances
    return count;
}

/*
    DATA MODEL METHODS

    Here all all data model methods.

    All methods are name __<OBJECT_NAME>_<METHOD_NAME>

    In C there is no need to "bind" these methods to the data model
    The odl parser will resolve the methods automatically, the only thing it
    needs is the name of the shared objects containing the implementation

    Each odl file can have just one shared object
 */

/*
    Greeter.say implementation

    Prints the message from someone or something and
    adds the message to the history
 */
function_exec_state_t __Greeter_say(function_call_t* fcall,
                                    argument_value_list_t* args,
                                    variant_t* retval) {
    // fetch the request attrributes
    // the attribute field of a request is a bitmap.
    // One of the bits is telling if the names of the arguments are provided or not.
    uint32_t attr = request_attributes(fcall_request(fcall));
    // Called on object Greeter (object pointer available in fcall context structure)
    object_t* greeter_obj = fcall_object(fcall);

    char* from = NULL;
    char* msg = NULL;
    bool retain = false;
    variant_t out_value;
    variant_initialize(&out_value, variant_type_string);

    // Fetch the arguments from the argument list
    // Always put these argument fetching functions in the order the arguments are
    // defined in the odl.
    // 1. If no argument names are provided in the argument list, this will work
    // 2. If argument names are provided, this will work as well.
    // If not in order as defined in the odl, you will break number 1
    argument_getChar(&from, args, attr, "from", NULL);
    argument_getChar(&msg, args, attr, "message", NULL);
    argument_getBool(&retain, args, attr, "retain", false);

    // Add history object if possible (this is a local function)
    if(add_message_history(greeter_obj, from, msg, retain)) {
        // print the message
        printf("%s\n", msg); // will not work when running as a daemon
        fflush(stdout);
        // set the return value
        variant_setChar(retval, msg);
        // free the allocated memory
        free(from);
        free(msg);

        // add out argument
        variant_setChar(&out_value, "Message added");
        argument_valueAdd(args, "result", &out_value);
        variant_cleanup(&out_value);

        // Tell pcb library the function call is done
        return function_exec_done;
    }

    // free the allocated memory
    free(from);
    free(msg);

    // add out argument
    variant_setChar(&out_value, "Failed to add message");
    argument_valueAdd(args, "result", &out_value);
    variant_cleanup(&out_value);

    // Tell pcb library the function has failed
    return function_exec_error;
}

function_exec_state_t __Greeter_echo(function_call_t* fcall,
                                     argument_value_list_t* args,
                                     variant_t* retval) {
    (void) fcall;
    (void) args;
    (void) retval;
    return function_exec_done;
}

/*
    Greeter.setMaxHistory implementation

    Sets a new maximum history size. If size is smaller then current size some
    messages might be deleted from the history.
    Never deletes the retained messages, so the set size can be bigger then the
    requested size.

    Returns the new maximuim size, can be different the one requested.
 */
function_exec_state_t __Greeter_setMaxHistory(function_call_t* fcall,
                                              argument_value_list_t* args,
                                              variant_t* retval) {
    // fetch the request attrributes
    // see __Greeter_say function for details
    uint32_t attr = request_attributes(fcall_request(fcall));
    // Called on object Greeter (object pointer available in fcall context structure)
    object_t* greeter_obj = fcall_object(fcall);
    // We also need to access the History object, start from the Greeter object
    // and find the History object
    object_t* history_obj = object_getObjectByKey(greeter_obj, "History");
    // The above function can take printf like formats to build an object path

    uint32_t newmax = 0;
    uint32_t oldmax = object_parameterUInt32Value(greeter_obj, "MaxHistory");
    argument_getUInt32(&newmax, args, attr, "max", 0);

    if(newmax > oldmax) {
        // More allowed just set the value
        object_parameterSetUInt32Value(greeter_obj, "MaxHistory", newmax);
    } else if(newmax < oldmax) {
        uint32_t instance_count = object_instanceCount(history_obj);
        if(instance_count > newmax) {
            // less allowed, remove oldest until new max can be set
            newmax += remove_oldest_history(history_obj, instance_count - newmax);
        }
        object_parameterSetUInt32Value(greeter_obj, "MaxHistory", newmax);
    }

    // return the new set max
    variant_setUInt32(retval, newmax);
    // commit all changes in the data model (strarting from the Greeter obj)
    object_commit(greeter_obj);
    // all done, all ok
    return function_exec_done;
}

/*
    Greeter.save implementation
 */
function_exec_state_t __Greeter_save(function_call_t* fcall,
                                     argument_value_list_t* args,
                                     variant_t* retval) {
    uint32_t attr = request_attributes(fcall_request(fcall));
    object_t* greeter_obj = fcall_object(fcall);
    object_t* root = object_root(greeter_obj);

    char* filename = NULL;
    argument_getChar(&filename, args, attr, "filename", NULL);

    // save the full datamodel to an odl file
    bool rv = datamodel_save(root, -1, filename, SERIALIZE_FORMAT(serialize_format_odl, 0, 0));
    variant_setBool(retval, rv);
    // free allocated memory
    free(filename);

    if(rv) {
        // all ok, all done
        return function_exec_done;
    } else {
        // make sure the caller sees an error
        // more detailed errors can be added to the error list
        return function_exec_error;
    }
}

/*
    Greeter.load implementation
 */
function_exec_state_t __Greeter_load(function_call_t* fcall,
                                     argument_value_list_t* args,
                                     variant_t* retval) {
    uint32_t attr = request_attributes(fcall_request(fcall));
    object_t* greeter_obj = fcall_object(fcall);
    object_t* history_obj = object_getObjectByKey(greeter_obj, "History");
    datamodel_t* dm = object_datamodel(greeter_obj);

    char* filename = NULL;
    argument_getChar(&filename, args, attr, "filename", NULL);

    // remove all instances from the history object
    history_clear(history_obj, true);

    // load the file - we assume it is an odl file
    // if the provided file does not contain valid odl this will fail
    bool rv = datamodel_load(dm, filename, SERIALIZE_FORMAT(serialize_format_odl, 0, 0));
    if(!rv) {
        // rollback, make sure all "deleted" instance are back
        // loading has failed - restore all
        object_rollback(greeter_obj);
    }
    variant_setBool(retval, rv);

    // free allocated memory
    free(filename);

    if(rv) {
        // all ok, all done
        return function_exec_done;
    } else {
        // make sure the caller sees an error
        return function_exec_error;
    }
}

/*
    Greeter.History.clear implementation

    Clears the full history.
    Messages with the retain flag are only removed when force is set

    returns the number of messages deleted.
 */
function_exec_state_t __History_clear(function_call_t* fcall,
                                      argument_value_list_t* args,
                                      variant_t* retval) {
    uint32_t attr = request_attributes(fcall_request(fcall));
    // called on object Greeter.History (fcall object = History template object)
    object_t* history_obj = fcall_object(fcall);

    uint32_t count = 0;
    bool force = false;
    argument_getBool(&force, args, attr, "force", false);

    // call the history clear method
    count = history_clear(history_obj, force);

    if(count) {
        // the history_clear function is not doing a commit.
        // lets do it here
        object_commit(history_obj);
    }

    variant_setUInt32(retval, count);
    return function_exec_done;
}

/*
    Greeter.History.<i>.reverse implementation

    Reverses the message of the history instance object and updates the message
    in the history object

    returns the reversed message
 */
function_exec_state_t __History_reverse(function_call_t* fcall,
                                        UNUSED argument_value_list_t* args,
                                        variant_t* retval) {
    // called on object Greeter.History.<i> (fcall object = History instance object)
    object_t* msg_obj = fcall_object(fcall);
    char* msg = variant_char(object_parameterValue(msg_obj, "Message"));

    // reverse the message - this is bussiness logic and should be in
    // a separate function
    uint32_t msg_length = strlen(msg);
    string_t reverse_msg;
    string_initialize(&reverse_msg, msg_length);
    for(uint32_t i = msg_length; i > 0; i--) {
        string_appendChar(&reverse_msg, msg + (i - 1));
        msg[i - 1] = 0;
    }

    // set the reversed message in the data model instance object.
    object_parameterSetStringValue(msg_obj, "Message", &reverse_msg);
    object_commit(msg_obj);
    variant_setString(retval, &reverse_msg);

    // print to stdout (will have no effect when running as daemon)
    printf("%s\n", string_buffer(&reverse_msg));

    // free the used memory
    string_cleanup(&reverse_msg);
    free(msg);
    return function_exec_done;
}

function_exec_state_t __History_sendNotification(function_call_t* fcall,
                                                 UNUSED argument_value_list_t* args,
                                                 UNUSED variant_t* retval) {
    // called on object Greeter.History.<i> (fcall object = History instance object)
    object_t* msg_obj = fcall_object(fcall);
    uint32_t attrs = request_attributes(fcall_request(fcall));
    char* path = object_pathChar(msg_obj, attrs & request_common_path_key_notation);

    notification_t* notification = notification_create(101);
    notification_setName(notification, "greeter:test");
    notification_setObjectPath(notification, path);

    notification_parameter_t* notif_data = notification_parameter_create("TestData", "Hallo");
    notification_addParameter(notification, notif_data);

    pcb_sendNotification(lpcb, NULL, NULL, notification);

    notification_destroy(notification);
    free(path);
    return function_exec_done;
}

function_exec_state_t __TestObject_TestFunc(UNUSED function_call_t* fcall,
                                            UNUSED argument_value_list_t* args,
                                            UNUSED variant_t* retval) {
    return function_exec_done;
}

// The plug-in initialization function
// This must be implemented and will be called by the odl parser after the odl files
// have been parsed (the data model exists when this function is called)
bool pcb_plugin_initialize(pcb_t* pcb,
                           UNUSED int argc,
                           UNUSED char* argv[]) {
    // for this plug-in we do not need to initialize anything.
    // so just return
    lpcb = pcb;
    return true;
}

// The plug-in clean-up function
// This must be implemented and will be called by the odl parser before the
// data model is destroyed and the data model memory is freed.
void pcb_plugin_cleanup() {
    // for this plug-in there is nothing to do here
}