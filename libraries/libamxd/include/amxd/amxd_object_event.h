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

#if !defined(__AMXD_OBJECT_EVENT_H__)
#define __AMXD_OBJECT_EVENT_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <amxd/amxd_types.h>

/**
   @file
   @brief
   Ambiorix Data Model API header file
 */

/**
   @ingroup amxd_object
   @defgroup amxd_object_event Event Methods
 */

/**
   @ingroup amxd_object_event
   @brief
   Send an object signal/event.

   Creates a data model event and calls all connected functions. When the
   trigger argument is set to true the connected functions (callback functions)
   are called immediately, when set to false the functions will be called
   from the eventloop implementation.

   A data model event always contains the name of the event and the object path
   in different formats.

   Example of a base event:
   @code
   {
       path = "Greeter.History.1.Info.1."
       object = "Greeter.History.1.Info.cpe-Info-1.",
       eobject = "Greeter.History.[1].Info.[cpe-Info-1].",
       notification = "dm:object-changed",
   }
   @endcode

   The base event data:
   - path: is the USP compatible object path using the indices for the instances.
   - object: the object path using the names of the instances, be aware that
     when the instance contains an Alias parameter, the value of the Alias parameter
     is used as the name of the instance. An Alias parameter value may contain
     dots.
   - eobject: the object path using the names of the instances put between
     brackets.
   - notification: the name of the event.

   Other data can be provided in an event. Which extra data is added, depends on the
   event type itself.

   @warning
   It is recommended to use the path and avoid to use the object or eobject. The
   path is compatible with USP specifications while object and eobject paths can
   only be used in ambiorix APIs.

   @param object the object for which the event must be sent.
   @param name the event name.
   @param data (optional, can be NULL) the event data.
   @param trigger when set to true, call callback functions immediately.
 */
void amxd_object_send_signal(amxd_object_t* const object,
                             const char* name,
                             amxc_var_t* const data,
                             bool trigger);

/**
   @ingroup amxd_object_event
   @brief
   Emit an object signal/event.

   @see amxd_object_send_signal.

   This function will call @ref amxd_object_send_signal with trigger set to false.

   @param object the object for which the event must be send.
   @param name the event name.
   @param data (optional, can be NULL) the event data.
 */
AMXD_INLINE
void amxd_object_emit_signal(amxd_object_t* const object,
                             const char* name,
                             amxc_var_t* const data) {
    amxd_object_send_signal(object, name, data, false);
}

/**
   @ingroup amxd_object_event
   @brief
   Emit an object signal/event.

   @see amxd_object_send_signal.

   This function will call @ref amxd_object_send_signal with trigger set to true.

   @param object the object for which the event must be send.
   @param name the event name.
   @param data (optional, can be NULL) the event data.
 */
AMXD_INLINE
void amxd_object_trigger_signal(amxd_object_t* const object,
                                const char* name,
                                amxc_var_t* const data) {
    amxd_object_send_signal(object, name, data, true);
}

/**
   @ingroup amxd_object_event
   @brief
   Send an add instance object event.

   Creates a data model add instance event and calls all connected functions. When
   the trigger argument is set to true the connected functions (callback functions)
   are called immediately, when set to false the functions will be called
   from the eventloop implementation.

   Besides the base event data an add instance event contains the index and name
   of the newly added instance, a hash table containing the key parameters and a
   hash table containing all parameters.

   Example of an add instance event:
   @code
   {
       path = "Greeter.History.1.Info.",
       object = "Greeter.History.1.Info.",
       eobject = "Greeter.History.[1].Info.",
       notification = "dm:instance-added",
       index = 1,
       name = "cpe-Info-1",
       keys = {
           Alias = "cpe-Info-1"
       },
       parameters = {
           Alias = "cpe-Info-1",
           Disabled = 0,
           Flags = "",
           Number = 0,
           SignedNumber = -100,
           Text = ""
       }
   }
   @endcode

   The event data:
   - The object path (path, object, eobject - see @ref amxd_object_send_signal)
     This is the path to the multi-instance object.
   - index: The index of the newly added instance
   - name: The object name of the newly added instance (mostly the value of the Alias parameter)
   - keys: The key parameters and their values as a hash table.
   - parameters: All parameters and their values as a hash table.

   @param instance The newly added instance.
   @param trigger when set to true, call callback functions immediately.
 */
void amxd_object_send_add_inst(amxd_object_t* instance, bool trigger);

/**
   @ingroup amxd_object_event
   @brief
   Emit an add instance object event.

   @see amxd_object_send_add_inst.

   This function will call @ref amxd_object_send_add_inst with trigger set to false.

   @param instance The newly added instance.
 */
AMXD_INLINE
void amxd_object_emit_add_inst(amxd_object_t* instance) {
    amxd_object_send_add_inst(instance, false);
}

/**
   @ingroup amxd_object_event
   @brief
   Trigger an add instance object event.

   @see amxd_object_send_add_inst.

   This function will call @ref amxd_object_send_add_inst with trigger set to true.

   @param instance The newly added instance.
 */
AMXD_INLINE
void amxd_object_trigger_add_inst(amxd_object_t* instance) {
    amxd_object_send_add_inst(instance, true);
}

void amxd_object_send_del_object(amxd_object_t* object, bool trigger);

/**
   @ingroup amxd_object_event
   @brief
   Send a delete instance object event.

   Creates a data model delete instance event and calls all connected functions. When
   the trigger argument is set to true the connected functions (callback functions)
   are called immediately, when set to false the functions will be called
   from the eventloop implementation.

   Besides the base event data a delete instance event contains the index and name
   of the newly deleted instance, a hash table containing the key parameters and their
   values and a hash table containing all parameters and their last known values.

   Example of a delete instance event:
   @code
   {
       path = "Greeter.History.1.Info.",
       object = "Greeter.History.1.Info.",
       eobject = "Greeter.History.[1].Info.",
       notification = "dm:instance-removed",
       index = 1,
       name = "cpe-Info-1",
       keys = {
           Alias = "cpe-Info-1"
       },
       parameters = {
           Alias = "cpe-Info-1",
           Disabled = 0,
           Flags = "",
           Number = 0,
           SignedNumber = -100,
           Text = ""
       }
   }
   @endcode

   The event data:
   - The object path (path, object, eobject - see @ref amxd_object_send_signal)
     This is the path to the multi-instance object that contained the instance.
   - index: The index of the deleted instance
   - name: The object name of the deleted instance (mostly the value of the Alias parameter)
   - keys: The key parameters and their last known values as a hash table.
   - parameters: All parameters and their last known values as a hash table.

   @warning
   It is possible that when the callback functions are called that the object already
   is deleted, so it will not be accessible anymore.

   @param instance The instance that is going to be deleted.
   @param trigger when set to true, call callback functions immediately.
 */
void amxd_object_send_del_inst(amxd_object_t* instance, bool trigger);
/**
   @ingroup amxd_object_event
   @brief
   Emit a delete instance object event.

   @see amxd_object_send_del_inst.

   This function will call @ref amxd_object_send_del_inst with trigger set to false.

   @param instance The instance that will be deleted.
 */
AMXD_INLINE
void amxd_object_emit_del_inst(amxd_object_t* instance) {
    amxd_object_send_del_object(instance, false);
}

/**
   @ingroup amxd_object_event
   @brief
   Trigger a delete instance object event.

   @see amxd_object_send_del_inst.

   This function will call @ref amxd_object_send_del_inst with trigger set to true.

   @param instance The instance that will be deleted.
 */
AMXD_INLINE
void amxd_object_trigger_del_inst(amxd_object_t* instance) {
    amxd_object_send_del_object(instance, true);
}

/**
   @ingroup amxd_object_event
   @brief
   Send an object changed event.

   Creates a data model object changed event and calls all connected functions. When
   the trigger argument is set to true the connected functions (callback functions)
   are called immediately, when set to false the functions will be called
   from the eventloop implementation.

   Besides the base event data an object changed event contains all changed parameters.
   For each changed parameter the event will contain the value of the parameter before
   the change and the changed value

   Example of an add instance event:
   @code
   {
       path = "Greeter.History.1.Info.1.",
       object = "Greeter.History.1.Info.cpe-Info-1.",
       eobject = "Greeter.History.[1].Info.[cpe-Info-1].",
       notification = "dm:object-changed",
       parameters = {
           Number = {
               from = 0,
               to = 101
           },
           Text = {
               from = "",
               to = "Hello"
           }
       },
   }
   @endcode

   The event data:
   - The object path (path, object, eobject - see @ref amxd_object_send_signal)
     This is the path to the object that has been changed.
   - notification: the name of the event
   - parameters: All changed parameters as a hash table, each parameter is represented
     as a hash table that contains the original value (from) and the new value (to).

   @param object The object for which the changed event must be sent.
   @param params A hash table of the parameters with their original values (before the change)
   @param trigger when set to true, call callback functions immediately.
 */
void amxd_object_send_changed(amxd_object_t* object,
                              amxc_var_t* params,
                              bool trigger);

/**
   @ingroup amxd_object_event
   @brief
   Emit an object changed event.

   @see amxd_object_send_changed.

   This function will call @ref amxd_object_send_changed with trigger set to false.

   @param object The object for which the changed event must be sent.
   @param params A hash table of the parameters with their original values (before the change)
 */
AMXD_INLINE
void amxd_object_emit_changed(amxd_object_t* object,
                              amxc_var_t* params) {
    amxd_object_send_changed(object, params, false);
}

/**
   @ingroup amxd_object_event
   @brief
   Trigger an object changed event.

   @see amxd_object_send_changed.

   This function will call @ref amxd_object_send_changed with trigger set to true.

   @param object The object for which the changed event must be sent.
   @param params A hash table of the parameters with their original values (before the change)
 */
AMXD_INLINE
void amxd_object_trigger_changed(amxd_object_t* object,
                                 amxc_var_t* params) {
    amxd_object_send_changed(object, params, true);
}

/**
   @ingroup amxd_object_event
   @brief
   Creates and starts a periodic inform event timer.

   A periodic inform timer will send an event at a regular interval. The event
   will contain all parameters of the object and their values at that moment.

   A periodic inform timer can be used to send the values of volatile parameters
   (typically statistics).

   Only one periodic inform timer can be created for an object.

   Use @ref amxd_object_delete_pi to stop and delete the periodic inform timer.

   When the object is deleted the timer will be stopped and deleted as well.

   Example of a periodic inform event:
   @code
   {
       path = "Greeter.Statistics.",
       object = "Greeter.Statistics.",
       eobject = "Greeter.Statistics.",
       notification = "dm:periodic-inform",
       parameters = {
           AddHistoryCount = 0,
           DelHistoryCount = 0,
           EventCount = 6
       }
   }
   @endcode

   The event data:
   - The object path (path, object, eobject - see @ref amxd_object_send_signal)
     This is the path to the multi-instance object.
   - notification: the event name
   - parameters: All parameters of the object and their values as a hash table.

   @param object The object for which a periodic inform event must be created.
   @param sec Interval in seconds at which the event must be sent.

   @return
   amxd_status_ok when periodic inform timer was created and started successfully.
   Any other value indicates an error.
 */
amxd_status_t amxd_object_new_pi(amxd_object_t* object,
                                 uint32_t sec);

/**
   @ingroup amxd_object_event
   @brief
   Stops and deletes a periodic inform event timer.

   A periodic inform timer can be created and started using @ref amxd_object_new_pi.

   This function will stop and deletes the periodic inform timer for the object.

   @param object The object for which a periodic inform event must be stopped.

   @return
   amxd_status_ok when periodic inform timer was created and started successfully.
   Any other value indicates an error.
 */
amxd_status_t amxd_object_delete_pi(amxd_object_t* object);

amxd_status_t amxd_object_describe_events(amxd_object_t* const object,
                                          amxc_var_t* const value,
                                          amxd_dm_access_t access);

/**
   @ingroup amxd_object_event
   @brief
   Adds an event definition to the object.

   Events and the data they can contain can be defined and stored in the
   data model definition.

   To allocate a variant containing the event data the function @ref amxd_object_new_event_data
   can be used.

   @param object The object in which an event must be defined.
   @param event_name The name of the event.
   @param event_data (optional) The event data definition template.

   @return
   amxd_status_ok when the event definition was successfully added to the object definition
   Any other value indicates an error.
 */
amxd_status_t amxd_object_add_event_ext(amxd_object_t* const object,
                                        const char* event_name,
                                        amxc_var_t* event_data);

/**
   @ingroup amxd_object_event
   @brief
   Adds an event definition to the object.

   Events can be defined and stored in the data model definition.

   If an event data template must be added use function @ref amxd_object_add_event_ext.

   This function wil call @ref amxd_object_add_event_ext and set the event data pointer
   to NULL.

   @param object The object in which an event must be defined.
   @param event_name The name of the event.

   @return
   amxd_status_ok when the event definition was successfully added to the object definition
   Any other value indicates an error.
 */
amxd_status_t amxd_object_add_event(amxd_object_t* const object,
                                    const char* event_name);

/**
   @ingroup amxd_object_event
   @brief
   Removes an event definition to the object.

   This function will remove an event definition from the data model definition.

   Events definitions can be added using @ref amxd_object_add_event or @ref amxd_object_add_event_ext.

   @param object The object from which an event must be removed.
   @param event_name The name of the event.

   @return
   amxd_status_ok when the event definition was successfully removed from the object definition
   Any other value indicates an error.
 */
void amxd_object_remove_event(amxd_object_t* const object,
                              const char* event_name);

/**
   @ingroup amxd_object_event
   @brief
   Allocates a variant that contains the predefined event data.

   This function allocates a variant on the heap. The returned variant pointer
   can be used to set the correct event values for the event data.

   The returned pointer must be freed using @ref amxc_var_delete.

   @param object The object from which an event must be removed.
   @param event_name The name of the event.

   @return
   A pointer to a amxc_var_t structure or a NULL pointer if no such event was defined.
 */
amxc_var_t* amxd_object_new_event_data(const amxd_object_t* object,
                                       const char* event_name);

#ifdef __cplusplus
}
#endif

#endif // __AMXD_OBJECT_EVENT_H__

