# Actions, Transactions & Events

***
> ## __Table of Contents__  
>
>  1. [Introduction](#introduction) 
>  2. [Actions](#actions)  
  2.1. [Implementing An Action Callback](#implementing-an-action-callback)  
  2.1.1. [Register Action Callback](#register-action-callback)  
  2.1.2. [Remove Action Callback](#remove-action-callback)  
  2.1.3. [Considerations](#considerations)  
  2.2. [Invoking Actions](#invoking-actions)  
  2.3. [Object Actions](#object-actions)  
  2.3.1. [action_object_read](#action_object_read)  
  2.3.2. [action_object_write](#action_object_write)  
  2.3.3. [action_object_validate](#action_object_validate)  
  2.3.4. [action_object_list](#action_object_list)  
  2.3.5. [action_object_describe](#action_object_describe)  
  2.3.6. [action_object_tree](#action_object_tree)  
  2.3.7. [action_object_add_inst](#action_object_add_inst)  
  2.3.8. [action_object_del_inst](#action_object_del_inst)  
  2.3.9. [action_object_destroy](#action_object_destroy)  
  2.4. [Parameter Actions](#parameter-actions)  
  2.4.1. [action_param_read](#action_param_read)  
  2.4.2. [action_param_write](#action_param_write)  
  2.4.3. [action_param_validate](#action_param_validate)  
  2.4.4. [action_param_describe](#action_param_describe)  
  2.4.5. [action_param_destroy](#action_param_destroy)  
  2.5. [action_any](#action_any)
>  3. [Transactions](#transactions)  
  3.1. [Instantiate Transaction](#instantiate-transaction)  
  3.2. [Build Action Sequence](#build-action-sequence)  
  3.3. [Apply Transaction](#apply-transaction)  
  3.4. [Failed Transaction](#failed-transaction)  
  3.5. [Example Transaction](#example-transaction)  
>  4. [Events](#events)  

## Introduction

The Ambiorix amxd library provides an extensive API to create and manage a data model. A data model is a hierarchical tree of objects where each object can contain parameters and functions.

A data model shows the current state of (system) services, can contain configuration data, statistics information and more.

Such a data model is dynamic in nature it can change all the time due to multiple reasons like (but not limited to) :

- changes in the system, example: network interface disabled
- changes in the configuration, from an external source, example firewall port opened through the web-ui.

So it must be possible to do some operations on the data model like:

- get (read the parameter values)
- set (change the parameter values)
- add instance (add a new object)
- delete instance (delete an object)
- validate (verifies that the values are correct)

Or even inspect the data model

- list all items in an object
- describe an object

All these operations on the data model are implemented in the Ambiorix amxd library using `actions`.

Often it is needed to execute multiple actions `at once`, and if one of the `actions` fails nothing should be changed. The Ambiorix amxd library provides such functionality as `transactions`.

Last but not least, often you want to get informed that changes have happened, you can get informed by subscribing on events.

## Actions

Actions implement operations on the data model on object level or parameter level. All actions have a default implementation and in most cases you do not need to override the default behavior, except for the validate and destroy actions.

As all data model operations are implemented in `actions`, actions are one of the most important parts of the data model implementation.

The actions (and the operations they perform) can be divided in two groups:

- the object actions
- the parameter actions.

All possible actions are defined as an enumeration in the header file `amxd_types.h`

```C
typedef enum _amxd_action {
    action_any,
    action_param_read,
    action_param_write,
    action_param_validate,
    action_param_describe,
    action_param_destroy,
    action_object_read,
    action_object_write,
    action_object_validate,
    action_object_list,
    action_object_describe,
    action_object_tree,
    action_object_add_inst,
    action_object_del_inst,
    action_object_destroy,
} amxd_action_t;
```

### Implementing An Action Callback

As mentioned before, in most cases it is not needed to implement an action callback, except for `validate` and `destroy` actions. There are of course use cases where you need to implement other (object) actions as well.

For example (not limited to):

- A template object is linked to a database table and each instance represents a record from that table. In this case you need to override all object actions of that template object (not the instances). In this case you will also not use the amxd library data model parameters.
- The (linux) system provides a C structure which needs to be mapped on data model parameters in a one-on-one relation. In this case you also can override all object actions. In this case you will also not use the amxd library data model parameters.

Other uses cases can exist where multiple or some actions need to be overridden.

Each action implementation function must match this signature:

```C
typedef amxd_status_t (*amxd_action_fn_t) (amxd_object_t * const object,
                                           amxd_param_t * const param,
                                           amxd_action_t reason,
                                           const amxc_var_t * const args,
                                           amxc_var_t * const retval,
                                           void *priv);
```

Such an `action` implementation is called an `action callback` function. For each action it is possible to add multiple `action callbacks`. The arguments provided to your `action callback` depend on the action itself. For more details see the section about the action itself.

In general:

- An object pointer is always provided for object actions, but not always for parameter actions.
- A parameter pointer is only provided for parameter actions
- The reason is always provided and is one of the values as defined in the `amxd_action_t` enum.
- What the content is of the two variants `args` and `retval` depends on the action itself, for more details see the action section
- The `priv` pointer is private user data as passed when registering the action callback.

#### Register Action Callback

When you implemented an `action callback` function you need to make it `available` to the data model.

The Ambiorix amxd library provides two APIs that makes it possible to add `action callbacks` to the data model, one for objects and one for parameters.

```C
amxd_status_t amxd_object_add_action_cb(amxd_object_t * const object,
                                        const amxd_action_t reason,
                                        amxd_action_fn_t fn,
                                        void *priv);

amxd_status_t amxd_param_add_action_cb(amxd_param_t * const param,
                                       const amxd_action_t reason,
                                       amxd_action_fn_t fn,
                                       void *priv);
```

Each `action callback` function (`fn`) can be used multiple times, but only once for each object or parameter. In other words if an `action callback` is already added to a certain object or parameter, it is not possible to add it again. The functions will fail in that case (return a none-zero value).

The reason SHOULD match the implementation, it is also recommended to check in the `action callback` implementation that the provided `reason` does match the implementation.

With each registration of an `action callback` it is possible to provide private user data (`priv`), this private user data is passed to the `action callback` as is.

Whenever an `action callback` is added to an object, it will be used in all derived objects, in other words, when an `action callback` is added to a template object, it will be used on all instances as well.

When an `action callback` for the same `reason` is added to such a derived object, that `action callback` is used on the derived object and not the one of the base object.

When an `action callback` is added, the default implementation will never be called anymore.

#### Remove Action Callback

It is possible to remove `action callbacks` from the data model as well. The Ambiorix amxd library provides two APIs that makes this possible:

```C
amxd_status_t amxd_object_remove_action_cb(amxd_object_t * const object,
                                           const amxd_action_t reason,
                                           amxd_action_fn_t fn);

amxd_status_t amxd_param_remove_action_cb(amxd_param_t * const param,
                                          const amxd_action_t reason,
                                          amxd_action_fn_t fn);
```

When all `action callbacks` for a certain `reason` are removed from the data model, the default implementation will be used again. Keep in mind that it can have effect on all derived objects as well.

#### Considerations

When implementing `action callbacks` a few things must be taken in consideration.

***Recursion***

The general rule is that `actions` can not call `actions`, so action recursion is not allowed, except:

- read actions (read, list, describe) can be invoked or called from any action.
- object actions can invoke parameter actions.

***Check The Reason***

Always check the `reason` argument in your `action callback` implementation to make sure that it is called for what it is intended to do. 

If the `reason` is not correct, you MUST return `amxd_status_function_not_implemented`

***Check The Input***

As anyone can call your `action callback` implementation using the generic action invoke function `amxd_dm_invoke_action` it is possible that not all input arguments are correct. This is a mistake of the caller, but never the less, it is better to be safe than sorry. 

If one of the arguments provided does not match the expectations, any `amxd_status_t` code can be returned, if you return status code `amxd_status_function_not_implemented`, the default implementation will be called.

### Invoking Actions

You can invoke actions by yourself from almost anywhere in your code using the function:

```C
amxd_status_t amxd_dm_invoke_action(amxd_object_t *object,
                                    amxd_param_t *param,
                                    amxd_action_t reason,
                                    const amxc_var_t * const args,
                                    amxc_var_t * const retval);
```

This function is a bit clumsy to use, as you need to know what you need to provide in the `args` argument, the good news is that in normal use case you do not need to call this function.

To make it easier wrapper functions are provided in the Ambiorix amxd library, that will make your life easier and makes it easier to invoke the actions

```C
// action_object_describe
amxd_status_t amxd_object_describe(amxd_object_t * const object,
                                   amxc_var_t * const value);

// action_object_list
amxd_status_t amxd_object_list(amxd_object_t * const object,
                               bool include_priv,
                               amxc_var_t * const list);

// action_object_read
amxd_status_t amxd_object_get_params(amxd_object_t * const object,
                                     bool include_priv,
                                     amxc_var_t * const params);

// action_object_read
amxd_status_t amxd_object_get_param(amxd_object_t * const object,
                                    const char *name,
                                    amxc_var_t * const value);

// action_object_write
amxd_status_t amxd_object_set_param(amxd_object_t * const object,
                                    const char *name,
                                    amxc_var_t * const value);

// action_object_destroy
void amxd_object_delete(amxd_object_t **object);


// action_param_describe
amxd_status_t amxd_param_describe(amxd_param_t * const param,
                                  amxc_var_t * const value);

// action_param_read
amxd_status_t amxd_param_get_value(amxd_param_t * const param,
                                   amxc_var_t * const value);

// action_param_validate
amxd_status_t amxd_param_validate(amxd_param_t * const param,
                                  amxc_var_t * const value);

// action_param_write
amxd_status_t amxd_param_set_value(amxd_param_t * const param,
                                   amxc_var_t * const value);

// action_param_destroy
void amxd_param_delete(amxd_param_t **param);
```

For detailed information about these functions, please consult the API documentation.
Most of these functions, just build the `args` content and call `amxd_dm_invoke_action` and eventually extract what is needed from the `retval`.

You probably noticed that there are no wrapper APIs for the following actions:

- action_object_add_inst
- action_object_del_inst
- action_object_validate

The reason is that these `actions` most of the time are used in a sequence of actions for example:

1. add instance
2. set instance parameter value
3. set instance parameter value
4. set instance parameter value
5. validate object

When you want to implement such a sequence of actions, it is recommended to use the `transaction` implementation, or if you know what you are doing, you could directly manipulate the data model with the provided APIs. 

Transactions make it easy to implement sequences like described above, and will validate all parameters and objects that are changed or created.

When there is a need for wrappers for these actions, they will be added.

### Object Actions

#### action_object_read

TODO

#### action_object_write

TODO

#### action_object_validate

You probably will override the default implementation of this action. Especially when some constrains are applied on the object. In most cases the constrains will be that only a certain combination of parameter values of the object is allowed or some combinations are not allowed.

Action callback functions that implement this action MUST only validate the object, they MUST not change the object in any way.

When multiple `action callbacks` are registered on the same object for action `action_object_validate` the object is considered valid if all of them return `amxd_status_ok`. If one of the implementations return another status code (except `amxd_status_function_not_implemented`), the object is considered invalid.

***Input***

The `object` argument provided MUST be valid and is pointing to the object that must be validated

The `param` argument MUST be ignored (and will be NULL)

The `reason` argument MUST be equal to `action_object_validate`

The 'priv' argument is private user data as passed when registering the `action callback`

The `args` argument MUST be ignored

***Output***

The implementation MAY return any of the `amxd_status_t` codes.

The implementation MUST return `amxd_Status_ok` if the object is valid.

When the returned status code is `amxd_status_function_not_implemented` the default implementation will be called if no other callbacks are registered for action `action_object_validate`. 


#### action_object_list

TODO

#### action_object_describe

TODO

#### action_object_tree

This action is currently never used. Adding an implementation will not have any effect, unless manually invoked using `amxd_dm_invoke_action`.

This action is defined for later used or could be removed in the future.

#### action_object_add_inst

You probably never need to override the default implementation of this action. Most of the time you just want to get informed when a new instance has been added. Subscribe for the event `dm:instance-added` on the template object to get informed when an instance has been added.

Action callback functions that implement this action must create an instance of a template object.

The instance can be created with function `amxd_object_new_instance`. If the creation of the instance succeeds and later the sets of the parameter values fail, this action MUST not delete the newly created instance, but must provide the `retval` filled with correct content and return a status code other then `amxd_status_ok` or `amxd_status_function_not_implemented`. The created instance will be removed later when this action was part of a transaction.

The implementation SHOULD not invoke `action_object_validate`. If the action is part of a transaction, the validation action will be done later and the instance will be deleted if the validation fails.

If the action is invoked manually (not using a transaction) it is up to the caller to do the validation and/or removal of the newly created instance.

***Input***

The `object` argument provided MUST be valid and is pointing to the template object.

The `param` argument MUST be ignored (and will be NULL)

The `reason` argument MUST be equal to `action_object_add_inst`

The 'priv' argument is private user data as passed when registering the `action callback`

The `args` argument MUST be a variant of type `AMXC_VAR_ID_HTABLE` and MUST contain fields:

- index (uint32)
- name (cstring_t)

Optionally it MAY contain fields:

- set_priv (boolean) - when true the instance MUST be created, even if the template object is marked private and privated parameters MUST be set if the value is given
- set_read_only (boolean) - when true the instance MUST be created, even if the template object is marked as read-only. This flag SHOULD NOT have effect on read-only parameters. During the creation of an instance setting the values is always allowed.
- parameters (amxc_htable_t) - a table containing key - value pairs where each key MUST match with a parameter name in the newly create instance. The action MAY fail when no parameter is found matching the key or MAY silently ignore the key - value pair.

***output***

The status code returned MAY be any of the `amxd_status_t` codes. When the action completed successful it MUST be `amxd_status_ok`. When the status code `amxd_status_function_not_implemented` is returned, the default implementation (if no other action callbacks are available) is called.

The `retval` argument MUST be set to the `AMC_VAR_ID_HTABLE` and MUST contain the following fields:

- index (uint32_t)
- name (cstring_t)

When the creation of the instance fails (not set of values) it MUST be deleted by the caller (in most cases this will be a transaction).

#### action_object_del_inst

TODO

#### action_object_destroy

You probably will override the default implementation in some cases and mostly only when private user data is allocated and attached to the object.

This `action callback` MUST NOT delete the object itself and MUST return one of these status code `amxd_status_ok` or `amxd_status_function_not_implemented`. The `action callback` MUST clean-up other allocations done and attached to the object.

***Input***

The `object` argument provided MUST be valid and is pointing to an object.

The `param` argument MUST be ignored (and will be NULL)

The `reason` argument MUST be equal to `action_object_destroy`

The `args` argument MUST be ignored

The `priv` argument is the one of importance here, Probably the destroy action implementation is added because private user data is added to the object. The object will be deleted (after the destroy action has finished) and therefor the private user data is not needed anymore and can be deleted as well.

The implementor of an `action_object_destroy` MAY remove all other `action callback` functions from within this action or do other clean-up actions as deemed necessary.

***Output***

The implementation MUST return one of these status code `amxd_status_ok` or `amxd_status_function_not_implemented`.

The `retval` argument MAY be cleared using `amxc_var_clean` or ignored.

### Parameter Actions

TODO

#### action_param_read

TODO

#### action_param_write

TODO

#### action_param_validate

TODO

#### action_param_describe

TODO

#### action_param_destroy

TODO

### action_any

TODO

## Transactions

Transactions invokes `actions` in a pre-defined order. When applying a transactions it can be considered as an `atomic` operation.

Using transactions is easy and involves just a few steps:

1. Instantiate a transaction
2. Build the sequence of actions
3. Apply the transaction

Besides executing the list of actions, a transaction contains extra functionality:

- it validates all changed parameters and objects (using the `action_parameter_validate` and `action_object_validate` actions)
- does a full rollback (revert the changes) when an action fails or when validation fails.
- emit events (signals) for all changed objects (only when transaction completed successful)
- garbage collection (removes deleted objects from the data model and frees the memory used by these objects).

The actions added to the transaction does not have to be limited to one single object in your data model, you can modify as many objects as you like using one single transaction.

### Instantiate Transaction

Instantiating a transaction is very easy and can be done using one of these (constructor) functions:

```C
amxd_status_t amxd_trans_init(amxd_trans_t * const trans);

amxd_status_t amxd_trans_new(amxd_trans_t **trans);
```

The first one can be used if the transaction is on the stack, the second one to allocate memory from the heap to store the transaction.

### Build Action Sequence

A transaction is intended to modify the data model, it can change parameter values, add or delete instances.

All these operations work on an data model object, and there for it is needed to `tell` the transaction on which object it should operate. The functions `amxd_trans_select_object` and `amxd_trans_select_pathf` adds an object selection to the transaction. All set, add, delete operations added after an object selection will operate on the selected object,

You can add multiple object selections in an transaction sequence. 

Adding the `actions` to the transaction does not have any impact on the data model until the transaction is applied (using `amxd_trans_apply` function)

The APIs that help in building the transaction sequence are:

**Selecting an object**:
```C
amxd_status_t amxd_trans_select_object(amxd_trans_t *trans,
                                       const amxd_object_t * const object);

amxd_status_t amxd_trans_select_pathf(amxd_trans_t * const trans,
                                      const char *path,
                                      ...);
```

The first function takes an object pointer, the second one takes the full object path and supports `printf` like string formatting.

**Adding an instance**:

```C
amxd_status_t amxd_trans_add_inst(amxd_trans_t * const trans,
                                  const uint32_t index,
                                  const char *name);
```

The selected object must be a template object. When the transaction is executed (using `amxd_trans_apply` function) and the creation of the instance is successful, the new instance will be selected as the active object. If the next action in the transaction is a `set` operation it will be executed on the new instance.

The argument `index` can be any index, when set to 0, the next index is chosen. The `name` argument can be 'NULL'. When no name is given, the index of the object will be used as the name (in string format). 

**Deleting an instance**:

```C
amxd_status_t amxd_trans_del_inst(amxd_trans_t * const trans,
                                  const uint32_t index,
                                  const char *name);
```

The selected object must be a template object. Only one of the `index` and `name` arguments must be given. If both are provided, the instance is searched using the given `index` and the `name` argument is ignored. 

If the instance does not exist, the function `amxd_trans_apply` will fail, not this function. This function only adds the `delete` operation to the transaction.

When the transaction is applied (using `amxd_trans_apply`) the instance object is not deleted immediately, but after all actions in de transaction sequence list are done.

**Set a parameter value**:

```C
amxd_status_t amxd_trans_set_param(amxd_trans_t * const trans,
                                   const char *param_name,
                                   amxc_var_t * const value);
```

Using this function, the value you want to set must be stored in a `variant`. This would clutter the code as you first need to set the value in a `variant` and the add a `set` operation to the transaction. 

To avoid that a helper macro is available:

```C
#define amxd_trans_set_value(type, trans, name, value)
```

This macro takes as first argument the type, the other arguments are matching the function `amxd_trans_set_param` except the value, as it can be a normal C type.

The type names allowed are:

- cstring_t for a `char *`
- bool
- int32_t
- uint32_t
- int64_t
- uint64_t
- double
- amxc_ts_t for timestamps

When multiple parameter set operations are done on the selected object, they will be combined into one action when applying the transaction (using `amxd_trans_apply`)

### Apply Transaction

When all operations on the data model are added to the transaction, they can be applied.
Applying a transaction is done using the function:

```C
amxd_status_t amxd_trans_apply(amxd_trans_t * const trans,
                               amxd_dm_t * const dm);
```

When the transaction completed successful (return code `amxd_status_ok`), all operations added to the transaction have been executed, all changed objects are validated, all deleted instances are gone, and data model events have been emitted.

When the transaction fails, none of the operations have been applied, no events have been emitted, nothing is deleted. The returned status code can provide an indication of the failure.

### Failed Transaction

When applying a transaction fails, it is not always clear why it failed or on which operation it failed.

This can be inspected using the `transaction` instance you have created. The `transaction` instance is a C structure defined as follows:

```C
typedef struct _amxd_transaction {
    amxc_llist_t actions;           // list of actions to do when transaction is applied
    amxc_llist_t validate;          // objects or object trees that needs validation
    amxc_llist_t garbage;           // list of objects that need to be destroyed when transaction is done
    amxd_object_t *current;         // current selected object
    amxd_trans_attr_t attr;         // transaction attributes
    amxc_var_t retvals;             // list of return values of actions
    amxd_status_t status;           // transaction status code
    int fail_index;                 // index of failed action
} amxd_trans_t;
```

Most fields are used during the execution of the transaction (when you called amxd_trans_apply), when the transaction fails, the fields `fail_index` and `status` will provide a good hint on which operation the transaction failed and why.

The index is the index of the action in the `actions` list and the `status` is the status code of that action.

To make it even more clear, a debugging function is available that can dump the full transaction in clear text:

```C
void amxd_trans_dump(const amxd_trans_t * const trans,
                     const int fd,
                     const bool reverse);
```

The `fd` argument is a file descriptor, and can be `STDOUT_FILENO` or any other valid file descriptor.

When reverse is set to `true` the list of actions is dumped in reverse order (so first the last action and ending with the first action).

### Example Transaction

```C
    amxd_trans_init(&transaction);
    amxd_trans_set_attr(&transaction, amxd_tattr_change_ro, true);

    amxd_trans_select_object(&transaction, history_obj);
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_param(&transaction, "From", from);
    amxd_trans_set_param(&transaction, "Message", msg);
    amxd_trans_set_param(&transaction, "Retain", retain);

    if (amxd_trans_apply(&transaction, dm) != amxd_status_ok) {
        // do some error handling
    }
```

Assume you don't set the attribute for changing read-only parameters and object. This will cause the transaction to fail (in this scenario). You can investigate why it failed by using `amxd_trans_dump`. It will show and output similar to this:

```
SELECT - 
{
    path = "Greeter.History."
}

ADD - 
{
    access = 1
    index = 0,
    name = "",
    parameters = {
        From = "me"
        Message = "hello",
        Retain = false,
    },
    set_read_only = false,
}
```

In the `ADD` action, you can see that `set_read_only` is set to `false`, which explains why the transaction failed.

### Successful Transaction

When a transaction succeeds, the return values can be found in the `retvals` field of the transaction. This variant is a list with the return values of each `action` that was executed. Note that the `set action` is not always a separate action. For example when executing an `add` followed by one or multiple `sets`, the `sets` will be added to the `add` instance action instead of doing them separately.

If the transaction succeeds, you can inspect the return values with `amxc_var_dump(&transaction.retvals, STDOUT_FILENO);`

```C
int amxc_var_dump(const amxc_var_t *const var,
                  int fd);
```

If we again consider the [Greeter. example](#example-transaction) from before and we make sure the attribute for changing read-only parameters is set, the `retvals` variant will look similar to this:

```
[
    <NULL>,
    {
        index = 3,
        name = "3",
        object = "Greeter.History.3.",
        parameters = {
        },
        path = "Greeter.History.3."
    }
]
```

The first element in the list is the return variant from selecting the object with `amxd_trans_select_object`. It does not have a return value, so the variant is always `NULL` for a `select` action. The second element in the list is the result of the `add` instance combined with `setting` the parameters (this is done in one action). This return variant can help you find the index of the new instance. Note that the `parameters` in the variant will only show the `key` parameters.

The `retvals` variant can only be used when the transaction succeeds (when it returns with `amxd_status_ok`). If the transaction fails, it will be a `NULL` variant.

## Events

When something changes in the data model (using a transaction for example), events can be `send` to inform you of the change.

To get informed you need to `subscribe` on the event and implement a callback function.

The event mechanism of the Ambiorix data model implementation is fully implemented on top of the signal/slot implementation of the Ambiorix amxp library (see [signal/slot](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxp/-/blob/main/doc/signal_slot.md) for more details)

Each data model (`dm_t` structure) contains a signal manager and by default the following signals (events) are registered in the data model's signal manager:

- dm:root-added
- dm:root-removed
- dm:object-added
- dm:object-removed
- dm:instance-added
- dm:instance-removed
- dm:object-changed
- dm:periodic-inform

These events are considered the default data model events. Other events can be added to the data model's signal manager. When these events are emitted or triggered, there is always `signal` data available, which contains at least the full object path of the object for which the `signal` (event) was emitted or triggered.

Using the signal manager, or adding signals (events), or subscribing for events (connect) is done using the API of Ambiorix amxp library. 

The data model library (libamxd) provides some API's to `send` the events.

The basic API's are:

```C
// any signal 
void amxd_object_send_signal(amxd_object_t * const object,
                             const char *name,
                             amxc_var_t * const data,
                             bool trigger);

// add instance signal
void amxd_object_send_add_inst(amxd_object_t *instance, bool trigger);

// delete instance signal
void amxd_object_send_del_inst(amxd_object_t *instance, bool trigger);

// object changed
void amxd_object_send_changed(amxd_object_t *object,
                              amxc_var_t *params,
                              bool trigger);
```

When using transactions, the transaction will automatically send out these signals when needed. 

When manipulating the data model manually, it is up to the implementor to make sure that the correct signals are send (or not send, depends on the implementation).

