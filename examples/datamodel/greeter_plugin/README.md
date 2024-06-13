# Data Model Example - Greeter Plugin

[[_TOC_]]

## Introduction

The `Greeter` data model plug-in is not a real world example, its only purpose is to show how you can create a data model using the `Ambiorix` framework. This example can be run using the `Ambiorix Run Time` application (`amxrt`).

Using the `Ambiorix` framework it is possible to create and implement Broadband Forum data models (or parts of it) as described in one of the many TR-XXX specifications (like TR-181) for CWMP and USP support.

Or you could use the `Ambiorix` framework to create a `public` interface for your application.
This interface will make it possible for other services and applications to configure your application and to interact with it.

The features shown in this example are:

- Object Definition Language (`libamxo`):
  - Conditional include.
  - Function resolving.
  - Registering event callbacks with and without event filtering.
  - Configuration section and configuration variables.
  - Use of configuration variables in the ODL file.
  - Data model definition (objects, parameters, methods).
  - Defining object and parameter action callback functions.
  <br />
- Data Model Management (`libamxd`):
  - Data model methods.
  - Object and parameter action callback functions.
  - Event handler callback functions.
  - Instance creation.
  - Data model transactions.
  - Mapping a `C` data struct to a data model object.
  - Periodic inform events.

## Building `greeter` plugin

### Build Prerequisites

To be able to build this example you will need to install:

- `libamxc`  (Data collections and data containers)
- `libamxd`  (Data Model Management API)
- `libamxo`  (ODL Parsing and saving)
- `libamxp`  (Common Functional Patterns)

### Building

Change your working directory to the root of this example and use `make`.

```Bash
cd <GreeterRoot>/
make
```

After the `make` has finished, you can install it by calling `sudo -E make install`.

Examples:

Install in your system root
```bash
$ sudo make install
/usr/bin/install -d /usr/bin/
/usr/bin/install -d /usr/local/lib/amx/greeter
/usr/bin/install -d /etc/amx/greeter
/usr/bin/install -m 0755 ./output/x86_64-linux-gnu/object/greeter.so /usr/local/lib/amx/greeter/greeter.so
/usr/bin/install -m 0644 ./odl/greeter_definition.odl /etc/amx/greeter/
/usr/bin/install -m 0644 ./odl/greeter_extra.odl /etc/amx/greeter/
/usr/bin/install -m 0644 ./odl/greeter_defaults.odl /etc/amx/greeter/
/usr/bin/install -m 0644 ./odl/greeter.odl /etc/amx/greeter
/usr/bin/install -m 0755 ./odl/greeter.odl  /usr/bin/
ln -sf /usr/bin/amxrt /usr/bin/greeter 
```

> NOTE<br>
> This example installs the `./odl/greeter.odl` in two different places. This is done for illustration purpose, see [Running](#running)<br>
> <br>
> It is recommended to install the odl files in `/etc/amx/<subdir>`.

## Running `greeter` plugin

### Run Prerequisites

To be able to run this example you will need to:

- Build and install the example
- Install `amxrt` (`Ambiorix Runtime`)
- Install an `Ambiorix` bus back-end

A software bus must be running and the correct back-end must be installed.

In this explanation it is assumed that you have `ubusd` running and the `ubus` tool is installed (so the `amxb-ubus.so` should be available as well).

### Running

Once it is built and everything is installed you can launch the example.

The example can be started in different ways:

1. Using the symbolic link in `/usr/bin`, no command-line arguments are needed.

    ```bash
    $ greeter
    ```

2. Using the odl file installed in '/usr/bin`

    ```bash
    $ greeter.odl
    ```

3. Using `amxrt`

   ```bash
   $ amxrt /etc/amx/greeter/greeter.odl
   ```

It is recommended to run this example in foreground as it prints information to the standard output.

```bash
$ greeter
```

At start-up you will see some output on your console and if everything goes well, you should be greeted by the following text:

```text
*************************************
*          Greeter started          *
*************************************
```

That indicates that all went well and the `greeter` example is ready to rock 'n roll.

## Interacting with the `greeter` application

Before we dive into the implementation details, let's use the `Greeter` application.

### Verify The Data Model is available

After the initial launch, the data model should be available and visible. This is easy to verify:

```bash
$ ubus list
Greeter
Greeter.History
Greeter.History.1
Greeter.Statistics
```

This provides you with all `data model objects` currently available in the `Greeter` applications. Each of these objects can have methods and/or parameters.

To get the list of available methods in an object use the following command:

```bash
$ ubus -v list Greeter
'Greeter' @28a5fe7f
        "say":{"from":"String","message":"String","retain":"Boolean"}
        "echo":{"data":"(unknown)"}
        "setMaxHistory":{"max":"(unknown)"}
        "save":{"file":"String"}
        "load":{"file":"String"}
        "list":{"parameters":"Boolean","functions":"Boolean","objects":"Boolean","instances":"Boolean"}
        "describe":{"parameters":"Boolean","functions":"Boolean"}
        "get":{"parameters":"Array"}
        "set":{"parameters":"Table"}
```

Note that `Greeter` here, is the "root" `Greeter` object, if you want to inspect other objects feel free to change the object name.

To get the list of available parameters in an object use the following command:

```bash
$ ubus call Greeter get
{
        "MaxHistory": 10,
        "State": "Idle",
        "HistorySize": 1
}
```

Here we just invoked the `get` method of the object `Greeter`. The `get` method by default returns the parameters of the object and their value. The `get` method is one of the default provided methods and is available on all objects in the data model.

In this example some application (and object) specific methods are implemented as well, these methods are for the `Greeter` object:

- `say`
- `echo`
- `setMaxHistory`
- `save`
- `load`

### Say something

Now let's invoke the `say` method. This method will print your message to the standard output (the console where you started the `greeter` application), and adds your message to the `History` object.

```bash
$ ubus call Greeter say '{"from":"Me", "message":"Hello World"}'
Command failed: Unknown error
```

The method call fails. The reason for this is that the state of the `Greeter` object/application is `Idle`.
It will only accept new messages when the state is running.

So let's change the state using the `set` method

```bash
$ ubus call Greeter set '{"parameters":{"State":"Start"}}'
{
        "retval": ""
}
```

You can verify that the state is changed:

```bash
$ ubus call Greeter get
{
        "MaxHistory": 10,
        "State": "Running",
        "HistorySize": 2
}
```

The state is now `Running`, the application will now accept messages.

Let's retry the `say` method.
```bash
$ ubus call Greeter say '{"from":"Me", "message":"Hello World"}'
{
        "retval": "Hello World"
}
```

Now it worked!
In the console where the `greeter` application is running (in foreground) you will see that a few things are printed, one of them should be:

```text
==> Me says 'Hello World'
```

As the `say` method adds your message to the `History` object, a new object should be visible.

```bash
$ ubus list
Greeter
Greeter.History
Greeter.History.1
Greeter.History.2
Greeter.Statistics
```

In this case it will be the object `Greeter.History.2`. Let's check the contents of the object:

```bash
$ ubus call Greeter.History.2 get
{
        "Retain": false,
        "Message": "Hello World",
        "From": "Me"
}
```

## Directories and files

- `odl` directory contains all object definition files
  - greeter.odl - the main odl file, this is the one passed to `amxrt`
  - greeter_definition.odl - contains the data model definition
  - greeter_extra.odl - extends the `Greeter` object with method `echo`
  - greeter_defaults.odl - populates the data model with default `instances` and `values`
- `src` directory contains all the source code for building the greeter `shared object` plugin
  - greeter_main.c - contains the entrypoint implementation and some helper functions
  - dm_greeter_methods.c - contains the implementation of all `data model object` methods
  - dm_greeter_actions.c - contains the implementation of all parameter and object custom action implementations
  - dm_greeter_events.c - contains the implementation of event handlers
- makefile - builds and install the `greeter` plugin
- makefile.inc - contains settings and configuration used during building and installing
- README.md - this file

## Diving into the code

### ODL Files

This example provides 3 ODL files:

1. `greeter.odl` - This is the main ODL file, the one passed to `amxrt`. This file includes the other ODL files
2. `greeter_definition.odl` - This file contains the data model definition
3. `greeter_extra.odl` - This file contains an extenstion of the `Greeter` object definition
4. `greeter_defaults.odl` - Creates an instance of the history object, sets the `welcome` message

It is not the intention of this readme to go into details of the ODL syntax and features, for more information please read [Object Definition Language](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxo/-/blob/main/doc/odl.md)

#### greeter.odl

This is the main ODL file:

- it contains `configuration` settings for the ODL parser, `amxrt` and your application.
- `imports` the implementation
- includes other ODL files
- defines an entry point


Note that on the first line of the `greeter.odl` there is a bash `shebang`, if you set the `executable` flag on the ODL file, you can just launch it.
```odl
#!/usr/bin/amxrt
```

***The configuration section:***

```odl
%config {
    // Application name
    name = "greeter";

    // amxrt config-options
    auto-detect = true;
    auto-connect = true;
    daemon = false;
    priority = 0;

    // amxo parser config-options
    import-dirs = [ "./${name}" ];
    include-dirs = [ "./${name}", "." ];
    import-dbg = true;

    // Application specific settings
    // persistent storage location
    rw_data_path = "/etc/config";
    // main files
    definition_file = "${name}_definition.odl";
    extra_file = "${name}_extra.odl";
    save_file = "${rw_data_path}/${name}/${name}.odl";
    defaults_file = "${name}_defaults.odl";
}
```

In the configuration sections you can provide a set of variables and values. In this configuration section, there are some options set that are used by the `Ambiorix Runtime`, the amxo ODL parser itself, and at the bottom some variables and settings used by the `greeter` application itself.

***Import the implementation***

```odl
import "${name}.so" as "${name}";
```

When using the `Ambiorix Runtime` you can provide data model function implementations by specifying a `shared object` (so file). Here the `${name}` refers to one of the variables defined and set in the config section. When importing a `shared object` an alias can be specified, which makes it easier to refer to the `shared object`, especially if paths are used.

The previous line in the ODL will translate to:

```odl
import "greeter.so" as "greeter";
```

The `shared objects` loaded with the `import` instruction in the ODL file, are not standard libraries, they are called `plug-in`. The defaults system search paths for libraries are not used here.

When loading an ODL file, using `amxrt` the working directory is set to the directory containing the ODL file being loaded (in our case it is the directory containing `greeter.odl`). All plugin `shared objects` are loaded relative from that path, unless an absolute path was set in the `import`. Extra search paths can be set in the config option `import-dirs`, which is an array of directories.

If the plugin `shared object`is not found, parsing of the ODL file fails.

***Include ODL files***

```odl
include "${definition_file}";
#include "${extra_file}";
?include "${save_file}":"${defaults_file}";
```

The data model definition is not in the `greeter.odl` itself, the `main` ODL file includes other ODL files:

- `greeter_definition.odl` - defines the data model
- `greeter_extra.odl` - extends the `Greeter` object definition with methods `echo` and `deferred_echo`
- `greeter_defaults.odl` - fills the data model

Here the real file names are also defined in the `config` section, the two include lines will translate into

```odl
include "greeter_definition.odl";
#include "greeter_extra.odl";
?include "/etc/config/greeter/greeter.odl":"greeter_defaults.odl";
```

The first include is a mandatory include, if the file is not found parsing of the ODL file fails.

The second include is an optional include, if the file is not found parsing of the ODL file continues.
>If file `greeter_extra.odl` exists but contains errors, parsing will fail as well and stops.

The third include is a conditional include and must be interpreted as:
>If file `/etc/config/greeter/greeter.odl` exists load that file, otherwise load `greeter_defaults.odl`. If none of the files exist the parsing of the ODL file fails.

If the first file exists, but contains errors, the parsing will fail as well.

***Define an entry point***

```odl
%define {
    entry-point greeter.greeter_main;
}
```

Entry points are functions that can be called at start-up (after all ODL files are parsed) and at tear-down (when the application is stopping).

The `Ambiorix Runtime` (amxrt) will call all entry points after parsing of the ODL files is done and just before exiting the application.

The entry point here is taken from `greeter.so` and the function is called `greeter_main`. Entry points can only be resolved by the `import` resolver. In this case the `import` resolver will look for the symbol `_greeter_main` in the `greeter.so` shared object.

You can find the implementation of that function in the source file [src/greeter_main.c](https://gitlab.com/prpl-foundation/components/ambiorix/examples/datamodel/greeter_plugin/-/blob/main/src/greeter_main.c#L94). This function is not really doing anything besides printing some information to the `stdout`. The entry point implementation is here just for demo purposes.

#### greeter_definition.odl

The `greeter_definition.odl`, defines the `greeter` data model in the `%define` section.

In the `%populate` section it takes subscriptions on events, with filtering on the event data.

The ODL parser with some help of function resolvers will bind the definition to the real implementation.

More information about the ODL syntax for defining a data model can be found [here](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxo/-/blob/main/doc/odl.md)

##### Objects

Objects are related to each other in a `parent-child` relationship. In this example the hierarchy is as follows:

```text
Greeter
   |---History
   |      |----instance 1
   |      |----instance 2
   |---Statistics
```

This hierarchy is described in the ODL file as well, the objects `History` and `Statistics` are both defined in the `Greeter` object.

```odl
%define {
    object Greeter {
        %persistent %read-only object History[] {
            ....
        }
        %read-only object Statistics {
            ....
        }
    }
}
```

Also note the square brackets behind object `History`, this indicates that the object is a multi-instance (aka template) object. The other objects defined in this ODL are `singleton` objects.

For the object `Statistics` no parameters are defined, only two methods `periodic_inform` and `reset`. Note that for this object a set of actions are overridden:

- `read` uses function [stats_read](https://gitlab.com/prpl-foundation/components/ambiorix/examples/datamodel/greeter_plugin/-/blob/main/src/dm_greeter_actions.c#L175)
- `list` uses function [stats_list](https://gitlab.com/prpl-foundation/components/ambiorix/examples/datamodel/greeter_plugin/-/blob/main/src/dm_greeter_actions.c#L175)
- `describe` uses function [stats_describe](https://gitlab.com/prpl-foundation/components/ambiorix/examples/datamodel/greeter_plugin/-/blob/main/src/dm_greeter_actions.c#L175)

When overriding these action implementations with your own you get full control on the content of the object. As the object is `read-only` the `write` action is not overridden.

Although no parameters are defined in the ODL file, the object has parameters. You can verify that by calling the `get` method on the `Greeter.Statistics` object

```bash
$ ubus call Greeter.Statistics get
{
        "EventCount": 6,
        "DelHistoryCount": 0,
        "AddHistoryCount": 1
}
```

##### Object Methods

In the file `greeter_definition.odl` there are many `object methods` defined. Let's have look at some of these definitions.

```odl
string say(%in %mandatory string from,
           %in %mandatory string message,
           %in bool retain = false);
```

The say method returns a string, in this example it will return the value of the `message` argument. It has 3 input arguments (which are indicated with the argument attribute `%in`) of which two are mandatory and the last one (`retain`) is optional. For optional arguments it is possible to provide a default value.

```odl
%template uint32 clear(%in bool force = false);
```

This method, when called, will remove instances from the `History` multi-instance object. This method can only be called on the multi-instance object itself and not on the instances, this is indicated with the `%template` attribute. By default it will only delete the instances of which the `Retain` parameter is set to `false` unless the force argument is set to `true` when calling the method.

##### Data model parameters

Although it is possible to define objects without parameters, in most cases you will need to define some parameters in each object.

Parameters can only be defined in an object. Each parameter must be defined with a type and can contain a value.

The simplest form of defining a parameter is as the `Retain` parameter of object `History`

```odl
%persistent bool Retain = false;
```

Often you need to add parameter value validation as not any value is valid for the parameter. The ODL parser already provides you with a set of parameter validate functions:

- `check_enum`
- `check_maximum`
- `check_maximum_length`
- `check_minimum`
- `check_minimum_length`
- `check_range`

These are called validate actions. Multiple validate actions can be added to a single parameter, and it is even possible to provide your own validation action function as well.

In our example the state parameter has two validation actions:

```odl
string State {
    default "Idle";
    on action validate call check_enum ["Idle", "Start", "Running", "Stop"];
    on action validate call check_change;
}
```

Changing a value of a parameter will fail, if at least one validation action fails.

It is possible to provide an implemention for other parameter actions as well, in this example only validate actions are added to parameters. Possible other parametere actions are:

- read
- write
- describe
- destroy

Check the example [parameter_actions](https://gitlab.com/prpl-foundation/components/ambiorix/examples/datamodel/parameter_actions) for an example that overrides these actions.

The `Ambiorix Data Model` library provides default implementations for all these parameter actions, in most cases the default implementation is sufficient.

##### Event Subscriptions

It is possible to register callback functions on `events` that `happen` in your data model, these functions are called `event handlers`. There are a set of `default` events defined by the `Ambiorix data model` library. These events are:

- `dm:root-added`
- `dm:root-removed`
- `dm:object-added`
- `dm:object-removed`
- `dm:instance-added`
- `dm:instance-removed`
- `dm:object-changed`
- `dm:periodic-inform`
- `app:start`
- `app:stop`

Most of these events, when sent, contain extra information or data. It is possible to filter on this data, so that the event handlers are only called when really needed.

In the `greeter_definition.odl` file 3 event handlers are registered in a `%populate` section. The first two are very similar:

```odl
on event "dm:object-changed" call enable_greeter
        filter 'object == "Greeter" &&
                parameters.State.from == "Idle" &&
                parameters.State.to == "Start"';

on event "dm:object-changed" call disable_greeter
        filter 'object == "Greeter" &&
                parameters.State.from == "Running" &&
                parameters.State.to == "Stop"';
```

Both register a event handler on the event `dm:object-changed` but the filter expressions are different.

The first event handler `enable_greeter` is only called when the event is sent by the object `Greeter` and the value of parameter `State` of that object changes from `Idle` to `Start`.

The second event handler `disable_greeter` is only called when the event is sent by the object `Greeter` and the value of parameter `State` of that object changes from `Running` to `Stop`.

The last registered event handler could be very handy during development and debugging:

```odl
on event "*" call print_event;
```

This registers the event handler `print_event` on all events.

> NOTE  
> The `Ambiorix Runtime` (amxrt) will disable the eventing mechanism during the initial loading and building of the data model. No event handler will be called during that time. The eventing mechanism is enabled right before the entrypoints are called.

#### greeter_defaults.odl

The purpose of the `greeter_defaults.odl` is to provide default instances for multi-instance objects and default values for the parameters.

For this example, an instance is created for the `History` object and the parameter values of this instance are set.

```odl
object Greeter.History {
    instance add (0,"") {
        !read-only parameter From = "odl parser";
        !read-only parameter Message = "Welcome to the Greeter App";
        parameter Retain = true;
    }
}
```

As the types of the parameters are defined in the `%define` section you do not need to repeat that in the `%populate` section.

Also note the `read-only` attribute for the parameters `From` and `Message` are removed. It is possible to change the values of these two parameters.

As the `main` ODL file includes this file in a conditional include, it is possible that it is not loaded anymore when the application is restarted.

### Implementation

To make the data model `work`, the `object` methods need an implementation as well as the `action` methods, the `entry points` and the `event handlers`.

In this example all these functions are implemented in a `shared object` data model plugin.

The data model `object methods` are implemented in [src/dm_greeter_methods.c](https://gitlab.com/prpl-foundation/components/ambiorix/examples/datamodel/greeter_plugin/-/blob/main/src/dm_greeter_methods.c)

#### Data model object methods

To make it possible to `bind` the data model object method definition with the `real` implementation in the `shared object` there are different possibilities:

---
___Possibility 1 - Automatic symbol resolving___

  The `import` resolver - the one that searches for symbols in a shared object - will try a few possibilities
  - the name of the function prefixed with the name of the object
  - the name of the function.

Example:

In the file [greeter_definition.odl](https://gitlab.com/prpl-foundation/components/ambiorix/examples/datamodel/greeter_plugin/-/blob/main/odl/greeter_definition.odl) you can find the following `object method` definition:

```odl
%define {
    object Greeter {
        ....

        uint32 say(%in %mandatory string from,
                   %in %mandatory string message,
                   %in bool retain = false);

        ....
    }
}
```

The `import` resolver will search for one of these symbols in this order:

- `_Greeter_say`
- `_say`

in all loaded `shared object` plug-ins (in this example `greeter.so`). If multiple `shared objects` are loaded they will be searched in the order they were loaded.

If the symbol is found the function is considered `resolved`. When no symbol is found a warning is given, but parsing of the ODL file continues.

When in one of the config sections (before the method definition) the option `import-dbg` is set to true, extra information is printed to `stdout`. This information shows which symbol is resolved from which `shared object` for which `data model function`.

When starting the greeter application you should see:
```text
[IMPORT-DBG] - dlopen - greeter.so
[IMPORT-DBG] - symbol _State_check_change resolved (for check_change) from greeter
[IMPORT-DBG] - symbol _Greeter_say resolved (for say) from greeter
[IMPORT-DBG] - symbol _function_dump resolved (for echo) from greeter
[IMPORT-DBG] - symbol _Greeter_setMaxHistory resolved (for setMaxHistory) from greeter
[IMPORT-DBG] - symbol _Greeter_save resolved (for save) from greeter
[IMPORT-DBG] - symbol _Greeter_load resolved (for load) from greeter
[IMPORT-DBG] - symbol _History_clear resolved (for clear) from greeter
[IMPORT-DBG] - symbol _periodic_inform resolved (for periodic_inform) from greeter
[IMPORT-DBG] - symbol _Statistics_reset resolved (for reset) from greeter
[IMPORT-DBG] - symbol _stats_read resolved (for stats_read) from greeter
[IMPORT-DBG] - symbol _stats_list resolved (for stats_list) from greeter
[IMPORT-DBG] - symbol _stats_describe resolved (for stats_describe) from greeter
[IMPORT-DBG] - symbol _greeter_main resolved (for greeter_main) from greeter
[IMPORT-DBG] - symbol _enable_greeter resolved (for enable_greeter) from greeter
[IMPORT-DBG] - symbol _disable_greeter resolved (for disable_greeter) from greeter
[IMPORT-DBG] - symbol _print_event resolved (for print_event) from greeter
```

You can find the implementation of the `say` method [here](https://gitlab.com/prpl-foundation/components/ambiorix/examples/datamodel/greeter_plugin/-/blob/main/src/dm_greeter_methods.c#L161)

---
---
__Possibility 2 - Using resolving instruction__

Behind any function in the data model definition it is possible to provide resolving instructions. These instructions can be used when the automatic function resolving can not resolve your function.

Resolving instructions always start with `<!` and ends with `!>`. They must at least contain the name of the resolver, and optionally can contain resolver data.

Example:

In the file [greeter_definition.odl](https://gitlab.com/prpl-foundation/components/ambiorix/examples/datamodel/greeter_plugin/-/blob/main/odl/greeter_definition.odl) you can find the following `object method` definition:

```odl
%define {
    object Greeter {
        ...

        variant echo(%in %mandatory variant data)<!import:${name}:_function_dump!>;

        ...
    }
}
```

This definition contains function resolving instructions, as the name of the defined `object` method does not match the name of the implementation (`echo` versus `_function_dump`) the automatic resolving mechanism will not work here.

This `data model method` will dump the input arguments of the function. The implementation can be found [here](https://gitlab.com/prpl-foundation/components/ambiorix/examples/datamodel/greeter_plugin/-/blob/main/src/dm_greeter_methods.c#L144)

---

#### Data model deferred object methods

Deferred object methods are methods that start an operation, give control back to the eventloop and send the result later. Typically this is used when the methods start an asynchronous I/O operation.

In the greeter example a deferred object method is added to demonstrate how such a deferred method can be implemented. In this example a timer is started in the method, the method gives back control to the eventloop and when the timer expires, the result is returned.

```C
amxd_status_t _deferred_echo(amxd_object_t* object,
                             amxd_function_t* func,
                             amxc_var_t* args,
                             UNUSED amxc_var_t* ret) {
    char* path = amxd_object_get_path(object, AMXD_OBJECT_NAMED);
    deferred_data_t* data = (deferred_data_t*) calloc(1, sizeof(deferred_data_t));
    uint32_t time = GET_UINT32(args, "time");

    printf("\n================================================================\n");
    printf("Function call: \n");
    printf("Object   - %s\n", path);
    printf("Function - %s\n", amxd_function_get_name(func));
    printf("Function returns in %d seconds\n", time);

    amxc_var_move(&data->data, args);
    amxd_function_defer(func, &data->call_id, ret, echo_deferred_cancel, data);

    printf("Call id = %" PRIu64 "\n", data->call_id);
    printf("================================================================\n\n");

    amxp_timer_new(&data->timer, echo_deferred_reply, data);
    amxp_timer_start(data->timer, time * 1000);

    free(path);
    return amxd_status_deferred;
}
```

A deferred method must return `amxd_status_deferred` and must create a deferred function context. The context is created using method `amxd_function_defer`. Optionally a cancel callback function can be provided and some private data.

When creating a deferred context, a call identifier is generated. This identifier must be used to all calls related to managing the deferred function context. It is possible to remove or complete the deferred function.

To remove a deferred function context call `amxd_function_deferred_remove`.

To complete a deferred function and send the result back to the caller call `amxd_function_deferred_done`.

In this example the function `echo_deferred_reply` is called when the timer expires.

```C
static void echo_deferred_reply(UNUSED amxp_timer_t* timer, void* priv) {
    deferred_data_t* data = (deferred_data_t*) priv;

    printf("Call id = %" PRIu64 " is done\n", data->call_id);
    amxd_function_deferred_done(data->call_id, amxd_status_ok, NULL, &data->data);
    amxc_var_clean(&data->data);
    amxp_timer_delete(&data->timer);
    free(data);
}
```

Here the deferred method is completed by calling `amxd_function_deferred_done`, the real `status` and `return value` are provided. Optionally out arguments can be given as well.

The cancel handler, passed when creating the deferred method context, will stop the timer and does some clean-up.

```C
static void echo_deferred_cancel(UNUSED uint64_t call_id, void* priv) {
    deferred_data_t* data = (deferred_data_t*) priv;
    printf("Call id = %" PRIu64 " is canceled\n", data->call_id);
    amxc_var_clean(&data->data);
    amxp_timer_delete(&data->timer);
    free(data);
}
```

##### `Greeter.History.clear` Implementation

The `Greeter.History.clear` object method removes instances from the multi-instance object `History`.

This method takes one argument of type `boolean`, when set to true it also deletes the instances that are `Retained`

Let's have a look at the implementation:

The C implementation of this method looks like this:

```C
amxd_status_t _History_clear(amxd_object_t *history,
                             amxd_function_t *func,
                             amxc_var_t *args,
                             amxc_var_t *ret)
```

Where the `history` pointer will point to the object the function is called on, in this case it will be the `Greeter.History` object.

The `func` pointer will point to the function definition (in most cases you can just ignore this pointer as you will not need it, as in this example).

The `args` pointer, points to a `amxc_var_t` that will contain a `htable` of all arguments. Note that you will not need to check if mandatory arguments are provided or not. If in the ODL definition an argument has the attribute `%mandatory` the `Ambiorix Data Model` library will not call your implementation if the argument is not provided.

The last argument of this function is `ret`, which is a pointer to a `amxc_var_t`and is initialized to the variant type `NULL`. The `return value` of the called method must be put in this variant.

Fetching the argument values is done using

```C
bool force = amxc_var_dyncast(bool, GET_ARG(args, "force"));
```

It is possible that more than one instance will be deleted.  If one of the instance deletions fail, it should restore all of them. So basically the `Greeter.History.clear` should behave itself in an `atomic` way, either all deletions are done, or no deletion is done at all. This can be achieved by a `Data Model Transaction`.

```C
amxd_trans_t transaction;
amxd_trans_init(&transaction);

amxd_trans_set_attr(&transaction, amxd_tattr_change_ro, true);
amxd_trans_select_object(&transaction, history);
amxd_object_for_each(instance, it, history) {
    amxd_object_t *inst = amxc_llist_it_get_data(it, amxd_object_t, it);
    bool retain = amxd_object_get_value(bool, inst, "Retain", NULL);
    if(!retain || force) {
        amxd_trans_del_inst(&transaction, amxd_object_get_index(inst), NULL);
        count++;
    }
}

if (amxd_trans_apply(&transaction, dm) != amxd_status_ok) {
    count = 0;
} else {
    stats->del_history += count;
}
amxd_trans_clean(&transaction);
```

The above code builds up a transaction and executes the transaction:

- by selecting the object, in this case `Greeter.History` using `amxd_trans_select_object`
- add for each instance that must be deleted a `delete instance action` using `amxd_trans_del_inst`
- executes the transaction using `amxd_trans_apply`

Note the call to `amxd_trans_set_attr`, as the `Greeter.History` is a `read-only` multi-instance object, you can not delete or add any instances, except when explicitly specifying that it is the intention. External sources that are interacting with your data model can never change `read-only` parameters or objects.

Note that adding actions to the transaction is not changing the data model at all, the changes are applied when calling `amxd_trans_apply`. If `amxd_trans_apply` fails, none of the deletions are done, and the state of the data model is exactly as it was.

When all done, the only thing still needed is to provide the `return value` and give back a status.

```C
amxc_var_set(uint32_t, ret, count);
return amxd_status_ok;
```

When returning any other status code than `amxd_status_ok` the function call will be considered as failed.
The caller will get an appropriate error code. The error code the caller gets, depends on the bus system that is being used, but you should not care about that here.

##### `Greeter.load` Implementation

With the `Greeter.load` method you can load previously saved ODL files (or the `greeter_defaults.odl`), and in this example only the `History` object has persistent data.

Before `restoring` a saved ODL file, the `Greeter.History` object must be cleared, that is all instances must be removed, this to avoid duplication errors during loading.

As the `Greeter.History` has a `clear` object method, we can call this method:

```C
amxd_object_t *history = amxd_object_findf(greeter, "History");
amxc_var_t clear_args;

amxc_var_init(&clear_args);
amxc_var_set_type(&clear_args, AMXC_VAR_ID_HTABLE);
amxc_var_add_key(bool, &clear_args, "force", true);
amxd_object_invoke_function(history, "clear", &clear_args, ret);
amxc_var_clean(&clear_args);
```

For the purpose of the example, there is no error checking implemented here. 

Basically to call methods in your data model, you will need to

1. fetch the object pointer of the object containing the method
1. build a variant containing a `htable` where all `mandatory` arguments are added
1. call the method using `amxd_object_invoke`
1. clean things up.

When done removing the current instances, it is possible to load the file:

```C
retval = amxo_parser_parse_file(parser, file, amxd_dm_get_root(dm));
amxc_var_set(bool, ret, retval == 0);
```

#### Data model actions

With actions you can change the default behavior of the data model. Any action can be overridden. Be aware that when you override an action, the default implementation (provided by the Ambiorix data model library) will not be called anymore.

In this example a validate action is implemented for parameter `Greeter.State` and some object actions are implemented for object `Greeter.Statistics`

##### `Greeter.State` parameter validation

The `validate` action will be one of the most common action overrides you will implement. On parameters  such an implementation should only check that the `new` value is valid, and should not change the value of the parameter itself or any other parameter. On objects it should verify that the object itself is valid (combination of parameter values, or any other check), and should never change any parameter value of the object or any other object.

Let's have a look at the `check_change` validation action implentation:

```C
amxd_status_t _State_check_change(UNUSED amxd_object_t *object,
                                  amxd_param_t *param,
                                  amxd_action_t reason,
                                  const amxc_var_t * const args,
                                  amxc_var_t * const retval,
                                  UNUSED void *priv)
```

Note the function name here is prefixed with the name of the parameter. This is because the validation action is only valid for the parameter and it is defined in the ODL definition under the parameter `State`.

```odl
string State {
    default "Idle";
    on action validate call check_enum ["Idle", "Start", "Running", "Stop"];
    on action validate call check_change;
}
```

The first part of the validation action implementation is doing some sanity checks, these checks are not strictly necessary but is recommended practice.

```C
if(param == NULL) {
    goto exit;
}
if(reason != action_param_validate) {
    status = amxd_status_function_not_implemented;
    goto exit;
}
if(amxc_var_is_null(args)) {
    status = amxd_status_invalid_value;
    goto exit;
}
```

As this validation action is intended to work on the `Greeter.State` parameter, the parameter pointer must be given.

As this is a parameter validation action implementation the only accepted reason is `action_param_validate`. Yes it is possible to implement in one single function multiple actions, but this is not recommended practice. In most cases you need to check that the `reason` is one that the function can handle and if not return `amxd_status_function_not_implemented`, the default implementation will then take over. When returning another status code, the action is considered as failed.

As this is a parameter validation action, the new value is provided in the `args` variant. When it is a `NULL` variant the value is considered invalid and the appropriate status code is returned.

The last part of the implementation is validating the new `value`. It is not needed to check that the value provided is one of "Idle", "Start", "Running", "Stop". This is handled by another validation action implementation `check_enum`. As it is defined before this validation action in the data model, the only possible values you will get in here is one these.

The only state changes allowed are:

1. No state change at all (the new value is the same as the current value)
1. "Idle" to "Start"
1. "Running" to "Stop"

```C
if(strcmp(current_value, new_value) == 0) {  // no state chage
    status = amxd_status_ok;
    goto exit;
}
if((strcmp(current_value, "Idle") == 0) && (strcmp(new_value, "Start") != 0)) {
    status = amxd_status_invalid_value;
    goto exit;
}
if((strcmp(current_value, "Running") == 0) && (strcmp(new_value, "Stop") != 0)) {
    status = amxd_status_invalid_value;
    goto exit;
}
```

See the [Event Handlers](#event-handlers) section to find out how the `State` parameter can be changed to "Running" or "Idle".

##### Greeter.Statistics object actions

The `Greeter.Statistics` object has no parameters defined in the `greeter_definition.odl`, however it exposes three parameters:

```bash
ubus call Greeter.Statistics list '{"parameters":true, "objects":false, "functions":false}'
{
        "parameters": [
                "AddHistoryCount",
                "DelHistoryCount",
                "EventCount"
        ]
}
```

The `greeter` application has internally a C structure defined containing some statistics counters:

```C
typedef struct _greeter_stats {
    uint32_t events;
    uint32_t del_history;
    uint32_t add_history;
} greeter_stats_t;
```

Using the actions defined on the `Greeter.Statistics` object these counters can be exposed as parameters in the data model.

The actions overridden on the `Greeter.Statistics` object are:

- `read` action - is called to read the parameter values
- `list` action - is called to get the list of available `functions`, `parameters` and `child` objects, this action is mainly used for introspection.
- `describe` action - is called to get detailed information about the `object`, it's `functions` and `parameters`

Let's have a look at the `read` action implementation:

```C
amxd_status_t _stats_read(amxd_object_t *object,
                          amxd_param_t *param,
                          amxd_action_t reason,
                          const amxc_var_t * const args,
                          amxc_var_t * const retval,
                          void *priv) {
    amxd_status_t status = amxd_action_object_read(object,
                                                   param,
                                                   reason,
                                                   args,
                                                   retval,
                                                   priv);
    amxc_var_t *req_params = NULL;
    const amxc_llist_t *lreq_params = NULL;
    greeter_stats_t *stats = greeter_get_stats();

    if((status != amxd_status_ok) &&
       ( status != amxd_status_parameter_not_found)) {
        goto exit;
    }

    req_params = amxc_var_get_key(args, "parameters", AMXC_VAR_FLAG_DEFAULT);
    lreq_params = amxc_var_constcast(amxc_llist_t, req_params);

    if(req_params == NULL) {
        amxc_var_add_key(uint32_t, retval, "AddHistoryCount", stats->add_history);
        amxc_var_add_key(uint32_t, retval, "DelHistoryCount", stats->del_history);
        amxc_var_add_key(uint32_t, retval, "EventCount", stats->events);
    } else {
        status = get_value_statistics(lreq_params, retval, stats);
    }

exit:
    return status;
}
```

The first it does is calling the default `read` action implementation as provided by the Ambiorix Data Model (amxd) library. This will construct a correct return value variant (`retval`). This variant will be of the type `htable`. This `htable` will contain another `htable` with all the parameters as defined in the ODL file, in our case it will be empty as no parameters were defined. 

The invoker of the `read` action can provide a list of parameter names in the `args` argument, to indicate which parameter values it wants to read or the `args` can be `NULL` to get all parameter values.

When `args` is `NULL` we just add all `counters` to the `retval`, if not `NULL` we only add the `requested` parameters.

Using the `ubus` command you can check that the `read` action is behaving as expected.

All parameters

```bash
$ ubus call Greeter.Statistics get
{
        "EventCount": 18,
        "DelHistoryCount": 4,
        "AddHistoryCount": 3
}
```

Or only one parameter

```bash
$ ubus call Greeter.Statistics get '{"parameters":["EventCount"]}'
{
        "EventCount": 18
}
```

The counters in the internal data structure are increased at multiple places in the code, in normal circumstances an event should be emitted when these values changes. That is not done in this case. As these parameters are mainly for statistics and can change often they can be declared `volatile`. As these parameters are not defined in the ODL definition, we need to implement the `describe` action as well.

In the describe action you need to provide the correct attributes of the parameters, the type name and type id.

In this example we want that the statistics counters are

- `volatile`
- `read-only`

A small helper function is added to the code that provides all this information in the correct structure

```C
static void describe_statistic(amxc_var_t *ht_params,
                               const char *name,
                               uint32_t value) {
    amxc_var_t *stat_param = amxc_var_add_key(amxc_htable_t,
                                              ht_params,
                                              name,
                                              NULL);
    amxc_var_t *stat_attrs = amxc_var_add_key(amxc_htable_t,
                                              stat_param,
                                              "attributes",
                                              NULL);

    amxc_var_add_key(bool, stat_attrs, "instance", false);
    amxc_var_add_key(bool, stat_attrs, "read-only", true);
    amxc_var_add_key(bool, stat_attrs, "volatile", true);
    amxc_var_add_key(bool, stat_attrs, "counter", false);
    amxc_var_add_key(bool, stat_attrs, "private", false);
    amxc_var_add_key(bool, stat_attrs, "template", false);
    amxc_var_add_key(bool, stat_attrs, "key", false);
    amxc_var_add_key(bool, stat_attrs, "persistent", false);

    amxc_var_add_key(uint32_t, stat_param, "value", value);
    amxc_var_add_key(cstring_t, stat_param, "name", name);
    amxc_var_add_key(cstring_t,
                     stat_param,
                     "type_name",
                     amxc_var_get_type_name_from_id(AMXC_VAR_ID_UINT32));
    amxc_var_add_key(uint32_t, stat_param, "type_id", AMXC_VAR_ID_UINT32);
}
```

The `describe` action implementation then calls this helper function for all the parameters

```C
amxd_status_t _stats_describe(amxd_object_t *object,
                              amxd_param_t *param,
                              amxd_action_t reason,
                              const amxc_var_t * const args,
                              amxc_var_t * const retval,
                              void *priv) {
    amxd_status_t status = amxd_action_object_describe(object,
                                                       param,
                                                       reason,
                                                       args,
                                                       retval,
                                                       priv);
    greeter_stats_t *stats = greeter_get_stats();
    amxc_var_t *params = NULL;
    if(status != amxd_status_ok) {
        goto exit;
    }
    params = amxc_var_get_path(retval, "parameters", AMXC_VAR_FLAG_DEFAULT);
    describe_statistic(params, "AddHistoryCount", stats->add_history);
    describe_statistic(params, "DelHistoryCount", stats->del_history);
    describe_statistic(params, "EventCount", stats->events);


exit:
    return status;
}
```

Also note that it calls the `default describe` action.

It is easy to verify that your implementation of the `describe` action is working:

```bash
$ ubus call Greeter.Statistics describe '{"parameters":true}'
{
        "attributes": {
                "private": false,
                "read-only": true,
                "locked": false,
                "persistent": false
        },
        "name": "Statistics",
        "parameters": {
                "EventCount": {
                        "attributes": {
                                "instance": false,
                                "read-only": true,
                                "volatile": true,
                                "counter": false,
                                "private": false,
                                "template": false,
                                "persistent": false,
                                "key": false
                        },
                        "value": 18,
                        "name": "EventCount",
                        "type_id": 8,
                        "type_name": "uint32_t"
                },
                "DelHistoryCount": {
                        "attributes": {
                                "instance": false,
                                "read-only": true,
                                "volatile": true,
                                "counter": false,
                                "private": false,
                                "template": false,
                                "persistent": false,
                                "key": false
                        },
                        "value": 4,
                        "name": "DelHistoryCount",
                        "type_id": 8,
                        "type_name": "uint32_t"
                },
                "AddHistoryCount": {
                        "attributes": {
                                "instance": false,
                                "read-only": true,
                                "volatile": true,
                                "counter": false,
                                "private": false,
                                "template": false,
                                "persistent": false,
                                "key": false
                        },
                        "value": 3,
                        "name": "AddHistoryCount",
                        "type_id": 8,
                        "type_name": "uint32_t"
                }
        },
        "type_name": "singleton",
        "type_id": 1
}
```

#### Event Handlers

Event handlers are an easy and convenient way to react on changes in your data model, these changes can be done **internally** by your application itself or **externally** by other applications that interact with your data model.

In this example the `Greeter` object has the parameter `State`. The `say` method of this object will only work when the `State` parameter is set to `Running`.

External users of your data model can change the parameter's value. Two of the event handlers registered in the `greeter_definitions.odl` file will react on these changes:

```odl
    on event "dm:object-changed" call enable_greeter
        filter 'object == "Greeter" &&
                parameters.State.from == "Idle" &&
                parameters.State.to == "Start"';

    on event "dm:object-changed" call disable_greeter
        filter 'object == "Greeter" &&
                parameters.State.from == "Running" &&
                parameters.State.to == "Stop"';
```

Let's have a look at the implementation of `enable_greeter`.

First of all, as there is a filter defined in the ODL file, the function is only called when the parameter `State` value changes from "Idle" to "Start".

```C
void _enable_greeter(UNUSED const char * const sig_name,
                     const amxc_var_t * const data,
                     UNUSED void * const priv) {
    amxd_object_t *object = amxd_dm_signal_get_object(greeter_get_dm(), data);
    amxd_param_t *state_param = amxd_object_get_param_def(object, "State");

    amxc_var_set(cstring_t, &state_param->value, "Running");
    emit_state_event(object, "Start");
}
```

The only thing done in this event handler is set the value to "Running". Note the value of the parameter is changed immediately. If transactions were used or one of the `object_set_value` functions, the validation actions of the parameter would be invoked and fail, because it is not allowed to change the value from "Start" to "Running". As this applications owns the data model it can *bypass* these extra checks and modify the value directly, the disadvantage of doing this is that no `change` event is sent, but that can easily be solved by sending the event yourself.

Each data model event will contain information about the object that has sent the event. Using function `amxd_dm_signal_get_object` it is easy to retrieve the object pointer.
