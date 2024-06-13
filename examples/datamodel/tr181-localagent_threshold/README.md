# Data Model Example - LocalAgent.Threshold

1. [Introduction](#introduction)
2. [Building `LocalAgent.Threshold` plugin](#building-localagent.threshold-plugin)  
2.1. [Build Prerequisites](#build-prerequisites)  
2.2. [Building](#building)  
3. [Running `LocalAgent.Threshold` plugin](#running-local.agent-plugin)  
3.1. [Run Prerequisites](#run-prerequisites)  
3.2. [Running](#running)
4. [Directories and files](#directories-and-files)  
5. [Diving into the code](#Diving-into-the-code)  
5.1. [ODL Files](#odl-files)  
5.1.1. [la_threshold.odl](#la_threshold.odl)  
5.1.2. [la_threshold_definition.odl](#la_threshold_definition.odl)  
5.1.2.1 [Objects](#objects)  
5.1.2.2 [Events](#events)  
5.1.2.3 [Custom actions](#custom-actions)  
5.1.2.4 [Event handlers](#event-handlers)  
5.1.3. [la_threshold_defaults.odl](#la_threshold_defaults.odl)  
5.2. [Implementation](#implementation) 
6. [Limitations and considerations](#limitations-and-considerations)

## Introduction

This example is an implementation of [USP Device:2.13 LocalAgent.Threshold](https://usp-data-models.broadband-forum.org/tr-181-2-13-0-usp.html#D.Device:2.Device.LocalAgent.Threshold.{i}.).

Using the `Ambiorix` framework it is possible to create and implement Broadband Forum data models (or parts of it) as described [TR-181](https://usp-data-models.broadband-forum.org/tr-181-2-13-0-usp.html). The `LocalAgent.Threshold` multi-instance object can be used to `Trigger` an event when a certain condition becomes true.

As describes in the specifications, it can `monitor` multiple objects at once using the search path notations. Using the `Ambiorix` framework `expression` and `search path` features it is not very complicated to implement the `LocalAgent.Threshold` 

The features shown in this example are:

- [Object Definition Language](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxo/-/blob/main/doc/odl.md) (libamxo)

  - Data model definition
  - Event subscription (internal)
  - Function binding

- Data model management (libamxd)

  - Search Paths - [TR-369](https://www.broadband-forum.org/download/TR-369.pdf) - Sections 4.2.2 and 4.2.3
  - Validation actions (object validation and parameter validation)
  - Event handlers (internal and external events)

- Expressions (libamxp)

  - Event filtering (external and internal)

## Building `LocalAgent.Threshold` plugin

### Build Prerequisites

To be able to build this example you will need to install:

- `libamxc`  (Data collections and data containers)
- `libamxd`  (Data Model Management API)
- `libamxo`  (ODL Parsing and saving)
- `libamxp`  (Common Functional Patterns)

### Building

Change your working directory to the root of this example and use `make`.

```Bash
cd <LocalAgentThresholdRoot>/
make
```

After the `make` has finished, you can install it by calling `make install`.
As this is example code, the `make install` will install in your build output directory and not in your system directories.
You can provide the `DEST` variable to change the root directory to where the example must be installed.

Examples:

Install in your system root
```bash
$ sudo make install
/usr/bin/install -d /usr/bin/la_threshold
/usr/bin/install -m 0755 ./output/x86_64-linux-gnu/object/la_threshold.so /usr/bin/la_threshold/la_threshold.so
/usr/bin/install -m 0644 ./odl/la_threshold_definition.odl /usr/bin/la_threshold/
/usr/bin/install -m 0644 ./odl/la_threshold_defaults.odl /usr/bin/la_threshold/
/usr/bin/install -m 0755 ./odl/la_threshold.odl /usr/bin/ 
```

## Running `LocalAgent.Threshold` plugin

### Run Prerequisites

To be able to run this example you will need to:

- Build and install the example
- Install `amxrt` (`Ambiorix Run Time`)
- Install an `Ambiorix` bus back-end

A software bus must be running and the correct back-end must be installed.

In this explanation it is assumed that you have `ubus` running and the `ubus` tool is installed (so the `amxb-ubus.so` back-end should be available as well).

### Running

Once it is built and everything is installed you can launch the example.

It is recommended to run this example in foreground in a separate console, as it prints information to the standard output.

```bash
amxrt <your install dir>/etc/amx/la_threshold/la_threshold.odl -o name=la_trheshold
```

---
> **NOTE** <br>
> The name is here provided as a command line option. The name can be added to the configuration section of the main odl (la_threshold.odl) file as well.
> ```
> %config {
>    // amxo parser config-options
>    import-dbg = true;
>
>    // the name
>    name = "la_threshold";
>
>    // Application specific settings
>    // persistent storage location
>    rw_data_path = "${prefix}/etc/config";
>
>    // main files
>    definition_file = "${name}_definition.odl";
>    save_file = "${rw_data_path}/${name}/${name}.odl";
>    defaults_file = "${name}_defaults.odl";
> }
> ``` 
>
> As an alternative a symbolic link can be created to amxrt. The name of the symbolic link will be used as the name configuration option
>
> ```
> $ ls -la /usr/bin/la_threshold
> lrwxrwxrwx 1 root root 5 Aug 24 11:02 /usr/bin/la_threshold -> amxrt
> ```
---

At start-up you will see some output on your console and if everything goes well, you should be greeted by the following text:

```text
**************************************
*    LocalAgent.Threshold started    *
**************************************
```

---
> **Note**<br>
> Before this message you will see some `[IMPORT-DBG]` messages as well, these are printed to the console because of one of the configuration options in the file `la_threshold.odl`. The configuration option responsible for this is `import-dbg = true;`. This option should be turned off for production code, but can give useful feedback during development and debugging. If all goes well, all methods and functions defined in the `ODL` files should be `resolved`.
>
> When adding the command line option `-d`, the final configuration options are printed as well.
>
> ```
> $ amxrt /etc/amx/la_threshold/la_threshold.odl -o name=la_threshold -d
> [IMPORT-DBG] - dlopen - la_threshold.so (0x56480018b390)
> [IMPORT-DBG] - symbol _threshold_instance_is_valid resolved (for threshold_instance_is_valid) from la_threshold
> [IMPORT-DBG] - symbol _threshold_instance_cleanup resolved (for threshold_instance_cleanup) from la_threshold
> [IMPORT-DBG] - symbol _threshold_changed resolved (for threshold_changed) from la_threshold
> [IMPORT-DBG] - symbol _threshold_added resolved (for threshold_added) from la_threshold
> [IMPORT-DBG] - symbol _print_event resolved (for print_event) from la_threshold
> [IMPORT-DBG] - symbol _threshold_main resolved (for threshold_main) from la_threshold
> [IMPORT-DBG] - symbols used of la_threshold = 6
> **************************************
> *    LocalAgent.Threshold started    *
> **************************************
> event received - app:start
> 
> Configuration:
> {
>     auto-connect = true,
>     auto-detect = true
>     auto-resolver-order = [
>         "ftab",
>         "import",
>         "*"
>     ],
>     backend-dir = "/usr/bin/mods/amxb",
>     backends = [
>         "/usr/bin/mods/amxb/mod-amxb-ubus.so"
>     ],
>     cfg-dir = "/etc/amx",
>     daemon = false,
>     defaults_file = "la_threshold_defaults.odl",
>     definition_file = "la_threshold_definition.odl",
>     dm-eventing-enabled = false,
>     dump-config = true,
>     import-dbg = true,
>     import-dirs = [
>         ".",
>         "${prefix}${plugin-dir}/${name}",
>         "${prefix}${plugin-dir}/modules",
>         "${prefix}/usr/local/lib/amx/${name}",
>         "${prefix}/usr/local/lib/amx/modules"
>     ],
>     import-pcb-compat = false,
>     include-dirs = [
>         ".",
>         "${prefix}${cfg-dir}/${name}",
>         "${prefix}${cfg-dir}/modules"
>     ],
>     listen = [
>     ],
>     log = false,
>     mib-dirs = [
>         "${prefix}${cfg-dir}/${name}/mibs"
>     ],
>     name = "la_threshold",
>     pid-file = true,
>     plugin-dir = "/usr/lib/amx",
>     prefix = "",
>     priority = 0,
>     requires = [
>     ],
>     rw_data_path = "/etc/config",
>     save_file = "/etc/config/la_threshold/la_threshold.odl",
>     storage-path = "${rw_data_path}/${name}/",
>     storage-type = "odl",
>     uris = [
>         "ubus:/var/run/ubus/ubus.sock"
>     ],
> }
> ```
---

The `LocalAgent.Threshold` is monitoring parameter values of `external` data models. Therefor another data model part must be started, this can be a `dummy` data model without any real functionality.

So let's create another data model part in a separate process.

Copy the following definition into a text file name "ethernet.odl"
```
%define {
    object Ethernet {
        bool WolSupported = false;

        object Interface[] {
            bool Enable = false;

            string Status {
                default "Down";
                on action validate call check_enum ["Up", "Down", "Unknown", "Dormant", "NotPresent", "LowerLayerDown", "Error"];
            }

            %unique %key string Alias {
                on action validate call check_maximum_length 64;
            }

            string Name {
                on action validate call check_maximum_length 64;
            }

            uint32 LastChange;

            csv_string LowerLayers {
                on action validate call check_maximum_length 1024;
            }

            bool Upstream;

            string MACAddress {
                on action validate call check_maximum_length 17;
            }

            int32 MaxBitRate {
                on action validate call check_minimum -1;
            }

            uint32 CurrentBitRate;

            string DuplexMode {
                default "Auto";
                on action validate call check_enum ["Half", "Full", "Auto"];
            }

            bool EEECapability = false;

            bool EEEEnable = false;

            object Stats {
                uint64 BytesSent;
                uint64 BytesReceived;
                uint64 PacketsSent;
                uint64 PacketsReceived;
                uint64 ErrorsSent;
                uint64 ErrorsReceived;
            }
        }
    }
}
```

Then start this data model using:

```bash
amxrt -D ./ethernet.odl
```

Verify that everything is running (LocalAgent.Threshold && Ethernet.Interface):

```bash
$ ubus list                                                               
Ethernet                                                                                     
Ethernet.Interface                                                                           
Ethernet.Interface.Stats                                                                     
LocalAgent                                                                                   
LocalAgent.Threshold 
```

Now that the data models are available, we need to create some instances:

Create two `Ethernet.Interface` instances

```bash
$ ubus call Ethernet.Interface add
{                                                                                            
        "index": 1,                                                                          
        "name": "cpe-Interface-1"                                                            
} 

$ ubus call Ethernet.Interface add

{
        "index": 2,
        "name": "cpe-Interface-2"
}
```

Create one `LocalAgent.Threshold` instance:

```bash
$ ubus call LocalAgent.Threshold add
{
        "index": 1,
        "name": "cpe-Threshold-1"
}
```

And configure the `LocalAgent.Threshold` instance:

```bash
$ ubus call LocalAgent.Threshold.cpe-Threshold-1 set '{"parameters":{"ThresholdValue":150,"ThresholdParam":"PacketsReceived","ReferencePath":"Ethernet.Interface.[Enable==1].Stats.","Enable":true}}'
{
        "retval": ""
}
```

Verify that the instance is correctly configured:

```bash
$ ubus call LocalAgent.Threshold.cpe-Threshold-1 get
{
        "LocalAgent.Threshold.1.": {
                "ReferencePath": "Ethernet.Interface.[Enable==true].Stats.",
                "OperatingMode": "Normal",
                "Enable": true,
                "ThresholdParam": "PacketsReceived",
                "ThresholdOperator": "Rise",
                "ThresholdValue": "150",
                "Alias": "cpe-Threshold-1"
        }
}
```

Would trigger a `LocalAgent.Threshold Triggered` event whenever a value of a parameter matching `Device.Ethernet.Interface.[Enable==1].Stats.PacketsRescieved` rises from below to above 150.

Almost there, open another console and subscribe for `LocalAgent.Threshold` events.

```bash
$ ubus subscribe LocalAgent.Threshold
```

Every event coming from `LocalAgent.Threshold` will be printed in this console, just keep the subscribe running. All we need to do now is enable a `Ethernet.Interface` and make change the parameter `.Stats.PacketsReceived` from below 150 to above 150.

Enable a `Ethernet.Interface`

```bash
$ ubus call Ethernet.Interface.cpe-Interface-1 set '{"parameters":{"Enable":true}}'
{
        "retval": ""
}
```

Set the value of `Ethernet.Interface.cpe-Interface-1.Stats.PacketsReceived` to 140:

```bash
$ ubus call Ethernet.Interface.cpe-Interface-1.Stats set '{"parameters":{"PacketsReceived":140}}'
{
        "retval": ""
}
```

Nothing should happen, and now change that same value to 160:

```bash
$ ubus call Ethernet.Interface.cpe-Interface-1.Stats set '{"parameters":{"PacketsReceived":160}}'
{
        "retval": ""
}
```

If all goes well you should see the `LocalAgent.Threshold Triggered` event being printed in the console where the `subscription` was taken:

```json
{ "Triggered": {"Trigger":{"ParamValue":160,"ParamPath":"Ethernet.Interface.1.Stats.PacketsReceived"},"object":"LocalAgent.Threshold.cpe-Threshold-1.","path":"LocalAgent.Threshold.1."} }
```
## Directories and files

- `odl` directory contains all object definition files
  - la_threshold.odl - the main odl file, this is the one passed to `amxrt`
  - la_threshold_definition.odl - contains the data model definition
  - la_threshold_defaults.odl - populates the data model with default `instances` and `values`
- `src` directory contains all the source code for building the local agent threshold `shared object` plugin
  - threshold_main.c - contains the entrypoint implementation and some helper functions
  - dm_threshold_actions.c - contains the implementation of all parameter and object custom action implementations
  - dm_threshold_events.c - contains the implementation of event handlers and the `Triggered` event generation
  - threshold_expr_builders.c - implementation of expression generators.

- makefile - builds and install the `local agent threshold` plugin
- makefile.inc - contains settings and configuration used during building and installing
- README.md - this file

## Diving into the code

### ODL Files

#### la_threshold.odl

This is the main ODL file:

- it contains `configuration` settings for the ODL parser, `amxrt` and your application.
- `imports` the implementation
- includes other ODL files
- defines an entry point


Note that on the first line of the `la_threshold.odl` there is a bash `shebang`, if you set the `executable` flag on the ODL file, you can just launch it.

```odl
#!/usr/bin/amxrt
```

#### la_threshold_definition.odl

The `la_threshold_definition.odl` defines the `LocalAgent.Threshold` data model in the `%define` section. The definition corresponds with [USP Device:2.13 LocalAgent.Threshold](https://usp-data-models.broadband-forum.org/tr-181-2-13-0-usp.html#D.Device:2.Device.LocalAgent.Threshold.{i}.).

In the `%populate` section it takes subscriptions on events, with filtering on the event data.

The ODL parser with some help of function resolvers will bind the definition to the real implementation.

More information about the ODL syntax for defining a data model can be found [here](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxo/-/blob/main/doc/odl.md)

##### Objects

Objects are related to each other in a `parent-child` relationship. In this example the hierarchy is as follows:

```text
LocalAgent
   |---Threshold
   |      |----instance 1
   |      |----instance 2
```

This hierarchy is described in the ODL file.

```odl
%define {
    object LocalAgent {
        object Threshold[] {
            ....
        }
    }
}
```

Also note the square brackets behind object `Threshold`, this indicates that the object is a multi-instance (aka template) object.

##### Events

##### Custom actions

In the definition ODL file two custom object actions are defined

Two for object `LocalAgent.Threshold`
```odl
on action validate call threshold_instance_is_valid;
on action destroy call threshold_instance_cleanup;
```

These two actions have an C implementation, you can find these implementations in the file `src/dm_threshold_actions.c`

##### Event handlers

In the `%populate` section three `event subscriptions` are put in place. Event subscriptions in ODL files always refer to the `local` data model, subscriptions to `external` data models can not be taken in an ODL file.

The event handler implementations have C implementation which can be found in the file `src/dm_threshold_definition.c`

#### la_threshold_defaults.odl

In this example the defaults only contains an empty  `%populate` section.

### Implementation

Most of the logic of the `LocalAgent.Threshold` is standard available in the `Ambiorix` framework. The features used in this example are `Ambiorix Expressions` and `Ambiorix data model eventing`.

The `Ambiorix` data model sends by default an event whenever a parameter has been changed (if there are subscriptions taken on the object containing the parameter).

These `object changed` default events contain some information that is very useful:

- The object that has been changed (full named object path, not USP compliant)
- The full indexed path of the object (as described in the USP specification)
- The parameters that have been changed, including a `from` and `to` value.

Example (in json format):

```text
{ 
    "dm:object-changed": {
        "object":"Ethernet.Interface.cpe-Interface-1.Stats.",
        "path":"Ethernet.Interface.1.Stats.",
        "parameters": {
            "PacketsReceived": {
                "from":140,
                "to":160
            }
        }
    }
}
```

This information is called the `event data`.

Let's assume we have created an instance of the `LocalAgent.Threshold` object and have set all the parameters to these values:

```bash
LocalAgent.Threshold.1.ReferencePath="Ethernet.Interface.[Enable==true].Stats."
LocalAgent.Threshold.1.OperatingMode="Normal"
LocalAgent.Threshold.1.Enable=true
LocalAgent.Threshold.1.ThresholdParam="PacketsReceived"
LocalAgent.Threshold.1.ThresholdOperator="Rise"
LocalAgent.Threshold.1.ThresholdValue="150"
```

These settings would trigger a `LocalAgent.Threshold Triggered` event whenever a value of a parameter matching `Device.Ethernet.Interface.[Enable==1].Stats.PacketsRescieved` rises from below to above 150.

This can be translated to an `Ambiorix expression` that can be applied on the event data.

```
{path} in search_path('Ethernet.Interface.[Enable==true].Stats.') &&
    {parameters.PacketsReceived.from} <= 150 &&
    {parameters.PacketsReceived.to} > 150

```

All strings between curly brackets are referring to the `event data`, the `Ambiorix expression` evaluator will replace these with the values from the received event.

Using our example changed event, this would resolve the expression into 

```
"Ethernet.Interface.1.Stats." in search_path('Ethernet.Interface.[Enable==true].Stats.') &&
    140 <= 150 &&
    160 > 150
```

So the `expression` will evaluate to `true` if "Ethernet.Interface.1.Stats." is in the results of the function call `search_path`. The function `search_path` returns an array of all object paths matching the given search paths. Let's assume there are 4 `Ethernet.Interface` instances available, of which two have the parameter `Enable` equal to 'true', `Ethernet.Interface.1.` and `Ethernet.Interface.3.`, then the function `search path would return an array containing:

```json
[
    "Ethernet.Interface.1.Stats.",
    "Ethernet.Interface.3.Stats."
]
```

Putting that in the expression would lead to:

```
"Ethernet.Interface.1.Stats." in ["Ethernet.Interface.1.Stats.","Ethernet.Interface.3.Stats."] &&
    140 <= 150 &&
    160 > 150
```

So the expression evaluates to `true` and the `Triggered` event can be sent.

Now let's have a look at the code. Following the description above an expression must be build. As there are different kinds of expressions, depending on the value of the `LocalAgent.Threshold.{i}.ThresholdOperator`, different functions are implemented to build these expressions. All these functions are implemented in `src/threshold_expr_builders.c`

The function responsible for building the `Rise` expression:

```C
static void threshold_rise_expression(amxc_string_t *expr_str,
                                      const char *ref_path,
                                      const char *ref_param,
                                      amxc_var_t *value) {
    const char *rise_expr[] = {
        "{path} in search_path('%s') && {parameters.%s.from} <= '%s' && {parameters.%s.to} > '%s'",
        "{path} in search_path('%s') && {parameters.%s.from} <= %s && {parameters.%s.to} > %s",
        "{path} == '%s' && {parameters.%s.from} <= '%s' && {parameters.%s.to} > '%s'",
        "{path} == '%s' && {parameters.%s.from} <= %s && {parameters.%s.to} > %s",
    };
    int32_t index = threshold_is_search_path(ref_path) ? 0 : 2;
    const char *str_value = amxc_var_constcast(cstring_t, value);
    if(threshold_value_is_number(value)) {
        index++;
    }

    amxc_string_appendf(expr_str, rise_expr[index], ref_path,
                        ref_param, str_value,
                        ref_param, str_value);
}
```

Depending on the type of the value (numeric or not), a slightly different expression is build.

Now there is still one question:

- Where is this generated expression used?

The answer is simple, when creating a subscription. The subscription is taken in function `threshold_subscribe` which can be found in `src/dm_threshold_events.c`.

The main parts in this function are:

```C
    expr = threshold_build_expression(ref_path, ref_param, operator, value);
    amxd_path_split(ref_path, &path_parts, amxd_build_search_path_parts);
    object_path = amxd_path_get_fixed(&path_parts, false);
```

This will call the `expression builder` and gets the `fixed` part from reference path.

A few lines later the subscription is taken:

```C
        retval = amxb_subscribe(bus_ctx,
                                object_path,
                                expr,
                                threshold_trigger,
                                object);
```

The `threshold_trigger` is the callback function that must be called whenever an event is received for which the expression is evaluated to true. 

The callback function will create a new event and send it.

```C
static void threshold_trigger(UNUSED const char * const sig_name,
                              const amxc_var_t * const data,
                              void * const priv) {
    amxd_object_t *threshold_obj = (amxd_object_t *) priv;
    amxc_var_t trigger_event_data;
    bool disable = false;

    amxc_var_init(&trigger_event_data);
    disable = threshold_build_trigger_event_data(&trigger_event_data,
                                                 threshold_obj,
                                                 data);
    amxd_object_send_signal(threshold_obj,
                            "Triggered",
                            &trigger_event_data,
                            true);

    if(disable) {
        amxd_trans_t trans;
        amxd_trans_init(&trans);
        amxd_trans_select_object(&trans, threshold_obj);
        amxd_trans_set_value(bool, &trans, "Enable", false);
        amxd_trans_apply(&trans, threshold_get_dm());
        amxd_trans_clean(&trans);
    }

    amxc_var_clean(&trigger_event_data);
}
```
This function just contains 2 simple steps:

1. Build the `Triggered` event data 
2. Send the `Triggered` event

The `Triggered` event data is build up as described in TR-181. The `Ambiorix` data model implementation will add two extra fields before `emitting` the event.

- object
- path

Example of the `Triggered` event

```json
{ 
    "Triggered": {
        "Trigger":{
            "ParamValue":160,
            "ParamPath":"Ethernet.Interface.1.Stats.PacketsReceived"
        },
        "object":"LocalAgent.Threshold.Test.",
        "path":"LocalAgent.Threshold.1."
    }
}
```

## Limitations and considerations

- As this is an example some error verifications are skipped, to keep the code clear. When using this example in production code extra error checking MUST be added.
- The `Cross` threshold operator is not implemented. 
- The values of parameters `LocalAgent.Threshold.{i}.ReferencePath` and `LocalAgent.Threshold.{i}.ThresholdParam` are not verified. A check could be added that the combination of the path and parameter name exists in the `external` data model. The TR-181 specifications does not state that they MUST refere to `existing` objects or parameters. The subscription will fail if the (fixed part of the) path is not existing.

