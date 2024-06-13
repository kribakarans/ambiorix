# Data Model Example - CPU Info Plugin

[[_TOC_]]

## Introduction

## Building `cpu_info` plugin

### Build Prerequisites

To be able to build this example you will need to install:

- `libamxc`  (Data collections and data containers)
- `libamxd`  (Data Model Management API)
- `libamxo`  (ODL Parsing and saving)
- `libamxp`  (Common Functional Patterns)

### Building

This example can be build in the `Ambiorix Debug And Development` container.

Change your working directory to the root of this example (that is the directory where you cloned the git repository in) and use `make`.

```Bash
cd <cpu-info>/
make
```

After the `make` has finished, you can install it by calling `sudo -E make install`.

Examples:

Install in your system root
```bash
$ sudo -E make install
make -C src all
make[1]: Entering directory '/home/sah4009/amx/ambiorix/examples/datamodel/cpu-info/src'
make[1]: Nothing to be done for 'all'.
make[1]: Leaving directory '/home/sah4009/amx/ambiorix/examples/datamodel/cpu-info/src'
/usr/bin/install -D -p -m 0644 odl/cpu_info_defaults.odl /etc/amx/cpu_info/cpu_info_defaults.odl
/usr/bin/install -D -p -m 0644 odl/cpu_info_definition.odl /etc/amx/cpu_info/cpu_info_definition.odl
/usr/bin/install -D -p -m 0644 odl/cpu_info.odl /etc/amx/cpu_info/cpu_info.odl
/usr/bin/install -D -p -m 0644 output/x86_64-linux-gnu/object/cpu_info.so /usr/lib/amx/cpu_info/cpu_info.so
/usr/bin/install -d -m 0755 /usr/bin
ln -sfr /usr/bin/amxrt /usr/bin/cpu_info
```

## Running `cpu_info` plugin

### Run Prerequisites

To be able to run this example you will need to:

- Build and install the example
- Install `amxrt` (`Ambiorix Runtime`)
- Install an `Ambiorix` bus back-end

A software bus must be running and the correct back-end must be installed.

In this explanation it is assumed that you have `ubusd` running and the `ubus` tool is installed (so the `amxb-ubus.so` should be available as well).

#### Configure The Container

1. Launch ubusd (in background) if it was not yet running - this should be done as `root` user
   ```bash
   $ ubusd &
   ```

### Running

Once it is built and everything is installed you can launch the example.

It is recommended to launch it as `root` user. When using the `Ambiorix` container open a termnal as root user:

```bash
docker exec -ti amxdev /bin/bash
```

Launch the `cpu-info` service

```bash
$ cpu_info
[IMPORT-DBG] - dlopen - cpu_info.so (0x559ffc48bee0)
[IMPORT-DBG] - symbol _cpu_monitor_cleanup resolved (for cpu_monitor_cleanup) from cpu_info
[IMPORT-DBG] - symbol _read_usage resolved (for read_usage) from cpu_info
[IMPORT-DBG] - symbol _cleanup_usage resolved (for cleanup_usage) from cpu_info
[IMPORT-DBG] - symbol _cpu_read resolved (for cpu_read) from cpu_info
[IMPORT-DBG] - symbol _cpu_list resolved (for cpu_list) from cpu_info
[IMPORT-DBG] - symbol _cpu_describe resolved (for cpu_describe) from cpu_info
[IMPORT-DBG] - symbol _cpu_cleanup resolved (for cpu_cleanup) from cpu_info
[IMPORT-DBG] - symbol _update_timer resolved (for update_timer) from cpu_info
[IMPORT-DBG] - symbol _enable_periodic_inform resolved (for enable_periodic_inform) from cpu_info
[IMPORT-DBG] - symbol _disable_periodic_inform resolved (for disable_periodic_inform) from cpu_info
[IMPORT-DBG] - symbol _cpu_main resolved (for cpu_main) from cpu_info
[IMPORT-DBG] - symbols used of cpu_info = 11
```

## Testing

### Run tests

Test can be run in the root directory:

```bash
make test
```

When all tests are ran and no test has failed a coverage report wil lbe printed:

```
------------------------------------------------------------------------------
                           GCC Code Coverage Report
Directory: ../../..
------------------------------------------------------------------------------
File                                       Lines    Exec  Cover   Missing
------------------------------------------------------------------------------
src/dm_usage_actions.c                        21      21   100%
src/dm_cpu_actions.c                          97      97   100%
src/dm_cpu_mon_actions.c                      11      11   100%
src/cpu_info.c                                66      66   100%
src/cpu_stats.c                               53      53   100%
src/dm_events.c                               44      44   100%
src/dm_cpu_mngt.c                             71      71   100%
src/cpu_main.c                                16      16   100%
------------------------------------------------------------------------------
TOTAL                                        379     379   100%
------------------------------------------------------------------------------
```

## `cpu-info` service

### Interact through data model using ubus

Before going into a detailed explanation of the example, try it out first.

1. Get the list of available CPUs
   ```bash
   $ ubus list CPUMonitor.*
   CPUMonitor.CPU
   CPUMonitor.CPU.1
   CPUMonitor.CPU.2
   CPUMonitor.CPU.3
   CPUMonitor.CPU.4
   ```

1. Get information of a specific CPU
   ```bash
   $ ubus call CPUMonitor.CPU.1 _get
   {
        "CPUMonitor.CPU.1.": {
                "Family": 6,
                "ID": 0,
                "MHz": "699.865",
                "Usage": 21,
                "ModelName": "Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz",
                "VendorId": "GenuineIntel",
                "Model": 142
        }
   }
   ```

### The data model

The purpose of this example is to show how you can provide data that is already available in the system through a `data model` without the need to copy or duplicate the data in the data model itself. In this example files from the `procfs` are used to fetch cpu information and statistics.

To keep the example simple and straight forward some parts of the logic are simplified, the cpu usage percentage is always calculated relative to the last time the information was retrieved.

#### `CPUMonitor` object

This is the root object of the cpu-info data model and contains three parameters:

- Usage - the global cpu usage percentage (calculated over all available cores)
- PeriodicInform - when set to true, the cpu-info service will send events at regular intervals, containing the cpu statistics.
- Interval - the interval (in seconds) use to send the cpu statistics. Only used when `PeriodicInform` is set to `true`.

#### `CPU` object

This is a multi-instance object and for each found `cpu core` an instance is created. The definition of this object doesn't contain any parameter definitions, instead a set of action callback functions are declared on the multi-instance object.

```
        %read-only object CPU[] {
            on action read call cpu_read;
            on action list call cpu_list;
            on action describe call cpu_describe;
            on action destroy call cpu_cleanup;
        }
```

- `cpu_read` - gets the values of all the parameters in the cpu instance object
- `cpu_list` - lists all parameters in the cpu instance object
- `cpu_describe` - describes the cpu instance object (introspection)
- `cpu_cleanup` - removes and cleans the private data attached to the cpu instance object.

### Implementation

#### Read and parse procfs files

The files `/proc/cpuinfo` and `/proc/stat` are read and parsed to fetch the information of the available cpu's and cores.

---
> **NOTE**<br>
> The content of the files can be different depending on the kernel version used or on which kernel options are enabled.
---

The implementation to parse `/proc/cpuinfo` can be found in `cpu_info.c`.  The file `/proc/cpuinfo` contains information of each available processor and typically is formatted with key-value pairs, separated with a `:`. An empty line is separating the different processors.

Example:

```text
processor       : 7
vendor_id       : GenuineIntel
cpu family      : 15
model           : 6
model name      : Common KVM processor
stepping        : 1
microcode       : 0x1
cpu MHz         : 2199.998
cache size      : 16384 KB
physical id     : 1
siblings        : 4
core id         : 3
cpu cores       : 4
apicid          : 7
initial apicid  : 7
fpu             : yes
fpu_exception   : yes
cpuid level     : 13
wp              : yes
...
```

This file is read line by line in function `cpu_info_read_lines` and each line is split into two parts using the separator `:` in function `cpu_info_add_line`. Each time an empty line is encountered, the cpu index is increased.

Each line is considered as an information field, only the fields which are configured in the config section of the main odl file are kept.

```odl
%config {
   
   ...

   cpu_field_names = {
        vendor_id = "VendorId",
        cpu_family = "Family",
        cpu_MHz = "MHz",
        model_name = "ModelName",
        model = "Model",
        processor = "ID"
   };

   ...

}
```

In the config section `cpu_field_names` the left side (key) is the name of the field as it is in the file `/proc/cpuinfo`, the right side (values) are the names of the parameters for the data model (`CPU` instance objects).

#### Data Model Read Action

Whenever a client (external or internal) reads the `CPU` instance objects (get operator), the method `_cpu_read` is called. This method will fetch the parameter values from the file `/proc/cpuinfo` using the implementation in `cpu_info.c` and fills a htable variant containing the data model parameters. 

```C
amxd_status_t _cpu_read(amxd_object_t* object,
                        amxd_param_t* param,
                        amxd_action_t reason,
                        const amxc_var_t* const args,
                        amxc_var_t* const retval,
                        void* priv) {
    amxc_var_t temp;
    uint64_t percentage = 0;
    amxd_status_t status = amxd_action_object_read(object, param, reason, args, retval, priv);
    amxc_string_t filter;

    amxc_var_init(&temp);
    amxc_string_init(&filter, 0);

    when_true(status != amxd_status_ok && status != amxd_status_parameter_not_found, exit);
    when_true(amxd_object_get_type(object) != amxd_object_instance, exit);

    status = amxd_action_object_read_filter(&filter, args);

    cpu_info_read(&temp, amxd_object_get_index(object));
    percentage = cpu_dm_get_stats(object, NULL);
    amxc_var_add_key(uint64_t, &temp, "Usage", percentage);

    dm_filter_params(retval, &temp, amxc_string_get(&filter, 0));

    if(amxc_var_is_null(retval)) {
        status = amxd_status_parameter_not_found;
    }

exit:
    amxc_string_clean(&filter);
    amxc_var_clean(&temp);
    return status;
}
```

As this function implements a data model action (object read action), it must follow the rules for that action and the return value (argument `retval`) must be in the correct format. For an object read action this format is a simple htable, that contains all parameters and their values.

The base implementation of the object read action will initialize a variant containing this structure.

```C
amxd_status_t status = amxd_action_object_read(object, param, reason, args, retval, priv);
```

As none of the parameters are defined in the data model definition file (odl), the initialized htable will be empty. The data is retrieved using `cpu_info_read` and added to the htable variant using `dm_filter_params`.

For an object read action it is possible that not all parameters are requested. To be able to filter out the parameters that should not be returned a filter can be created using `amxd_action_object_read_filter`.

```C
status = amxd_action_object_read_filter(&filter, args);
```

The function `dm_filter_params` will only add the parameters to the htable variant that must be returned.

Putting it all together the end result is a htable variant containing all requested parameters:

Example:
```text
{
    Family = 6,
    ID = 0,
    MHz = 1299.902000,
    Model = 142
    ModelName = "Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz",
    Usage = 999,
    VendorId = "GenuineIntel",
}
```

This is returned back to the client requesting the data.

---
> **NOTE**<br>
> When no `cpu_field_names` configuration option is defined in the config section of the main odl, all fields from the file `/proc/cpuinfo` are added to the return value. The parameter names used are the ones specified in that file, all spaces will be replaced with an `_` to make the parameter names TR-181 compatible.
---

#### Data Model Introspection

Besides reading the parameters values through the data model, meta-data can be provided as well. In most situations the meta-data is provided in the data model definition (odl file). In this case none of the CPU parameters are defined in the odl file. To make it possible for clients to access the meta-data, two extra data model actions functions can be provided.

- a describe action function
- a list action function

The list action function is the easiest, this method should return the list of parameters, functions, sub-objects or instances.

The return value must be a htable variant containing three lists:

```
{
    functions = [
    ],
    objects = [
    ],
    parameters = [
    ]
}
```

The return variant can be initialized and populated with the correct names using `amxd_action_object_list`. In this example this will result in a variant containing empty lists, as the parameters are not defined in the odl, the cpu instances have no functions and no sub-objects.

If the `cpu_field_names` config option is defined in the config section of the main odl, the field names are added to the parameters list otherwise the file `/proc/cpuinfo` is read and all available fields are added to the parameters list.

```C
amxd_status_t _cpu_list(amxd_object_t* object,
                        amxd_param_t* param,
                        amxd_action_t reason,
                        const amxc_var_t* const args,
                        amxc_var_t* const retval,
                        void* priv) {

    ...

    amxd_status_t status = amxd_action_object_list(object,
                                                   param,
                                                   reason,
                                                   args,
                                                   retval,
                                                   priv);

    ...

    params = amxc_var_get_path(retval, "parameters", AMXC_VAR_FLAG_DEFAULT);

    ...

    name_mapping = GET_ARG(config, "cpu_field_names");
    if(name_mapping != NULL) {
        amxc_var_for_each(field, name_mapping) {
            amxc_var_add(cstring_t, params, GET_CHAR(field, NULL));
        }
    } else {
        cpu_info_read(&temp, amxd_object_get_index(object));
        amxc_var_for_each(value, &temp) {
            const char* param_name = amxc_var_key(value);
            amxc_var_add(cstring_t, params, param_name);
        }
    }

    ...
}
```

Besides listing the names of the parameters, functions and sub-objects, more meta-data can be requested by clients. The describe action is used to fetch the full meta-data of an object. The returned data must be a htable variant containing the meta-data of the object, all of its parameters and functions. This data structure is more complex, the method `amxd_action_object_describe` will initialize the variant and fill it with the data available.

When `describing` one of the `CPU` instance objects, this method will create a htable variant containig the following data:

```
{
    attributes = {
        locked = false,
        persistent = false
        private = false,
        protected = false,
        read-only = true,
    },
    functions = {
    },
    index = 1,
    name = "1",
    object = "CPUMonitor.CPU.",
    objects = [
    ],
    parameters = {
    }
    path = "CPUMonitor.CPU.",
    type_id = 3,
    type_name = "instance",
}
```

As there are no functions or sub-objects available, this list or tables will be empty. The parameters are also empty in this case as none of the parameters are defined in the data model definition (odl) file.

The describe action implementation will add the parameters:

```C
amxd_status_t _cpu_describe(amxd_object_t* object,
                            amxd_param_t* param,
                            amxd_action_t reason,
                            const amxc_var_t* const args,
                            amxc_var_t* const retval,
                            void* priv) {
    amxd_status_t status = amxd_action_object_describe(object, param, reason,
                                                       args, retval, priv);
    amxc_var_t* params = NULL;
    amxc_var_t cpu_data;
    uint64_t percentage = 0;

    amxc_var_dump(retval, STDOUT_FILENO);

    amxc_var_init(&cpu_data);

    when_false(status == amxd_status_ok, exit);
    when_true(amxd_object_get_type(object) != amxd_object_instance, exit);

    params = amxc_var_get_path(retval, "parameters", AMXC_VAR_FLAG_DEFAULT);
    when_null(params, exit);

    cpu_info_read(&cpu_data, amxd_object_get_index(object));
    percentage = cpu_dm_get_stats(object, NULL);
    amxc_var_add_key(uint64_t, &cpu_data, "Usage", percentage);

    amxc_var_for_each(value, &cpu_data) {
        const char* key = amxc_var_key(value);
        dm_describe_param(params, key, value);
    }

exit:
    amxc_var_clean(&cpu_data);
    return status;
}
```

The real implementation to add a single parameter is in `dm_describe_param`. which is a very simple method:

```C
static amxc_var_t* dm_describe_param(amxc_var_t* ht_params,
                                     const char* name,
                                     amxc_var_t* value) {
    amxc_var_t* param = amxc_var_add_key(amxc_htable_t,
                                         ht_params,
                                         name,
                                         NULL);

    amxd_param_build_description(param, name, amxc_var_type_of(value),
                                 SET_BIT(amxd_pattr_read_only) |
                                 SET_BIT(amxd_pattr_variable),
                                 NULL);

    amxc_var_set_key(param, "value", value, AMXC_VAR_FLAG_UPDATE);

    return param;
}
```

This method is called for each parameter. The method `amxd_param_build_description` creates a htable variant that will contain all (meta-) data of a single parameter.

As all parameters are read-only and we do not know when the value is changed, the attribute bits `read-only` and `volatile` are set.

---
> **NOTE**<br>
> When using object describe and object read actions often the parameter value changes can not be evented, as it will only be possible to know that a value has changed by reading the value again.
---

A parameter description variant looks like:

```
{
    attributes = {
        counter = false,
        instance = false,
        key = false,
        persistent = false
        private = false,
        protected = false,
        read-only = true,
        template = false,
        unique = false,
        volatile = true,
    },
    flags = [
    ],
    name = "Model",
    type_id = 8
    type_name = "uint32_t",
    value = <NULL>,
}
```

The value will be a `NULL` variant and is set to the correct value using:

```
amxc_var_set_key(param, "value", value, AMXC_VAR_FLAG_UPDATE);
```

After adding all parameters, depending on the `cpu_field_names` configuration option, the parameters field in the describe structure will look like:

```
{
    attributes = {
        locked = false,
        persistent = false
        private = false,
        protected = false,
        read-only = true,
    },
    functions = {
    },
    index = 1,
    name = "1",
    object = "CPUMonitor.CPU.",
    objects = [
    ],
    parameters = {
       Family = {                  
          attributes = {                                     
                counter = false,  
                instance = false,
                key = false,     
                persistent = false
                private = false, 
                protected = false,
                read-only = true, 
                template = false,
                unique = false,   
                volatile = true, 
          },                   
          flags = [             
          ],                  
          name = "Family",      
          type_id = 8          
          type_name = "uint32_t",
          value = 6,           
       },                      
       ID = {                     
          attributes = {      
                counter = false,  
                instance = false,
                key = false,     
                persistent = false 
                private = false, 
                protected = false,
                read-only = true, 
                template = false,
                unique = false,   
                volatile = true, 
          },                     
          flags = [             
          ],                  
          name = "ID",          
          type_id = 8          
          type_name = "uint32_t",
          value = 0,           
       },

       ....

    }
    path = "CPUMonitor.CPU.",
    type_id = 3,
    type_name = "instance",
}
```

To get the full output, you can use the ubus command line tool and call the method `_describe` on the `CPU` instance objects.

Example:

```
$ ubus call CPUMonitor.CPU.1 _describe          
{                                   
        "object": "CPUMonitor.CPU.",
        "name": "1",          
        "type_id": 3,                  
        "type_name": "instance",                  
        "path": "CPUMonitor.CPU.",                
        "attributes": {                          
                "private": false,                
                "read-only": true,              
                "locked": false,                 
                "protected": false,               
                "persistent": false                
        },                                   
        "index": 1,                                
        "parameters": {   
                "Family": {                                                 
                        "attributes": {
                                "instance": false,
                                "read-only": true,
                                "volatile": true,
                                "counter": false,
                                "unique": false,
                                "private": false,
                                "template": false,
                                "protected": false,
                                "key": false,     
                                "persistent": false
                        },                       
                        "value": 6,              
                        "flags": [              
                                                 
                        ],                        
                        "name": "Family",          
                        "type_name": "uint32_t",
                        "type_id": 8               
                },        
                "ID": {                         
                        "attributes": {
                                "instance": false,
                                "read-only": true,
                                "volatile": true,
                                "counter": false,
                                "unique": false,
                                "private": false,
                                "template": false,
                                "protected": false,
                                "key": false,     
                                "persistent": false
                        },                       
                        "value": 0,              
                        "flags": [              
                                                 
                        ],                        
                        "name": "ID",              
                        "type_name": "uint32_t",
                        "type_id": 8               
                },      

                ...  

```

Using the tool `ubus-cli` it is also possible to invoke the `_describe` method on the `CPU` instance objects and get a more human readable output:

```
$ ubus-cli 
Copyright (c) 2020 - 2021 SoftAtHome
amxcli version : 0.2.16

!amx silent true

  _______                     ________        __
 |       |.-----.-----.-----.|  |  |  |.----.|  |_
 |   -   ||  _  |  -__|     ||  |  |  ||   _||   _|
 |_______||   __|_____|__|__||________||__|  |____|
          |__| W I R E L E S S   F R E E D O M
 -----------------------------------------------------
 ubus - cli
 -----------------------------------------------------

sah4009 - ubus: - [ubus-cli] (0)
 > dump -p CPUMonitor.CPU.1.
.R.... <public>       instance CPUMonitor.CPU.1.
.R...V <public>         uint32 CPUMonitor.CPU.1.Family=6
.R...V <public>         uint64 CPUMonitor.CPU.1.Usage=30
.R...V <public>         double CPUMonitor.CPU.1.MHz=1179.718000
.R...V <public>         uint32 CPUMonitor.CPU.1.ID=0
.R...V <public>         string CPUMonitor.CPU.1.ModelName=Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
.R...V <public>         string CPUMonitor.CPU.1.VendorId=GenuineIntel
.R...V <public>         uint32 CPUMonitor.CPU.1.Model=142

sah4009 - ubus: - [ubus-cli] (0)
 >
```

### Considerations

Using data model action callback functions on objects (or parameters) can add a lot of flexibility and makes it possible to retrieve data from the system without the need of duplicating the data (values) in the data model itself. However it has some drawbacks, it is hard to send object changed events if the data can only be retrieved by reading it. Most of the time when implemnenting a read action for an object or some parameters it will render these parameters as not eventable.

