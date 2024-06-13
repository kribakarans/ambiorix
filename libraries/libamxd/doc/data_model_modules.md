# Data Model Modules - Extending A Data Model

[[_TOC_]]

## Introduction

A fundamental aspect of effective data management is the use of data models, which provide a structured representation of data and its relationships. These data models are defined and standardized by [Broadband Forum](https://www.broadband-forum.org/). However, as business requirements become more complex and data sets grow in size and diversity, the need for flexible and scalable data models has become apparent. This is where data model modules come into play. The standard defined data models often do not completely cover all custom requirements. 

The ambiorix data model engine in combination with the [Object Definition Language](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxo/-/blob/main/doc/odl.md) provides functionality to make it easy (or easier) to implement the bbf defined data models (or parts of it), for example [TR-181](https://usp-data-models.broadband-forum.org/tr-181-2-16-0-usp.html).

Data model modules are specialized components designed to extend and enhance the capabilities of a core data model. They offer a modular approach to data modeling, allowing organizations to adapt the data model structures efficiently to accommodate changing needs without having to overhaul the core data model definition and implementation. By providing a means to add or modify data elements, relationships, constraints and functionality, data model modules empower businesses to better align their data models with evolving business processes and objectives.

## Types Of Data Model Extensions

Two main kinds of data model extensions can be identified:

1. Functional data model extensions - These extensions are adding functionality to the existing data model. Often used to add custom logic or specialized data model actions (like parameter validation)
2. Non-functional data model extensions - These extensions only add extra objects or parameters to the existing data model, only used to store extra data that is not defined in the standards  

Of course data model modules (extensions) can combine both as well (and often do).

### Non-functional Data Model Extensions

This kind of extension is the easiest to achieve, as no coding is required, when using the [Object Definition Language](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxo/-/blob/main/doc/odl.md).

To be able to add extra object or parameter definitions to an existing data model, without the need to modify the core data model definition, two steps need to be done:

1. Create a sub-directory "extensions" in directory where the core data model definitions are installed
2. Define your data model extension and install them in the sub-directory.

All odl files installed in the "extensions" directory will be loaded in alphabetical order, after the core odl files are loaded.

---
> **NOTE**<br>
> When one of the odl files in the subdirectory contains an error, loading will fail.
---

The directory from which data model extensions are loaded can be configured with the configuration option `extensions-dir`. By default this option is set to `${prefix}${cfg-dir}/extensions/`. 

#### Define The Extension(s).

A non-functional extension odl file mainly will add parameters and/or objects to the existing already defined data model. Redefining an object will generate an error, so it must be made clear to the odl parser that the file is extending an already defined object. The object definition language provides the keyword `select` which will select the object and apply the extra defined parameters and/or (sub)objects.

Let's take this main data model definition file `/etc/amx/greeter/greeter_definition.odl`

```
%define {
    object Greeter {
        object History[] {
            string Message;
            string From;
            bool Retain;
        }
    }
}
```

And this main odl file `/etc/amx/greeter/greeter.odl`

```
%config {
    name = "greeter";

    definition_file = "${name}_definition.odl";
}

include "${definition_file}";
```

A data model provider can now be launched using `amxrt`.

```
amxrt /etc/amx/greeter/greeter.odl
```

Using a client application (like ubus-cli when using ubus as bus system), it is possible to add new instances to the `Greeter.History.` object.

```
root@2aca014eac54:/# ubus-cli 
Copyright (c) 2020 - 2023 SoftAtHome
amxcli version : 0.3.1

!amx silent true

                   _  ___  ____
  _ __  _ __ _ __ | |/ _ \/ ___|
 | '_ \| '__| '_ \| | | | \___ \
 | |_) | |  | |_) | | |_| |___) |
 | .__/|_|  | .__/|_|\___/|____/
 |_|        |_| based on OpenWrt
 -----------------------------------------------------
 ubus - cli
 -----------------------------------------------------

root - ubus: - [ubus-cli] (0)
 > Greeter.History+{Message="Hello World", From="me", Retain=false}
Greeter.History.1.

root - ubus: - [ubus-cli] (0)
 > Greeter.?
Greeter.
Greeter.History.1.
Greeter.History.1.From="me"
Greeter.History.1.Message="Hello World"
Greeter.History.1.Retain=0

root - ubus: - [ubus-cli] (0)
 > 
 ```

If for a specific project an extra parameter needs to be added, like a timestamp, a new odl file can be created and added to `/etc/amx/greeter/extensions/`:

file: `/etc/amx/greeter/extensions/history_timestamp.odl`

```
%define {
    select Greeter.History {
        datetime Timestamp;
    }
}
```

When launching the same data model provider again (make sure the previous instance is stopped), a new parameter is available in the `Greeter.History.` object, which can be set.

```
root - ubus: - [ubus-cli] (0)
 > Greeter.History+{Message="Hello World", From="me", Retain=false, Timestamp="2023-08-17T09:11:20Z"}
Greeter.History.1.

root - ubus: - [ubus-cli] (0)
 > Greeter.?
Greeter.
Greeter.History.1.
Greeter.History.1.From="me"
Greeter.History.1.Message="Hello World"
Greeter.History.1.Retain=0
Greeter.History.1.Timestamp="2023-08-17T09:11:20Z"
```

For more information and full syntax overview of the keyword `select` read the [Object Definition Language](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxo/-/blob/main/doc/odl.md#extend-using-select) documentation.

#### Considerations

- Extending a multi-instance object will not impact already created instances:
  That is, the existing instances will not be modified when a multi-instance object (template) object is modified. If it is needed that all instances are extended, make sure that data model extensions are loaded before the instances are created.
- It is possible to extend instances, but this is not recommended. Extending a single (or some instances) and not all, will create TR-181 (and USP) incompatibilities. USP controllers will not be able to cope with the fact that not all instances have the same parameters and/or sub-objects.

### Functional Data Model Extensions

Although non-functional data model extensions can be used to extend an existing data model and allow data model clients to store and retrieve extra information in the data model, the data model provider will not use these extensions. Often extra functionality is also needed in the data model provider.

Two main categories of functional data model extensions or data model modules can be defined:

1. Data model extensions (modules) that provide common functionality. These modules provide functionality that could be used by many data model providers.  
2. Data model extensions (modules) that provide extra custom functionality that can only be used by one single data model provider. These are often used to add project/customer specific functionality to a specific data model provider.

#### Common Data Model Extensions

A common data model extension can provide extra functionality that can be used by many data model providers. This functionality can be (but is not limited to):

- Extra parameter value validators (example: parameter validators, like value matches a regular expression).
- Re-usable data model logic (example: ordered instances, parameter references).

These kind of modules are typically installed in `/usr/lib/amx/modules`. This path is by default a search path for the odl `import` keyword. 

Some real examples of such modules are:

- [mod_dmext](https://gitlab.com/prpl-foundation/components/core/modules/mod_dmext)<br>
  This module provides a set of parameter value validators like
  - Regular expression matching (string matches a regular expression)
  - IPv4 and IPv6 address validation (is valid IP address)
  - Logical expression validation (using the value the logical expression evaluates to true)<br><br>

  It also provides some extra common data model functionality like
  - Ordered instances (as defined in TR-181)
  - Parameters with object path references, which will check if the referenced object exists, and monitors the referenced object, when deleted the parameter is reset to an empty string. This can be used to implement strong references as defined in TR-181.<br><br>

- [mod_sahtrace](https://gitlab.com/prpl-foundation/components/core/modules/mod_sahtrace)<br>
  Enables sahtrace and makes it possible to configure sahtrace from within the odl configuration section and adds tracing RPC protected methods to the data model objects, which will make it possible for data model clients to modify the tracing configuration of the data model provider.

Using a common functional data model extension is easy, all that needs to be done is `import` the shared object from within an odl file (typically the main odl file of the data model provider) and use the functionality provided. It is recommended to read the documentation provided by the data model extension. Sometimes it is needed to also define the entry point.

Example using `mod_dmext` functional data model extension:

file: `/etc/amx/greeter/greeter.odl`
```
%config {
    name = "greeter";

    definition_file = "${name}_definition.odl";
}

import "mod-dmext.so" as "dmext";

include "${definition_file}";
```

file: `/etc/amx/greeter/greeter_definition.odl`

```
%define {
    object Greeter {
        object History[] {
            string Message;
            string From {
                // from value must start with "User-"
                on action validate call matches_regexp "^User-*.$";
            }
            bool Retain;
        }
    }
}
```

When such a common data model module is only used in a data model extension and not imported by the main (or core) data model definition, it can be imported in the data model extension definition as well.

file: `/etc/amx/greeter/greeter.odl`
```
%config {
    name = "greeter";

    definition_file = "${name}_definition.odl";
}

include "${definition_file}";
```

file: `/etc/amx/greeter/greeter_definition.odl`

```
%define {
    object Greeter {
        object History[] {
            string Message;
            string From;
            bool Retain;
        }
    }
}
```

file: `/etc/amx/greeter/greeter_extension.odl`

```
import "mod-dmext.so";

%define {
    select Greeter.History {
        string SourceInfo {
            on action validate call matches_regexp "^(User|Device|Service)-.*$";
        }
    }
}
```

When launching a data model provider using these files a new parameter "SourceInfo" is added. The value of this parameter must start with "User-", "Device-" or "Service-".

```
sah4009 - ubus: - [ubus-cli] (0)
 > Greeter.History+{Message="Hello World", From="me", Retain=false, Timestamp="2023-08-17T09:11:20Z", SourceInfo="User-MyID"}
Greeter.History.1.

sah4009 - ubus: - [ubus-cli] (0)
 > Greeter.?
Greeter.
Greeter.History.1.
Greeter.History.1.From="me"
Greeter.History.1.Message="Hello World"
Greeter.History.1.Retain=0
Greeter.History.1.SourceInfo="User-MyID"
Greeter.History.1.Timestamp="2023-08-17T09:11:20Z"
```

#### Custom Data Model Extensions

These kind of extensions are used to extend a specific data model provider implementation and often add project or customer specific logic. 

Implementing such an extension (module) is basically the same as implementing a full data model provider, with the main difference that the module can not run stand-alone an must be loaded into a data model provider. These modules are always built as a shared object, and are typically installed in the same directory as where the main shared object of the data model provider is installed. This directory is mostly `/usr/lib/amx/<NAME>/` where `<NAME>` is the name of the data model provider.

Assume that for a specific project the `Greeter.History.` object must be extended with a `Timestamp` parameter which is read-only and must be set to the time the instance was created.

To achieve this there are some options:

1. Implement a custom add-instance handler that sets the `Timestamp` parameter to the current time.
2. Implement an event handler method that sets the `Timestamp` to the current time when an `dm:instace-added` event is recieved.

Both will achieve the same, with some small difference. The second option will update the created instance, while the first option will set the `Timestamp` parameter at creation time.

The greeter timestamp example:

The code below implements an add instance action handler, that will set the "TimeStamp" parameter to the current time.

When saving this implementation into a file named "greeter_timestamp.c" a shared object file can be created by using these commands, executed in the directory where the file is save. After these two commands a file `greeter_timestamp.so` is created, which can be copied to the greeter implementation directory (`/usr/lib/amx/greeter/`)

```
gcc -fPIC -g3 -c -o greeter_timestamp.o greeter_timestamp.c
gcc -Wl,-soname,greeter_timestamp.so -o greeter_timestamp.so greeter_timestamp.o -shared -fPIC -lamxc -lamxd
sudo cp greeter_timestamp.so /usr/lib/amx/greeter/
```

```C
#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>
#include <amxp/amxp.h>

#include <amxd/amxd_action.h>
#include <amxd/amxd_object.h>

amxd_status_t _set_timestamp(amxd_object_t* const object,
                             amxd_param_t* const p,
                             amxd_action_t reason,
                             const amxc_var_t* const args,
                             amxc_var_t* const retval,
                             void* priv);

static amxd_object_t* amxd_action_add_inst_is_created(amxd_object_t* const object,
                                                      amxc_var_t* data) {
    amxd_object_t* instance = NULL;

    when_false(amxc_var_type_of(data) == AMXC_VAR_ID_HTABLE, exit);
    when_null(GET_ARG(data, "index"), exit);
    instance = amxd_object_get_instance(object, NULL, GET_UINT32(data, "index"));

exit:
    return instance;
}

amxd_status_t _set_timestamp(amxd_object_t* const object,
                             amxd_param_t* const p,
                             amxd_action_t reason,
                             const amxc_var_t* const args,
                             amxc_var_t* const retval,
                             void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* params = NULL;
    amxc_var_t aargs;
    const amxc_var_t* margs = args;
    amxd_object_t* instance = NULL;
    amxc_ts_t now;

    amxc_var_init(&aargs);
    amxc_ts_now(&now);
    when_null(object, exit);
    when_null(retval, exit);

    instance = amxd_action_add_inst_is_created(object, retval);

    params = amxc_var_get_key(args, "parameters", AMXC_VAR_FLAG_DEFAULT);
    if(params == NULL) {
        amxc_var_copy(&aargs, args);
        margs = &aargs;
        params = amxc_var_add_key(amxc_htable_t, &aargs, "parameters", NULL);
    }

    amxc_var_add_key(amxc_ts_t, params, "Timestamp", &now);

    if(instance != NULL) {
        amxd_param_t* pts = amxd_object_get_param_def(instance, "Timestamp");
        amxc_var_set(amxc_ts_t, &pts->value, &now);
        status = amxd_status_ok;
    } else {
        status = amxd_action_object_add_inst(object, p, reason, margs, retval, priv);
    }

exit:
    amxc_var_clean(&aargs);
    return status;
}
```

If the following odl files are created:

file: `/etc/amx/greeter/greeter_definition.odl`

```
%define {
    object Greeter {
        object History[] {
            string Message;
            string From;
            bool Retain;
        }
    }
}
```

file: `/etc/amx/greeter/greeter.odl`

```
%config {
    name = "greeter";

    definition_file = "${name}_definition.odl";
}

include "${definition_file}";
```

file: `/etc/amx/greeter/extensions/history_timestamp.odl`

---
> **NOTE**<br>
> Other odl files can in the directory `/etc/amx/greeter/extensions/` can be removed.
---

```
import "greeter_timestamp.so";

%define {
    select Greeter.History {
        on action add-inst call set_timestamp;
        %read-only datetime Timestamp;
    }
}
```

After launching the data model provider, the extension odl is loaded and the timestamp implementation is imported.

When creating a new `Greeter.History.` instance the `Timestamp` parameter will be set.

```
sah4009 - ubus: - [ubus-cli] (4)
 > Greeter.History+{Message="Hello World", From="me", Retain=false}
Greeter.History.1.

sah4009 - ubus: - [ubus-cli] (0)
 > Greeter.?
Greeter.
Greeter.History.1.
Greeter.History.1.From="me"
Greeter.History.1.Message="Hello World"
Greeter.History.1.Retain=0
Greeter.History.1.Timestamp="2023-08-17T10:38:41.459725796Z"
```

#### Considerations

- Functional modules (shared object files) can be imported multiple times (in different odl files). The odl parser (and the system) will make sure each shared object is only loaded once into memory (even if it is imported more than once).
- Functions from modules (shared object files) can only be used after they are imported.
- When multiple modules (shared object files) are imported and there is a function name conflict (multiple modules provide the same function names), the odl parser will take the function of the first loaded shared object file by default. This behaviour can be modified by providing resolver instructions (see [Function Resolving](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxo/-/blob/main/doc/odl.md#function-resolving) in odl documentation).

