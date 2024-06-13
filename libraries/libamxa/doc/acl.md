# Access Control Lists

Disclaimer: this documentation is not final and is subject to change during development.

[[_TOC_]]

## Introduction

Access control is important when dealing with untrusted parties. Access rights must be verified at
the border of the host resident firmware. Internal components (within the firmware) are 
assumed to be trusted and can communicate freely using
the available bus. This means that ACL verification is needed when

- a service on the host requests something from a service in a container
- a service in a container requests something from a service on the host
- an external controller requests something from a service on the host
- an external controller requests something from a service in a container

Note that this last type of request will pass through the host system before being forwarded to the
container.

## How does ACL verification work in Ambiorix systems

Access control verification within Ambiorix is based on the USP Role Based Access Control (RBAC)
system. A process at the gateway border (typically a USP agent) will verify the role of the entity
that wishes to interact with the gateway data model (typically a USP controller). Based on its role,
the requestor is allowed to access or prevented from accessing certain data model elements.

> Note: To simplify the syntax in the remainder of this document, we will speak of a USP agent as
> the process that verifies ACLs and a USP controller as the requesting process. However, when the
> gateway is accessed through the web-ui for example, ACLs must also be verified using the same
> mechanisms as for a USP agent.

To validate the ACLs, a USP agent will need the following things:

- Access control lists (ACLs). 
- This library as it contains the needed APIs for validating ACLs.
- The [acl-manager](https://gitlab.com/prpl-foundation/components/ambiorix/applications/acl-manager), which is responsible for merging ACL files into a single source of truth (more on this later).

### Access control lists (ACLs)

ACL verification within Ambiorix is implemented based on the USP RBAC system, which can be
summarized by the `Device.LocalAgent.ControllerTrust.Role.{i}.` data model. Any USP controller will
have one or multiple roles, which are listed in this data model. Each `Role.{i}.` object has a set
of `Role.{i}.Permission.{i}.` elements specifying the permissions that correspond to the Role.

A permission object has the following parameters to set/restrict access rights:

- `Param`: permission information related to parameters.
- `Obj`: permission information related to objects.
- `InstantiatedObj`: permission information related to instances.
- `CommandEvent`: permission information related to commands and events.

Each of these parameters is a string of 4 characters "rwxn", where each character represents a
permission ("r" for Read, "w" for Write, "x" for Execute and "n" for Notify). The string is always
in the same order (rwxn) and the lack of a permission is signified by using a "-" character
(e.g. "r--n" would imply read permission and permission to receive notifications for the targeted
data model).

For detailed information explaining what each character gives access to, refer to the [TR-181 data model](https://usp-data-models.broadband-forum.org/tr-181-2-15-0-usp.html#D.Device:2.Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.)

Besides the permission parameters, the `Permission` object also has a `Targets` parameter to
indicate which data model path the permissions apply to and an `Order` parameter, to handle
overlapping `Targets`. A higher `Order` means the permissions of overlapping `Targets` will be
overridden. This is mainly important when using search paths in the `Targets`.

The Ambiorix ACL system reuses the parameters of this Permission object for specifying the various
permissions, however, instead of dumping all that information in the data model, ACL files in JSON
format are used.

Take a look at the section about [Roles (Access Control)](https://usp.technology/specification/08-index-auth.html#sec:roles-access-control) in the USP specification for more information about RBAC.

#### ACL examples

An ACL file will have the following format:

```json
{
    "Path.To.Data.Model.": {
        "Order": 1,
        "Param": "rwxn",
        "Obj": "rwxn",
        "InstantiatedObj": "rwxn",
        "CommandEvent": "rwxn"
    }
}
```

It is important to note that by default no permissions are granted. Each permission explicitly needs
to be set with one of the `rwxn` strings. Note that the following 2 ACL files give the exact same
permissions:

```json
{
    "Path.To.Data.Model.": {
        "Order": 1,
        "Param": "----",
        "Obj": "rwxn",
        "InstantiatedObj": "rwxn",
        "CommandEvent": "rwxn"
    }
}
```
```json
{
    "Path.To.Data.Model.": {
        "Order": 1,
        "Obj": "rwxn",
        "InstantiatedObj": "rwxn",
        "CommandEvent": "rwxn"
    }
}
```

In the first file, all parameter access is disabled by using dashes `-` for each character in the
`Param` string. In the second file, the entire `Param` section is missing, which also implies no
parameter access is granted for the user.

Also note that when permissions are granted for a root object, users with the role to which the
permissions apply will have access to everything under the root object. For example:

```json
{
    "Device.IP.": {
        "Order": 1,
        "Param": "rwxn",
        "Obj": "rwxn",
        "InstantiatedObj": "rwxn",
        "CommandEvent": "rwxn"
    }
}
```

will give access to everything under the `Device.IP.` object (as specified in TR-181). There is no
need to add separate rules for granting access to sub-objects. It is of course possible to further
restrict access to certain sub-objects by adding an extra rule:

```json
{
    "Device.IP.": {
        "Order": 1,
        "Param": "rwxn",
        "Obj": "rwxn",
        "InstantiatedObj": "rwxn",
        "CommandEvent": "rwxn"
    },
    "Device.IP.Interface.": {
        "Order": 2,
        "Param": "r---",
        "Obj": "r---",
        "InstantiatedObj": "r---",
        "CommandEvent": "r---"
    }
}
```

Note that the second rule has a higher order, so it will take precedence over the first rule. If the
orders were swapped, the second rule would have no effect (think about this).

ACL rules can also be written with USP search paths:

```json
{
    "Device.IP.": {
        "Order": 1,
        "Param": "rwxn",
        "Obj": "rwxn",
        "InstantiatedObj": "rwxn",
        "CommandEvent": "rwxn"
    },
    "Device.IP.Interface.[Alias == 'data'].": {
        "Order": 2,
        "Param": "r---",
        "Obj": "r---",
        "InstantiatedObj": "r---",
        "CommandEvent": "r---"
    }
}
```

Finally note that the above 2 rules could be written in a single ACL file or in 2 separate ACL
files. The `acl-manager` will make sure they are merged together.

#### Storage location of ACL files for different roles

Now that you understand what ACL files look like, it is important to know how they can be applied
to the different roles. By default 4 roles will be defined:

- An "admin" role: it must be possible to do everything the UI is capable of
- A "guest" role: has no access by default, but can be used for demo purposes
- An "operator" role: this role must be able to do everything
- An "untrusted" role: it must be able to log in (and display some very generic information)"

All ACL files for a role need to be installed in the `/etc/acl/<role>/` directory. The `acl-manager`
will make sure the files are merged together to a single file per role for easy verification of
access rights. More on this in the next section.

### The acl-manager

As explained above, ACL files can contain rules with overlapping targets, different orders,
search paths and can be written in one or multiple files. That's why there is a need for an
`acl-manager`. The `acl-manager` is responsible for reading all ACL files that belong to a certain
role and merging them together to a single "master" ACL file. This "master" ACL file will serve as
the single source of truth for handling ACL verification and must be used by the USP agent (or other
processes at the gateway borders).

#### Collecting access rules and merging them together

Access rules can generally be defined in 2 ways:

- By adding them to ACL files
- By adding instances to the `Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.` data model

On startup the `acl-manager` will copy all files from `/etc/acl/` to `/cfg/etc/acl/`, which is
guaranteed to be a writable directory on the devices we use. It will merge files together to a
single file in `/cfg/etc/acl/merged/<role>.json`, which can be used to verify access rights for the
role.

At any time, these rules can be updated by adding extra ACL files to `/cfg/etc/acl/` or new instances in the
`ControllerTrust` data model (which will in turn add ACL files to `/cfg/etc/acl/`).

> NOTE:  
> At compile time/install time all known ACL files are installed to the `/etc/acl/<role>/` directory,
> which is a reboot persistent directory. Depending on the embedded target and chosen filesystem,
> the directory will be read-only. Because the `/cfg/` directory is writable on all devices we use,
> all ACL files are copied here on startup of the `acl-manager`. If anything is added dynamically at
> runtime, it should also be added to `/cfg/etc/acl/<role>/`.

> NOTE:  
> `/etc/acl/` and `/cfg/etc/acl/` are the default directories used for ACL files. It is recommended
> to make these paths configurable, similar to how it was done for the [acl-manager](https://gitlab.com/prpl-foundation/components/ambiorix/applications/acl-manager/-/blob/main/odl/acl-manager.odl).

Whenever something changes, the correct access rights need to be recalculated because these changes
could override any of the existing rules. Therefore, the `acl-manager` will monitor the acl
directories and recalculate the master acl file for a role every time a file is changed, added or
removed. Instead of collecting and merging the access rules every time a request arrives, it is only
done once at boot time and repeated if something changes. This simplifies ACL verification to a
quick look-up in a file (after search paths have been resolved).

#### Resolving search paths

ACL rules can contain search paths which need to be resolved before it is known which instances they
apply to. A set of permissions could for example be specified for the path
`Device.WiFi.Radio.[Enable == False].` if a controller is only allowed to read and configure
things for disabled radios. The `Enable` parameter of each radio could change at any time, which
makes it impossible to resolve this search path in advance. It can only be resolved once a request
for `Device.WiFi.Radio.` arrives.

So the master ACL file for each role can contain search paths that need to be resolved before you
can figure out if the requestor has the right permissions. To minimize the overhead introduced by
search paths, they will only be resolved for paths starting from a root path. In other words, if
a request arrives for `Device.WiFi.` or one of its child objects, then search paths will only be
resolved if they start with `Device.WiFi.`.

Some extra information about the `acl-manager` can be found in its [README.md file](https://gitlab.com/prpl-foundation/components/ambiorix/applications/acl-manager/-/blob/main/README.md).

### The libamxa APIs

`libamxa` has been written to make it easy for several border control processes to validate ACLs
using the same ACL files and APIs. Verifying the access rights requires several steps. In this
section the different steps will be explained and the required APIs that are needed will be
discussed.

- Reading the acls can be done with [amxa_parse_files](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxa/-/blob/main_v0.4.12/include/amxa/amxa_merger.h#L94). This function will return a variant of type hash table with the information of the master ACL file.
- The ACLs can contain search paths and these need to be resolved whenever a data model operation is done. We are dealing with dynamic data models, so these search paths can resolve to different objects at different moments in time. Resolving search paths can be done with the function [amxa_resolve_search_paths](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxa/-/blob/main_v0.4.12/include/amxa/amxa_resolver.h#L106).
- The next step is figuring out which data models the current role has access to. This depends on the operation that needs to be executed (get/set/...). `libamxa` provides a function [amxa_get_filters](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxa/-/blob/main_v0.4.12/include/amxa/amxa_validator.h#L131) to get a list of objects that need to be filtered from a request or response. It takes a `bitmask` as input argument which is different for the available operations. For a `get` operation it would be `AMXA_PERMIT_GET`. A full list of bitmasks will be provided in a table below.
- In case of a `get` operation, you also need to check if you are allowed to use search paths, which can be done with [amxa_is_search_path_allowed](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxa/-/blob/main_v0.4.12/include/amxa/amxa_validator.h#L105). For some reason, you don't need to check this for the other operations (refer to [TR-181](https://usp-data-models.broadband-forum.org/tr-181-2-15-0-usp.html#D.Device:2.Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.InstantiatedObj) for more information).
- Based on the retrieved filters you need to check whether the operation is allowed. For a `get` this can be done with [amxa_is_get_allowed](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxa/-/blob/main_v0.4.12/include/amxa/amxa_validator.h#L192).
- If the operation is allowed, you can invoke it with the right `amxb` call, for example is `amxb_get`.
- In case of a `get`, `get_supported` or `get_instances` operation, you also need to filter the output, because it is possible that you had access to certain parameters, but not to others. The ones you don't have access to need to be filtered out with [amxa_filter_get_resp](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxa/-/blob/main_v0.4.12/include/amxa/amxa_validator.h#L153). This is the last step of the ACL verification process, so the remaining output (or error) can be forwarded to the requestor.

Note that we are working on streamlining this process. For a `get`, `set` and `get_instances` operation, there already exist API functions to do all of the above steps for you.

- [amxa_get](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxa/-/blob/main_v0.4.12/include/amxa/amxa_get.h#L136)
- [amxa_set_multiple](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxa/-/blob/main_v0.4.12/include/amxa/amxa_set.h#L103)
- [amxa_get_instances](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxa/-/blob/main_v0.9.1/include/amxa/amxa_get_instances.h#L143)

The other operators will hopefully have similar functions in the near future.

The use of the aforementioned bitmask is inspired by the code in obuspa. The following bitmasks are defined.

```C
//------------------------------------------------------------------------------
// Bits in bitmask defining permissions. If the bit is set, then the permission is granted
#define AMXA_PERMIT_GET                0x0001 // Grants the capability to read the value of the Parameter via Get and read the meta-information of the Parameter via GetSupportedDM.
#define AMXA_PERMIT_SET                0x0002 // Grants the capability to update the value of the Parameter via Add or Set.
#define AMXA_PERMIT_ADD                0x0004 // Grants no capabilities for Static Objects. Grants the capability to create a new instance of a Multi-Instanced Object via Add
#define AMXA_PERMIT_DEL                0x0008 // Grants the capability to remove an existing instance of an Instantiated Object via Delete (e.g. Device.LocalAgent.Controller.1.).
#define AMXA_PERMIT_OPER               0x0010 // Grants the capability to execute the Command via Operate, but grants no capabilities to an Event.

#define AMXA_PERMIT_SUBS_VAL_CHANGE    0x0020 // Grants the capability to use this Parameter in the ReferenceList of an Event or ValueChange Subscription.
#define AMXA_PERMIT_SUBS_OBJ_ADD       0x0040 // Grants the capability to use this Object in the ReferenceList of an Event or ObjectCreation (for multi-instance objects only) Subscription.
#define AMXA_PERMIT_SUBS_OBJ_DEL       0x0100 // Grants the capability to use this Instantiated Object in the ReferenceList of an Event or ObjectDeletion Subscription
#define AMXA_PERMIT_SUBS_EVT_OPER_COMP 0x0200 // Grants the capability to use this Event or Command in the ReferenceList of an Event or OperationComplete Subscription.

#define AMXA_PERMIT_GET_INST           0x0080 // Grants the capability to read the instance numbers and unique keys of the Instantiated Object via GetInstances. Also allows the use of search paths in get operations.
#define AMXA_PERMIT_OBJ_INFO           0x0400 // Grants the capability to read the meta-information of the Object via GetSupportedDM.
#define AMXA_PERMIT_CMD_INFO           0x0800 // Grants the capability to read the meta-information of the Command (including input and output arguments) and Event (including arguments) via GetSupportedDM.

#define AMXA_PERMIT_NONE               0x0000 // Grants no capabilities
#define AMXA_PERMIT_ALL                0xFFFF // Grants all capabilities
```

The following table shows which bits are enabled by the `Param`, `Obj`, `InstantiatedObj` and
`CommandEvent` entries in the `Permission.{i}.` data model:

| Data model param | rwxn | Bit                            |
| ---------------- | -    | ------------------------------ |
| Param            | r    | AMXA_PERMIT_GET                |
|                  | w    | AMXA_PERMIT_SET                |
|                  | x    |                                |
|                  | w    | AMXA_PERMIT_SUBS_VAL_CHANGE    |
|                  |      |                                |
| Obj              | r    | AMXA_PERMIT_OBJ_INFO           |
|                  | w    | AMXA_PERMIT_ADD                |
|                  | x    |                                |
|                  | w    | AMXA_PERMIT_SUBS_OBJ_ADD       |
|                  |      |                                |
| InstantiatedObj  | r    | AMXA_PERMIT_GET_INST           |
|                  | w    | AMXA_PERMIT_DEL                |
|                  | x    |                                |
|                  | w    | AMXA_PERMIT_SUBS_OBJ_DEL       |
|                  |      |                                |
| CommandEvent     | r    | AMXA_PERMIT_CMD_INFO           |
|                  | w    |                                |
|                  | x    | AMXA_PERMIT_OPER               |
|                  | w    | AMXA_PERMIT_SUBS_EVT_OPER_COMP |

Note that some characters in the `rwxn` string don't have any use. This is because it doesn't make
sense to execute a parameter for example.

## Additional information

### ACL rules for Get Supported Data Model messages (GSDM)

TODO: Update GSDM validation now that it is possible to invoke a GSDM request on an instance path.
Before anything can be updated, BBF first needs to decide how this should work. The discussion can
be followed in [USP-778](https://issues.broadband-forum.org/browse/USP-778).

The `r` flag used in `Param`, `Obj` and `CommandEvent` permissions indicates whether meta-data can
be read from parameters, objects, commands and events using GSDM messages. Note that the target
paths for these rules work a bit different than for the other operations. It does not make sense to
restrict GSDM access when the target path is an instance or wildcard, because it is not possible to
execute a GSDM operation on these types of paths (in version 1.1 of the USP specification).

Consider the following example:

```json
{
    "DHCPv4.Client.1.": {
        "Order": 1,
        "Param": "-wxn",
        "Obj": "rwxn",
        "InstantiatedObj": "rwxn",
        "CommandEvent": "rwxn"
    },
    "DHCPv4.Server.Pool.*.": {
        "Order": 2,
        "Param": "rwxn",
        "Obj": "-wxn",
        "InstantiatedObj": "rwxn",
        "CommandEvent": "rwxn"
    },
    "DHCPv4.Relay.Forwarding.[Enable == True].": {
        "Order": 3,
        "Param": "rwxn",
        "Obj": "rwxn",
        "InstantiatedObj": "rwxn",
        "CommandEvent": "-wxn"
    }
}
```

> ! WARNING !
> Some people within BBF believe that wildcarded paths do make sense for supported paths. It is
> possible that paths containing an asterisk should be replaced by supported paths with {i} before
> evaluating the ACLs. This is currently undocumented anywhere in TR-369 and TR-181, so it is left
> up to the implementation.

The first rule makes sense for Get messages to prevent a controller from reading parameter values,
but it does not make sense for GSDM messages, because it is not possible to invoke a GSDM operation
using `DHCPv4.Client.1.` as an input path. 

> ! WARNING !
> In USP version 1.2 it will be allowed to execute a get supported dm operation on an instance path.
> This is useful when different instances have diverging paths (e.g. different parameters). Perhaps
> it will then make sense to take search paths, wildcards and instance numbers into account.
> See [USP-542](https://issues.broadband-forum.org/browse/USP-542) for details.

If there is a need to restrict access to meta-data for Client objects, an additional rule must be 
added with a target path of `DHCPv4.Client.` and with an order that is lower than the first rule.
If the order for the rule with `DHCPv4.Client.` is higher than the order for `DHCPv4.Client.1.`,
then only the first rule will be used, because it applies recursively to all sub-objects and it has
precedence due to its higher order.

Both the second and third rule don't make any sense. They only restrict access to meta-data for
objects, commands or events using a GSDM message, but it is not possible to use wildcards or search
paths in GSDM messages. Consequently, neither of these rules will do anything and there is also no
need to resolve search paths or wildcards present in the ACL rules before fitering GSDM responses.
If access to meta-information must be restricted for the `Pool` or `Forwarding` object, the rules
should be applied to the parent path path i.e. `DHCPv4.Server.Pool.` or
`DHCPv4.Relay.Forwarding.`.

Interesting note from USP-542:

> If the Agent encounters a diverging Supported Data Model, e.g. due to the use of different Mounted Objects underneath a Mountpoint, the Agent will skip the traversal of the children Objects without adding any information to the Response and continue processing with the next unambiguous Object. The Supported Data Model of such divergent Objects can only be obtained by specifically using Instantiated Object Paths in the `obj_paths` field.

## Who can create ACL files?

It is possible to add ACL files in the component repository. This gives the implementor of the
component the ability to define which roles are allowed to access its data model. During
installation, they can then be installed in a designated directory which should be `/etc/acl` by
default. The permissions of this directory should be limited at runtime. Only the `acl-manager` is
supposed to have read access to this directory such that is can copy the files to `/cfg/etc/acl`
which can be updated at runtime. This directory should also have restricted access rights.

It is also possible to define all or a subset of ACL files at config level. It does not matter how
many files there are as long as they are written in the correct format.

At run time it is also possible to override or extend ACL rules by using the
`LocalAgent.ControllerTrust.` data model directly. Permissions that are added to this data model
will result in extra ACL files in `/cfg/etc/acl/<role>`, which will be picked up by the
`acl-manager`.

### Installation of ACL files by USP Services

Some parts of the data model will be provided by USP Services in the cloud or in a container.
These USP Services need to be able to publish their ACLs to restrict access rights to the data
models they provide. This could be accomplished in either of two ways:

- the LCM agent pushes the USP Service's ACL files to the designated directory; or
- the LCM agent updates the `Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.` data model with permissions for the USP Service's data model.
