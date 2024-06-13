# Bus Agnostic CLI

## __Table of Contents__  

[[_TOC_]]

## Introduction

This ba-cli module provides a set of commands to interact with bus systems and BBF data models. This module can be loaded by the cli-engine [amx-cli](https://gitlab.com/prpl-foundation/components/ambiorix/applications/amx-cli).

The ba-cli module provides functionality to:

- load/unload back-ends.
- connect/disconnect to bus sockets.
- interact with available data models.

This document focuses on the commands provided to interact with the BBF data models.

A quick reference is provided in the [README.md](https://gitlab.com/prpl-foundation/components/ambiorix/modules/amx_cli/mod-ba-cli/-/blob/main/README.md).

## USP Compatible Commands

It is recommended to read the following sections of the [TR-369 USP Specification](https://usp.technology/specification/):

- section [2.4 Data Models](https://usp.technology/specification/#sec:data-models)
- section [2.5 Path Names](https://usp.technology/specification/#sec:path-names)
- section [2.5.2 Using Instance Identifiers in Path Names](https://usp.technology/specification/#sec:using-instance-identifiers-in-path-names)
- section [2.5.4 Searching with Expressions](https://usp.technology/specification/#sec:searching-with-expressions)
- section [2.5.5 Searching by Wildcard](https://usp.technology/specification/#sec:searching-by-wildcard)
- section [2.6.1 Reference Following](https://usp.technology/specification/#sec:reference-following)
- section [7.4 Creating, Updating, and Deleting Objects](https://usp.technology/specification/#sec:creating-updating-and-deleting-objects)
- section [7.4.1 Selecting Objects and Parameters](https://usp.technology/specification/#sec:selecting-objects-and-parameters)

### USP Compatibility Notes

Although these commands are highly compatible with the corresponding USP requests, there are some minor differences.

- In general the USP requests can take multiple paths in one request, the ba-cli commands only take one path. If you need to execute the operation on multiple paths, the same command with a different path each time can be done in sequence.
- The ba-cli GET command depth is interpreted differently than the USP GET request depth. The ba-cli GET depth = USP GET depth - 1. For example, if the USP GET depth is 2, the ba-cli GET depth is 1.<br>
  To get the full (sub)tree with USP a deph of 0 must be provided while with ba-cli a depth of -1 must be provided (which is the default if no depth is provided).
- In USP request the reference following syntax can be used in almost all requests (GET, SET, ADD, DELETE). In ba-cli the reference following syntax is only supported in the GET command. Following all references (USP notation `<PATH>.<PARAM>*+.`) is not supported in ba-cli.
- When using search paths, the expressions used in the search path support both `&&` (AND) and `||` (OR) logical operators in ba-cli, while in USP only `&&` is supported.<br>
  Extract from the USP specification ([2.5.4 Searching with Expressions](https://usp.technology/specification/#sec:searching)):
  > An Expression consists of one or more Expression Components that are concatenated by the AND (&&) logical operator (Note: the OR logical operator is not supported).
- According to USP specification ([2.6.1.2 Search Expressions and Reference Following](https://usp.technology/specification/#sec:search-expressions-and-reference-following)) it is allowed to use reference following within a search expression. This is currently not supported by the ambiorix based data models.
  > The Reference Following and Search Expression mechanisms can be combined. For example, reference the Signal Strength of all Wi-Fi Associated Devices using the “ac” Operating Standard on the “MyHome” SSID, you would use the Path Name: <br>
  > `Device.WiFi.AccessPoint.[SSIDReference+.SSID=="MyHome"].AssociatedDevice.[OperatingStandard=="ac"].SignalStrength`

### GET

The basic get command is used to retrieve the values of the object's parameters in order to learn the current state. It takes a path name as an input and returns the complete tree of all objects and sub-objects of any object matched by the specified expressions, along with each object’s parameters and their values. The search paths specified in a get command can also target an individual parameter within objects to be returned.

The GET command symbol in cli is `?`.

Syntax:

---
> `<PATH>.[<PARAM>]?[<DEPTH>] [<PARAM-FILTER-EXPR>]`
---

This commands has support for:
  - Object paths: `Device.IP.Interface.1.IPv4Address.1.`
  - Parameter paths: `Device.IP.Interface.1.IPv4Address.1.Enable`
  - Search paths: `Device.IP.Interface.[Status=='Error'].`
  - Wildcard paths: `Device.IP.Interface.*.IPv4Address.*.IPAddress`
  - Key addressing: `Device.IP.Interface.[Alias=='lan'].`
  - Any combination of above mentioned path types.

The `<DEPTH>` parameter is optional and can be used to limit the depth of the returned tree. When not provided the full tree is returned.

---
> **NOTE**<br>
> The depth in the cli command is not compatible with the USP specifications. In USP a depth of `0` is considered to be the full tree, in the cli a depth of `0` is the requested object only. In the cli a depth of `0` is the same as in USP depth `1`. The full tree in the cli is a depth of `-1`. The difference between USP and the cli implementation is historical. The earlier version of the USP specification didn't define the depth, while the cli has support for the depth from the beginning. When it was added to the USP specification they decided to use depth '0' as the default value to not break any existing USP controller implementations. Because of this the '0' is the full tree as it was in the earlier versions of USP without the depth.
---

The `<PARAM-FILTER-EXPR>` is optional and can be used to limit the parameters returned for the objects. The filter expression is a boolean expression that evaluates on the meta data of the parameters. Only parameters for which the meta-data is matching are returned.

The parameter meta-data contains the following information:
- flags - these are custom userflags that can be added to the parameter definitions
- type_id - the parameter type identifier
- type_name - the parameter type name
- name - the parameter name
- value - the current parameter value
- attributes - the parameter attributes, this is a fixed set of attributes and is available as a table containing:
  - read-only - is true when the parameter is read-only
  - key - is true when the parameter is a key parameter
  - unique - is true when the parameter is a unique key parameter (not part of a set of key parameters)
  - persistent - is true when the parameter is marked as a persistent. These parameters are save in a text file which is read during boot (boot persistent parameters)
  - counter - is true when the parameter is an instance counter
  - volatile - is true when the parameter is not evented (typically used on statistics parameters)
  - protected - is true when the parameter is not public available
  - private - is true when the parameter is only available to the process owning the data model, these parameters are never returned to the cli.
  - mutable - is true when the value of the parameter can be changed, typically used in combination with the key attribute. By default key parameters can not be changed once set.
  - instance - is true when the parameter is defined in a template object (multi-instance object) and will be inherited by the instances.
  - template - is true when the parameter is defined in a template object (multi-instance object) but will not be inherited by the instances. Parameters with this attribute set can be used directly on the template object (= supported data model). These parameters are not USP compliant.
- validate - a table containing all reported parameter validation functions (constraints). Each entry in this table will have a name (the validation function) and can have extra value(s) which are used by the validation function.

---
> **NOTE**<br>
> Parameter filtering on meta-data is not USP compatible but an ambiorix extension to make it possible to limit the parameters that are returned.
---

Example of a parameter filter expression:

Return only the parameters that have the persistent attribute set or contain in the flags "usersetting"
```
attributes.persistent == true || "usersetting" in flags
```

When a search path or path with wildcards is given and there are no objects matching it the message `No data found` is given, and is not considered an error, the path is in the `supported data model`. If a path to an object is given that is not in the supported data model an error is given (error code 2 - amxd_status_object_not_found).

When the provided path references a multi-instance object, all instances are returned. It would be the same as ending the path with `*` (wildcard symbol).

The `GET` command has support for reference following. When a parameter contains a reference to an object or multiple references to objects (as a comma separated list of references), the [reference following](https://usp.technology/specification/#sec:reference-following) notation can be used. 

---
> **NOTE**<br>
> Following all references in a reference list is not (yet) supported.<br>
> Example:
> ```
> root - * - [bus-cli] (0)
> > Bridging.Bridge.2.Port.1.LowerLayers?
> Bridging.Bridge.2.Port.1.LowerLayers="Device.Bridging.Bridge.2.Port.2.,Device.Bridging.Bridge.2.Port.3."
> ```
> The above parameter is referencing multiple objects, using reference following it is possible to fetch the referenced objects.
> `Bridging.Bridge.2.Port.1.LowerLayers#1+.?0`  
> `Bridging.Bridge.2.Port.1.LowerLayers#2+.?0` 
>
> Accoding to the USP specifications when using `Bridging.Bridge.2.Port.1.LowerLayers#*+.?0 ` all references should be followed.
>
> Search paths in combination with reference following is also not supported.
---

`GET` command examples:

```
root - * - [bus-cli] (2)
 > Device.IP.Interface.1.IPv4Address.1.?
Device.IP.Interface.1.IPv4Address.1.
Device.IP.Interface.1.IPv4Address.1.AddressingType="Static"
Device.IP.Interface.1.IPv4Address.1.Alias="loopback_ipv4"
Device.IP.Interface.1.IPv4Address.1.Enable=1
Device.IP.Interface.1.IPv4Address.1.IPAddress="127.0.0.1"
Device.IP.Interface.1.IPv4Address.1.Status="Enabled"
Device.IP.Interface.1.IPv4Address.1.SubnetMask="255.0.0.0"

root - * - [bus-cli] (0)
 > Device.IP.Interface.[Status=='Error'].?0
No data found

root - * - [bus-cli] (0)
 > Device.IP.Interface.[Status!='Error'&&Enable==true].Alias?0
Device.IP.Interface.1.Alias="loopback"
Device.IP.Interface.2.Alias="wan"
Device.IP.Interface.3.Alias="lan"
Device.IP.Interface.4.Alias="guest"
Device.IP.Interface.5.Alias="lcm"

root - * - [bus-cli] (0)
 > Device.IP.Interface.[Status!='Error'&&Enable==true].Alias? 
Device.IP.Interface.1.Alias="loopback"
Device.IP.Interface.1.IPv4Address.1.Alias="loopback_ipv4"
Device.IP.Interface.1.IPv6Address.1.Alias="loopbackipv6"
Device.IP.Interface.2.Alias="wan"
Device.IP.Interface.2.IPv4Address.1.Alias="primary"
Device.IP.Interface.2.IPv6Address.1.Alias="GUA_RA"
Device.IP.Interface.2.IPv6Address.2.Alias="DHCP"
Device.IP.Interface.2.IPv6Address.4.Alias="LLA"
Device.IP.Interface.2.IPv6Prefix.1.Alias="GUA_IAPD"
Device.IP.Interface.2.IPv6Prefix.2.Alias="GUA_RA"
Device.IP.Interface.3.Alias="lan"
Device.IP.Interface.3.IPv4Address.1.Alias="lan"
Device.IP.Interface.3.IPv4Address.2.Alias="public-lan"
Device.IP.Interface.3.IPv6Address.1.Alias="ULA"
Device.IP.Interface.3.IPv6Address.2.Alias="GUA"
Device.IP.Interface.3.IPv6Address.3.Alias="LLA"
Device.IP.Interface.3.IPv6Prefix.1.Alias="ULA64"
Device.IP.Interface.3.IPv6Prefix.2.Alias="GUA"
Device.IP.Interface.3.IPv6Prefix.3.Alias="GUA_IAPD"
Device.IP.Interface.4.Alias="guest"
Device.IP.Interface.4.IPv4Address.1.Alias="guest"
Device.IP.Interface.4.IPv6Address.1.Alias="GUA"
Device.IP.Interface.4.IPv6Prefix.1.Alias="GUA"
Device.IP.Interface.4.IPv6Prefix.2.Alias="GUA_IAPD"
Device.IP.Interface.5.Alias="lcm"
Device.IP.Interface.5.IPv4Address.1.Alias="lcm"

root - * - [bus-cli] (0)
 > Device.IP.Interface.[Status!='Error'&&Enable==true].IPv4Address.[IPAddress!=""].IPAddress?
Device.IP.Interface.1.IPv4Address.1.IPAddress="127.0.0.1"
Device.IP.Interface.2.IPv4Address.1.IPAddress="192.168.99.100"
Device.IP.Interface.3.IPv4Address.1.IPAddress="192.168.1.1"
Device.IP.Interface.4.IPv4Address.1.IPAddress="192.168.2.1"
Device.IP.Interface.5.IPv4Address.1.IPAddress="192.168.5.1"

root - * - [bus-cli] (0)
 > Device.IP.Interface.2.Router+.?0
Device.Routing.Router.1.
Device.Routing.Router.1.Alias="main"
Device.Routing.Router.1.Enable=1
Device.Routing.Router.1.IPv4ForwardingNumberOfEntries=5
Device.Routing.Router.1.IPv6ForwardingNumberOfEntries=18
Device.Routing.Router.1.Status="Enabled"
```

### ADD

The `ADD` command is used to create new instances of multi-instance objects in the instantiated data model. The `ADD` command symbol in cli is `+`.

Syntax:

---
>  `<PATH>.+ [{<PARAM>=<VALUE>}, ...]`
---

The provided path must reference multi-instance objects and can be a search path or can contain wildcards. If multiple multi-instance objects are matching with the path, for each of them an instance will be added. If a failure occurs then no instances will be added.

It is possible to provide values for each of the parameters. If no value is provided for a parameter, the default value is taken. Providing parameter values is optional unless key parameters are defined in the multi-instance object.

If key parameters are defined in the multi-instance object, values must be provided for these key parameters, except for the `Alias` parameter or if the implementation supports setting a default key parameter.

When the command was executed successfully the newly created object path is returned, including all key parameters and their values. When failed a [libamxd](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxd/-/blob/main/include/amxd/amxd_types.h?ref_type=heads#L77) error code is returned.

The cli is not doing any client side validation of the provided values for parameters.

`ADD` command examples:
```
root - * - [bus-cli] (0)
 > Device.DynamicDNS.Client.+
Device.DynamicDNS.Client.3.
Device.DynamicDNS.Client.3.Alias="cpe-Client-3"

root - * - [bus-cli] (0)
 > Device.DynamicDNS.Client.3.?
Device.DynamicDNS.Client.3.
Device.DynamicDNS.Client.3.Alias="cpe-Client-3"
Device.DynamicDNS.Client.3.Enable=0
Device.DynamicDNS.Client.3.HostnameNumberOfEntries=0
Device.DynamicDNS.Client.3.Interface=""
Device.DynamicDNS.Client.3.LastError="MISCONFIGURATION_ERROR"
Device.DynamicDNS.Client.3.Password=""
Device.DynamicDNS.Client.3.Server=""
Device.DynamicDNS.Client.3.Status="Error_Misconfigured"
Device.DynamicDNS.Client.3.Username=""

root - * - [bus-cli] (0)
 > Device.DynamicDNS.Client.+{Alias="MyDynDNSClient", Enable=true, Interface="Device.IP.Interface.2"}
Device.DynamicDNS.Client.4.
Device.DynamicDNS.Client.4.Alias="MyDynDNSClient"

root - * - [bus-cli] (0)
 > Device.DynamicDNS.Client.[Alias=="MyDynDNSClient"].?
Device.DynamicDNS.Client.4.
Device.DynamicDNS.Client.4.Alias="MyDynDNSClient"
Device.DynamicDNS.Client.4.Enable=1
Device.DynamicDNS.Client.4.HostnameNumberOfEntries=0
Device.DynamicDNS.Client.4.Interface="Device.IP.Interface.2"
Device.DynamicDNS.Client.4.LastError="MISCONFIGURATION_ERROR"
Device.DynamicDNS.Client.4.Password=""
Device.DynamicDNS.Client.4.Server=""
Device.DynamicDNS.Client.4.Status="Error_Misconfigured"
Device.DynamicDNS.Client.4.Username=""

root - * - [bus-cli] (0)
 > IP.Interface.[Enable==true].IPv4Address.+
IP.Interface.1.IPv4Address.2.
IP.Interface.1.IPv4Address.2.Alias="cpe-IPv4Address-2"
IP.Interface.2.IPv4Address.2.
IP.Interface.2.IPv4Address.2.Alias="cpe-IPv4Address-2"
IP.Interface.3.IPv4Address.3.
IP.Interface.3.IPv4Address.3.Alias="cpe-IPv4Address-3"
IP.Interface.4.IPv4Address.2.
IP.Interface.4.IPv4Address.2.Alias="cpe-IPv4Address-2"
IP.Interface.5.IPv4Address.2.
IP.Interface.5.IPv4Address.2.Alias="cpe-IPv4Address-2"
```

### SET

The `SET` command is used to update the parameters of existing objects in the instantiated data model. The `SET` command symbol in cli is `=`.

Syntax:

---
>  `<PATH>.<PARAM>=<VALUE> | <PATH>.{<PARAM>=<VALUE>, ...}`
---

The provided path must reference existing objects and can be a search path or can contain wildcards. If multiple objects are matching with the path all of them will be updated.

If the provided path is not matching any object an error is returned (2 - amxd_status_object_not_found). If one of the provided values is invalid an error is returned (amxd_status_invalid_value). If the set of a single parameter or a single object fails, but multiple parameters are provided or multiple objects match the given path, none of them is modified. When trying to change read-only parameter values an error is returned (15 - amxd_status_read_only).

Using the set command multiple parameters in the matching objects can be changed at once. Provide after the path a table containing the name of each parameter and the new value.

This command will return all changed objects and the changed parameters. Unchanged parameters or parameters that are indirectly changed are not returned.

The cli is not doing any client side validation of the provided values for parameters.

`SET` command examples:

```
root - * - [bus-cli] (0)
 > Device.IP.Interface.[Status!='Error'&&Enable==true].IPv4Address.[IPAddress!=""].Enable=false
Device.IP.Interface.1.IPv4Address.1.
Device.IP.Interface.1.IPv4Address.1.Enable=0
Device.IP.Interface.2.IPv4Address.1.
Device.IP.Interface.2.IPv4Address.1.Enable=0
Device.IP.Interface.3.IPv4Address.1.
Device.IP.Interface.3.IPv4Address.1.Enable=0
Device.IP.Interface.4.IPv4Address.1.
Device.IP.Interface.4.IPv4Address.1.Enable=0
Device.IP.Interface.5.IPv4Address.1.
Device.IP.Interface.5.IPv4Address.1.Enable=0

root - * - [bus-cli] (0)
 > Device.IP.Interface.9.LastChange=635
ERROR: set Device.IP.Interface.9.LastChange failed (15)

root - * - [bus-cli] (0)
 > Device.Firewall.Service.46.{DestPort=22, Enable=true, IPVersion=4, Interface="Device.IP.Interface.2.", Protocol="6"}
Device.Firewall.Service.46.
Device.Firewall.Service.46.DestPort="22"
Device.Firewall.Service.46.Enable=1
Device.Firewall.Service.46.IPVersion=4
Device.Firewall.Service.46.Interface="Device.IP.Interface.2."
Device.Firewall.Service.46.Protocol="6"
```

### DELETE

The `DELETE` command is used to remove instances of multi-instance objects in the instantiated data model. The `DELETE` command symbol in cli is `-`.

Syntax:

---
> `<PATH>.-`
---

The provided path must reference existing instance objects and can be a search path or can contain wildcards. If multiple instance objects are matching the path, all of them will be deleted. If one of the instances fails to delete not a single instance will be deleted and an error is returned.

If the provided path is not matching any instance object an error is returned (2 - amxd_status_object_not_found).

When the delete command is succesful it will return a list of all deleted object paths. This includes all sub-objects of the deleted instances.

`DELETE` command examples:

```
root - * - [bus-cli] (0)
 > Device.Firewall.Service.46.-
Device.Firewall.Service.46.

root - * - [bus-cli] (0)
 > Device.IP.Interface.[Enable==false].- 
Device.IP.Interface.6.
Device.IP.Interface.6.Stats.
Device.IP.Interface.6.IPv4Address.
Device.IP.Interface.6.IPv6Address.
Device.IP.Interface.6.IPv6Address.1.
Device.IP.Interface.6.IPv6Address.2.
Device.IP.Interface.6.IPv6Prefix.
Device.IP.Interface.6.IPv6Prefix.1.
Device.IP.Interface.6.IPv6Prefix.2.
Device.IP.Interface.7.
Device.IP.Interface.7.Stats.
Device.IP.Interface.7.IPv4Address.
Device.IP.Interface.7.IPv4Address.1.
Device.IP.Interface.7.IPv6Address.
Device.IP.Interface.7.IPv6Prefix.
Device.IP.Interface.8.
Device.IP.Interface.8.Stats.
Device.IP.Interface.8.IPv4Address.
Device.IP.Interface.8.IPv6Address.
Device.IP.Interface.8.IPv6Prefix.
Device.IP.Interface.9.
Device.IP.Interface.9.Stats.
Device.IP.Interface.9.IPv4Address.
Device.IP.Interface.9.IPv4Address.1.
Device.IP.Interface.9.IPv6Address.
Device.IP.Interface.9.IPv6Prefix.
Device.IP.Interface.10.
Device.IP.Interface.10.Stats.
Device.IP.Interface.10.IPv4Address.
Device.IP.Interface.10.IPv4Address.1.
Device.IP.Interface.10.IPv6Address.
Device.IP.Interface.10.IPv6Prefix.
Device.IP.Interface.11.
Device.IP.Interface.11.Stats.
Device.IP.Interface.11.IPv4Address.
Device.IP.Interface.11.IPv4Address.1.
Device.IP.Interface.11.IPv6Address.
Device.IP.Interface.11.IPv6Prefix.
```

### GET SUPPORTED DATA MODEL

GetSupportedDM command (referred to informally as GSDM) is used to retrieve the objects, parameters, events, and commands in the supported data model. This allows to learn what the data model implementation understands, rather than its current state.

The gsdm command is different from other commands in that it only returns information about the supported data model. This means that path names to multi-instance objects only address the multi-instance object itself, rather than instances of the multi-instance object, and those path names that contain multi-instance objects in the path name use the `{i}` identifier to indicate their place in the path name.

Syntax:

---
> `gsdm [<OPTIONS>] <PATH>.`
---

The provided path must be a an object path. Search paths, wildcard paths and supported paths (using the `{i}` placeholder for indexes) are not accepted. The returned information will always be the supported data model.

Requesting the supported data model for object `Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.` can be done by using `gsdm Device.PCP.Client.Server.InboundMapping.`

Using options it is possible to get more or less information. The supported options are:

- `-l` - fetch and print first level only
- `-p` - fetch information about the supported parameters of the object
- `-f` - fetch information about the supported operations (commands) of the object (aka data model RPC methods)
- `-e` - fetch information about the supported events of the object.

---
> **NOTE**
> When requesting the supported events, the default data model events will not be listed, they are always available. The events listed will be the events that are specific to the object itself.
---

By default (when no options are specified) the full object tree is returned, starting from the requested object. When printed in human-readable form, some extra information will be printed before each object, parameter, method. This extra information contains some attributes of the object, parameter or method and its type.

For objects the printed attributes can be one or more of these:

- `M` - is a multi-instance object
- `A` - an instance can be added (by a controller or another external process)
- `D` - in instance can be deleted (by a controller or another external process)

For parameters the printed attributes can be one or more of these:
- `R` - the parameter value can be read.
- `W` - the parameter value can be changed (written).

For commands the printed attributes can be one or more of these:
- `U` - unknown command type (assumed to be synchronous)
- `S` - synchronous command
- `A` - asynchronous command.

`GSDM` command examples:

```
root - * - [bus-cli] (0)
 > gsdm -lpfe Device.IP.
... (Object      ) Device.IP.
.RW (bool        ) Device.IP.IPv4Enable
.R. (uint32_t    ) Device.IP.ActivePortNumberOfEntries
.RW (cstring_t   ) Device.IP.ULAPrefix
.R. (uint32_t    ) Device.IP.InterfaceNumberOfEntries
.R. (bool        ) Device.IP.IPv6Capable
.R. (cstring_t   ) Device.IP.IPv6Status
.RW (bool        ) Device.IP.IPv6Enable
.R. (cstring_t   ) Device.IP.IPv4Status
.R. (bool        ) Device.IP.IPv4Capable
MAD (Object      ) Device.IP.ActivePort.{i}.
MAD (Object      ) Device.IP.Interface.{i}.

root - * - [bus-cli] (0)
 > gsdm -pfe Device.PCP.Client.Server.InboundMapping.
MAD (Object      ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.
.RW (uint32_t    ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.Lifetime
.RW (cstring_t   ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.ThirdPartyAddress
.R. (cstring_t   ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.Status
.RW (uint32_t    ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.InternalPort
.RW (bool        ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.Enable
.RW (int32_t     ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.ProtocolNumber
.R. (uint32_t    ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.FilterNumberOfEntries
.RW (uint32_t    ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.SuggestedExternalPort
.R. (uint32_t    ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.AssignedExternalPort
.RW (cstring_t   ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.Description
.R. (cstring_t   ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.AssignedExternalIPAddress
.R. (uint32_t    ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.ErrorCode
.R. (uint32_t    ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.AssignedExternalPortEndRange
.R. (cstring_t   ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.Origin
.RW (cstring_t   ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.SuggestedExternalIPAddress
.R. (cstring_t   ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.Alias
.RW (uint32_t    ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.SuggestedExternalPortEndRange
MAD (Object      ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.Filter.{i}.
.RW (uint32_t    ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.Filter.{i}.PrefixLength
.RW (uint32_t    ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.Filter.{i}.RemotePortEndRange
.R. (cstring_t   ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.Filter.{i}.Alias
.RW (uint32_t    ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.Filter.{i}.RemotePort
.RW (cstring_t   ) Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.Filter.{i}.RemoteHostIPAddress

root - * - [bus-cli] (0)
 > gsdm -f Device.ManagementServer.
... (Object      ) Device.ManagementServer.
..S (Command     ) Device.ManagementServer.updateConnectionRequestURL()
MAD (Object      ) Device.ManagementServer.ManageableDevice.{i}.
```

### GET INSTANTIATED DATA MODEL

The get instantiated data model command takes a path name to an object and will return the instances of that object that exist and possibly any multi-instance sub-objects that exist as well as their instances. This is used for getting a quick map of the instances that are currently available, and their (unique) key parameters, so that they can be addressed and manipulated later.

Syntax:

---
> `gi [<OPTIONS>] <PATH>.`
---

The path must reference a multi-instance object and can not be a search path or a path with wildcards.

When the referenced path doesn't exist or is not a multi-instance object an empty result is returned.

By default all instances will be returned, also instances of multi-instance sub-objects. Using the option `-l` only the first level is returned.

`GI` command example:

```
root - * - [bus-cli] (21)
 > gi Device.IP.Interface.               
Device.IP.Interface.1.
Device.IP.Interface.1.Alias="loopback"
Device.IP.Interface.1.IPv4Address.1.
Device.IP.Interface.1.IPv4Address.1.Alias="loopback_ipv4"
Device.IP.Interface.1.IPv6Address.1.
Device.IP.Interface.1.IPv6Address.1.Alias="loopbackipv6"
Device.IP.Interface.10.
Device.IP.Interface.10.Alias="iptv"
Device.IP.Interface.10.IPv4Address.1.
Device.IP.Interface.10.IPv4Address.1.Alias="primary"
Device.IP.Interface.11.
Device.IP.Interface.11.Alias="mgmt"
Device.IP.Interface.11.IPv4Address.1.
Device.IP.Interface.11.IPv4Address.1.Alias="primary"
Device.IP.Interface.2.
Device.IP.Interface.2.Alias="wan"
Device.IP.Interface.2.IPv4Address.1.
Device.IP.Interface.2.IPv4Address.1.Alias="primary"
Device.IP.Interface.2.IPv6Address.1.
Device.IP.Interface.2.IPv6Address.1.Alias="GUA_RA"
Device.IP.Interface.2.IPv6Address.2.
Device.IP.Interface.2.IPv6Address.2.Alias="DHCP"
Device.IP.Interface.2.IPv6Address.4.
Device.IP.Interface.2.IPv6Address.4.Alias="LLA"
Device.IP.Interface.2.IPv6Prefix.1.
Device.IP.Interface.2.IPv6Prefix.1.Alias="GUA_IAPD"
Device.IP.Interface.2.IPv6Prefix.2.
Device.IP.Interface.2.IPv6Prefix.2.Alias="GUA_RA"
Device.IP.Interface.3.
Device.IP.Interface.3.Alias="lan"
Device.IP.Interface.3.IPv4Address.1.
Device.IP.Interface.3.IPv4Address.1.Alias="lan"
Device.IP.Interface.3.IPv4Address.2.
Device.IP.Interface.3.IPv4Address.2.Alias="public-lan"
Device.IP.Interface.3.IPv6Address.1.
Device.IP.Interface.3.IPv6Address.1.Alias="ULA"
Device.IP.Interface.3.IPv6Address.2.
Device.IP.Interface.3.IPv6Address.2.Alias="GUA"
Device.IP.Interface.3.IPv6Address.3.
Device.IP.Interface.3.IPv6Address.3.Alias="LLA"
Device.IP.Interface.3.IPv6Prefix.1.
Device.IP.Interface.3.IPv6Prefix.1.Alias="ULA64"
Device.IP.Interface.3.IPv6Prefix.2.
Device.IP.Interface.3.IPv6Prefix.2.Alias="GUA"
Device.IP.Interface.3.IPv6Prefix.3.
Device.IP.Interface.3.IPv6Prefix.3.Alias="GUA_IAPD"
Device.IP.Interface.4.
Device.IP.Interface.4.Alias="guest"
Device.IP.Interface.4.IPv4Address.1.
Device.IP.Interface.4.IPv4Address.1.Alias="guest"
Device.IP.Interface.4.IPv6Address.1.
Device.IP.Interface.4.IPv6Address.1.Alias="GUA"
Device.IP.Interface.4.IPv6Prefix.1.
Device.IP.Interface.4.IPv6Prefix.1.Alias="GUA"
Device.IP.Interface.4.IPv6Prefix.2.
Device.IP.Interface.4.IPv6Prefix.2.Alias="GUA_IAPD"
Device.IP.Interface.5.
Device.IP.Interface.5.Alias="lcm"
Device.IP.Interface.5.IPv4Address.1.
Device.IP.Interface.5.IPv4Address.1.Alias="lcm"
Device.IP.Interface.6.
Device.IP.Interface.6.Alias="wan6"
Device.IP.Interface.6.IPv6Address.1.
Device.IP.Interface.6.IPv6Address.1.Alias="GUA_RA"
Device.IP.Interface.6.IPv6Address.2.
Device.IP.Interface.6.IPv6Address.2.Alias="DHCP"
Device.IP.Interface.6.IPv6Prefix.1.
Device.IP.Interface.6.IPv6Prefix.1.Alias="GUA_IAPD"
Device.IP.Interface.6.IPv6Prefix.2.
Device.IP.Interface.6.IPv6Prefix.2.Alias="GUA_RA"
Device.IP.Interface.7.
Device.IP.Interface.7.Alias="DSLite-entry"
Device.IP.Interface.7.IPv4Address.1.
Device.IP.Interface.7.IPv4Address.1.Alias="primary"
Device.IP.Interface.8.
Device.IP.Interface.8.Alias="DSLite-exit"
Device.IP.Interface.9.
Device.IP.Interface.9.Alias="voip"
Device.IP.Interface.9.IPv4Address.1.
Device.IP.Interface.9.IPv4Address.1.Alias="primary"
```

### OPERATE (aka data model RPC)

Additional methods (operations) are and can be defined in the data model. Operations are generally defined on an object, using the “command” attribute.

Invoking data model methods is very intinutive, it is just like calling a method in most scripting/programming languages.

Syntax:

---
> `<PATH>.<METHOD>([<ARG>=<VALUE> [, <ARG>=<VALUE>] ...])`
---

The path must reference to an object in the instantiated data model and can be a search path or wildcard path. When multiple objects are matching the provided path the method is invoked on all of them.

When no object is found then an error will be returned, when the method is not supported by the referenced object(s) an error will be returned.

Arguments must always be provided by name, the order of the arguments is not important. A method can have mandatory arguments and optional arguments. Always check the documentation of the method about the arguments.

The returned value and returned out arguments depends on the invoked method.

When in interactive mode all method calls are done asynchronously, while in automated mode all method calls are done synchronously.

`OPERATE` command examples:

```
root - * - [bus-cli] (0)
 > Device.ManagementServer.updateConnectionRequestURL()        
ERROR: call Device.ManagementServer.updateConnectionRequestURL() failed with status 7

root - * - [bus-cli] (7)
 > Device.ManagementServer.updateConnectionRequestURL(host="192.168.1.100",port=1970,update=yes)

root - * - [bus-cli] (0)
 > Device.SoftwareModules.InstallDU(URL = "docker://docker-prpl.sahrd.io/qa/hgwui/smallshell_rpi_oci:v1", UUID = "00000000-0000-5000-b000-000000000000", Username = "lcm_qa_test", Password = "<&Dm\\E5cj)aeS2t3Bn", ExecutionEnvRef = "generic")
Device.SoftwareModules.InstallDU() returned
[
    ""
]

root - * - [bus-cli] (0)
 > 
 ```

## Ambiorix Extenstions

### CD

When doing multiple operations in sequence on a certain object or sub-tree, it can become very cumbersome to always have to enter the full path of the object. Using the `cd` command it is possible to select an object in the data model. After that a relative path can be used.

Syntax:

---
> `cd <PATH>.`
---

The provided path must be an object path in the instantiated data model.
To go back to the root of the data model use '.'.

When the object is selected the prompt will change and print the path of the selected object in front of the ">" symbol.

`DELETE` command example:

```
root - * - [bus-cli] (0)
 > cd Device.Firewall.Service.

root - * - [bus-cli] (2)
Device.Firewall.Service. > 43.?0        
Device.Firewall.Service.43.
Device.Firewall.Service.43.Action="Accept"
Device.Firewall.Service.43.Alias="cwmpd_conn_request"
Device.Firewall.Service.43.DestPort="50805"
Device.Firewall.Service.43.Enable=1
Device.Firewall.Service.43.ICMPType=-1
Device.Firewall.Service.43.IPVersion=4
Device.Firewall.Service.43.Interface="Device.IP.Interface.2."
Device.Firewall.Service.43.Protocol="6"
Device.Firewall.Service.43.SourcePrefixes=""
Device.Firewall.Service.43.Status="Enabled"
Device.Firewall.Service.43.X_PRPL-COM_Log=1
```

### LS or LIST

The command 'ls' or 'list' can provide a list of all available parameters, functions and/or sub-objects of a given path.

Syntax:

---
> `ls [OPTIONS] [<PATH>.]`
---

This is the only command that can provide information without providing a path.

---
> **NOTE**<br>
> When not using a path with the list command it is possible that some restrictions apply. The restrictions depend on the protocol or bus system used. Most of the time only object names are possible to list when no path is provided.
---

If a path is provided it must be a path to an object in the instantiated data model, search paths or wildcards paths are not supported.

Using the options it is possible to indicate what must be listed.

The supported options are:

- `-p` - this will list all parameters.
- `-f` - this will list all functions (operators).
- `-r` - list recursively, provide the full tree starting from the provided path.

---
> **NOTE**<br>
> When no path is provided the list command will ignore the given options. Most of the time it is only possible to list the available root objects. Some protocols or bus systems don't have support for discovery, in that case the list command without a path will not return anything. 
---

`LIST` command example:

```
root - * - [bus-cli] (0)
 > ls -p Device.IP.Interface.1.
Device.IP.Interface.1.
Device.IP.Interface.1.AutoIPEnable
Device.IP.Interface.1.IPv4AddressNumberOfEntries
Device.IP.Interface.1.IPv6AddressNumberOfEntries
Device.IP.Interface.1.Status
Device.IP.Interface.1.LowerLayers
Device.IP.Interface.1.MaxMTUSize
Device.IP.Interface.1.Enable
Device.IP.Interface.1.IPv6Enable
Device.IP.Interface.1.Name
Device.IP.Interface.1.Router
Device.IP.Interface.1.Type
Device.IP.Interface.1.Loopback
Device.IP.Interface.1.IPv4Enable
Device.IP.Interface.1.IPv6PrefixNumberOfEntries
Device.IP.Interface.1.ULAEnable
Device.IP.Interface.1.LastChange
Device.IP.Interface.1.Alias
Device.IP.Interface.1.Stats
Device.IP.Interface.1.IPv4Address
Device.IP.Interface.1.IPv6Address
Device.IP.Interface.1.IPv6Prefix
```

### DUMP

Fetches the full object, parameter and method definitions. 

Syntax:

---
> `dump [<OPTIONS>] <PATH>.`
---

The provided path must reference an object in the instantiated data model.

Using the options extra information can be fetched of the object.
The available options are:

- `-r` - recursive. Dump the full tree starting from the object provided in the path.
- `-p` - parameters. Dump information about the supported parameters.
- `-f` - functions. Dump information about the supported methods, include all supported arguments.
- `-e` - events. Dump information about the supported events. The default data model events will not be shown, only the object specific events.

This command will by default only print information about the requested object without any parameters, functions or events.

When in interactive mode (and no JSON output) the information will be printed in human-readable format. 

The general output format for parameters and objects is:
> `<ATTR> <ACCESS> <TYPE> <PATH>[.<NAME>=<VALUE>]`

For functions this becomes:
> `<ATTR> <ACCESS> <RETURN TYPE> <PATH>.<NAME>([<ATTR> <TYPE> <NAME>][,<ATTR> <TYPE> <NAME>]... )`

Parameters on which constraints are defined can provide information about the constraints that are applied.

Attributes of objects, parameters and functions can be one of these:
 - `P` = persistent - parameter/object is persistent
 - `R` = read-only - parameter is read-only, when set on multi-instance objects it will not be possible for "external" processes to add or delete instances. 
 - `M` = mutable (in combination with key) - parameter value can be changed, by default key parameters can not be changed.
 - `U` = unique (in combination with key) - parameter value must be unique in the set of instances of the multi-instance object 
 - `K` = key - parameter is a key parameter, the combiniation of all key parameters (not unique keys) must be unique in the set of instances of the multi-instance object
 - `C` = instance counter - parameter is an instance counter. These kind of parameters keep track of the number of instances of a multi-instance object
 - `V` = volatile - the parameter value can change a lot and will not be evented when changed (usefull for statistic parameters).
 - `A` = asynchronous function - the method is intended to be called in a asynchronous manner, can take a while to execute.

Attributes of method arguments can be one of these
 - `I` = in argument - the argument is an input argument
 - `O` = out argument - the argument is an output argument (no need to provide it when calling the method)
 - `S` = strict - the argument type is strict, make sure when calling the method that arguments with this attribute is of the correct type.
 - `M` = madatory - the argument is mandatory, if the attribute is not set on an argument the argument is optional.

`DUMP` command example:

```
root - * - [bus-cli] (0)
 > dump -pf Device.ManagementServer.
P....... <public>      singleton Device.ManagementServer.
P....... <public>         uint32 Device.ManagementServer.DefaultActiveNotificationThrottle=0
P....... <public>           bool Device.ManagementServer.EnableCWMP=1
P....... <public>         string Device.ManagementServer.Username=cdrouter
                                     check_maximum_length 256
P....... <public>         string Device.ManagementServer.ConnectionRequestUsername=acs
                                     check_maximum_length 256
P....... <public>         string Device.ManagementServer.Password=
                                     check_maximum_length 256
P....... <public>           bool Device.ManagementServer.PeriodicInformEnable=1
P....... <public>         uint32 Device.ManagementServer.X_PRPL-COM_MaxConnectionRequest=50
                                     check_minimum 1
P....... <public>         string Device.ManagementServer.ConnectionRequestPassword=
                                     check_maximum_length 256
P....... <public>         uint32 Device.ManagementServer.PeriodicInformInterval=432000
                                     check_minimum 1
P....... <public>       datetime Device.ManagementServer.PeriodicInformTime=0001-01-01T00:00:00Z
P....... <public>         string Device.ManagementServer.InstanceMode=InstanceNumber
                                     check_enum ["InstanceNumber","InstanceAlias"]
.R...... <public>         string Device.ManagementServer.ConnectionRequestURL=http://192.168.99.100:50805/MtP6rM5JXzqUJ5XZ
P....... <public>         uint32 Device.ManagementServer.X_PRPL-COM_FreqConnectionRequest=3600
                                     check_minimum 60
P....... <public>           bool Device.ManagementServer.InstanceWildcardsSupported=1
P....... <public>         string Device.ManagementServer.URL=http://acs-download.qacafe.com
.R...... <public>           bool Device.ManagementServer.AutoCreateInstances=0
.R...C.. <public>         uint32 Device.ManagementServer.ManageableDeviceNumberOfEntries=0
........ <public>         uint32 Device.ManagementServer.ManageableDeviceNotificationLimit=0
P....... <public>         string Device.ManagementServer.ParameterKey=
P....... <public>           bool Device.ManagementServer.UpgradesManaged=1
.R...... <public>           bool Device.ManagementServer.AliasBasedAddressing=1
........ <public>           void Device.ManagementServer.updateConnectionRequestURL(I..M bool update, I... string host, I... uint16 port)
........ <public>     multi-inst Device.ManagementServer.ManageableDevice.
```

### RESOLVE

Resolves the given path. This useful when using a search or wildcard path. This command will print all matching object paths at that moment.

Syntax:

---
> `resolve <PATH>.`
---

The path can be an object path or a search path.

`RESOLVE` command example:

```
root - * - [bus-cli] (0)
 > resolve Device.IP.Interface.[Enable==false&&(IPv4AddressNumberOfEntries>0||IPv6AddressNumberOfEntries>0)].
Device.IP.Interface.9.
Device.IP.Interface.10.
Device.IP.Interface.11.
Device.IP.Interface.6.
Device.IP.Interface.7.

root - * - [bus-cli] (0)
 > resolve Device.IP.Interface.[Alias=="voip"].                                                              
Device.IP.Interface.9.

root - * - [bus-cli] (0)
 > resolve Device.IP.Interface.9.              
Device.IP.Interface.9.
```

### SUBSCRIBE

Subscribe for events from a object and its sub-objects. To limit the number of printed events a filter can be provided. When a filter is provided only events matching the filter will be printed. The `SUBSCRIBE` command symbol in cli is `?&`.

When no event filter is supplied with the command, all recieved events on that object path (or one of its subobjects) will be printed.

When a parameter path is provided, it will automatically apply an event filter, so that only events containing the parameter name will be printed.

The default data model events (dm:object-changed, dm:instance-added, dm:instance-removed, dm:object-added, dm:object-removed, ...) will be printed in human-readable format. Custom events will always be printed in `raw event` format.

To see all details of all events, without it being `pretty` printed, the variable `raw-event` can be set to true.

```
root - * - [bus-cli] (0)
 > setenv raw-event=true
> !amx variable  raw-event=true
```

Subscriptions stay active until either the cli process is stopped or the `unsubscribe` command is invoked on the same path.

When mutliple subscriptions are taken on the same object path it is possible that the events are printed multiple times (once for each subscription, depending on the applied event filter if any.)

Syntax:

---
> `<PATH>.[<PARAM>]?& [<EVENT-FILTER>]`
---


`SUBSCRIBE` command example:

```
root - * - [bus-cli] (0)
 > Device.IP.Interface.[Enable==true].?& notification == "dm:object-changed" && contains("parameters.Status")
Added subscription for Device.IP.Interface.[Enable==true].
Using filter   notification == "dm:object-changed" && contains("parameters.Status")

root - * - [bus-cli] (0)
 > Device.IP.Interface.2.Enable=true 
Device.IP.Interface.2.
Device.IP.Interface.2.Enable=1

[2023-12-04T17:02:09Z] Event dm:object-changed received from Device.IP.Interface.2.IPv6Prefix.1.
<  dm:object-changed> Device.IP.Interface.2.IPv6Prefix.1.Status = Error -> Enabled

[2023-12-04T17:02:09Z] Event dm:object-changed received from Device.IP.Interface.3.IPv6Prefix.2.
<  dm:object-changed> Device.IP.Interface.3.IPv6Prefix.2.Status = Error -> Enabled

[2023-12-04T17:02:10Z] Event dm:object-changed received from Device.IP.Interface.3.IPv6Prefix.3.
<  dm:object-changed> Device.IP.Interface.3.IPv6Prefix.3.Status = Error -> Enabled

[2023-12-04T17:02:10Z] Event dm:object-changed received from Device.IP.Interface.4.IPv6Prefix.1.
<  dm:object-changed> Device.IP.Interface.4.IPv6Prefix.1.Status = Error -> Enabled

[2023-12-04T17:02:10Z] Event dm:object-changed received from Device.IP.Interface.4.IPv6Prefix.2.
<  dm:object-changed> Device.IP.Interface.4.IPv6Prefix.2.Status = Error -> Enabled

[2023-12-04T17:02:10Z] Event dm:object-changed received from Device.IP.Interface.3.IPv6Address.2.
<  dm:object-changed> Device.IP.Interface.3.IPv6Address.2.Status = Error -> Enabled

[2023-12-04T17:02:10Z] Event dm:object-changed received from Device.IP.Interface.4.IPv6Address.1.
<  dm:object-changed> Device.IP.Interface.4.IPv6Address.1.Status = Error -> Enabled

[2023-12-04T17:02:10Z] Event dm:object-changed received from Device.IP.Interface.3.IPv6Address.2.
<  dm:object-changed> Device.IP.Interface.3.IPv6Address.2.Status = Enabled -> Error

[2023-12-04T17:02:10Z] Event dm:object-changed received from Device.IP.Interface.4.IPv6Address.1.
<  dm:object-changed> Device.IP.Interface.4.IPv6Address.1.Status = Enabled -> Error

[2023-12-04T17:02:10Z] Event dm:object-changed received from Device.IP.Interface.3.IPv6Address.2.
<  dm:object-changed> Device.IP.Interface.3.IPv6Address.2.Status = Error -> Enabled

[2023-12-04T17:02:10Z] Event dm:object-changed received from Device.IP.Interface.4.IPv6Address.1.
<  dm:object-changed> Device.IP.Interface.4.IPv6Address.1.Status = Error -> Enabled
```

### UNSUBSCRIBE

To remove a subscription the unsubscribe command can be invoked. The `UNSUBSCRIBE` command symbol in cli is `?$`.

When multiple subscriptions were taken on the same path (with or without filter) it will close the first subscription for that path. To close them all, you will need to do multiple unsubscribes for that path.

Syntax:

---
> `<PATH>.?$`
---

`UNSUBSCRIBE` command example:

```
root - * - [bus-cli] (0)
 > subscriptions
Subscription path    : Device.IP.Interface
    Requested path   : Device.IP.Interface.

Subscription path    : Device.Firewall.Service
    Requested path   : Device.Firewall.Service.

root - * - [bus-cli] (0)
 > Device.Firewall.Service.?$
Remove subscription for [Device.Firewall.Service]

root - * - [bus-cli] (0)
 > subscriptions
Subscription path    : Device.IP.Interface
    Requested path   : Device.IP.Interface.
```

### SUBSRIPTIONS

This command provides an overview of all open subscriptions. When a subscription was taken using a search path, it will display all matching objects.

When no active subscriptions are available a message will be printed.

Syntax:

---
> `subscriptions`
---

`SUBSCRIPTIONS` command example:

```
root - * - [bus-cli] (0)
 > subscriptions
Subscription path    : Device.IP.Interface
    Applied filter   :   notification == "dm:object-changed" && contains("parameters.Status")
    Requested path   : Device.IP.Interface.[Enable==true].
    Matching objects : Device.IP.Interface.1.
                       Device.IP.Interface.2.
                       Device.IP.Interface.3.
                       Device.IP.Interface.4.
                       Device.IP.Interface.5.

root - * - [bus-cli] (0)
 > Device.IP.Interface.?$
Remove subscription for [Device.IP.Interface]

root - * - [bus-cli] (0)
 > subscriptions
No subscriptions taken
```

### REQUESTS

Lists all pending RPC requests. Typically this will be an empty list.

Syntax:

---
> `requests`
---


### HELP

The help command provides more information about the available commands or more information about a specific command.

Syntax:

---
> `help [<CMD>]`
---

`HELP` command examples:

```
root - * - [bus-cli] (0)
 > help

help [<CMD>]
        Print this help

cd <PATH>
        Sets the default object path

list [<OPTIONS>] [<PATH>] | ls <SEARCH PATH>
        List objects.

ls [<OPTIONS>] [<PATH>]
        List objects.

dump [<OPTIONS>] <PATH>
        Dump object details

resolve <PATH>
        Expand a search path to all matching object paths

subscriptions
        List all open event subscriptions

requests
        List all pending RPC requests

gsdm [<OPTIONS>] <PATH>
        Get supported data model

gi [<OPTIONS>] <PATH>
        Get instances

<PATH>.[<PARAM>]?[<DEPTH>|&|$]
        Get object parameters

<PATH>.<PARAM>=<VALUE> | <PATH>.{<PARAM>=<VALUE>, ...}
        Changes the value of parameter(s)

<PATH>.+ [{<PARAM>=<VALUE>}, ...]
        Adds a new instance of a multi-instance object

<PATH>.-
        Deletes an instance of a multi-instance object

<PATH>.<METHOD>([<ARG1>=<VALUE>][,<ARG2>=<VALUE>]...)
        Calls a method on the specified object path
        
root - * - [bus-cli] (0)
 > help ?

Get object parameters
Usage: <PATH>[<PARAM>]?[<DEPTH>|&|$]

Get all object parameters.
Gets all object parameters and prints the parameter pathsincluding the values in a flat list
When '&' is added, a subscription is taken on the object tree
and events will be printed in human readable form when received
Set variable 'raw-event' to true to print the events as is
When '$' is added, the subscription for that object tree is closed

This command supports json output format.

This commands has support for:
  - Object paths.......: Device.IP.Interface.1.IPv4Address.1.
  - Parameter paths....: Device.IP.Interface.1.IPv4Address.1.Enable
  - Search paths.......: Device.IP.Interface.[Status=='Error'].
  - Wildcard paths.....: Device.IP.Interface.*.IPv4Address.*.IPAddress
  - Key addressing.....: Device.IP.Interface.[Alias=='lan'].
  - Reference following: Device.IP.Interface.1.LowerLayers#1+.

For more information about these different path types read 
section 2.5 Path Names of https://usp.technology/specification/index.html
```

## Tips & Tricks

### Automated Scripts

The bus agnostic cli can be started in many different ways, each with its own advantages and disadvantages. 

By default it will be started in interactive mode. This will provide a prompt and interpreted colored output, which is intended to make the output more readable for humans.

It is however possible to use this tool in shell scripting mode. In this mode the output will be uncolored. It can provide JSON formatted output. This can be useful for automated processing. On PrplOs builds (based on OpenWrt) a tool [jsonfilter](https://openwrt.org/docs/guide-developer/jshn) is available which can be used to fetch or filter parts of the json output.

To execute a single command with json output use:
```
ba-cli -j <command>
```

To execute multiple-commands in automated mode with json output create a text file containg the commands that must be executed, one command per line, then start the cli using as input the file:
```
ba-cli -aj < <commands-file>
```

The option `-a` will make sure that the cli stops when all commands that are in the file are executed. As an alternative the last command in the file could be `exit`. If `-a` option or `exit` command in the file are ommited, the cli tool will switch to interactive mode.

It is also possible to pipe the output of an other process to the cli. 
```
cat <commands-file> | ba-cli -aj
```

The command will always be printed as well, this is not in JSON format and is always preceded with a `>` symbol.

---
> **NOTE**<br>
> The following two lines will do exactly the same thing:<br>
> `ba-cli -aj < /tmp/commands`<br>
> `cat /tmp/commands | ba-cli -aj`<br>
---

If you need to execute the same commands over and over again while testing or debugging, but depending on the situation you need to execute some extra command, you could create a file with the initial set of commands, and then let the cli switch to interactive mode.

Examples:
```
# Execute a set of commands in a file and exit, human readable output
root@prplOS:~# ba-cli -a < /tmp/commands
> Device.IP.Interface.[Status!='Error'&&Enable==true].IPv4Address.[IPAddress!=""].IPAddress?
Device.IP.Interface.1.IPv4Address.1.IPAddress="127.0.0.1"
Device.IP.Interface.2.IPv4Address.1.IPAddress="192.168.99.100"
Device.IP.Interface.3.IPv4Address.1.IPAddress="192.168.1.1"
Device.IP.Interface.4.IPv4Address.1.IPAddress="192.168.2.1"
Device.IP.Interface.5.IPv4Address.1.IPAddress="192.168.5.1"
> Device.IP.Interface.[Status!='Error'&&Enable==true].IPv6Address.[IPAddress!=""].IPAddress?
Device.IP.Interface.1.IPv6Address.1.IPAddress="::1"
Device.IP.Interface.2.IPv6Address.1.IPAddress="2a02:1802:94:99:c23c:4ff:febe:3310"
Device.IP.Interface.2.IPv6Address.4.IPAddress="fe80::c23c:4ff:febe:3310"
Device.IP.Interface.3.IPv6Address.2.IPAddress="2a02:1802:94:4000::1"
Device.IP.Interface.3.IPv6Address.3.IPAddress="fe80::c23c:4ff:febe:3311"
Device.IP.Interface.4.IPv6Address.1.IPAddress="2a02:1802:94:4001::1"

# Execute a set of commands in a file and exit, JSON output
root@prplOS:~# ba-cli -aj < /tmp/commands
> Device.IP.Interface.[Status!='Error'&&Enable==true].IPv4Address.[IPAddress!=""].IPAddress?
[{"Device.IP.Interface.2.IPv4Address.1.":{"IPAddress":"192.168.99.100"},"Device.IP.Interface.5.IPv4Address.1.":{"IPAddress":"192.168.5.1"},"Device.IP.Interface.1.IPv4Address.1.":{"IPAddress":"127.0.0.1"},"Device.IP.Interface.4.IPv4Address.1.":{"IPAddress":"192.168.2.1"},"Device.IP.Interface.3.IPv4Address.1.":{"IPAddress":"192.168.1.1"}}]
> Device.IP.Interface.[Status!='Error'&&Enable==true].IPv6Address.[IPAddress!=""].IPAddress?
[{"Device.IP.Interface.3.IPv6Address.2.":{"IPAddress":"2a02:1802:94:4000::1"},"Device.IP.Interface.2.IPv6Address.1.":{"IPAddress":"2a02:1802:94:99:c23c:4ff:febe:3310"},"Device.IP.Interface.3.IPv6Address.3.":{"IPAddress":"fe80::c23c:4ff:febe:3311"},"Device.IP.Interface.1.IPv6Address.1.":{"IPAddress":"::1"},"Device.IP.Interface.4.IPv6Address.1.":{"IPAddress":"2a02:1802:94:4001::1"},"Device.IP.Interface.2.IPv6Address.4.":{"IPAddress":"fe80::c23c:4ff:febe:3310"}}]

# Execute a set of commands and switch to interactive mode
root@prplOS:~# ba-cli < /tmp/commands

Copyright (c) 2020 - 2023 SoftAtHome
amxcli version : 0.4.2

!amx silent true

                   _  ___  ____
  _ __  _ __ _ __ | |/ _ \/ ___|
 | '_ \| '__| '_ \| | | | \___ \
 | |_) | |  | |_) | | |_| |___) |
 | .__/|_|  | .__/|_|\___/|____/
 |_|        |_| based on OpenWrt
 -----------------------------------------------------
 Bus Agnostic CLI
 -----------------------------------------------------

root - * - [bus-cli] (0)
 > Device.IP.Interface.[Status!='Error'&&Enable==true].IPv4Address.[IPAddress!=""].IPAddress?
Device.IP.Interface.1.IPv4Address.1.IPAddress="127.0.0.1"
Device.IP.Interface.2.IPv4Address.1.IPAddress="192.168.99.100"
Device.IP.Interface.3.IPv4Address.1.IPAddress="192.168.1.1"
Device.IP.Interface.4.IPv4Address.1.IPAddress="192.168.2.1"
Device.IP.Interface.5.IPv4Address.1.IPAddress="192.168.5.1"

root - * - [bus-cli] (0)
 > Device.IP.Interface.[Status!='Error'&&Enable==true].IPv6Address.[IPAddress!=""].IPAddress?
Device.IP.Interface.1.IPv6Address.1.IPAddress="::1"
Device.IP.Interface.2.IPv6Address.1.IPAddress="2a02:1802:94:99:c23c:4ff:febe:3310"
Device.IP.Interface.2.IPv6Address.4.IPAddress="fe80::c23c:4ff:febe:3310"
Device.IP.Interface.3.IPv6Address.2.IPAddress="2a02:1802:94:4000::1"
Device.IP.Interface.3.IPv6Address.3.IPAddress="fe80::c23c:4ff:febe:3311"
Device.IP.Interface.4.IPv6Address.1.IPAddress="2a02:1802:94:4001::1"

root - * - [bus-cli] (0)
 > 
 ```

### Chaining Reference Following

It is possible to chain reference following. This can be very handy when you try to fetch the correct information from the data model.

As an example take the `Device.Bridging.` data model.

```
root - * - [bus-cli] (0)
 > Device.Bridging.Bridge.1.Port.1.LowerLayers? 
Device.Bridging.Bridge.1.Port.1.LowerLayers="Device.Bridging.Bridge.1.Port.2.,Device.Bridging.Bridge.1.Port.3.,Device.Bridging.Bridge.1.Port.4.,Device.Bridging.Bridge.1.Port.5.,Device.Bridging.Bridge.1.Port.6.,Device.Bridging.Bridge.1.Port.7.,Device.Bridging.Bridge.1.Port.8."
```

The parameter `LowerLayers` of object `Device.Bridging.Bridge.1.Port.1.` is referencing a list of objects, where each of them has again a `LowerLayers` parameter.

```
root - * - [bus-cli] (0)
 > Device.Bridging.Bridge.1.Port.2.LowerLayers?
Device.Bridging.Bridge.1.Port.2.LowerLayers="Device.Ethernet.Interface.1."
```

This lower layer parameter is referencing the real interface.

To get the object in the data model that is the real interface reference following can be used in a chain

```
root - * - [bus-cli] (0)
 > Device.Bridging.Bridge.1.Port.1.LowerLayers#1+.LowerLayers+.?0
Device.Ethernet.Interface.1.
Device.Ethernet.Interface.1.Alias="ETH0"
Device.Ethernet.Interface.1.CurrentBitRate=1000
Device.Ethernet.Interface.1.CurrentDuplexMode="Full"
Device.Ethernet.Interface.1.DuplexMode="Auto"
Device.Ethernet.Interface.1.EEECapability=0
Device.Ethernet.Interface.1.EEEEnable=0
Device.Ethernet.Interface.1.Enable=1
Device.Ethernet.Interface.1.LastChange=31350
Device.Ethernet.Interface.1.LowerLayers=""
Device.Ethernet.Interface.1.MACAddress="C0:3C:04:BE:33:10"
Device.Ethernet.Interface.1.MaxBitRate=0
Device.Ethernet.Interface.1.Name="eth0"
Device.Ethernet.Interface.1.Status="Up"
Device.Ethernet.Interface.1.Upstream=0
```

### Verifying ACLs with CLI

Role based access control is supported by the data model implementations. In general applications can be deviced in trusted and untrusted applications. The cli is considered as a trusted application, while an application that provides external access to the data model is considered an untrusted application. Examples of untrusted applications are: 

- usp-agent - provides access to the data model for external usp-controllers
- amx-fcgi - provides access to the data model through a web-server for web-ui.

These kind of application must authenticate themselves and then a role is assigned to them. For each role a set of access controls can be defined, these ACLs define what the role can do.

To be able to test the defined ACLs for your data model implementation the cli can be a useful tool. The cli can be started with the option `-u` followed by a role name. When started with this option a set of cli variables will be set, to see the values of these variables use `printenv`

```
root@prplOS:~# ba-cli -u admin
Copyright (c) 2020 - 2023 SoftAtHome
amxcli version : 0.4.2

!amx silent true

                   _  ___  ____
  _ __  _ __ _ __ | |/ _ \/ ___|
 | '_ \| '__| '_ \| | | | \___ \
 | |_) | |  | |_) | | |_| |___) |
 | .__/|_|  | .__/|_|\___/|____/
 |_|        |_| based on OpenWrt
 -----------------------------------------------------
 Bus Agnostic CLI
 -----------------------------------------------------

root - * - [bus-cli] (0)
 > printenv
> !amx variable
acl-dir = "/cfg/etc/acl/"
acl-enabled = true
automated = false
cli-name = "bus-cli"
color = {
    bg-black = "",
    bg-green = "",
    bg-red = "",
    blue = "",
    green = "",
    red = "",
    reset = "",
    white = "",
    yellow = ""
}
connection = "*"
init-script = "/etc/amx/cli/ba-cli.init"
no-colors = false
no-logo = true
role = "admin"
rv = 0
time = "2023-12-05T17:48:55Z"
pcb = {
    acl-dir = "/cfg/etc/acl/",
    uris = [
        "pcb:/var/run/pcb_sys"
    ]
}
ubus = {
    uris = [
        "ubus:/var/run/ubus/ubus.sock"
    ],
    watch-ubus-events = true
}
```

The variables that are set are:

- `acl-dir` - this contains a path to the directory where the combined acl files are stored
- `acl-enabled` - when enabled the cli will evaluate the acls for the configured role as it is done for untrusted applications.
- `role` - the selected role.

These variables can be changed using the `setenv` command.

```
root - * - [bus-cli] (0)
 > setenv acl-enabled=false
> !amx variable  acl-enabled=false

root - * - [bus-cli] (0)
 > printenv acl-enabled
> !amx variable  acl-enabled
acl-enabled = false
```

A special role exists the `untrusted` role. This role is used to provide access to untrusted applications that didn't authenticate themselves and should have almost no access on anything. It is always a good idea to verify that this role doesn't have access to data model parts it should not be able to access

```
root@prplOS:~# ba-cli -u untrusted
Copyright (c) 2020 - 2023 SoftAtHome
amxcli version : 0.4.2

!amx silent true

                   _  ___  ____
  _ __  _ __ _ __ | |/ _ \/ ___|
 | '_ \| '__| '_ \| | | | \___ \
 | |_) | |  | |_) | | |_| |___) |
 | .__/|_|  | .__/|_|\___/|____/
 |_|        |_| based on OpenWrt
 -----------------------------------------------------
 Bus Agnostic CLI
 -----------------------------------------------------

root - * - [bus-cli] (0)
 > Device.IP.Interface.10.?0
ERROR: get Device.IP.Interface.10. failed (-1)

root - * - [bus-cli] (0)
 > setenv acl-enabled=false
> !amx variable  acl-enabled=false

root - * - [bus-cli] (0)
 > Device.IP.Interface.10.?0
Device.IP.Interface.10.
Device.IP.Interface.10.Alias="iptv"
Device.IP.Interface.10.AutoIPEnable=0
Device.IP.Interface.10.Enable=0
Device.IP.Interface.10.IPv4AddressNumberOfEntries=1
Device.IP.Interface.10.IPv4Enable=1
Device.IP.Interface.10.IPv6AddressNumberOfEntries=0
Device.IP.Interface.10.IPv6Enable=0
Device.IP.Interface.10.IPv6PrefixNumberOfEntries=0
Device.IP.Interface.10.LastChange=19316
Device.IP.Interface.10.Loopback=0
Device.IP.Interface.10.LowerLayers="Device.Ethernet.Link.2."
Device.IP.Interface.10.MaxMTUSize=1500
Device.IP.Interface.10.Name=""
Device.IP.Interface.10.Router="Device.Routing.Router.1."
Device.IP.Interface.10.Status="Unknown"
Device.IP.Interface.10.Type="Normal"
Device.IP.Interface.10.ULAEnable=0

root - * - [bus-cli] (0)
 > 
 ```

## Appendix A: Passing Values

The cli engine will interprete the commands provided, this includes the values for parameters as well.

The cli will not fetch the object/parameter introspection data to verify the data type, all conversion will be done by the cli as best effort conversion.

Use the `dump` command to verify the correct parameter types. The recieving side (data model provider) will do conversion if needed and if it is possible.


### String Values

It is recommended that string values are passed using single quotes or double quotes. When not quotes are put arround a string it is possible that the cli-engine will interprete the value as a number or as a boolean.

### Number Values

Values not enclosed in single or double quotes are considered a number when it can be converted to a number without any error.

The following notations are considered numbers:

- `[+-]?[0-9]*` : decimal number
- `0x[0-9A-Fa-f]*` : hexadecimal number
- `0[0-7]*` : octal number

### Boolean Values

Values not enclosed in single or double quotes are considered a boolean when it matches with one of these:

- true values: `true`, `yes`, `on`
- false values: `false`, `no`, `off`

`0` or `1` can be considered a boolean value as well, but will be passes as a number. 
