# Bus Agnostic Example - Subscribe

1. [Introduction](#introduction)  
2. [Building `amx-subscribe`](#building-amx-subscribe)  
2.1. [Build Prerequisites](#build-prerequisites)  
2.2. [Building](#building)  
3. [Running `amx-subscribe`](#running-amx-subscribe)  
3.1. [Run Prerequisites](#run-prerequisites)  
3.2. [Running](#running)

## Introduction

The `amx-subscribe` bus agnostic example can be used to subscribe for events coming from a `data model` provider. 

Using the `Ambiorix` framework it is possible to connect to different software bus systems (ubus, pcb, ...) and create applications that can interact with all these buses without the need of changing the code depending on the bus implementation that is used.

The `amx-subscribe` application is an example. Most bus systems have support for notifications or events. This example demonstrates that it is possible with the `Ambiorix` framework to connect to a bus and subscribe for events. The `Ambiorix` framework adds `event filtering` on top of that using the `expressions` feature.

This examples demonstrates the following features:
- data model event subscription
- event filtering with expressions
- wait until an object is registered/available in the bus system (if the bus system supports this functionality)
- automatic resubscription when object was removed and re-added

## Building `amx-subscribe`

### Build Prerequisites

To be able to build this example you will need to install:

- `libamxc`  (Data collections and data containers)
- `libamxp`  (Common Functional Patterns)
- `libamxb`  (Bus agnostic API)
- `libamxrt`
### Building

Change your working directory to the root of this example and use `make`.

```Bash
cd <SubscribeRoot>/
make
```

After the `make` has finished, you can install it by calling `sudo -E make install`. This will
install the application in `/usr/bin/` by default. You can specify a different install location
for example the output directory by using `make install DEST=./output BINDIR=""`.

Examples:

Install to output directory
```bash
$ make install DEST=./output BINDIR=""
make -C src all
/usr/bin/install -D -p -m 0755 src/amx-subscribe ./output/amx-subscribe
```

## Running `amx-subscribe`

### Run Prerequisites

To be able to run this example you will need to:

- Build and install the example
- Install an `Ambiorix` bus back-end
- Make a `data model` available on the bus
- A software bus must be running and the correct back-end must be installed.
- Another `application` must be running that sends events over the bus.

In this explanation it is assumed that you have `ubus` running and the `ubus` tool is installed (so the `amxb-ubus.so` should be available as well). For the remote end the `greeter_plugin` example is used, this will send events. Using ubus requires root permissions, so everything that is mentioned from now on must be run as a root user. You can switch to the root user with the following command:

```bash
sudo -E su -
```

Before continuing, make sure that you have the `greeter_plugin` example running (as root) and it is connected to ubus.

You can verify this by using the `ubus` tool.

```bash
$ ubus list
Greeter
Greeter.History
Greeter.History.1
Greeter.Statistics
```

### Running

Once it is built and everything is installed you can launch the example.

This application can take some options, followed by two command line arguments.

```bash
amx-subscribe [OPTIONS] <OBJECT> [<EXPRESSION>]
```

- OBJECT - the object path of the `data model` object of which you want to receive events.
- EXPRESSION - (optional) an event filter expression.

```bash
$ amx-subscribe Greeter.History. 
```

When launched nothing will happen, the `amx-subscribe` is now waiting for events. All you need to do is make sure the `greeter_plugin` is generating events on the object `Greeter.History.`

So open a new console and make sure events are generated, just execute the following two commands:

```bash
ubus call Greeter _set '{"parameters":{"State":"Start"}}'
ubus call Greeter say '{"from":"ubus", "message":"hello world"}'
```

After that you have executed these two commands, you should see an event being printed in the console where the `amx-subscribe` application is running:

```text
Notification received [Greeter.History]:
{
    object = "Greeter.History.",
    index = 2,
    notification = "dm:instance-added",
    name = "2",
    parameters = {
        Retain = false,
        Message = "hello world",
        From = "ubus"
    },
    path = "Greeter.History."
}
```

All data between the curly brackets `{ }` is `event data`. What is in the data depends on the type of event. When the remote end is an `Ambiorix` based data model the following fields are always available:

- `object` - The `Ambiorix` data model object path
- `eobject` - The same as `object` but the instance names are put between square brackets `[` and `]`
- `path` - The `USP` compliant object path
- `notification` - The `name` of the notification (Ambiorix default data model events always start with `dm:`). This field indicates the type of the event. All events of the same type have the same structure.

---
> **NOTE**
> The paths that are available in `object` or `eobject` are not USP (TR-369) compatible paths, these are ambiorix specific path extentions. 
---

Using the `expression` feature of the `Ambiorix` framework , it is possible to easily filter out the events you want to see. The `amx-subscribe` that is running, will print all events from all objects under the `Greeter.History` object.

Now stop the `amx-subscribe` (press CTRL+C in the console where it is running) application and relaunch it:

```bash
amx-subscribe Greeter.History. "notification in ['dm:instance-added','dm:instance-removed'] && parameters.From == 'ubus'"
```

Now let's generate some more events and see what happens:

```bash
$ ubus call Greeter say '{"from":"me", "message":"hello world"}'
# Nothing should be printed by subscribe, the received event does not match the filter.
$ ubus call Greeter say '{"from":"ubus", "message":"hello subscribe"}'
# An event should be printed by subscribe
$ ubus call Greeter.History clear
# Two events should be printed by subscribe
```

### Lua Alternative

The same can be achieved with a simple lua script:

```lua
local pretty = require 'pl.pretty'
local lamx = require 'lamx'
local sub

lamx.auto_connect()

local el = lamx.eventloop.new()

local print_event = function(event, data)
   print("Notification received from " .. event);
   print("Event " .. tostring(event))
   pretty.dump(data)
end

local objects_available = function()
    print("Wait done - object " .. arg[1] .. " is available");
    if arg[2] then 
        sub = lamx.bus.subscribe(arg[1], print_event, arg[2]);
    else
        sub = lamx.bus.subscribe(arg[1], print_event);
    end
end

print("Wait until object " .. arg[1] .. " is available");
lamx.bus.wait_for(arg[1], objects_available)

el:start()

lamx.disconnect_all()
```

The lua package `penlight` must be installed to run this lua script. This can be done using
```
luarocks install penlight
```

---
> **NOTE**<br>
> - When using the ambiorix development and debug container, `luarocks` and `penlight` will be installed.
> - The lua script is available in this repository under `scripts/` directory.
--

