# Data Model Example - Greeter Application

1. [Introduction](#introduction)
2. [Building `greeter` app](#building-greeter-app)<br>
2.1. [Build Prerequisites](#build-prerequisites)<br>
2.2. [Building](#building)<br>
3. [Running `greeter` app](#running-greeter-app)<br>
3.1. [Run Prerequisites](#run-prerequisites)<br>
3.2. [Running](#running)
4. [Differences with greeter_plugin](#differences-with-greeter_plugin)
5. [Connect to a bus](#connect-to-a-bus)<br>
5.1. [Loading a back-end](#loading-a-back-end)<br>
5.2. [Creating a connection](#creating-a-connection)
6. [Integrating in Event Loops](#integrating-in-event-loops)<br>
6.1. [File Descriptors](#file-descriptors)<br>
6.2. [Reading the data](#reading-the-data)<br>
7. [Integrating the Data Model](#integrating-the-data-model)<br>
7.1 [Loading the ODL file](#loading-the-ODL-file)<br>
7.2 [Registering the data model](#registering-the-data-model)
8. [Notes](#notes)

## Introduction

The `Greeter` data model application is not a real world example, its only purpose is to show how you integrate the `Ambiorix` framework in a existing application that already has an event loop.

The data model functionality is exactly the same as the [greeter_plugin](https://gitlab.com/prpl-foundation/components/ambiorix/examples/datamodel/greeter_plugin) example. If you want to know more about the `data model` implementation please read [greeter_plugin README.md](https://gitlab.com/prpl-foundation/components/ambiorix/examples/datamodel/greeter_plugin/-/blob/main/README.md)

## Building `greeter` application

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

After the `make` has finished, you can install it by calling `make install`.
As this is example code, the `make install` will install in your build output directory and not in your system directories.
You can provide the `DEST` variable to change the root directory to where the example must be installed.

Examples:

Install in your system root
```bash
$ sudo make install
/usr/bin/install -d /usr/bin/
/usr/bin/install -m 0755 ./output/x86_64-linux-gnu/object/greeter /usr/bin/greeter
/usr/bin/install -d /etc/amx/greeter
/usr/bin/install -m 0644 ./odl/greeter_definition.odl /etc/amx/greeter/
/usr/bin/install -m 0644 ./odl/greeter_extra.odl /etc/amx/greeter/
/usr/bin/install -m 0644 ./odl/greeter_defaults.odl /etc/amx/greeter/
/usr/bin/install -m 0644 ./odl/greeter.odl /etc/amx/greeter 
```

## Running `greeter` application

### Run Prerequisites

To be able to run this example you will need to:

- Build and install the example
- Install an `Ambiorix` bus back-end

A software bus must be running and the correct back-end must be installed.

In this example it is assumed that you have `ubus` running and the `ubus` tool is installed (so the `amxb-ubus.so` should be available as well).

### Running

Once it is built and everything is installed you can launch the example.

  ```bash
  $ greeter
  ```

When the application is started, it will print the configuration options, followed by this message.

```text
*************************************
*          Greeter started          *
*************************************
```

That indicates that all went well and the `greeter` example is ready to rock 'n roll.

For more information on how to interact with this application see [greeter_plugin README.md](https://gitlab.com/prpl-foundation/components/ambiorix/examples/datamodel/greeter_plugin/-/blob/main/README.md)

## Differences with greeter_plugin

The greeter_plugin and this example are basically doing exactly the same, the main difference is that the `greeter_plugin` example uses the [Ambiorix Run Time](https://gitlab.com/prpl-foundation/components/ambiorix/applications/amxrt) application to get started while this example can run by itself.

This example uses [libamxrt](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxrt) to:

 - parse the command line options
 - load the backends 
 - set up the socket connection(s) to the bus system(s)
 - load the odl file(s), there is no need to specify the odl files that need to be loaded. By default the name of the application is used (greeter) to find to odl file needed. If all goes well the odl file `/etc/amx/greeter/greeter.odl` should be loaded.
 - register the data model to the used bus system(s)

As it is not possible for the odl parser's import function resolver to resolve symbols in an executable (app), the functions needed must be provided using the odl parser's function table.

The `ODL` parser library provides a method to populate a function table with function pointers. This method is:

```C
int amxo_resolver_ftab_add(amxo_parser_t *parser,
                           const char *fn_name,
                           amxo_fn_ptr_t fn)
```

Using this function, function pointers can be passed to the `ODL` parser. The first argument of this function is the parser itself, this is the same parser as used to read the `ODL` file. The second argument is the function name as mentioned in the `ODL` file. The function name may be prefixed with the object path, the last argument is the real function pointer.

To add the `say` implementation defined under object `Greeter` just call:

```C
amxo_resolver_ftab_add(parser, "Greeter.say", AMXO_FUNC(_Greeter_say));
```

or as an alternative, without the `object` prefix:

```C
amxo_resolver_ftab_add(parser, "say", AMXO_FUNC(_Greeter_say));
```

So adding the functions to the odl parser's function table is done with this code:

```c
    amxo_resolver_ftab_add(parser, "check_change", AMXO_FUNC(_State_check_change));
    amxo_resolver_ftab_add(parser, "Greeter.Statistics.stats_read", AMXO_FUNC(_stats_read));
    amxo_resolver_ftab_add(parser, "Greeter.Statistics.stats_list", AMXO_FUNC(_stats_list));
    amxo_resolver_ftab_add(parser, "Greeter.Statistics.stats_describe", AMXO_FUNC(_stats_describe));

    // event handlers
    amxo_resolver_ftab_add(parser, "enable_greeter", AMXO_FUNC(_enable_greeter));
    amxo_resolver_ftab_add(parser, "disable_greeter", AMXO_FUNC(_disable_greeter));
    amxo_resolver_ftab_add(parser, "print_event", AMXO_FUNC(_print_event));

    // datamodel RPC funcs
    amxo_resolver_ftab_add(parser, "Greeter.echo", AMXO_FUNC(_function_dump));
    amxo_resolver_ftab_add(parser, "Greeter.say", AMXO_FUNC(_Greeter_say));
    amxo_resolver_ftab_add(parser, "Greeter.History.clear", AMXO_FUNC(_History_clear));
    amxo_resolver_ftab_add(parser, "Greeter.setMaxHistory", AMXO_FUNC(_Greeter_setMaxHistory));
    amxo_resolver_ftab_add(parser, "Greeter.save", AMXO_FUNC(_Greeter_save));
    amxo_resolver_ftab_add(parser, "Greeter.load", AMXO_FUNC(_Greeter_load));
    amxo_resolver_ftab_add(parser, "Greeter.Statistics.periodic_inform", AMXO_FUNC(_periodic_inform));
    amxo_resolver_ftab_add(parser, "Greeter.Statistics.reset", AMXO_FUNC(_Statistics_reset));
```

The `parser` can be fetched using the method `amxrt_get_parser();`

Always use the `AMXO_FUNC` macro to pass the function pointers.

All data model functions mentioned in the `ODL` file must be added the `ODL` parser's function table prior parsing the `ODL` files.

After registering the data model functions that are needed, all that needs to be done is start the Ambiorix Run Time. In this example the simple `amxrt` method is used, that will do all the work for you.

```c
    retval = amxrt(argc, argv, NULL);
```

See the [README.md](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxrt/-/blob/main/README.md) file of [libamxrt](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxrt) for more information or other possibilities to create an ambiorix application.

