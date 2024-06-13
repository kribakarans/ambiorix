# Using Ambiorix Interactive Command Line Interface

[[_TOC_]]

## Introduction

`amx-cli` is a tool mainly focused on human interaction and is not intended to automate tasks. It provides an interactive command line interface with only some basic functionality.

The main features of the tool are:

- loading and unloading of cli modules (add-ons)
- keep a command history
- record and play-back of commands (for demo purposes)
- aliases - shortcut for one or more commands
- variables - store values which can be used in commands
- command <TAB> completion

To use `amx-cli` to interact with a bus system or make it perform some tasks, one or more add-ons must be loaded. Each add-on can provide one or more modules. 

Most `amx-cli` built-in features are provided by built-in modules.

## Start up

Starting `amx-cli` is straightforward, just launch it as any other application installed on your system:

```bash
$ amx-cli


=============================================================================

                A
               AAA
              A:::A
             A:::::A
            A:::::::A
           A:::::::::A              mmmmmmm    mmmmmmm   xxxxxxx      xxxxxxx
          A:::::A:::::A           mm:::::::m  m:::::::mm  x:::::x    x:::::x
         A:::::A A:::::A         m::::::::::mm::::::::::m  x:::::x  x:::::x
        A:::::A   A:::::A        m::::::::::::::::::::::m   x:::::xx:::::x
       A:::::A     A:::::A       m:::::mmm::::::mmm:::::m    x::::::::::x
      A:::::AAAAAAAAA:::::A      m::::m   m::::m   m::::m     x::::::::x
     A:::::::::::::::::::::A     m::::m   m::::m   m::::m     x::::::::x
    A:::::AAAAAAAAAAAAA:::::A    m::::m   m::::m   m::::m    x::::::::::x
   A:::::A             A:::::A   m::::m   m::::m   m::::m   x:::::xx:::::x
  A:::::A               A:::::A  m::::m   m::::m   m::::m  x:::::x  x:::::x
 A:::::A                 A:::::A m::::m   m::::m   m::::m x:::::x    x:::::x
AAAAAAA                   AAAAAAAmmmmmm   mmmmmm   mmmmmmxxxxxxx      xxxxxxx

=============================================================================


Copyright (c) 2020 - 2021 SoftAtHome
amxcli version : 0.0.7


2021-03-11T07:28:47Z - sah4009 - [AMX] (0)
 >
```

Without any configuration file or initialization file, you get the default `interactive command line interface`. To make the tool more useful, extra add-ons must be loaded. The `amx-cli modules` can be put anywhere in your file system, normally these modules are installed in the directory `/usr/lib/amx/amx-cli`. 

Loading such a module can be done with the command `!addon load <ADDON NAME> <ADDON SO FILE>`. An example of an `amx-cli` add-on is [mod-ba-cli](https://gitlab.com/prpl-foundation/components/ambiorix/modules/amx_cli/mod-ba-cli) which provides modules and commands that can interact with bus-systems and data models. More information about this add-on can be found in the git repository:
- https://gitlab.com/prpl-foundation/components/ambiorix/modules/amx_cli/mod-ba-cli

To load this add-on use following command:

```bash
2021-04-14T12:47:54Z - sah4009 - [AMX] (0)
 > !addon load ba-cli /usr/lib/amx/amx-cli/mod-ba-cli.so
Loading shared object /usr/lib/amx/amx-cli/mod-ba-cli.so
Loading successful
ba-cli backend
ba-cli connection
ba-cli cli
```

The add-on name is a name that can be chosen freely as long as it does not conflict with another name of an already loaded `amx-cli` add-on.

When one or more add-ons are loaded you can use the command `!help` to see the full list of loaded add-ons and the modules they provide:

```bash
2021-04-14T12:48:28Z - sah4009 - [ba-cli] (0)
 > !help
amx modules:
        Use ! prefix to execute amx modules commands

        record - record and playback cli commands
        amx - Ambiorix Interactive Command Line Control.
        history - Can display, clear, save and load the command history
        addon - loads & unloads add-ons - adds or removes functionality
        help - Shows help

aliases:
        exit = !amx exit
        printenv = !amx variable
        quit = !amx exit
        setenv = !amx variable

Available addons:
         ba-cli - /usr/lib/amx/amx-cli/mod-ba-cli.so
                backend - Manage backends
                connection - Manage connections
                cli - Bus Agnostic cli.

Select addon with !addon select <ADDON> [<MODULE>]
```

To use the add-on you need to select one of its modules. This can be done using the following command:

```bash
2021-04-14T12:49:23Z - sah4009 - [ba-cli] (0)
 > !addon select ba-cli connection
```

Once a module is selected the commands provided by that module can be used. See the documentation of the add-on that provides the module to know how to use it.

Often you will use the same set of add-ons or one particular module of an add-on, so each time you start `amx-cli` you need to load the add-ons and select a module before you can get started. This is of course a bit annoying, luckily `amx-cli` can be configured.

## Configuration

`amx-cli` can be configured using two type of files:

- a configuration file `amx-cli.conf`. The data in that file is in JSON format and can be used to turn-off features, modules and commands. An example of such a file can be found [here](https://gitlab.com/prpl-foundation/components/ambiorix/applications/amx-cli/-/blob/main/config/example.conf). It is not needed to mention all possible settings in that file. By default all features, modules and commands are turned on. It is sufficient to only mention the features, modules or commands you want to turn off. Also note that the settings are in `reverse logic`.
- an initialization file `amx-cli.init`. This file contains a sequence of commands that needs to be executed at start-up. An example of such an initialize file can be found [here](https://gitlab.com/prpl-foundation/components/ambiorix/applications/amx-cli/-/blob/main/config/example.init).

When launching `amx-cli`, it will load the correct config and init files from `/etc/amx/cli/`. Which files are selected depends on how you launch the application. If you launch it with `amx-cli`, it will load `/etc/amx/cli/amx-cli.init` and `/etc/amx/cli/amx-cli.conf`.

It is however also possible to create a symbolic link to `amx-cli` to load different files. For example you can create a symbolic link `foo` to `amx-cli`

```bash
ln -s /usr/bin/amx-cli foo
```

Then you can run `./foo`, which will launch `amx-cli` due to the symbolic link, but it will load `/etc/amx/cli/foo.init` as initialization file and `/etc/amx/cli/foo.conf` as config file. So by specifying a different symbolic link to `amx-cli`, you can select different configuration and startup options.

## Launch `amx-cli`

If you launch `amx-cli` you will be presented with an interface that looks like this:

```text
2021-04-14T08:27:34Z - root - [AMX] (0)
 > 
```

On the first line you will see the date and time, the user that started the process, the selected addon or module between square brackets `[]` and the return value of the last command between round brackets `()`. This interface can change when different addons are loaded. The functionality of `amx-cli` depends a lot on which addons are loaded, but there are also some built-in modules which will be explained in the following sections.

## Built-in modules

`amx-cli` on its own already has a few built-in modules. For more information about a module you can use `help <module>`. The built-in modules are

- help
- addon
- amx
- history
- record

All of the built-in modules can be used at any point when using the CLI by prefixing your command with an exclamation mark `!`. Why this is important will be explained in the example of the `addon` module.

Note that this is not the case for any new commands that are added after loading addons with modules. You can usually only use the commands that are available in the current selected module. 

As mentioned in the previous section, the selected addon can change and is listed between square brackets `[]`. Depending on which addon or module is selected, you will not be able to use all commands.

### addon

The `addon` module can be used to dynamically load and remove different addons. It can also be used to select a module from a loaded addon or list all loaded addons. Executing `help addon` will show you what you can do with the module:

```text
 > help addon

help [<CMD>]
	Prints help

load <ALIAS> <ADDON>
	loads an add-on shared object.

remove <ALIAS>
	Removes an add-on shared-object.

select <ALIAS> [<MODULE>]
	Selects an add-on as the active add-on.

list
	Lists all loaded add-on
```

#### Example

You can load the bus agnostic CLI addon with the following command:

```text
2021-04-14T08:11:51Z - root - [AMX] (0)
 > !addon load ba-cli /usr/lib/amx/amx-cli/mod-ba-cli.so
Loading shared object /usr/lib/amx/amx-cli/mod-ba-cli.so
Loading successful
ba-cli backend
ba-cli connection
ba-cli cli

2021-04-14T08:11:57Z - root - [mod_ba] (0)
 > 
 ```

This loads the addon and `selects` it as well. You can see this by looking at the value between square brackets `[mod_ba]`. Because the selected addon has changed, you can no longer use the commands from the `[AMX]` module without prefixing them with an exclamation mark. So to switch back to the main application use `!addon select` without arguments, but with an exclamation mark

```text
2021-04-14T08:11:57Z - root - [mod_ba] (0)
 > !addon select

2021-04-14T08:14:42Z - root - [AMX] (0)
 > 
```

You can also use `!addon select` to select one of the addon modules

```text
2021-04-14T08:15:25Z - root - [AMX] (0)
 > !addon select mod_ba backend

2021-04-14T08:15:37Z - root - [mod_ba backend] (0)
 > 
```

---
> Note: As a rule of thumb you can always run the built-in modules with an exclamation mark to make sure they will work as expected.
---

Use `!addon list` to list which addons are loaded and which alias you need to use to select them

```text
2021-04-14T09:00:56Z - root - [mod_ba] (0)
 > !addon list

mod_ba - /usr/lib/amx/amx-cli/mod-ba-cli.so
```

Use `!addon remove` to remove a previously loaded addon

```text
2021-04-14T09:02:32Z - root - [mod_ba] (0)
 > !addon remove mod_ba
Removing shared object mod_ba (/usr/lib/amx/amx-cli/mod-ba-cli.so)
Removed mod_ba
```

### amx

The `amx` module can be used to configure various CLI settings. Executing `!help amx` will show what you can do with the module.

```text
2021-04-14T09:02:43Z - root - [AMX] (0)
 > !help amx

help [<CMD>]
	Prints help

exit
	Exits Ambiorix Command Line Interface.

silent true|false
	Sets cli silent

log [<OPTIONS>] true|false
	Enables or disables logging

prompt <TEXT>
	Changes the prompt.

alias [<ALIAS> [<CMD>]]
	Defines an alias.

variable [<VARIABLE>]
	Prints variable(s) value.

variable <VARIABLE> = <VALUE>
	Creates variable or changes a variable value.
```

Most commands are pretty straightforward and are explained with the help command. To get more specific information about one of the commands, use `!help amx <command>`, for example:

```text
2021-04-14T09:35:36Z - root - [AMX] (0)
 > !help amx log

Enables or disables logging
Usage: log [<OPTIONS>] true|false

Enables or disables logging.
Available options:
	-o --output Enables/disables output logging.
	-m --msg    Enables/disables messages logging.
```

### history

The `history` module is very useful to track previous commands that were executed. You can use the up and down arrow keys to cycle through previous executed commands like you can do in most CLIs. The available `history` commands are shown with `!help history`:

```text
2021-04-14T09:40:26Z - root - [AMX] (0)
 > help history

help [<CMD>]
	Prints help

show
	Shows command history.

clear
	clear command history.

save <FILE>
	Saves command history to a file.

load <FILE>
	Loads command history from a file.
```

The command history is saved to a file in `/tmp/` when you shut down the application, but you can also save the history to a different file with `history save` or load it with `history load`.

### record

The `record` module can be used to record certain commands and play them again at a later time. This can be useful for demo purposes. The available commands are shown with `!help record`:

```text
2021-04-14T09:53:30Z - root - [AMX] (0)
 > !help record

help [<CMD>]
	Prints help

start <FILE>
	Records commands into a file.

stop
	Stops recording commands.

play [<OPTIONS>] <FILE>
	Playback a previously recorded sequence of commands.
```

Again the commands are pretty straightforward. An interesting thing to note is that the `record play` has a wait option `-w` that executes recorded commands one by one after a key-press.
