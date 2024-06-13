# Object Definition Language Compiler/Generator

[[_TOC_]]

## Introduction

The tool `amxo-cg` (Ambiorix ODL Compiler/Generator) is a tool that can parse odl files and generates other files from it.

It is mainly used to verify the syntax of the ODL file.

Using add-ons it can:
- generate template source code from the odl file for a client C library
- generate template source code from the odl file for the data model plug-in
- generate html documentation from the odl file

## Building, installing and testing

### Docker container

You could install all tools needed for testing and developing on your local machine, but it is easier to just use a pre-configured environment. Such an environment is already prepared for you as a docker container.

1. Install docker

    Docker must be installed on your system.

    If you have no clue how to do this here are some links that could help you:

    - [Get Docker Engine - Community for Ubuntu](https://docs.docker.com/install/linux/docker-ce/ubuntu/)
    - [Get Docker Engine - Community for Debian](https://docs.docker.com/install/linux/docker-ce/debian/)
    - [Get Docker Engine - Community for Fedora](https://docs.docker.com/install/linux/docker-ce/fedora/)
    - [Get Docker Engine - Community for CentOS](https://docs.docker.com/install/linux/docker-ce/centos/)<br /><br />
    
    Make sure you user id is added to the docker group:

    ```
    sudo usermod -aG docker $USER
    ```

1. Fetch the container image

    To get access to the pre-configured environment, all you need to do is pull the image and launch a container.

    Pull the image:

    ```bash
    docker pull registry.gitlab.com/soft.at.home/docker/oss-dbg:latest
    ```

    Before launching the container, you should create a directory which will be shared between your local machine and the container.

    ```bash
    mkdir -p ~/amx_project/applications/
    ```

    Launch the container:

    ```bash
    docker run -ti -d --name oss-dbg --restart always --cap-add=SYS_PTRACE --sysctl net.ipv6.conf.all.disable_ipv6=1 -e "USER=$USER" -e "UID=$(id -u)" -e "GID=$(id -g)" -v ~/amx_project/:/home/$USER/amx_project/ registry.gitlab.com/soft.at.home/docker/oss-dbg:latest
    ```

    The `-v` option bind mounts the local directory for the ambiorix project in the container, at the exact same place.
    The `-e` options create environment variables in the container. These variables are used to create a user name with exactly the same user id and group id in the container as on your local host (user mapping).

    You can open as many terminals/consoles as you like:

    ```bash
    docker exec -ti --user $USER oss-dbg /bin/bash
    ```

### Building

#### Prerequisites

- [libamxo](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxo) - The ODL compiler library
- [libamxc](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxc) - Generic C api for common data containers
- [libamxd](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxd) - Data model C API
- [libxml2](https://gitlab.gnome.org/GNOME/libxml2) - XML Toolkit

#### Build amxo-cg

1. Clone the git repository

    To be able to build it, you need the source code. So open the directory just created for the ambiorix project and clone this library in it (on your local machine).

    ```bash
    cd ~/amx_project/applications
    git clone git@gitlab.com:prpl-foundation/components/ambiorix/applications/amxo-cg.git
    ``` 

1. Install dependencies

    Although the container will contain all tools needed for building, it does not contain the libraries needed for building `amxo-cg`. To be able to build `amxo-cg` you need `libamxd`, `libamxc`, `libamxo` and libxml2. These libraries can be installed in the container by executing the following commands. 

    ```bash
    sudo apt update
    sudo apt install libamxo libxml2-dev
    ```

    Note that you do not need to install all components explicitly. Some components will be installed automatically because other components depend on them.

1. Build it

    ```bash
    cd ~/amx_project/applications/amxo-cg
    make
    ```

### Installing

#### Using make target install

You can install your own compiled version easily in the container by running the install target.

```bash
cd ~/amx_project/applications/amxo-cg
sudo -E make install
```

#### Using package

From within the container you can create packages.

```bash
cd ~/amx_project/applications/amxo-cg
make package
```

The packages generated are:

```
~/amx_project/applications/amxo-cg/amxo-cg-<VERSION>.tar.gz
~/amx_project/applications/amxo-cg/amxo-cg-<VERSION>.deb
```

You can copy these packages and extract/install them.

For ubuntu or debian distributions use dpkg:

```bash
sudo dpkg -i ~/amx_project/applications/amxo-cg/amxo-cg-<VERSION>.deb
```

### Testing

Currently no tests are available for amxo-cg.

## Using amxo-cg

amxo-cg can be used as an ODL file syntax verification tool or as a file generator tool starting from ODL file(s). 

Read the `verify odl syntax` for explanation of the common options and working of `amxo-cg`

All available options can be retrieved using `amxo-cg --help`

```text
$ amxo-cg --help
Ambiorix ODL File Parser/Generator v1.1.0
        powered by libamxo v1.1.2

amxo-cg [OPTIONS] <odl files> <directories>

Options:
--------
        -h   --help             Print this help
        -v   --verbose          Print verbose logging
        -I   --include-dir      Adds an include directory
        -L   --import-dir       Adds an import directory
        -R   --import-resolve   Adds an import directory
        -i   --include-odl      Adds an odl file that should be treated as include file
        -G   --generator        Enables a generator (see generators)
        -s   --silent           Supress warnings and messages
        -w   --no-warnings      Supress warnings only
        -c   --continue         Continue with other files after error
        -n   --no-colors        Disable colored output
        -d   --dump-config      Dump parser config, unless silent is set
        -r   --reset            Clear data model before loading next root odl

WARNING: do not use -r and -i in combination

Generators:
-----------

        Generators can create files during the parsing of the odl file(s).

        This amxo-cg supports:
          - "dm_methods" use '--help=dm_methods' or '-hdm_methods' for more information.
          - "xml" use '--help=xml' or '-hxml' for more information.
```

### Verify odl syntax

The most common use case of `amxo-cg` is to verify the ODL syntax.

`amxo-cg` uses the default paths to search for include files. Include paths can be added using the `-I` option.

By default `amxo-cg` disables import and function resolving features of the ODL parser, if you want that the imports and function resolving are done while loading the odl files use `-R` option. Extra import paths can be added using option `-L`.

---
> **NOTE**<br>
> When a shared object, mentioned in an import, is not found  or can not be loaded (because of wrong architecture), amxo-cg will print an error and fails. (exit code not 0). 
---

After any options a list of odl files or directories can be specified. It is possible when providing multiple odl files that parsing one of them fails, in that case `amxo-cg` stops and will not parse the remaining odl files. This default behavior can be changed using the `-c` option. When this option is set `amxo-cg` will continue with the other files and will end if all files have been parsed. The exit code however will be not 0 (failure).

When providing odl files, each of them must be able to build a valid data model. Often defaults for the data model are also defined in a separate odl file, but these odl files can not be loaded stand-alone as they are missing the data model definition.

Example:

When using the `greeter_defaults.odl` an error will be printed as the `Greeter.History` object is not defined in that odl file.
```text
$ amxo-cg /etc/amx/greeter/greeter_defaults.odl
INFO   : Collecting files ...
INFO   : Add file [/etc/amx/greeter/greeter_defaults.odl]
INFO   :
INFO   : Building include tree ...
       /etc/amx/greeter/greeter_defaults.odl  (includes 0, used 0)
INFO   :
INFO   : Run generators ...
INFO   : Parsing file [/etc/amx/greeter/greeter_defaults.odl]
ERROR 2 - Object Greeter.History not found (start searching from "root")@/etc/amx/greeter/greeter_defaults.odl:line 2
ERROR  : Error parsing [/etc/amx/greeter/greeter_defaults.odl]
ERROR  :
```

Typically you provide the `main` odl file to `amxo-cg` which will take all includes into account as well:

```text
$ amxo-cg /etc/amx/greeter/greeter.odl
INFO   : Collecting files ...
INFO   : Add file [/etc/amx/greeter/greeter.odl]
INFO   :
INFO   : Building include tree ...
       /etc/amx/greeter/greeter.odl  (includes 3, used 0)
       |---/etc/amx/greeter/greeter_defaults.odl  (includes 0, used 1)
       |---/etc/amx/greeter/greeter_definition.odl  (includes 0, used 1)
       |---/etc/amx/greeter/greeter_extra.odl  (includes 0, used 1)
INFO   :
INFO   : Run generators ...
INFO   : Parsing file [/etc/amx/greeter/greeter.odl]
```

The odl file loading and verification is done in 3 stages:

1. build a list of all odl files, or when a directory is provided the directory tree is searched recursively for all odl files and they are added to the list
1. build include tree and clean-up odl files list
   - odl files that are included by another odl file are removed from the list
   - odl files that can not be loaded stand-alone (gives errors when loaded) and are detected by the directory scan are removed from the list.
1. verify all top level odl files (these are the files not included by another odl file).

So providing the `main` odl file alone or providing all odl files or the directory containing all odl files could give the same result. 

Examples:

```text
 amxo-cg /etc/amx/greeter/greeter.odl /etc/amx/greeter/greeter_defaults.odl /etc/amx/greeter/greeter_definition.odl
INFO   : Collecting files ...
INFO   : Add file [/etc/amx/greeter/greeter.odl]
INFO   : Add file [/etc/amx/greeter/greeter_defaults.odl]
INFO   : Add file [/etc/amx/greeter/greeter_definition.odl]
INFO   :
INFO   : Building include tree ...
       /etc/amx/greeter/greeter.odl  (includes 3, used 0)
       |---/etc/amx/greeter/greeter_defaults.odl  (includes 0, used 1)
       |---/etc/amx/greeter/greeter_definition.odl  (includes 0, used 1)
       |---/etc/amx/greeter/greeter_extra.odl  (includes 0, used 1)
INFO   :
INFO   : Run generators ...
INFO   : Parsing file [/etc/amx/greeter/greeter.odl]

$ amxo-cg /etc/amx/greeter/greeter.odl /etc/amx/greeter/
INFO   : Collecting files ...
INFO   : Add file [/etc/amx/greeter/greeter.odl]
INFO   : Scan directory [/etc/amx/greeter]
INFO   : Add file [/etc/amx/greeter/greeter_definition.odl]
INFO   : Add file [/etc/amx/greeter/greeter_defaults.odl]
INFO   : Add file [/etc/amx/greeter/greeter.odl]
INFO   : Add file [/etc/amx/greeter/greeter_extra.odl]
INFO   :
INFO   : Building include tree ...
       /etc/amx/greeter/greeter.odl  (includes 3, used 0)
       |---/etc/amx/greeter/greeter_defaults.odl  (includes 0, used 1)
       |---/etc/amx/greeter/greeter_definition.odl  (includes 0, used 1)
       |---/etc/amx/greeter/greeter_extra.odl  (includes 0, used 1)
INFO   :
INFO   : Run generators ...
INFO   : Parsing file [/etc/amx/greeter/greeter.odl]
```

---
> **NOTE**<br>
> Using the `-s` option all warnings and messages can be suppressed. 
---

To see all details of the odl parsing, verbose logging can be turned on using the `-v` option. When verbose logging is on, a hierachical tree is dumped containing the full details of the actions taken by the odl parser.

Example:

```text
$ amxo-cg -vs /etc/amx/greeter/greeter.odl /etc/amx/greeter/
INFO   : Parsing file [/etc/amx/greeter/greeter.odl]    
Start - /etc/amx/greeter/greeter.odl
|   Open section config - /etc/amx/greeter/greeter.odl@3
|   |   Set config option name - /etc/amx/greeter/greeter.odl@5
|   |   Set config option listen - /etc/amx/greeter/greeter.odl@8
|   |   Set config option storage-path - /etc/amx/greeter/greeter.odl@12
|   |   Set config option odl - /etc/amx/greeter/greeter.odl@19
|   |   Set config option definition_file - /etc/amx/greeter/greeter.odl@22
|   |   Set config option extra_file - /etc/amx/greeter/greeter.odl@23
|   |   Set config option defaults_file - /etc/amx/greeter/greeter.odl@24
|   Close section config - /etc/amx/greeter/greeter.odl@25
|   Open include file /etc/amx/greeter/greeter_definition.odl - /etc/amx/greeter/greeter.odl@29
|   |   Open section define - /etc/amx/greeter/greeter_definition.odl@1
|   |   |   Create object singleton Greeter - /etc/amx/greeter/greeter_definition.odl@2
|   |   |   |   Add parameter uint32_t MaxHistory - /etc/amx/greeter/greeter_definition.odl@3
|   |   |   |   Set parameter MaxHistory = 10 - /etc/amx/greeter/greeter_definition.odl@5
|   |   |   |   Add parameter cstring_t State - /etc/amx/greeter/greeter_definition.odl@8
|   |   |   |   Set parameter State = Idle - /etc/amx/greeter/greeter_definition.odl@9
|   |   |   |   Add function cstring_t say( cstring_t from, cstring_t message, bool retain ) - /etc/amx/greeter/greeter_definition.odl@16
|   |   |   |   Add function uint32_t setMaxHistory( uint32_t max ) - /etc/amx/greeter/greeter_definition.odl@18
|   |   |   |   Add function bool save( cstring_t file ) - /etc/amx/greeter/greeter_definition.odl@20
|   |   |   |   Add function bool load( cstring_t file ) - /etc/amx/greeter/greeter_definition.odl@21
|   |   |   |   Create object template History - /etc/amx/greeter/greeter_definition.odl@23
|   |   |   |   |   Add function uint32_t clear( bool force ) - /etc/amx/greeter/greeter_definition.odl@26
|   |   |   |   |   Add parameter cstring_t From - /etc/amx/greeter/greeter_definition.odl@28
|   |   |   |   |   Add parameter cstring_t Message - /etc/amx/greeter/greeter_definition.odl@31
|   |   |   |   |   Add parameter bool Retain - /etc/amx/greeter/greeter_definition.odl@34
|   |   |   |   |   Set parameter Retain = false - /etc/amx/greeter/greeter_definition.odl@34
|   |   |   |   Done object History - /etc/amx/greeter/greeter_definition.odl@35
|   |   |   |   Create object singleton Statistics - /etc/amx/greeter/greeter_definition.odl@37
|   |   |   |   |   Add function null periodic_inform( uint32_t secs ) - /etc/amx/greeter/greeter_definition.odl@38
|   |   |   |   |   Add function null reset( ) - /etc/amx/greeter/greeter_definition.odl@39
|   |   |   |   Done object Statistics - /etc/amx/greeter/greeter_definition.odl@44
|   |   |   Done object Greeter - /etc/amx/greeter/greeter_definition.odl@45
|   |   Close section define - /etc/amx/greeter/greeter_definition.odl@46
|   |   Open section populate - /etc/amx/greeter/greeter_definition.odl@48
|   |   Close section populate - /etc/amx/greeter/greeter_definition.odl@58
|   Close include file /etc/amx/greeter/greeter_definition.odl - /etc/amx/greeter/greeter.odl@29
|   Open include file /etc/amx/greeter/greeter_extra.odl - /etc/amx/greeter/greeter.odl@30
|   |   Open section config - /etc/amx/greeter/greeter_extra.odl@1
|   |   |   Set config option define-behavior - /etc/amx/greeter/greeter_extra.odl@4
|   |   Close section config - /etc/amx/greeter/greeter_extra.odl@5
|   |   Open section define - /etc/amx/greeter/greeter_extra.odl@7
|   |   |   Create object singleton Greeter - /etc/amx/greeter/greeter_extra.odl@8
|   |   |   |   Add function (null) echo( (null) data ) - /etc/amx/greeter/greeter_extra.odl@9
|   |   |   Done object Greeter - /etc/amx/greeter/greeter_extra.odl@10
|   |   Close section define - /etc/amx/greeter/greeter_extra.odl@11
|   Close include file /etc/amx/greeter/greeter_extra.odl - /etc/amx/greeter/greeter.odl@30
|   Open include file /etc/amx/greeter/greeter_defaults.odl - /etc/amx/greeter/greeter.odl@32
|   |   Open section populate - /etc/amx/greeter/greeter_defaults.odl@1
|   |   |   Select from (root) Greeter.History - /etc/amx/greeter/greeter_defaults.odl@2
|   |   |   |   Add instance (0, "") - /etc/amx/greeter/greeter_defaults.odl@3
|   |   |   |   |   Set parameter From = odl parser - /etc/amx/greeter/greeter_defaults.odl@4
|   |   |   |   |   Set parameter Message = Welcome to the Greeter App - /etc/amx/greeter/greeter_defaults.odl@5
|   |   |   |   |   Set parameter Retain = true - /etc/amx/greeter/greeter_defaults.odl@6
|   |   |   |   Done object (1, "1") - /etc/amx/greeter/greeter_defaults.odl@7
|   |   |   Done object History - /etc/amx/greeter/greeter_defaults.odl@8
|   |   Close section populate - /etc/amx/greeter/greeter_defaults.odl@9
|   Close include file /etc/amx/greeter/greeter_defaults.odl - /etc/amx/greeter/greeter.odl@32
|   Open section define - /etc/amx/greeter/greeter.odl@34
|   Close section define - /etc/amx/greeter/greeter.odl@36
|   Open section populate - /etc/amx/greeter/greeter.odl@38
|   Close section populate - /etc/amx/greeter/greeter.odl@41
End - (null)
```

### Special cases and pitfalls

### ODL files include in code

Sometimes it is possible that odl files are loaded/included using code instead of `include` in the odl files. When these files must be included in the generated output or in the verification process they can be added using `-i` or `--include-odl` option. This option can take an individual odl file or a directory. It is allowed to use this option multiple times. 

The odl files or directories specified using the `-i` option will be loaded after all other odl files are loaded.

### Use a top level directory

Caution is needed when specifying a top level directory (typically an output directory of a full image build). All odl files found in that directory or in any sub-directory will be loaded by amxo-cg. This could cause conflicts as multiple odl files could define the same objects or mibs. To avoid these conflicts the option `-r` or `--reset` can be specified. This will make sure that before loading each top level odl in the include tree the internal data model is reset. 

The option `-r` and `-i` can not be used in combination. The `-r` will reset the data model, so the `saved odl` files can not be loaded as the data model is reset before they are loaded.

### Generators

Currently two generators are available:
- dm_methods - generates C files which contain a C implementation for each data model method encountered. These generated C functions can be used as a template.
- xml - generates xml files for each loaded odl file. These xml files can then be transformed using xsl transformations to any other format, for example html.

Multiple generators can be used in one run, but each generator can only be mentioned once.

Generators are activated with the `-G` option and the format is `-G<generator name>[,<output directory>]`. When no output directory is provided, all files are created in the current working directory.

Example:

```text
amxo-cg -s -Gxml /etc/amx/greeter/greeter.odl
INFO   : Parsing file [/etc/amx/greeter/greeter.odl]
INFO   : Creating file [/home/sah4009/amxo-cg-demo/greeter.odl.xml]
```

The above example will generate a file `greeter.odl.xml` in the current directory.

#### xml generator

The xml generator converts odl files in one or more xml files. One xml file is generated for each top-level odl file. Besides the odl definition the xml generator also takes the comments in the odl files into account.


The comments that are taken into account by the xml generator are the comments just before an object definition, a parameter definition, a function definition (in define sections) or the comments before an instance creation or a parameter set (in populate sections).

The comments are parsed and must be provided in a fixed structure:

```text
<brief description>

<description paragraph>

<description paragraph>

...

<tag> [<name>] <description>
<tag> [<name>] <description>
<tag> [<name>] <description>
...

```

- The brief description should be one single line, followed by an empty line.
- Description paragraphs can be multi-line text. A paragaph ends when an empty line is encountered.
- Special tags can be added after the last description paragraph.

The `amxo-cg` tool will print warnings whenever a definition (object, parameter, function) is encountered without any comments preceding it.

##### Supported Tags

All tags always start with `@`followed by the tag name.

- @version \<VERSION> - specifies the version 
- @param \<ARGUMENT NAME> \<ARGUMENT DESCRIPTION> - only of use for function documentation and describes the function argument in more detail
- @return \<RETURN VALUE DESCRIPTION> - only of use for function documentation and describes the possible function return values.

##### Path Translation

The xml converted can translate to internal object paths to TR-181 object paths. This allows the generated xml to reference objects using their TR-181 names and paths.
To enable the translation a configuration file must be provided in odl format with a configuration section that contains the path names that must be translated.

Example translation configuration file:
```
%config {
    amxo-cg = {
        translate = {
            "'DHCPv4Server.'" = "Device.DHCPv4.Server.",
            "'DHCPv4Client.'" = "Device.DHCPv4."            
        }
    };
}
```

##### Skip protected elements

By default all elements defined in odl files are included in the generated xml file. To skip protected elements add to a configuration file the option 'skip-protected' and set it to true.

Exmaple config file with translation and skipping all protected elements:
```
%config {
    amxo-cg = {
        translate = {
            "'DHCPv4Server.'" = "Device.DHCPv4.Server.",
            "'DHCPv4Client.'" = "Device.DHCPv4."            
        },
        skip-protected = true
    };
}
```

##### Example ODL to HTML

![Convert ODL files to HTML documentation pages](examples/odl2html.mp4)

#### dm_methods generator

In ODL files data model methods can be defined, which are part of the data model interface and can be called by other processes. These methods need an implentation and are often implemented in C code.

The data model method generator can generate C template functions which can be used as a start for implementing these methods.

This generator will generate a C file for each top level odl file, it is not the intention to use these generated files directly in your project, the generated C template functions can be copied in your project. The generator does not generate the implementation itself.

Example:

```bash
$ amxo-cg -s -Gdm_methods /etc/amx/greeter/greeter.odl                                                                    
INFO   : Parsing file [/etc/amx/greeter/greeter.odl]
INFO   : Creating file [/home/user/amxo-cg-demo/greeter.odl.c]
```

This will generate a file called `/home/user/amxo-cg-demo/greeter.odl.c` and will generate a C function for each data model method defined in the odl files.

```C
/* AUTO GENERATED WITH amx_odl_version 1.0.4 */   
                                           
#include <stdlib.h>                   
#include <stdio.h>                           
                                          
#include <amxc/amxc.h>               
#include <amxp/amxp_signal.h>
#include <amxd/amxd_dm.h>                                                    
#include <amxd/amxd_object.h>
                                     
                                    
amxd_status_t _Greeter_say(amxd_object_t *object,
                     amxd_function_t *func,
                     amxc_var_t *args,
                     amxc_var_t *ret) {
    amxd_status_t status = amxd_status_ok;
    char*  retval;

    char*  from = amxc_var_dyncast(cstring_t, GET_ARG(args, "from"));
    char*  message = amxc_var_dyncast(cstring_t, GET_ARG(args, "message"));
    bool retain = amxc_var_dyncast(bool, GET_ARG(args, "retain"));

    /* < ADD IMPLEMENTATION HERE > */

    amxc_var_set(cstring_t, ret, retval);

    free(from);
    free(message);
    return status;
}

....
```
