# Ambiorix Runtime

[[_TOC_]]

## Introduction

The Ambiorix Run-Time is a base application that can launch an Ambiorix based data model service or an Ambiorix based data model client.

The application by itself is not providing any service or functionality. It provides an eventloop (using libevent), can load one or more odl (Object Definition Language) files, can load one or more Ambiorix bus back-ends.

The real functionality is implemented in amxrt plug-ins (add-ons), which are imported using the odl file.

ODL Files can define:

- A data model
- The shared objects (add-ons) to load.
- Configuration options.

The ODL syntax is described in [odl.md](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxo/-/blob/main/doc/odl.md) document.

All configuration options can be specified in an ODL file, some of them can be provided at startup as command line arguments as well.

Some commandline options can not be defined in an ODL file.

```text
amxrt [OPTIONS] <odl files>

Options:

    -h    --help                   Print usage help
    -H    --HELP                   Print extended help
    -B    --backend <so file>      Loads the shared object as bus backend
    -u    --uri <uri>              Adds an uri to the list of uris
    -A    --no-auto-detect         Do not auto detect unix domain sockets and back-ends
    -C    --no-connect             Do not auto connect the provided or detected uris
    -I    --include-dir <dir>      Adds include directory for odl parser, multiple allowed
    -L    --import-dir <dir>       Adds import directory for odl parser, multiple allowed
    -o    --option <name=value>    Adds a configuration option
    -F    --forced-option <name=value>Adds a configuration option, which can not be overwritten by odl files
    -O    --ODL <<odl string>>     An ODL in string format, only one ODL string allowed
    -D    --daemon                 Daemonize the process
    -p    --priority <nice level>  Sets the process nice level
    -N    --no-pid-file            Disables the creation of a pid-file in /var/run
    -E    --eventing               Enables eventing during loading of ODL files
    -d    --dump-config            Dumps configuration options at start-up
    -R    --requires               Checks if datamodel objects are available or waits until they are available
```

Examples of data model plug-in implementations:
- [greeter plug-in](https://gitlab.com/prpl-foundation/components/ambiorix/examples/datamodel/greeter_plugin)
- [TR-181 LocalAgent Threshold](https://gitlab.com/prpl-foundation/components/ambiorix/examples/datamodel/localagent_threshold) 

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
    mkdir -p ~/amx_project/applications
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

- [libamxrt](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxrt) - Ambiorix Runtime implementation library

#### Build amxrt

1. Clone the git repository

    To be able to build it, you need the source code. So open the directory just created for the ambiorix project and clone this library in it (on your local machine).

    ```bash
    cd ~/amx_project/applications
    git clone git@gitlab.com:prpl-foundation/components/ambiorix/applications/amxrt.git
    ``` 

1. Install dependencies

    Although the container will contain all tools needed for building, it does not contain the libraries needed for building `amxrt`. To be able to build `amxrt` you need `libamxrt`. These libraries can be installed in the container by executing the following commands. 

    ```bash
    sudo apt update
    sudo apt install libamxrt
    ```

    Note that you do not need to install all components explicitly. Some components will be installed automatically because other components depend on them. Some of the components are allready preinstalled in the container.

1. Build it
    
    ```bash
    cd ~/amx_project/applications/amxrt
    make
    ```

### Installing

#### Using make target install

You can install your own compiled version easily in the container by running the install target.

```bash
cd ~/amx_project/applications/amxrt
sudo -E make install
```

#### Using package

From within the container you can create packages.

```bash
cd ~/amx_project/applications/amxrt
make package
```

The packages generated are:

```
~/amx_project/applications/amxrt/amxrt-<VERSION>.tar.gz
~/amx_project/applications/amxrt/amxrt-<VERSION>.deb
```

You can copy these packages and extract/install them.

For ubuntu or debian distributions use dpkg:

```bash
sudo dpkg -i ~/amx_project/applications/amxrt/amxrt-<VERSION>.deb
```

### Testing

#### Prerequisites

No extra components are needed for testing `amxrt`, all needed tools are installed in the container.

#### Run tests

You can run the tests by executing the following command.

```bash
cd ~/amx_project/applications/amxrt/test
make
```

Or this command if you also want the coverage tests to run:

```bash
cd ~/amx_project/applications/amxrt/test
make run coverage
```

Ot from the root directory of this repository,

```bash
cd ~/amx_project/applications/amxrt
make test
```

This last will run the unit-tests and generate the test coverage reports in one go.

#### Coverage reports

The coverage target will generate coverage reports using [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html) and [gcovr](https://gcovr.com/en/stable/guide.html).

A summary for each file (*.c files) is printed in your console after the tests are run.
A HTML version of the coverage reports is also generated. These reports are available in the output directory of the compiler used.
Example: using native gcc
When the output of `gcc -dumpmachine` is `x86_64-linux-gnu`, the HTML coverage reports can be found at `~/amx_project/applications/amxrt/output/x86_64-linux-gnu/coverage/report.`

You can easily access the reports in your browser.
In the container start a python3 http server in background.

```bash
cd ~/amx_project/
python3 -m http.server 8080 &
```

Use the following url to access the reports `http://<IP ADDRESS OF YOUR CONTAINER>:8080/applications/amxrt/output/<MACHINE>/coverage/report`
You can find the ip address of your container by using the `ip` command in the container.

Example:

```bash
USER@<CID>:~/applications/amxrt/libamxd$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
173: eth0@if174: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:07 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.7/16 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 2001:db8:1::242:ac11:7/64 scope global nodad 
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe11:7/64 scope link 
       valid_lft forever preferred_lft forever
```

in this case the ip address of the container is `172.17.0.7`.
So the uri you should use is: `http://172.17.0.7:8080/applications/amxrt/output/x86_64-linux-gnu/coverage/report/`

## Run

---
> **NOTE**<br>
> The amxrt application uses libamxrt, handling of the command line argument options and providing the default configuration options are done by this library. For completness, the documentation of the default configuration options and command line arguments are mentioned here as well.
--- 

Start amxrt and provide odl files.

Example:

```
amxrt tr181-mqtt.odl 
```

Command line options are available. Use `--help` to get the list of available command line options.

Configuration options can be specified in the `%config` section of the odl file(s), or can be provided with the command line using option `-o` or `-F`.

```
$ amxrt --help
amxrt [OPTIONS] <odl files>

Options:

    -h    --help                          Print usage help and exit
    -H    --HELP                          Print extended help and exit
    -B    --backend <so file>             Loads the shared object as bus backend
    -u    --uri <uri>                     Adds an uri to the list of uris
    -A    --no-auto-detect                Do not auto detect unix domain sockets and back-ends
    -C    --no-connect                    Do not auto connect the provided or detected uris
    -I    --include-dir <dir>             Adds include directory for odl parser, multiple allowed
    -L    --import-dir <dir>              Adds import directory for odl parser, multiple allowed
    -o    --option <name=value>           Adds a configuration option
    -F    --forced-option <name=value>    Adds a configuration option, which can not be overwritten by odl files
    -O    --ODL <odl-string>              An ODL in string format, only one ODL string allowed
    -D    --daemon                        Daemonize the process
    -p    --priority <nice level>         Sets the process nice level
    -N    --no-pid-file                   Disables the creation of a pid-file in /var/run
    -E    --eventing                      Enables eventing during loading of ODL files
    -d    --dump-config                   Dumps configuration options at start-up
    -l    --log                           Write to syslog instead of stdout and stderr
    -R    --requires <root object>        Checks if datamodel objects are available or waits until they are available
    -V    --version                       Print version
```

## Configuration Options

The `amxrt` application already provides defaults for most configuration options. All these run-time configuration options can be changed using the `%config` section in the ODL files and most of them can be set using the commandline arguments.

### Defaults

The defaults configuration options provided by `amxrt` can be dumped to stdout using `amxrt -d`, all options are printed in alhabetical order:

```bash
$ amxrt -d

Configuration:
{
    auto-connect = true,
    auto-detect = true,
    auto-resolver-order = [
        "ftab",
        "import",
        "*"
    ],
    backend-dir = "/usr/bin/mods/amxb",
    backends = [
        "/usr/bin/mods/amxb/mod-amxb-pcb.so",
        "/usr/bin/mods/amxb/mod-amxb-ubus.so"
    ],
    cfg-dir = "/etc/amx",
    daemon = false,
    dm-eventing-enabled = false,
    dump-config = true,
    import-dbg = false,
    import-dirs = [
        ".",
        "${prefix}${plugin-dir}/${name}",
        "${prefix}${plugin-dir}/modules",
        "${prefix}/usr/local/lib/amx/${name}",
        "${prefix}/usr/local/lib/amx/modules"
    ],
    include-dirs = [
        ".",
        "${prefix}${cfg-dir}/${name}",
        "${prefix}${cfg-dir}/modules"
    ],
    listen = [
    ],
    log = false,
    mib-dirs = [
        "${prefix}${cfg-dir}/${name}/mibs"
    ],
    name = "amxrt",
    pcb = {
        register-name = "amxrt"
    },
    pid-file = true,
    plugin-dir = "/usr/lib/amx",
    prefix = "",
    priority = 0,
    requires = [
    ],
    rw_data_path = "${prefix}/etc/config",
    storage-path = "${rw_data_path}/${name}/",
    storage-type = "odl",
    uris = [
        "pcb:/var/run/pcb_sys",
        "ubus:/var/run/ubus/ubus.sock"
    ]
}
```

---
> **NOTE**<br>
> Some values of the default configuration options can be different, depending on which back-ends are installed or which unix domain sockets are found. This also depends on the value of `auto-detect`.<br> 
> The configuration option that could be different are:
> - `uris`
> - `backends`
---
#### Options

- auto-connect: (boolean) when set to true (default), the application will automatically connect to all uris specified in config option `uris`. If one of the connections fail, an error is printed to stderr. At least one connection must be available.
- auto-detect: (boolean) when set to true (default), the back-end directory is scanned and all found back-ends are loaded. A search is done for all known bus unix domain sockets, all found are added to the `uris` list and will be connected to when `auto-connect` is set to true.
- auto-resolver-order: (array) Used by the ODL parser function resolver. Defines in which order the function resolvers must be called to resolve a function name into a function pointer. More information about the ODL parser function resolving can be found in the ODL documentation.
- backend-dir: (string) Directory that must be scanned for valid back-end implementations. When `auto-detect` is set to true, this directory will be scanned and all valid back-end implementations found are added to the option `backend`.
- backends: (array) Array of back-ends that need to be loaded. When `auto-detect` option and `backend-dir` option are set this list is filled automatically.
- cfg-dir: (string) The base directory where ODL files are stored. Typically a subdirectoy is added with the same name of the application.  
- daemon: (boolean) When set to true, the application daemonizes after all ODL files are loaded (except post includes) and before the entry-points are invoked.
- dm-eventing-enabled: (boolean) When set to true (default is false), data model eventing is enabled during the load of the ODL files provided at command line.
- dm-events-before-start: (boolean) When set the data model events are handled before `app:start` event is triggered. Default is false.
- dm-events-suspend-when-requires: (boolean) When set the data model events will be suspended until all required objects are available, when not set the data model events can occur before the entry-points are called, if required objects are not yet available. Default is false.
- dump-config: (boolean) This configuration option is mostly automatically set or using the command line option `-d`. When an error occurs during start-up this option is set and the `current` configuration is dumped to stdout. 
- import-dbg: (boolean) Used by the ODL import resolver. When set to true (default is false), the import ODL resolver will print more information to stdout when resolving functions and loading shared objects.
- import-dirs: (array) Used by the ODL import resolver. It contains a list of directories where the import resolver should search for shared objects (plug-ins). Plug-ins (aka addons) are no ordinary libraries, and are loaded at run-time by the ODL import resolver, when the keyword `import` is encountered in the ODL file. Extra directories can be added using commandline option `-L`.
- import-pcb-compat: (boolean) Used by the ODL import function resolver. When set the import function resolver, will resolve the function in a PCB compatible way. This is only needed when strict PCB compatibility is required. 
- include-dirs: (array) List of include directories. These directories are used by the ODL parser. When an `include` keyword is encountered in the ODL files and it does not contain an absolute path, the include file is searched in these include directories, in the order specified. Extra include directories can be added to the list with the commandline option `-I`
- listen: (array) List of listen sockets that must be created.
- log: (boolean) When set to true, `amxrt` will open the system log (syslog) and can write messages to it.
- mib-dirs: (array) List of directories. Each of these directories will be scanned for ODL files. The ODL files in that directory should only define a MIB.
- name: (string) The name of the application. When using a symbolic link to `amxrt` the name of the symbolic link is used as the `name` option.
- pcb: (table) Configuration settings for the PCB back-end. If the PCB back-end is not loaded these options have no effect.
- pid-file: (boolean) When set to true (default), a pid-file is created, with the name of the application (using the `name` configuration option).
- plugin-dir: (string) Base directory for plug-ins (aka addons). Typically a subdirectory is created with the name of the application. 
- prefix: (string) By default this is empty. When set (using commandline option `-o`) all paths are prefixed with this string. This option is mainly used for debugging reasons.
- priority: (integer) Sets the nice level of the application (default = 0)
- rw_data_path: (string) Base path were persistent storage files are saved. Typically a sub-directory is created in this directory with the name of the application.
- storage-path: (string) The (base) directory where the application will store the persistent storage files.
- storage-type: (string) The persistent storage type. This configuration option defines in which format the saved files should be written (default is "odl" format). The Ambiorix run-time can only handle the `odl` format to store persistent data. If another format is needed, a module (plug-in) is needed that can support the needed format.
- uris: (array) List of uris that are used to create the connections.
- requires: (array) Array of required data model objects. Using the command line option `-R` or `--requires` extra objects can be added to the list. When the list is not empty, the Ambiorix run-time will wait until all objects in the list are available before calling the entry points and triggering the event `app:start`.

### Forcing Options From Commandline

When in odl files configuration options are specified (in `%config` section) the values specified in the odl file are taken. Using the `-F` or `--forced-option`, you can force a specific value for a configuration option from command line. The `forced options` can not be overwritten by odl files.

---
> **NOTE**<br>
> In odl files the `%config` sections are scoped and are only valid in the odl file where they are defined, and in all odl files that are included in that file after the `%config` section. If the file where the `%config` section is defined is included by another odl file (the parent odl file), the parent will not see these values for the config options, unless the config options was declared with `%global`
---

### Required Objects

Using the command line option `-R` or `--requires` object paths can be added to the list of required objects. These objects are mostly provided by other processes and it is possible that these objects are not yet available. Ambiorix run-time will wait until all objects in the `required` list are available before calling any entry-point and triggering the event `app:start`. The data model of your application will not be registered to the bus systems until all `required` objects are available.

When the command line option `-D` or configuration option `daemon` is set, the run-time will daemonize itself even if not all required objects are available.

When all required objects are available, the `requires` array is reset to an empty array. 

### ODL Persistent Storage 

The Ambiorix run-time can store persistent data in `ODL` format save files.

By default no persistent data is saved. To enable this on configuration a table must be added to the configuration section of your main ODL file.

The `ODL` storage format is only active when the `storage-type` configuration option is set to `odl`.

#### ODL Load And Save Options

All ODL persistent storage options must be set in the `odl` and can be divided in 3 logical parts:

1. Common Setting

- odl.directory: (string) The directory where the persistent storage files are saved. This directory is also used to load the stored files (or can be used in an include) 

2. Load Settings

    ---
    >**NOTE**<br>
    >When using `include` in the `ODL` files to load the previously saved files, these settings should not be used.
    >
    >It is not recommended to use `include` and the `load` functionality toghether.
---

- odl.dm-load: (boolean) When set to true, all ODL files in the `odl.directory` are loaded.
- odl.dm-defaults: (string) String containing a directory or file. When no saved `ODL` files are found or exist, the defaults will be loaded defined by this configuration option.
- odl.load-dm-events: (boolean) When set to true data model eventing will be enabled when loading the saved files (or the defaults).

3. Save settings

- odl.dm-save: (boolean) When set to true, `amxrt` will save the persistent data at exit.
- odl.dm-save-on-changed: (boolean) When set to true `amxrt` will save the persistent data when the data has been changed.
- odl.dm-save-delay: (integer, default is 500ms) Time in milliseconds to wait before writing the changes. Each time a change occurs before the time expires, the timer is reset. So at least no changes should occur to persistent data before the changes are saved. 
- odl.dm-objects: (csv string) Object paths that must be saved, when this option is set only the data model (sub)trees are saved that are specified. The name of the file will be the object path of the object.

#### Example

```odl
%config {
    odl = {
        dm-save = true,
        dm-save-on-changed = true,
        dm-save-delay = 1000,
        directory = "${storage-path}/odl"
    };
}
```

Using above example the Ambiorix run-time (`amxrt`) will save all `persistent` objects and parameters (they must have the `%persistent` attribute) to a file with the name `${name}.odl` in the directory specified with `odl.directory` option. The save will be done when the application exits and only when `odl.dm-save` is set to true.

When odl.dm-save-on-changed is set, changes are saved immediatly after the datamodel did not receive changes in odl.dm-save-delay time to the file and not only when the applications exits.

When persistent data changes and not other changes occur for at least `odl.dm-save-delay` the persistent data is saved.
