# Data Model Example - Dropbear Controller

[[_TOC_]]

## Introduction

## Building `ssh_server` plugin

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
cd <ssh_server>/
make
```

After the `make` has finished, you can install it by calling `sudo -E make install`.

Examples:

Install in your system root
```bash
$ sudo -E make install
/usr/bin/install -D -p -m 0644 odl/ssh_server.odl /etc/amx/ssh_server/ssh_server.odl
/usr/bin/install -D -p -m 0644 odl/ssh_server_definition.odl /etc/amx/ssh_server/ssh_server_definition.odl
/usr/bin/install -D -p -m 0644 odl/ssh_server_defaults.odl /etc/amx/ssh_server/ssh_server_defaults.odl
/usr/bin/install -D -p -m 0644 output/x86_64-linux-gnu/object/ssh-server.so.0.0.0 /usr/lib/amx/ssh_server/ssh_server.so.0.0.0
/usr/bin/install -d -m 0755 /usr/bin
ln -sfr /usr/lib/amx/ssh_server/ssh_server.so.0.0.0 /usr/lib/amx/ssh_server/ssh_server.so.0
ln -sfr /usr/lib/amx/ssh_server/ssh_server.so.0.0.0 /usr/lib/amx/ssh_server/ssh_server.so
ln -sfr /usr/bin/amxrt /usr/bin/ssh_server
```

## Running `ssh server` plugin

### Run Prerequisites

To be able to run this example you will need to:

- Build and install the example
- Install `amxrt` (`Ambiorix Runtime`)
- Install an `Ambiorix` bus back-end
- Install `dropbear`
- Create a user id that can be used for testing.

A software bus must be running and the correct back-end must be installed.

In this explanation it is assumed that you have `ubusd` running and the `ubus` tool is installed (so the `amxb-ubus.so` should be available as well).

#### Configure The Container

`Dropbear` can be installed in the `Ambiorix Debug And Development` container.

Before continuing make sure that `dropbear` can be started and is working correctly:

1. Add a test user - when requested fill in a password
    ```bash
    $ sudo adduser --home /home/johnd --shell /bin/bash johndoe
    Adding user johndoe ...
    Adding new group johndoe (1001) ...
    Adding new user johndoe (1001) with group johndoe ...
    Creating home directory /home/johnd ...
    Copying files from /etc/skel ...
    New password:
    Retype new password:
    passwd: password updated successfully
    Changing the user information for johndoe
    Enter the new value, or press ENTER for the default
          Full Name []:
          Room Number []:
          Work Phone []:
          Home Phone []:
          Other []:
    Is the information correct? [Y/n] y
    ```
1. Create a directory where `dropbear` will store some files
    ```bash
    $ sudo mkdir -p /etc/dropbear
    ``` 

1. Install `dropbear`
   ```bash
   sudo apt install dropbear 
   ```

1. Test `dropbear`<br>
   In the container launch dropbear:
   ```bash
   $ sudo dropbear -g -F -E -R -p 22
   ```
   On your host system try to open a ssh-session to the container.
   ```bash
   $ ssh johndoe@172.17.0.3
   johndoe@172.17.0.3 s password:
   johndoe@fd113c3f9bbc:~$
   ```

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

Launch the `dropbear` controller called `ssh_server`

```bash
# ssh_server
[IMPORT-DBG] - dlopen - ssh_server.so
[IMPORT-DBG] - symbol _cleanup_server resolved (for cleanup_server) from ssh_server
[IMPORT-DBG] - symbol _app_start resolved (for app_start) from ssh_server
[IMPORT-DBG] - symbol _ssh_toggle resolved (for ssh_toggle) from ssh_server
[IMPORT-DBG] - symbol _ssh_server_added resolved (for ssh_server_added) from ssh_server
[IMPORT-DBG] - symbol _ssh_server_changed resolved (for ssh_server_changed) from ssh_server
[IMPORT-DBG] - symbol _ssh_server_main resolved (for ssh_server_main) from ssh_server
```

## Testing

### Run tests

You can run the tests by executing the following command.

```bash
make test
```

#### Coverage reports

The test target will generate coverage reports using [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html) and [gcovr](https://gcovr.com/en/stable/guide.html).

A summary for each file (*.c files) is printed in your console after the tests are run.
A HTML version of the coverage reports is also generated. These reports are available in the output directory of the compiler used.
Example: using native gcc
When the output of `gcc -dumpmachine` is `x86_64-linux-gnu`, the HTML coverage reports can be found at `./output/x86_64-linux-gnu/coverage/report.`

You can easily access the reports in your browser.
In the container start a python3 http server in background.

```bash
cd ~/<WORKSPACE DIR>
python3 -m http.server 8080 &
```

Use the following url to access the reports `http://<IP ADDRESS OF YOUR CONTAINER>:8080/examples/datamodel/ssh-server/output/<MACHINE>/coverage/report`
You can find the ip address of your container by using the `ip` command in the container.

Example:

```bash
USER@<CID>:~/amx_project/libraries/libamxc$ ip a
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
So the uri you should use is: `http://172.17.0.7:8080/examples/datamodel/ssh-server/output/<MACHINE>/coverage/report/`

## `Dropbear controller` - ssh_server

### Interact through data model using ubus

Before going into a detailed explanation of the example, try it out first.

1. Add a `Server` instance
   ```bash
   $ ubus call SSH.Server _add
   {
        "object": "SSH.Server.cpe-Server-1.",
        "index": 1,
        "name": "cpe-Server-1",
        "parameters": {
                "Alias": "cpe-Server-1"
        },
        "path": "SSH.Server.1."
   }
   ```

1. Enable the `Server` instance
   ```bash
   $ ubus call SSH.Server.1 _set '{"parameters":{"Enable":true}}'
   {
        "SSH.Server.1.": {
                "Enable": true
        }
   }
   ```

After above two commands a `dropbear` application should be launched and running.

```bash
$ ps aux | grep dropbear
root      3400  5.7  0.0   6376  1108 pts/3    S+   18:16   0:00 dropbear -g -F -E -R -p 22
root      3464  0.0  0.0   7928   876 pts/4    S+   18:16   0:00 grep dropbear
```

It should now be possible to open a `ssh` session.

```bash
$ ssh johndoe@172.17.0.3
johndoe@172.17.0.3 s password:
johndoe@fd113c3f9bbc:~$
```

### The data model

#### SSH object

The object `SSH` contains one parameter `Enable`. When this parameter is set to false, it is possible to create and configure `Server` instances, but no `dropbear` applications are launched. When the `Enable` parameter is set to `true` all enabled `Server` instances will launch a `dropbear` application.

Two methods are available in the `SSH` object:

- `void load(%in bool reset = true)` - loads a previously saved file. The name and path of the file is defined in the configuration option `save_file`. When reset is set to true, all current instances of `SSH.Server.{i}.` are removed before loading the file. When set to false, the existing instances are kept and updated if needed.  
- `void save()` - saves the persistent data in the data model to a file. The name and path of the file is defined in the configuration option `save_file`.

#### Server object

The `Server` object is a multi-instance object. Each instance corresponds with a `dropbear` application. Each instance contains configuration parameters and status parameters.

The configuration parameters are:
- `AllowPasswordLogin` - Users can login using a password.
- `AllowRootLogin` - If set to true, it will be possible to login as root user.
- `AllowRootPasswordLogin` - If set to true, it will be possible to login using the root passwor. This setting has no effect when `AllowRootLogin` is set to false.
- `ActivationDuration` - time in minutes that the `dropbear` application will be running. When the duration time expires, the `dropbear` application is stopped, including all open sessions. 
- `Port` - the port on which the `dropbear` application listens for incoming connections
- `SourcePrefix` - address on which the `dropbear` application listens for incoming connections. When an empty string, listens on all addresses.
- `Enable` - When set to true a `dropbear` application is launched, when set to `false` the running application is stopped.

The status parameters are:
- `Status` - Current (or last) status of the `dropbear` application. The possible statuses are:
    - `Disabled` - when the `Enable` flag is set to `false` while the application was not running. Is also the initial (default) state.
    - `Running` - when the `Enable` flag is set to `true` and the `dropbear` application was started successful.
    - `Stopped` - the `dropbear` application was stopped. Either due to external reasons, or due to `timeout` (see parameter `ActivationDuration)
    - `Error` - the `dropbear` application failed to start.

- `ActivationDate` - when active (`dropbeaar` application is running), this is the data and time when the `dropbear` application was launched. When inactive this parameter will be set to the `unknown time`
- `PID` - the process ID of the running `dropbear` application.
- `ActiveSessions` - The number of active/open sessions of the `dropbear` application.

Each instance object also has one method `close_sessions`. When this method is called all open ssh sessions opened with that particular `dropbear` instance are closed. 

When an instance is created you can fetch all these parameters using the `ubus` tool.

List all instances:
```bash
$ ubus list SSH.Server.*
SSH.Server.1
SSH.Server.2
```

Fetch the parameters of a single instance:
```bash
$ ubus call SSH.Server.1 _get
{
        "SSH.Server.1.": {
                "Port": 22,
                "ActivationDuration": 0,
                "Status": "Running",
                "AllowPasswordLogin": true,
                "AllowRootLogin": true,
                "ActiveSessions": 1,
                "PID": 3400,
                "Enable": true,
                "ActivationDate": "2021-02-27T18:16:28.604827246Z",
                "AllowRootPasswordLogin": false,
                "Alias": "cpe-Server-1",
                "SourcePrefix": ""
        }
}

$ ubus call SSH.Server.2 _get
{
        "SSH.Server.2.": {
                "Port": 22,
                "ActivationDuration": 0,
                "Status": "Disabled",
                "AllowPasswordLogin": true,
                "AllowRootLogin": true,
                "ActiveSessions": 0,
                "PID": 0,
                "Enable": false,
                "ActivationDate": "0001-01-01T00:00:00Z",
                "AllowRootPasswordLogin": false,
                "Alias": "cpe-Server-2",
                "SourcePrefix": ""
        }
}
```

### Source Files

#### `ssh_server_dropbear_crtl.c`

This file contains a function to build the `dropbear` command line that is used to launch the application. No data model functions are used in this source file. It can be used as well without using a data model as controller.

Each `dropbear controller` is represented by a `amxp_proc_ctrl_t` structure as defined in the library `libamxp`.

This source file only contains one single function that is used as callback function in the `amxp_proc_ctrl_t` and will be called bu `amxp_proc_strl_start`

- `dropbear_ctrl_build_cmd` - Builds the `dropbear` command line using the provided settings.

---
> **Note**<br>
> The `dropbear` application will create a child process for each accepted `ssh` session. When stopping the `dropbear` application launched using the `ssh server data model` process wil not automatically stop all open `dropbear session` child processes. 

> Using linux's process file system (procfs) that typically is mounted on `/proc` it is possible to fetch the list of the PIDs of these child processes. The correct `procfs file` is read when needed to fetch these child processes. It is not possible to use `inotify` to get notified when files in `/proc` are changed, as `inotify` is not working on `procfs`.

> To circumvent this limitation, a timer is used that fetches the PIDs of the `dropbear` child processes at regular intervals. The timer callback function is implemented in `ssh_server_main.c` and is called `ssh_server_check`. The timer is only started as soon as there is at least one `dropbear` application is launched and runnng.
---

---
> **Note**
> Children of dropbear are tracked using the `procfs` file system through file `/proc/<pid>/task/<tid>/children`. This file is exposed by the Linux kernel since version 3.5.<br>
> Until Linux 4.2, the presence of this file was governed by the `CONFIG_CHECKPOINT_RESTORE` kernel configuration option. Since Linux 4.2, it is governed by the `CONFIG_PROC_CHILDREN` option.
>
> When using an older kernel version or the configuration option is disable, this children are tracked by scanning the full `/proc/` and find all children of the launched `dropbear` instance. The `/proc` is scanned using function `amxp_proci_findf`.
---
#### `dm_ssh_server_event.c`

This file contains event callback functions. These event callback functions are `bounded` to data model events as described in the `ssh_server_definition.odl`

```odl
%populate {
    on event "app:start" call app_start;

    on event "dm:object-changed" call ssh_toggle
        filter 'path == "SSH." && contains("parameters.Enable")';

    on event "dm:instance-added" call ssh_server_added
        filter 'path == "SSH.Server."';

    on event "dm:object-changed" call ssh_server_enable_changed
        filter 'path matches "SSH\.Server\.[0-9]+\." && 
                contains("parameters.Enable")';

    on event "dm:object-changed" call ssh_server_duration_changed
        filter 'path matches "SSH\.Server\.[0-9]+\." && 
                contains("parameters.ActivationDuration")';

    on event "dm:object-changed" call ssh_server_settings_changed
        filter 'path matches "SSH\.Server\.[0-9]+\." && 
                (contains("parameters.AllowRootLogin") ||
                 contains("parameters.AllowRootPasswordLogin") ||
                 contains("parameters.AllowPasswordlogin") ||
                 contains("parameters.Port") )';
}
```

- `_app_start` function is called when the application is started. This function will allocate a `amxp_proc_ctrl_t` structure for all existing `SSH.Server.{i}.` instances in the data model and bind that structure to the instance object (private data). 
    ```C
    amxd_object_for_all(servers, "*", ssh_server_proc_initialize, &is_enabled);
    ```
    It also adds a callback function to the `proc:disable` and `proc:stopped` signals which are emitted by the `amxp_proc_ctrl`.
    ```C
    amxp_slot_connect(NULL, "proc:disable", NULL, ssh_server_proc_disable, NULL);
    amxp_slot_connect(NULL, "proc:stopped", NULL, ssh_server_proc_stopped, NULL);
    ```
- `_ssh_toggle` function is called when the parameter `SSH.Enable` is changed. When `SSH.Enable` is set to true It will start `dropbear` applications of all `SSH.Server.{i}.` instances that are enabled. When `SSH.Eanble` is set to false it stops all instances where `SSH.Server.{i}.Status` is set "Running".
    ```C
    const char* filter = "[Status == 'Running'].";
    const char* status = "Stopped";

    if(enable) {
        fn = ssh_server_enable;
        filter = "[Enable == true].";
        status = NULL;
    }

    amxd_object_for_all(servers, filter, fn, (void*) status);
    ```
- `_ssh_server_added` function is called when a new `SSH.Server.{i}` instance is added to the data model. It will allocate a `amxp_proc_ctrl_t` structure and bind it to the new instance. If the instance is created with `Enable` set to true and `SSH.Enable` is set to true a `dropbear` application is launched immediately.
    ```C
    server = amxd_object_get_instance(ssh_servers, NULL, index);
    if(server != NULL) {
        ssh_server_proc_initialize(ssh_servers, server, &is_enabled);
    }
    ```
- `ssh_server_enable_changed` function is called when the parameter `Enable` of an instance is changed. When `SSH.Eanble` is set to true, this function will start or stop the `dropbear` application that is represented by the `amxp_proc_ctrl_T` structure that is bound to the instance object.
    ```C
    if((server != NULL) && ssh_is_enabled) {
        if(server_is_enabled) {
            ssh_server_enable(ssh_servers, server, NULL);
        } else {
            ssh_server_disable(ssh_servers, server, NULL);
        }
    }
    ``` 
- `ssh_server_duration_changed` is called when the `ActivationDuration` parameter is changed. If will restart the active `amxp_proc_ctrl_t` timer. When that timer expires the `dropbear` application is stopped.
   ```C
   amxp_proc_ctrl_set_active_duration(dropbear_ctrl, time);
   ```
- `ssh_server_settings_changed` when any of the configuration settings are changed and a `dropbear` application is running, it will be stopped and restarted with the new settings. This function uses configuration option `ssh-server.auto-restart` to check if the `dropbear` application must be restarted if configuration parameters are changed
   ```C
       if(GETP_BOOL(config, "ssh-server.auto-restart")) {
        if((status != NULL) && (strcmp(status, "Running") == 0)) {
            ssh_server_stop(NULL, server, (void*) "Stopped");
            ssh_server_start(NULL, server, NULL);
        }
    }
   ```

There is one event callback function that is not related to data model events. This function is `ssh_server_proc_disable` and is called whenever the `active timer` expires. The event data contains the process id for which the timer has expired. This function will search the correct data model instance object and updates the status of that instance accordingly.

```C
    server = amxd_dm_findf(dm, "SSH.Server.[ PID == %d ].", pid);
    if(server != NULL) {
        ssh_server_update_status(server, status);
    }
```

The same function is called when a `SIGCHLD` signal is received by the `ssh_server` application.  Depending on the `event_name` the status is correctly set.

```C
    const char* status = "Disabled";
    if(strcmp(event_name, "proc:stopped") == 0) {
        status = "Stopped";
    }
```

#### `dm_ssh_server_method.c`

This file implements all data model methods.

- `_close_sessions` - close all open sessions created with the `dropbear` application, represented by the instance object that the method is called on. 
- `_SSH_save` - saves the data model to the file defined in `save_file` configuration option.
- `_SSH_load` - loads a previously saved file.

#### `dm_ssh_server_action.c`

On the multi-instance object `SSH.Server.` one action callback function is defined.

The action callback is called when the object or an instance is removed from the data model.

```odl
%define {
    %persistent object SSH {

        bool Enable = true;

        %persistent object Server[] {
            on action destroy call cleanup_server;

            %persistent %unique %key string Alias;

            ...
        }
    }
}
```

The function `_cleanup_server` will make sure that the `amxp_proc_ctrl_t` structure that was allocated and bound to the instance is deleted using `amxp_proc_ctrl_delete`. 

```C
    dropbear_ctrl = (amxp_proc_ctrl_t*) object->priv;
    object->priv = NULL;
    amxp_proc_ctrl_delete(&dropbear_ctrl);
```

#### `dm_ssh_server_object.c`

This file contains two helper functions that implements some data model manipulation.

- `ssh_server_update_status` - will update the `SSH.Server.{i}.Status` parameter and other parameters depending on the new status set or the current set status.
- `ssh_server_update_sessions` - will update the `SSH.Server.{i}.ActiveSessions` parameter, this function is called by the timer callback function `ssh_server_check` that checks the list of `dropbear` child processes for each running `dropbear` application.

Both functions use a data model transaction to update the parameters, which will send out data model events when applied.

#### `dm_ssh_server_common.c`

The `dropbear control` functionality is implemented in library `libamxp - amxp_proc_ctrl.c`  and is fully independent from the data model. The data model implementations uses these functions to start and stop `dropbear` applications. 

When starting a `dropbear` application it must be able to pass the data model configuration parameters to the function that starts the `dropbear` application. A htable variant is used for this purpose. The `dropbear command line builder` function expects the following fields in the htable variant:

- `allow_password_login` - boolean value
- `allow_root_login` - boolean value
- `allow_root_password_login` - boolean value
- `port` - unsigned integer
- `address` - ipv4 address or ipv6 address on which the `dropbear` application needs listen for incoming connections.

The function `ssh_server_fetch_settings` creates a htable variant from the data model instance parameters. In the function is a mapping defined between the data model parameter names and the key names that must be added in the htable variant.

```C
setting_map_t mapper[] = {
    { "AllowPasswordLogin", CONFIG_ALLOW_PWD_LOGIN },
    { "AllowRootLogin", CONFIG_ALLOW_ROOT_LOGIN },
    { "AllowRootPasswordLogin", CONFIG_ALLOW_ROOT_PWD_LOGIN },
    { "Port", CONFIG_PORT },
    { "SourcePrefix", CONFIG_ADDRESS },
    { "ActivationDuration", CONFIG_DURATION },
    { NULL, NULL }
};
```

Using that mapper it is easy to build the correct htable variant:

```C
amxd_object_get_params(instance, &data, amxd_dm_access_private);
for(int i = 0; mapper[i].param_name != NULL; i++) {
    amxc_var_t* setting = GET_ARG(&data, mapper[i].param_name);
    amxc_var_set_key(settings, mapper[i].setting_name, setting, AMXC_VAR_FLAG_DEFAULT);
}
```

### Run-time configuration

In the main odl file `ssh_server.odl` the `%config` contains some `ssh_server` specific configuration:

```odl
%config {

    ...

    system-signals = [ 17 ]; // enable SIGCHILD

    ...

    dropbear-child-monitor = {
        enable = true,
        interval = 5000
    };

    ...

    ssh-server = {
        auto-restart = true
    };
}
```

The `system-signals` option is used by `amxrt`. It will make sure that system signal with ID 17 (SIGCHLD) is monitored by the event loop.
Whenever a SIGCHLD system signal is received, it will be converted to an amxp signal. That makes it possible to connect functions (slots) to this signal using the `amxp signal/slot` implementation.

The `dropear-child-monitor` contains settings that are used to start a timer. The timer callback function will fetch all PIDs of launched `dropbear` applications. The timer is only started when `enable` is set to true. The interval of the timer is taken from `interval`, this interval must be set in milli-seconds.

The `ssh-server` contains `ssh-server` settings used in this service:
- `auto-restart` - boolean and is used in the event callback function which is called when configuration parameters of a `SSH.Server.{i}.` are changed.