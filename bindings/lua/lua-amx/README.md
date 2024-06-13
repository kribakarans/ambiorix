# Ambiorix Lua bindings

[[_TOC_]]

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
    mkdir -p ~/amx_project/bindings/lua
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

- [libamxc](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxc) - Generic C api for common data containers
- [libamxj](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxj) - JSON parser & generator using yajl and libamxc variants
- [libamxp](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxp) - Common patterns implementation
- [libamxb](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxb) - PCB backend implementation for bus agnostic API
- [libamxd](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxd) - Data model C API
- [libamxo](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxo) - The ODL compiler library
- [libevent-dev](https://packages.debian.org/buster/libevent-dev)
- [liblua](https://github.com/lua/lua) - Supported versions: lua 5.1, lua 5.3

---
Dependency graph - libraries needed by lua-amx.
For graph simplicity direct dependencies which are also an indirect dependency are not shown.

```mermaid
graph TD;
  lua-amx-->libamxb
  lua-amx-->libamxj
  lua-amx-->libevent
  lua-amx-->liblua

  libamxp-->libamxc
  libamxd-->libamxp
  libamxb-->libamxd
  libamxj-->libamxc
```
---

#### Build lua-amx

1. Clone the git repository

    To be able to build it, you need the source code. So open the directory just created for the ambiorix project and clone this library in it (on your local machine).

    ```bash
    cd ~/amx_project/bindings/lua
    git clone git@gitlab.com:prpl-foundation/components/ambiorix/bindings/lua/lua-amx.git
    ``` 

1. Install dependencies

    Although the container will contain all tools needed for building, it does not contain the libraries needed for building `lua-amx`. To be able to build `lua-amx` you need `libamxc`, `libamxp`, `libamxd`, `libamxb` and `libamxo`. These libraries can be installed in the container by executing the following commands.

    ```bash
    sudo apt update
    sudo apt install libamxo libamxb
    ```

    Note that you do not need to install all components explicitly. Some components will be installed automatically because other components depend on them. Some of the components are allready preinstalled in the container.

1. Build it
    
    ```bash
    cd ~/amx_project/bindings/lua/lua-amx
    make
    ```

### Installing

#### Using make target install

You can install your own compiled version easily in the container by running the install target.

```bash
cd ~/amx_project/bindings/lua/lua-amx
sudo -E make install
```

### Testing

#### Prerequisites

No extra components are needed for testing `lua-amx`, all needed tools are installed in the container.

#### Run tests

You can run the tests by executing the following command.

```bash
cd ~/amx_project/bindings/lua/lua-amx/test
make
```

Or this command if you also want the coverage tests to run:

```bash
cd ~/amx_project/bindings/lua/lua-amx/test
make run coverage
```

Ot from the root directory of this repository,

```bash
cd ~/amx_project/bindings/lua/lua-amx
make test
```

This last will run the unit-tests and generate the test coverage reports in one go.

#### Coverage reports

The coverage target will generate coverage reports using [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html) and [gcovr](https://gcovr.com/en/stable/guide.html).

A summary for each file (*.c files) is printed in your console after the tests are run.
A HTML version of the coverage reports is also generated. These reports are available in the output directory of the compiler used.
Example: using native gcc
When the output of `gcc -dumpmachine` is `x86_64-linux-gnu`, the HTML coverage reports can be found at `~/amx_project/bindings/lua/lua-amx/output/x86_64-linux-gnu/coverage/report.`

You can easily access the reports in your browser.
In the container start a python3 http server in background.

```bash
cd ~/amx_project/
python3 -m http.server 8080 &
```

Use the following url to access the reports `http://<IP ADDRESS OF YOUR CONTAINER>:8080/bindings/lua/lua-amx/output/<MACHINE>/coverage/report`
You can find the ip address of your container by using the `ip` command in the container.

Example:

```bash
USER@<CID>:~/bindings/lua/lua-amx$ ip a
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
So the uri you should use is: `http://172.17.0.7:8080/bindings/lua/lua-amx/output/x86_64-linux-gnu/coverage/report/`

## Example scripts

### amx_wait_for

This script can be used to wait until objects become available in the data model.

The script will stop when the object is available.

Usage:
```
amx_wait_for <object path> [<object path> <object path>]
```

Example:
```
amx_wait_for "NetDev" "DHCPv4.Client" 
```

### amx_monitor_dm

Monitor certain parameters or objects in the data model. Changes are logged to a file.

This script takes 1 argument, a file containing a valid lua object.

Examples of a config object for the monitor script:
```
return {
  log_file = "/tmp/amx_mon_objects.log",
  objects = {
    {
      path = "Greeter.History.*.Info.*.",
      filter = "first_existing(parameters.Text.to, parameters.Text) in ['Boe1', 'Boe3']"
    }
  }
}
```

Above config object will cause the script to wait until object `Greeter.History.` becomes available and then take subscription on object `Greeter.History.*.Info.*.` with event filter `first_existing(parameters.Text.to, parameters.Text) in ["Boe1", "Boe3"]`. Each time an event is recieved it will be logged to the file `/tmp/amx_mon_objects.log`.

```
return {
  log_file = "/tmp/amx_mon_objects.log",
  objects = {
    {
      path = "Greeter.History.*.Info.*.",
      param = "Text",
      value = "Boe1"
    },
    {
      path = "Greeter.History.2.Info.*.",
      param = "Text",
      value = "Boe3",
      requires = "Greeter.History.2."
    }
  }
}
```

Above config object will cause the script to wait until object `Greeter.History.` becomes available. When the object is available it will check if there is an object that matches the path `Greeter.History.*.Info.*.` for which the parameter `Text` has the value `Boe1`.
It will also take a subscription on `Greeter.History.*.Info.*` and logs every time the `Text` parameter is set to value `Boe`.

It will start waiting for object `Greeter.History.2.Info.*.` as soon as object `Greeter.History.` became available. As soon as `Greeter.History.2.Info.` becomes available, the script will take a subscription on `Greeter.Histor.2.Info.*.` and monitors the value of the `Text` parameters.

It is possible to provide the log message in the config. This can be either a string or a function that returns a string.

```
local lamx = require 'lamx'

local create_log_message = function(path)
    local data = lamx.bus.get(path)

    return "Alias " .. data[path].Alias .. " is set"
end

return {
  log_file = "/tmp/amx_mon_objects.log",
  objects = {
    {
      path = "Greeter.History.*.Info.*.",
      param = "Text",
      value = "Boe1",
      comment = "This is a log message"
    },
    {
      path = "Greeter.History.2.Info.*.",
      param = "Text",
      value = "Boe3",
      requires = "Greeter.History.2.",
      comment = create_log_message
    }
  }
}
```

Above config will do exactly the same as previous config, but will write to the log file the message (comment) provided in the config.

The up time is always logged in front of the message in the log file.

Usage:
```
amx_monitor_dm <config object file>
```

Example output:
```
232599.84 - Available Greeter.History.*.Info.*.
232607.59 - Filter first_existing(parameters.Text.to) in ['Boe1', 'Boe3'] for path Greeter.History.1.Info.1. triggered
232631.29 - Available Greeter.History.*.Info.*.
232637.69 - Filter first_existing(parameters.Text.to, parameters.Text) in ['Boe1', 'Boe3'] for path Greeter.History.1.Info.1. triggered
232650.08 - Filter first_existing(parameters.Text.to, parameters.Text) in ['Boe1', 'Boe3'] for path Greeter.History.1.Info.3. triggered

```