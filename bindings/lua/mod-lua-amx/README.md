# mod-lua-amx

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
- [libamxp](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxp) - Common patterns implementation
- [libamxb](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxb) - PCB backend implementation for bus agnostic API
- [libamxd](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxd) - Data model C API
- [libamxo](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxo) - The ODL compiler library
- [libevent-dev](https://packages.debian.org/buster/libevent-dev)

#### Build mod-lua-amx

1. Clone the git repository

    To be able to build it, you need the source code. So open the directory just created for the ambiorix project and clone this library in it (on your local machine).

    ```bash
    cd ~/amx_project/bindings/lua
    git clone git@gitlab.com:prpl-foundation/components/ambiorix/bindings/lua/mod-lua-amx.git
    ``` 

1. Install dependencies

    Although the container will contain all tools needed for building, it does not contain the libraries needed for building `mod-lua-amx`. To be able to build `mod-lua-amx` you need `libamxc`, `libamxp`, `libamxd` and `libamxo`. These libraries can be installed in the container by executing the following commands.

    ```bash
    sudo apt update
    sudo apt install libamxo
    ```

    Note that you do not need to install all components explicitly. Some components will be installed automatically because other components depend on them. Some of the components are allready preinstalled in the container.

1. Build it
    
    ```bash
    cd ~/amx_project/bindings/lua/mod-lua-amx
    make
    ```

### Installing

#### Using make target install

You can install your own compiled version easily in the container by running the install target.

```bash
cd ~/amx_project/bindings/lua/mod-lua-amx
sudo -E make install
```

### Testing

#### Prerequisites

No extra components are needed for testing `mod-lua-amx`, all needed tools are installed in the container.

#### Run tests

You can run the tests by executing the following command.

```bash
cd ~/amx_project/bindings/lua/mod-lua-amx/test
make
```

Or this command if you also want the coverage tests to run:

```bash
cd ~/amx_project/bindings/lua/mod-lua-amx/test
make run coverage
```

Ot from the root directory of this repository,

```bash
cd ~/amx_project/bindings/lua/mod-lua-amx
make test
```

This last will run the unit-tests and generate the test coverage reports in one go.

#### Coverage reports

The coverage target will generate coverage reports using [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html) and [gcovr](https://gcovr.com/en/stable/guide.html).

A summary for each file (*.c files) is printed in your console after the tests are run.
A HTML version of the coverage reports is also generated. These reports are available in the output directory of the compiler used.
Example: using native gcc
When the output of `gcc -dumpmachine` is `x86_64-linux-gnu`, the HTML coverage reports can be found at `~/amx_project/bindings/lua/mod-lua-amx/output/x86_64-linux-gnu/coverage/report.`

You can easily access the reports in your browser.
In the container start a python3 http server in background.

```bash
cd ~/amx_project/
python3 -m http.server 8080 &
```

Use the following url to access the reports `http://<IP ADDRESS OF YOUR CONTAINER>:8080/bindings/lua/mod-lua-amx/output/<MACHINE>/coverage/report`
You can find the ip address of your container by using the `ip` command in the container.

Example:

```bash
USER@<CID>:~/bindings/lua/mod-lua-amx/libamxd$ ip a
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
So the uri you should use is: `http://172.17.0.7:8080/bindings/lua/mod-lua-amx/output/x86_64-linux-gnu/coverage/report/`

## Using mod-lua-amx

### Import the module

In your odl file `import` the shared object of this module and make sure its entry point is called. This is typically done in the main odl file.

```odl
import "mod-lua-amx.so" as "mod_lua";

%define {
    entry-point mod_lua.mod_lua_main;
}
```

After importing it, a function resolver is added that can resolve RPC methods and event handlers that are written in LUA. 

### Implementing a RPC method using lua

When `mod-lua-amx` is imported it is possible to write a RPC method using a LUA script. Indicate in the odl file, behind the RPC method definition that the LUA function resolver needs to be used.

Example:

```odl
%define {
    object MyObject {
        uint32 Number = 0;
        string Text = "";

        uint32 MyRpc(%in string text, %in uint32 number, %out string combined) <!LUA:
            function(object, args)
                local pretty = require 'pl.pretty'
                local out_args = { }
                local transaction = lamx.transaction.new()

                print("Method MYRpc called on object " .. object:get_path())
                pretty.dump(args)

                transaction:select(object)
                transaction:set("Number", args.number)
                transaction:set("Text", args.text)
                transaction:apply()

                out_args.combined = args.text .. " - " .. tostring(args.number)
                return args.number, out_args
            end
        !>;
    }
}
```

To indicate that the RPC method is implemented using LUA, use the function resolver instruction `<!LUA:` and close it with `!>;`. In between implement the RPC method using LUA.

The LUA function will be called with two arguments:
1. The data model object
1. The RPC method arguments, as a table

In the RPC LUA implementation almost all of the [lua-amx API's](http://sah2artifactory01.be.softathome.com:10000/documentation/ambiorix/bindings/lua/lua-amx/master/) can be used. Some lua-amx methods or classes will not be available. For more information see the notes at the end of this document.

The data model object argument is an instance of the class [dmobject](http://sah2artifactory01.be.softathome.com:10000/documentation/ambiorix/bindings/lua/lua-amx/master/classes/dmobject.html)

The first return value of the LUA RPC method implementation will be used as the data model RPC method return value, the second return value must be a table and will be used as the out arguments of the data model RPC method.

### Implementing an event handler

Similar to the RPC method implementation, event handlers can be implemented using a LUA script after the module has been imported.

Example:

```odl
%populate {
    on event "dm:object-changed" call MyEventHandler <!LUA:
            function(object, event, data)
                local pretty = require 'pl.pretty'

                print("Event " .. event .. " received for object " .. object:get_path())
                pretty.dump(data)
            end
        !> filter 'parameters.Number.from < 100 && parameters.Number.to >= 100';
}
```

The resolver instruction must be placed right after the function name.

The LUA event handler will be called with 3 arguments:
1. The data model object (instance of class dmobject)
1. The event name (a string)
1. The event data (a table)

In the event handler almost all the [lua-amx API's](http://sah2artifactory01.be.softathome.com:10000/documentation/ambiorix/bindings/lua/lua-amx/master/) can be used. Some lua-amx methods or classes will not be available. For more information see the notes at the end of this document.

### Limitations and Considerations

#### Unavailable lua-amx classes and methods

Some of the lua-amx methods or classes will not be available in the LUA RPC method or event handler implementations:

1. Class `eventloop` will not be available
1. Method `lamx.dm.create` will not be available
1. Method `lamx.dm.destroy` will not be available
1. Method `lamx.bus.register` will not be availble

Typically an odl file is loaded using [amxrt](https://gitlab.com/prpl-foundation/components/ambiorix/applications/amxrt) which will create the data model, registers it to the bus system and create an eventloop. The data model life cycle is also managed by `amxrt`.

Another option is that a LUA script is used to load the odl file and create the event loop, in that case the script will be managing the data model life cycle and eventloop.

Example lua script to launch a data model:

```lua
#!/usr/bin/env lua

local lamx = require 'lamx'
local connections = { 
    ["ubus:"] = "/usr/bin/mods/amxb/mod-amxb-ubus.so",
    ["pcb:/var/run/pcb_sys"] = "/usr/bin/mods/amxb/mod-amxb-pcb.so"
}

local el = lamx.eventloop.new()

local load_be = function(so_path, uri)
    lamx.backend.load(so_path)
    lamx.bus.open(uri, "protected")
end

lamx.dm.create()
lamx.dm.load("./lua_odl_methods/lua_dm_methods.odl")

for socket, backend in pairs(connections) do
    if(pcall(load_be, backend, socket)) then
        print("Loaded " .. backend .. " back-end")
    else
        print("Failed to load " .. backend .. " back-end")
    end
end

lamx.bus.register()

el:start()

lamx.dm.destroy()
lamx.backend.remove("pcb")
lamx.backend.remove("ubus")
```

The above LUA script is basically the same as:

```bash
> amxrt ./lua_odl_methods/lua_dm_methods.odl
```

#### ODL LUA methods run in a separate LUA stack

A separate LUA stack is created for the odl LUA methods (RPC's and event handlers). This is mainly done for security considerations, to make it possible to limit what can be done in these LUA method implementations.

A side effect is that it will not be possible to call LUA functions defined in the main lua script, if the data model is started with a lua script.
