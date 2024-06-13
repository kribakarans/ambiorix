# Python3 AMX Language Bindings

[[_TOC_]]

## Introduction

These Python AMX Bindings allow users to interact with AMX plugins in several ways:

- Interacting with Ambiorix Data Models
- Calling Ambiorix Data Model Functions
- Make use of AMX Timers in Python
- Subscribing to AMX Events in Python

## Building, installing and testing

### Docker container

You could install all tools needed for testing and developing on your local machine, but it is easier to just use a pre-configured environment. Such an environment is already prepared for you as a docker container.

1. Install docker

    Docker must be installed on your system.

    If you have no clue how to do this here are some links that could help you:

    - [Get Docker Engine - Community for Ubuntu](https://docs.docker.com/install/linux/docker-ce/ubuntu/)
    - [Get Docker Engine - Community for Debian](https://docs.docker.com/install/linux/docker-ce/debian/)
    - [Get Docker Engine - Community for Fedora](https://docs.docker.com/install/linux/docker-ce/fedora/)
    - [Get Docker Engine - Community for CentOS](https://docs.docker.com/install/linux/docker-ce/centos/)  <br /><br />
    
    Make sure your user id is added to the docker group:

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
    mkdir -p ~/amx_project/bindings/
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
- [libevent-dev](https://packages.debian.org/buster/libevent-dev)

#### Build Python AMX bindings

1. Clone the git repository

    To be able to build it, you need the source code. So open the directory just created for the ambiorix project and clone this library in it (on your local machine).

    ```bash
    mkdir -p ~/amx_project/bindings
    cd ~/amx_project/bindings
    git clone git@gitlab.com:prpl-foundation/components/ambiorix/bindings/python3.git
    ``` 

1. Install dependencies

    Although the container will contain all tools needed for building, it does not contain the libraries needed for building `python-amx`. To be able to build `python-amx` you need `libamxc`, `libamxp`, `libamxd`, `libamxb` and `libevent-dev`. These libraries can be installed in the container.

    ```bash
    sudo apt update
    sudo apt install libamxb libevent-dev
    ```

    Note that you do not need to install all components explicitly. Some components will be installed automatically because the other components depend on them. Some of the components are allready preinstalled in the container.

1. Build it

    ```bash
    cd ~/amx_project/bindings/python3
    make
    ```

### Installing

#### Manual install

You can install your own compiled version easily by running the following command after building by performing.
```bash
cd ~/amx_project/bindings/python3
sudo python3 -m pip install --upgrade src/dist/*.whl
```

### Testing

#### Prerequisites

For testing `pamx`, pytest is needed.

```bash
sudo python3 -m pip install pytest
```

#### Run tests

You can run the tests by executing the following command.

```bash
cd ~/amx_project/bindings/python3/test
make
```

Or this command if you also want the coverage tests to run:

```bash
cd ~/amx_project/bindings/python3/test
make run coverage
```

#### Coverage reports

The coverage target will generate coverage reports using [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html) and [gcovr](https://gcovr.com/en/stable/guide.html).

A summary for each file (*.c files) is printed in your console after the tests are run.
A HTML version of the coverage reports is also generated. These reports are available in the output directory of the compiler used.
Example: using native gcc
When the output of `gcc -dumpmachine` is `x86_64-linux-gnu`, the HTML coverage reports can be found at `~/amx_project/bindings/python3/output/x86_64-linux-gnu/coverage/report.`

You can easily access the reports in your browser.
In the container start a python3 http server in background.

```bash
cd ~/amx_project/bindings
python3 -m http.server 8080 &
```

Use the following url to access the reports `http://<IP ADDRESS OF YOUR CONTAINER>:8080/bindings/python3/output/<MACHINE>/coverage/report`
You can find the ip address of your container by using the `ip` command in the container.

Example:

```bash
USER@<CID>:~/amx_project/bindings/python3$ ip a
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
So the uri you should use is: `http://172.17.0.7:8080/bindings/python3/output/x86_64-linux-gnu/coverage/report/`

## Documentation and Examples

This section will provide documentation and examples of how to use the Python AMX bindings in your Python scripts.

The examples rely on two amxrt plugins and a running ubus and pcb_sysbus.
To intialize this environment manually, perform: 

```bash
sudo -E pcb_sysbus -I /tmp/local
sudo -E ubusd &
cd ~/amx_project/bindings/python3/test/model
amxrt -D conversion.odl
amxrt -D phonebook.odl
```

### pamx.backend

One powerful aspect of amx is that it is compatible with multiple process bus implementations. A user simply needs to load in the proper backend .so file. The `pamx.backend` object allows users to load and remove any amx backend .so files. It can also list the currently loaded backends.

#### pamx.backend.load

This method will load a specified backend.

Parameters:
* path: string specifying the path of the .so file to load.

This method raises pamx.AMXError if the .so file cannot be loaded.

Example:
```
>>> import pamx
>>> pamx.backend.load("/usr/bin/mods/amxb/mod-amxb-pcb.so")
```

#### pamx.backend.set_config

This method will set a config for the backends. When called without any parameters, the default config will be set.
Optionally, you can pass a python dict to specify config values.

Example:
```
>>> pamx.backend.set_config()
```

#### pamx.backend.list

This method will list the names of the currently loaded backends.

Example:
```
>>> pamx.backend.list()
['pcb']
```

#### pamx.backend.remove

This method will remove a specified loaded backend
Parameters:
* path: string specifying the name of the currently loaded backend to be removed. This wil render all connections made with this backend useless.

This method raises pamx.AMXError if the backend cannot be removed.

Example:
```
>>> pamx.backend.remove("pcb")
>>> pamx.backend.list()
[]
```

### pamx.eventloop

The Python amx bindings also contains the `pamx.eventloop` object. This allows the user to start and stop an eventloop, which is necessary for event monitoring.
```
pamx.eventloop.start()
pamx.eventloop.stop()
```

### pamx.bus

The `pamx.bus` object allows users to create connections to a process bus. It can also scan existing connections for existing objects and return a connection that has the requested object.

#### pamx.bus.connect

This method will create a connection to the specified url. It is necessary that the corresponding backend has been loaded using `pamx.backend.load` first.

Parameters:
* uri: string specifying the uri with which the user wants to connect.

This method raises pamx.AMXError if the connection cannot be made

It will return a pamx Connection object.

Example:
```
connection = pamx.bus.connect("pcb:/tmp/local")
```

#### pamx.bus.who_has

This method will scan existing connections for a object specified by the provided path. It is important to note that this method will not create any connections itself. It can only look through the currently open connections.
Parameters:
* path: string specifying the path of the object the user is looking for.

    This function supports following paths:
    * object path - must end with a "."

This method raises pamx.AMXError if no open connection provides the requested path.

It will return a pamx Connection object which contains the path.

Example:
```
>>> pamx.bus.who_has("Phonebook.")
<pamx.PAMXConnection object at 0x7f0dea2ba708>
```

### pamx connection objects

PAMX connection objects provide a multitude of methods to interact with a data model.

#### connection.uri
The uri attribute of pamx connection objects is the uri to which the connection was made. This cannot be changed later on.

Example:
```
>>> connection = pamx.bus.connect("pcb:/tmp/local")
>>> connection.uri
'pcb:/tmp/local'
```

#### connection.access_level

The access level attribute of pamx connection objects will impact the return values of calls made with the respective connection. The current supported access levels are `public` and `protected`. The default value is `public`

Example:
```
>>> connection = pamx.bus.connect("pcb:/tmp/local")
>>> connection.access_level
'public'
```

#### connection.add

Adds an instance to a multi-instance object.
Using this method, an instance can be created and the parameters values of that instance can be set.
It is not possible to create an instance for a read-only multi instance object.
It is not possible to set the value of read-only parameters using this function.

Parameters:
* path:
    
    This function supports following paths:
    * object path - must end with a "."

* values: 

    A python dictionary containing the values for the new instance.
    Note: Any datetime objects will be converted to utc time.

* index:
    If not 0, the index the new instance must have. Otherwise the next available index will be used.
    Default value: 0

* name:
    Optional parameter specifiying the name for the new instance.
    Default value: None

* timeout_sec: 

    Timeout in seconds.
    Default value: 5

Returns a list containing the newly added instance. The method shall raise pamx.AMXError if the instance cannot be added for any reason e.g. name or index clash.

Example:
```
>>> connection.add(
...         "Phonebook.Contact.", {
...             "FirstName": "John", "LastName": "Doe"})
[{'object': 'Phonebook.Contact.1.', 'index': 1, 'name': '1', 'parameters': {},   'path': 'Phonebook.Contact.1.'}]

```

#### connection.get

Fetches one or more objects or a single parameter.
It is possible to get the parameters from multiple objects at once or to get one single parameter of one or more objects.

Parameters:
* path:
    
    This function supports following paths:
    * object path - must end with a "."
    * search path - can contain expressions or wildcard to filter out instances. they can end with a parameter name, a "." or a "*"
    * parameter path - must end with a parameter name (no "." at the end)

    In a search path a wildcard "*" or an expression can be put where an instance identifier (instance index) is in an object path.

    Examples of valid search paths:
    ```
    "Phonebook.Contact.*."
    "Phonebook.Contact.*"
    "Phonebook.Contact.[FirstName == 'Jane']."
    "Phonebook.Contact.*.FirstName"
    "Device.IP.Interface.[Type=='Normal'].IPv4Address.[AddressingType=='Static'].IPAddress"
    "Device.IP.Interface.[Type=='Normal' && Stats.ErrorsSent>0].IPv4Address.[AddressingType=='Static'].IPAddress"
    ```

* depth: 

    relative depth, if not zero it indicates how many levels of child objects are returned 
    Default value: 0

* timeout_sec: 

    Timeout in seconds.
    Default value: 5

This function a list containing all matching objects and parameters.

Example:
```
>>> connection.get("Phonebook.Contact.1.")
[{'Phonebook.Contact.1.': {'LastName': 'Doe', 'Plugin': 'PAMX', 'FirstName': 'John'}}]

```

Trick:
Use json to get a readable output:
```
>>> import json
>>> contact = connection.get("Phonebook.Contact.1.")
>>> print(json.dumps(contact, sort_keys=True, indent=2)))
[
  {
    "Phonebook.Contact.1.": {
      "FirstName": "John",
      "LastName": "Doe",
      "Plugin": "PAMX"
    }
  }
]
```

#### connection.set

Sets parameter values of one single object or of multiple instance objects.
Using this method, the parameter values of an object can be changed.
It is not possible to change read-only parameter values using this function. 

Parameters:
* path:
    
    This function supports following paths:
    * object path - must end with a "."
    * search path - can contain expressions or wildcard to filter out instances. and must end with a "." or "*"

    In a search path a wildcard "*" or an expression can be put where an instance identifier (instance index) is in an object path.

    Examples of valid search paths:
    ```
    Phonebook.Contact.*.
    Phonebook.Contact.*
    Phonebook.Contact.[FirstName == 'Jane'].
    Device.IP.Interface.[Type=='Normal'].IPv4Address.[AddressingType=='Static'].
    Device.IP.Interface.[Type=='Normal' && Stats.ErrorsSent>0].IPv4Address.[AddressingType=='Static'].
    ```

* values: 

    A python dictionary containing the values that need to be set.

* timeout_sec: 

    Timeout in seconds.
    Default value: 5

This function returns a list of all modified values.

Example:
```
>>> path = "Phonebook.Contact.1."
>>> connection.set(path, {"FirstName": "Jane"})
[{'Phonebook.Contact.1.': {'FirstName': 'Jane'}}]
```

#### connection.delete

Deletes one or more instances of a multi-instance object.
Using this method, one or more instances can be deleted from a multi-instance object.
It is not possible to delete instances from a read-only multi instance object.

Parameters:
* path:
    
    This function supports following paths:
    * object path - must end with a "."
    * search path - must end with a "." or "*"

    The provided paths must either result or point to:
    * a multi-instance object (should be exactly one)
    * an instance (can be more then one)

    When the given path is a multi-instance object, an index or name of the instance that will be deleted must be given. If both an index (instance identifier) and a name are given, the index takes precedence.
    When the given path is an instance path, index and name arguments are ignored.
    When the given path is a search path where multiple-instances match, all of the matching instances will be deleted and the index and name arguments are ignored.

* index:
    If not 0, the index of the instance that must be deleted.
    Default value: 0

* name:
    Optional parameter specifiying the name for the to be deleted instance.
    Default value: None

* timeout_sec: 

    Timeout in seconds.
    Default value: 5

Returns a list containing the deleted instances.

Example:
```
>>> connection.delete("Phonebook.Contact.1.")
['Phonebook.Contact.1.']
>>> connection.get("Phonebook.Contact.1.")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
pamx.AMXError: Could not perform get
```

#### connection.describe

Describes an object.
This function is mainly used for data model introspection. Besides the values of the parameters, more information can be obtained.
Use this function for introspection purposes.

Parameters:
* path:
    
    This function supports following paths:
    * object path - must end with a "."

* functions:

    If 1, information about the object's functions is included.
    Default value: 0

* parameters:

    If 1, information about the object's parameters is included.
    Default value: 0

* objects:

    If 1, information about the object's child objects is included.
    Default value: 0

* instances:

    If 1, information about the object's instances is included.
    Default value: 0

* timeout_sec: 

    Timeout in seconds. 
    Default value: 5

The Information included in the returned data structure is:
* parameter, object, function attributes
* index and name - for instance objects
* indexed and named object path (path and object fields)
* type information for parameters, objects and functions
* function names, and all function arguments

Example:
```
description = connection.describe(
>>> connection.describe("Phonebook.Contact.1.")
[
    {
        'attributes': 
        {
            'private': False,
            'read-only': False,
            'locked': False,
            'protected': False,
            'persistent': False
        },
        'object': 'Phonebook.Contact.',
        'index': 1,
        'name': '1',
        'type_id': 3,
        'type_name': 'instance',
        'path': 'Phonebook.Contact.'
    }
]

```

#### connection.get_supported

Gets the supported data model.
This function is mainly used to have support for the USP "get supported dm" message.
Use this function for introspection purposes.

This function does not return any instance, it only indicates which objects are multi-instance objects. The place in the object path where normally an instance identfier (index) is set, the place holder "{i}" is used.

Use this function for introspection purposes.

Parameters:
* path:
    
    Must be in this supported data model notation.
    Example:
    ```
    "Phonebook.Contact.{i}.PhoneNumber.{i}."
    ```

* first_level:

    If 1, exclude child objects.
    Default value: 0

* functions:

    If 1, information about the object's functions is included.
    Default value: 0

* parameters:

    If 1, information about the object's parameters is included.
    Default value: 0

* events:

    If 1, information about the object's events is included.
    Default value: 0

* timeout_sec: 

    Timeout in seconds. 
    Default value: 5

Returns a structure containing the requested information.

Example:
```
>>> connection.get_supported("Phonebook.Contact.{i}.")
[{'Phonebook.Contact.{i}.': {'is_multi_instance': True, 'access': 1}}]
```

#### connection.list

List the service elements/nodes of an object.
This function is mainly used for data model introspection and provides list of the service elements/nodes that are part of the object.
Use this function for introspection purposes.

Parameters:
* path:
    
    Must be in this supported data model notation.
    Example:
    ```
    "Phonebook.Contact.{i}.PhoneNumber.{i}."
    ```

* function:

    Callback function. If an error occurs in the callback functions, the bindings will stop any active eventloop.

* userdata:
    
    Optional data that will be passed to the callback function. 

* functions:
    
    If 1, information about the object's functions is included.
    Default value: 0

* parameters:
    
    If 1, information about the object's parameters is included.
    Default value: 0

* objects:
    
    If 1, information about the object's child objects is included.
    Default value: 0

* instances:
    
    If 1, information about the object's instances is included.
    Default value: 00


Example:
```
>>> def list_handler(data):
...     """ callback function for list handler """
...     print(data)
...
>>> connection.list(
...     "Phonebook.Contact.",
...     list_handler,
...     functions=1,
...     parameters=1,
...     objects=1,
...     instances=1)
>>> pamx.eventloop.start()
[]
['Phonebook.Contact.1.', 'Phonebook.Contact.1.LastName', 'Phonebook.Contact.1.Plugin', 'Phonebook.Contact.1.FirstName']
None

```

#### connection.call

Invokes a data model function.
Calls a data model method. A data model method is a function that is exposed in the data model in a specific object.
If no response is received before the timeout expires, this function will return an error, but it is possible that the RPC method is still busy.

Parameters:

* path:
    
    Path of the object whose function the user wishes to invoke
    This function supports following paths:
    * object path - must end with a "."

* function:
    Name of the function to invoke

* parameters:
    Python dictionary containing parameters for the functions. This is optional 

* timeout_sec: 

    Timeout in seconds. 
    Default value: 5

This function returns the return value of the method call.


Example:
```
>>> path = "Phonebook.Contact.1."
>>> connection.call(path, "_get")
[{'Phonebook.Contact.1.': {'LastName': 'Doe', 'Plugin': 'PAMX', 'FirstName': 'John'}}]

```

#### connection.async_call

Invokes a data model function asynchronously.
Calls a data model method. A data model method is a function that is exposed in the data model in a specific object.
If no response is received before the timeout expires, this function will return an error, but it is possible that the RPC method is still busy.

Parameters:
* path:
    
    Path of the object whose function the user wishes to invoke
    This function supports following paths:
    * object path - must end with a "."

* function:
    Name of the function to invoke

* callback:
    Callback function. This is optional 

* userdata: 
    Userdata for callback function. This is optional 


This function returns a pamx request object. This request contains a wait method which will allow the script to await completion of the asynchronous function call.


Example:
```
>>> connection.get("Phonebook.Contact.ASYNC.")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
pamx.AMXError: Could not perform get
>>> request = connection.async_call(
...     "Phonebook.Contact.", "_add", {
...         "name": "ASYNC"})
>>> request.wait()
>>> connection.get("Phonebook.Contact.ASYNC.")
[{'Phonebook.Contact.ASYNC.': {'LastName': '', 'Plugin': 'PAMX', 'FirstName': ''}}]
```

#### connection.subscribe

Subscribes for events of a object tree.
Subscribes for all events matching the given filter on an object (sub)tree.
Using the provided object path, all events matching the given expression, of that object or any of the child objects (instances included) are passed to the callback function.

Parameters:
* path:
    
    Path of the object whose function the user wishes to invoke
    This function supports following paths:
    * object path - must end with a "."

* expression:
    Expression to filter the events of the subscription.

* callback:
    Callback function. If an error occurs during the callback function, any active eventloops are stopped.

* userdata: 
    Userdata for callback function. This is optional


This function returns a subscription object. This request contains a close method which will remove the subscription.


Example:
```
>>> def contact_added_with_userdata(sig_name, data, userdata):
...     """ Callback function for subscriptions with userdata """
...     print(sig_name)
...     print(data)
...     pamx.eventloop.stop()
... 
>>> params = {
...     "FirstName": "Subscription",
...     "LastName": "Test",
...     "Plugin": "PAMX"}
>>> sub = connection.subscribe(
...     "Phonebook.Contact.",
...     "notification in ['dm:instance-added']",
...     contact_added_with_userdata,
...     ["SubTest", params])
>>> connection.async_call(
...     "Phonebook.Contact.", "_add", {
...         "name": "SubTest", "parameters": params})
<pamx.PAMXRequest object at 0x7f6e1fb81b20>
>>> pamx.eventloop.start()
>>> def contact_added_with_userdata(sig_name, data, userdata):
...     """ Callback function for subscriptions with userdata """
...     print(sig_name)
...     print(data)
...     pamx.eventloop.stop()
... 
>>> params = {
...     "FirstName": "Subscription",
...     "LastName": "Test",
...     "Plugin": "PAMX"}
>>> sub = connection.subscribe(
...     "Phonebook.Contact.",
...     "notification in ['dm:instance-added']",
...     contact_added_with_userdata,
...     ["SubTest", params])
>>> connection.async_call(
...     "Phonebook.Contact.", "_add", {
...         "name": "SubTest", "parameters": params})
<pamx.PAMXRequest object at 0x7f6e1fb81b20>
>>> pamx.eventloop.start()
Phonebook.Contact
{'object': 'Phonebook.Contact.', 'index': 6, 'keys': {}, 'notification': 'dm:instance-added', 'name': 'SubTest', 'parameters': {'LastName': 'Test', 'Plugin': 'PAMX', 'FirstName': 'Subscription'}, 'path': 'Phonebook.Contact.'}

```

#### connection.close

The close method closes the connection. After this, the connection can no longer be used.

Example:
```
connection.close()
```

### pamx request objects

PAMX request objects allow users to await completion of async method calls.

#### request.wait

This method awaits the completion of the async method call related to this request.

Parameters:
* timeout:
    The amount of seconds the wait may take.
    Default value: 5

This method raises an error if the wait times out.

#### request.close

This method closes the request and will cancel all calls to the callback function.
This also happens automatically when the request is garbage collected.

### pamx subscriptions objects

PAMX subscriptions objects allow users to manage data model subscriptions.

#### subscription.close

This method closes the request and will remove the subscription.
This also happens automatically when the sbuscription is garbage collected.

### Python AMX Timers

The Python AMX bindings offer support for AMX timers.

#### pamx.Timer

Creation parameters:

* callback: The function that needs to be called once the timer expires. This parameter is not optional.
* callback_data: The parameters for the callback function. If the callback does not require parameters, callback_data can be omitted.
* interval: The interval for the timer in seconds. This is optional.  

Python timer objects have three attributes.

* state: String representation of the current state of the timer. This cannot be changed manually. Possible values are "OFF", "STARTED", "RUNNING" and "EXPIRED".
* remaining: The remaining time of the timer in milliseconds. This cannot be set manually.
* interval: The current interval value of the timer. This can be changed manually.

```
>>> def end_of_timer(data):
...     print(data)
...     pamx.eventloop.stop()
... 
>>> timer = pamx.Timer(callback=end_of_timer,callback_data=(1,2),interval=5)
>>> timer.start(1000)
>>> pamx.eventloop.start()
(1, 2)
>>> timer.stop()

>>> timer.interval
5
>>> timer.state
'OFF'
>>> timer.remaining
0
```

#### timer.start

This function starts the timer.

Parameters:
The amount of milliseconds after which this timer will time out.

```
timer.start(1000)
```

#### timer.stop

This method stops the timer.

```
timer.stop()
```

### Python AMX DMOBject

The Python AMX bindings offer support for users to interact with data model objects as if they were python objects.

#### pamx.DMObject

Creation parameters:
* object_path: 

    The path of the object the user wants to interact with.
    This function supports following paths:

    * object path - must end with a "."

This object allows users to directly access object parameters and functions as if it was a regular python object.
All available protected methods of the object are available under the dmmngt subobject. These protected methods are only available if a connection with protected access level exists to the bus with the data model.

Example: 
```
>>> connection.access_level="protected"
>>> template = pamx.DMObject("Phonebook.Contact.")
>>> template.__dict__
{'LastName': <pamx.DMParameter object at 0x7f5f87788ba0>, 'Plugin': <pamx.DMParameter object at 0x7f5f87788b70>, 'FirstName': <pamx.DMParameter object at 0x7f5f87788b10>}
>>> template.dmmngt.__dict__
{'exec': <pamx.DMMethod object at 0x7f5f87785b98>, 'add': <pamx.DMMethod object at 0x7f5f87785b20>, 'delete': <pamx.DMMethod object at 0x7f5f87785b48>, 'set': <pamx.DMMethod object at 0x7f5f87785be8>, 'describe': <pamx.DMMethod object at 0x7f5f87785c38>, 'get_supported': <pamx.DMMethod object at 0x7f5f87785c60>, 'list': <pamx.DMMethod object at 0x7f5f877859e0>, 'get': <pamx.DMMethod object at 0x7f5f87785c88>}
>>> template.dmmngt.add({"name": "OBJECTTEST", "index": 456, "parameters": {
...                 "FirstName": "OBJECT", "LastName": "TEST"}})
[{'object': 'Phonebook.Contact.OBJECTTEST.', 'index': 456, 'name': 'OBJECTTEST', 'parameters': {}, 'path': 'Phonebook.Contact.456.'}]
>>> 
>>> path = "Phonebook.Contact.OBJECTTEST."
>>> contact = pamx.DMObject(path)
>>> contact.FirstName
'OBJECT'
>>> contact.LastName
'TEST'
```

#### DMObject.__dict__
Any pamx.DMObject that isn't a template object contains a __dict__ attribute.
This is a dict containing all parameter values of this object.
Example:
```
>>> conversion = connection.get("Conversion.")
>>> conversion_obj = pamx.DMObject("Conversion.")
>>> conversion_obj.__dict__
{'1': <pamx.DMObject object at 0x7f1456264ba8>, '123': <pamx.DMObject object at 0x7f14561a0180>, '125': <pamx.DMObject object at 0x7f14561a0528>, '126': <pamx.DMObject object at 0x7f14561a00b0>, '127': <pamx.DMObject object at 0x7f14561a0d48>, '128': <pamx.DMObject object at 0x7f14561a0db0>, '129': <pamx.DMObject object at 0x7f14561a0e18>, '130': <pamx.DMObject object at 0x7f1456155118>, '456': <pamx.DMObject object at 0x7f1456155180>}

```

#### DMObject.async_methods

All pamx.DMobject instances have a async_methods attribute. This includes asynchronous versions of all the available mehods of the object. Invoking any one of these methods returns a pamx request object. Asynchronous versions of the available protected methods are availabe under async_methods.protected. These protected methods are only available if a connection with protected access level exists to the bus with the data model.

Example: 
```
>>> connection.access_level="protected"
>>> template = pamx.DMObject("Phonebook.Contact.")
>>> dir(template.async_methods.protected)
['add', 'delete', 'describe', 'exec', 'get', 'get_supported', 'list', 'set']
>>> request = template.async_methods.add({"name": "OBJECTASYNC"})
>>> request.wait()
>>> connection.get("Phonebook.Contact.OBJECTASYNC.")
[{'Phonebook.Contact.OBJECTASYNC.': {'LastName': '', 'Plugin': 'PAMX', 'FirstName': ''}}]
```

#### DMObject.dmmngt.type_name
pamx.DMobject.dmmngt has the type_name attribute. This contains a string identifying the type of the associated object

Example: 
```
>>> phonebook = pamx.DMObject("Phonebook.")
>>> phonebook.dmmngt.type_name
'singleton'
>>> contact = pamx.DMObject("Phonebook.Contact.")
>>> contact.dmmngt.type_name
'template'
>>> instance = pamx.DMObject("Phonebook.Contact.1.")
>>> instance.dmmngt.type_name
'instance'
```

#### DMObject.dmmngt.instances
pamx.DMobject.dmmngt has the instances function. This will return a dict containing all instances of this object. If the object is not a template, the function will return None
Example: 
```
>>> contact = pamx.DMObject("Phonebook.Contact.")
>>> contact.dmmngt.instances()
{'1': <pamx.DMObject object at 0x7f1456264ba8>, '123': <pamx.DMObject object at 0x7f14561a0180>, '125': <pamx.DMObject object at 0x7f14561a0528>, '126': <pamx.DMObject object at 0x7f14561a00b0>, '127': <pamx.DMObject object at 0x7f14561a0d48>, '128': <pamx.DMObject object at 0x7f14561a0db0>, '129': <pamx.DMObject object at 0x7f14561a0e18>, '130': <pamx.DMObject object at 0x7f1456155118>, '456': <pamx.DMObject object at 0x7f1456155180>}
```

#### DMObject.dmmngt.objects
pamx.DMobject.dmmngt has the objects function. This will return a dict containing all subobjects of this object.
Example: 
```
>>> phonebook = pamx.DMObject("Phonebook.")
>>> phonebook.dmmngt.objects()
{'Contact': <pamx.DMObject object at 0x7f14561a0ce0>}
```

#### DMObject.dmmngt.subscribe

pamx.DMobject.dmmngt has the subscribe method. This method will open a subscription to events of this object.

Parameters:
* expression:
    Expression to filter the events of the subscription.

* callback:
    Callback function. If an error occurs during the callback function, any active eventloops are stopped.

* userdata: 
    Userdata for callback function. This is optional.

It returns a subscription object.

Example: 
```
>>> def dm_contact_added_with_userdata(sig_name, data, userdata):
...     """ Callback function for subscriptions with userdata """
...     print(sig_name)
...     print(data)
...     print(userdata)
...     pamx.eventloop.stop()
... 
>>> template = pamx.DMObject("Phonebook.Contact.")
>>> userdata = {
...     "FirstName": "Subscription",
...     "LastName": "Test",
...     "Plugin": "PAMX"}
>>> sub = template.dmmngt.subscribe(
...     "notification in ['dm:instance-added']",
...     dm_contact_added_with_userdata,
...     userdata)
>>> connection.async_call(
...     "Phonebook.Contact.", "_add", {
...         "name": "DMSubTest2", "parameters": userdata})
<pamx.PAMXRequest object at 0x7f6e1f3fff80>
>>> pamx.eventloop.start()
Phonebook.Contact
{'object': 'Phonebook.Contact.', 'index': 456, 'keys': {}, 'notification': 'dm:instance-added', 'name': 'OBJECTTEST', 'parameters': {'LastName': 'TEST', 'Plugin': 'PAMX', 'FirstName': 'OBJECT'}, 'path': 'Phonebook.Contact.'}
Phonebook.Contact
{'object': 'Phonebook.Contact.', 'index': 456, 'keys': {}, 'notification': 'dm:instance-added', 'name': 'OBJECTTEST', 'parameters': {'LastName': 'TEST', 'Plugin': 'PAMX', 'FirstName': 'OBJECT'}, 'path': 'Phonebook.Contact.'}
{'FirstName': 'Subscription', 'LastName': 'Test', 'Plugin': 'PAMX'}
Phonebook.Contact
{'object': 'Phonebook.Contact.', 'index': 457, 'keys': {}, 'notification': 'dm:instance-added', 'name': 'OBJECTASYNC', 'parameters': {'LastName': '', 'Plugin': 'PAMX', 'FirstName': ''}, 'path': 'Phonebook.Contact.'}
Phonebook.Contact
{'object': 'Phonebook.Contact.', 'index': 457, 'keys': {}, 'notification': 'dm:instance-added', 'name': 'OBJECTASYNC', 'parameters': {'LastName': '', 'Plugin': 'PAMX', 'FirstName': ''}, 'path': 'Phonebook.Contact.'}
{'FirstName': 'Subscription', 'LastName': 'Test', 'Plugin': 'PAMX'}
Phonebook.Contact
{'object': 'Phonebook.Contact.', 'index': 458, 'keys': {}, 'notification': 'dm:instance-added', 'name': 'DMSubTest2', 'parameters': {'LastName': 'Test', 'Plugin': 'PAMX', 'FirstName': 'Subscription'}, 'path': 'Phonebook.Contact.'}
Phonebook.Contact
{'object': 'Phonebook.Contact.', 'index': 458, 'keys': {}, 'notification': 'dm:instance-added', 'name': 'DMSubTest2', 'parameters': {'LastName': 'Test', 'Plugin': 'PAMX', 'FirstName': 'Subscription'}, 'path': 'Phonebook.Contact.'}
{'FirstName': 'Subscription', 'LastName': 'Test', 'Plugin': 'PAMX'}
>>> sub.close()

```
