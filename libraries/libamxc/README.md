# C Generic Data Containers

[[_TOC_]]

## Introduction

`Lib_amxc` is a library providing generic reusable data containers.

The library provides:

- Double Linked List
- Dynamic Array
- Hash Table
- Ring Buffer
- Dynamic String
- Queues
- Stacks
- Variants

### Why libamxc?

- To fulfill some requirements:
  - Need for linked list and hash table (key value pairs) in which any kind of data can be stored (like pointers to structures, simple types, ... ).
  - The linked list or hash table can contain different kinds of data in one list or hash table. Most implementations available can create linked lists, arrays, hash table, but only serve one type.
  - Dynamic strings and arrays, in memory allocation. Can grow and shrink (automatically). Static allocated string or arrays are often ok, but once in a while they are too small. Either you over-allocate to be able to handle the rare-cases or make sure that extra memory can be allocated when needed and freed again when not needed anymore.
  - A dynamic (in memory allocation) ring buffer, that support read and write functions.

When using C++ there is a good choice in possible data container implementations, even the standard is supporting data containers.

- [Boost](https://www.boost.org/doc/libs/?view=category_containers)
  - Array, Bitmap, Circular Buffer, Property Map, Property tree, ...
- [Qt](https://doc.qt.io/qt-5/containers.html)
  - QList, QLinkedList, QVector, QMap, QHash, ...
- [C++ STL](https://embeddedartistry.com/blog/2017/8/2/an-overview-of-c-stl-containers)
  - dynamic arrays, queues, stacks, ...

While on C there is no standard library for data containers.

It is even hard to find generic implementations:
- [Search Results](https://www.google.com/search?q=data+containers+C&oq=data+containers+C&aqs=chrome..69i57j69i61j0j69i61l2j0.3913j0j4&sourceid=chrome&ie=UTF-8)

There are existing implementations, all different, all with different focus and different approach
- [bkthomps/Containers](https://github.com/bkthomps/Containers)
- [SGLIB](http://sglib.sourceforge.net/)
- [ccl](https://code.google.com/archive/p/ccl/source)
- and maybe more ...

None of C libraries found fulfill all requirements and do not always comply with the coding guidelines of the project (see [Coding Guidelines](https://gitlab.com/prpl-foundation/components/ambiorix/ambiorix/blob/main/doc/CODING_GUIDELINES.md))

So either:

- select a project, fork from it, update all code according to the guidelines and add all needed features
- or create a new library and implement everything needed.

The second option was chosen. 

Is this library better than others? Absolutely not. It just better fits the needs.

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
    mkdir -p ~/amx_project/libraries/
    ```

    Launch the container:

    ```bash
    docker run -ti -d --name oss-dbg --restart always --cap-add=SYS_PTRACE --sysctl net.ipv6.conf.all.disable_ipv6=1 -e "USER=$USER" -e "UID=$(id -u)" -e "GID=$(id -g)" -v ~/amx_project/:/home/$USER/amx_project/ registry.gitlab.com/soft.at.home/docker/oss-dbg:latest
    ```

    If you are using vpn, you need to add `--dns 192.168.16.10 --dns 192.168.16.11` to the docker run command.

    The `-v` option bind mounts the local directory for the ambiorix project in the container, at the exact same place.
    The `-e` options create environment variables in the container. These variables are used to create a user name with exactly the same user id and group id in the container as on your local host (user mapping).

    You can open as many terminals/consoles as you like:

    ```bash
    docker exec -ti --user $USER oss-dbg /bin/bash
    ```

### Building

#### Prerequisites

`Lib_amxc` does not need any other library to work.

#### Build libamxc

1. Clone the git repository

    To be able to build it, you need the source code. So open the directory just created for the ambiorix project and clone this library in it (on your local machine).

    ```bash
    cd ~/amx_project/libraries/
    git clone git@gitlab.com:prpl-foundation/components/ambiorix/libraries/libamxc.git
    ``` 

1. Build it


    ```bash
    cd ~/amx_project/libraries/libamxc
    make
    ```

1. Build API documentation

   All public API functions are documented with doxygen tags. To generate the documentation (in html format) doxygen must be installed.

   ```bash
    cd ~/amx_project/libraries/libamxc
    make doc
   ```

   The documentation will be available in `./output/doc/doxy-html/`. Open the file `./output/doc/doxy-html/index.html` in your favorite browser.

   Another option is to open the public header files, the documentation is available there as well.

### Installing

#### Using make target install

You can install your own compiled version easily in the container by running the install target.

```bash
cd ~/amx_project/libraries/libamxc
sudo -E make install
```

#### Using package

From within the container you can create packages.

```bash
cd ~/amx_project/libraries/libamxc
make package
```

The packages generated are:

```
~/amx_project/libraries/libamxc/libamxc-<VERSION>.tar.gz
~/amx_project/libraries/libamxc/libamxc-<VERSION>.deb
```

You can copy these packages and extract/install them.

For ubuntu or debian distributions use dpkg:

```bash
sudo dpkg -i ~/amx_project/libraries/libamxc/libamxc-<VERSION>.deb
```

### Testing

#### Prerequisites

No extra components are needed for testing `libamxc`.

#### Run tests

You can run the tests by executing the following command.

```bash
cd ~/amx_project/libraries/libamxc/tests
make
```

Or this command if you also want the coverage tests to run:

```bash
cd ~/amx_project/libraries/libamxc/tests
make run coverage
```

#### Coverage reports

The coverage target will generate coverage reports using [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html) and [gcovr](https://gcovr.com/en/stable/guide.html).

A summary for each file (*.c files) is printed in your console after the tests are run.
A HTML version of the coverage reports is also generated. These reports are available in the output directory of the compiler used.
Example: using native gcc
When the output of `gcc -dumpmachine` is `x86_64-linux-gnu`, the HTML coverage reports can be found at `~/amx_project/libraries/libamxc/output/x86_64-linux-gnu/coverage/report.`

You can easily access the reports in your browser.
In the container start a python3 http server in background.

```bash
cd ~/amx_project/
python3 -m http.server 8080 &
```

Use the following url to access the reports `http://<IP ADDRESS OF YOUR CONTAINER>:8080/libraries/libamxc/output/<MACHINE>/coverage/report`
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
So the uri you should use is: `http://172.17.0.7:8080/libraries/libamxc/output/x86_64-linux-gnu/coverage/report/`