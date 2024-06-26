# Dummy baapi back-end  

[[_TOC_]]

## Introduction

Dummy implementation for the bus agnostic api. This back-end can be loaded using the `amxb_be_load` function which is implemented in [libamxb](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxb).

This bus backend makes it possible to write unittests for functions that call other
functions that need an `amxb_bus_ctxt_t*`, like `amxb_get`.

To write a unittest that needs the dummy bus, it is recommended to not use the dummy bus directly
and instead use `libamxut`, which takes care of setting up the dummy bus, datamodel, etc.

Supported:
- connect, disconnect
- signals

Unsupported: everything else.

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
    mkdir -p ~/amx_project/modules/amxb_backends/
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

#### Build amxb_dummy

1. Clone the git repository

    To be able to build it, you need the source code. So open the directory just created for the ambiorix project and clone this library in it (on your local machine).

    ```bash
    cd ~/amx_project/modules/amxb_backends/
    git clone git@gitlab.com:prpl-foundation/components/ambiorix/modules/amxb_backends/amxb_dummy.git
    ``` 

1. Install dependencies

    Although the container will contain all tools needed for building, it does not contain the libraries needed for building `amxb_dummy`. To be able to build `amxb_dummy` you need `libamxc`, `libamxp` and `libamxb`. These libraries can be installed in the container.

    ```bash
    sudo apt update
    sudo apt install libamxc
    sudo apt install libamxb
    ```

    Note that you do not need to install all components explicitly. Some components will be installed automatically because the other components depend on them. Some of the components are allready preinstalled in the container.

1. Build it

    ```bash
    cd ~/amx_project/modules/amxb_backends/amxb_dummy
    make
    ```

### Installing

#### Using make target install

You can install your own compiled version easily in the container by running the install target.

```bash
cd ~/amx_project/modules/amxb_backends/amxb_dummy
sudo -E make install
```

#### Using package

From within the container you can create packages.

```bash
cd ~/amx_project/modules/amxb_backends/amxb_dummy
make package
```

The packages generated are:

```
~/amx_project/modules/amxb_backends/amxb_dummy/mod-amxb-dummy-<VERSION>.tar.gz
~/amx_project/modules/amxb_backends/amxb_dummy/mod-amxb-dummy-<VERSION>.deb
```

You can copy these packages and extract/install them.

For ubuntu or debian distributions use dpkg:

```bash
sudo dpkg -i ~/amx_project/modules/amxb_backends/amxb_dummy/mod-amxb-dummy-<VERSION>.deb
```

### Testing

#### Run tests

1. Run tests

    You can run the tests by executing the following command.

    ```bash
    cd ~/amx_project/modules/amxb_backends/amxb_dummy/tests
    sudo make
    ```

    Or this command if you also want the coverage tests to run:

    ```bash
    cd ~/amx_project/modules/amxb_backends/amxb_dummy/tests
    make run coverage
    ```

#### Coverage reports

The coverage target will generate coverage reports using [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html) and [gcovr](https://gcovr.com/en/stable/guide.html).

A summary for each file (*.c files) is printed in your console after the tests are run.
A HTML version of the coverage reports is also generated. These reports are available in the output directory of the compiler used.
Example: using native gcc
When the output of `gcc -dumpmachine` is `x86_64-linux-gnu`, the HTML coverage reports can be found at `~/amx_project/modules/amxb_backends/amxb_dummy/output/x86_64-linux-gnu/coverage/report.`

You can easily access the reports in your browser.
In the container start a python3 http server in background.

```bash
cd ~/amx_project/
python3 -m http.server 8080 &
```

Use the following url to access the reports `http://<IP ADDRESS OF YOUR CONTAINER>:8080/modules/amxb_backends/amxb_dummy/output/<MACHINE>/coverage/report`
You can find the ip address of your container by using the `ip` command in the container.

Example:

```bash
USER@<CID>:~/amx_project/modules/amxb_backends/amxb_dummy$ ip a
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
So the uri you should use is: `http://172.17.0.7:8080/modules/amxb_backends/amxb_dummy/output/x86_64-linux-gnu/coverage/report/`

## Dummy odl config options

The dummy back-end currently does not support using config options of the odl `%config` section.

