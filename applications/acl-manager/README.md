# ACL manager

[[_TOC_]]

## Introduction

The ACL manager is an ambiorix plugin that is responsible for managing the ACL (Access Control List) files that are present on a gateway. It will make sure that ACL verification can be done quickly by several other processes that require some sort of access validation.

The ACL system uses role based access control to manage permissions. There will be a common ACL directory (`/etc/acl/` by default) that will contain a subfolder for each defined role. Every role can have as many ACL files as needed. These ACL files will be merged together to a single file for a given role based on the TR-369 and TR-181 specifications. By default the merged files can be found in `/etc/acl/merged/<role-name>.json`. Like the name suggests, all ACL files will be written in JSON format.

A process, such as a USP agent, that needs to do access control validation for a given role, can simply parse the merged ACL file for the chosen role and use the provided [libamxa](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxa) API functions to validate the role's permissions.

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

- [libamxc](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxc) - Generic C api for common data containers
- [libamxj](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxj) - JSON parser & generator using yajl and libamxc variants
- [libamxd](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxd) - Data model C API
- [libamxo](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxo) - The ODL compiler library
- [libamxa](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxa) - Access control verification library
- [libsahtrace](https://gitlab.com/soft.at.home/logging/libsahtrace) - Logging library

#### Build acl-manager

1. Clone the git repository

    To be able to build it, you need the source code. So open the directory just created for the ambiorix project and clone this library in it (on your local machine).

    ```bash
    cd ~/amx_project/applications
    git clone git@gitlab.com:prpl-foundation/components/core/plugins/acl-manager.git
    ``` 

1. Install dependencies

    Although the container will contain all tools needed for building, it does not contain the libraries needed for building the `acl-manager`. To be able to build the `acl-manager` you need `libamxc`, `libamxj`, `libamxd`, `libamxo`, `libamxa` and `libsahtrace`. These libraries can be installed in the container by executing the following commands. 

    ```bash
    sudo apt update
    sudo apt install libamxj libamxo libamxa sah-lib-sahtrace-dev
    ```

    Note that you do not need to install all components explicitly. Some components will be installed automatically because other components depend on them.

1. Build it
    
    ```bash
    cd ~/amx_project/applications/acl-manager
    make
    ```

### Installing

#### Using make target install

You can install your own compiled version easily in the container by running the install target.

```bash
cd ~/amx_project/applications/acl-manager
sudo -E make install
```

#### Using package

From within the container you can create packages.

```bash
cd ~/amx_project/applications/acl-manager
make package
```

The packages generated are:

```
~/amx_project/applications/acl-manager/acl-manager-<VERSION>.tar.gz
~/amx_project/applications/acl-manager/acl-manager-<VERSION>.deb
```

You can copy these packages and extract/install them.

For ubuntu or debian distributions use dpkg:

```bash
sudo dpkg -i ~/amx_project/applications/acl-manager/acl-manager-<VERSION>.deb
```

### Run time prerequisites

- [amxrt](https://gitlab.com/prpl-foundation/components/ambiorix/applications/amxrt)
- [mod-sahtrace](https://gitlab.com/prpl-foundation/components/core/modules/mod_sahtrace) (optional)

This plugin runs with `amxrt` like most ambiorix plugins. For logging it loads the sahtrace module at run time if it is available. Both of these tools can be installed from debian packages.

```bash
sudo apt install amxrt mod-sahtrace
```

### Testing

#### Prerequisites

- [libamxp](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxp) - Common patterns implementation

#### Run tests

1. Install dependencies

    Most of the packages needed for testing are already preinstalled in the container. To be able to test the `acl-manager` you additionally need to install `libamxp`.

    ```bash
    sudo apt update
    sudo apt install libamxp
    ```

1. Run tests

    You can run the tests by executing the following command.
    
    ```bash
    cd ~/amx_project/applications/acl-manager/test
    sudo make
    ```
    
    Or this command if you also want the coverage tests to run:
    
    ```bash
    cd ~/amx_project/applications/acl-manager/test
    sudo make run coverage
    ```
    
    Or from the root directory of this repository,
    
    ```bash
    cd ~/amx_project/applications/acl-manager
    sudo make test
    ```
    
    This last will run the unit-tests and generate the test coverage reports in one go.

    Note that the tests need to be run as root user because the file and directory ownership is
    updated to `root:acl`. Also note that the `acl` group must exist to prevent memory leaks.
    You can add the `acl` group with the following command.

    ```bash
    sudo groupadd acl
    ```

#### Coverage reports

The coverage target will generate coverage reports using [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html) and [gcovr](https://gcovr.com/en/stable/guide.html).

A summary for each file (*.c file) is printed in your console after the tests are run.
A HTML version of the coverage reports is also generated. These reports are available in the output directory of the compiler used.
Example: using native gcc
When the output of `gcc -dumpmachine` is `x86_64-linux-gnu`, the HTML coverage reports can be found at `~/amx_project/applications/acl-manager/output/x86_64-linux-gnu/coverage/report.`

You can easily access the reports in your browser.
In the container start a python3 http server in background.

```bash
cd ~/amx_project/
python3 -m http.server 8080 &
```

Use the following url to access the reports `http://<IP ADDRESS OF YOUR CONTAINER>:8080/applications/acl-manager/output/<MACHINE>/coverage/report`
You can find the ip address of your container by using the `ip` command in the container.

Example:

```bash
USER@<CID>:~/applications/acl-manager/libamxd$ ip a
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

In this case the IP address of the container is `172.17.0.7`.
So the uri you should use is: `http://172.17.0.7:8080/applications/acl-manager/output/x86_64-linux-gnu/coverage/report/`

## Running the acl-manager

During the installation of the plugin a symbolic link to `amxrt` is created

- `/usr/bin/acl-manager` -> `/usr/bin/amxrt`

You can run the acl-manager using the symbolic link `acl-manager`.

The acl-manager can be configured in the config section of the `acl-manager.odl` file. There are 2 main things to be configured:

- `acl_dir`: this is the top level directory that will be used for managing ACL files. For each role there will be a subdirectory with the role name and inside this directory, the ACL files for this role must be saved. The `acl-manager` will merge these ACL files and save a master ACL file for each role in `<acl_dir>/merged/<role_name>.json`. This master ACL file can be consulted by other applications to validate the access rights for a role. Note that this implies that `merged` cannot be used as a role name.
- `inotify-enabled`: by default, the `acl-manager` uses inotify to automatically pick up changes made to the ACL directories. These changes include modified files, added or deleted files and moved files. Whenever a change happens, the `acl-manager` will automatically recompute the master ACL file for the needed roles. If inotify is not enabled on your system, you should set this flag to `false`. Whenever an ACL directory is updated, you can still manually call the RPC `ACLManager.Role.[Name == "your-role"].UpdateACL()`.

By default the `acl-manager` will create an `operator` and a `guest` role. The permissions for these roles can be found in the `acl/` directory of the repository. In short, the `operator` role will have access to the entire data model. The `guest` role won't have any access rights by default, but ACLs could be added for it if there is a specific use case. Right now, this role is mainly used for demo purposes.
