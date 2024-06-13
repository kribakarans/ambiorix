# Backend Inspector 

[[_TOC_]]

## Introduction

Bus Agnostic back-ends are shared objects that implements the bus specific functionality.
As these are loaded dynamically from within an application, we must be sure that they are valid.

This tool verifies that a shared object is a valid and usable amxb back-end.

Checks that are done include:

- Can it be loaded using `dlopen`?
- Does it contain the symbol `amxb_be_info`?
- Does it provide correct information? (versions, name, ...)
- Can the installed version of libamxb be used with the loaded back-end?
- Does the back-end registers a valid function table?
- Are mandatory functions implemented? 

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
    docker pull softathome/oss-dbg:latest
    ```

    Before launching the container, you should create a directory which will be shared between your local machine and the container.

    ```bash
    mkdir -p ~/amx_project/applications
    ```

    Launch the container:

    ```bash
    docker run -ti -d --name oss-dbg --restart always --cap-add=SYS_PTRACE --sysctl net.ipv6.conf.all.disable_ipv6=1 -e "USER=$USER" -e "UID=$(id -u)" -e "GID=$(id -g)" -v ~/amx_project/:/home/$USER/amx_project/ softathome/oss-dbg:latest
    ```

    The `-v` option bind mounts the local directory for the ambiorix project in the container, at the exact same place.
    The `-e` options create environment variables in the container. These variables are used to create a user name with exactly the same user id and group id in the container as on your local host (user mapping).

    You can open as many terminals/consoles as you like:

    ```bash
    docker exec -ti --user $USER oss-dbg /bin/bash
    ```

### Building

#### Prerequisites

- [libamxb](https://gitlab.com/soft.at.home/ambiorix/libraries/libamxb) - Bus Agnostic API implementation

### Build amxb-inspect

1. Clone the git repository

    To be able to build it, you need the source code. So open the directory just created for the ambiorix project and clone this library in it.

    ```bash
    cd ~/amx_project/applications
    git clone https://gitlab.com/soft.at.home/ambiorix/applications/amxb-inspect.git
    ```

1. Install dependencies

    Although the container will contain all tools needed for building, it does not contain the libraries needed for building `amxb-inspect`. To be able to build `amxb-inspect` you need `libamxb`. This library can be installed in the container using the following command.

    ```bash
    sudo apt update
    sudo apt install libamxb
    ```

1. Build it

    ```bash
    cd ~/amx_project/applications/amxb-inspect
    make
    ```

### Installing

#### Using make target install

You can install your own compiled version easily in the container by running the install target.

```bash
cd ~/amx_project/applications/amxb-inspect
sudo make install
```

#### Using package

From within the container you can create packages.

```bash
cd ~/amx_project/applications/amxb-inspect
make package
```

The packages generated are:

```
~/amx_project/applications/amxb-inspect/amxb-inspect-<VERSION>.tar.gz
~/amx_project/applications/amxb-inspect/amxb-inspect-<VERSION>.deb
```

You can copy these packages and extract/install them.

For ubuntu or debian distributions use dpkg:

```bash
sudo dpkg -i ~/amx_project/applications/amxb-inspect/amxb-inspect-<VERSION>.deb
```

### Testing

Currently no tests are available for amxb-inspect.
