# Example Webui With Lighttpd 

## Running Exmaple Webui With Lighttpd

### Docker Container

1. Create and launch an [Ambiorix Development and Debug Container](https://gitlab.com/prpl-foundation/components/ambiorix/applications/amx-fcgi/-/tree/main/#docker-container)
1. Open a terminal in the container.
   ```
   docker exec -ti --user $USER oss-dbg /bin/bash
   ```
1. In the container clone this repository in a directory, for this example it is assumed that the git repository is cloned in directory `/home/$USER/workspace/`
   ```
   # create the directory if it doesn't exist yet.
   mkdir -p /home/$USER/workspace/
   cd /home/$USER/workspace/
   git clone git@gitlab.com:prpl-foundation/components/ambiorix/applications/amx-fcgi.git
   cd amx-fcgi
   ```
1. Build `amx-fcgi`
   ```
   make
   ```
1. Update `amx-fcgi` configuration
   To be able to run `amx-fcgi` stand-alone, the ACL verification must be turned off and the dummy session controller can be used. When `amx-fci` is used in a production environment, this should not be done.

   Open the file `odl/amx-fcg.odl` and uncomment the lines 14 and 28. The file should look like this after the modification:
   ```
   %config {
       // Application name
       name = "amx-fcgi";

       fcgi-socket = "$(LIGHTTPD_CHROOT)$(FCGI_SOCKET_DIR)$(FCGI_SOCKET)";
       username = "$(LIGHTTPD_USER)";
       groupname = "acl";
       acl = {
           /* 
              To make it easier in a development environment to debug and
              develop a web-ui it is possible to disable ACL verification.
              Never disable ACL verification in production environments.
           */
           disable = true,
           path = "/cfg/etc/acl/merged/"
       };
       mod-path = "${prefix}${plugin-dir}/${name}/modules";
       /*
          A different session controller can be selected.
          The default session controller uses the user manager and the user interface
          data models. To make it easier in a development environment to debug
          and develop a web-ui a dummy session controller is available. This
          dummy controller will emulate the session without realy doing any
          verification. It will still be needed to open a session and use the 
          session id in the http requests.
          Never use the dummy session controller in production environments. 
       */
       session-ctrl = "session-dummy";
       upload-folder = "/tmp";
   }

   import "${name}.so" as "${name}";

   %define {
       entry-point amx-fcgi.amx_fcgi_main;
   }
   ``` 

1. install `amx-fcgi`
   ```
   sudo -E make install
   ```

### Prepare Your Environment

Export the following environment variables

```bash
export LIGHTTPD_CHROOT=/home/$USER/workspace/amx-fcgi/examples/lighttpd/
export LIGHTTPD_USER=$USER
export LIGHTTPD_GROUP=$(id -g -n $USER)

export FCGI_SOCKET_DIR=/var/run/
export FCGI_SOCKET=amx-fcgi.sock
```

Make sure a bus system is running in the container:

Example - start ubusd
```bash
ubusd &
```

Start your data model provider services:

Example - launch greeter
```bash
greeter -D
```

### Step 1: launch amx-fcgi application

Run following command as root. The amx-fcgi application will drop root priveledges and will switch to user defined in `LIGHTTPD_USER`.

```bash
amx-fcgi -D
```

### Step 2: Launch Lighttpd

When running lighttpd in foreground it needs access to `/dev/null`. As lighttpd is started in a chrooted environment there is no `/dev/null` available and lighttpd will fail to start as a daemon. To work around this issue lighttpd is started in foreground with stdout redirected to stderr.

Run following command as root. The amx-fcgi application will drop root priveledges and will switch to user defined in `LIGHTTPD_USER`.

```bash
cd $LIGHTTPD_CHROOT
lighttpd -D -f ./etc/lighttpd.conf 2>&1 &
```

### Step 3: Access Webui

Open your favorite browser and open `http://<YOUR DOCKER IP>:8080/tr181ui.html`

When prompted for a username and password use:
- username: `admin`
- password: `admin`

For this example the users and passwords are defined in `/etc/lighttpd.user`

### On Target

When using a HGW running a prplOS build with lighttpd configured it is very easy to have this example up an running in no time.

First check the following:

1. Make sure your laptop/PC is connected on the LAN side of the HGW.
2. Make sure a SSH session can be opened to the HGW.
3. Make sure that the filesystem used on the HGW is writeable (overlayfs).
4. Make sure amx-fcgi is installed and running on the HGW.

All you now need to do is recursivly copy all files in the subdirectory `./examples/lighttpd/htdocs/` of this repository to `/webui/htdocs/` on the HGW.

